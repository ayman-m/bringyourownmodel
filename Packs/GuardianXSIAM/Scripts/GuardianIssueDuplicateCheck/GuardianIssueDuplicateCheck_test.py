import json

import pytest

import GuardianIssueDuplicateCheck as dup


def _issue(issue_id="20", rule="rule-1", name="Silent data source (ExampleVendor)", assets=None, vendor="ExampleVendor",
           product="ExampleProduct", **extra):
    custom = {"ruleid": rule, "_vendor": [vendor] if vendor else [], "_product": [product] if product else []}
    if assets is not None:
        custom["asset_ids"] = assets
    custom.update(extra)
    return {"id": issue_id, "name": name, "CustomFields": custom}


class _Rest:
    """Fake executeCommand: records every call and answers the search and the close."""

    def __init__(self, candidates=None, total=None, search_error=None, close_error=None, search_contents=None):
        self.calls = []
        self.candidates = candidates if candidates is not None else []
        self.total = total if total is not None else len(self.candidates)
        self.search_error = search_error
        self.close_error = close_error
        self.search_contents = search_contents

    def __call__(self, command, args):
        self.calls.append((command, args))
        if command == "demisto-api-post":
            if self.search_error:
                return [{"Type": 4, "Contents": self.search_error}]
            contents = self.search_contents if self.search_contents is not None else {
                "response": {"data": self.candidates, "total": self.total}}
            return [{"Type": 1, "Contents": contents}]
        if command == "core-update-issue":
            if self.close_error:
                return [{"Type": 4, "Contents": self.close_error}]
            return [{"Type": 1, "Contents": "ok"}]
        raise AssertionError("unexpected command: {} {}".format(command, args))

    def searches(self):
        return [a for c, a in self.calls if c == "demisto-api-post"]

    def closes(self):
        return [a for c, a in self.calls if c == "core-update-issue"]


def _install(monkeypatch, rest):
    monkeypatch.setattr(dup.demisto, "executeCommand", rest)
    monkeypatch.setattr(dup.demisto, "error", lambda msg: None)
    return rest


def _run(monkeypatch, issue, candidates=None, close=False, **kw):
    rest = _install(monkeypatch, _Rest(candidates, **kw))
    return dup.guardian_dup_run(issue, close=close), rest


# --- the fingerprint -------------------------------------------------------------------------------------------------

def test_fingerprint_is_lowercase_sorted_deduplicated_and_tolerant_of_case_and_separators():
    issue = {"id": "1", "CustomFields": {"_Vendor": ["ExampleVendor", "examplevendor"], "PRODUCT": "ExampleProduct",
                                          "Agent_Hostname": " Host-B ", "user_name": ["Bob", "alice"], "LocalIP": "10.0.0.5",
                                          "remote_ip": ["10.0.0.9"], "Action_File_SHA256": "ABCD", "domain": "Example.Test"}}
    assert dup.guardian_dup_fingerprint(issue) == {
        "vendor": ["examplevendor"], "product": ["exampleproduct"], "host": ["host-b"], "user": ["alice", "bob"],
        "local_ip": ["10.0.0.5"], "remote_ip": ["10.0.0.9"], "file_sha256": ["abcd"], "domain": ["example.test"]}


def test_fingerprint_leaves_out_absent_empty_and_unusable_fields_and_reads_the_top_level_too():
    issue = {"id": "1", "hostname": "h1", "CustomFields": {"_vendor": [], "_product": "", "username": None, "domain": {"a": 1}, "alert_domain": "DOMAIN_HEALTH"}}
    assert dup.guardian_dup_fingerprint(issue) == {"host": ["h1"]}  # alert_domain is not the `domain` field
    assert dup.guardian_dup_fingerprint({}) == {}


def test_asset_ids_are_lowercase_deduplicated_and_a_comma_separated_text_is_a_list():
    assert dup.guardian_dup_assets({"CustomFields": {"asset_ids": ["A-1", "a-1", "B-2"]}}) == ["a-1", "b-2"]
    assert dup.guardian_dup_assets({"CustomFields": {"AssetIds": "A-1, b-2"}}) == ["a-1", "b-2"]
    assert dup.guardian_dup_assets({"CustomFields": {}}) == []


# --- the decision ------------------------------------------------------------------------------------------------------

def test_a_duplicate_names_the_lowest_open_match_as_the_original(monkeypatch):
    candidates = [_issue("12", assets=["a-1"]), _issue("15", assets=["a-1"]), _issue("20", assets=["a-1"]), _issue("30", assets=["a-1"])]
    result, rest = _run(monkeypatch, _issue("20", assets=["A-1"]), candidates)
    assert result["is_duplicate"] == "true" and result["original_id"] == "12"
    assert result["matching_open_ids"] == ["12", "15", "30"] and result["open_in_group"] == 4
    assert result["rule_id"] == "rule-1" and result["issue_id"] == "20" and result["closed"] == "false"
    assert "#12" in result["reason"]
    assert rest.closes() == []


def test_the_search_is_one_call_with_the_rule_filter_oldest_first_and_the_size(monkeypatch):
    result, rest = _run(monkeypatch, _issue("20", assets=["a-1"]), [])
    assert len(rest.calls) == 1
    body = json.loads(rest.searches()[0]["body"])
    assert rest.searches()[0]["uri"] == "/incidents/search"
    assert body == {"filter": {"page": 0, "size": 50, "query": 'ruleid:"rule-1" and -status:closed',
                               "sort": [{"field": "id", "asc": True}]}}
    assert result["is_duplicate"] == "false"


def test_the_original_is_not_a_duplicate_and_gets_a_proposal_when_later_issues_repeat_it(monkeypatch):
    candidates = [_issue("12", assets=["a-1"]), _issue("15", assets=["a-1"]), _issue("16", assets=["a-9"])]
    result, _ = _run(monkeypatch, _issue("12", assets=["a-1"]), candidates)
    assert result["is_duplicate"] == "false" and result["original_id"] == ""
    assert result["matching_open_ids"] == ["15"] and result["open_in_group"] == 2
    proposal = result["proposed_exclusion"]
    assert proposal["rule_id"] == "rule-1" and proposal["rule_name"] == "Silent data source (ExampleVendor)"
    assert proposal["scope"]["asset_ids"] == ["a-1"] and proposal["scope"]["vendor"] == ["examplevendor"]
    assert proposal["suggested_review_days"] == 7 and "#15" in proposal["reason"]
    assert result["proposed_exclusion_text"].startswith("Exclude or suppress rule")


def test_a_duplicate_carries_a_proposed_exclusion(monkeypatch):
    result, _ = _run(monkeypatch, _issue("20", assets=["a-1"]), [_issue("12", assets=["a-1"])])
    proposal = result["proposed_exclusion"]
    assert proposal["scope"] == {"vendor": ["examplevendor"], "product": ["exampleproduct"], "asset_ids": ["a-1"]}
    assert proposal["rule_name"] and proposal["suggested_review_days"] == 7 and "#12" in proposal["reason"]


def test_an_issue_alone_in_its_group_is_not_a_duplicate_and_has_no_proposal(monkeypatch):
    result, _ = _run(monkeypatch, _issue("20", assets=["a-1"]), [_issue("20", assets=["a-1"])])
    assert result["is_duplicate"] == "false" and result["matching_open_ids"] == [] and result["open_in_group"] == 1
    assert result["proposed_exclusion"] == {} and result["proposed_exclusion_text"] == ""
    assert "no other open issue" in result["reason"]


def test_no_rule_id_fails_open_without_a_search(monkeypatch):
    issue = {"id": "20", "name": "x", "CustomFields": {"asset_ids": ["a-1"]}}
    result, rest = _run(monkeypatch, issue, [_issue("12", assets=["a-1"])])
    assert result["is_duplicate"] == "false" and "no rule id" in result["reason"] and rest.calls == []


@pytest.mark.parametrize("rule", ['bad"rule', "bad\\rule", "bad\nrule", "x" * 201])
def test_a_rule_id_that_cannot_go_into_a_query_fails_open_without_a_search(monkeypatch, rule):
    result, rest = _run(monkeypatch, _issue("20", rule=rule, assets=["a-1"]), [_issue("12", assets=["a-1"])])
    assert result["is_duplicate"] == "false" and "rule id" in result["reason"] and rest.calls == []


def test_a_lookup_error_fails_open(monkeypatch):
    result, rest = _run(monkeypatch, _issue("20", assets=["a-1"]), search_error="HTTP 500 server error")
    assert result["is_duplicate"] == "false" and "lookup" in result["reason"] and "500" in result["reason"]
    assert result["issue_id"] == "20" and len(rest.calls) == 1


@pytest.mark.parametrize("contents", [{"response": {"unexpected": 1}}, {"response": "text"}, "plain text", {"nothing": True}])
def test_an_unreadable_search_result_fails_open(monkeypatch, contents):
    result, _ = _run(monkeypatch, _issue("20", assets=["a-1"]), search_contents=contents)
    assert result["is_duplicate"] == "false" and "failed" in result["reason"]


def test_an_empty_search_result_with_a_null_data_list_is_not_an_error(monkeypatch):
    result, _ = _run(monkeypatch, _issue("20", assets=["a-1"]), search_contents={"response": {"data": None, "total": 0}})
    assert result["is_duplicate"] == "false" and "failed" not in result["reason"]


def test_assets_that_intersect_match_even_when_the_fingerprints_differ(monkeypatch):
    candidate = _issue("12", assets=["a-9", "A-1"], vendor="OtherVendor", product="OtherProduct")
    result, _ = _run(monkeypatch, _issue("20", assets=["a-1", "a-2"]), [candidate])
    assert result["is_duplicate"] == "true" and result["original_id"] == "12"


def test_assets_that_do_not_intersect_never_fall_back_to_the_fingerprint(monkeypatch):
    result, _ = _run(monkeypatch, _issue("20", assets=["a-1"]), [_issue("12", assets=["a-2"])])
    assert result["is_duplicate"] == "false" and "none on the same assets" in result["reason"]


def test_assets_on_one_side_only_never_match(monkeypatch):
    result, _ = _run(monkeypatch, _issue("20", assets=["a-1"]), [_issue("12")])
    assert result["is_duplicate"] == "false"
    result, _ = _run(monkeypatch, _issue("20"), [_issue("12", assets=["a-1"])])
    assert result["is_duplicate"] == "false"


def test_equal_fingerprints_match_when_neither_issue_has_assets(monkeypatch):
    candidate = _issue("12", vendor="examplevendor", product="EXAMPLEPRODUCT")
    result, _ = _run(monkeypatch, _issue("20"), [candidate])
    assert result["is_duplicate"] == "true" and result["original_id"] == "12"
    assert result["fingerprint"] == {"vendor": ["examplevendor"], "product": ["exampleproduct"]}
    assert result["proposed_exclusion"]["scope"]["fingerprint"] == result["fingerprint"]
    assert "asset_ids" not in result["proposed_exclusion"]["scope"]


def test_different_fingerprints_do_not_match(monkeypatch):
    result, _ = _run(monkeypatch, _issue("20"), [_issue("12", product="AnotherProduct"), _issue("13", hostname="other-host")])
    assert result["is_duplicate"] == "false"


def test_a_fingerprint_that_differs_by_one_extra_field_does_not_match(monkeypatch):
    result, _ = _run(monkeypatch, _issue("20"), [_issue("12", hostname="h1")])
    assert result["is_duplicate"] == "false"


def test_an_empty_fingerprint_without_assets_is_never_a_match(monkeypatch):
    issue = {"id": "20", "name": "x", "CustomFields": {"ruleid": "rule-1"}}
    candidate = {"id": "12", "name": "x", "CustomFields": {"ruleid": "rule-1"}}
    result, rest = _run(monkeypatch, issue, [candidate])
    assert result["is_duplicate"] == "false" and "neither asset ids nor source fields" in result["reason"]
    assert result["fingerprint"] == {} and result["open_in_group"] == 1


def test_a_candidate_of_another_rule_is_ignored_even_if_the_search_returned_it(monkeypatch):
    result, _ = _run(monkeypatch, _issue("20", assets=["a-1"]), [_issue("12", rule="rule-2", assets=["a-1"])])
    assert result["is_duplicate"] == "false"


def test_the_rule_id_is_compared_case_insensitively(monkeypatch):
    result, _ = _run(monkeypatch, _issue("20", rule="Rule-A", assets=["a-1"]), [_issue("12", rule="rule-a", assets=["A-1"])])
    assert result["is_duplicate"] == "true"


def test_two_issues_running_together_never_mark_each_other(monkeypatch):
    candidates = [_issue("30", assets=["a-1"]), _issue("31", assets=["a-1"])]
    first, _ = _run(monkeypatch, _issue("30", assets=["a-1"]), candidates)
    second, _ = _run(monkeypatch, _issue("31", assets=["a-1"]), candidates)
    assert first["is_duplicate"] == "false" and first["open_in_group"] == 2
    assert second["is_duplicate"] == "true" and second["original_id"] == "30"


def test_ids_are_compared_as_numbers_not_text(monkeypatch):
    # "9" sorts after "10" as text, but 9 is the lower number
    result, _ = _run(monkeypatch, _issue("10", assets=["a-1"]), [_issue("9", assets=["a-1"]), _issue("100", assets=["a-1"])])
    assert result["is_duplicate"] == "true" and result["original_id"] == "9"
    assert result["matching_open_ids"] == ["9", "100"]


def test_a_non_numeric_candidate_id_is_listed_but_never_counts_as_lower(monkeypatch):
    result, _ = _run(monkeypatch, _issue("20", assets=["a-1"]), [_issue("abc", assets=["a-1"])])
    assert result["is_duplicate"] == "false" and result["matching_open_ids"] == ["abc"] and result["open_in_group"] == 2


def test_a_non_numeric_issue_id_fails_open(monkeypatch):
    result, _ = _run(monkeypatch, _issue("abc", assets=["a-1"]), [_issue("12", assets=["a-1"])])
    assert result["is_duplicate"] == "false" and "not a number" in result["reason"]


def test_matching_ids_are_capped_at_twenty_but_the_group_count_is_not(monkeypatch):
    candidates = [_issue(str(100 + i), assets=["a-1"]) for i in range(30)]
    result, _ = _run(monkeypatch, _issue("500", assets=["a-1"]), candidates)
    assert len(result["matching_open_ids"]) == 20 and result["matching_open_ids"][0] == "100"
    assert result["open_in_group"] == 31 and result["original_id"] == "100"


@pytest.mark.parametrize("raw, size", [(None, 50), ("", 50), ("abc", 50), ("0", 50), ("-5", 50), ("10", 10), (25, 25), ("100", 100),
                                       ("101", 100), ("100000", 100)])
def test_max_candidates_defaults_to_fifty_and_is_capped_at_one_hundred(monkeypatch, raw, size):
    rest = _install(monkeypatch, _Rest([]))
    dup.guardian_dup_run(_issue("20", assets=["a-1"]), max_candidates=raw)
    assert json.loads(rest.searches()[0]["body"])["filter"]["size"] == size


def test_a_search_cut_at_its_limit_says_so(monkeypatch):
    result, _ = _run(monkeypatch, _issue("20", assets=["a-1"]), [_issue("12", assets=["a-1"])], total=400)
    assert result["is_duplicate"] == "true" and "cut at its limit" in result["reason"]


# --- closing ---------------------------------------------------------------------------------------------------------------

def test_close_duplicates_closes_only_this_issue_with_the_duplicate_status(monkeypatch):
    result, rest = _run(monkeypatch, _issue("20", assets=["a-1"]), [_issue("12", assets=["a-1"])], close=True)
    assert result["is_duplicate"] == "true" and result["closed"] == "true" and result["close_error"] == ""
    assert len(rest.closes()) == 1
    assert rest.closes()[0] == {"id": "20", "issue_id": "20", "status": "Resolved - Duplicate Issue"}


def test_a_failed_close_is_recorded_and_never_raises(monkeypatch):
    result, rest = _run(monkeypatch, _issue("20", assets=["a-1"]), [_issue("12", assets=["a-1"])], close=True,
                        close_error="Error in API call [400] - bad status")
    assert result["is_duplicate"] == "true" and result["closed"] == "false" and "400" in result["close_error"]
    assert len(rest.closes()) == 1


def test_a_close_that_raises_is_recorded(monkeypatch):
    rest = _install(monkeypatch, _Rest([_issue("12", assets=["a-1"])]))

    def fake(command, args):
        if command == "core-update-issue":
            raise RuntimeError("boom")
        return rest(command, args)

    monkeypatch.setattr(dup.demisto, "executeCommand", fake)
    result = dup.guardian_dup_run(_issue("20", assets=["a-1"]), close=True)
    assert result["closed"] == "false" and "boom" in result["close_error"]


def test_nothing_is_closed_for_an_original_or_when_close_is_off(monkeypatch):
    _, rest = _run(monkeypatch, _issue("12", assets=["a-1"]), [_issue("12", assets=["a-1"]), _issue("20", assets=["a-1"])], close=True)
    assert rest.closes() == []
    _, rest = _run(monkeypatch, _issue("20", assets=["a-1"]), [_issue("12", assets=["a-1"])], close=False)
    assert rest.closes() == []


def test_nothing_is_closed_when_the_check_failed_open(monkeypatch):
    _, rest = _run(monkeypatch, _issue("20", assets=["a-1"]), search_error="HTTP 500", close=True)
    assert rest.closes() == []


@pytest.mark.parametrize("raw, expected", [("true", True), ("True", True), (" YES ", True), ("1", True), ("false", False), ("", False),
                                           (None, False), ("no", False)])
def test_close_duplicates_is_read_as_a_flag(raw, expected):
    assert dup.guardian_dup_truthy(raw) is expected


# --- main: the context ---------------------------------------------------------------------------------------------------

class _Context:
    def __init__(self, monkeypatch, issue, args, rest, stale=None):
        self.writes, self.results = [], []
        monkeypatch.setattr(dup.demisto, "incident", lambda: issue)
        monkeypatch.setattr(dup.demisto, "args", lambda: args)
        monkeypatch.setattr(dup.demisto, "executeCommand", rest)
        monkeypatch.setattr(dup.demisto, "error", lambda msg: None)
        self.stale = stale
        monkeypatch.setattr(dup.demisto, "setContext", lambda path, value: self.writes.append((path, value)))
        monkeypatch.setattr(dup, "return_results", lambda value: self.results.append(value))


def test_main_empties_the_context_first_then_writes_the_answer_and_returns_it_keyed_by_the_issue(monkeypatch):
    ctx = _Context(monkeypatch, _issue("20", assets=["a-1"]), {"close_duplicates": "false"}, _Rest([_issue("12", assets=["a-1"])]))
    dup.main()
    assert ctx.writes[0] == ("Guardian.Duplicate", {})
    path, final = ctx.writes[-1]
    assert path == "Guardian.Duplicate" and final["is_duplicate"] == "true" and final["original_id"] == "12"
    assert len(ctx.writes) == 2
    command_result = ctx.results[0]
    assert command_result.outputs_prefix == "Guardian.Duplicate" and command_result.outputs_key_field == "issue_id"
    assert command_result.outputs == final
    assert "duplicate" in command_result.readable_output and "#12" in command_result.readable_output
    assert "Proposed exclusion" in command_result.readable_output


def test_main_on_an_unexpected_error_still_ends_with_a_fail_open_answer_and_no_error_entry(monkeypatch):
    ctx = _Context(monkeypatch, _issue("20", assets=["a-1"]), {}, _Rest([]))
    monkeypatch.setattr(dup, "guardian_dup_run", lambda *a, **k: (_ for _ in ()).throw(ValueError("odd")))
    called = []
    monkeypatch.setattr(dup, "return_error", lambda msg: called.append(msg))
    dup.main()
    assert called == []
    assert ctx.writes[0] == ("Guardian.Duplicate", {})
    final = ctx.writes[-1][1]
    assert final["is_duplicate"] == "false" and "unexpectedly" in final["reason"] and final["issue_id"] == "20"
    assert ctx.results[0].outputs["is_duplicate"] == "false"


def test_main_leaves_no_stale_answer_when_the_context_write_itself_fails(monkeypatch):
    ctx = _Context(monkeypatch, _issue("20", assets=["a-1"]), {}, _Rest([]))

    def broken(path, value):
        raise RuntimeError("no context")

    monkeypatch.setattr(dup.demisto, "setContext", broken)
    dup.main()  # must not raise
    assert ctx.results[0].outputs["is_duplicate"] == "false"


def test_main_with_close_duplicates_true_passes_it_through(monkeypatch):
    rest = _Rest([_issue("12", assets=["a-1"])])
    ctx = _Context(monkeypatch, _issue("20", assets=["a-1"]), {"close_duplicates": "true", "max_candidates": "5"}, rest)
    dup.main()
    assert ctx.writes[-1][1]["closed"] == "true" and len(rest.closes()) == 1
    assert json.loads(rest.searches()[0]["body"])["filter"]["size"] == 5
    assert "closed" in ctx.results[0].readable_output


def test_the_readable_output_for_each_outcome(monkeypatch):
    original, _ = _run(monkeypatch, _issue("12", assets=["a-1"]), [_issue("15", assets=["a-1"])])
    assert dup.guardian_dup_readable(original).startswith("Duplicate check: **original** of 2 open issues.")
    plain, _ = _run(monkeypatch, _issue("12", assets=["a-1"]), [])
    assert dup.guardian_dup_readable(plain).startswith("Duplicate check: not a duplicate.")
    failed, _ = _run(monkeypatch, _issue("20", assets=["a-1"]), [_issue("12", assets=["a-1"])], close=True, close_error="denied")
    assert "Closing this issue failed: denied" in dup.guardian_dup_readable(failed)
