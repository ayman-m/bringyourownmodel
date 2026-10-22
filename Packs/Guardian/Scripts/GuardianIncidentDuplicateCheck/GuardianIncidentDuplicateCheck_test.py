import json

import pytest

import GuardianIncidentDuplicateCheck as dup


def _incident(incident_id="20", kind="Phishing", name="Suspicious email report", host="HOST-A", brand="ExampleBrand",
              instance="example-instance", **custom):
    fields = {"hostname": host} if host else {}
    fields.update(custom)
    record = {"id": incident_id, "type": kind, "name": name, "CustomFields": fields}
    if brand:
        record["sourceBrand"] = brand
    if instance:
        record["sourceInstance"] = instance
    return record


class _Rest:
    """Fake executeCommand: records every call and answers the search (getIncidents) and the close (linkIncidents)."""

    def __init__(self, candidates=None, total=None, search_error=None, close_error=None, search_contents=None,
                 close_contents="1 incidents marked as duplicates"):
        self.calls = []
        self.candidates = candidates if candidates is not None else []
        self.total = total if total is not None else len(self.candidates)
        self.search_error = search_error
        self.close_error = close_error
        self.search_contents = search_contents
        self.close_contents = close_contents

    def __call__(self, command, args):
        self.calls.append((command, args))
        if command == "getIncidents":
            if self.search_error:
                return [{"Type": 4, "Contents": self.search_error}]
            contents = self.search_contents if self.search_contents is not None else {
                "data": self.candidates or None, "total": self.total}
            return [{"Type": 1, "Contents": contents}]
        if command == "linkIncidents":
            if self.close_error:
                return [{"Type": 4, "Contents": self.close_error}]
            return [{"Type": 1, "Contents": self.close_contents}]
        raise AssertionError("unexpected command: {} {}".format(command, args))

    def searches(self):
        return [a for c, a in self.calls if c == "getIncidents"]

    def closes(self):
        return [a for c, a in self.calls if c == "linkIncidents"]


def _install(monkeypatch, rest):
    monkeypatch.setattr(dup.demisto, "executeCommand", rest)
    monkeypatch.setattr(dup.demisto, "error", lambda msg: None)
    return rest


def _run(monkeypatch, incident, candidates=None, close=False, **kw):
    rest = _install(monkeypatch, _Rest(candidates, **kw))
    return dup.guardian_dup_run(incident, close=close), rest


# --- the fingerprint -------------------------------------------------------------------------------------------------

def test_fingerprint_is_lowercase_sorted_deduplicated_and_tolerant_of_case_and_separators():
    incident = {"id": "1", "CustomFields": {"Host_Name": " Host-B ", "UserName": ["Bob", "alice", "BOB"], "Source_IP": "10.0.0.5",
                                             "DestinationIP": ["10.0.0.9"], "File_SHA256": "ABCD", "URL": "http://Example.test/A",
                                             "Email_From": "Sender@Example.test"}}
    assert dup.guardian_dup_fingerprint(incident) == {
        "host": ["host-b"], "user": ["alice", "bob"], "source_ip": ["10.0.0.5"], "destination_ip": ["10.0.0.9"],
        "file_hash": ["abcd"], "url": ["http://example.test/a"], "email_sender": ["sender@example.test"]}


def test_fingerprint_accepts_every_documented_field_name():
    names = {"host": ("hostname", "devicename", "agenthostname"), "user": ("username", "users", "account"),
             "source_ip": ("sourceip", "srcip"), "destination_ip": ("destinationip", "dstip"),
             "file_hash": ("filesha256", "filehash", "sha256"), "url": ("url",), "email_sender": ("emailfrom", "emailsender")}
    assert {key: tuple(n) for key, n in dict(dup.GUARDIAN_DUP_FINGERPRINT_FIELDS).items()} == names
    for key, accepted in names.items():
        for field in accepted:
            assert dup.guardian_dup_fingerprint({"CustomFields": {field: "V1"}}) == {key: ["v1"]}, field


def test_fingerprint_reads_custom_fields_then_the_top_level_then_the_labels():
    incident = {"id": "1", "hostname": "top", "CustomFields": {"hostname": "custom"}, "labels": [{"type": "Host Name", "value": "label"}]}
    assert dup.guardian_dup_fingerprint(incident) == {"host": ["custom"]}
    del incident["CustomFields"]
    assert dup.guardian_dup_fingerprint(incident) == {"host": ["top"]}
    del incident["hostname"]
    assert dup.guardian_dup_fingerprint(incident) == {"host": ["label"]}


def test_fingerprint_collects_every_label_of_a_type_and_ignores_empty_and_unrelated_labels():
    incident = {"id": "1", "labels": [{"type": "Email/from", "value": "B@x.test"}, {"type": "email_from", "value": "a@x.test"},
                                       {"type": "Email/from", "value": ""}, {"type": "Brand", "value": "other"}, "junk", {"value": "x"}]}
    assert dup.guardian_dup_fingerprint(incident) == {"email_sender": ["a@x.test", "b@x.test"]}


def test_fingerprint_leaves_out_absent_empty_and_unusable_fields():
    incident = {"id": "1", "CustomFields": {"hostname": [], "username": "", "sourceip": None, "url": {"a": 1}, "filehash": True,
                                             "externalid": "EXT-1", "alertdomain": "x"}}
    assert dup.guardian_dup_fingerprint(incident) == {}
    assert dup.guardian_dup_fingerprint({}) == {}


def test_the_external_id_is_not_part_of_the_fingerprint():
    assert dup.guardian_dup_fingerprint({"CustomFields": {"externalid": "A", "hostname": "h1"}}) == {"host": ["h1"]}


def test_the_group_is_the_normalized_type_name_brand_and_instance():
    assert dup.guardian_dup_group({"type": " Phishing ", "name": "A   B\tC", "sourceBrand": "Brand", "sourceInstance": "I-1"}) == (
        "phishing", "a b c", "brand", "i-1")
    assert dup.guardian_dup_group({}) == ("", "", "", "")


# --- the decision ------------------------------------------------------------------------------------------------------

def test_a_duplicate_names_the_lowest_open_match_as_the_original(monkeypatch):
    candidates = [_incident("12"), _incident("15"), _incident("20"), _incident("30")]
    result, rest = _run(monkeypatch, _incident("20"), candidates)
    assert result["is_duplicate"] == "true" and result["original_id"] == "12"
    assert result["matching_open_ids"] == ["12", "15", "30"] and result["open_in_group"] == 4
    assert result["incident_type"] == "Phishing" and result["incident_name"] == "Suspicious email report"
    assert result["incident_id"] == "20" and result["closed"] == "false" and "#12" in result["reason"]
    assert result["fingerprint"] == {"host": ["host-a"]}
    assert rest.closes() == []


def test_the_search_is_one_call_with_the_type_and_name_filter_oldest_first_and_the_size(monkeypatch):
    result, rest = _run(monkeypatch, _incident("20"), [])
    assert len(rest.calls) == 1
    assert rest.calls[0][0] == "getIncidents"
    assert rest.searches()[0] == {"query": 'type:"Phishing" and name:"Suspicious email report" and -status:closed',
                                  "size": 50, "sort": "id.asc"}
    assert result["is_duplicate"] == "false"


def test_the_original_is_not_a_duplicate_and_gets_a_proposal_when_later_incidents_repeat_it(monkeypatch):
    candidates = [_incident("12"), _incident("15"), _incident("16", host="other-host")]
    result, _ = _run(monkeypatch, _incident("12"), candidates)
    assert result["is_duplicate"] == "false" and result["original_id"] == ""
    assert result["matching_open_ids"] == ["15"] and result["open_in_group"] == 2
    proposal = result["proposed_exclusion"]
    assert proposal["incident_type"] == "Phishing" and proposal["incident_name"] == "Suspicious email report"
    assert proposal["scope"] == {"source_brand": "examplebrand", "source_instance": "example-instance", "fingerprint": {"host": ["host-a"]}}
    assert proposal["suggested_review_days"] == 7 and "#15" in proposal["reason"] and "pre-process rule" in proposal["mechanism"]
    assert result["proposed_exclusion_text"].startswith("Consider a pre-process rule or fetch filter")


def test_a_duplicate_carries_a_proposal_phrased_as_a_proposal(monkeypatch):
    result, _ = _run(monkeypatch, _incident("20", username="Bob"), [_incident("12", username="bob")])
    text = result["proposed_exclusion_text"]
    assert "type 'Phishing' named 'Suspicious email report'" in text and "host host-a" in text and "user bob" in text
    assert "#12" in text and "7 days" in text
    assert result["proposed_exclusion"]["scope"]["fingerprint"] == result["fingerprint"]


def test_an_incident_alone_in_its_group_is_not_a_duplicate_and_has_no_proposal(monkeypatch):
    result, _ = _run(monkeypatch, _incident("20"), [_incident("20")])
    assert result["is_duplicate"] == "false" and result["matching_open_ids"] == [] and result["open_in_group"] == 1
    assert result["proposed_exclusion"] == {} and result["proposed_exclusion_text"] == ""
    assert "no other open incident" in result["reason"]


@pytest.mark.parametrize("incident, reason", [
    (_incident("20", kind=""), "no type or no name"),
    (_incident("20", name=""), "no type or no name"),
    (_incident("20", host=None), "none of the host"),
    (_incident("abc"), "not a number"),
])
def test_an_incident_that_cannot_be_compared_fails_open_without_a_search(monkeypatch, incident, reason):
    result, rest = _run(monkeypatch, incident, [_incident("12")])
    assert result["is_duplicate"] == "false" and reason in result["reason"] and rest.calls == []


def test_an_empty_fingerprint_never_matches_even_if_the_candidate_is_empty_too(monkeypatch):
    result = dup.guardian_dup_decide(_incident("20", host=None), [_incident("12", host=None)])
    assert result["is_duplicate"] == "false" and result["open_in_group"] == 1 and "none of the host" in result["reason"]


@pytest.mark.parametrize("kind, name", [('bad"type', "ok"), ("ok", 'bad"name'), ("ok", "bad\\name"), ("ok", "bad\nname"),
                                        ("x" * 201, "ok"), ("ok", "x" * 301)])
def test_a_type_or_name_that_cannot_go_into_a_query_fails_open_without_a_search(monkeypatch, kind, name):
    result, rest = _run(monkeypatch, _incident("20", kind=kind, name=name), [_incident("12", kind=kind, name=name)])
    assert result["is_duplicate"] == "false" and "cannot be used in a search" in result["reason"] and rest.calls == []


def test_a_lookup_error_fails_open(monkeypatch):
    result, rest = _run(monkeypatch, _incident("20"), search_error="HTTP 500 server error")
    assert result["is_duplicate"] == "false" and "lookup" in result["reason"] and "500" in result["reason"]
    assert result["incident_id"] == "20" and len(rest.calls) == 1


@pytest.mark.parametrize("contents", [{"unexpected": 1}, {"data": "text", "total": 1}, {"data": None, "total": 5}, "plain text", [1]])
def test_an_unreadable_search_result_fails_open(monkeypatch, contents):
    result, _ = _run(monkeypatch, _incident("20"), search_contents=contents)
    assert result["is_duplicate"] == "false" and "failed" in result["reason"]


def test_an_empty_search_result_with_a_null_data_list_is_not_an_error(monkeypatch):
    result, _ = _run(monkeypatch, _incident("20"), search_contents={"data": None, "total": 0})
    assert result["is_duplicate"] == "false" and "failed" not in result["reason"]


def test_type_and_name_are_compared_case_and_space_insensitively(monkeypatch):
    candidate = _incident("12", kind="PHISHING", name="  suspicious   EMAIL report ")
    result, _ = _run(monkeypatch, _incident("20"), [candidate])
    assert result["is_duplicate"] == "true" and result["original_id"] == "12"


def test_a_candidate_of_another_type_or_name_is_ignored_even_if_the_search_returned_it(monkeypatch):
    for other in (_incident("12", kind="Malware"), _incident("13", name="Another report")):
        result, _ = _run(monkeypatch, _incident("20"), [other])
        assert result["is_duplicate"] == "false" and result["open_in_group"] == 1 and "no other open incident" in result["reason"]


def test_a_candidate_from_another_source_brand_or_instance_is_not_a_match(monkeypatch):
    for other in (_incident("12", brand="OtherBrand"), _incident("13", instance="other-instance"),
                  _incident("14", brand=None), _incident("15", instance=None)):
        result, _ = _run(monkeypatch, _incident("20"), [other])
        assert result["is_duplicate"] == "false", other


def test_an_incident_without_a_source_matches_only_another_without_one(monkeypatch):
    own = _incident("20", brand=None, instance=None)
    result, _ = _run(monkeypatch, own, [_incident("12")])
    assert result["is_duplicate"] == "false"
    result, _ = _run(monkeypatch, own, [_incident("12", brand=None, instance=None)])
    assert result["is_duplicate"] == "true" and result["original_id"] == "12"


def test_equal_fingerprints_match_whatever_the_field_spelling(monkeypatch):
    candidate = {"id": "12", "type": "Phishing", "name": "Suspicious email report", "sourceBrand": "ExampleBrand",
                 "sourceInstance": "example-instance", "labels": [{"type": "Host Name", "value": "host-a"}]}
    result, _ = _run(monkeypatch, _incident("20"), [candidate])
    assert result["is_duplicate"] == "true" and result["original_id"] == "12"


def test_different_fingerprints_do_not_match(monkeypatch):
    result, _ = _run(monkeypatch, _incident("20"), [_incident("12", host="host-b"), _incident("13", host=None, username="bob")])
    assert result["is_duplicate"] == "false" and "none on the same entities" in result["reason"]


def test_a_fingerprint_that_differs_by_one_extra_field_does_not_match(monkeypatch):
    result, _ = _run(monkeypatch, _incident("20"), [_incident("12", username="bob")])
    assert result["is_duplicate"] == "false"


def test_two_incidents_running_together_never_mark_each_other(monkeypatch):
    candidates = [_incident("30"), _incident("31")]
    first, _ = _run(monkeypatch, _incident("30"), candidates)
    second, _ = _run(monkeypatch, _incident("31"), candidates)
    assert first["is_duplicate"] == "false" and first["open_in_group"] == 2
    assert second["is_duplicate"] == "true" and second["original_id"] == "30"


def test_ids_are_compared_as_numbers_not_text(monkeypatch):
    # "9" sorts after "10" as text, but 9 is the lower number
    result, _ = _run(monkeypatch, _incident("10"), [_incident("9"), _incident("100")])
    assert result["is_duplicate"] == "true" and result["original_id"] == "9"
    assert result["matching_open_ids"] == ["9", "100"]


def test_a_non_numeric_candidate_id_is_listed_but_never_counts_as_lower(monkeypatch):
    result, _ = _run(monkeypatch, _incident("20"), [_incident("abc")])
    assert result["is_duplicate"] == "false" and result["matching_open_ids"] == ["abc"] and result["open_in_group"] == 2


def test_junk_candidates_are_skipped(monkeypatch):
    result, _ = _run(monkeypatch, _incident("20"), ["text", None, 5, {"name": "no id"}, _incident("12")])
    assert result["is_duplicate"] == "true" and result["original_id"] == "12" and result["open_in_group"] == 2


def test_matching_ids_are_capped_at_twenty_but_the_group_count_is_not(monkeypatch):
    candidates = [_incident(str(100 + i)) for i in range(30)]
    result, _ = _run(monkeypatch, _incident("500"), candidates)
    assert len(result["matching_open_ids"]) == 20 and result["matching_open_ids"][0] == "100"
    assert result["open_in_group"] == 31 and result["original_id"] == "100"


@pytest.mark.parametrize("raw, size", [(None, 50), ("", 50), ("abc", 50), ("0", 50), ("-5", 50), ("10", 10), (25, 25), ("100", 100),
                                       ("101", 100), ("100000", 100)])
def test_max_candidates_defaults_to_fifty_and_is_capped_at_one_hundred(monkeypatch, raw, size):
    rest = _install(monkeypatch, _Rest([]))
    dup.guardian_dup_run(_incident("20"), max_candidates=raw)
    assert rest.searches()[0]["size"] == size


def test_a_search_cut_at_its_limit_says_so(monkeypatch):
    result, _ = _run(monkeypatch, _incident("20"), [_incident("12")], total=400)
    assert result["is_duplicate"] == "true" and "cut at its limit" in result["reason"]


# --- closing ---------------------------------------------------------------------------------------------------------------

def test_close_duplicates_links_and_closes_only_this_incident_in_one_native_call(monkeypatch):
    result, rest = _run(monkeypatch, _incident("20"), [_incident("12")], close=True)
    assert result["is_duplicate"] == "true" and result["closed"] == "true" and result["close_error"] == ""
    assert [c for c, _a in rest.calls] == ["getIncidents", "linkIncidents"]
    assert rest.closes() == [{"incidentId": "12", "linkedIncidentIDs": "20", "action": "duplicate"}]


def test_an_incident_the_platform_did_not_close_is_recorded_as_not_closed(monkeypatch):
    result, rest = _run(monkeypatch, _incident("20"), [_incident("12")], close=True, close_contents="0 incidents marked as duplicates")
    assert result["is_duplicate"] == "true" and result["closed"] == "false"
    assert "did not close" in result["close_error"] and "mandatory fields" in result["close_error"]
    assert len(rest.closes()) == 1


def test_a_failed_close_is_recorded_and_never_raises(monkeypatch):
    result, rest = _run(monkeypatch, _incident("20"), [_incident("12")], close=True, close_error="Error in API call [400] - bad status")
    assert result["is_duplicate"] == "true" and result["closed"] == "false" and "400" in result["close_error"]
    assert len(rest.closes()) == 1


def test_a_close_that_raises_is_recorded(monkeypatch):
    rest = _install(monkeypatch, _Rest([_incident("12")]))

    def fake(command, args):
        if command == "linkIncidents":
            raise RuntimeError("boom")
        return rest(command, args)

    monkeypatch.setattr(dup.demisto, "executeCommand", fake)
    result = dup.guardian_dup_run(_incident("20"), close=True)
    assert result["closed"] == "false" and "boom" in result["close_error"]


def test_nothing_is_changed_for_an_original_or_when_close_is_off(monkeypatch):
    _, rest = _run(monkeypatch, _incident("12"), [_incident("12"), _incident("20")], close=True)
    assert rest.closes() == []
    _, rest = _run(monkeypatch, _incident("20"), [_incident("12")], close=False)
    assert rest.closes() == []


def test_nothing_is_changed_when_the_check_failed_open(monkeypatch):
    _, rest = _run(monkeypatch, _incident("20"), search_error="HTTP 500", close=True)
    assert rest.closes() == []
    _, rest = _run(monkeypatch, _incident("20", host=None), [_incident("12", host=None)], close=True)
    assert rest.calls == []


@pytest.mark.parametrize("raw, expected", [("true", True), ("True", True), (" YES ", True), ("1", True), ("false", False), ("", False),
                                           (None, False), ("no", False)])
def test_close_duplicates_is_read_as_a_flag(raw, expected):
    assert dup.guardian_dup_truthy(raw) is expected


# --- main: the context ---------------------------------------------------------------------------------------------------

class _Context:
    def __init__(self, monkeypatch, incident, args, rest):
        self.writes, self.results = [], []
        monkeypatch.setattr(dup.demisto, "incident", lambda: incident)
        monkeypatch.setattr(dup.demisto, "args", lambda: args)
        monkeypatch.setattr(dup.demisto, "executeCommand", rest)
        monkeypatch.setattr(dup.demisto, "error", lambda msg: None)
        monkeypatch.setattr(dup.demisto, "setContext", lambda path, value: self.writes.append((path, value)))
        monkeypatch.setattr(dup, "return_results", lambda value: self.results.append(value))


def test_main_empties_the_context_first_then_writes_the_answer_and_returns_it_keyed_by_the_incident(monkeypatch):
    ctx = _Context(monkeypatch, _incident("20"), {"close_duplicates": "false"}, _Rest([_incident("12")]))
    dup.main()
    assert ctx.writes[0] == ("Guardian.Duplicate", {})
    path, final = ctx.writes[-1]
    assert path == "Guardian.Duplicate" and final["is_duplicate"] == "true" and final["original_id"] == "12"
    assert len(ctx.writes) == 2
    command_result = ctx.results[0]
    assert command_result.outputs_prefix == "Guardian.Duplicate" and command_result.outputs_key_field == "incident_id"
    assert command_result.outputs == final
    assert "duplicate" in command_result.readable_output and "#12" in command_result.readable_output
    assert "Proposed exclusion" in command_result.readable_output


def test_main_on_an_unexpected_error_still_ends_with_a_fail_open_answer_and_no_error_entry(monkeypatch):
    ctx = _Context(monkeypatch, _incident("20"), {}, _Rest([]))
    monkeypatch.setattr(dup, "guardian_dup_run", lambda *a, **k: (_ for _ in ()).throw(ValueError("odd")))
    called = []
    monkeypatch.setattr(dup, "return_error", lambda msg: called.append(msg))
    dup.main()
    assert called == []
    assert ctx.writes[0] == ("Guardian.Duplicate", {})
    final = ctx.writes[-1][1]
    assert final["is_duplicate"] == "false" and "unexpectedly" in final["reason"] and final["incident_id"] == "20"
    assert ctx.results[0].outputs["is_duplicate"] == "false"


def test_main_leaves_no_stale_answer_when_the_context_write_itself_fails(monkeypatch):
    ctx = _Context(monkeypatch, _incident("20"), {}, _Rest([]))

    def broken(path, value):
        raise RuntimeError("no context")

    monkeypatch.setattr(dup.demisto, "setContext", broken)
    dup.main()  # must not raise
    assert ctx.results[0].outputs["is_duplicate"] == "false"


def test_main_with_close_duplicates_true_passes_it_through(monkeypatch):
    rest = _Rest([_incident("12")])
    ctx = _Context(monkeypatch, _incident("20"), {"close_duplicates": "true", "max_candidates": "5"}, rest)
    dup.main()
    assert ctx.writes[-1][1]["closed"] == "true" and len(rest.closes()) == 1
    assert rest.searches()[0]["size"] == 5
    assert "closed" in ctx.results[0].readable_output


def test_the_readable_output_for_each_outcome(monkeypatch):
    original, _ = _run(monkeypatch, _incident("12"), [_incident("15")])
    assert dup.guardian_dup_readable(original).startswith("Duplicate check: **original** of 2 open incidents.")
    plain, _ = _run(monkeypatch, _incident("12"), [])
    assert dup.guardian_dup_readable(plain).startswith("Duplicate check: not a duplicate.")
    failed, _ = _run(monkeypatch, _incident("20"), [_incident("12")], close=True, close_error="denied")
    assert "Closing this incident failed: denied" in dup.guardian_dup_readable(failed)
    closed, _ = _run(monkeypatch, _incident("20"), [_incident("12")], close=True)
    assert "linked to #12 and closed as a duplicate" in dup.guardian_dup_readable(closed)
