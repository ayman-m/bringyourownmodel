import json

import pytest

import GuardianXQL as xql

REPO = __import__("pathlib").Path(__file__).resolve().parents[2]
SHIPPED = json.loads((REPO / "Lists" / "list-guardian_xql_templates.json").read_text())["data"]


class Fake:
    """``results`` are the replies xdr-xql-get-query-results gives, one per call (the last one repeats)."""

    def __init__(self, reply=None, error=None, templates=SHIPPED, results=None, results_error=None):
        self.calls, self.reply, self.error, self.templates = [], reply, error, templates
        self.results, self.results_error = list(results or []), results_error

    @staticmethod
    def _entry(reply):
        return [{"Type": 1, "Contents": "x", "EntryContext": {"PaloAltoNetworksXQL.GenericQuery(val.execution_id == obj.execution_id)": reply}}]

    def __call__(self, command, args):
        self.calls.append((command, dict(args)))
        if command == "getList":
            return [{"Type": 1, "Contents": self.templates}] if self.templates else [{"Type": 4, "Contents": "Item not found"}]
        if command == "xdr-xql-get-query-results":
            if self.results_error:
                return [{"Type": 4, "Contents": self.results_error}]
            return self._entry(self.results.pop(0) if len(self.results) > 1 else self.results[0])
        if self.error:
            return [{"Type": 4, "Contents": self.error}]
        return self._entry(self.reply)

    def query_calls(self):
        return [a for c, a in self.calls if c == "xdr-xql-generic-query"]

    def result_calls(self):
        return [a for c, a in self.calls if c == "xdr-xql-get-query-results"]


REPLY = {"status": "SUCCESS", "number_of_results": 2, "query_cost": 0.001, "remaining_quota": 4.8,
         "results": [{"operation_name": "a", "events": 3}, {"operation_name": "b", "events": 1}]}


@pytest.fixture
def tenant(monkeypatch):
    def make(**kw):
        fake = Fake(**kw)
        monkeypatch.setattr(xql.demisto, "executeCommand", fake)
        return fake
    return make


def test_identity_activity_runs_the_filled_query_and_reports_cost(tenant):
    fake = tenant(reply=REPLY)
    out = xql.guardian_xql_run("identity_activity", {"identity": "alice@example.test"}, run_id="55", sequence=2)
    call = fake.query_calls()[0]
    assert 'filter (lowercase(identity_name) = "alice@example.test" or lowercase(identity_uuid) = "alice@example.test")' in call["query"]
    assert "contains" not in call["query"] and "~=" not in call["query"]  # a UPN is matched exactly, never as a substring
    assert call["time_frame"] == "6 hours" and call["query_name"] == "guardian-55-2"
    assert out["query_cost"] == 0.001 and out["remaining_quota"] == 4.8 and out["number_of_results"] == 2
    assert out["rows"][0]["operation_name"] == "a" and "error" not in out


@pytest.mark.parametrize("bad", ['x" | limit 1 | filter "y', "a|b", "a;b", "a`b", "{identity}", "line\nbreak", "", None,
                                 "a\\b\\c", "\\b", "a\\", "my domain\\b", 'dom\\x"y', "dom\\x|y"])
def test_unsafe_or_missing_values_never_reach_the_query(tenant, bad):
    fake = tenant(reply=REPLY)
    out = xql.guardian_xql_run("identity_activity", {"identity": bad})
    assert "error" in out and fake.query_calls() == []


@pytest.mark.parametrize("given, account", [
    ("x-lab\\jane.doe", "jane.doe"),
    (" CORP.example\\Jane.Doe ", "jane.doe"),
    ("CORP\\svc-app$", "svc-app$"),
    ("a\\b", "b"),
])
def test_a_domain_account_is_matched_by_the_upn_local_part_with_a_split_not_a_regex(tenant, given, account):
    """The audit log carries UPNs (`account@org-domain`), so `DOMAIN\\account` can only match on the part before the `@`:
    an exact, lowercased comparison of the split local part. A regex with escaped metacharacters parsed on a real tenant
    but matched nothing, so no regex and no escaping is used."""
    fake = tenant(reply=REPLY)
    out = xql.guardian_xql_run("identity_activity", {"identity": given})
    assert "error" not in out
    query = fake.query_calls()[0]["query"]
    assert 'filter arrayindex(split(lowercase(identity_name), "@"), 0) = "{}" |'.format(account) in query
    assert "~=" not in query and "contains" not in query and "identity_uuid" not in query
    assert query == out["query"]
    # the domain text never reaches the query, and the account needs no escaping: not one backslash in the query
    assert given.strip().split("\\")[0] + "\\" not in query and 'identity_name = "' not in query
    assert "\\" not in query
    assert "Matched by account name {} across all domains; check identity_name.".format(account) in out["advisory"]


@pytest.mark.parametrize("bad", ['CORP\\svc"app', 'CORP\\"', "CORP\\a\\b"])
def test_a_domain_account_with_a_quote_or_backslash_is_refused_not_escaped(tenant, bad):
    fake = tenant(reply=REPLY)
    out = xql.guardian_xql_run("identity_activity", {"identity": bad})
    assert "error" in out and fake.query_calls() == []


@pytest.mark.parametrize("account", ['svc"app', "svc\\app", 'a\\"b'])
def test_the_account_query_helper_refuses_a_quote_or_backslash_in_the_account(monkeypatch, account):
    # defence in depth: even if the identity check ever let one through, this path refuses it with a message
    monkeypatch.setattr(xql, "guardian_xql_check_value", lambda name, value: ("CORP\\\\" + account, None))
    template = {"params": ["identity"], "account_query": 'filter x = "{account}"'}
    query, found, error = xql.guardian_xql_account_query(template, {"identity": "CORP\\x"})
    assert query is None and found == "" and "double quote or a backslash" in error


def test_a_upn_or_plain_name_gets_no_account_note_and_no_split(tenant):
    fake = tenant(reply=REPLY)
    out = xql.guardian_xql_run("identity_activity", {"identity": "Alice@Example.test"})
    assert "~=" not in fake.query_calls()[0]["query"] and out["advisory"] == []
    out = xql.guardian_xql_run("identity_activity", {"identity": "00000000-0000-0000-0000-000000000001"})
    assert 'lowercase(identity_uuid) = "00000000-0000-0000-0000-000000000001"' in fake.query_calls()[1]["query"]


def test_the_domain_account_split_applies_to_identity_activity_only(tenant):
    # the permissions template has no account_query: it keeps the escaped DOMAIN\\account literal
    fake = tenant(reply=REPLY)
    xql.guardian_xql_run("identity_unused_permissions", {"identity": "CORP\\svc-reporting"})
    query = fake.query_calls()[0]["query"]
    assert 'source_cloud_resource_name contains "CORP\\\\svc-reporting"' in query and "~=" not in query


@pytest.mark.parametrize("single, doubled", [
    ("x-lab\\sameh", "x-lab\\\\sameh"), ("CORP.example\\svc_backup", " CORP.example\\\\svc_backup "),
    ("CORP\\WS-01$", "CORP\\\\WS-01$"),
])
def test_a_double_escaped_domain_account_is_the_same_account(tenant, single, doubled):
    # a model that already escaped the backslash must get the identical query, not a refusal and not four backslashes
    fake = tenant(reply=REPLY)
    xql.guardian_xql_run("identity_activity", {"identity": single})
    xql.guardian_xql_run("identity_activity", {"identity": doubled})
    plain, escaped = [c["query"] for c in fake.query_calls()]
    assert plain == escaped
    assert "\\\\\\" not in escaped


@pytest.mark.parametrize("bad", [
    "dom\\\\\\x", "dom\\\\\\\\x",                  # three or four backslashes in a row
    "dom\\\\", "\\\\x", "\\\\",                    # an empty side
    "dom\\\\x\\\\y", "dom\\\\x\\y", "dom\\x\\\\y",  # a second separator, doubled or not
    'dom\\\\x"y', 'dom\\\\"x', "dom\\\\x|y", "dom\\\\x;y", "dom\\\\x`y", "dom\\\\x y", "dom\\\\{x}",  # unsafe next to a doubled one
])
def test_a_doubled_backslash_does_not_open_the_door_to_anything_else(tenant, bad):
    fake = tenant(reply=REPLY)
    out = xql.guardian_xql_run("identity_activity", {"identity": bad})
    assert "error" in out and fake.query_calls() == []


def test_a_doubled_backslash_is_still_refused_for_resource_and_ip(tenant):
    fake = tenant(reply=REPLY)
    assert "error" in xql.guardian_xql_run("resource_change_history", {"resource": "dom\\\\res"})
    assert "error" in xql.guardian_xql_run("resource_access_activity", {"resource": "dom\\\\res"})
    assert "error" in xql.guardian_xql_run("ip_activity", {"ip": "1.2.3.4\\\\5"})
    assert fake.query_calls() == []


def test_a_plain_name_or_address_is_unchanged(tenant):
    fake = tenant(reply=REPLY)
    xql.guardian_xql_run("identity_activity", {"identity": "alice@example.test"})
    assert "\\" not in fake.query_calls()[0]["query"]


@pytest.mark.parametrize("bad", ["a\\b\\c", "\\b", "a\\", "my domain\\b", "dom\\us er", 'dom\\x"y', 'dom"\\x', "dom\\x|y", "dom\\x;y",
                                 "dom\\x`y", "dom\\{x}", "dom\\x\ny", "dom$\\x", "dom\\x@y", "dom\\x\\"])
def test_injection_through_a_domain_account_is_still_refused(tenant, bad):
    fake = tenant(reply=REPLY)
    out = xql.guardian_xql_run("identity_activity", {"identity": bad})
    assert "error" in out and fake.query_calls() == []


def test_only_the_identity_value_may_carry_a_backslash(tenant):
    fake = tenant(reply=REPLY)
    assert "error" in xql.guardian_xql_run("resource_change_history", {"resource": "dom\\res"})
    assert "error" in xql.guardian_xql_run("ip_activity", {"ip": "1.2.3.4\\5"})
    assert "error" in xql.guardian_xql_run("resource_access_activity", {"resource": "dom\\res"})
    assert fake.query_calls() == []


def test_ip_must_look_like_an_address(tenant):
    fake = tenant(reply=REPLY)
    assert "error" in xql.guardian_xql_run("ip_activity", {"ip": "evil.example.test"})
    assert "error" in xql.guardian_xql_run("ip_activity", {"ip": "1.2.3.4 or 1=1"})
    out = xql.guardian_xql_run("ip_activity", {"ip": "2001:db8::1"}, hours=24)
    assert "error" not in out and fake.query_calls()[0]["time_frame"] == "24 hours"


def test_a_longer_window_is_allowed_with_a_note_and_nothing_blocks(tenant):
    fake = tenant(reply=REPLY)
    out = xql.guardian_xql_run("identity_activity", {"identity": "a"}, hours=500)
    assert fake.query_calls()[0]["time_frame"] == "500 hours"
    assert any("longer than this template's usual maximum" in n for n in out["advisory"])
    out = xql.guardian_xql_run("identity_activity", {"identity": "a"}, hours=999999)
    assert fake.query_calls()[-1]["time_frame"] == "2160 hours"


@pytest.mark.parametrize("hours", ["abc", "0", "-3"])
def test_bad_hours_is_an_error(tenant, hours):
    tenant(reply=REPLY)
    assert "error" in xql.guardian_xql_run("identity_activity", {"identity": "a"}, hours=hours)


def test_list_describes_the_templates(tenant):
    tenant()
    out = xql.guardian_xql_run("list", {})
    names = [t["name"] for t in out["templates"]]
    assert {"identity_activity", "resource_change_history", "ip_activity", "identity_unused_permissions"} <= set(names)


def test_unknown_template_names_the_available_ones_and_the_raw_fallback(tenant):
    tenant()
    out = xql.guardian_xql_run("nope", {})
    assert "identity_activity" in out["error"] and "query=" in out["error"]


def test_a_failed_query_returns_the_platform_error_to_the_model(tenant):
    tenant(error="Field 'foo' does not exist in dataset api_key=sk-secretsecretsecret123")
    out = xql.guardian_xql_run("identity_unused_permissions", {"identity": "role-a"})
    assert "does not exist" in out["error"] and "sk-secretsecretsecret123" not in out["error"]


def test_quota_spent_error_is_passed_on(tenant):
    tenant(error="QUOTA_EXCEEDED: query usage exceeded max daily quota")
    assert "QUOTA_EXCEEDED" in xql.guardian_xql_run("ip_activity", {"ip": "1.2.3.4"})["error"]


def test_missing_template_list_is_a_clear_error(tenant):
    tenant(templates=None)
    assert "could not read" in xql.guardian_xql_run("ip_activity", {"ip": "1.2.3.4"})["error"]


def test_rows_are_capped(tenant):
    tenant(reply=dict(REPLY, results=[{"i": i} for i in range(250)], number_of_results=250))
    out = xql.guardian_xql_run("ip_activity", {"ip": "1.2.3.4"})
    assert len(out["rows"]) == 100 and any("first 100 of 250" in n for n in out["advisory"])


def test_a_non_success_status_is_reported(tenant):
    tenant(reply=dict(REPLY, status="FAIL"))
    assert "FAIL" in xql.guardian_xql_run("ip_activity", {"ip": "1.2.3.4"})["error"]


def test_advisory_for_the_issues_view():
    assert xql.guardian_xql_advisories("dataset = issues | limit 1")
    assert xql.guardian_xql_advisories("dataset  =  Cases | limit 1")
    assert not xql.guardian_xql_advisories("dataset = cloud_audit_logs | limit 1")


def test_shipped_templates_are_well_formed():
    templates = xql.guardian_xql_parse_templates(SHIPPED)
    assert len(templates) >= 4
    for t in templates:
        stripped = t["query"]
        for param in t["params"]:
            assert "{" + param + "}" in t["query"] or "{" + param + "_lc}" in t["query"]
            stripped = stripped.replace("{" + param + "_lc}", "").replace("{" + param + "}", "")
        assert "{" not in stripped
        assert t["query"].startswith("dataset = ") and t["default_hours"] <= t["max_hours"]


def test_cost_reported_as_a_dict_keyed_by_execution_id_is_summed(tenant):
    tenant(reply=dict(REPLY, query_cost={"2209": 0.001, "2210": 0.0005}))
    assert xql.guardian_xql_run("ip_activity", {"ip": "1.2.3.4"})["query_cost"] == 0.0015
    tenant(reply={k: v for k, v in dict(REPLY, query_cost_charged={"1": 0.002}).items() if k != "query_cost"})
    assert xql.guardian_xql_run("ip_activity", {"ip": "1.2.3.4"})["query_cost"] == 0.002


# A query that is still running: the reply the tenant gave a script (2026-10-10), with the ids replaced.
PENDING = {"status": "PENDING", "execution_id": "1111_inv", "number_of_results": 0, "query_name": "guardian-55-2"}
NO_SLEEP = {"sleep": lambda seconds: None}


def test_a_pending_query_is_polled_until_it_has_rows(tenant):
    fake = tenant(reply=dict(PENDING, query_cost=0.001), results=[PENDING, dict(REPLY, query_cost=None)])
    out = xql.guardian_xql_run("identity_activity", {"identity": "alice@example.test"}, **NO_SLEEP)
    assert out["status"] == "SUCCESS" and out["number_of_results"] == 2 and "error" not in out
    assert fake.result_calls() == [{"query_id": "1111_inv"}, {"query_id": "1111_inv"}] and len(fake.query_calls()) == 1
    assert out["query_cost"] == 0.001  # the final reply did not say, so the first reply's cost is kept


def test_a_query_still_running_returns_its_execution_id(tenant):
    fake = tenant(reply=PENDING, results=[PENDING])
    out = xql.guardian_xql_run("identity_activity", {"identity": "a"}, **NO_SLEEP)
    assert len(fake.result_calls()) == xql.GUARDIAN_XQL_POLL_ATTEMPTS
    assert out["execution_id"] == "1111_inv" and "execution_id=1111_inv" in out["error"] and "costs nothing" in out["error"]
    assert out["rows"] == []


def test_a_failed_poll_is_reported(tenant):
    tenant(reply=PENDING, results_error="Query id not found")
    assert "Query id not found" in xql.guardian_xql_run("identity_activity", {"identity": "a"}, **NO_SLEEP)["error"]


def test_execution_id_fetches_without_starting_a_query(tenant):
    fake = tenant(reply=REPLY, results=[REPLY])
    out = xql.guardian_xql_run("", {}, execution_id="1111_inv", **NO_SLEEP)
    assert fake.query_calls() == [] and fake.result_calls() == [{"query_id": "1111_inv"}]
    assert out["number_of_results"] == 2 and out["template"] == "results"


def test_a_raw_query_runs_as_written_with_no_limits(tenant):
    fake = tenant(reply=REPLY)
    raw = 'dataset = cloud_audit_logs | filter identity_name = "a" | comp count() by operation_name'
    out = xql.guardian_xql_run("", {}, query=raw)
    assert fake.query_calls()[0]["query"] == raw and fake.query_calls()[0]["time_frame"] == "24 hours"
    assert out["template"] == "raw" and "error" not in out
    xql.guardian_xql_run("", {}, query=raw, hours=5000)
    assert fake.query_calls()[-1]["time_frame"] == "5000 hours"
    assert xql.guardian_xql_run("", {}, query="dataset = issues | limit 1")["advisory"]


def test_the_war_room_shows_the_templates_and_the_first_rows(tenant):
    tenant(reply=REPLY)
    listing = xql.guardian_xql_readable(xql.guardian_xql_run("list", {}))
    assert "identity_activity" in listing and "identity_unused_permissions" in listing
    run = xql.guardian_xql_readable(xql.guardian_xql_run("ip_activity", {"ip": "1.2.3.4"}))
    assert "2 row(s), cost 0.001 compute units, 4.8 left today" in run and "operation_name" in run


def test_resource_access_activity_template_lists_who_only_read_the_resource(tenant):
    fake = tenant(reply=REPLY)
    out = xql.guardian_xql_run("resource_access_activity", {"resource": "stg-prod-01"}, run_id="55", sequence=1)
    query = fake.query_calls()[0]["query"]
    assert 'lowercase(referenced_resource_name) = "stg-prod-01"' in query and 'state_changing_event = "false"' in query
    assert "by identity_name, identity_type" in query and query.endswith("limit 50")
    assert out["template"] == "resource_access_activity" and out["hours"] == 24
    by_name = {t["name"]: t for t in xql.guardian_xql_parse_templates(SHIPPED)}
    assert by_name["resource_access_activity"]["params"] == ["resource"] and by_name["resource_access_activity"]["max_hours"] == 168
    # on this platform state_changing_event is a string, so the value is quoted like resource_change_history's
    assert 'state_changing_event = "true"' in by_name["resource_change_history"]["query"]
    assert "resource_access_activity" in [t["name"] for t in xql.guardian_xql_run("list", {})["templates"]]


_FULL_ID = "/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/rg-example/providers/microsoft.network/routetables/rt-example"


@pytest.mark.parametrize("value", ["rt-example", _FULL_ID])
def test_resource_templates_match_the_full_id_or_the_short_name_with_equals(tenant, value):
    fake = tenant(reply=REPLY)
    for template in ("resource_change_history", "resource_access_activity"):
        xql.guardian_xql_run(template, {"resource": value}, run_id="55", sequence=1)
    change, access = [c["query"] for c in fake.query_calls()]
    match = '(lowercase(referenced_resource) = "{0}" or lowercase(referenced_resource_name) = "{0}")'.format(value.lower())
    assert "| filter " + match + ' and state_changing_event = "true" |' in change
    # reads can carry a null state_changing_event, so the read template accepts null as well as "false"
    assert "| filter " + match + ' and (state_changing_event = "false" or state_changing_event = null) |' in access
    for query in (change, access):
        assert "contains" not in query and "case_sensitive" not in query


# --- anchor_time ----------------------------------------------------------------------------------------------------

from datetime import datetime, timezone

NOW = datetime(2026, 1, 2, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def clock(monkeypatch):
    monkeypatch.setattr(xql, "guardian_xql_now", lambda: NOW)


def test_without_an_anchor_the_window_counts_back_from_now(tenant, clock):
    fake = tenant(reply=REPLY)
    out = xql.guardian_xql_run("identity_activity", {"identity": "alice@example.test"})
    assert fake.query_calls()[0]["time_frame"] == "6 hours" and "window" not in out
    xql.guardian_xql_run("", {}, query='dataset = cloud_audit_logs | filter identity_name = "a" | limit 1', hours=3, anchor_time="")
    assert fake.query_calls()[1]["time_frame"] == "3 hours"


def test_an_anchor_gives_the_verified_between_window_for_a_template(tenant, clock):
    fake = tenant(reply=REPLY)
    out = xql.guardian_xql_run("identity_activity", {"identity": "alice@example.test"}, anchor_time="2026-01-01T03:04:05.678Z")
    # [anchor - 6 h, anchor + 1 h], whole seconds, UTC
    assert fake.query_calls()[0]["time_frame"] == "between 2025-12-31 21:04:05 +00:00 and 2026-01-01 04:04:05 +00:00"
    assert out["window"] == fake.query_calls()[0]["time_frame"] and out["anchor_time"] == "2026-01-01T03:04:05Z"
    assert any("Window anchored on 2026-01-01 03:04:05" in note for note in out["advisory"])
    assert "error" not in out and out["number_of_results"] == 2


def test_the_window_end_never_passes_now(tenant, clock):
    fake = tenant(reply=REPLY)
    xql.guardian_xql_run("resource_change_history", {"resource": "rt-example"}, anchor_time="2026-01-02T11:30:00Z", hours=2)
    assert fake.query_calls()[0]["time_frame"] == "between 2026-01-02 09:30:00 +00:00 and 2026-01-02 12:00:00 +00:00"


def test_an_anchor_in_the_future_is_an_error_and_no_query_runs(tenant, clock):
    fake = tenant(reply=REPLY)
    out = xql.guardian_xql_run("identity_activity", {"identity": "a"}, anchor_time="2026-01-09T00:00:00Z")
    assert "future" in out["error"] and fake.query_calls() == []


def test_an_anchor_later_than_now_with_a_window_start_in_the_past_runs_and_says_it_was_clamped(tenant, clock):
    fake = tenant(reply=REPLY)
    out = xql.guardian_xql_run("identity_activity", {"identity": "a"}, anchor_time="2026-01-02T14:00:00Z")
    assert "error" not in out
    assert fake.query_calls()[0]["time_frame"] == "between 2026-01-02 08:00:00 +00:00 and 2026-01-02 12:00:00 +00:00"
    assert "anchor_time is in the future; the window is clamped to now." in out["advisory"]
    # an anchor in the past carries no such line
    past = xql.guardian_xql_run("identity_activity", {"identity": "a"}, anchor_time="2026-01-01T12:00:00Z")
    assert not any("future" in note for note in past["advisory"])


@pytest.mark.parametrize("anchor, expected_start", [
    ("2026-01-01T12:00:00Z", "2026-01-01 06:00:00"),
    ("2026-01-01T14:00:00+02:00", "2026-01-01 06:00:00"),     # an offset is converted to UTC
    ("2026-01-01T12:00:00", "2026-01-01 06:00:00"),           # no zone: UTC
    (1767268800, "2026-01-01 06:00:00"),                      # epoch seconds (int)
    ("1767268800", "2026-01-01 06:00:00"),                    # epoch seconds (text)
    (1767268800000, "2026-01-01 06:00:00"),                   # epoch milliseconds
    ("1767268800000", "2026-01-01 06:00:00"),
])
def test_anchor_formats(tenant, clock, anchor, expected_start):
    fake = tenant(reply=REPLY)
    out = xql.guardian_xql_run("identity_activity", {"identity": "a"}, anchor_time=anchor)
    assert "error" not in out
    assert fake.query_calls()[0]["time_frame"] == "between {} +00:00 and 2026-01-01 13:00:00 +00:00".format(expected_start)


@pytest.mark.parametrize("bad", ["yesterday", "2026-13-45", "0001-01-01T00:00:00Z", "12:00", "1e5", True, {"a": 1}])
def test_an_unreadable_anchor_is_a_clear_error_and_no_query_runs(tenant, clock, bad):
    fake = tenant(reply=REPLY)
    out = xql.guardian_xql_run("identity_activity", {"identity": "a"}, anchor_time=bad)
    assert "anchor_time" in out["error"] and "ISO-8601" in out["error"] and fake.query_calls() == []
    out = xql.guardian_xql_run("", {}, query="dataset = cloud_audit_logs | limit 1", anchor_time=bad)
    assert "anchor_time" in out["error"] and fake.query_calls() == []


def test_a_raw_query_is_anchored_too(tenant, clock):
    fake = tenant(reply=REPLY)
    out = xql.guardian_xql_run("", {}, query='dataset = cloud_audit_logs | filter identity_name = "a" | limit 1',
                               hours=24, anchor_time="2026-01-01T12:00:00Z")
    assert fake.query_calls()[0]["time_frame"] == "between 2025-12-31 12:00:00 +00:00 and 2026-01-01 13:00:00 +00:00"
    assert out["template"] == "raw" and out["window"] == fake.query_calls()[0]["time_frame"]


def test_an_anchor_is_ignored_when_fetching_an_earlier_query(tenant, clock):
    fake = tenant(reply=REPLY, results=[REPLY])
    out = xql.guardian_xql_run("", {}, execution_id="abc", anchor_time="not a time")
    assert "anchor_time" not in out.get("error", "") and fake.query_calls() == []


def test_the_yml_documents_the_anchor_argument():
    import yaml
    doc = yaml.safe_load((REPO / "Scripts" / "GuardianXQL" / "GuardianXQL.yml").read_text())
    arg = {a["name"]: a for a in doc["args"]}["anchor_time"]
    assert arg["required"] is False and "event time" in " ".join(arg["description"].split())


_MIXED_ID = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/RG-Example/providers/Microsoft.Network/routeTables/RT-Example"


def test_a_mixed_case_resource_or_identity_is_compared_in_lower_case_on_both_sides(tenant):
    """Stored `referenced_resource` values are lowercase while the ids an issue or a model carries are often mixed-case,
    so the template lowercases the field and the value: `lowercase(field) = "<lowercase value>"`."""
    fake = tenant(reply=REPLY)
    for template in ("resource_change_history", "resource_access_activity"):
        xql.guardian_xql_run(template, {"resource": _MIXED_ID}, run_id="55", sequence=1)
    xql.guardian_xql_run("identity_activity", {"identity": "Alice@Example.TEST"}, run_id="55", sequence=1)
    change, access, identity = [c["query"] for c in fake.query_calls()]
    low = _MIXED_ID.lower()
    for query in (change, access):
        assert '(lowercase(referenced_resource) = "{0}" or lowercase(referenced_resource_name) = "{0}")'.format(low) in query
        assert "RG-Example" not in query and "{resource" not in query
    assert '(lowercase(identity_name) = "alice@example.test" or lowercase(identity_uuid) = "alice@example.test")' in identity
    assert "Alice" not in identity and "{identity" not in identity


def test_the_shipped_templates_never_compare_these_fields_with_a_bare_equals():
    for template in xql.guardian_xql_parse_templates(SHIPPED):
        for field in ("referenced_resource", "referenced_resource_name", "identity_name", "identity_uuid"):
            assert (field + " =") not in template["query"].replace("lowercase(" + field + ")", ""), (template["name"], field)


_LONG_VMSS_ID = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/rg-example-" + "x" * 50 +
                 "/providers/microsoft.compute/virtualmachinescalesets/vmss-example-" + "y" * 50 + "/virtualmachines/12")


def test_a_long_resource_id_reaches_the_query_intact(tenant):
    assert 250 <= len(_LONG_VMSS_ID) <= 270
    fake = tenant(reply=REPLY)
    for template in ("resource_change_history", "resource_access_activity"):
        out = xql.guardian_xql_run(template, {"resource": _LONG_VMSS_ID}, run_id="55", sequence=1)
        assert "error" not in out
    for query in [c["query"] for c in fake.query_calls()]:
        assert 'lowercase(referenced_resource) = "{0}" or lowercase(referenced_resource_name) = "{0}"'.format(_LONG_VMSS_ID) in query


def test_the_value_cap_matches_the_triage_cap_and_still_refuses_longer_values(tenant):
    assert xql.GUARDIAN_XQL_MAX_VALUE_LEN == xql.GUARDIAN_TRIAGE_ENTITY_MAX_CHARS == 512
    fake = tenant(reply=REPLY)
    at_cap = "/subscriptions/" + "a" * (512 - len("/subscriptions/"))
    assert "error" not in xql.guardian_xql_run("resource_change_history", {"resource": at_cap})
    for name, values, template in (("resource", {"resource": at_cap + "b"}, "resource_change_history"),
                                   ("identity", {"identity": "a" * 513}, "identity_activity")):
        out = xql.guardian_xql_run(template, values)
        assert "longer than 512 characters" in out["error"] and name in out["error"]
    assert len(fake.query_calls()) == 1


def test_the_yml_names_every_shipped_template():
    text = (REPO / "Scripts" / "GuardianXQL" / "GuardianXQL.yml").read_text()
    for template in xql.guardian_xql_parse_templates(SHIPPED):
        assert template["name"] in text, template["name"]


def test_context_key_redirects_the_result_and_is_checked(monkeypatch):
    assert xql.guardian_xql_context_prefix("") == ("Guardian.XQL", "")
    assert xql.guardian_xql_context_prefix(None) == ("Guardian.XQL", "")
    assert xql.guardian_xql_context_prefix("Guardian.Enrich.IdentityActivity") == ("Guardian.Enrich.IdentityActivity", "")
    for bad in ("Guardian.Loop", "Guardian.Enrich", "Guardian.Enrich.", "Core.Issue", "Guardian.Enrich.a.b", "Guardian.Enrich.x y", "Guardian.XQL"):
        prefix, error = xql.guardian_xql_context_prefix(bad)
        assert prefix == "Guardian.XQL" and "Guardian.Enrich" in error, bad
    results, errors = [], []
    monkeypatch.setattr(xql.demisto, "args", lambda: {"template": "ip_activity", "ip": "1.2.3.4", "context_key": "Guardian.Enrich.IpActivity"})
    monkeypatch.setattr(xql.demisto, "incident", lambda: {"id": "7"})
    monkeypatch.setattr(xql.demisto, "executeCommand", Fake(reply=REPLY))
    monkeypatch.setattr(xql, "return_results", results.append)
    monkeypatch.setattr(xql, "return_error", errors.append)
    xql.main()
    assert not errors and results[0].outputs_prefix == "Guardian.Enrich.IpActivity"
    monkeypatch.setattr(xql.demisto, "args", lambda: {"template": "ip_activity", "ip": "1.2.3.4"})
    xql.main()
    assert results[1].outputs_prefix == "Guardian.XQL"
    monkeypatch.setattr(xql.demisto, "args", lambda: {"template": "ip_activity", "ip": "1.2.3.4", "context_key": "Guardian.Loop"})
    xql.main()
    assert errors and "context_key" in errors[0] and len(results) == 2
