import json

import GuardianWidgetApprovalsQueue as gwaq


# --- fixtures / test harness --------------------------------------------------


def _entries(contents):
    return [{"Type": 1, "Contents": contents}]


def _not_found(list_name):
    return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(list_name)}]


NOW = "2026-07-05T12:00:00Z"

SAMPLE_ROWS = [
    {
        "approval_id": "aaaaaaaa1111",
        "kind": "tool",
        "incident_id": "100",
        "tool_name": "closeInvestigation",
        "risk_tier": "hard",
        "status": "pending",
        "created_ts": "2026-07-05T11:30:00Z",  # 30 min old
    },
    {
        "approval_id": "bbbbbbbb2222",
        "kind": "plan",
        "incident_id": "101",
        "summary": "Contain host X",
        "steps": [{"tool_name": "ip"}, {"tool_name": "closeInvestigation"}],
        "risk_tier": "soft",
        "status": "pending",
        "created_ts": "2026-07-05T10:00:00Z",  # 120 min old -- oldest
    },
    {
        "approval_id": "cccccccc3333",
        "kind": "tool",
        "incident_id": "102",
        "tool_name": "setIncident",
        "risk_tier": "soft",
        "status": "approved",  # not pending -- excluded
        "created_ts": "2026-07-05T09:00:00Z",
    },
    {
        "approval_id": "dddddddd4444",
        "kind": "plan",
        "incident_id": "103",
        "steps": [{"tool_name": "ip"}],
        "risk_tier": "soft",
        "status": "pending",
        "created_ts": "2026-07-05T11:55:00Z",  # 5 min old -- newest, no summary
    },
]


# --- age / iso parsing -----------------------------------------------------------


def test_parse_iso_valid_and_zero_date():
    assert gwaq._guardian_widget_approvalsqueue_parse_iso("2026-07-05T12:00:00Z") is not None
    assert gwaq._guardian_widget_approvalsqueue_parse_iso("0001-01-01T00:00:00Z") is None
    assert gwaq._guardian_widget_approvalsqueue_parse_iso(None) is None
    assert gwaq._guardian_widget_approvalsqueue_parse_iso("") is None
    assert gwaq._guardian_widget_approvalsqueue_parse_iso("not-a-date") is None


def test_age_minutes_normal():
    age = gwaq.guardian_widget_approvalsqueue_age_minutes("2026-07-05T11:30:00Z", NOW)
    assert age == 30.0


def test_age_minutes_unparseable_is_none():
    assert gwaq.guardian_widget_approvalsqueue_age_minutes("garbage", NOW) is None
    assert gwaq.guardian_widget_approvalsqueue_age_minutes("2026-07-05T11:30:00Z", None) is None


# --- describe ----------------------------------------------------------------------


def test_describe_tool_name():
    assert gwaq.guardian_widget_approvalsqueue_describe({"tool_name": "ip"}) == "ip"


def test_describe_plan_summary():
    assert gwaq.guardian_widget_approvalsqueue_describe({"summary": "Contain host X"}) == "Contain host X"


def test_describe_plan_steps_fallback():
    row = {"steps": [{"tool_name": "ip"}, {"tool_name": "closeInvestigation"}]}
    assert gwaq.guardian_widget_approvalsqueue_describe(row) == "plan (2 step(s))"


def test_describe_unknown():
    assert gwaq.guardian_widget_approvalsqueue_describe({}) == "(unknown)"


# --- build -----------------------------------------------------------------------


def test_build_only_pending_oldest_first():
    widget = gwaq.guardian_widget_approvalsqueue_build(SAMPLE_ROWS, NOW)
    displayed = json.loads(widget.to_display())
    assert displayed["total"] == 3
    incidents_in_order = [row["Incident"] for row in displayed["data"]]
    assert incidents_in_order == ["101", "100", "103"]  # oldest created_ts first
    # spot-check age + approval id truncation on the oldest row
    oldest = displayed["data"][0]
    assert oldest["Age (min)"] == 120.0
    assert oldest["Approval ID"] == "bbbbbbbb"
    assert oldest["Kind"] == "plan"
    assert oldest["Tool / Plan"] == "Contain host X"


def test_build_empty_is_graceful():
    widget = gwaq.guardian_widget_approvalsqueue_build([], NOW)
    assert json.loads(widget.to_display()) == {"total": 0, "data": []}

    widget_none_now = gwaq.guardian_widget_approvalsqueue_build(SAMPLE_ROWS, None)
    displayed = json.loads(widget_none_now.to_display())
    assert all(row["Age (min)"] == "n/a" for row in displayed["data"])


def test_build_caps_and_notes_dropped_rows(monkeypatch):
    monkeypatch.setattr(gwaq, "GUARDIAN_APPROVALS_QUEUE_MAX_ROWS", 1)
    widget = gwaq.guardian_widget_approvalsqueue_build(SAMPLE_ROWS, NOW)
    displayed = json.loads(widget.to_display())
    assert len(displayed["data"]) == 2  # 1 kept + 1 "dropped" summary row
    assert "not shown" in displayed["data"][-1]["Tool / Plan"]


# --- load_rows ---------------------------------------------------------------------


def test_load_rows_not_found_is_empty_list(monkeypatch):
    def fake_execute(command, args):
        assert command == "getList"
        assert args["listName"] == gwaq.GUARDIAN_APPROVALS_LEDGER_LIST_NAME
        return _not_found(gwaq.GUARDIAN_APPROVALS_LEDGER_LIST_NAME)

    monkeypatch.setattr(gwaq.demisto, "executeCommand", fake_execute)
    result = gwaq.guardian_widget_approvalsqueue_load_rows()
    assert result == {"ok": True, "data": [], "error": None, "retryable": False, "is_auth_error": False}


def test_load_rows_parses_json_string(monkeypatch):
    monkeypatch.setattr(gwaq.demisto, "executeCommand", lambda c, a: _entries(json.dumps(SAMPLE_ROWS)))
    result = gwaq.guardian_widget_approvalsqueue_load_rows()
    assert result["ok"] is True
    assert result["data"] == SAMPLE_ROWS


# --- main() end-to-end (server time via GetTime) ------------------------------------


def test_main_end_to_end(monkeypatch):
    def fake_execute(command, args):
        if command == "getList":
            return _entries(json.dumps(SAMPLE_ROWS))
        if command == "GetTime":
            return _entries(NOW)
        raise AssertionError("unexpected command {}".format(command))

    monkeypatch.setattr(gwaq.demisto, "executeCommand", fake_execute)
    gwaq.RESULTS.clear()
    gwaq.main()
    assert len(gwaq.RESULTS) == 1
    displayed = json.loads(gwaq.RESULTS[0])
    assert displayed["total"] == 3
