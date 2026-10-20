import json

import GuardianWidgetEventFeed as gwef


# --- fixtures / test harness --------------------------------------------------


def _entries(contents):
    return [{"Type": 1, "Contents": contents}]


def _not_found(list_name):
    return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(list_name)}]


SAMPLE_ROWS = [
    {"ts": "2026-07-05T12:00:00Z", "actor": "agent", "action": "ip", "target": "1.2.3.4", "status": "ok"},
    {
        "ts": "2026-07-05T12:05:00Z",
        "actor": "agent",
        "action": "demisto-api-delete",
        "status": "denied",
        "detail": {"kill_switch_note": "kill switch active"},
    },
    {"ts": "2026-07-05T12:10:00Z", "actor": "agent", "action": "SearchIncidentsV2", "status": "error"},
    {
        "ts": "2026-07-05T11:00:00Z",
        "actor": "operator",
        "action": "guardian-killswitch",
        "status": "halted",
        "detail": {"reason": "incident spike"},
    },
    {"ts": "2026-07-05T10:00:00Z", "actor": "guardian-jobguard", "action": "job_disabled", "status": "ok"},
    {"ts": "2026-07-05T09:00:00Z", "actor": "agent", "action": "closeInvestigation", "status": "pending_approval"},
]


# --- is_high_signal --------------------------------------------------------------


def test_is_high_signal_status():
    assert gwef.guardian_widget_eventfeed_is_high_signal({"status": "denied"}) is True
    assert gwef.guardian_widget_eventfeed_is_high_signal({"status": "error"}) is True
    assert gwef.guardian_widget_eventfeed_is_high_signal({"status": "halted"}) is True


def test_is_high_signal_action_regardless_of_status():
    assert gwef.guardian_widget_eventfeed_is_high_signal({"action": "guardian-killswitch", "status": "ok"}) is True
    assert gwef.guardian_widget_eventfeed_is_high_signal({"action": "job_disabled", "status": "ok"}) is True


def test_is_not_high_signal():
    assert gwef.guardian_widget_eventfeed_is_high_signal({"action": "ip", "status": "ok"}) is False
    assert gwef.guardian_widget_eventfeed_is_high_signal({"status": "pending_approval"}) is False
    assert gwef.guardian_widget_eventfeed_is_high_signal("not-a-dict") is False


# --- cell / note helpers -----------------------------------------------------------


def test_cell_none_and_truncation():
    assert gwef.guardian_widget_eventfeed_cell(None) == ""
    long_text = "x" * 200
    cell = gwef.guardian_widget_eventfeed_cell(long_text, max_len=10)
    assert len(cell) == 10
    assert cell.endswith("…")


def test_note_for_row():
    assert gwef.guardian_widget_eventfeed_note_for_row({"detail": {"kill_switch_note": "active"}}) == "active"
    assert gwef.guardian_widget_eventfeed_note_for_row({"detail": {}}) == ""
    assert gwef.guardian_widget_eventfeed_note_for_row({}) == ""


# --- build ---------------------------------------------------------------------------


def test_build_filters_and_sorts_most_recent_first():
    widget = gwef.guardian_widget_eventfeed_build(SAMPLE_ROWS)
    displayed = json.loads(widget.to_display())
    assert displayed["total"] == 4  # denied, error, guardian-killswitch, job_disabled
    times = [row["Time"] for row in displayed["data"]]
    assert times == sorted(times, reverse=True)
    actions = [row["Action"] for row in displayed["data"]]
    assert actions[0] == "SearchIncidentsV2"  # most recent (12:10)
    # kill-switch row carries its note
    killswitch_rows = [row for row in displayed["data"] if row["Action"] == "guardian-killswitch"]
    assert killswitch_rows[0]["Status"] == "halted"


def test_build_empty_is_graceful():
    widget = gwef.guardian_widget_eventfeed_build([])
    assert json.loads(widget.to_display()) == {"total": 0, "data": []}

    widget_all_ok = gwef.guardian_widget_eventfeed_build(
        [{"ts": "2026-07-05T12:00:00Z", "action": "ip", "status": "ok"}]
    )
    assert json.loads(widget_all_ok.to_display()) == {"total": 0, "data": []}


def test_build_caps_and_notes_dropped_rows(monkeypatch):
    monkeypatch.setattr(gwef, "GUARDIAN_EVENT_FEED_MAX_ROWS", 2)
    widget = gwef.guardian_widget_eventfeed_build(SAMPLE_ROWS)
    displayed = json.loads(widget.to_display())
    assert len(displayed["data"]) == 3  # 2 kept + 1 "dropped" summary row
    assert "not shown" in displayed["data"][-1]["Action"]


# --- load_rows -----------------------------------------------------------------------


def test_load_rows_not_found_is_empty_list(monkeypatch):
    def fake_execute(command, args):
        assert command == "getList"
        assert args["listName"] == gwef.GUARDIAN_AUDIT_LIST_NAME
        return _not_found(gwef.GUARDIAN_AUDIT_LIST_NAME)

    monkeypatch.setattr(gwef.demisto, "executeCommand", fake_execute)
    result = gwef.guardian_widget_eventfeed_load_rows()
    assert result == {"ok": True, "data": [], "error": None, "retryable": False, "is_auth_error": False}


def test_load_rows_parses_json_string(monkeypatch):
    monkeypatch.setattr(gwef.demisto, "executeCommand", lambda c, a: _entries(json.dumps(SAMPLE_ROWS)))
    result = gwef.guardian_widget_eventfeed_load_rows()
    assert result["ok"] is True
    assert result["data"] == SAMPLE_ROWS


# --- main() end-to-end -----------------------------------------------------------------


def test_main_end_to_end(monkeypatch):
    monkeypatch.setattr(gwef.demisto, "executeCommand", lambda c, a: _entries(json.dumps(SAMPLE_ROWS)))
    gwef.RESULTS.clear()
    gwef.main()
    assert len(gwef.RESULTS) == 1
    displayed = json.loads(gwef.RESULTS[0])
    assert displayed["total"] == 4


def test_main_missing_list_is_graceful(monkeypatch):
    monkeypatch.setattr(gwef.demisto, "executeCommand", lambda c, a: _not_found(gwef.GUARDIAN_AUDIT_LIST_NAME))
    gwef.RESULTS.clear()
    gwef.main()
    assert json.loads(gwef.RESULTS[0]) == {"total": 0, "data": []}
