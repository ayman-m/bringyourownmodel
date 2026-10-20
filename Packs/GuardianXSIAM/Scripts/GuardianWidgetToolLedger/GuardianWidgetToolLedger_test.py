import json

import GuardianWidgetToolLedger as gwtl


# --- fixtures / test harness --------------------------------------------------


def _entries(contents):
    return [{"Type": 1, "Contents": contents}]


def _not_found(list_name):
    return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(list_name)}]


SAMPLE_ROWS = [
    {"ts": "2026-07-05T12:50:10Z", "actor": "agent", "action": "ip", "target": "1.2.3.4", "status": "ok"},
    {"ts": "2026-07-05T12:50:32Z", "actor": "agent", "action": "SearchIncidentsV2", "status": "error"},
    {"ts": "2026-07-04T13:10:53Z", "actor": "agent", "action": "closeInvestigation", "status": "pending_approval"},
    {"ts": "2026-07-04T13:07:18Z", "actor": "agent", "action": "demisto-api-delete", "status": "denied"},
    {"ts": "2026-07-04T13:00:00Z", "actor": "agent", "action": "ip", "target": "5.6.7.8", "status": "ok"},
    {"ts": "2026-07-04T12:00:00Z", "actor": "agent", "action": "weird"},  # missing status
]


# --- guardian_widget_toolledger_count_by_status --------------------------------


def test_count_by_status():
    counts = gwtl.guardian_widget_toolledger_count_by_status(SAMPLE_ROWS)
    assert counts == {"ok": 2, "error": 1, "pending_approval": 1, "denied": 1, "unknown": 1}


def test_count_by_status_empty():
    assert gwtl.guardian_widget_toolledger_count_by_status([]) == {}
    assert gwtl.guardian_widget_toolledger_count_by_status(None) == {}


# --- guardian_widget_toolledger_build -------------------------------------------


def test_build_produces_sorted_pie_categories():
    widget = gwtl.guardian_widget_toolledger_build(SAMPLE_ROWS)
    displayed = json.loads(widget.to_display())
    names = [cat["name"] for cat in displayed]
    assert names == sorted(names)
    by_name = {cat["name"]: cat["data"][0] for cat in displayed}
    assert by_name == {"denied": 1, "error": 1, "ok": 2, "pending_approval": 1, "unknown": 1}


def test_build_empty_is_graceful():
    widget = gwtl.guardian_widget_toolledger_build([])
    assert widget.to_display() == "[]"


# --- guardian_widget_toolledger_load_rows ---------------------------------------


def test_load_rows_not_found_is_empty_list(monkeypatch):
    def fake_execute(command, args):
        assert command == "getList"
        assert args["listName"] == gwtl.GUARDIAN_AUDIT_LIST_NAME
        return _not_found(gwtl.GUARDIAN_AUDIT_LIST_NAME)

    monkeypatch.setattr(gwtl.demisto, "executeCommand", fake_execute)
    result = gwtl.guardian_widget_toolledger_load_rows()
    assert result == {"ok": True, "data": [], "error": None, "retryable": False, "is_auth_error": False}


def test_load_rows_parses_json_string(monkeypatch):
    monkeypatch.setattr(gwtl.demisto, "executeCommand", lambda c, a: _entries(json.dumps(SAMPLE_ROWS)))
    result = gwtl.guardian_widget_toolledger_load_rows()
    assert result["ok"] is True
    assert result["data"] == SAMPLE_ROWS


def test_load_rows_malformed_json_fails(monkeypatch):
    monkeypatch.setattr(gwtl.demisto, "executeCommand", lambda c, a: _entries("{not json"))
    result = gwtl.guardian_widget_toolledger_load_rows()
    assert result["ok"] is False


def test_load_rows_wrong_type_fails(monkeypatch):
    monkeypatch.setattr(gwtl.demisto, "executeCommand", lambda c, a: _entries({"not": "a list"}))
    result = gwtl.guardian_widget_toolledger_load_rows()
    assert result["ok"] is False


# --- main() end-to-end -----------------------------------------------------------


def test_main_returns_widget_json(monkeypatch):
    monkeypatch.setattr(gwtl.demisto, "executeCommand", lambda c, a: _entries(json.dumps(SAMPLE_ROWS)))
    gwtl.RESULTS.clear()
    gwtl.main()
    assert len(gwtl.RESULTS) == 1
    displayed = json.loads(gwtl.RESULTS[0])
    assert isinstance(displayed, list)
    assert len(displayed) == 5


def test_main_missing_list_is_graceful(monkeypatch):
    monkeypatch.setattr(gwtl.demisto, "executeCommand", lambda c, a: _not_found(gwtl.GUARDIAN_AUDIT_LIST_NAME))
    gwtl.RESULTS.clear()
    gwtl.main()
    assert gwtl.RESULTS == ["[]"]
