import json

import GuardianCostCommand as cost


# --- fixtures / test harness --------------------------------------------------


def _install(monkeypatch, getlist_handler=None, incident=None, ctx=None):
    def default_handler(args):
        return [{"Type": 4, "Contents": "Item not found (8) on list [guardian_cost_ledger]"}]

    handler = getlist_handler or default_handler

    def fake_execute(command, args):
        if command != "getList":
            raise AssertionError("unexpected command dispatched: {} {}".format(command, args))
        return handler(args)

    monkeypatch.setattr(cost.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(cost.demisto, "error", lambda msg: None)
    monkeypatch.setattr(cost.demisto, "info", lambda msg: None)
    monkeypatch.setattr(cost.demisto, "incident", lambda: incident if incident is not None else {})
    monkeypatch.setattr(cost.demisto, "context", lambda: ctx if ctx is not None else {})


def _getlist_ok(contents):
    def handler(args):
        return [{"Type": 1, "Contents": contents}]

    return handler


def _getlist_error(message):
    def handler(args):
        return [{"Type": 4, "Contents": message}]

    return handler


# --- guardian_cost_cmd_load_ledger ------------------------------------------------


def test_missing_list_is_graceful_empty(monkeypatch):
    _install(monkeypatch, _getlist_error("Item not found (8) on list [guardian_cost_ledger]"))
    result = cost.guardian_cost_cmd_load_ledger()
    assert result["ok"] is True
    assert result["data"] == {}


def test_other_getlist_failure_is_a_real_error(monkeypatch):
    _install(monkeypatch, _getlist_error("Internal Server Error (500)"))
    result = cost.guardian_cost_cmd_load_ledger()
    assert result["ok"] is False


def test_stale_empty_array_normalizes_to_empty_dict(monkeypatch):
    _install(monkeypatch, _getlist_ok(json.dumps([])))
    result = cost.guardian_cost_cmd_load_ledger()
    assert result["ok"] is True
    assert result["data"] == {}


def test_non_empty_array_is_an_error(monkeypatch):
    _install(monkeypatch, _getlist_ok(json.dumps([1, 2])))
    result = cost.guardian_cost_cmd_load_ledger()
    assert result["ok"] is False


def test_malformed_json_is_an_error(monkeypatch):
    _install(monkeypatch, _getlist_ok("not json"))
    result = cost.guardian_cost_cmd_load_ledger()
    assert result["ok"] is False


def test_valid_rollup_parsed(monkeypatch):
    rollup = {"2026-07-05": {"gemini-2.5-flash": {"guardian_reasoning_tick": {"calls": 2, "total_tokens": 100, "usd": 0.01}}}}
    _install(monkeypatch, _getlist_ok(json.dumps(rollup)))
    result = cost.guardian_cost_cmd_load_ledger()
    assert result["ok"] is True
    assert result["data"] == rollup


# --- guardian_cost_cmd_summarize --------------------------------------------------


def test_summarize_empty_rollup():
    summary = cost.guardian_cost_cmd_summarize({})
    assert summary["by_day"] == {}
    assert summary["by_model"] == {}
    assert summary["grand_total"] == {"calls": 0, "total_tokens": 0, "usd": 0.0}


def test_summarize_single_bucket():
    rollup = {"2026-07-05": {"gemini-2.5-flash": {"trigger_a": {"calls": 2, "total_tokens": 100, "usd": 0.01}}}}
    summary = cost.guardian_cost_cmd_summarize(rollup)
    assert summary["by_day"]["2026-07-05"] == {"calls": 2, "total_tokens": 100, "usd": 0.01}
    assert summary["by_model"]["gemini-2.5-flash"] == {"calls": 2, "total_tokens": 100, "usd": 0.01}
    assert summary["grand_total"] == {"calls": 2, "total_tokens": 100, "usd": 0.01}


def test_summarize_multiple_days_models_triggers_accumulate():
    rollup = {
        "2026-07-04": {
            "gemini-2.5-flash": {"a": {"calls": 1, "total_tokens": 10, "usd": 0.001}},
        },
        "2026-07-05": {
            "gemini-2.5-flash": {
                "a": {"calls": 2, "total_tokens": 20, "usd": 0.002},
                "b": {"calls": 3, "total_tokens": 30, "usd": 0.003},
            },
            "gemini-2.5-pro": {"a": {"calls": 4, "total_tokens": 40, "usd": 0.004}},
        },
    }
    summary = cost.guardian_cost_cmd_summarize(rollup)
    assert summary["by_day"]["2026-07-04"]["calls"] == 1
    assert summary["by_day"]["2026-07-05"]["calls"] == 9
    assert summary["by_model"]["gemini-2.5-flash"]["calls"] == 6
    assert summary["by_model"]["gemini-2.5-pro"]["calls"] == 4
    assert summary["grand_total"]["calls"] == 10
    assert round(summary["grand_total"]["usd"], 3) == 0.01


def test_summarize_tolerates_malformed_nested_values():
    rollup = {
        "2026-07-05": {
            "gemini-2.5-flash": "not-a-dict",
            "gemini-2.5-pro": {"a": "not-a-dict-either", "b": {"calls": 1, "total_tokens": 5, "usd": 0.001}},
        },
        "bad-day": "not-a-dict",
    }
    summary = cost.guardian_cost_cmd_summarize(rollup)
    assert summary["by_model"]["gemini-2.5-pro"]["calls"] == 1
    assert "gemini-2.5-flash" not in summary["by_model"] or summary["by_model"].get("gemini-2.5-flash", {}).get(
        "calls", 0
    ) == 0


# --- guardian_cost_cmd_this_run ---------------------------------------------------


def test_this_run_no_incident_no_loop(monkeypatch):
    _install(monkeypatch, incident={}, ctx={})
    this_run = cost.guardian_cost_cmd_this_run()
    assert this_run["incident_id"] is None
    assert this_run["loop_present"] is False


def test_this_run_with_loop_and_field(monkeypatch):
    _install(
        monkeypatch,
        incident={"id": "22486", "CustomFields": {"guardiancostusd": 0.05}},
        ctx={"Guardian": {"Loop": {"status": "running", "tick": 3, "cost_usd": 0.05, "cost_tokens_total": 5000}}},
    )
    this_run = cost.guardian_cost_cmd_this_run()
    assert this_run["incident_id"] == "22486"
    assert this_run["field_cost_usd"] == 0.05
    assert this_run["loop_present"] is True
    assert this_run["loop_status"] == "running"
    assert this_run["loop_tick"] == 3
    assert this_run["loop_cost_usd"] == 0.05
    assert this_run["loop_cost_tokens_total"] == 5000


def test_this_run_malformed_field_ignored(monkeypatch):
    _install(monkeypatch, incident={"id": "1", "CustomFields": {"guardiancostusd": "not-a-number"}}, ctx={})
    this_run = cost.guardian_cost_cmd_this_run()
    assert this_run["field_cost_usd"] is None


# --- guardian_cost_cmd_run (end to end) -------------------------------------------


def test_run_empty_ledger_is_graceful(monkeypatch):
    _install(monkeypatch, _getlist_error("Item not found (8) on list [guardian_cost_ledger]"), incident={}, ctx={})
    result = cost.guardian_cost_cmd_run()
    assert result["ok"] is True
    assert result["data"]["ledger_empty"] is True
    assert result["data"]["grand_total"]["usd"] == 0.0


def test_run_populated_ledger(monkeypatch):
    rollup = {"2026-07-05": {"gemini-2.5-flash": {"a": {"calls": 1, "total_tokens": 10, "usd": 0.01}}}}
    _install(monkeypatch, _getlist_ok(json.dumps(rollup)), incident={"id": "22486"}, ctx={})
    result = cost.guardian_cost_cmd_run()
    assert result["ok"] is True
    assert result["data"]["ledger_empty"] is False
    assert result["data"]["grand_total"]["usd"] == 0.01


# --- guardian_cost_cmd_render ------------------------------------------------------


def test_render_empty_ledger_message():
    data = {
        "this_run": {
            "incident_id": None,
            "field_cost_usd": None,
            "loop_present": False,
            "loop_status": None,
            "loop_tick": None,
            "loop_cost_usd": None,
            "loop_cost_tokens_total": None,
        },
        "by_day": {},
        "by_model": {},
        "grand_total": {"calls": 0, "total_tokens": 0, "usd": 0.0},
        "ledger_empty": True,
    }
    text = cost.guardian_cost_cmd_render(data)
    assert "No cost has been recorded yet" in text
    assert "No Guardian Agent Loop has run" in text


def test_render_populated_ledger_and_active_loop():
    data = {
        "this_run": {
            "incident_id": "22486",
            "field_cost_usd": 0.05,
            "loop_present": True,
            "loop_status": "running",
            "loop_tick": 3,
            "loop_cost_usd": 0.05,
            "loop_cost_tokens_total": 5000,
        },
        "by_day": {"2026-07-05": {"calls": 1, "total_tokens": 10, "usd": 0.01}},
        "by_model": {"gemini-2.5-flash": {"calls": 1, "total_tokens": 10, "usd": 0.01}},
        "grand_total": {"calls": 1, "total_tokens": 10, "usd": 0.01},
        "ledger_empty": False,
    }
    text = cost.guardian_cost_cmd_render(data)
    assert "incident 22486" in text
    assert "running" in text
    assert "2026-07-05" in text
    assert "gemini-2.5-flash" in text
    assert "Grand total" in text


# --- main() smoke tests --------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    _install(monkeypatch, _getlist_error("Item not found (8) on list [guardian_cost_ledger]"), incident={}, ctx={})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    cost.main()

    assert len(csp.RESULTS) == 1
    result = csp.RESULTS[0]
    assert result.outputs["ledger_empty"] is True


def test_main_hard_error_calls_return_error(monkeypatch):
    import pytest

    _install(monkeypatch, _getlist_error("Internal Server Error (500)"), incident={}, ctx={})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    with pytest.raises(SystemExit):
        cost.main()
    assert len(csp.RESULTS) == 0
