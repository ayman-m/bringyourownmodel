import json

import GuardianPlanApprove as plan


DEFAULT_DENYLIST = {
    "protected_lists": ["guardian_policy", "guardian_tool_allowlist", "guardian_tool_denylist", "guardian_kill_switch"],
    "denied": ["setList:guardian_policy", "demisto-api-post", "setIntegration"],
}
DEFAULT_SETTINGS = {"batch_cap": 5}


def _install(monkeypatch, ledger=None, denylist=None, settings=None, incident=None, command_handlers=None):
    ledger_list = [] if ledger is None else ledger
    notes = []

    def handle_get_list(args):
        name = args["listName"]
        if name == "guardian_approvals_ledger":
            return [{"Type": 1, "Contents": json.dumps(ledger_list)}]
        if name == "guardian_tool_denylist":
            return [{"Type": 1, "Contents": json.dumps(DEFAULT_DENYLIST if denylist is None else denylist)}]
        if name == "guardian_settings":
            return [{"Type": 1, "Contents": json.dumps(DEFAULT_SETTINGS if settings is None else settings)}]
        raise AssertionError("no fixture wired for getList listName={}".format(name))

    def handle_set_list(args):
        assert args["listName"] == "guardian_approvals_ledger"
        ledger_list[:] = json.loads(args["listData"])
        return [{"Type": 1, "Contents": "Done: list updated"}]

    def handle_create_list(args):
        ledger_list[:] = json.loads(args["listData"])
        return [{"Type": 1, "Contents": "Done: list created"}]

    def handle_add_entries(args):
        notes.append(args)
        return [{"Type": 1, "Contents": "Done"}]

    def handle_get_time(args):
        return [{"Type": 1, "Contents": "2026-07-05T12:00:00Z"}]

    handlers = {
        "getList": handle_get_list,
        "setList": handle_set_list,
        "createList": handle_create_list,
        "addEntries": handle_add_entries,
        "GetTime": handle_get_time,
    }
    if command_handlers:
        handlers.update(command_handlers)

    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command dispatched: {} {}".format(command, args))
        return handlers[command](args)

    monkeypatch.setattr(plan.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(plan.demisto, "incident", lambda: dict(incident) if incident else {})
    monkeypatch.setattr(plan.demisto, "error", lambda msg: None)

    return ledger_list, notes


# --- pre-card validation -------------------------------------------------------


def test_blank_steps_is_a_usage_error(monkeypatch):
    _install(monkeypatch)
    ok, result = plan.guardian_plan_approve_run("")
    assert ok is False
    assert "required" in result["error"]


def test_steps_not_json_is_a_usage_error(monkeypatch):
    _install(monkeypatch)
    ok, result = plan.guardian_plan_approve_run("not json")
    assert ok is False
    assert "not valid JSON" in result["error"]


def test_steps_missing_tool_name_is_rejected(monkeypatch):
    _install(monkeypatch)
    ok, result = plan.guardian_plan_approve_run(json.dumps([{"tool_args": {}}]))
    assert ok is False
    assert "tool_name" in result["error"]


def test_batch_cap_exceeded_is_rejected(monkeypatch):
    ledger, _notes = _install(monkeypatch, settings={"batch_cap": 2})
    steps = json.dumps([{"tool_name": "ip", "tool_args": {}}] * 3)
    ok, result = plan.guardian_plan_approve_run(steps)
    assert ok is False
    assert "batch_cap" in result["error"]
    assert ledger == []  # no row created for a rejected plan


def test_denylisted_step_rejects_whole_plan_precard(monkeypatch):
    ledger, notes = _install(monkeypatch)
    steps = json.dumps(
        [{"tool_name": "ip", "tool_args": {"ip": "1.1.1.1"}}, {"tool_name": "demisto-api-post", "tool_args": {}}]
    )
    ok, result = plan.guardian_plan_approve_run(steps)
    assert ok is False
    assert "step 1" in result["error"]
    assert "demisto-api-post" in result["error"]
    assert ledger == []
    assert notes == []  # never even got to posting a card


def test_self_escape_step_via_protected_lists_rejects_whole_plan(monkeypatch):
    ledger, _notes = _install(monkeypatch)
    steps = json.dumps([{"tool_name": "setList", "tool_args": {"listName": "guardian_kill_switch", "listData": "{}"}}])
    ok, result = plan.guardian_plan_approve_run(steps)
    assert ok is False
    assert "protected_list" in result["error"]
    assert ledger == []


def test_denylist_unreadable_rejects_the_plan_fail_closed(monkeypatch):
    def broken_denylist(args):
        if args["listName"] == "guardian_tool_denylist":
            return [{"Type": 4, "Contents": "connection refused"}]
        raise AssertionError("unexpected getList {}".format(args))

    _install(monkeypatch, command_handlers={"getList": broken_denylist})
    ok, result = plan.guardian_plan_approve_run(json.dumps([{"tool_name": "ip", "tool_args": {}}]))
    assert ok is False
    assert "cannot validate plan" in result["error"]


# --- success path ---------------------------------------------------------


def test_valid_plan_creates_ledger_row_and_note(monkeypatch):
    ledger, notes = _install(monkeypatch, incident={"id": "42"})
    steps = json.dumps(
        [
            {"tool_name": "setIncident", "tool_args": {"id": "42", "severity": 3}},
            {"tool_name": "closeInvestigation", "tool_args": {"id": "42"}},
        ]
    )

    ok, result = plan.guardian_plan_approve_run(steps, summary="Wrap up incident 42")

    assert ok is True
    assert result["status"] == "pending_approval"
    assert result["kind"] == "plan"
    assert result["step_count"] == 2
    assert result["risk_tier"] == "destructive"  # closeInvestigation is destructive-tier

    assert len(ledger) == 1
    row = ledger[0]
    assert row["kind"] == "plan"
    assert row["status"] == "pending"
    assert row["risk_tier"] == "destructive"
    assert row["incident_id"] == "42"
    assert len(row["steps"]) == 2
    assert row["steps"][0]["tool_name"] == "setIncident"
    assert row["steps"][0]["consumed"] is False
    assert row["steps"][1]["tool_name"] == "closeInvestigation"

    assert len(notes) == 1
    note_body = notes[0]["entries"][0]["Contents"]
    assert "DESTRUCTIVE" in note_body
    assert "setIncident" in note_body
    assert "closeInvestigation" in note_body
    assert result["approval_id"] in note_body


def test_plan_risk_tier_is_the_loudest_among_steps(monkeypatch):
    _install(monkeypatch)
    steps = json.dumps([{"tool_name": "setIncident", "tool_args": {}}, {"tool_name": "GuardianApiKeysRotate", "tool_args": {}}])
    ok, result = plan.guardian_plan_approve_run(steps)
    assert ok is True
    assert result["risk_tier"] == "credential"


def test_all_soft_steps_gives_soft_tier_and_plain_card(monkeypatch):
    _install(monkeypatch)
    ok, result = plan.guardian_plan_approve_run(json.dumps([{"tool_name": "setIncident", "tool_args": {}}]))
    assert ok is True
    assert result["risk_tier"] == "soft"


def test_bootstraps_missing_ledger_list(monkeypatch):
    def missing_ledger_get_list(args):
        if args["listName"] == "guardian_approvals_ledger":
            return [{"Type": 4, "Contents": "Item not found (8) on list [...]"}]
        if args["listName"] == "guardian_tool_denylist":
            return [{"Type": 1, "Contents": json.dumps(DEFAULT_DENYLIST)}]
        if args["listName"] == "guardian_settings":
            return [{"Type": 1, "Contents": json.dumps(DEFAULT_SETTINGS)}]
        raise AssertionError("unexpected getList {}".format(args))

    ledger, _notes = _install(monkeypatch, command_handlers={"getList": missing_ledger_get_list})
    ok, result = plan.guardian_plan_approve_run(json.dumps([{"tool_name": "ip", "tool_args": {}}]))
    assert ok is True
    assert len(ledger) == 1


def test_war_room_note_failure_does_not_block_the_plan(monkeypatch):
    def failing_add_entries(args):
        return [{"Type": 4, "Contents": "addEntries down"}]

    ledger, _notes = _install(monkeypatch, command_handlers={"addEntries": failing_add_entries})
    ok, result = plan.guardian_plan_approve_run(json.dumps([{"tool_name": "ip", "tool_args": {}}]))
    assert ok is True
    assert result["posted_to_war_room"] is False
    assert len(ledger) == 1


# --- risk tier classification (pure) -------------------------------------------


def test_risk_tier_matches_bridge_classification():
    assert plan.guardian_plan_risk_tier("closeInvestigation") == "destructive"
    assert plan.guardian_plan_risk_tier("GuardianApiKeysRotate") == "credential"
    assert plan.guardian_plan_risk_tier("setIncident") == "soft"


def test_risk_tier_promotes_sensitive_argument_name_without_reading_value():
    assert plan.guardian_plan_risk_tier("ip", {"api_key": "do-not-log"}) == "credential"


def test_risk_tier_write_spl_is_destructive_and_read_spl_is_soft():
    assert plan.guardian_plan_risk_tier("splunk-search", {"query": "index=notable | collect index=main"}) == "destructive"
    assert plan.guardian_plan_risk_tier("splunk-search", {"query": "index=notable | head 5"}) == "soft"
    assert plan.guardian_plan_risk_tier("ip", {"ip": "| outputlookup x.csv"}) == "soft"


def test_plan_with_a_write_spl_step_is_destructive(monkeypatch):
    _install(monkeypatch)
    steps = json.dumps(
        [
            {"tool_name": "setIncident", "tool_args": {}},
            {"tool_name": "splunk-search", "tool_args": {"query": "index=notable | outputlookup snapshot.csv"}},
        ]
    )
    ok, result = plan.guardian_plan_approve_run(steps)
    assert ok is True
    assert result["risk_tier"] == "destructive"


def test_spl_rule_matches_the_bridge():
    """This script's SPL rule is a hand-kept copy of GuardianToolBridge's (no
    cross-script imports in XSOAR); load the bridge and fail on any drift."""
    import importlib.util
    import pathlib

    bridge_path = pathlib.Path(__file__).resolve().parents[1] / "GuardianToolBridge" / "GuardianToolBridge.py"
    spec = importlib.util.spec_from_file_location("guardian_bridge_for_sync_check", bridge_path)
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)

    assert plan.GUARDIAN_SPL_QUERY_COMMANDS == bridge.GUARDIAN_SPL_QUERY_COMMANDS
    assert plan.GUARDIAN_SPL_WRITE_COMMANDS == bridge.GUARDIAN_SPL_WRITE_COMMANDS
    assert plan._GUARDIAN_SPL_COMMAND_RE.pattern == bridge._GUARDIAN_SPL_COMMAND_RE.pattern
    assert plan.GUARDIAN_RISK_TIER_DESTRUCTIVE_COMMANDS == bridge.GUARDIAN_RISK_TIER_DESTRUCTIVE_COMMANDS


# --- structural allowlist membership (the agent MUST be able to call this) ---


def test_guardian_plan_approve_is_on_the_allowlist():
    """Unlike guardian-approve/guardian-deny (which must be ABSENT), this
    tool is deliberately curated onto guardian_tool_allowlist so the model
    can call it -- catches an accidental omission that would silently break
    the plan-approval feature end-to-end."""
    import pathlib

    lists_dir = pathlib.Path(__file__).resolve().parents[2] / "Lists"
    allowlist_data = json.loads(json.loads((lists_dir / "list-guardian_tool_allowlist.json").read_text())["data"])
    assert "GuardianPlanApprove" in (allowlist_data.get("commands") or [])


# --- main() smoke tests --------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    _install(monkeypatch)
    monkeypatch.setattr(plan.demisto, "args", lambda: {"steps": json.dumps([{"tool_name": "ip", "tool_args": {}}])})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    plan.main()

    assert len(csp.RESULTS) == 1
    assert csp.RESULTS[0].outputs["status"] == "pending_approval"


def test_main_rejected_plan_calls_return_error(monkeypatch):
    import pytest

    _install(monkeypatch)
    monkeypatch.setattr(plan.demisto, "args", lambda: {"steps": ""})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    with pytest.raises(SystemExit):
        plan.main()
    assert len(csp.RESULTS) == 0
