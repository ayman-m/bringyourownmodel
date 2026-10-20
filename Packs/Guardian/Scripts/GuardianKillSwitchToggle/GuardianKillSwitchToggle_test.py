import json

import GuardianKillSwitchToggle as tog


# --- test harness -------------------------------------------------------------


def _install(monkeypatch, list_state=None, set_ok=True, set_error="", create_ok=True, audit_ok=True):
    """Wire demisto.executeCommand for setList/createList/GuardianAuditWrite/
    GetTime. `list_state` is a dict the setList/createList handler writes into
    (so a test can inspect the persisted state object afterward).

    :return: `(writes, audit_calls)` -- `writes` is a list of the parsed
        state objects setList/createList persisted; `audit_calls` the audit
        arg dicts.
    """
    writes = []
    audit_calls = []
    state = {} if list_state is None else list_state

    def handle_set_list(args):
        assert args["listName"] == "guardian_kill_switch"
        if not set_ok:
            return [{"Type": 4, "Contents": set_error}]
        parsed = json.loads(args["listData"])
        state.clear()
        state.update(parsed)
        writes.append(parsed)
        return [{"Type": 1, "Contents": "Done: list updated"}]

    def handle_create_list(args):
        assert args["listName"] == "guardian_kill_switch"
        if not create_ok:
            return [{"Type": 4, "Contents": "createList failed: disk full"}]
        parsed = json.loads(args["listData"])
        state.clear()
        state.update(parsed)
        writes.append(parsed)
        return [{"Type": 1, "Contents": "Done: list created"}]

    def handle_audit(args):
        audit_calls.append(args)
        if not audit_ok:
            return [{"Type": 4, "Contents": "audit down"}]
        return [{"Type": 1, "Contents": "Guardian audit row written"}]

    def handle_get_time(args):
        return [{"Type": 1, "Contents": "2026-07-06T12:00:00Z"}]

    handlers = {
        "setList": handle_set_list,
        "createList": handle_create_list,
        "GuardianAuditWrite": handle_audit,
        "GetTime": handle_get_time,
    }

    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command dispatched: {} {}".format(command, args))
        return handlers[command](args)

    monkeypatch.setattr(tog.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(tog.demisto, "error", lambda msg: None)

    return writes, audit_calls


# --- state validation ---------------------------------------------------------


def test_run_rejects_missing_state(monkeypatch):
    _install(monkeypatch)
    ok, result = tog.guardian_toggle_run(None)
    assert ok is False
    assert "state" in result["error"]


def test_run_rejects_bad_state(monkeypatch):
    _install(monkeypatch)
    ok, result = tog.guardian_toggle_run("maybe")
    assert ok is False
    assert "on" in result["error"] and "off" in result["error"]


# --- operator-only actor guard (defense in depth) -----------------------------


def test_run_rejects_agent_actor(monkeypatch):
    _install(monkeypatch)
    ok, result = tog.guardian_toggle_run("on", actor="agent")
    assert ok is False
    assert "operator-only" in result["error"]


def test_run_rejects_agent_actor_case_insensitive(monkeypatch):
    _install(monkeypatch)
    ok, result = tog.guardian_toggle_run("on", actor="AGENT")
    assert ok is False
    assert "operator-only" in result["error"]


# --- writes the List correctly (the core behavior) ----------------------------


def test_run_on_writes_enabled_true(monkeypatch):
    writes, audit_calls = _install(monkeypatch)
    ok, result = tog.guardian_toggle_run("on", reason="test halt")
    assert ok is True
    assert result["enabled"] is True
    assert result["state"] == "on"
    # exactly one write, carrying the full state object shape
    assert len(writes) == 1
    persisted = writes[0]
    assert persisted["enabled"] is True
    assert persisted["reason"] == "test halt"
    assert persisted["toggled_by"] == "operator"
    assert persisted["ts"] == "2026-07-06T12:00:00Z"


def test_run_off_writes_enabled_false(monkeypatch):
    writes, _audit = _install(monkeypatch)
    ok, result = tog.guardian_toggle_run("off")
    assert ok is True
    assert result["enabled"] is False
    assert writes[0]["enabled"] is False
    assert writes[0]["reason"] is None


def test_run_normalizes_uppercase_state(monkeypatch):
    writes, _audit = _install(monkeypatch)
    ok, result = tog.guardian_toggle_run("ON")
    assert ok is True
    assert result["enabled"] is True
    assert writes[0]["enabled"] is True


def test_run_custom_actor_recorded(monkeypatch):
    writes, _audit = _install(monkeypatch)
    ok, result = tog.guardian_toggle_run("on", actor="alice")
    assert ok is True
    assert result["toggled_by"] == "alice"
    assert writes[0]["toggled_by"] == "alice"


# --- setList -> createList fallback when the List is absent -------------------


def test_run_creates_list_when_absent(monkeypatch):
    writes, _audit = _install(
        monkeypatch, set_ok=False, set_error="Item not found (8) on list [guardian_kill_switch]"
    )
    ok, result = tog.guardian_toggle_run("on")
    assert ok is True
    assert result["created"] is True
    assert writes[0]["enabled"] is True


def test_run_reports_setlist_error_when_not_absent(monkeypatch):
    _install(monkeypatch, set_ok=False, set_error="boom: server on fire")
    ok, result = tog.guardian_toggle_run("on")
    assert ok is False
    assert "failed to write guardian_kill_switch" in result["error"]


def test_run_reports_create_failure(monkeypatch):
    _install(monkeypatch, set_ok=False, set_error="Item not found (8)", create_ok=False)
    ok, result = tog.guardian_toggle_run("on")
    assert ok is False
    assert "could not be created" in result["error"]


# --- audits the toggle --------------------------------------------------------


def test_run_audits_on_toggle(monkeypatch):
    _writes, audit_calls = _install(monkeypatch)
    ok, result = tog.guardian_toggle_run("on", reason="incident response")
    assert ok is True
    assert result["audited"] is True
    assert len(audit_calls) == 1
    audit = audit_calls[0]
    assert audit["action"] == "guardian-killswitch"
    assert audit["target"] == "guardian_kill_switch"
    assert audit["status"] == "halted"  # ON -> halted
    assert audit["actor"] == "operator"
    assert audit["detail"]["enabled"] is True
    assert audit["detail"]["reason"] == "incident response"


def test_run_audit_status_ok_when_off(monkeypatch):
    _writes, audit_calls = _install(monkeypatch)
    tog.guardian_toggle_run("off")
    assert audit_calls[0]["status"] == "ok"  # OFF -> ok


def test_run_audit_failure_does_not_block_toggle(monkeypatch):
    writes, _audit = _install(monkeypatch, audit_ok=False)
    ok, result = tog.guardian_toggle_run("on")
    # the switch still flipped even though the audit row failed
    assert ok is True
    assert result["audited"] is False
    assert writes[0]["enabled"] is True


# --- main() smoke -------------------------------------------------------------


def test_main_on_success(monkeypatch):
    tog.RESULTS.clear()
    _install(monkeypatch)
    monkeypatch.setattr(tog.demisto, "args", lambda: {"state": "on", "reason": "kill it"})
    tog.main()
    assert len(tog.RESULTS) == 1
    cr = tog.RESULTS[0]
    assert cr.outputs["enabled"] is True
    assert "ENABLED" in cr.readable_output


def test_main_bad_state_return_error(monkeypatch):
    tog.RESULTS.clear()
    _install(monkeypatch)
    monkeypatch.setattr(tog.demisto, "args", lambda: {"state": "banana"})
    import pytest

    with pytest.raises(SystemExit) as exc_info:
        tog.main()
    assert "state" in str(exc_info.value)


# --- structural operator-only boundary: never on allowlist/policy -------------


def test_killswitch_command_absent_from_allowlist_and_policy():
    """The REAL operator-only boundary (see the .py module docstring): the
    guardian-killswitch command (and its script name) must NEVER appear on
    guardian_tool_allowlist or in guardian_policy, or the agent's own
    tool-calling path could reach its own off-switch through GuardianToolBridge.
    Reads the actual pack-seeded List JSON so an accidental future addition
    fails CI immediately."""
    import pathlib

    lists_dir = pathlib.Path(__file__).resolve().parents[2] / "Lists"

    allowlist_data = json.loads(json.loads((lists_dir / "list-guardian_tool_allowlist.json").read_text())["data"])
    policy_data = json.loads(json.loads((lists_dir / "list-guardian_policy.json").read_text())["data"])

    allowlist_commands = set(allowlist_data.get("commands") or [])
    policy_keys = set(policy_data.keys())

    for forbidden in ("guardian-killswitch", "GuardianKillSwitchToggle"):
        assert forbidden not in allowlist_commands, "{} must never be on guardian_tool_allowlist".format(forbidden)
        assert forbidden not in policy_keys, "{} must never be a guardian_policy key".format(forbidden)


def test_kill_switch_is_a_protected_list():
    """guardian_kill_switch must be in guardian_tool_denylist.protected_lists,
    so the AGENT can never write it through the bridge -- the reason this
    toggle has to write it directly."""
    import pathlib

    lists_dir = pathlib.Path(__file__).resolve().parents[2] / "Lists"
    denylist_data = json.loads(json.loads((lists_dir / "list-guardian_tool_denylist.json").read_text())["data"])
    assert "guardian_kill_switch" in set(denylist_data.get("protected_lists") or [])
