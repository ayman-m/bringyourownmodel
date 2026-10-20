import json

import GuardianApprovalResolve as resolve


# --- fixtures / test harness --------------------------------------------------


def _install(monkeypatch, ledger=None, command_handlers=None):
    """Wires demisto.executeCommand for getList/setList (a real, mutating
    in-memory ledger -- setList updates the SAME list object in place so a
    test can inspect it after the call), addEntries, GuardianAuditWrite, and
    GetTime. Any other command dispatched raises AssertionError.

    :return: `(ledger_list, audit_calls, notes)`.
    """
    ledger_list = [] if ledger is None else ledger
    audit_calls = []
    notes = []

    def handle_get_list(args):
        assert args["listName"] == "guardian_approvals_ledger"
        return [{"Type": 1, "Contents": json.dumps(ledger_list)}]

    def handle_set_list(args):
        assert args["listName"] == "guardian_approvals_ledger"
        new_rows = json.loads(args["listData"])
        ledger_list[:] = new_rows
        return [{"Type": 1, "Contents": "Done: list updated"}]

    def handle_add_entries(args):
        notes.append(args)
        return [{"Type": 1, "Contents": "Done"}]

    def handle_audit(args):
        audit_calls.append(args)
        return [{"Type": 1, "Contents": "Guardian audit row written: action=x status=y target=z"}]

    def handle_get_time(args):
        return [{"Type": 1, "Contents": "2026-07-05T12:00:00Z"}]

    handlers = {
        "getList": handle_get_list,
        "setList": handle_set_list,
        "addEntries": handle_add_entries,
        "GuardianAuditWrite": handle_audit,
        "GetTime": handle_get_time,
    }
    if command_handlers:
        handlers.update(command_handlers)

    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command dispatched: {} {}".format(command, args))
        return handlers[command](args)

    monkeypatch.setattr(resolve.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(resolve.demisto, "error", lambda msg: None)

    return ledger_list, audit_calls, notes


def _pending_row(**overrides):
    row = {
        "approval_id": "approval-1",
        "kind": "tool",
        "tool_name": "setIncident",
        "tool_args": {"id": "1"},
        "canonical_args": '{"id": "1"}',
        "risk_tier": "soft",
        "status": "pending",
        "requested_by": "agent",
        "resolved_by": None,
        "resolved_ts": None,
        "reason": None,
        "confirm_provided": False,
        "consumed": False,
    }
    row.update(overrides)
    return row


# --- guardian_approval_resolve_run: usage errors ------------------------------


def test_blank_approval_id_is_a_usage_error(monkeypatch):
    _install(monkeypatch)
    ok, result = resolve.guardian_approval_resolve_run("")
    assert ok is False
    assert "required" in result["error"]


def test_invalid_action_is_a_usage_error(monkeypatch):
    _install(monkeypatch, ledger=[_pending_row()])
    ok, result = resolve.guardian_approval_resolve_run("approval-1", action="destroy")
    assert ok is False
    assert "must be one of" in result["error"]


def test_unknown_approval_id_is_a_usage_error(monkeypatch):
    _install(monkeypatch, ledger=[])
    ok, result = resolve.guardian_approval_resolve_run("nope")
    assert ok is False
    assert "not found" in result["error"]


def test_ledger_unreadable_is_reported_fail_closed(monkeypatch):
    def broken_get_list(args):
        return [{"Type": 4, "Contents": "connection refused"}]

    _install(monkeypatch, command_handlers={"getList": broken_get_list})
    ok, result = resolve.guardian_approval_resolve_run("approval-1")
    assert ok is False
    assert "unreadable" in result["error"]


def test_already_resolved_row_cannot_be_resolved_twice(monkeypatch):
    ledger, _audit, _notes = _install(monkeypatch, ledger=[_pending_row(status="approved")])
    ok, result = resolve.guardian_approval_resolve_run("approval-1", action="deny")
    assert ok is False
    assert "already resolved" in result["error"]
    assert ledger[0]["status"] == "approved"  # untouched


# --- self-resolve prevention ---------------------------------------------------


def test_self_resolve_rejected_when_actor_is_agent(monkeypatch):
    ledger, _audit, _notes = _install(monkeypatch, ledger=[_pending_row()])
    ok, result = resolve.guardian_approval_resolve_run("approval-1", actor="agent")
    assert ok is False
    assert "self-resolve rejected" in result["error"]
    assert ledger[0]["status"] == "pending"  # untouched


def test_self_resolve_rejected_case_insensitively(monkeypatch):
    _install(monkeypatch, ledger=[_pending_row()])
    ok, result = resolve.guardian_approval_resolve_run("approval-1", actor="Agent")
    assert ok is False
    assert "self-resolve rejected" in result["error"]


def test_self_resolve_rejected_when_actor_matches_requested_by(monkeypatch):
    """Generalized form: reject whenever the resolver equals the ledger row's
    own requested_by, not just the literal string "agent" -- today
    requested_by is always "agent" (covered by the case above), but this is
    the SECOND, generic layer described in the module docstring."""
    ledger, _audit, _notes = _install(monkeypatch, ledger=[_pending_row(requested_by="some-automation")])
    ok, result = resolve.guardian_approval_resolve_run("approval-1", actor="some-automation")
    assert ok is False
    assert "must differ from the requester" in result["error"]


def test_normal_human_actor_is_accepted(monkeypatch):
    _install(monkeypatch, ledger=[_pending_row()])
    ok, result = resolve.guardian_approval_resolve_run("approval-1", actor="alice")
    assert ok is True
    assert result["resolved_by"] == "alice"


def test_default_actor_is_analyst_when_none_given(monkeypatch):
    _install(monkeypatch, ledger=[_pending_row()])
    ok, result = resolve.guardian_approval_resolve_run("approval-1")
    assert ok is True
    assert result["resolved_by"] == "analyst"


# --- the approve path ----------------------------------------------------------


def test_approve_flips_status_records_resolver_and_writes_audit(monkeypatch):
    ledger, audit_calls, notes = _install(monkeypatch, ledger=[_pending_row()])

    ok, result = resolve.guardian_approval_resolve_run("approval-1", actor="alice")

    assert ok is True
    assert result == {
        "approval_id": "approval-1",
        "status": "approved",
        "resolved_by": "alice",
        "kind": "tool",
        "tool_name": "setIncident",
        "posted_to_war_room": True,
        "ts_warning": None,
    }
    assert ledger[0]["status"] == "approved"
    assert ledger[0]["resolved_by"] == "alice"
    assert ledger[0]["resolved_ts"] == "2026-07-05T12:00:00Z"
    assert ledger[0]["consumed"] is False  # resolution alone never consumes the token

    assert len(notes) == 1
    assert "APPROVED" in notes[0]["entries"][0]["Contents"]
    assert "approval-1" in notes[0]["entries"][0]["Contents"]

    assert len(audit_calls) == 1
    assert audit_calls[0]["action"] == "setIncident"
    assert audit_calls[0]["status"] == "approved"
    assert audit_calls[0]["actor"] == "alice"
    assert audit_calls[0]["target"] == "approval-1"


def test_deny_flips_status_and_records_reason(monkeypatch):
    ledger, audit_calls, _notes = _install(monkeypatch, ledger=[_pending_row()])

    ok, result = resolve.guardian_approval_resolve_run("approval-1", action="deny", reason="not needed", actor="bob")

    assert ok is True
    assert result["status"] == "denied"
    assert ledger[0]["status"] == "denied"
    assert ledger[0]["reason"] == "not needed"
    assert ledger[0]["resolved_by"] == "bob"
    assert audit_calls[0]["status"] == "denied"


def test_plan_kind_audit_action_is_generic(monkeypatch):
    plan_row = {
        "approval_id": "plan-1",
        "kind": "plan",
        "status": "pending",
        "steps": [{"tool_name": "setIncident"}, {"tool_name": "closeInvestigation"}],
        "requested_by": "agent",
    }
    _ledger, audit_calls, notes = _install(monkeypatch, ledger=[plan_row])

    ok, result = resolve.guardian_approval_resolve_run("plan-1", actor="carol")

    assert ok is True
    assert result["kind"] == "plan"
    assert result["tool_name"] is None
    assert audit_calls[0]["action"] == "GuardianPlanApprove"
    assert "Steps:** 2" in notes[0]["entries"][0]["Contents"]


# --- credential-tier typed-CONFIRM ceremony --------------------------------


def test_credential_tier_approve_requires_exact_confirm(monkeypatch):
    ledger, _audit, _notes = _install(monkeypatch, ledger=[_pending_row(risk_tier="credential")])

    ok, result = resolve.guardian_approval_resolve_run("approval-1")
    assert ok is False
    assert "confirm=CONFIRM" in result["error"]
    assert ledger[0]["status"] == "pending"  # untouched


def test_credential_tier_approve_rejects_wrong_confirm_value(monkeypatch):
    _install(monkeypatch, ledger=[_pending_row(risk_tier="credential")])
    ok, result = resolve.guardian_approval_resolve_run("approval-1", confirm="yes please")
    assert ok is False
    assert "confirm=CONFIRM" in result["error"]


def test_credential_tier_approve_is_case_sensitive_confirm(monkeypatch):
    _install(monkeypatch, ledger=[_pending_row(risk_tier="credential")])
    ok, result = resolve.guardian_approval_resolve_run("approval-1", confirm="confirm")
    assert ok is False


def test_credential_tier_approve_succeeds_with_exact_confirm(monkeypatch):
    ledger, _audit, _notes = _install(monkeypatch, ledger=[_pending_row(risk_tier="credential")])
    ok, result = resolve.guardian_approval_resolve_run("approval-1", confirm="CONFIRM", actor="alice")
    assert ok is True
    assert ledger[0]["status"] == "approved"
    assert ledger[0]["confirm_provided"] is True


def test_credential_tier_deny_needs_no_confirm(monkeypatch):
    """Denial never executes anything -- no ceremony required, regardless of
    risk tier."""
    ledger, _audit, _notes = _install(monkeypatch, ledger=[_pending_row(risk_tier="credential")])
    ok, result = resolve.guardian_approval_resolve_run("approval-1", action="deny", actor="alice")
    assert ok is True
    assert ledger[0]["status"] == "denied"


def test_soft_tier_approve_needs_no_confirm(monkeypatch):
    ledger, _audit, _notes = _install(monkeypatch, ledger=[_pending_row(risk_tier="soft")])
    ok, result = resolve.guardian_approval_resolve_run("approval-1")
    assert ok is True
    assert ledger[0]["status"] == "approved"


# --- resilience: a note/audit failure never blocks the resolution itself ---


def test_war_room_note_failure_does_not_block_resolution(monkeypatch):
    def failing_add_entries(args):
        return [{"Type": 4, "Contents": "addEntries down"}]

    ledger, _audit, _notes = _install(monkeypatch, ledger=[_pending_row()], command_handlers={"addEntries": failing_add_entries})
    ok, result = resolve.guardian_approval_resolve_run("approval-1")
    assert ok is True
    assert ledger[0]["status"] == "approved"
    assert result["posted_to_war_room"] is False


def test_audit_failure_does_not_block_resolution(monkeypatch):
    def failing_audit(args):
        return [{"Type": 4, "Contents": "audit down"}]

    ledger, _audit, _notes = _install(monkeypatch, ledger=[_pending_row()], command_handlers={"GuardianAuditWrite": failing_audit})
    ok, result = resolve.guardian_approval_resolve_run("approval-1")
    assert ok is True
    assert ledger[0]["status"] == "approved"


# --- structural self-resolve boundary: never on the allowlist/policy ----------


def test_guardian_approve_and_deny_are_absent_from_allowlist_and_policy():
    """The REAL self-resolve boundary (see the .py module docstring's
    "OPERATOR-ONLY" section): neither command name may EVER appear in
    guardian_tool_allowlist or guardian_policy, or the agent's own
    tool-calling path would be able to reach them through
    GuardianToolBridge. This test reads the actual pack-seeded List JSON
    files so a future accidental addition fails CI immediately."""
    import pathlib

    lists_dir = pathlib.Path(__file__).resolve().parents[2] / "Lists"

    allowlist_data = json.loads(json.loads((lists_dir / "list-guardian_tool_allowlist.json").read_text())["data"])
    policy_data = json.loads(json.loads((lists_dir / "list-guardian_policy.json").read_text())["data"])

    allowlist_commands = set(allowlist_data.get("commands") or [])
    policy_keys = set(policy_data.keys())

    for forbidden in ("guardian-approve", "guardian-deny", "GuardianApprovalResolve", "GuardianDeny"):
        assert forbidden not in allowlist_commands, "{} must never be on guardian_tool_allowlist".format(forbidden)
        assert forbidden not in policy_keys, "{} must never be a guardian_policy key".format(forbidden)


# --- main() smoke tests --------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    _install(monkeypatch, ledger=[_pending_row()])
    monkeypatch.setattr(resolve.demisto, "args", lambda: {"approval_id": "approval-1"})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    resolve.main()

    assert len(csp.RESULTS) == 1
    result = csp.RESULTS[0]
    assert result.outputs["status"] == "approved"
    assert "APPROVED" in result.readable_output


def test_main_missing_approval_id_calls_return_error(monkeypatch):
    import pytest

    _install(monkeypatch)
    monkeypatch.setattr(resolve.demisto, "args", lambda: {})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    with pytest.raises(SystemExit) as exc_info:
        resolve.main()
    assert "required" in str(exc_info.value)
    assert len(csp.RESULTS) == 0


def test_main_self_resolve_calls_return_error(monkeypatch):
    import pytest

    _install(monkeypatch, ledger=[_pending_row()])
    monkeypatch.setattr(resolve.demisto, "args", lambda: {"approval_id": "approval-1", "actor": "agent"})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    with pytest.raises(SystemExit) as exc_info:
        resolve.main()
    assert "self-resolve" in str(exc_info.value)
