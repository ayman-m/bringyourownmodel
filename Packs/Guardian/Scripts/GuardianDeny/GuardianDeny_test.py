import GuardianDeny as deny


def _install(monkeypatch, handler=None):
    calls = []

    def default_handler(args):
        calls.append(args)
        return [
            {
                "Type": 1,
                "Contents": {
                    "approval_id": args.get("approval_id"),
                    "status": "denied",
                    "resolved_by": args.get("actor") or "analyst",
                    "kind": "tool",
                    "tool_name": "setIncident",
                    "posted_to_war_room": True,
                    "ts_warning": None,
                },
            }
        ]

    fn = handler or default_handler

    def fake_execute(command, args):
        if command != "guardian-approve":
            raise AssertionError("unexpected command dispatched: {} {}".format(command, args))
        return fn(args)

    monkeypatch.setattr(deny.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(deny.demisto, "error", lambda msg: None)
    return calls


def test_forwards_to_guardian_approve_with_action_forced_to_deny(monkeypatch):
    calls = _install(monkeypatch)

    ok, result = deny.guardian_deny_run("approval-1", reason="not needed", actor="bob")

    assert ok is True
    assert result["status"] == "denied"
    assert len(calls) == 1
    assert calls[0] == {"approval_id": "approval-1", "action": "deny", "reason": "not needed", "actor": "bob"}


def test_forwards_with_no_optional_args(monkeypatch):
    calls = _install(monkeypatch)

    ok, result = deny.guardian_deny_run("approval-1")

    assert ok is True
    assert calls[0] == {"approval_id": "approval-1", "action": "deny"}


def test_underlying_failure_is_surfaced(monkeypatch):
    def failing_handler(args):
        return [{"Type": 4, "Contents": "approval_id not found"}]

    _install(monkeypatch, handler=failing_handler)

    ok, result = deny.guardian_deny_run("does-not-exist")

    assert ok is False
    assert "not found" in result["error"]


def test_underlying_malformed_response_is_reported(monkeypatch):
    def malformed_handler(args):
        return [{"Type": 1, "Contents": "not a dict"}]

    _install(monkeypatch, handler=malformed_handler)

    ok, result = deny.guardian_deny_run("approval-1")

    assert ok is False
    assert "no usable result" in result["error"]


# --- main() smoke tests --------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    _install(monkeypatch)
    monkeypatch.setattr(deny.demisto, "args", lambda: {"approval_id": "approval-1", "reason": "no"})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    deny.main()

    assert len(csp.RESULTS) == 1
    assert csp.RESULTS[0].outputs["status"] == "denied"


def test_main_missing_approval_id_calls_return_error(monkeypatch):
    def failing_handler(args):
        return [{"Type": 4, "Contents": "approval_id is required"}]

    import pytest

    _install(monkeypatch, handler=failing_handler)
    monkeypatch.setattr(deny.demisto, "args", lambda: {"approval_id": ""})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    with pytest.raises(SystemExit):
        deny.main()
    assert len(csp.RESULTS) == 0
