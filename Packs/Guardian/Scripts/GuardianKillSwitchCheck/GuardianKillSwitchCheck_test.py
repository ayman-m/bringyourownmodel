import json

import sys
from pathlib import Path

import GuardianKillSwitchCheck as ksc

# The parity tests below import the loop's own implementation to compare answers.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "GuardianReasoningTick"))


def _list_handler(payload=None, error=None, raw=None):
    def handler(command, args):
        assert command == "getList" and args == {"listName": "guardian_kill_switch"}
        if error:
            return [{"Type": 4, "Contents": error}]
        return [{"Type": 1, "Contents": raw if raw is not None else json.dumps(payload)}]

    return handler


def _run(monkeypatch, handler):
    monkeypatch.setattr(ksc.demisto, "executeCommand", handler)
    monkeypatch.setattr(ksc.demisto, "error", lambda msg: None)
    return ksc.guardian_killswitchcheck_run()


def test_switch_off_proceeds(monkeypatch):
    r = _run(monkeypatch, _list_handler({"enabled": False}))
    assert r == {"halted": False, "proceed": "true", "reason": "kill switch is off"}


def test_switch_on_halts_and_carries_the_operator_reason(monkeypatch):
    r = _run(monkeypatch, _list_handler({"enabled": True, "reason": "incident freeze"}))
    assert r["halted"] is True and r["proceed"] == "false"
    assert "incident freeze" in r["reason"]


def test_switch_on_without_a_reason_still_halts(monkeypatch):
    r = _run(monkeypatch, _list_handler({"enabled": True}))
    assert r["proceed"] == "false" and r["reason"] == "kill switch is ON"


def test_only_a_real_true_halts(monkeypatch):
    """'enabled' as a string or number is not the operator's boolean: same strictness as the loop."""
    for value in ("true", "yes", 1):
        assert _run(monkeypatch, _list_handler({"enabled": value}))["proceed"] == "true"


def test_unreadable_switch_is_fail_open(monkeypatch):
    r = _run(monkeypatch, _list_handler(error="connection refused"))
    assert r["proceed"] == "true" and r["halted"] is False and "fail-open" in r["reason"]


def test_malformed_switch_is_fail_open(monkeypatch):
    assert _run(monkeypatch, _list_handler(raw="{not json"))["proceed"] == "true"
    assert _run(monkeypatch, _list_handler(raw=json.dumps(["not", "a", "dict"])))["proceed"] == "true"


def test_main_outputs_to_the_preflight_context_path(monkeypatch):
    captured = {}
    monkeypatch.setattr(ksc.demisto, "executeCommand", _list_handler({"enabled": True, "reason": "freeze"}))
    monkeypatch.setattr(ksc, "return_results", lambda res: captured.update(res=res))
    ksc.main()
    res = captured["res"]
    assert res.outputs_prefix == "Guardian.Preflight.KillSwitch"
    assert res.outputs["proceed"] == "false"
    assert "HALTED" in res.readable_output


def test_agrees_with_the_loops_own_check(monkeypatch):
    """The playbook task and the loop's per-tick check must answer the same for every List shape."""
    import GuardianReasoningTick as tick

    shapes = [{"enabled": False}, {"enabled": True}, {"enabled": "true"}, {}, {"enabled": None}]
    for shape in shapes:
        monkeypatch.setattr(tick.demisto, "executeCommand", _list_handler(shape))
        monkeypatch.setattr(tick.demisto, "error", lambda msg: None)
        loop_halted = tick.guardian_tick_check_kill_switch()["halted"]
        assert (_run(monkeypatch, _list_handler(shape))["halted"]) is loop_halted, shape
