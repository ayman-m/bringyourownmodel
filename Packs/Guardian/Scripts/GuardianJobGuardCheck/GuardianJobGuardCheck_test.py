import sys
from pathlib import Path

import GuardianJobGuardCheck as jgc

# The parity tests below import the loop's own implementation to compare answers.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "GuardianReasoningTick"))


def _install(monkeypatch, trigger_source, guard_contents=None, guard_error=None, calls=None):
    incident = {"CustomFields": {"guardiantriggersource": trigger_source}} if trigger_source is not None else {}
    monkeypatch.setattr(jgc.demisto, "incident", lambda: incident)
    monkeypatch.setattr(jgc.demisto, "error", lambda msg: None)

    def handler(command, args):
        if calls is not None:
            calls.append((command, dict(args)))
        assert command == "GuardianJobGuard"
        if guard_error:
            return [{"Type": 4, "Contents": guard_error}]
        return [{"Type": 1, "Contents": guard_contents}]

    monkeypatch.setattr(jgc.demisto, "executeCommand", handler)


def test_a_run_with_no_job_has_nothing_to_check_and_never_calls_jobguard(monkeypatch):
    calls = []
    for source in (None, "manual", "eval", "soc-agent"):
        _install(monkeypatch, source, calls=calls)
        r = jgc.guardian_jobguardcheck_run()
        assert r["proceed"] == "true" and r["halted"] is False and r["job_name"] is None
    assert calls == []


def test_a_job_spawned_run_asks_jobguard_with_the_real_job_name(monkeypatch):
    calls = []
    _install(monkeypatch, "job:intake-sweep", {"proceed": True, "reason": None}, calls=calls)
    r = jgc.guardian_jobguardcheck_run()
    assert calls == [("GuardianJobGuard", {"action": "check", "job_name": "GuardianIntakeSweep"})]
    assert r["proceed"] == "true" and r["job_name"] == "GuardianIntakeSweep"


def test_an_auto_disabled_job_halts_with_its_reason(monkeypatch):
    _install(monkeypatch, "job:intake-sweep", {"proceed": False, "reason": "10 consecutive failures"})
    r = jgc.guardian_jobguardcheck_run()
    assert r["proceed"] == "false" and r["halted"] is True
    assert "10 consecutive failures" in r["reason"]


def test_jobguard_errors_are_fail_open(monkeypatch):
    _install(monkeypatch, "job:intake-sweep", guard_error="registry down")
    assert jgc.guardian_jobguardcheck_run()["proceed"] == "true"
    _install(monkeypatch, "job:intake-sweep", guard_contents="not a dict")
    assert jgc.guardian_jobguardcheck_run()["proceed"] == "true"


def test_job_name_table_matches_the_loops():
    import GuardianReasoningTick as tick

    assert jgc.GUARDIAN_JOBGUARDCHECK_JOB_NAME_BY_TRIGGERSOURCE == tick.GUARDIAN_TICK_JOB_NAME_BY_TRIGGERSOURCE


def test_job_name_resolution_agrees_with_the_loops(monkeypatch):
    import GuardianReasoningTick as tick

    for source in (None, "job:intake-sweep", "manual", " job:intake-sweep "):
        _install(monkeypatch, source)
        monkeypatch.setattr(tick.demisto, "incident", lambda s=source: {"CustomFields": {"guardiantriggersource": s}} if s is not None else {})
        assert jgc.guardian_jobguardcheck_resolve_job_name() == tick.guardian_tick_resolve_job_name(), source


def test_main_outputs_to_the_preflight_context_path(monkeypatch):
    captured = {}
    _install(monkeypatch, "job:intake-sweep", {"proceed": False, "reason": "x"})
    monkeypatch.setattr(jgc, "return_results", lambda res: captured.update(res=res))
    jgc.main()
    assert captured["res"].outputs_prefix == "Guardian.Preflight.JobGuard"
    assert "HALTED" in captured["res"].readable_output
