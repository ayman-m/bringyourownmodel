import GuardianSocAgentSetState as state


def test_requires_a_safe_choice_and_reason():
    ok, result = state.guardian_soc_agent_set_state("on", "reason")
    assert ok is False
    assert "pause or resume" in result["error"]
    ok, result = state.guardian_soc_agent_set_state("pause", "")
    assert ok is False
    assert "reason" in result["error"]


def test_pause_dispatches_only_to_established_kill_switch(monkeypatch):
    calls = []

    def fake_execute(command, args):
        calls.append((command, args))
        return [{"Type": 1, "Contents": "Done"}]

    monkeypatch.setattr(state.demisto, "executeCommand", fake_execute)
    ok, result = state.guardian_soc_agent_set_state("pause", "maintenance")
    assert ok is True
    assert result["state"] == "Paused"
    assert calls == [("guardian-killswitch", {"state": "on", "reason": "maintenance"})]


def test_kill_switch_errors_are_not_reported_as_success(monkeypatch):
    monkeypatch.setattr(state.demisto, "executeCommand", lambda _command, _args: [{"Type": 4, "Contents": "write denied"}])
    ok, result = state.guardian_soc_agent_set_state("resume", "maintenance complete")
    assert ok is False
    assert "write denied" in result["error"]


# --- main() message shape: only Pause/Resume speak in those exact words -----


def test_main_pause_reports_agent_paused(monkeypatch):
    state.RESULTS.clear()
    monkeypatch.setattr(state.demisto, "executeCommand", lambda _c, _a: [{"Type": 1, "Contents": "Done"}])
    monkeypatch.setattr(state.demisto, "args", lambda: {"state": "pause", "reason": "Manual"})
    state.main()
    assert len(state.RESULTS) == 1
    assert state.RESULTS[0].readable_output == "Agent paused."


def test_main_resume_reports_agent_resumed(monkeypatch):
    state.RESULTS.clear()
    monkeypatch.setattr(state.demisto, "executeCommand", lambda _c, _a: [{"Type": 1, "Contents": "Done"}])
    monkeypatch.setattr(state.demisto, "args", lambda: {"state": "resume", "reason": "Manual"})
    state.main()
    assert state.RESULTS[0].readable_output == "Agent resumed."


# No manual '"Pause/Resume Agent" ...' prefix in either case -- the layout UI
# itself picks the CORRECT one of the two buttons' own labels and wraps the
# toast with it (confirmed live via POST /indicator/execute/{id}), even
# though both buttons share this one script; restating it here would double
# the sentence.


def test_main_pause_failure_carries_no_manual_prefix(monkeypatch):
    import pytest

    monkeypatch.setattr(state.demisto, "executeCommand", lambda _c, _a: [{"Type": 4, "Contents": "write denied"}])
    monkeypatch.setattr(state.demisto, "args", lambda: {"state": "pause", "reason": "Manual"})
    with pytest.raises(SystemExit) as exc_info:
        state.main()
    assert str(exc_info.value) == "guardian-killswitch failed: write denied"


def test_main_resume_failure_carries_no_manual_prefix(monkeypatch):
    import pytest

    monkeypatch.setattr(state.demisto, "executeCommand", lambda _c, _a: [{"Type": 4, "Contents": "write denied"}])
    monkeypatch.setattr(state.demisto, "args", lambda: {"state": "resume", "reason": "Manual"})
    with pytest.raises(SystemExit) as exc_info:
        state.main()
    assert str(exc_info.value) == "guardian-killswitch failed: write denied"
