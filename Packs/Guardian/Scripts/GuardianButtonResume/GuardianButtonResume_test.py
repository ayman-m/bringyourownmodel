import pytest

import GuardianButtonResume as button

OK = [{"Type": 1, "Contents": "Done", "HumanReadable": "Done"}]


def _install(monkeypatch, responses=None):
    calls = []
    responses = responses or {}

    def fake_execute(command, args):
        calls.append((command, args))
        return responses.get(command, OK)

    monkeypatch.setattr(button.demisto, "executeCommand", fake_execute)
    return calls


def _run_main(monkeypatch, args):
    import CommonServerPython as csp

    csp.RESULTS.clear()
    monkeypatch.setattr(button.demisto, "args", lambda: args)
    return csp


def test_resume_sets_the_kill_switch_off_through_the_audited_command_only(monkeypatch):
    calls = _install(monkeypatch)
    ok, text = button.guardian_button_resume("  maintenance window ")
    assert ok is True and "kill switch off" in text
    assert calls == [("guardian-killswitch", {"state": "off", "reason": "maintenance window", "actor": "analyst (layout button)"})]


def test_resume_requires_a_reason(monkeypatch):
    calls = _install(monkeypatch)
    for bad in (None, "", "  ", 4):
        ok, text = button.guardian_button_resume(bad)
        assert ok is False and "reason is required" in text
    assert calls == []


def test_resume_surfaces_the_command_error(monkeypatch):
    _install(monkeypatch, {"guardian-killswitch": [{"Type": 4, "Contents": "write denied"}]})
    assert button.guardian_button_resume("because") == (False, "write denied")


def test_resume_text_never_claims_a_per_run_effect(monkeypatch):
    _install(monkeypatch)
    assert "Guardian runs are resumed" in button.guardian_button_resume("x")[1]


def test_main_success_and_failure(monkeypatch):
    _install(monkeypatch)
    csp = _run_main(monkeypatch, {"reason": "because"})
    button.main()
    assert len(csp.RESULTS) == 1 and csp.RESULTS[0].readable_output
    _run_main(monkeypatch, {"reason": ""})
    with pytest.raises(SystemExit) as exc_info:
        button.main()
    assert "reason is required" in str(exc_info.value)
