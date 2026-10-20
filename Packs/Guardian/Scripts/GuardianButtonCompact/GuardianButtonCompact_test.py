import pytest

import GuardianButtonCompact as button

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


def test_compact_calls_only_guardian_compact_with_its_defaults(monkeypatch):
    calls = _install(monkeypatch, {"guardian-compact": [{"Type": 1, "Contents": "x", "HumanReadable": "Compacted 12 messages."}]})
    ok, text = button.guardian_button_compact()
    assert ok is True and "Compacted 12 messages." in text
    assert calls == [("guardian-compact", {})]


def test_compact_default_text_and_error_passthrough(monkeypatch):
    _install(monkeypatch, {"guardian-compact": [{"Type": 1, "Contents": {"a": 1}}]})
    assert button.guardian_button_compact() == (True, "Transcript compacted.")
    _install(monkeypatch, {"guardian-compact": [{"Type": 4, "Contents": "no active loop"}]})
    assert button.guardian_button_compact() == (False, "no active loop")


def test_compact_does_not_raise_when_the_command_raises(monkeypatch):
    def boom(command, args):
        raise RuntimeError("down")

    monkeypatch.setattr(button.demisto, "executeCommand", boom)
    ok, text = button.guardian_button_compact()
    assert ok is False and "down" in text


def test_main_success_and_failure(monkeypatch):
    _install(monkeypatch)
    csp = _run_main(monkeypatch, {})
    button.main()
    assert len(csp.RESULTS) == 1
    _install(monkeypatch, {"guardian-compact": [{"Type": 4, "Contents": "no active loop"}]})
    _run_main(monkeypatch, {})
    with pytest.raises(SystemExit) as exc_info:
        button.main()
    assert "no active loop" in str(exc_info.value)
