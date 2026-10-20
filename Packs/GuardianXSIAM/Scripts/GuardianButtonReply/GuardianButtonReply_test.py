import pytest

import GuardianButtonReply as button

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


def test_reply_queues_the_message_through_guardian_chat_only(monkeypatch):
    calls = _install(monkeypatch, {"guardian-chat": [{"Type": 1, "Contents": "x", "HumanReadable": "Message queued -- it will be added on the next tick."}]})
    ok, text = button.guardian_button_reply("  focus on the 10.x subnet  ")
    assert ok is True and "Message queued" in text
    assert calls == [("guardian-chat", {"message": "focus on the 10.x subnet"})]


def test_reply_relays_the_reopened_loop_warning(monkeypatch):
    _install(monkeypatch, {"guardian-chat": [{"Type": 1, "Contents": "x", "HumanReadable": "RE-OPENED. Re-run the `GuardianAgentLoop` playbook."}]})
    assert "Re-run the `GuardianAgentLoop` playbook" in button.guardian_button_reply("hello")[1]


def test_reply_has_a_default_message_when_the_command_returns_no_text(monkeypatch):
    _install(monkeypatch, {"guardian-chat": [{"Type": 1, "Contents": {"queued": True}}]})
    assert button.guardian_button_reply("hello") == (True, "Message queued for the agent.")


def test_reply_requires_a_message_and_caps_its_length(monkeypatch):
    calls = _install(monkeypatch)
    for bad in (None, "", "   ", 3):
        assert button.guardian_button_reply(bad) == (False, "A message is required.")
    assert calls == []
    button.guardian_button_reply("m" * 9000)
    assert len(calls[0][1]["message"]) == button.GUARDIAN_BUTTON_MAX_TEXT_CHARS


def test_reply_surfaces_the_command_error(monkeypatch):
    _install(monkeypatch, {"guardian-chat": [{"Type": 4, "Contents": "NEEDS_CONTEXT: wrong incident"}]})
    assert button.guardian_button_reply("hi") == (False, "NEEDS_CONTEXT: wrong incident")


def test_main_success_and_failure(monkeypatch):
    _install(monkeypatch)
    csp = _run_main(monkeypatch, {"message": "hi"})
    button.main()
    assert len(csp.RESULTS) == 1 and csp.RESULTS[0].readable_output
    _run_main(monkeypatch, {"message": ""})
    with pytest.raises(SystemExit) as exc_info:
        button.main()
    assert "message is required" in str(exc_info.value)
