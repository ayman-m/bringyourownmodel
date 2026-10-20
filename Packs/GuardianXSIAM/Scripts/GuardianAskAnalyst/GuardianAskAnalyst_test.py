import GuardianAskAnalyst as aa


# --- fixtures / test harness --------------------------------------------------


def _install(monkeypatch, addentries_handler=None):
    """Wires demisto.executeCommand for `addEntries`. Any OTHER command dispatched
    raises AssertionError -- this script should never call anything else.
    """
    calls = []

    def default_handler(args):
        calls.append(args)
        return [{"Type": 1, "Contents": "Done"}]

    handler = addentries_handler or default_handler

    def fake_execute(command, args):
        if command != "addEntries":
            raise AssertionError("unexpected command dispatched: {} {}".format(command, args))
        return handler(args)

    monkeypatch.setattr(aa.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(aa.demisto, "error", lambda msg: None)
    monkeypatch.setattr(aa.demisto, "info", lambda msg: None)
    return calls


# --- guardian_ask_analyst_run --------------------------------------------------


def test_blank_question_is_a_usage_error(monkeypatch):
    _install(monkeypatch)
    ok, result = aa.guardian_ask_analyst_run("   ")
    assert ok is False
    assert "required" in result["error"]


def test_none_question_is_a_usage_error(monkeypatch):
    _install(monkeypatch)
    ok, result = aa.guardian_ask_analyst_run(None)
    assert ok is False
    assert "required" in result["error"]


def test_oversized_question_is_a_usage_error(monkeypatch):
    _install(monkeypatch)
    ok, result = aa.guardian_ask_analyst_run("x" * (aa.GUARDIAN_ASK_ANALYST_MAX_QUESTION_LEN + 1))
    assert ok is False
    assert "over the" in result["error"]
    # No addEntries call should have happened for a rejected question.


def test_valid_question_posts_note_and_returns_awaiting_envelope(monkeypatch):
    calls = _install(monkeypatch)
    ok, result = aa.guardian_ask_analyst_run("Should I contain host-42?")
    assert ok is True
    assert result == {
        "status": "awaiting_analyst",
        "question": "Should I contain host-42?",
        "posted_to_war_room": True,
    }
    assert len(calls) == 1
    entries = calls[0]["entries"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["Note"] is True
    assert entry["ContentsFormat"] == "markdown"
    assert entry["Tags"] == [aa.GUARDIAN_ASK_ANALYST_TAG]
    assert "Should I contain host-42?" in entry["Contents"]
    assert "guardian-chat" in entry["Contents"]


def test_question_is_stripped_of_surrounding_whitespace(monkeypatch):
    _install(monkeypatch)
    ok, result = aa.guardian_ask_analyst_run("  Is this expected?  ")
    assert ok is True
    assert result["question"] == "Is this expected?"


def test_war_room_post_failure_does_not_fail_the_call(monkeypatch):
    # The tool's actual state-machine signal is the returned envelope, not the
    # War Room note -- a note-post failure must never turn this into a
    # bridge-visible "error" outcome (see the .py module docstring).
    def failing_handler(args):
        return [{"Type": 4, "Contents": "addEntries is not available"}]

    _install(monkeypatch, addentries_handler=failing_handler)
    ok, result = aa.guardian_ask_analyst_run("Should I contain host-42?")
    assert ok is True
    assert result["status"] == "awaiting_analyst"
    assert result["posted_to_war_room"] is False
    assert "warning" in result


# --- main() smoke tests --------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    _install(monkeypatch)
    monkeypatch.setattr(aa.demisto, "args", lambda: {"question": "Should I contain host-42?"})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    aa.main()

    assert len(csp.RESULTS) == 1
    result = csp.RESULTS[0]
    assert result.outputs["status"] == "awaiting_analyst"
    assert "Should I contain host-42?" in result.readable_output


def test_main_blank_question_calls_return_error(monkeypatch):
    import pytest

    _install(monkeypatch)
    monkeypatch.setattr(aa.demisto, "args", lambda: {"question": ""})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    with pytest.raises(SystemExit) as exc_info:
        aa.main()
    assert "required" in str(exc_info.value)
    assert len(csp.RESULTS) == 0
