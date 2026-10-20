import GuardianChatCommand as chat


# --- fixtures / test harness --------------------------------------------------


def _install(monkeypatch, incident_id="999"):
    """Wires demisto.context/setContext with a real-shaped in-memory dict, and
    demisto.incident -- mirrors GuardianReasoningTick_test.py's own harness.
    """
    ctx = {}

    def fake_set_context(path, value):
        parts = path.split(".")
        cur = ctx
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = value
        return {"status": True}

    monkeypatch.setattr(chat.demisto, "context", lambda: ctx)
    monkeypatch.setattr(chat.demisto, "setContext", fake_set_context)
    monkeypatch.setattr(chat.demisto, "incident", lambda: {"id": incident_id} if incident_id else {})
    monkeypatch.setattr(chat.demisto, "error", lambda msg: None)
    monkeypatch.setattr(chat.demisto, "info", lambda msg: None)

    def unexpected_execute(command, args):
        raise AssertionError("unexpected command dispatched: {} {}".format(command, args))

    monkeypatch.setattr(chat.demisto, "executeCommand", unexpected_execute)
    return ctx


# --- guardian_chat_resolve_incident_id -----------------------------------------


def test_resolve_incident_id_defaults_to_current(monkeypatch):
    _install(monkeypatch, incident_id="123")
    ok, incident_id, error = chat.guardian_chat_resolve_incident_id(None)
    assert ok is True
    assert incident_id == "123"
    assert error is None


def test_resolve_incident_id_accepts_matching_value(monkeypatch):
    _install(monkeypatch, incident_id="123")
    ok, incident_id, error = chat.guardian_chat_resolve_incident_id("123")
    assert ok is True
    assert incident_id == "123"


def test_resolve_incident_id_rejects_mismatch(monkeypatch):
    _install(monkeypatch, incident_id="123")
    ok, incident_id, error = chat.guardian_chat_resolve_incident_id("456")
    assert ok is False
    assert "456" in error
    assert "123" in error


# --- guardian_chat_command_run: blank/never-started/running/reopen ------------


def test_blank_message_is_a_usage_error(monkeypatch):
    _install(monkeypatch)
    ok, result = chat.guardian_chat_command_run("   ")
    assert ok is False
    assert "required" in result["error"]


def test_mismatched_incident_id_is_a_usage_error(monkeypatch):
    _install(monkeypatch, incident_id="123")
    ok, result = chat.guardian_chat_command_run("hello", requested_incident_id="456")
    assert ok is False
    assert "456" in result["error"]


def test_message_queued_when_loop_never_started(monkeypatch):
    ctx = _install(monkeypatch)
    ok, result = chat.guardian_chat_command_run("hello there")
    assert ok is True
    assert result["ever_started"] is False
    assert result["reopened"] is False
    assert result["pending_count"] == 1
    assert ctx["Guardian"]["Loop"]["pending_user_input"] == ["hello there"]
    # No status/messages key was fabricated -- this is a minimal skeleton only.
    assert "status" not in ctx["Guardian"]["Loop"]


def test_message_appended_to_existing_queue_when_running(monkeypatch):
    ctx = _install(monkeypatch)
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "x"}],
            "tick": 3,
            "status": "running",
            "pending_user_input": ["earlier message"],
        }
    }
    ok, result = chat.guardian_chat_command_run("second message")
    assert ok is True
    assert result["ever_started"] is True
    assert result["reopened"] is False
    assert result["pending_count"] == 2
    loop = ctx["Guardian"]["Loop"]
    assert loop["pending_user_input"] == ["earlier message", "second message"]
    # Status/tick/messages untouched for a running loop.
    assert loop["status"] == "running"
    assert loop["tick"] == 3
    assert loop["messages"] == [{"role": "system", "content": "x"}]


def test_message_queued_while_awaiting_analyst_does_not_touch_the_flag(monkeypatch):
    # GuardianChatCommand only enqueues -- clearing `awaiting_analyst` is the
    # TICK's job (on drain), not this command's.
    ctx = _install(monkeypatch)
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "x"}],
            "status": "running",
            "awaiting_analyst": {"question": "Contain host-42?", "since_tick": 2},
            "pending_user_input": [],
        }
    }
    ok, result = chat.guardian_chat_command_run("Yes, contain it.")
    assert ok is True
    loop = ctx["Guardian"]["Loop"]
    assert loop["awaiting_analyst"] == {"question": "Contain host-42?", "since_tick": 2}
    assert loop["pending_user_input"] == ["Yes, contain it."]


def test_reopens_concluded_loop_and_resets_terminal_flags(monkeypatch):
    ctx = _install(monkeypatch)
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "x"}],
            "tick": 10,
            "status": "done",
            "force_conclude": True,
            "force_conclude_reason": "a tool call was repeated too many times",
            "awaiting_analyst": None,
            "pending": None,
            "pending_user_input": [],
        }
    }
    ok, result = chat.guardian_chat_command_run("one more thing")
    assert ok is True
    assert result["reopened"] is True
    assert result["previous_status"] == "done"
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "running"
    assert loop["force_conclude"] is False
    assert loop["force_conclude_reason"] is None
    assert loop["awaiting_analyst"] is None
    assert loop["awaiting_ticks"] == 0
    assert loop["pending"] is None  # was already None -- stays None, nothing to preserve
    # tick count / messages are preserved, never reset.
    assert loop["tick"] == 10
    assert loop["messages"] == [{"role": "system", "content": "x"}]


def test_reopen_preserves_an_approved_but_unconsumed_pending_approval(monkeypatch):
    """Task 3.1 fix (caught live): the ONLY way a "stopped" loop can still
    have `Loop.pending` set is a kill-switch halt (a status-only overlay
    that never touches `pending`) -- reopening via `!guardian-chat` must
    NOT clear it, or an analyst resuming a kill-switch-halted run would
    silently orphan a real, already-`approved` ledger row: the resumed tick
    would never notice there was anything left to re-dispatch."""
    ctx = _install(monkeypatch)
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "x"}],
            "tick": 5,
            "status": "stopped",
            "force_conclude": False,
            "awaiting_analyst": None,
            "pending": {"approval_id": "abc123", "kind": "tool", "risk_tier": "soft", "since_tick": 4},
            "pending_ticks": 3,
            "pending_user_input": [],
        }
    }
    ok, result = chat.guardian_chat_command_run("kill switch cleared, please resume")
    assert ok is True
    assert result["reopened"] is True
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "running"
    # THE fix: pending survives the reopen untouched.
    assert loop["pending"] == {"approval_id": "abc123", "kind": "tool", "risk_tier": "soft", "since_tick": 4}
    assert loop["pending_ticks"] == 3


def test_reopens_stopped_and_error_statuses_too(monkeypatch):
    for status in ("stopped", "error"):
        ctx = _install(monkeypatch)
        ctx["Guardian"] = {"Loop": {"messages": [{"role": "system", "content": "x"}], "status": status}}
        ok, result = chat.guardian_chat_command_run("hi")
        assert ok is True
        assert result["reopened"] is True
        assert ctx["Guardian"]["Loop"]["status"] == "running"


def test_whole_dict_write_not_a_subpath_write(monkeypatch):
    # guardian_ctx_write must be called with the WHOLE Loop dict as one call,
    # never a Loop.<subkey> path (see the module docstring's Context-ownership
    # rationale) -- assert on the actual setContext path used.
    ctx = _install(monkeypatch)
    calls = []
    real_set_context = chat.demisto.setContext

    def recording_set_context(path, value):
        calls.append(path)
        return real_set_context(path, value)

    monkeypatch.setattr(chat.demisto, "setContext", recording_set_context)
    chat.guardian_chat_command_run("hello")
    assert calls == ["Guardian.Loop"]


# --- guardian_chat_narrate ------------------------------------------------------


def test_narrate_never_started():
    lines = chat.guardian_chat_narrate(
        {"ever_started": False, "reopened": False, "previous_status": None, "pending_count": 1}
    )
    assert any("No active Guardian Agent Loop" in line for line in lines)


def test_narrate_running_not_reopened():
    lines = chat.guardian_chat_narrate(
        {"ever_started": True, "reopened": False, "previous_status": "running", "pending_count": 1}
    )
    assert any("next scheduled tick" in line for line in lines)
    assert not any("RE-OPENED" in line for line in lines)


def test_narrate_reopened_mentions_playbook_rerun():
    lines = chat.guardian_chat_narrate(
        {"ever_started": True, "reopened": True, "previous_status": "done", "pending_count": 1}
    )
    joined = "\n".join(lines)
    assert "RE-OPENED" in joined
    assert "GuardianAgentLoop" in joined
    assert "done" in joined


# --- main() smoke tests --------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    _install(monkeypatch)
    monkeypatch.setattr(chat.demisto, "args", lambda: {"message": "hello"})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    chat.main()

    assert len(csp.RESULTS) == 1
    result = csp.RESULTS[0]
    assert result.outputs["queued"] is True
    assert result.outputs["pending_count"] == 1


def test_main_blank_message_calls_return_error(monkeypatch):
    import pytest

    _install(monkeypatch)
    monkeypatch.setattr(chat.demisto, "args", lambda: {"message": ""})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    with pytest.raises(SystemExit) as exc_info:
        chat.main()
    assert "required" in str(exc_info.value)
    assert len(csp.RESULTS) == 0


def test_main_mismatched_incident_id_calls_return_error(monkeypatch):
    import pytest

    _install(monkeypatch, incident_id="123")
    monkeypatch.setattr(chat.demisto, "args", lambda: {"message": "hi", "incident_id": "999"})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    with pytest.raises(SystemExit) as exc_info:
        chat.main()
    assert "999" in str(exc_info.value)
    assert len(csp.RESULTS) == 0
