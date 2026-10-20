import json

import GuardianPlanCommand as plan_cmd


# --- fixtures / test harness --------------------------------------------------


def _default_prompt_handler(args):
    # GuardianPromptBuilder's real Contents shape: {"prompt": str, "meta": {...}} (its
    # raw_response, no outputs/outputs_prefix set) -- NOT a bare string. See the live-bug fix
    # this test fixture now matches (Task 2.3, GuardianPlanCommand.guardian_plan_cmd_run).
    return [{"Type": 1, "Contents": {"prompt": "SYSTEM PROMPT TEXT", "meta": {"CharLen": 18}}}]


def _default_llm_handler(args):
    return [
        {
            "Type": 1,
            "Contents": {
                "model": "gemini-2.5-flash",
                "usage": {"prompt_tokens": 500, "completion_tokens": 100, "total_tokens": 600},
                "choices": [{"message": {"role": "assistant", "content": "1. Do X.\n2. Do Y."}}],
            },
        }
    ]


def _default_addentries_handler(args):
    return [{"Type": 1, "Contents": "Done"}]


def _default_cost_handler(args):
    return [{"Type": 1, "Contents": {"usd": 0.002, "tokens": {"total_tokens": 600}}}]


def _install(
    monkeypatch,
    incident_id="999",
    incident=None,
    ctx=None,
    prompt_handler=None,
    llm_handler=None,
    addentries_handler=None,
    cost_handler=None,
):
    handlers = {
        "GuardianPromptBuilder": prompt_handler or _default_prompt_handler,
        "guardian-llm-chat": llm_handler or _default_llm_handler,
        "addEntries": addentries_handler or _default_addentries_handler,
        "GuardianCostLedger": cost_handler or _default_cost_handler,
    }

    def fake_execute(command, args_):
        if command not in handlers:
            raise AssertionError("unexpected command dispatched: {} {}".format(command, args_))
        return handlers[command](args_)

    monkeypatch.setattr(plan_cmd.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(plan_cmd.demisto, "error", lambda msg: None)
    monkeypatch.setattr(plan_cmd.demisto, "info", lambda msg: None)
    monkeypatch.setattr(
        plan_cmd.demisto,
        "incident",
        lambda: incident if incident is not None else ({"id": incident_id} if incident_id else {}),
    )
    monkeypatch.setattr(plan_cmd.demisto, "context", lambda: ctx if ctx is not None else {})


# --- guardian_plan_cmd_resolve_incident_id ----------------------------------------


def test_resolve_incident_id_defaults_to_current(monkeypatch):
    _install(monkeypatch, incident_id="123")
    ok, incident_id, error = plan_cmd.guardian_plan_cmd_resolve_incident_id(None)
    assert ok is True
    assert incident_id == "123"


def test_resolve_incident_id_rejects_mismatch(monkeypatch):
    _install(monkeypatch, incident_id="123")
    ok, incident_id, error = plan_cmd.guardian_plan_cmd_resolve_incident_id("456")
    assert ok is False
    assert "456" in error and "123" in error


# --- guardian_plan_cmd_wrap_untrusted / loop_status_note / build_user_message -----


def test_wrap_untrusted():
    wrapped = plan_cmd.guardian_plan_cmd_wrap_untrusted("hello")
    assert wrapped.startswith("<untrusted-case-data>\n")
    assert wrapped.endswith("\n</untrusted-case-data>")
    assert "hello" in wrapped


def test_loop_status_note_absent_when_no_loop():
    assert plan_cmd.guardian_plan_cmd_loop_status_note(None) is None
    assert plan_cmd.guardian_plan_cmd_loop_status_note({}) is None


def test_loop_status_note_present_when_loop_ran():
    note = plan_cmd.guardian_plan_cmd_loop_status_note(
        {"status": "running", "tick": 4, "messages": [1, 2, 3]}
    )
    assert "status=running" in note
    assert "tick=4" in note
    assert "3 transcript message(s)" in note


def test_build_user_message_includes_instructions_and_projection_and_note():
    text = plan_cmd.guardian_plan_cmd_build_user_message({"id": "22486", "name": "Test"}, "loop note here")
    assert "PLAN" in text
    assert "<untrusted-case-data>" in text
    assert '"id": "22486"' in text
    assert "loop note here" in text


def test_build_user_message_omits_note_when_none():
    text = plan_cmd.guardian_plan_cmd_build_user_message({"id": "1"}, None)
    assert "Note: a Guardian Agent Loop" not in text


# --- guardian_plan_cmd_call_llm ---------------------------------------------------


def test_call_llm_message_kind(monkeypatch):
    _install(monkeypatch)
    turn = plan_cmd.guardian_plan_cmd_call_llm([{"role": "system", "content": "s"}])
    assert turn["kind"] == "message"
    assert turn["content"] == "1. Do X.\n2. Do Y."
    assert turn["model"] == "gemini-2.5-flash"


def test_call_llm_error_kind(monkeypatch):
    def failing_llm(args):
        return [{"Type": 4, "Contents": "connection refused"}]

    _install(monkeypatch, llm_handler=failing_llm)
    turn = plan_cmd.guardian_plan_cmd_call_llm([{"role": "system", "content": "s"}])
    assert turn["kind"] == "error"


def test_call_llm_content_filter_kind(monkeypatch):
    def filtered_llm(args):
        return [
            {
                "Type": 1,
                "Contents": {
                    "model": "gemini-2.5-flash",
                    "usage": {"total_tokens": 10},
                    "content_filter": True,
                    "content_filter_detail": {"message": "blocked"},
                },
            }
        ]

    _install(monkeypatch, llm_handler=filtered_llm)
    turn = plan_cmd.guardian_plan_cmd_call_llm([{"role": "system", "content": "s"}])
    assert turn["kind"] == "content_filter"
    assert turn["detail"] == "blocked"


def test_call_llm_empty_kind_no_choices(monkeypatch):
    def empty_llm(args):
        return [{"Type": 1, "Contents": {"model": "gemini-2.5-flash", "usage": {}, "choices": []}}]

    _install(monkeypatch, llm_handler=empty_llm)
    turn = plan_cmd.guardian_plan_cmd_call_llm([{"role": "system", "content": "s"}])
    assert turn["kind"] == "empty"


def test_call_llm_empty_kind_blank_content(monkeypatch):
    def empty_llm(args):
        return [
            {
                "Type": 1,
                "Contents": {
                    "model": "gemini-2.5-flash",
                    "usage": {},
                    "choices": [{"message": {"role": "assistant", "content": ""}}],
                },
            }
        ]

    _install(monkeypatch, llm_handler=empty_llm)
    turn = plan_cmd.guardian_plan_cmd_call_llm([{"role": "system", "content": "s"}])
    assert turn["kind"] == "empty"


# --- guardian_plan_cmd_run (end to end) -------------------------------------------


def test_run_success_posts_note_and_charges_cost(monkeypatch):
    _install(monkeypatch, incident_id="22486", incident={"id": "22486", "name": "Suspicious login"})
    ok, result = plan_cmd.guardian_plan_cmd_run()
    assert ok is True
    assert result["incident_id"] == "22486"
    assert result["plan"] == "1. Do X.\n2. Do Y."
    assert result["model"] == "gemini-2.5-flash"
    assert result["posted_to_war_room"] is True
    assert "plan cost" in result["cost_note"]


def test_run_mismatched_incident_id_is_a_usage_error(monkeypatch):
    _install(monkeypatch, incident_id="123")
    ok, result = plan_cmd.guardian_plan_cmd_run(requested_incident_id="456")
    assert ok is False
    assert "456" in result["error"]


def test_run_prompt_builder_failure_is_surfaced(monkeypatch):
    def failing_prompt(args):
        return [{"Type": 4, "Contents": "guardian_prompt_head unreadable"}]

    _install(monkeypatch, prompt_handler=failing_prompt)
    ok, result = plan_cmd.guardian_plan_cmd_run()
    assert ok is False
    assert "GuardianPromptBuilder failed" in result["error"]


def test_run_blank_prompt_is_surfaced(monkeypatch):
    def blank_prompt(args):
        return [{"Type": 1, "Contents": {"prompt": "   ", "meta": {}}}]

    _install(monkeypatch, prompt_handler=blank_prompt)
    ok, result = plan_cmd.guardian_plan_cmd_run()
    assert ok is False
    assert "no usable system prompt" in result["error"]


def test_run_non_dict_prompt_contents_is_surfaced(monkeypatch):
    # GuardianPromptBuilder's Contents is always a dict in practice, but a malformed/foreign
    # response (bare string, list, etc.) must degrade to the same clean error, never a raw
    # AttributeError from blindly calling .get() on it.
    def malformed_prompt(args):
        return [{"Type": 1, "Contents": "not-a-dict"}]

    _install(monkeypatch, prompt_handler=malformed_prompt)
    ok, result = plan_cmd.guardian_plan_cmd_run()
    assert ok is False
    assert "no usable system prompt" in result["error"]


def test_run_model_error_is_surfaced(monkeypatch):
    def failing_llm(args):
        return [{"Type": 4, "Contents": "timeout"}]

    _install(monkeypatch, llm_handler=failing_llm)
    ok, result = plan_cmd.guardian_plan_cmd_run()
    assert ok is False
    assert "model call failed" in result["error"]


def test_run_content_filter_is_surfaced(monkeypatch):
    def filtered_llm(args):
        return [
            {
                "Type": 1,
                "Contents": {
                    "model": "gemini-2.5-flash",
                    "usage": {},
                    "content_filter": True,
                    "content_filter_detail": {"message": "blocked for policy reasons"},
                },
            }
        ]

    _install(monkeypatch, llm_handler=filtered_llm)
    ok, result = plan_cmd.guardian_plan_cmd_run()
    assert ok is False
    assert "blocked for policy reasons" in result["error"]


def test_run_empty_response_is_surfaced(monkeypatch):
    def empty_llm(args):
        return [{"Type": 1, "Contents": {"model": "gemini-2.5-flash", "usage": {}, "choices": []}}]

    _install(monkeypatch, llm_handler=empty_llm)
    ok, result = plan_cmd.guardian_plan_cmd_run()
    assert ok is False
    assert "empty response" in result["error"]


def test_run_war_room_post_failure_does_not_fail_the_call(monkeypatch):
    def failing_addentries(args):
        return [{"Type": 4, "Contents": "addEntries is not available"}]

    _install(monkeypatch, addentries_handler=failing_addentries)
    ok, result = plan_cmd.guardian_plan_cmd_run()
    assert ok is True
    assert result["posted_to_war_room"] is False
    assert "warning" in result


def test_run_cost_ledger_failure_does_not_fail_the_call(monkeypatch):
    def failing_cost(args):
        return [{"Type": 4, "Contents": "GuardianCostLedger unavailable"}]

    _install(monkeypatch, cost_handler=failing_cost)
    ok, result = plan_cmd.guardian_plan_cmd_run()
    assert ok is True
    assert result["cost_note"] is None


def test_run_includes_loop_status_note_when_loop_present(monkeypatch):
    captured = {}

    def recording_llm(args):
        captured["args"] = args
        return _default_llm_handler(args)

    _install(
        monkeypatch,
        llm_handler=recording_llm,
        ctx={"Guardian": {"Loop": {"status": "running", "tick": 2, "messages": [1, 2]}}},
    )
    plan_cmd.guardian_plan_cmd_run()
    user_message = plan_cmd.guardian_arg_decode(captured["args"]["messages"])[1]["content"]  # b64 on XSIAM
    assert "status=running" in user_message


def test_run_never_writes_to_context(monkeypatch):
    _install(monkeypatch)

    def unexpected_set_context(path, value):
        raise AssertionError("GuardianPlanCommand must never write Context ({})".format(path))

    monkeypatch.setattr(plan_cmd.demisto, "setContext", unexpected_set_context)
    ok, result = plan_cmd.guardian_plan_cmd_run()
    assert ok is True


# --- guardian_plan_cmd_narrate ------------------------------------------------------


def test_narrate_includes_plan_and_model():
    text = plan_cmd.guardian_plan_cmd_narrate(
        {"model": "gemini-2.5-flash", "plan": "1. Do X.", "posted_to_war_room": True, "cost_note": "plan cost: $0.002, 600 tokens"}
    )
    assert "gemini-2.5-flash" in text
    assert "1. Do X." in text
    assert "plan cost" in text


def test_narrate_includes_warning_when_not_posted():
    text = plan_cmd.guardian_plan_cmd_narrate(
        {"model": "x", "plan": "plan text", "posted_to_war_room": False, "warning": "note failed", "cost_note": None}
    )
    assert "WARNING: note failed" in text


# --- main() smoke tests --------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    _install(monkeypatch)
    monkeypatch.setattr(plan_cmd.demisto, "args", lambda: {})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    plan_cmd.main()

    assert len(csp.RESULTS) == 1
    assert csp.RESULTS[0].outputs["plan"] == "1. Do X.\n2. Do Y."


def test_main_failure_calls_return_error(monkeypatch):
    import pytest

    def failing_llm(args):
        return [{"Type": 4, "Contents": "timeout"}]

    _install(monkeypatch, llm_handler=failing_llm)
    monkeypatch.setattr(plan_cmd.demisto, "args", lambda: {})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    with pytest.raises(SystemExit):
        plan_cmd.main()
    assert len(csp.RESULTS) == 0
