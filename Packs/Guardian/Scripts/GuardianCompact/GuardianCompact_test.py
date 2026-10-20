import json

import GuardianCompact as gc


# --- fixtures / test harness --------------------------------------------------


def _completion(content=None, usage=None, model="gemini-2.5-flash", content_filter=False):
    payload = {
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}}],
        "finish_reason": "stop",
        "content_filter": content_filter,
        "usage": usage or {"prompt_tokens": 500, "completion_tokens": 120, "total_tokens": 620},
    }
    if content_filter:
        payload["content_filter_detail"] = {"message": "blocked for testing"}
    return payload


def _llm_handler(completion, calls=None):
    calls = calls if calls is not None else []

    def handle(args):
        calls.append(dict(args))
        return [{"Type": 1, "Contents": completion}]

    handle.calls = calls
    return handle


def _install(monkeypatch, command_handlers=None):
    handlers = dict(command_handlers or {})

    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command dispatched: {} {}".format(command, args))
        return handlers[command](args)

    monkeypatch.setattr(gc.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(gc.demisto, "args", lambda: {})
    monkeypatch.setattr(gc.demisto, "error", lambda msg: None)
    monkeypatch.setattr(gc.demisto, "info", lambda msg: None)


def _tool_msg(call_id, content):
    return {"role": "tool", "tool_call_id": call_id, "content": content}


def _assistant_tool_call(call_id, name="ip", arguments=None):
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {"id": call_id, "type": "function", "function": {"name": name, "arguments": json.dumps(arguments or {})}}
        ],
    }


# --- guardian_compact_parse_messages_arg ---------------------------------------


def test_parse_messages_arg_accepts_list():
    messages, error = gc.guardian_compact_parse_messages_arg([{"role": "user", "content": "hi"}])
    assert error is None
    assert messages == [{"role": "user", "content": "hi"}]


def test_parse_messages_arg_accepts_json_string():
    raw = json.dumps([{"role": "user", "content": "hi"}])
    messages, error = gc.guardian_compact_parse_messages_arg(raw)
    assert error is None
    assert messages == [{"role": "user", "content": "hi"}]


def test_parse_messages_arg_rejects_missing():
    messages, error = gc.guardian_compact_parse_messages_arg(None)
    assert messages is None
    assert "required" in error


def test_parse_messages_arg_rejects_invalid_json():
    messages, error = gc.guardian_compact_parse_messages_arg("{not json")
    assert messages is None
    assert "not valid JSON" in error


def test_parse_messages_arg_rejects_non_array_json():
    messages, error = gc.guardian_compact_parse_messages_arg(json.dumps({"a": 1}))
    assert messages is None
    assert "must be a JSON array" in error


def test_parse_messages_arg_rejects_wrong_type():
    messages, error = gc.guardian_compact_parse_messages_arg(42)
    assert messages is None
    assert "must be a list" in error


# --- guardian_compact_split -----------------------------------------------------


def test_split_empty_messages():
    result = gc.guardian_compact_split([], keep_recent=5)
    assert result == {"prior_checkpoint": None, "old_portion": [], "kept_messages": []}


def test_split_everything_fits_within_keep_recent():
    messages = [{"role": "user", "content": "turn-{}".format(i)} for i in range(3)]
    result = gc.guardian_compact_split(messages, keep_recent=10)
    assert result["old_portion"] == []
    assert result["kept_messages"] == messages
    assert result["prior_checkpoint"] is None


def test_split_drops_oldest_into_old_portion():
    messages = [{"role": "user", "content": "turn-{}".format(i)} for i in range(10)]
    result = gc.guardian_compact_split(messages, keep_recent=3)
    assert len(result["old_portion"]) == 7
    assert len(result["kept_messages"]) == 3
    assert result["kept_messages"][-1]["content"] == "turn-9"
    assert result["old_portion"][0]["content"] == "turn-0"


def test_split_never_orphans_tool_reply_at_recent_window_start():
    # A naive fixed-size suffix cut can land exactly between an
    # assistant+tool_calls message and its own role:"tool" reply -- the
    # recent window must never start with an orphaned tool message.
    messages = []
    for i in range(5):
        messages.append({"role": "user", "content": "user-{}".format(i)})
        messages.append(_assistant_tool_call("call-{}".format(i)))
        messages.append(_tool_msg("call-{}".format(i), "result-{}".format(i)))

    # keep_recent=2 would naively cut right on a tool message (the last
    # trio's assistant+tool_calls before its own tool reply) -- confirm the
    # walk-forward boundary fix snaps past it.
    result = gc.guardian_compact_split(messages, keep_recent=2)
    assert result["kept_messages"][0]["role"] != "tool"

    seen_call_ids = set()
    for msg in result["kept_messages"]:
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            for call in msg["tool_calls"]:
                seen_call_ids.add(call["id"])
        elif msg.get("role") == "tool":
            assert msg["tool_call_id"] in seen_call_ids


def test_split_extracts_leading_prior_checkpoint():
    checkpoint = {"role": "system", "content": "old summary", "guardian_checkpoint": True, "covers_until": 5}
    messages = [checkpoint] + [{"role": "user", "content": "turn-{}".format(i)} for i in range(10)]
    result = gc.guardian_compact_split(messages, keep_recent=3)
    assert result["prior_checkpoint"] == checkpoint
    assert len(result["old_portion"]) == 7
    assert len(result["kept_messages"]) == 3
    # The checkpoint itself never ends up in either bucket.
    assert checkpoint not in result["old_portion"]
    assert checkpoint not in result["kept_messages"]


def test_split_uses_default_keep_recent_when_omitted():
    messages = [{"role": "user", "content": "turn-{}".format(i)} for i in range(30)]
    result = gc.guardian_compact_split(messages, keep_recent=None)
    assert len(result["kept_messages"]) == gc.GUARDIAN_COMPACT_DEFAULT_KEEP_RECENT


def test_split_negative_keep_recent_falls_back_to_default():
    messages = [{"role": "user", "content": "turn-{}".format(i)} for i in range(30)]
    result = gc.guardian_compact_split(messages, keep_recent=-5)
    assert len(result["kept_messages"]) == gc.GUARDIAN_COMPACT_DEFAULT_KEEP_RECENT


# --- guardian_compact_render_transcript -----------------------------------------


def test_render_transcript_basic_roles():
    messages = [
        {"role": "user", "content": "investigate 8.8.8.8"},
        {"role": "assistant", "content": "on it"},
    ]
    text = gc.guardian_compact_render_transcript(messages)
    assert "[1] user:\ninvestigate 8.8.8.8" in text
    assert "[2] assistant:\non it" in text


def test_render_transcript_labels_tool_messages_with_call_id():
    text = gc.guardian_compact_render_transcript([_tool_msg("call_1", "8.8.8.8 is benign")])
    assert "tool[call_1]:" in text
    assert "8.8.8.8 is benign" in text


def test_render_transcript_truncates_long_tool_content():
    long_content = "x" * (gc.GUARDIAN_COMPACT_TOOL_CONTENT_RENDER_CAP + 500)
    text = gc.guardian_compact_render_transcript([_tool_msg("call_1", long_content)])
    assert "[+500 chars]" in text
    assert len(text) < len(long_content)


def test_render_transcript_renders_assistant_tool_calls_with_no_content():
    text = gc.guardian_compact_render_transcript([_assistant_tool_call("call_1", "ip", {"ip": "8.8.8.8"})])
    assert "requested tool call(s): ip(" in text
    assert "8.8.8.8" in text


def test_render_transcript_empty_for_empty_input():
    assert gc.guardian_compact_render_transcript([]) == ""


# --- guardian_compact_call_llm --------------------------------------------------


def test_call_llm_uses_tool_choice_none_and_no_tools_key(monkeypatch):
    calls = []
    _install(monkeypatch, {"guardian-llm-chat": _llm_handler(_completion(content="a summary"), calls)})
    result = gc.guardian_compact_call_llm(gc.GUARDIAN_COMPACT_SUMMARIZE_INSTRUCTIONS, "some transcript", None)
    assert result["ok"] is True
    assert len(calls) == 1
    assert calls[0]["tool_choice"] == "none"
    assert "tools" not in calls[0]


def test_call_llm_prompt_carries_verbatim_identifier_instruction(monkeypatch):
    # Load-bearing per the task brief: the summarizer prompt MUST instruct
    # the model to copy opaque identifiers verbatim, never paraphrase.
    calls = []
    _install(monkeypatch, {"guardian-llm-chat": _llm_handler(_completion(content="a summary"), calls)})
    gc.guardian_compact_call_llm(gc.GUARDIAN_COMPACT_SUMMARIZE_INSTRUCTIONS, "some transcript", None)
    system_message = calls[0]["messages"][0]
    assert system_message["role"] == "system"
    assert "VERBATIM" in system_message["content"]
    assert "copy them EXACTLY" in system_message["content"]
    assert "never paraphrase" in system_message["content"].lower()


def test_summarize_instructions_require_flagging_unverified_assertions():
    # Live-caught 2026-08-22 (incident #316, medium-tier/command-r 32B): the
    # original instructions let a model's own ungrounded, pre-tool-call
    # speculation get folded into "findings already made" and copied
    # VERBATIM, which then got repeated as a confident, fabricated verdict.
    # The summarizer prompt must now require a fact/identifier to be backed
    # by a tool result or the incident's own record before it counts as a
    # finding -- anything the assistant merely asserted must be called out
    # as unverified.
    text = gc.GUARDIAN_COMPACT_SUMMARIZE_INSTRUCTIONS
    assert "UNVERIFIED" in text
    assert "tool call or incident-record field backing it" in text
    assert "never launder an unverified assertion into settled fact" in text.lower()


def test_call_llm_folds_prior_checkpoint_text_into_user_message(monkeypatch):
    calls = []
    _install(monkeypatch, {"guardian-llm-chat": _llm_handler(_completion(content="a summary"), calls)})
    gc.guardian_compact_call_llm(gc.GUARDIAN_COMPACT_SUMMARIZE_INSTRUCTIONS, "new transcript", "an old summary text")
    user_message = calls[0]["messages"][1]
    assert "[Prior compaction summary]" in user_message["content"]
    assert "an old summary text" in user_message["content"]
    assert "new transcript" in user_message["content"]


def test_call_llm_empty_transcript_and_no_prior_is_an_error(monkeypatch):
    _install(monkeypatch)
    result = gc.guardian_compact_call_llm(gc.GUARDIAN_COMPACT_SUMMARIZE_INSTRUCTIONS, "", None)
    assert result["ok"] is False
    assert "nothing to summarize" in result["error"]


def test_call_llm_transport_failure_returns_clear_error(monkeypatch):
    def failing(args):
        return [{"Type": 4, "Contents": "provider unreachable"}]

    _install(monkeypatch, {"guardian-llm-chat": failing})
    result = gc.guardian_compact_call_llm(gc.GUARDIAN_COMPACT_SUMMARIZE_INSTRUCTIONS, "transcript", None)
    assert result["ok"] is False
    assert "guardian-llm-chat failed" in result["error"]


def test_call_llm_content_filter_is_an_error(monkeypatch):
    calls = []
    _install(
        monkeypatch,
        {"guardian-llm-chat": _llm_handler(_completion(content_filter=True), calls)},
    )
    result = gc.guardian_compact_call_llm(gc.GUARDIAN_COMPACT_SUMMARIZE_INSTRUCTIONS, "transcript", None)
    assert result["ok"] is False
    assert "content filter" in result["error"]


def test_call_llm_blank_summary_is_an_error(monkeypatch):
    calls = []
    _install(monkeypatch, {"guardian-llm-chat": _llm_handler(_completion(content="   "), calls)})
    result = gc.guardian_compact_call_llm(gc.GUARDIAN_COMPACT_SUMMARIZE_INSTRUCTIONS, "transcript", None)
    assert result["ok"] is False
    assert "no usable summary" in result["error"]


def test_call_llm_returns_usage_and_model_on_success(monkeypatch):
    usage = {"prompt_tokens": 900, "completion_tokens": 250, "total_tokens": 1150}
    _install(
        monkeypatch,
        {"guardian-llm-chat": _llm_handler(_completion(content="a summary", usage=usage, model="gemini-2.5-flash"))},
    )
    result = gc.guardian_compact_call_llm(gc.GUARDIAN_COMPACT_SUMMARIZE_INSTRUCTIONS, "transcript", None)
    assert result["ok"] is True
    assert result["data"]["summary"] == "a summary"
    assert result["data"]["usage"] == usage
    assert result["data"]["model"] == "gemini-2.5-flash"


# --- guardian_compact_build_checkpoint ------------------------------------------


def test_build_checkpoint_shape():
    checkpoint = gc.guardian_compact_build_checkpoint("the summary text", messages_summarized=12)
    assert checkpoint["role"] == "system"
    assert checkpoint["guardian_checkpoint"] is True
    assert checkpoint["covers_until"] == 12
    assert "CONVERSATION CHECKPOINT" in checkpoint["content"]
    assert "the summary text" in checkpoint["content"]


# --- guardian_compact_run: full integration -------------------------------------


def test_run_success_shape_and_verbatim_identifiers_preserved(monkeypatch):
    messages = [
        {"role": "user", "content": "investigate 8.8.8.8, 1.1.1.1, and example.com"},
        _assistant_tool_call("call_1", "ip", {"ip": "8.8.8.8"}),
        _tool_msg("call_1", "8.8.8.8 reputation: Good, ASN 15169, hostname dns.google"),
        {"role": "user", "content": "keep going"},
    ]
    summary_text = (
        "The analyst is investigating 8.8.8.8, 1.1.1.1, and example.com. 8.8.8.8 was checked via the ip "
        "command and returned reputation Good, ASN 15169, hostname dns.google."
    )
    _install(
        monkeypatch,
        {"guardian-llm-chat": _llm_handler(_completion(content=summary_text))},
    )

    result = gc.guardian_compact_run({"messages": messages, "keep_recent": 1})
    assert result["ok"] is True
    data = result["data"]

    checkpoint = data["checkpoint"]
    assert checkpoint["role"] == "system"
    assert checkpoint["guardian_checkpoint"] is True
    assert "CONVERSATION CHECKPOINT" in checkpoint["content"]
    # Verbatim identifiers survive into the checkpoint content exactly.
    assert "8.8.8.8" in checkpoint["content"]
    assert "1.1.1.1" in checkpoint["content"]
    assert "example.com" in checkpoint["content"]
    assert "dns.google" in checkpoint["content"]

    # The recent window (last 1 message) is preserved verbatim, not summarized.
    assert data["kept_messages"] == [{"role": "user", "content": "keep going"}]
    assert data["messages_summarized"] == 3
    assert data["had_prior_checkpoint"] is False
    assert data["usage"]["total_tokens"] == 620
    assert data["model"] == "gemini-2.5-flash"


def test_run_folds_and_supersedes_prior_checkpoint(monkeypatch):
    prior_checkpoint = {
        "role": "system",
        "content": "CONVERSATION CHECKPOINT -- earlier turns summarized\nold summary mentions 10.0.0.1",
        "guardian_checkpoint": True,
        "covers_until": 4,
    }
    messages = [prior_checkpoint, {"role": "user", "content": "turn-a"}, {"role": "user", "content": "turn-b"}]
    calls = []
    _install(monkeypatch, {"guardian-llm-chat": _llm_handler(_completion(content="new summary"), calls)})

    result = gc.guardian_compact_run({"messages": messages, "keep_recent": 1})
    assert result["ok"] is True
    assert result["data"]["had_prior_checkpoint"] is True
    # Only ONE checkpoint message ever comes back -- the prior one is folded
    # into the summarizer input, not re-emitted alongside the new one.
    assert result["data"]["checkpoint"]["content"].count("CONVERSATION CHECKPOINT") == 1

    user_message = calls[0]["messages"][1]
    assert "10.0.0.1" in user_message["content"]


def test_run_nothing_to_compact_is_a_clear_error(monkeypatch):
    _install(monkeypatch)
    messages = [{"role": "user", "content": "turn-a"}, {"role": "user", "content": "turn-b"}]
    result = gc.guardian_compact_run({"messages": messages, "keep_recent": 10})
    assert result["ok"] is False
    assert "nothing to compact" in result["error"]


def test_run_llm_failure_returns_clear_error(monkeypatch):
    def failing(args):
        return [{"Type": 4, "Contents": "rate limited"}]

    _install(monkeypatch, {"guardian-llm-chat": failing})
    messages = [{"role": "user", "content": "turn-{}".format(i)} for i in range(10)]
    result = gc.guardian_compact_run({"messages": messages, "keep_recent": 2})
    assert result["ok"] is False
    assert "guardian-llm-chat failed" in result["error"]


def test_run_missing_messages_arg_is_a_clear_error(monkeypatch):
    _install(monkeypatch)
    result = gc.guardian_compact_run({})
    assert result["ok"] is False
    assert "required" in result["error"]


# --- main() ----------------------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    import CommonServerPython as csp

    messages = [{"role": "user", "content": "turn-{}".format(i)} for i in range(10)]
    _install(
        monkeypatch,
        {"guardian-llm-chat": _llm_handler(_completion(content="a summary"))},
    )
    monkeypatch.setattr(gc.demisto, "args", lambda: {"messages": messages, "keep_recent": 2})
    csp.RESULTS.clear()
    gc.main()
    assert len(csp.RESULTS) == 1
    outputs = csp.RESULTS[0].outputs
    assert outputs["checkpoint"]["guardian_checkpoint"] is True
    assert len(outputs["kept_messages"]) == 2


def test_main_failure_calls_return_error(monkeypatch):
    _install(monkeypatch)
    monkeypatch.setattr(gc.demisto, "args", lambda: {})
    errors = []
    monkeypatch.setattr(gc, "return_error", lambda msg, **kwargs: errors.append(msg), raising=False)
    gc.main()
    assert len(errors) == 1
    assert "GuardianCompact failed" in errors[0]


# --- tool results shown to the summarizer scale with the run's per-result limit; the request fits the budget -----


def _decode(value):
    """The request's messages as a list, whether this edition sends them as b64 text, JSON text or a list."""
    decoder = getattr(gc, "guardian_arg_decode", None)
    if isinstance(value, str):
        return decoder(value) if decoder else json.loads(value)
    return value


def _sent_tokens(calls):
    sent = _decode(calls[0]["messages"])
    return sum(gc.guardian_estimate_tokens(m) for m in sent)


def test_the_incident_pin_and_the_task_are_never_summarized():
    pin = {"role": "system", "content": "YOU ARE ALREADY WORKING THIS INCIDENT -- id 42"}
    task = {"role": "user", "content": "<untrusted-case-data>Investigate 42</untrusted-case-data>"}
    old = [_assistant_tool_call("c1"), _tool_msg("c1", "r1"), {"role": "user", "content": "keep going"}]
    recent = [{"role": "assistant", "content": "newest"}]
    for arrangement in ([pin, task] + old + recent, old[:1] + [pin] + old[1:] + [task] + recent):
        split = gc.guardian_compact_split(arrangement, 1)
        assert pin not in split["old_portion"] and task not in split["old_portion"]
        assert split["kept_messages"][:2] == [pin, task] and split["kept_messages"][-1] == recent[0]
        assert [m for m in split["old_portion"] if m.get("role") == "tool"] == [old[1]]
    # nothing left to summarize but the protected messages: they are returned, not folded away
    only = gc.guardian_compact_split([pin, task, recent[0]], 1)
    assert only["old_portion"] == [] and only["kept_messages"] == [pin, task, recent[0]]
    # a checkpoint is not protected: it is folded in as before
    checkpoint = {"role": "system", "content": "CONVERSATION CHECKPOINT", "guardian_checkpoint": True}
    assert gc.guardian_compact_split([checkpoint, pin, task] + old + recent, 1)["prior_checkpoint"] == checkpoint


def test_the_pin_and_the_task_never_reach_the_summarizer(monkeypatch):
    calls = []
    _install(monkeypatch, {"guardian-llm-chat": _llm_handler(_completion(content="summary"), calls)})
    pin = {"role": "system", "content": "YOU ARE ALREADY WORKING THIS INCIDENT -- id 42"}
    task = {"role": "user", "content": "<untrusted-case-data>Investigate 42</untrusted-case-data>"}
    messages = [pin, task, {"role": "user", "content": "older"}, {"role": "assistant", "content": "newer"}]
    result = gc.guardian_compact_run({"messages": messages, "keep_recent": 1})
    assert result["ok"] is True and result["data"]["kept_messages"] == [pin, task, messages[3]]
    sent = json.dumps(calls[0])
    assert "YOU ARE ALREADY WORKING" not in sent and "Investigate 42" not in sent


def test_render_transcript_cap_is_a_parameter_with_the_old_default():
    long_tool = [_tool_msg("c1", "y" * 5000)]
    assert "...[+3000 chars]" in gc.guardian_compact_render_transcript(long_tool)            # default cap 2000
    assert "...[+3000 chars]" not in gc.guardian_compact_render_transcript(long_tool, 17340)  # the large-model cap
    assert "y" * 5000 in gc.guardian_compact_render_transcript(long_tool, 17340)
    assert "...[+4000 chars]" in gc.guardian_compact_render_transcript(long_tool, 1000)
    for bad in (0, -3, "big", None, True):
        assert "...[+3000 chars]" in gc.guardian_compact_render_transcript(long_tool, bad)


def test_fit_transcript_shrinks_tool_results_then_cuts_the_middle():
    old = [{"role": "user", "content": "START-OF-CASE"}] + [_tool_msg("c{}".format(i), "t" * 20000) for i in range(10)] + [
        {"role": "assistant", "content": "NEWEST-TURN"}]
    instructions = "i" * 400
    # no budget: rendered as is
    text, cap, cut = gc.guardian_compact_fit_transcript(old, instructions, None, 20000, None)
    assert cap == 20000 and cut is False and len(text) > 100000
    # a budget that the full render exceeds: the per-tool cap halves until it fits
    text, cap, cut = gc.guardian_compact_fit_transcript(old, instructions, None, 20000, 12000)
    assert cap < 20000 and cut is False
    assert gc.guardian_estimate_tokens(instructions) + gc.guardian_estimate_tokens(text) <= 12000
    # so small that even the minimum cap does not fit: the middle is cut, the start and the newest turn stay
    text, cap, cut = gc.guardian_compact_fit_transcript(old, instructions, "p" * 8000, 20000, 2500)
    assert cut is True and "START-OF-CASE" in text and "NEWEST-TURN" in text and "omitted to fit" in text
    assert gc.guardian_estimate_tokens(instructions) + gc.guardian_estimate_tokens("p" * 8000) + gc.guardian_estimate_tokens(text) <= 2500 + 5


def test_run_sends_a_request_within_the_callers_budget_and_uses_its_render_cap(monkeypatch):
    calls = []
    _install(monkeypatch, {"guardian-llm-chat": _llm_handler(_completion(content="summary"), calls)})
    messages = [{"role": "user", "content": "go"}] + [_tool_msg("c{}".format(i), "q" * 60000) for i in range(8)] + [
        {"role": "assistant", "content": "ok"}]
    result = gc.guardian_compact_run({"messages": messages, "keep_recent": 1, "max_input_tokens": "9000", "tool_render_chars": "17340"})
    assert result["ok"] is True
    assert _sent_tokens(calls) <= 9000


def test_run_reads_the_runs_own_numbers_when_the_caller_passes_none(monkeypatch):
    calls = []
    _install(monkeypatch, {"guardian-llm-chat": _llm_handler(_completion(content="summary"), calls)})
    params = gc.guardian_resolve_model_params({"model_tier": "large"}, {"active": "a", "profiles": {"a": {"max_input_tokens": 173400}}})
    monkeypatch.setattr(gc, "guardian_run_model_params", lambda: (params, "snapshot"))
    messages = [{"role": "user", "content": "go"}, _tool_msg("c1", "w" * 30000), {"role": "assistant", "content": "ok"}]
    gc.guardian_compact_run({"messages": messages, "keep_recent": 1})
    sent = _decode(calls[0]["messages"])
    assert "w" * 17340 in sent[1]["content"] and "w" * 17341 not in sent[1]["content"]   # max(2000, 138720 / 8)


def test_run_without_any_numbers_keeps_the_old_cap_and_no_budget(monkeypatch):
    calls = []
    _install(monkeypatch, {"guardian-llm-chat": _llm_handler(_completion(content="summary"), calls)})
    monkeypatch.setattr(gc, "guardian_run_model_params", lambda: (None, None))
    messages = [{"role": "user", "content": "go"}, _tool_msg("c1", "w" * 30000), {"role": "assistant", "content": "ok"}]
    gc.guardian_compact_run({"messages": messages, "keep_recent": 1})
    sent = _decode(calls[0]["messages"])
    assert "w" * 2000 in sent[1]["content"] and "w" * 2001 not in sent[1]["content"]
