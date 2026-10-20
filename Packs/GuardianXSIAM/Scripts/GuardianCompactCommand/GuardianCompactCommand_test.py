import json

import GuardianCompactCommand as compact_cmd


# --- fixtures / test harness --------------------------------------------------


def _install(monkeypatch, incident_id="999", compact_handler=None, cost_handler=None, rest_post_handler=None):
    ctx = {}

    def fake_set_context(path, value):
        parts = path.split(".")
        cur = ctx
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = value
        return {"status": True}

    monkeypatch.setattr(compact_cmd.demisto, "context", lambda: ctx)
    monkeypatch.setattr(compact_cmd.demisto, "setContext", fake_set_context)
    monkeypatch.setattr(compact_cmd.demisto, "incident", lambda: {"id": incident_id} if incident_id else {})
    monkeypatch.setattr(compact_cmd.demisto, "error", lambda msg: None)
    monkeypatch.setattr(compact_cmd.demisto, "info", lambda msg: None)

    default_compact = lambda args: [
        {
            "Type": 1,
            "Contents": {
                "checkpoint": {"role": "system", "guardian_checkpoint": True, "content": "summary", "covers_until": 2},
                "kept_messages": [{"role": "user", "content": "recent"}],
                "messages_summarized": 2,
                "had_prior_checkpoint": False,
                "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
                "model": "gemini-2.5-flash",
            },
        }
    ]
    default_cost = lambda args: [
        {"Type": 1, "Contents": {"usd": 0.001, "tokens": {"total_tokens": 120}}}
    ]
    default_rest = lambda args: [{"Type": 1, "Contents": {"response": {"data": [{"id": incident_id, "version": 3}]}}}]

    handlers = {
        "GuardianCompact": compact_handler or default_compact,
        "GuardianCostLedger": cost_handler or default_cost,
        "demisto-api-post": rest_post_handler or default_rest,
        "core-api-post": rest_post_handler or default_rest,
    }

    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command dispatched: {} {}".format(command, args))
        return handlers[command](args)

    monkeypatch.setattr(compact_cmd.demisto, "executeCommand", fake_execute)
    return ctx


def _seed_loop(ctx, messages, extra=None):
    loop = {"messages": messages, "tick": 5, "status": "running"}
    if extra:
        loop.update(extra)
    ctx["Guardian"] = {"Loop": loop}


# --- guardian_compact_cmd_resolve_incident_id -------------------------------------


def test_resolve_incident_id_defaults_to_current(monkeypatch):
    _install(monkeypatch, incident_id="123")
    ok, incident_id, error = compact_cmd.guardian_compact_cmd_resolve_incident_id(None)
    assert ok is True
    assert incident_id == "123"


def test_resolve_incident_id_rejects_mismatch(monkeypatch):
    _install(monkeypatch, incident_id="123")
    ok, incident_id, error = compact_cmd.guardian_compact_cmd_resolve_incident_id("456")
    assert ok is False
    assert "456" in error and "123" in error


# --- guardian_compact_cmd_run: no loop / nothing to compact -----------------------


def test_no_active_loop_is_a_usage_error(monkeypatch):
    _install(monkeypatch)
    ok, result = compact_cmd.guardian_compact_cmd_run()
    assert ok is False
    assert "no active Guardian Agent Loop" in result["error"]


def test_mismatched_incident_id_is_a_usage_error(monkeypatch):
    ctx = _install(monkeypatch, incident_id="123")
    _seed_loop(ctx, [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}])
    ok, result = compact_cmd.guardian_compact_cmd_run(requested_incident_id="456")
    assert ok is False
    assert "456" in result["error"]


def test_nothing_to_compact_is_a_friendly_error(monkeypatch):
    def nothing_handler(args):
        return [{"Type": 4, "Contents": "NEEDS_CONTEXT: nothing to compact -- 'messages' fit entirely."}]

    ctx = _install(monkeypatch, compact_handler=nothing_handler)
    _seed_loop(ctx, [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}])
    ok, result = compact_cmd.guardian_compact_cmd_run()
    assert ok is False
    assert "Nothing to compact" in result["error"]


def test_bad_keep_recent_arg_is_a_usage_error(monkeypatch):
    ctx = _install(monkeypatch)
    _seed_loop(ctx, [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}])
    ok, result = compact_cmd.guardian_compact_cmd_run(keep_recent="not-a-number")
    assert ok is False
    assert "keep_recent" in result["error"]


def test_engine_failure_is_surfaced(monkeypatch):
    def failing_handler(args):
        return [{"Type": 4, "Contents": "guardian-llm-chat call failed: timeout"}]

    ctx = _install(monkeypatch, compact_handler=failing_handler)
    _seed_loop(ctx, [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}])
    ok, result = compact_cmd.guardian_compact_cmd_run()
    assert ok is False
    assert "GuardianCompact failed" in result["error"]


# --- guardian_compact_cmd_run: success path ---------------------------------------


def test_success_strips_system_message_before_calling_engine(monkeypatch):
    captured = {}

    def recording_handler(args):
        captured["args"] = args
        return [
            {
                "Type": 1,
                "Contents": {
                    "checkpoint": {"role": "system", "guardian_checkpoint": True, "content": "s"},
                    "kept_messages": [{"role": "user", "content": "recent"}],
                    "messages_summarized": 2,
                    "had_prior_checkpoint": False,
                    "usage": None,
                    "model": None,
                },
            }
        ]

    ctx = _install(monkeypatch, compact_handler=recording_handler)
    system_msg = {"role": "system", "content": "sys"}
    messages = [system_msg, {"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}, {"role": "user", "content": "recent"}]
    _seed_loop(ctx, messages)

    ok, result = compact_cmd.guardian_compact_cmd_run()
    assert ok is True
    assert compact_cmd.guardian_arg_decode(captured["args"]["messages"]) == messages[2:]  # b64 on XSIAM; the task (messages[1]) stays
    assert "keep_recent" not in captured["args"]  # omitted when not given


def test_success_passes_keep_recent_override(monkeypatch):
    captured = {}

    def recording_handler(args):
        captured["args"] = args
        return [
            {
                "Type": 1,
                "Contents": {
                    "checkpoint": {"role": "system", "guardian_checkpoint": True, "content": "s"},
                    "kept_messages": [],
                    "messages_summarized": 1,
                    "had_prior_checkpoint": False,
                    "usage": None,
                    "model": None,
                },
            }
        ]

    ctx = _install(monkeypatch, compact_handler=recording_handler)
    _seed_loop(ctx, [{"role": "system", "content": "sys"}, {"role": "user", "content": "a"}])

    compact_cmd.guardian_compact_cmd_run(keep_recent="3")
    assert captured["args"]["keep_recent"] == 3


def test_success_rebuilds_transcript_and_persists_whole_loop_dict(monkeypatch):
    ctx = _install(monkeypatch)
    system_msg = {"role": "system", "content": "sys"}
    messages = [system_msg, {"role": "user", "content": "old1"}, {"role": "user", "content": "old2"}, {"role": "user", "content": "recent"}]
    _seed_loop(ctx, messages, extra={"cost_usd": 0.01, "cost_tokens_total": 500, "dropped_count": 3})

    ok, result = compact_cmd.guardian_compact_cmd_run()
    assert ok is True
    loop = ctx["Guardian"]["Loop"]
    assert loop["messages"][0] == system_msg
    assert loop["messages"][1] == {"role": "user", "content": "old1"}      # the first user message is the task: it stays
    assert loop["messages"][2]["guardian_checkpoint"] is True
    assert loop["messages"][3] == {"role": "user", "content": "recent"}
    assert loop["dropped_count"] == 3 + 2  # prior 3 + this call's 2 summarized (the stub engine reports 2)
    # tick/status untouched
    assert loop["tick"] == 5
    assert loop["status"] == "running"


def test_success_charges_cost_and_accumulates_onto_loop(monkeypatch):
    ctx = _install(monkeypatch)
    _seed_loop(
        ctx,
        [{"role": "system", "content": "sys"}, {"role": "user", "content": "a"}, {"role": "user", "content": "b"}],
        extra={"cost_usd": 0.005, "cost_tokens_total": 200},
    )
    ok, result = compact_cmd.guardian_compact_cmd_run()
    assert ok is True
    loop = ctx["Guardian"]["Loop"]
    assert round(loop["cost_usd"], 6) == round(0.005 + 0.001, 6)
    assert loop["cost_tokens_total"] == 200 + 120
    assert "compaction cost" in result["cost_note"] or result["cost_note"] is not None


def test_success_with_no_usage_reports_no_cost_note(monkeypatch):
    def no_usage_handler(args):
        return [
            {
                "Type": 1,
                "Contents": {
                    "checkpoint": {"role": "system", "guardian_checkpoint": True, "content": "s"},
                    "kept_messages": [],
                    "messages_summarized": 2,
                    "had_prior_checkpoint": False,
                    "usage": None,
                    "model": None,
                },
            }
        ]

    def unexpected_cost_call(args):
        raise AssertionError("GuardianCostLedger should not be called when usage is empty")

    ctx = _install(monkeypatch, compact_handler=no_usage_handler, cost_handler=unexpected_cost_call)
    _seed_loop(ctx, [{"role": "system", "content": "sys"}, {"role": "user", "content": "a"}, {"role": "user", "content": "b"}])

    ok, result = compact_cmd.guardian_compact_cmd_run()
    assert ok is True
    assert result["cost_note"] is None


def test_cost_ledger_failure_does_not_fail_the_compaction(monkeypatch):
    def failing_cost(args):
        return [{"Type": 4, "Contents": "GuardianCostLedger unavailable"}]

    ctx = _install(monkeypatch, cost_handler=failing_cost)
    _seed_loop(ctx, [{"role": "system", "content": "sys"}, {"role": "user", "content": "a"}, {"role": "user", "content": "b"}])

    ok, result = compact_cmd.guardian_compact_cmd_run()
    assert ok is True
    assert result["cost_note"] is None


def test_whole_dict_write_not_a_subpath_write(monkeypatch):
    ctx = _install(monkeypatch)
    _seed_loop(ctx, [{"role": "system", "content": "sys"}, {"role": "user", "content": "a"}, {"role": "user", "content": "b"}])

    calls = []
    real_set_context = compact_cmd.demisto.setContext

    def recording_set_context(path, value):
        calls.append(path)
        return real_set_context(path, value)

    monkeypatch.setattr(compact_cmd.demisto, "setContext", recording_set_context)
    compact_cmd.guardian_compact_cmd_run()
    assert calls == ["Guardian.Loop"]


# --- guardian_compact_cmd_narrate --------------------------------------------------


def test_narrate_includes_counts_and_cost():
    text = compact_cmd.guardian_compact_cmd_narrate(
        {"messages_summarized": 5, "kept_count": 3, "had_prior_checkpoint": False, "cost_note": "compaction cost: $0.001, 120 tokens"}
    )
    assert "summarized 5 message(s)" in text
    assert "3 message(s) preserved" in text
    assert "compaction cost" in text


def test_narrate_mentions_prior_checkpoint_superseded():
    text = compact_cmd.guardian_compact_cmd_narrate(
        {"messages_summarized": 5, "kept_count": 3, "had_prior_checkpoint": True, "cost_note": None}
    )
    assert "superseding a prior checkpoint" in text


# --- main() smoke tests --------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    ctx = _install(monkeypatch)
    _seed_loop(ctx, [{"role": "system", "content": "sys"}, {"role": "user", "content": "a"}, {"role": "user", "content": "b"}])
    monkeypatch.setattr(compact_cmd.demisto, "args", lambda: {})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    compact_cmd.main()

    assert len(csp.RESULTS) == 1
    assert csp.RESULTS[0].outputs["messages_summarized"] == 2


def test_main_no_loop_calls_return_error(monkeypatch):
    import pytest

    _install(monkeypatch)
    monkeypatch.setattr(compact_cmd.demisto, "args", lambda: {})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    with pytest.raises(SystemExit):
        compact_cmd.main()
    assert len(csp.RESULTS) == 0


def test_the_pin_and_the_task_are_kept_verbatim_and_never_sent_to_the_summarizer(monkeypatch):
    captured = {}

    def recording_handler(args):
        captured["args"] = args
        return [{"Type": 1, "Contents": {
            "checkpoint": {"role": "system", "guardian_checkpoint": True, "content": "s"},
            "kept_messages": [{"role": "user", "content": "recent"}], "messages_summarized": 2,
            "had_prior_checkpoint": False, "usage": None, "model": None}}]

    ctx = _install(monkeypatch, compact_handler=recording_handler)
    head = [{"role": "system", "content": "sys"}, {"role": "system", "content": "YOU ARE ALREADY WORKING THIS INCIDENT -- id 999"},
            {"role": "user", "content": "<untrusted-case-data>investigate</untrusted-case-data>"}]
    _seed_loop(ctx, head + [{"role": "user", "content": "old"}, {"role": "assistant", "content": "older"}, {"role": "user", "content": "recent"}])
    ok, _result = compact_cmd.guardian_compact_cmd_run()
    assert ok is True
    saved = ctx["Guardian"]["Loop"]["messages"]
    assert saved[:3] == head and saved[3]["guardian_checkpoint"] is True and saved[4] == {"role": "user", "content": "recent"}
    decode = getattr(compact_cmd, "guardian_arg_decode", None)   # b64 text on the Cortex platform edition, plain on XSOAR 6
    sent = json.dumps(decode(captured["args"]["messages"]) if decode else captured["args"]["messages"])
    assert "old" in sent and "YOU ARE ALREADY WORKING" not in sent and "investigate" not in sent
