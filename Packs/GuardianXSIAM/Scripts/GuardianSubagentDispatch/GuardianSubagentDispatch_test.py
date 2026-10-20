import json

import GuardianSubagentDispatch as gsd


# --- fixtures / test harness --------------------------------------------------

#: Mirrors the phishing-analyst's real allowed_tools -- plus a couple of
#: EXTRA schemas (a command NOT in that specialist's allowed_tools, and
#: GuardianSubagentDispatch itself) so filtering tests can prove both are
#: stripped even though they're present on the "real" main-loop catalogue.
FULL_CATALOG = [
    {"type": "function", "function": {"name": "url", "description": "look up a URL", "parameters": {}}},
    {"type": "function", "function": {"name": "domain", "description": "look up a domain", "parameters": {}}},
    {"type": "function", "function": {"name": "ews-search-mailbox", "description": "search mailbox", "parameters": {}}},
    {"type": "function", "function": {"name": "GuardianKBSearch", "description": "kb search", "parameters": {}}},
    {"type": "function", "function": {"name": "xdr-isolate-endpoint", "description": "isolate", "parameters": {}}},
    {"type": "function", "function": {"name": "GuardianSubagentDispatch", "description": "dispatch", "parameters": {}}},
]


def _install(
    monkeypatch,
    llm_turns=None,
    catalog=None,
    bridge_handler=None,
    incident=None,
    catalog_error=False,
    cost_handler=None,
):
    """Wires demisto.executeCommand for GuardianToolCatalogBuilder,
    guardian-llm-chat (a scripted sequence of completions from `llm_turns`),
    GuardianToolBridge (routed through `bridge_handler(tool_name, args) ->
    tool_result dict`, default: always succeeds with a canned Contents echo),
    GuardianAuditWrite (captured into the returned sink), and (FIX D)
    GuardianCostLedger (routed through `cost_handler(args)`, default: a
    working ledger that records each charge and returns a canned
    `{"usd", "tokens": {"total_tokens"}}`).

    :return: ``{"audit_calls": [...], "llm_calls": [...], "bridge_calls":
        [...], "cost_calls": [...]}``
    """
    catalog = FULL_CATALOG if catalog is None else catalog
    llm_turns = list(llm_turns or [])
    audit_calls = []
    llm_calls = []
    bridge_calls = []
    cost_calls = []

    def handle_catalog_builder(args):
        if catalog_error:
            return [{"Type": 4, "Contents": "catalog builder exploded"}]
        return [{"Type": 1, "Contents": {"catalog": catalog}}]

    def handle_llm(args):
        llm_calls.append(args)
        if not llm_turns:
            raise AssertionError("guardian-llm-chat called more times than llm_turns provided")
        return [{"Type": 1, "Contents": llm_turns.pop(0)}]

    def handle_cost_ledger(args):
        cost_calls.append(args)
        if cost_handler:
            return cost_handler(args)
        return [{"Type": 1, "Contents": {"usd": 0.0012, "tokens": {"total_tokens": 345}}}]

    def handle_bridge(args):
        bridge_calls.append(args)
        tool_name = args["tool_name"]
        tool_args = args.get("tool_args")
        parsed_args = json.loads(tool_args) if isinstance(tool_args, str) and tool_args else (tool_args or {})
        if bridge_handler:
            tool_result = bridge_handler(tool_name, parsed_args)
        else:
            tool_result = {
                "tool_call_id": args.get("tool_call_id"),
                "tool_name": tool_name,
                "status": "ok",
                "ok": True,
                "result": {"echo": parsed_args},
                "error": None,
            }
        return [{"Type": 1, "Contents": {"tool_result": tool_result}}]

    def handle_audit(args):
        audit_calls.append(args)
        return [{"Type": 1, "Contents": "Guardian audit row written"}]

    handlers = {
        "GuardianToolCatalogBuilder": handle_catalog_builder,
        "guardian-llm-chat": handle_llm,
        "GuardianToolBridge": handle_bridge,
        "GuardianAuditWrite": handle_audit,
        "GuardianCostLedger": handle_cost_ledger,
    }

    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command dispatched: {} {}".format(command, args))
        return handlers[command](args)

    monkeypatch.setattr(gsd.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(gsd.demisto, "incident", lambda: dict(incident) if incident else {"id": "42"})
    monkeypatch.setattr(gsd.demisto, "error", lambda msg: None)
    monkeypatch.setattr(gsd.demisto, "context", lambda: {})
    monkeypatch.setattr(gsd.demisto, "setContext", lambda path, value: {"status": True})

    return {
        "audit_calls": audit_calls,
        "llm_calls": llm_calls,
        "bridge_calls": bridge_calls,
        "cost_calls": cost_calls,
    }


def _assistant_tool_call(call_id, name, arguments):
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{"id": call_id, "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}}],
                }
            }
        ]
    }


def _assistant_final(text):
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


# --- input validation ----------------------------------------------------------


def test_run_rejects_unknown_specialist(monkeypatch):
    _install(monkeypatch)
    result = gsd.guardian_subagent_run("unknown-guy", "do something", None)
    assert result["ok"] is False
    assert "unknown specialist" in result["error"]


def test_run_rejects_missing_task(monkeypatch):
    _install(monkeypatch)
    result = gsd.guardian_subagent_run("phishing-analyst", "   ", None)
    assert result["ok"] is False
    assert "'task' is required" in result["error"]


def test_run_rejects_missing_specialist(monkeypatch):
    _install(monkeypatch)
    result = gsd.guardian_subagent_run(None, "investigate", None)
    assert result["ok"] is False
    assert "'specialist' is required" in result["error"]


# --- the bounded loop happy path ------------------------------------------------


def test_happy_path_one_tool_call_then_final_summary(monkeypatch):
    sink = _install(
        monkeypatch,
        llm_turns=[
            _assistant_tool_call("call-1", "url", {"url": "http://evil.example"}),
            _assistant_final("This looks like phishing. Confidence: high."),
        ],
    )

    result = gsd.guardian_subagent_run("phishing-analyst", "Is this URL phishing?", None)

    assert result["ok"] is True
    data = result["data"]
    assert data["specialist"] == "phishing-analyst"
    assert data["summary"] == "This looks like phishing. Confidence: high."
    assert data["iterations_used"] == 2
    assert data["max_iterations"] == 3  # default
    assert data["bounded_exit"] is False
    assert data["tool_calls"] == [{"tool_name": "url", "status": "ok", "ok": True}]

    # exactly one real sub-tool-call dispatched through GuardianToolBridge
    assert len(sink["bridge_calls"]) == 1
    assert sink["bridge_calls"][0]["tool_name"] == "url"

    # exactly one audit row for the whole run
    assert len(sink["audit_calls"]) == 1
    assert sink["audit_calls"][0]["action"] == "GuardianSubagentDispatch"
    assert sink["audit_calls"][0]["target"] == "phishing-analyst"
    assert sink["audit_calls"][0]["status"] == "ok"
    assert sink["audit_calls"][0]["detail"]["bounded_exit"] is False


def test_run_with_no_tool_calls_returns_final_message_immediately(monkeypatch):
    sink = _install(monkeypatch, llm_turns=[_assistant_final("Not phishing, this is legitimate.")])

    result = gsd.guardian_subagent_run("phishing-analyst", "check this", 3)

    assert result["data"]["summary"] == "Not phishing, this is legitimate."
    assert result["data"]["iterations_used"] == 1
    assert sink["bridge_calls"] == []


# --- max_iterations: default / clamping -----------------------------------------


def test_max_iterations_defaults_when_none_given(monkeypatch):
    _install(monkeypatch, llm_turns=[_assistant_final("done")])
    result = gsd.guardian_subagent_run("phishing-analyst", "check this", None)
    assert result["data"]["max_iterations"] == gsd.GUARDIAN_SUBAGENT_DEFAULT_MAX_ITERATIONS


def test_max_iterations_defaults_on_invalid_value(monkeypatch):
    _install(monkeypatch, llm_turns=[_assistant_final("done")])
    result = gsd.guardian_subagent_run("phishing-analyst", "check this", "not-a-number")
    assert result["data"]["max_iterations"] == gsd.GUARDIAN_SUBAGENT_DEFAULT_MAX_ITERATIONS


def test_max_iterations_clamped_to_hard_ceiling(monkeypatch):
    """SAFETY invariant (bounded ticks): requesting far more than the hard
    ceiling still clamps to it -- a model cannot talk its way past the
    ceiling by just asking for more."""
    turns = [_assistant_tool_call("c{}".format(i), "url", {"url": "x"}) for i in range(20)]
    _install(monkeypatch, llm_turns=turns)

    result = gsd.guardian_subagent_run("phishing-analyst", "check this", 999)

    assert result["data"]["max_iterations"] == gsd.GUARDIAN_SUBAGENT_HARD_MAX_ITERATIONS
    assert result["data"]["iterations_used"] == gsd.GUARDIAN_SUBAGENT_HARD_MAX_ITERATIONS


def test_max_iterations_floor_is_one_not_zero(monkeypatch):
    _install(monkeypatch, llm_turns=[_assistant_final("done")])
    result = gsd.guardian_subagent_run("phishing-analyst", "check this", 0)
    assert result["data"]["max_iterations"] == 1


# --- bounded exit: forced closing turn ------------------------------------------


def test_bounded_exit_forces_a_closing_summary_when_budget_exhausted(monkeypatch):
    """SAFETY invariant (bounded ticks): if the specialist NEVER volunteers a
    final answer (keeps requesting tool calls every turn), the loop still
    stops at max_iterations and forces exactly ONE more, tools-stripped
    closing turn -- which itself cannot request further tool calls."""
    turns = [_assistant_tool_call("c{}".format(i), "url", {"url": "x"}) for i in range(3)]
    turns.append(_assistant_final("Forced summary: inconclusive, budget exhausted."))
    sink = _install(monkeypatch, llm_turns=turns)

    result = gsd.guardian_subagent_run("phishing-analyst", "check this", 3)

    assert result["data"]["bounded_exit"] is True
    assert result["data"]["iterations_used"] == 3
    assert result["data"]["summary"] == "Forced summary: inconclusive, budget exhausted."
    # 3 regular turns + 1 forced closing turn = 4 guardian-llm-chat calls
    assert len(sink["llm_calls"]) == 4
    # the forced closing call must never offer tools
    assert "tools" not in sink["llm_calls"][-1]
    assert sink["llm_calls"][-1]["tool_choice"] == "none"


def test_bounded_exit_with_no_closing_content_falls_back_to_placeholder(monkeypatch):
    turns = [_assistant_tool_call("c{}".format(i), "url", {"url": "x"}) for i in range(3)]
    turns.append({"choices": []})  # closing turn produces nothing usable
    _install(monkeypatch, llm_turns=turns)

    result = gsd.guardian_subagent_run("phishing-analyst", "check this", 3)

    assert result["data"]["bounded_exit"] is True
    assert "exhausted its iteration budget" in result["data"]["summary"]


def test_content_filter_turn_stops_loop_and_forces_closing_summary(monkeypatch):
    turns = [{"content_filter": True, "content_filter_detail": {"message": "blocked"}}, _assistant_final("closing")]
    sink = _install(monkeypatch, llm_turns=turns)

    result = gsd.guardian_subagent_run("phishing-analyst", "check this", 3)

    assert result["data"]["bounded_exit"] is True
    assert result["data"]["summary"] == "closing"
    assert sink["bridge_calls"] == []


# --- no-recursion + filtered tool subset (SECURITY-CRITICAL) --------------------


def test_no_recursion_self_dispatch_refused_without_calling_bridge(monkeypatch):
    """The dispatch tool can never call itself -- refused LOCALLY, never
    reaching demisto.executeCommand('GuardianToolBridge', ...) at all."""
    turns = [
        _assistant_tool_call("c-1", "GuardianSubagentDispatch", {"specialist": "phishing-analyst", "task": "x"}),
        _assistant_final("gave up trying to recurse"),
    ]
    sink = _install(monkeypatch, llm_turns=turns)

    result = gsd.guardian_subagent_run("phishing-analyst", "check this", 3)

    assert result["ok"] is True
    assert result["data"]["tool_calls"] == [
        {"tool_name": "GuardianSubagentDispatch", "status": "denied", "ok": False}
    ]
    assert sink["bridge_calls"] == []  # never reached the bridge


def test_out_of_scope_tool_call_refused_without_calling_bridge(monkeypatch):
    """A command not in this specialist's allowed_tools (even one for a
    genuinely destructive action) is refused locally -- never dispatched."""
    turns = [
        _assistant_tool_call("c-1", "xdr-isolate-endpoint", {"endpoint_id": "ep-1"}),
        _assistant_final("could not isolate, not in scope"),
    ]
    sink = _install(monkeypatch, llm_turns=turns)

    result = gsd.guardian_subagent_run("phishing-analyst", "check this", 3)

    assert result["data"]["tool_calls"] == [{"tool_name": "xdr-isolate-endpoint", "status": "denied", "ok": False}]
    assert sink["bridge_calls"] == []


def test_filtered_catalog_excludes_out_of_scope_and_self(monkeypatch):
    """guardian_subagent_load_filtered_catalog must intersect the real
    catalogue with the specialist's allowed_tools -- xdr-isolate-endpoint and
    GuardianSubagentDispatch itself (both present on the FAKE 'real'
    catalogue in this test) must never appear in the filtered result."""
    _install(monkeypatch)
    allowed_tools = gsd.guardian_subagent_resolve_tool_subset(gsd.GUARDIAN_SUBAGENT_REGISTRY["phishing-analyst"])

    result = gsd.guardian_subagent_load_filtered_catalog(allowed_tools)

    assert result["ok"] is True
    names = {schema["function"]["name"] for schema in result["data"]}
    assert "GuardianSubagentDispatch" not in names
    assert "xdr-isolate-endpoint" not in names
    assert "url" in names
    assert "ews-search-mailbox" in names


def test_resolve_tool_subset_strips_self_even_if_registry_named_it(monkeypatch):
    """Defense-in-depth: even a (hypothetical) registry entry that named
    GuardianSubagentDispatch in its own allowed_tools would have it stripped."""
    fake_entry = {"allowed_tools": ("url", "GuardianSubagentDispatch", "domain")}
    resolved = gsd.guardian_subagent_resolve_tool_subset(fake_entry)
    assert "GuardianSubagentDispatch" not in resolved
    assert resolved == ("url", "domain")


# --- real dispatch through GuardianToolBridge (in-scope calls) ------------------


def test_in_scope_tool_call_dispatches_through_bridge_and_logs_result(monkeypatch):
    def bridge_handler(tool_name, args):
        assert tool_name == "domain"
        return {"tool_call_id": "c-1", "tool_name": "domain", "status": "ok", "ok": True, "result": {"verdict": "bad"}, "error": None}

    turns = [
        _assistant_tool_call("c-1", "domain", {"domain": "evil.example"}),
        _assistant_final("Confirmed malicious domain."),
    ]
    sink = _install(monkeypatch, llm_turns=turns, bridge_handler=bridge_handler)

    result = gsd.guardian_subagent_run("phishing-analyst", "check this domain", 3)

    assert result["data"]["tool_calls"] == [{"tool_name": "domain", "status": "ok", "ok": True}]
    assert len(sink["bridge_calls"]) == 1
    assert sink["bridge_calls"][0]["tool_args"] == json.dumps({"domain": "evil.example"})


def test_bridge_dispatch_failure_is_logged_but_run_continues(monkeypatch):
    """A failing GuardianToolBridge executeCommand call (e.g. a transport
    error, not a normal denied/pending_approval result) becomes an "error"
    tool_result -- the loop still continues to the specialist's next turn
    rather than aborting the whole run."""
    turns = [_assistant_tool_call("c-1", "url", {"url": "x"}), _assistant_final("done anyway")]
    _install(monkeypatch, llm_turns=turns)

    original_execute = gsd.demisto.executeCommand

    def patched_execute(command, args):
        if command == "GuardianToolBridge":
            raise RuntimeError("transport exploded")
        return original_execute(command, args)

    monkeypatch.setattr(gsd.demisto, "executeCommand", patched_execute)

    result = gsd.guardian_subagent_run("phishing-analyst", "check this", 3)

    assert result["ok"] is True
    assert result["data"]["summary"] == "done anyway"
    assert result["data"]["tool_calls"] == [{"tool_name": "url", "status": "error", "ok": False}]


# --- pending_approval sub-tool-call is handled like any other result -----------


def test_pending_approval_sub_tool_call_is_handled_gracefully(monkeypatch):
    """If a specialist's tool were ever (mis)tiered require_approval, the
    bridge's pending_approval result is just another tool_result -- the
    subagent loop doesn't crash or special-case it."""

    def bridge_handler(tool_name, args):
        return {
            "tool_call_id": "c-1",
            "tool_name": tool_name,
            "status": "pending_approval",
            "ok": False,
            "result": {"approval_id": "abc"},
            "error": "approval required",
        }

    turns = [_assistant_tool_call("c-1", "url", {"url": "x"}), _assistant_final("noted, could not confirm")]
    sink = _install(monkeypatch, llm_turns=turns, bridge_handler=bridge_handler)

    result = gsd.guardian_subagent_run("phishing-analyst", "check this", 3)

    assert result["ok"] is True
    assert result["data"]["tool_calls"] == [{"tool_name": "url", "status": "pending_approval", "ok": False}]


# --- error paths -----------------------------------------------------------------


def test_llm_call_failure_returns_error_envelope(monkeypatch):
    def failing_executor(command, args):
        if command == "GuardianToolCatalogBuilder":
            return [{"Type": 1, "Contents": {"catalog": FULL_CATALOG}}]
        if command == "guardian-llm-chat":
            raise RuntimeError("provider down")
        raise AssertionError("unexpected command: {}".format(command))

    _install(monkeypatch)
    monkeypatch.setattr(gsd.demisto, "executeCommand", failing_executor)

    result = gsd.guardian_subagent_run("phishing-analyst", "check this", 3)

    assert result["ok"] is False
    assert "subagent LLM call failed" in result["error"]


def test_catalog_builder_failure_returns_error_envelope(monkeypatch):
    _install(monkeypatch, catalog_error=True)
    result = gsd.guardian_subagent_run("phishing-analyst", "check this", 3)
    assert result["ok"] is False
    assert "failed to build filtered tool catalogue" in result["error"]


# --- main() ------------------------------------------------------------------


def test_main_success_writes_context_and_returns_results(monkeypatch):
    import CommonServerPython as csp

    csp.RESULTS.clear()
    _install(monkeypatch, llm_turns=[_assistant_final("All clear, not phishing.")])
    monkeypatch.setattr(gsd.demisto, "args", lambda: {"specialist": "phishing-analyst", "task": "check this"})

    gsd.main()

    assert len(csp.RESULTS) == 1
    outputs = csp.RESULTS[0].outputs
    assert outputs["summary"] == "All clear, not phishing."
    assert outputs["specialist"] == "phishing-analyst"


def test_main_calls_return_error_on_unknown_specialist(monkeypatch):
    import pytest

    _install(monkeypatch)
    monkeypatch.setattr(gsd.demisto, "args", lambda: {"specialist": "nope", "task": "check this"})

    with pytest.raises(SystemExit) as exc_info:
        gsd.main()

    assert "unknown specialist" in str(exc_info.value)


def test_main_handles_unexpected_exception(monkeypatch):
    import pytest
    monkeypatch.setattr(gsd.demisto, "args", lambda: {"specialist": "phishing-analyst", "task": "x"})

    def explode(specialist, task, max_iterations):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(gsd, "guardian_subagent_run", explode)

    with pytest.raises(SystemExit) as exc_info:
        gsd.main()

    assert "unexpectedly" in str(exc_info.value)


# --- FIX D: subagent LLM turns charged to GuardianCostLedger ------------------


def _assistant_final_with_usage(text, usage=None, model="gemini-2.5-flash"):
    completion = {"choices": [{"message": {"role": "assistant", "content": text}}]}
    completion["usage"] = usage or {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
    completion["model"] = model
    return completion


def test_subagent_turn_charges_cost_ledger(monkeypatch):
    """FIX D core: a subagent model turn must result in a GuardianCostLedger
    charge, attributed to the parent incident (run_id) under a
    subagent-scoped trigger."""
    sink = _install(
        monkeypatch,
        llm_turns=[_assistant_final_with_usage("Not phishing.")],
        incident={"id": "77"},
    )

    result = gsd.guardian_subagent_run("phishing-analyst", "check this", 3)

    assert result["ok"] is True
    # Exactly one model turn -> exactly one cost-ledger charge.
    assert len(sink["cost_calls"]) == 1
    charge = sink["cost_calls"][0]
    assert charge["run_id"] == "77"  # attributed to the parent incident/run
    assert charge["trigger"] == "guardian_subagent:phishing-analyst"
    # The turn's own usage was forwarded (JSON-encoded, same as the main tick).
    assert json.loads(charge["usage"])["total_tokens"] == 150
    assert charge["model"] == "gemini-2.5-flash"
    # The dispatch result surfaces the accumulated cost (canned $0.0012/345tok).
    assert result["data"]["cost_usd"] == 0.0012
    assert result["data"]["cost_tokens_total"] == 345
    # And the audit row carries the same cost story.
    assert sink["audit_calls"][0]["detail"]["cost_usd"] == 0.0012


def test_subagent_charges_every_turn_including_forced_closing(monkeypatch):
    """Each guardian-llm-chat turn is billed -- 3 tool-calling turns + the 1
    forced closing turn = 4 cost-ledger charges, and the accumulated total is
    the sum of all four canned charges."""
    turns = [_assistant_tool_call("c{}".format(i), "url", {"url": "x"}) for i in range(3)]
    turns.append(_assistant_final_with_usage("Forced summary."))
    sink = _install(monkeypatch, llm_turns=turns)

    result = gsd.guardian_subagent_run("phishing-analyst", "check this", 3)

    assert len(sink["llm_calls"]) == 4
    assert len(sink["cost_calls"]) == 4  # one charge per real provider turn
    assert result["data"]["cost_usd"] == round(0.0012 * 4, 6)
    assert result["data"]["cost_tokens_total"] == 345 * 4


def test_subagent_cost_ledger_failure_does_not_break_run(monkeypatch):
    """Cost accounting is observability, not a correctness gate: a failing
    GuardianCostLedger call is swallowed (logged), the run still succeeds, and
    the accumulated cost simply stays 0."""
    sink = _install(
        monkeypatch,
        llm_turns=[_assistant_final_with_usage("Not phishing.")],
        cost_handler=lambda args: [{"Type": 4, "Contents": "ledger unavailable"}],
    )

    result = gsd.guardian_subagent_run("phishing-analyst", "check this", 3)

    assert result["ok"] is True
    assert result["data"]["summary"] == "Not phishing."
    assert len(sink["cost_calls"]) == 1  # the charge WAS attempted
    assert result["data"]["cost_usd"] == 0.0  # ...but nothing accrued on failure


def test_subagent_charge_turn_cost_noops_on_error_kind(monkeypatch):
    """The charge helper must no-op for an 'error' turn (nothing reached the
    provider, so nothing to bill) -- never even calling GuardianCostLedger."""
    sink = _install(monkeypatch, llm_turns=[_assistant_final("x")])
    charged = gsd.guardian_subagent_charge_turn_cost(
        {"kind": "error", "error": "boom"}, "77", "guardian_subagent:phishing-analyst"
    )
    assert charged == {"usd": 0.0, "total_tokens": 0}
    assert sink["cost_calls"] == []  # never dispatched


# --- tool results scale with the run's numbers and the specialist's request stays within the input budget --------


def _run_numbers(budget, tier="large"):
    return gsd.guardian_resolve_model_params({"model_tier": tier}, {"active": "a", "profiles": {"a": {"max_input_tokens": budget}}})


def test_subagent_limits_follow_the_runs_numbers_and_keep_the_old_cap_without_them(monkeypatch):
    monkeypatch.setattr(gsd, "guardian_run_model_params", lambda: (None, None))
    assert gsd.guardian_subagent_limits() == (8000, None)
    monkeypatch.setattr(gsd, "guardian_run_model_params", lambda: (_run_numbers(173400), "snapshot"))
    assert gsd.guardian_subagent_limits() == (138720, 173400 * 4 * 60 // 100)
    monkeypatch.setattr(gsd, "guardian_run_model_params", lambda: (_run_numbers(28258, "small"), "run state"))
    assert gsd.guardian_subagent_limits() == (22606, 28258 * 4 * 60 // 100)


def test_the_subagent_tool_message_is_cut_at_the_cap_it_is_given():
    result = {"tool_call_id": "c", "tool_name": "url", "status": "ok", "result": "HEAD-" + "m" * 50000 + "-TAIL"}
    default = gsd.guardian_subagent_tool_message(result)["content"]
    assert len(default) < 8000 + 100 and "subagent tool message truncated" in default
    wide = gsd.guardian_subagent_tool_message(result, 138720)["content"]
    assert "truncated" not in wide and len(wide) > 50000
    narrow = gsd.guardian_subagent_tool_message(result, 3000)["content"]
    assert len(narrow) < 3100 and '-TAIL"' in narrow[-30:]


def _decode(value):
    """A request argument as Python data, whether this edition sends it as b64 text, JSON text or as is."""
    decoder = getattr(gsd, "guardian_arg_decode", None)
    if isinstance(value, str):
        return decoder(value) if decoder else json.loads(value)
    return value


def test_every_subagent_request_stays_within_the_input_budget(monkeypatch):
    budget = 28258
    monkeypatch.setattr(gsd, "guardian_run_model_params", lambda: (_run_numbers(budget, "small"), "snapshot"))
    huge = lambda name, args: {"tool_call_id": "c", "tool_name": name, "status": "ok", "ok": True,  # noqa: E731
                               "result": "r" * 400000, "error": None}
    calls = [{"id": "c{}".format(i), "type": "function", "function": {"name": "url", "arguments": json.dumps({"url": "http://x/{}".format(i)})}}
             for i in range(6)]
    turns = [{"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": calls}}]}] * 4
    sink = _install(monkeypatch, llm_turns=turns + [_assistant_final("summary")], bridge_handler=huge)
    result = gsd.guardian_subagent_run("phishing-analyst", "check the url", 5)
    assert result["ok"] is True
    assert len(sink["llm_calls"]) >= 4
    for call in sink["llm_calls"]:
        sent = _decode(call["messages"])
        tools = _decode(call["tools"]) if call.get("tools") else None
        total = sum(gsd.guardian_estimate_tokens(m) for m in sent) + (gsd.guardian_estimate_tokens(tools) if tools else 0)
        assert total <= budget, total
