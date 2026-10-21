import json
from pathlib import Path

import pytest

import GuardianReasoningTick as tick


REPO_ROOT = Path(__file__).resolve().parents[4]


def _shipped_list_text(list_name):
    path = REPO_ROOT / "Packs" / "Guardian" / "Lists" / "list-{}.json".format(list_name)
    data = json.loads(path.read_text())["data"]
    try:
        data = json.loads(data)
    except ValueError:
        pass
    return json.dumps(data, sort_keys=True) if isinstance(data, (dict, list)) else data


# --- fixtures / test harness --------------------------------------------------

DEFAULT_KILL_SWITCH = {"enabled": False}
DEFAULT_SETTINGS = {
    "MAX_TICKS": 25,
    "tick_cadence_seconds": 12,
    "batch_cap": 25,
    "evidence_truncate_bytes": 16384,
}


def _getlist_handler(list_payloads):
    def handle(args):
        name = args["listName"]
        if name == "guardian_model_profile" and name not in list_payloads:
            return [{"Type": 4, "Contents": "Item not found (8)"}]  # the optional measured profile
        if name not in list_payloads:
            raise AssertionError("no fixture wired for getList listName={}".format(name))
        payload = list_payloads[name]
        contents = payload if isinstance(payload, str) else json.dumps(payload)
        return [{"Type": 1, "Contents": contents}]

    return handle


def _default_cost_ledger_handler(args):
    """A working (not just silently-tolerated-as-unwired) default
    GuardianCostLedger stub, wired into every `_install()` call by default --
    Task 1.7 (PART A) adds a GuardianCostLedger call to EVERY LLM turn, so
    without a default handler every pre-existing test would either need
    updating individually or would silently no-op its cost charging (
    `guardian_execute`'s own try/except around `demisto.executeCommand`
    converts an unwired-command AssertionError into a quiet `ok=False`
    envelope, which `guardian_tick_charge_turn_cost` treats as "nothing to
    charge" rather than failing loudly) -- giving every test a REAL,
    functioning cost pipeline by default is more representative and catches
    real regressions a silent no-op would hide. Computes a small
    deterministic USD figure from `usage` (mirrors GuardianCostLedger's own
    non-cached-prompt + completion pricing) so tests asserting `cost_usd`
    grew can rely on it being nonzero for a non-empty usage payload.
    """
    usage = args.get("usage")
    if isinstance(usage, str):
        usage = json.loads(usage) if usage.strip() else {}
    usage = usage or {}
    prompt_tokens = usage.get("prompt_tokens") or 0
    completion_tokens = usage.get("completion_tokens") or 0
    cached_tokens = usage.get("cached_tokens") or 0
    total_tokens = usage.get("total_tokens") or (prompt_tokens + completion_tokens)
    usd = round(((prompt_tokens - cached_tokens) * 0.30 + completion_tokens * 2.50) / 1_000_000.0, 8)
    cost = {
        "usd": usd,
        "tokens": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "cached_tokens": cached_tokens,
            "total_tokens": total_tokens,
        },
        "model": args.get("model"),
        "day": "2026-07-05",
        "trigger": args.get("trigger"),
        "run_id": args.get("run_id"),
        "rollup_updated": True,
        "rollup_bucket": None,
        "warning": None,
    }
    return [{"Type": 1, "Contents": cost}]


def _make_fake_incident_store(incident_id):
    """Seed a single fake incident record for the default `demisto-api-post`
    stub below -- shaped enough (`id`, `version`, `CustomFields`) for
    `guardian_set_incident_fields`'s REST full-object-merge round trip
    (GuardianCommon, Task D1) to exercise for real against the test harness,
    mirroring the incident shape confirmed live against XSOAR 6.14.0.
    """
    return {str(incident_id): {"id": str(incident_id), "version": 1, "CustomFields": {}}}


def _default_demisto_api_post_handler(fake_incidents):
    """Default `demisto-api-post` stub (Task D1's `guardiancostusd`/
    `guardiantickcount` field writes go through `guardian_set_incident_fields`,
    which speaks REST, not the `setIncident` command) -- simulates the REST
    full-object-merge contract that helper relies on: `/incidents/search`
    returns the current fake incident(s) by id, `/incident` merges the
    posted body's `CustomFields` into the stored record (bumping `version`,
    mirroring the server's own optimistic-lock counter) and echoes the
    updated object back. Mirrors the real XSOAR response shape verified live
    on XSOAR 6.14.0 (Task D1 report): `Contents == {"response": <body>}`.

    Tests that care about the exact fields written inspect `fake_incidents`
    directly (exposed off the `_install()` return value's `ctx["_incidents"]`
    for convenience) rather than the raw command args.
    """

    def handle(args):
        uri = args.get("uri")
        raw_body = args.get("body")
        try:
            payload = json.loads(raw_body) if isinstance(raw_body, str) and raw_body.strip() else (raw_body or {})
        except ValueError:
            payload = {}

        if uri == "/incidents/search":
            wanted_ids = {str(i) for i in ((payload.get("filter") or {}).get("id") or [])}
            matches = [dict(inc) for iid, inc in fake_incidents.items() if iid in wanted_ids]
            return [{"Type": 1, "Contents": {"response": {"total": len(matches), "data": matches}}}]

        if uri == "/incident":
            incident_id = str(payload.get("id"))
            updated = dict(payload)
            updated["version"] = (payload.get("version") or 1) + 1
            fake_incidents[incident_id] = updated
            return [{"Type": 1, "Contents": {"response": dict(updated)}}]

        raise AssertionError("no fixture wired for demisto-api-post uri={}".format(uri))

    return handle


def _default_get_context_handler(ctx):
    """Default `getContext` stub (Task 2.2 review fix "chat-write race"):
    mirrors the REAL server's native `!getContext id=<incident>` response
    shape (`{"cacheVersn":..., "context": {...the WHOLE incident context
    tree...}}` -- confirmed live on XSOAR 6.14.0) by handing back the SAME
    live `ctx` dict `fake_set_context` mutates -- a real, working default so
    every pre-existing test exercises the actual fresh-read-and-merge
    codepath (finding nothing new to merge, since nothing mutates
    `ctx["Guardian"]["Loop"]["pending_user_input"]` behind the tick's back in
    those tests) rather than silently no-op'ing on an unwired command. Tests
    simulating a genuinely concurrent chat write override this via
    `command_handlers={"getContext": ...}` with their own fixed, late
    snapshot -- see
    `test_late_analyst_chat_write_is_merged_not_dropped_at_final_persist`.
    """

    def handle(args):
        return [{"Type": 1, "Contents": {"cacheVersn": 0, "context": ctx}}]

    return handle


def _install(
    monkeypatch, kill_switch=None, settings=None, command_handlers=None, incident_id="999", approvals_ledger=None,
    model_profile=None, extra_lists=None,
):
    """Wires demisto.executeCommand/context/setContext/incident with a
    real-shaped in-memory context dict, so guardian_ctx_read/write behave
    exactly as they do against the live server (dotted-path reads over a
    nested dict; a whole-subtree replace per write). Any command dispatched
    that isn't wired here raises AssertionError -- a test can't silently
    pass over an unexpected call.

    `GuardianCostLedger`/`demisto-api-post` get working defaults so EVERY
    test exercises the real cost-charging + incident-field-write path unless
    it overrides them via `command_handlers` -- see
    `_default_cost_ledger_handler` / `_default_demisto_api_post_handler`. The
    returned `ctx` dict also carries the fake incident store at
    `ctx["_incidents"]` (keyed by string incident id) for tests asserting on
    what `guardian_set_incident_fields` actually persisted. `getContext` also
    gets a working default (Task 2.2 review fix "chat-write race" --
    `guardian_tick_persist_with_merge` dispatches it on EVERY persist) -- see
    `_default_get_context_handler`.
    """
    ctx = {}
    list_payloads = {
        "guardian_kill_switch": DEFAULT_KILL_SWITCH if kill_switch is None else kill_switch,
        "guardian_settings": DEFAULT_SETTINGS if settings is None else settings,
        # Task 3.1: the approvals ledger this tick's Step 5 reads fresh every
        # invocation while `Loop.pending` is set. Defaults to empty (no row
        # ever found -> "still pending", the same behavior a genuinely
        # unreadable/absent List produces) -- tests exercising a real
        # approve/deny resolution pass their own row list via
        # `approvals_ledger=` (also exposed back at `ctx["_approvals_ledger"]`
        # -- the SAME list object `setList`/`guardian_tick_expire_approval`
        # mutate in place, mirroring GuardianToolBridge_test.py's identical
        # fixture).
        "guardian_approvals_ledger": [] if approvals_ledger is None else approvals_ledger,
    }
    if model_profile is not None:
        list_payloads["guardian_model_profile"] = model_profile
    list_payloads.update(extra_lists or {})
    fake_incidents = _make_fake_incident_store(incident_id) if incident_id else {}

    def _default_set_list_handler(args):
        # Preserve object identity for list-shaped payloads (mirrors
        # GuardianToolBridge_test.py's identical fixture) so a test that
        # captured `list_payloads["guardian_approvals_ledger"]` (or mutated
        # it directly before the call) keeps seeing the live content after a
        # `setList` write (Task 3.1's `guardian_tick_expire_approval`).
        name = args["listName"]
        new_value = json.loads(args["listData"])
        old = list_payloads.get(name)
        if isinstance(old, list) and isinstance(new_value, list):
            old[:] = new_value
        else:
            list_payloads[name] = new_value
        return [{"Type": 1, "Contents": "Done: list updated"}]

    handlers = {
        "getList": _getlist_handler(list_payloads),
        "GuardianCostLedger": _default_cost_ledger_handler,
        "demisto-api-post": _default_demisto_api_post_handler(fake_incidents),
        "getContext": _default_get_context_handler(ctx),
        "setList": _default_set_list_handler,
    }
    if command_handlers:
        handlers.update(command_handlers)

    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command dispatched: {} {}".format(command, args))
        return handlers[command](args)

    def fake_set_context(path, value):
        parts = path.split(".")
        cur = ctx
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = value
        return {"status": True}

    monkeypatch.setattr(tick.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(tick.demisto, "context", lambda: ctx)
    monkeypatch.setattr(tick.demisto, "setContext", fake_set_context)
    monkeypatch.setattr(tick.demisto, "incident", lambda: {"id": incident_id} if incident_id else {})
    monkeypatch.setattr(tick.demisto, "error", lambda msg: None)
    monkeypatch.setattr(tick.demisto, "info", lambda msg: None)
    ctx["_incidents"] = fake_incidents
    ctx["_approvals_ledger"] = list_payloads["guardian_approvals_ledger"]
    return ctx


def _ok_getlist(contents):
    return lambda args: [{"Type": 1, "Contents": contents if isinstance(contents, str) else json.dumps(contents)}]


def _prompt_builder_handler(prompt_text="SYSTEM PROMPT"):
    # Mirrors GuardianPromptBuilder's real main(): CommandResults(raw_response=
    # {"prompt":..., "meta":...}) -- the tick reads this straight from the
    # executeCommand response's Contents, NOT via a same-execution Context
    # re-read (see GuardianReasoningTick.py's "Component callers" docstring
    # note -- this was a real bug caught on the lab tenant, not a hypothetical).
    def handle(args):
        return [{"Type": 1, "Contents": {"prompt": prompt_text, "meta": {}}}]

    return handle


def _catalog_builder_handler(catalog=None):
    # Mirrors GuardianToolCatalogBuilder's real main(): CommandResults(
    # raw_response={"catalog": [...], ...}).
    def handle(args):
        return [{"Type": 1, "Contents": {"catalog": catalog if catalog is not None else []}}]

    return handle


def _catalog_builder_handler_counting(catalog=None):
    """Same as `_catalog_builder_handler`, but records every call for a
    call-count assertion (used by the review round-1 IMPORTANT-3 regression
    test: the builder must run exactly once on tick 0, not twice).
    """
    calls = []

    def handle(args):
        calls.append(args)
        return [{"Type": 1, "Contents": {"catalog": catalog if catalog is not None else []}}]

    handle.calls = calls
    return handle


def _completion(content=None, tool_calls=None, content_filter=False, usage=None):
    payload = {
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}}],
        "finish_reason": "tool_calls" if tool_calls else "stop",
        "content_filter": content_filter,
        "usage": usage or {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }
    if tool_calls:
        payload["choices"][0]["message"]["tool_calls"] = tool_calls
    if content_filter:
        payload["content_filter_detail"] = {"message": "blocked for testing"}
    return payload


def _llm_handler_sequence(completions):
    """Returns a guardian-llm-chat handler that yields each completion in
    `completions` in order (one per call) as the executeCommand response's
    own Contents (mirrors GuardianLLM's real
    CommandResults(raw_response=result)), and records every call's args for
    inspection.
    """
    calls = []

    def handle(args):
        calls.append(args)
        idx = len(calls) - 1
        completion = completions[idx] if idx < len(completions) else completions[-1]
        return [{"Type": 1, "Contents": completion}]

    handle.calls = calls
    return handle


def _tool_bridge_handler(result_by_tool_name=None, default_result=None, full_payload=None):
    # Mirrors GuardianToolBridge's real main(): CommandResults(raw_response=
    # {"tool_result": {...}, "audit": {...}, "full_payload": ...}).
    def handle(args):
        tool_name = args.get("tool_name")
        if result_by_tool_name and tool_name in result_by_tool_name:
            result = dict(result_by_tool_name[tool_name])
        elif default_result is not None:
            result = dict(default_result)
        else:
            raise AssertionError("no fixture wired for GuardianToolBridge tool_name={}".format(tool_name))
        result.setdefault("tool_call_id", args.get("tool_call_id"))
        result.setdefault("tool_name", tool_name)
        result.setdefault("truncated", False)
        result.setdefault("truncation_note", None)
        return [{"Type": 1, "Contents": {"tool_result": result, "audit": {}, "full_payload": full_payload}}]

    return handle


def _tool_call(call_id, name, arguments_obj):
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": json.dumps(arguments_obj)}}


def _compact_handler(
    summary_text="stub compaction summary",
    kept_messages=None,
    messages_summarized=None,
    usage=None,
    model="gemini-2.5-flash",
    had_prior_checkpoint=False,
):
    """Mirrors GuardianCompact's real main(): CommandResults(raw_response={
    "checkpoint": {...}, "kept_messages": [...], ...}). Records every call's
    args for inspection (Task 1.8 tick-integration tests).
    """
    calls = []

    def handle(args):
        calls.append(dict(args))
        n_summarized = messages_summarized if messages_summarized is not None else len(args.get("messages") or []) - len(
            kept_messages if kept_messages is not None else []
        )
        data = {
            "checkpoint": {
                "role": "system",
                "content": "CONVERSATION CHECKPOINT -- earlier turns summarized\n{}".format(summary_text),
                "guardian_checkpoint": True,
                "covers_until": n_summarized,
            },
            "kept_messages": kept_messages if kept_messages is not None else [],
            "messages_summarized": n_summarized,
            "had_prior_checkpoint": had_prior_checkpoint,
            "usage": usage or {"prompt_tokens": 400, "completion_tokens": 100, "total_tokens": 500},
            "model": model,
        }
        return [{"Type": 1, "Contents": data}]

    handle.calls = calls
    return handle


def _compact_failure_handler(error_message="summarizer unavailable"):
    calls = []

    def handle(args):
        calls.append(dict(args))
        return [{"Type": 4, "Contents": error_message}]

    handle.calls = calls
    return handle


def _full_settings(batch_cap=25, compact_after_dropped=5, **overrides):
    """A complete `guardian_tick_load_settings()`-shaped dict (Task 1.8 adds
    `compact_after_dropped`/`output_reserve_tokens` to that shape) for tests
    that call the compaction helpers directly rather than through
    `guardian_tick_load_settings` itself.
    """
    settings = {
        "max_ticks": 25,
        "cadence_seconds": 12,
        "batch_cap": batch_cap,
        "evidence_truncate_bytes": 16384,
        "max_same_call": 3,
        "max_repeats": 4,
        "compact_after_dropped": compact_after_dropped,
        "output_reserve_tokens": 4096,
        "readable": True,
    }
    settings.update(overrides)
    return settings


def _long_transcript(n, prefix="turn"):
    return [{"role": "user", "content": "{}-{}".format(prefix, i)} for i in range(n)]


# --- guardian_tick_check_kill_switch ------------------------------------------


def test_kill_switch_halted(monkeypatch):
    _install(monkeypatch, kill_switch={"enabled": True})
    assert tick.guardian_tick_check_kill_switch() == {"halted": True}


def test_kill_switch_not_halted(monkeypatch):
    _install(monkeypatch, kill_switch={"enabled": False})
    assert tick.guardian_tick_check_kill_switch() == {"halted": False}


def test_kill_switch_unreadable_fails_open(monkeypatch):
    ctx = _install(monkeypatch)

    def broken_getlist(args):
        if args["listName"] == "guardian_kill_switch":
            return [{"Type": 4, "Contents": "Item not found (8) on list [...]"}]
        return _getlist_handler({"guardian_settings": DEFAULT_SETTINGS})(args)

    monkeypatch.setattr(
        tick.demisto,
        "executeCommand",
        lambda command, args: broken_getlist(args) if command == "getList" else (_ for _ in ()).throw(
            AssertionError("unexpected command {}".format(command))
        ),
    )
    assert tick.guardian_tick_check_kill_switch() == {"halted": False}


# --- guardian_tick_resolve_job_name / guardian_tick_check_job_guard / report --


def test_resolve_job_name_maps_known_triggersource(monkeypatch):
    monkeypatch.setattr(
        tick.demisto, "incident", lambda: {"id": "1", "CustomFields": {"guardiantriggersource": "job:intake-sweep"}}
    )
    assert tick.guardian_tick_resolve_job_name() == "GuardianIntakeSweep"


def test_resolve_job_name_none_for_unmapped_triggersource(monkeypatch):
    """A manually-created investigation, an eval run, etc. -- any trigger
    source not in the mapping table is NOT a Job-spawned run; JobGuard must
    never be consulted for it."""
    monkeypatch.setattr(
        tick.demisto, "incident", lambda: {"id": "1", "CustomFields": {"guardiantriggersource": "eval"}}
    )
    assert tick.guardian_tick_resolve_job_name() is None


def test_resolve_job_name_none_when_no_triggersource(monkeypatch):
    monkeypatch.setattr(tick.demisto, "incident", lambda: {"id": "1", "CustomFields": {}})
    assert tick.guardian_tick_resolve_job_name() is None


def test_resolve_job_name_none_when_incident_unreadable(monkeypatch):
    monkeypatch.setattr(tick.demisto, "incident", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert tick.guardian_tick_resolve_job_name() is None


def test_check_job_guard_not_halted_when_proceed_true(monkeypatch):
    def fake_execute(command, args):
        assert command == "GuardianJobGuard"
        assert args == {"action": "check", "job_name": "GuardianIntakeSweep"}
        return [{"Type": 1, "Contents": {"proceed": True, "job_name": "GuardianIntakeSweep"}}]

    monkeypatch.setattr(tick.demisto, "executeCommand", fake_execute)
    assert tick.guardian_tick_check_job_guard("GuardianIntakeSweep") == {"halted": False, "reason": None}


def test_check_job_guard_halted_when_proceed_false(monkeypatch):
    def fake_execute(command, args):
        return [{"Type": 1, "Contents": {"proceed": False, "reason": "job_disabled"}}]

    monkeypatch.setattr(tick.demisto, "executeCommand", fake_execute)
    assert tick.guardian_tick_check_job_guard("GuardianIntakeSweep") == {"halted": True, "reason": "job_disabled"}


def test_check_job_guard_fails_open_on_command_error(monkeypatch):
    monkeypatch.setattr(tick.demisto, "executeCommand", lambda command, args: [{"Type": 4, "Contents": "boom"}])
    monkeypatch.setattr(tick.demisto, "error", lambda msg: None)
    assert tick.guardian_tick_check_job_guard("GuardianIntakeSweep") == {"halted": False, "reason": None}


def test_check_job_guard_fails_open_on_malformed_contents(monkeypatch):
    monkeypatch.setattr(tick.demisto, "executeCommand", lambda command, args: [{"Type": 1, "Contents": "not a dict"}])
    monkeypatch.setattr(tick.demisto, "error", lambda msg: None)
    assert tick.guardian_tick_check_job_guard("GuardianIntakeSweep") == {"halted": False, "reason": None}


def test_report_job_guard_maps_done_to_success(monkeypatch):
    calls = []
    monkeypatch.setattr(
        tick.demisto,
        "executeCommand",
        lambda command, args: calls.append((command, args)) or [{"Type": 1, "Contents": {"ok": True}}],
    )
    tick.guardian_tick_report_job_guard("GuardianIntakeSweep", "done")
    assert calls == [("GuardianJobGuard", {"action": "report", "job_name": "GuardianIntakeSweep", "outcome": "success"})]


def test_report_job_guard_maps_every_non_done_status_to_failure(monkeypatch):
    """Product decision: 'stopped' (kill-switch toggle or denied approval
    included) and 'error' both count toward JobGuard's consecutive-failure
    threshold -- simplicity over distinguishing why a run stopped."""
    for status in ("stopped", "error", None, "something-unexpected"):
        calls = []
        monkeypatch.setattr(
            tick.demisto,
            "executeCommand",
            lambda command, args: calls.append((command, args)) or [{"Type": 1, "Contents": {"ok": True}}],
        )
        tick.guardian_tick_report_job_guard("GuardianIntakeSweep", status)
        assert calls == [
            ("GuardianJobGuard", {"action": "report", "job_name": "GuardianIntakeSweep", "outcome": "failure"})
        ], status


def test_report_job_guard_never_raises_on_command_error(monkeypatch):
    monkeypatch.setattr(tick.demisto, "executeCommand", lambda command, args: [{"Type": 4, "Contents": "boom"}])
    monkeypatch.setattr(tick.demisto, "error", lambda msg: None)
    tick.guardian_tick_report_job_guard("GuardianIntakeSweep", "done")  # must not raise


# --- guardian_tick_load_settings -----------------------------------------------


def test_load_settings_uses_defaults_when_unreadable(monkeypatch):
    def broken_getlist(args):
        return [{"Type": 4, "Contents": "boom"}]

    monkeypatch.setattr(tick.demisto, "executeCommand", broken_getlist)
    monkeypatch.setattr(tick.demisto, "error", lambda msg: None)
    settings = tick.guardian_tick_load_settings()
    assert settings["max_ticks"] == tick.GUARDIAN_DEFAULT_MAX_TICKS
    assert settings["cadence_seconds"] == tick.GUARDIAN_DEFAULT_TICK_CADENCE_SECONDS
    assert settings["readable"] is False


def test_load_settings_clamps_cadence_floor(monkeypatch):
    _install(monkeypatch, settings={"tick_cadence_seconds": 2, "MAX_TICKS": 25, "batch_cap": 25})
    settings = tick.guardian_tick_load_settings()
    assert settings["cadence_seconds"] == tick.GUARDIAN_MIN_CADENCE_SECONDS


def test_load_settings_honors_configured_values(monkeypatch):
    _install(monkeypatch, settings={"MAX_TICKS": 7, "tick_cadence_seconds": 20, "batch_cap": 40})
    settings = tick.guardian_tick_load_settings()
    assert settings["max_ticks"] == 7
    assert settings["cadence_seconds"] == 20
    assert settings["batch_cap"] == 40


# --- guardian_tick_call_llm -----------------------------------------------------


def test_call_llm_normal_message(monkeypatch):
    _install(
        monkeypatch,
        command_handlers={"guardian-llm-chat": _llm_handler_sequence([_completion(content="hello")])},
    )
    result = tick.guardian_tick_call_llm([{"role": "user", "content": "hi"}], [], "auto")
    assert result["kind"] == "message"
    assert result["message"] == {"role": "assistant", "content": "hello"}


def test_call_llm_with_tool_calls(monkeypatch):
    tc = _tool_call("call_1", "ip", {"ip": "8.8.8.8"})
    _install(
        monkeypatch,
        command_handlers={"guardian-llm-chat": _llm_handler_sequence([_completion(tool_calls=[tc])])},
    )
    result = tick.guardian_tick_call_llm([], [{"type": "function"}], "auto")
    assert result["kind"] == "message"
    assert result["message"]["tool_calls"] == [tc]


def test_call_llm_content_filter(monkeypatch):
    _install(
        monkeypatch,
        command_handlers={"guardian-llm-chat": _llm_handler_sequence([_completion(content_filter=True)])},
    )
    result = tick.guardian_tick_call_llm([], [], "auto")
    assert result["kind"] == "content_filter"
    assert result["detail"] == "blocked for testing"


def test_call_llm_empty_turn(monkeypatch):
    _install(
        monkeypatch,
        command_handlers={"guardian-llm-chat": _llm_handler_sequence([_completion(content=None)])},
    )
    result = tick.guardian_tick_call_llm([], [], "auto")
    assert result["kind"] == "empty"


def test_call_llm_downgrades_required_to_auto_when_tools_empty(monkeypatch):
    # Review round-1 MINOR-6 regression: `tool_choice="required"` combined
    # with an empty/absent tools catalogue is a combination some providers
    # reject outright -- guardian_tick_call_llm must downgrade to "auto"
    # rather than sending that combination through.
    handler = _llm_handler_sequence([_completion(content="ok")])
    _install(monkeypatch, command_handlers={"guardian-llm-chat": handler})
    result = tick.guardian_tick_call_llm([], [], "required")
    assert result["kind"] == "message"
    assert handler.calls[0]["tool_choice"] == "auto"
    assert "tools" not in handler.calls[0]


def test_call_llm_keeps_required_when_tools_present(monkeypatch):
    handler = _llm_handler_sequence([_completion(content="ok")])
    _install(monkeypatch, command_handlers={"guardian-llm-chat": handler})
    result = tick.guardian_tick_call_llm([], [{"type": "function"}], "required")
    assert result["kind"] == "message"
    assert handler.calls[0]["tool_choice"] == "required"
    assert handler.calls[0]["tools"] == [{"type": "function"}]


def test_call_llm_command_failure(monkeypatch):
    def broken(args):
        return [{"Type": 4, "Contents": "provider down"}]

    _install(monkeypatch, command_handlers={"guardian-llm-chat": broken})
    result = tick.guardian_tick_call_llm([], [], "auto")
    assert result["kind"] == "error"
    assert "provider down" in result["error"]


# --- guardian_tick_model_turn_with_retry (empty-turn / leaked-tool-call retry) --


def test_model_turn_first_try_succeeds(monkeypatch):
    _install(
        monkeypatch,
        command_handlers={"guardian-llm-chat": _llm_handler_sequence([_completion(content="ok")])},
    )
    result, empty_observed, billable_turns = tick.guardian_tick_model_turn_with_retry([], [])
    assert result["kind"] == "message"
    assert empty_observed == 0
    assert billable_turns == [result]


def test_model_turn_retries_with_tool_choice_required_then_succeeds(monkeypatch):
    tc = _tool_call("call_1", "ip", {"ip": "1.1.1.1"})
    handler = _llm_handler_sequence([_completion(content=None), _completion(tool_calls=[tc])])
    _install(monkeypatch, command_handlers={"guardian-llm-chat": handler})
    result, empty_observed, billable_turns = tick.guardian_tick_model_turn_with_retry([], [{"type": "function"}])
    assert result["kind"] == "message"
    assert empty_observed == 1
    assert handler.calls[0]["tool_choice"] == "auto"
    assert handler.calls[1]["tool_choice"] == "required"
    # Fix (review round-1, "cost undercount on empty-turn retry"): BOTH real
    # provider calls this made (the discarded empty first try, then the
    # retry) must be reported so the caller can charge both.
    assert len(billable_turns) == 2
    assert billable_turns[0]["kind"] == "empty"
    assert billable_turns[1] is result


def test_model_turn_still_empty_after_retry(monkeypatch):
    handler = _llm_handler_sequence([_completion(content=None), _completion(content=None)])
    _install(monkeypatch, command_handlers={"guardian-llm-chat": handler})
    result, empty_observed, billable_turns = tick.guardian_tick_model_turn_with_retry([], [])
    assert result["kind"] == "empty"
    assert empty_observed == 2
    assert len(handler.calls) == 2
    assert len(billable_turns) == 2
    assert billable_turns[0]["kind"] == "empty"
    assert billable_turns[1] is result


# --- content-filter retry: a blocked turn is retried with a reworded request ---------------------------------


def test_content_filter_variant_adds_note_and_leaves_input_alone():
    messages = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    variant = tick.guardian_tick_content_filter_variant(messages, 1)
    assert variant[-1] == {"role": "user", "content": tick.GUARDIAN_CONTENT_FILTER_NOTE}
    assert variant[:2] == messages
    assert len(messages) == 2


def test_content_filter_variant_second_attempt_cuts_only_fresh_tool_results():
    long = "x" * 2000
    messages = [
        {"role": "tool", "tool_call_id": "old", "content": long},
        {"role": "assistant", "content": None},
        {"role": "tool", "tool_call_id": "new", "content": long},
    ]
    first = tick.guardian_tick_content_filter_variant(messages, 1)
    assert first[2]["content"] == long
    second = tick.guardian_tick_content_filter_variant(messages, 2)
    assert second[0]["content"] == long
    assert len(second[2]["content"]) < len(long)
    assert second[2]["content"].endswith(tick.GUARDIAN_CONTENT_FILTER_CUT_MARK)
    assert messages[2]["content"] == long


def test_model_turn_content_filter_retry_succeeds(monkeypatch):
    handler = _llm_handler_sequence([
        _completion(content_filter=True), _completion(content_filter=True), _completion(content="fine"),
    ])
    _install(monkeypatch, command_handlers={"guardian-llm-chat": handler})
    result, _, billable = tick.guardian_tick_model_turn_with_retry(
        [{"role": "user", "content": "u"}], [], content_filter_retries=2)
    assert result["kind"] == "message"
    assert result["content_filter_retries"] == 2
    assert result["content_filter_variant"][-1]["content"] == tick.GUARDIAN_CONTENT_FILTER_NOTE
    assert len(handler.calls) == 3
    assert len(billable) == 3


def test_model_turn_content_filter_gives_up_after_the_retries(monkeypatch):
    handler = _llm_handler_sequence([_completion(content_filter=True)])
    _install(monkeypatch, command_handlers={"guardian-llm-chat": handler})
    result, _, billable = tick.guardian_tick_model_turn_with_retry([], [], content_filter_retries=2)
    assert result["kind"] == "content_filter"
    assert result["content_filter_retries"] == 2
    assert "content_filter_variant" not in result
    assert len(handler.calls) == 3
    assert len(billable) == 3


def test_model_turn_content_filter_retry_off_stops_at_first_block(monkeypatch):
    handler = _llm_handler_sequence([_completion(content_filter=True)])
    _install(monkeypatch, command_handlers={"guardian-llm-chat": handler})
    result, _, billable = tick.guardian_tick_model_turn_with_retry([], [])
    assert result["kind"] == "content_filter"
    assert "content_filter_retries" not in result
    assert len(handler.calls) == 1


def test_content_filter_retries_setting_parsing():
    assert tick.guardian_tick_content_filter_retries(None) == tick.GUARDIAN_DEFAULT_CONTENT_FILTER_RETRIES
    assert tick.guardian_tick_content_filter_retries("x") == tick.GUARDIAN_DEFAULT_CONTENT_FILTER_RETRIES
    assert tick.guardian_tick_content_filter_retries(-1) == tick.GUARDIAN_DEFAULT_CONTENT_FILTER_RETRIES
    assert tick.guardian_tick_content_filter_retries(0) == 0
    assert tick.guardian_tick_content_filter_retries("3") == 3


# --- guardian_tick_dispatch_tool_call + memo -----------------------------------


def test_dispatch_tool_call_success(monkeypatch):
    _install(
        monkeypatch,
        command_handlers={
            "GuardianToolBridge": _tool_bridge_handler(
                default_result={"status": "ok", "ok": True, "result": {"Score": 1}, "error": None}
            )
        },
    )
    tc = _tool_call("call_1", "ip", {"ip": "8.8.8.8"})
    result = tick.guardian_tick_dispatch_tool_call(tc, tick=0, run_id="999")
    assert result["ok"] is True
    assert result["tool_call_id"] == "call_1"
    assert result["tool_name"] == "ip"


def test_dispatch_tool_call_malformed_no_name(monkeypatch):
    _install(monkeypatch)
    result = tick.guardian_tick_dispatch_tool_call({"id": "call_1", "function": {}}, tick=0, run_id="999")
    assert result["ok"] is False
    assert result["status"] == "error"
    assert "no function name" in result["error"]


def test_dispatch_tool_call_bridge_failure(monkeypatch):
    def broken(args):
        return [{"Type": 4, "Contents": "boom"}]

    _install(monkeypatch, command_handlers={"GuardianToolBridge": broken})
    tc = _tool_call("call_1", "ip", {"ip": "8.8.8.8"})
    result = tick.guardian_tick_dispatch_tool_call(tc, tick=0, run_id="999")
    assert result["ok"] is False
    assert "GuardianToolBridge call failed" in result["error"]


def test_dispatch_tool_call_attaches_full_payload_when_truncated(monkeypatch):
    """Task Backlog-Board item 14: a truncated tool_result must trigger a
    real fileResult attach, and the model-facing tool_result itself must
    end up noting the attached filename -- proving the wiring reaches all
    the way from GuardianToolBridge's response through to the War Room."""
    file_calls = []
    monkeypatch.setattr(tick, "fileResult", lambda filename, data: file_calls.append((filename, data)) or {
        "Type": 3, "File": filename,
    })
    results_calls = []
    monkeypatch.setattr(tick.demisto, "results", lambda entry: results_calls.append(entry))
    _install(
        monkeypatch,
        command_handlers={
            "GuardianToolBridge": _tool_bridge_handler(
                default_result={
                    "status": "ok", "ok": True, "result": "...[truncated]...",
                    "error": None, "truncated": True, "truncation_note": "evidence exceeded the ceiling.",
                },
                full_payload={"note": "y" * 500},
            )
        },
    )
    tc = _tool_call("call_1", "ip", {"ip": "8.8.8.8"})

    result = tick.guardian_tick_dispatch_tool_call(tc, tick=0, run_id="999")

    assert len(file_calls) == 1
    filename, data = file_calls[0]
    assert "call_1" in filename or "ip" in filename
    assert json.loads(data) == {"note": "y" * 500}
    assert len(results_calls) == 1
    assert "attached to the War Room as" in result["truncation_note"]
    assert filename in result["truncation_note"]


def test_dispatch_tool_call_does_not_attach_when_not_truncated(monkeypatch):
    file_calls = []
    monkeypatch.setattr(tick, "fileResult", lambda filename, data: file_calls.append((filename, data)))
    _install(
        monkeypatch,
        command_handlers={
            "GuardianToolBridge": _tool_bridge_handler(
                default_result={"status": "ok", "ok": True, "result": {"Score": 1}, "error": None}
            )
        },
    )
    tc = _tool_call("call_1", "ip", {"ip": "8.8.8.8"})

    tick.guardian_tick_dispatch_tool_call(tc, tick=0, run_id="999")

    assert file_calls == []


def test_attach_truncated_evidence_is_a_noop_when_full_payload_missing(monkeypatch):
    """Defensive: full_payload is None despite truncated=True should never
    happen per GuardianToolBridge's own contract, but this cross-script
    boundary is never trusted blindly -- must not raise or call fileResult."""
    file_calls = []
    monkeypatch.setattr(tick, "fileResult", lambda filename, data: file_calls.append((filename, data)))
    tool_result = {"tool_name": "ip", "truncated": True, "truncation_note": "cut"}

    tick.guardian_tick_attach_truncated_evidence(tool_result, None, "call_1")

    assert file_calls == []
    assert tool_result["truncation_note"] == "cut"  # unchanged


def test_attach_truncated_evidence_never_raises_on_fileresult_failure(monkeypatch):
    monkeypatch.setattr(tick, "fileResult", lambda filename, data: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(tick.demisto, "error", lambda msg: None)
    tool_result = {"tool_name": "ip", "truncated": True, "truncation_note": "cut"}

    tick.guardian_tick_attach_truncated_evidence(tool_result, {"note": "x"}, "call_1")  # must not raise

    assert tool_result["truncation_note"] == "cut"  # unchanged on failure


# --- guardian_tick_tool_message trimming ---------------------------------------


def test_tool_message_small_result_not_trimmed():
    tool_result = {"tool_call_id": "call_1", "tool_name": "ip", "status": "ok", "ok": True, "result": "x", "error": None}
    message = tick.guardian_tick_tool_message(tool_result, truncate_bytes=16384)
    assert message["role"] == "tool"
    assert message["tool_call_id"] == "call_1"
    assert "truncated" not in message["content"]


def test_tool_message_large_result_trimmed():
    tool_result = {
        "tool_call_id": "call_1",
        "tool_name": "ip",
        "status": "ok",
        "ok": True,
        "result": "x" * 5000,
        "error": None,
    }
    message = tick.guardian_tick_tool_message(tool_result, truncate_bytes=200)
    assert "truncated" in message["content"]
    assert len(message["content"].encode("utf-8")) < 5000


# --- fingerprint + identical-fail short-circuit --------------------------------


def test_fingerprint_stable_for_identical_input():
    msg = {"content": None, "tool_calls": [_tool_call("c1", "ip", {"ip": "1.1.1.1"})]}
    fp1 = tick.guardian_tick_fingerprint(msg)
    fp2 = tick.guardian_tick_fingerprint(msg)
    assert fp1 == fp2


def test_fingerprint_differs_for_different_args():
    msg1 = {"content": None, "tool_calls": [_tool_call("c1", "ip", {"ip": "1.1.1.1"})]}
    msg2 = {"content": None, "tool_calls": [_tool_call("c1", "ip", {"ip": "2.2.2.2"})]}
    assert tick.guardian_tick_fingerprint(msg1) != tick.guardian_tick_fingerprint(msg2)


def test_identical_fail_step_first_failure_does_not_stop():
    stop, consec = tick.guardian_tick_identical_fail_step(None, 0, "fp-a", had_failure=True)
    assert stop is False
    assert consec == 1


def test_identical_fail_step_second_identical_failure_stops():
    stop, consec = tick.guardian_tick_identical_fail_step("fp-a", 1, "fp-a", had_failure=True)
    assert stop is True
    assert consec == 2


def test_identical_fail_step_different_fingerprint_resets():
    stop, consec = tick.guardian_tick_identical_fail_step("fp-a", 1, "fp-b", had_failure=True)
    assert stop is False
    assert consec == 1


def test_identical_fail_step_success_resets_to_zero():
    stop, consec = tick.guardian_tick_identical_fail_step("fp-a", 1, "fp-a", had_failure=False)
    assert stop is False
    assert consec == 0


# --- guardian_tick_normalize_for_overlap / content_is_near_duplicate ----------


def test_normalize_for_overlap_lowercases_and_dedupes():
    tokens = tick.guardian_tick_normalize_for_overlap("No Evidence, no evidence found!")
    assert tokens == frozenset({"no", "evidence", "found"})


def test_normalize_for_overlap_non_str_is_empty():
    assert tick.guardian_tick_normalize_for_overlap(None) == frozenset()
    assert tick.guardian_tick_normalize_for_overlap(123) == frozenset()


def test_content_is_near_duplicate_true_for_reworded_finding():
    prev = "No concrete indicators were found linking this host to malicious activity."
    curr = "No concrete indicators found linking the host to any malicious activity."
    assert tick.guardian_tick_content_is_near_duplicate(prev, curr) is True


def test_content_is_near_duplicate_false_for_genuinely_different_content():
    prev = "No concrete indicators were found linking this host to malicious activity."
    curr = "The endpoint reputation lookup returned a confirmed malware family match."
    assert tick.guardian_tick_content_is_near_duplicate(prev, curr) is False


def test_content_is_near_duplicate_false_when_either_side_empty():
    assert tick.guardian_tick_content_is_near_duplicate(None, "some real content here") is False
    assert tick.guardian_tick_content_is_near_duplicate("some real content here", None) is False
    assert tick.guardian_tick_content_is_near_duplicate("", "") is False
    assert tick.guardian_tick_content_is_near_duplicate(None, None) is False


def test_content_is_near_duplicate_respects_custom_threshold():
    prev = "alpha beta gamma delta"
    curr = "alpha beta epsilon zeta"
    # 2/6 = 0.333 overlap -- below the default 0.6 bar, above a loosened one.
    assert tick.guardian_tick_content_is_near_duplicate(prev, curr) is False
    assert tick.guardian_tick_content_is_near_duplicate(prev, curr, threshold=0.3) is True


def test_identical_fail_step_reworded_repeat_counts_as_same_turn():
    """The near-duplicate fallback: DIFFERENT fingerprints (the content string
    changed) but near-duplicate wording must still count as the same
    repeated failing turn, not a fresh one -- this is the whole point of
    the fix (a byte-exact fingerprint alone misses this)."""
    prev_content = "No concrete indicators were found linking this host to malicious activity."
    curr_content = "No concrete indicators found linking the host to any malicious activity."
    stop, consec = tick.guardian_tick_identical_fail_step(
        "fp-a", 1, "fp-b", had_failure=True, prev_content=prev_content, curr_content=curr_content
    )
    assert stop is True
    assert consec == 2


def test_identical_fail_step_genuinely_new_content_does_not_short_circuit():
    """A DIFFERENT fingerprint with genuinely unrelated content must still
    reset the counter -- the near-duplicate fallback must not become an
    always-match that defeats the guard's own purpose."""
    prev_content = "No concrete indicators were found linking this host to malicious activity."
    curr_content = "The endpoint reputation lookup returned a confirmed malware family match."
    stop, consec = tick.guardian_tick_identical_fail_step(
        "fp-a", 1, "fp-b", had_failure=True, prev_content=prev_content, curr_content=curr_content
    )
    assert stop is False
    assert consec == 1


def test_identical_fail_step_omitting_content_args_falls_back_to_exact_fingerprint_only():
    """Backward compatibility: a caller that doesn't pass prev_content/
    curr_content at all gets exactly the pre-fix behavior (pure exact-
    fingerprint comparison) -- covers any future caller of this function
    that hasn't been updated to thread content through."""
    stop, consec = tick.guardian_tick_identical_fail_step("fp-a", 1, "fp-b", had_failure=True)
    assert stop is False
    assert consec == 1


# --- guardian_tick_compact_messages --------------------------------------------


#: The first user message after the system prompt is the task: compaction never drops or summarizes it.
_TASK = {"role": "user", "content": "<untrusted-case-data>investigate</untrusted-case-data>"}


def test_compact_messages_no_op_under_cap():
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}]
    loop_state = {"dropped_count": 0}
    result = tick.guardian_tick_compact_messages(messages, batch_cap=25, loop_state=loop_state)
    assert result == messages
    assert loop_state["dropped_count"] == 0


def test_compact_messages_drops_oldest_with_breadcrumb():
    messages = [{"role": "system", "content": "sys"}, _TASK] + [
        {"role": "user", "content": "turn-{}".format(i)} for i in range(10)
    ]
    loop_state = {"dropped_count": 0}
    result = tick.guardian_tick_compact_messages(messages, batch_cap=5, loop_state=loop_state)
    assert result[0] == {"role": "system", "content": "sys"} and result[1] == _TASK   # the head is never dropped
    assert result[2]["content"].startswith(tick.GUARDIAN_BREADCRUMB_PREFIX)
    assert len(result) == 5
    assert loop_state["dropped_count"] > 0
    # Recent turns are kept, not the oldest ones.
    assert result[-1]["content"] == "turn-9"


def test_compact_messages_never_orphans_tool_reply_across_boundary():
    # Review round-1 IMPORTANT-4 regression: a naive fixed-size suffix cut
    # can land exactly between an assistant+tool_calls message and its own
    # role:"tool" reply, e.g. with batch_cap=6 below the cut boundary lands
    # ON a tool message (see the hand-worked index math in the review
    # findings) -- the compacted result must never start with an orphaned
    # tool reply, and every kept tool reply must have its owning
    # assistant+tool_calls message present somewhere earlier in the result.
    messages = [{"role": "system", "content": "sys"}]
    for i in range(6):
        messages.append({"role": "user", "content": "user-{}".format(i)})
        messages.append(
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {"id": "call-{}".format(i), "type": "function", "function": {"name": "ip", "arguments": "{}"}}
                ],
            }
        )
        messages.append({"role": "tool", "tool_call_id": "call-{}".format(i), "content": "result-{}".format(i)})

    loop_state = {"dropped_count": 0}
    result = tick.guardian_tick_compact_messages(messages, batch_cap=6, loop_state=loop_state)

    assert result[0] == {"role": "system", "content": "sys"}
    # The first message after system/breadcrumb must never be an orphaned
    # tool reply.
    assert result[1]["role"] != "tool"

    # Every tool reply kept in the result must have its owning
    # assistant+tool_calls message present earlier in the SAME result list --
    # i.e. no assistant+tool_calls/tool_reply pair was split by the cut.
    seen_call_ids = set()
    for msg in result:
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            for call in msg["tool_calls"]:
                seen_call_ids.add(call["id"])
        elif msg.get("role") == "tool":
            assert msg.get("tool_call_id") in seen_call_ids, "orphaned tool reply {} in compacted result".format(
                msg.get("tool_call_id")
            )


def test_compact_messages_updates_breadcrumb_not_accumulates():
    loop_state = {"dropped_count": 3}
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": tick.GUARDIAN_BREADCRUMB_PREFIX + "old note"}]
    messages += [{"role": "user", "content": "turn-{}".format(i)} for i in range(10)]
    result = tick.guardian_tick_compact_messages(messages, batch_cap=5, loop_state=loop_state)
    breadcrumbs = [m for m in result if str(m.get("content", "")).startswith(tick.GUARDIAN_BREADCRUMB_PREFIX)]
    assert len(breadcrumbs) == 1
    assert loop_state["dropped_count"] > 3


def test_compact_messages_with_prior_checkpoint_never_exceeds_batch_cap():
    """Fix (Task 1.8 review Important-1): a leading real checkpoint
    (`guardian_checkpoint: True`) makes `prefix` 2 elements (system +
    checkpoint) instead of 1 -- the old hardcoded `keep_budget = batch_cap -
    2` assumed a 1-element prefix always, so `prefix(2) + breadcrumb(1) +
    kept(<= batch_cap - 2)` overshot to `batch_cap + 1` every time a
    checkpoint was already present. With batch_cap=6 and plenty of messages
    after the checkpoint, the buggy code returned 7 messages; the fix must
    return <= 6 (and, here, exactly 6, since there's more than enough
    overflow to fill the corrected budget).
    """
    checkpoint = {"role": "user", "guardian_checkpoint": True, "content": "checkpoint summary"}
    messages = [{"role": "system", "content": "sys"}, checkpoint] + [
        {"role": "user", "content": "turn-{}".format(i)} for i in range(20)
    ]
    loop_state = {"dropped_count": 0}
    result = tick.guardian_tick_compact_messages(messages, batch_cap=6, loop_state=loop_state)

    assert len(result) <= 6
    assert len(result) == 6
    assert result[0] == {"role": "system", "content": "sys"}
    assert result[1] == checkpoint  # the prior checkpoint is preserved, never dropped
    assert result[2]["content"].startswith(tick.GUARDIAN_BREADCRUMB_PREFIX)


def test_compact_messages_no_checkpoint_still_respects_batch_cap():
    """The no-checkpoint breadcrumb path must stay byte-for-byte the same as
    before the Important-1 fix -- `len(prefix) == 1` reduces the new
    `batch_cap - len(prefix) - 1` formula to the exact same `batch_cap - 2`
    used previously. Checked across several batch_cap sizes (not just the
    one already covered by test_compact_messages_drops_oldest_with_breadcrumb)
    to guard against a future change reintroducing an overshoot from the
    other direction.
    """
    for batch_cap in (3, 5, 6, 10, 25):
        messages = [{"role": "system", "content": "sys"}] + [
            {"role": "user", "content": "turn-{}".format(i)} for i in range(30)
        ]
        loop_state = {"dropped_count": 0}
        result = tick.guardian_tick_compact_messages(messages, batch_cap=batch_cap, loop_state=loop_state)
        assert len(result) <= batch_cap, "batch_cap={} overshot: got {}".format(batch_cap, len(result))


# --- guardian_tick_check_model_tier_consistency ---------------------------------


def _mock_integration_search(monkeypatch, instances, configurations=None):
    """Patch guardian_execute so _guardian_rest_post("/settings/integration/search", ...)
    returns a canned {"instances": [...], "configurations": [...]} response,
    matching the exact executeCommand entry-list shape _guardian_rest_post expects."""
    response = {"instances": instances, "configurations": configurations or []}

    def fake_execute(command, args, using=None):
        if command == "demisto-api-post":
            return {"ok": True, "data": [{"Contents": {"response": response}}]}
        return {"ok": False, "error": "unexpected command in test: {}".format(command)}

    monkeypatch.setattr(tick, "guardian_execute", fake_execute)


def _guardian_instance(name="GuardianCohereLabStandin", brand="GuardianCohere", enabled="true", model_tier=None):
    data = []
    if model_tier is not None:
        data.append({"name": "model_tier", "value": model_tier})
    return {"name": name, "brand": brand, "enabled": enabled, "data": data}


def test_model_tier_consistency_no_op_when_instance_search_fails(monkeypatch):
    monkeypatch.setattr(
        tick,
        "guardian_execute",
        lambda *a, **k: {"ok": False, "error": "boom", "retryable": False, "is_auth_error": False},
    )
    assert tick.guardian_tick_check_model_tier_consistency("small") is None


def test_model_tier_consistency_no_op_when_no_instances(monkeypatch):
    _mock_integration_search(monkeypatch, instances=[])
    assert tick.guardian_tick_check_model_tier_consistency("small") is None


def test_model_tier_consistency_no_op_when_instance_tier_unset(monkeypatch):
    # Exactly the live-caught state: instance model_tier is None/absent.
    # Nothing to compare against -- not a mismatch, no narration.
    _mock_integration_search(monkeypatch, instances=[_guardian_instance(model_tier=None)])
    assert tick.guardian_tick_check_model_tier_consistency("medium") is None


def test_model_tier_consistency_no_op_when_values_agree(monkeypatch):
    _mock_integration_search(monkeypatch, instances=[_guardian_instance(model_tier="medium")])
    assert tick.guardian_tick_check_model_tier_consistency("medium") is None


def test_model_tier_consistency_warns_on_mismatch(monkeypatch):
    _mock_integration_search(monkeypatch, instances=[_guardian_instance(model_tier="large")])
    warning = tick.guardian_tick_check_model_tier_consistency("small")
    assert warning is not None
    assert "model size this run uses is \"small\"" in warning
    assert "GuardianCohereLabStandin" in warning
    assert "large" in warning
    assert "DISPLAY-ONLY" in warning


def test_model_tier_consistency_ignores_disabled_instance(monkeypatch):
    _mock_integration_search(
        monkeypatch, instances=[_guardian_instance(enabled="false", model_tier="large")]
    )
    assert tick.guardian_tick_check_model_tier_consistency("small") is None


def test_model_tier_consistency_ignores_non_provider_brand(monkeypatch):
    _mock_integration_search(
        monkeypatch,
        instances=[_guardian_instance(name="SomeOtherIntegration", brand="SomeOtherBrand", model_tier="large")],
    )
    assert tick.guardian_tick_check_model_tier_consistency("small") is None


# --- FIX C: max_input_tokens compaction wiring --------------------------------


def test_estimate_input_tokens_counts_messages_and_catalog():
    messages = [{"role": "system", "content": "x" * 400}, {"role": "user", "content": "y" * 400}]
    catalog = [{"name": "ip", "description": "z" * 400}]
    with_catalog = tick.guardian_tick_estimate_input_tokens(messages, catalog)
    without_catalog = tick.guardian_tick_estimate_input_tokens(messages)
    assert with_catalog > without_catalog > 0


def test_compact_messages_prices_the_catalog_not_just_messages():
    """Live-caught 2026-08-23. Step 6.5 DETECTS overflow with the catalogue
    included but used to REMEDY it pricing messages only, so a transcript
    whose messages alone fit -- but which blows the ceiling once the tool
    catalogue is added -- was returned untouched and sent over budget with
    no drop and therefore no narration anywhere.

    Messages here total well under the ceiling; the catalogue is what puts
    the turn over it. Pre-fix this returned `messages` unchanged.
    """
    messages = [{"role": "system", "content": "sys"}] + [
        {"role": "user", "content": "turn-{}-".format(i) + "x" * 800} for i in range(4)
    ]
    catalog = [{"name": "big_tool", "description": "d" * 20000}]
    ceiling = 3000
    # Precondition: messages ALONE fit, so only the catalogue can trip it.
    assert tick.guardian_tick_estimate_input_tokens(messages) < ceiling
    assert tick.guardian_tick_estimate_input_tokens(messages, catalog) > ceiling

    loop_state = {"dropped_count": 0}
    result = tick.guardian_tick_compact_messages(
        messages, batch_cap=25, loop_state=loop_state, max_input_tokens=ceiling, catalog=catalog
    )
    assert len(result) < len(messages)
    assert loop_state["dropped_count"] > 0
    assert result[0] == {"role": "system", "content": "sys"}


def test_compact_messages_without_catalog_arg_is_unchanged():
    """The catalogue is opt-in: omitting it must reproduce the pre-fix
    arithmetic exactly, so the terminal call sites (which disable the token
    ceiling entirely) keep behaving byte for byte as before."""
    messages = [{"role": "system", "content": "sys"}] + [
        {"role": "user", "content": "turn-{}-".format(i) + "x" * 800} for i in range(4)
    ]
    loop_state = {"dropped_count": 0}
    result = tick.guardian_tick_compact_messages(
        messages, batch_cap=25, loop_state=loop_state, max_input_tokens=3000
    )
    assert result == messages
    assert loop_state["dropped_count"] == 0


def test_compact_plan_prices_the_catalog_not_just_messages():
    """Same asymmetry on the real-summarization planning path."""
    messages = [{"role": "system", "content": "sys"}] + [
        {"role": "user", "content": "turn-{}-".format(i) + "x" * 800} for i in range(4)
    ]
    catalog = [{"name": "big_tool", "description": "d" * 20000}]
    ceiling = 3000
    assert tick.guardian_tick_compact_plan(messages, batch_cap=25, max_input_tokens=ceiling)["needed"] is False
    assert tick.guardian_tick_compact_plan(
        messages, batch_cap=25, max_input_tokens=ceiling, catalog=catalog
    )["needed"] is True


def test_compact_messages_noop_when_max_input_tokens_none_even_if_big():
    """A big transcript UNDER batch_cap by count and with the token ceiling
    DISABLED (None) must pass through untouched -- pure count behavior, byte
    for byte as before FIX C."""
    messages = [{"role": "system", "content": "sys"}] + [
        {"role": "user", "content": "x" * 5000} for _ in range(5)
    ]
    loop_state = {"dropped_count": 0}
    result = tick.guardian_tick_compact_messages(messages, batch_cap=25, loop_state=loop_state, max_input_tokens=None)
    assert result == messages
    assert loop_state["dropped_count"] == 0


def test_compact_messages_token_budget_triggers_drop_under_count_cap():
    """FIX C core: a transcript UNDER batch_cap by COUNT but OVER a positive
    max_input_tokens must still be compacted (oldest dropped, breadcrumb
    added, most-recent kept)."""
    # 6 big user turns (~1250 tokens each via chars/4) under batch_cap=25 by
    # count, but well over a 3000-token ceiling.
    messages = [{"role": "system", "content": "sys"}, _TASK] + [
        {"role": "user", "content": "turn-{}-".format(i) + "x" * 5000} for i in range(6)
    ]
    loop_state = {"dropped_count": 0}
    result = tick.guardian_tick_compact_messages(
        messages, batch_cap=25, loop_state=loop_state, max_input_tokens=3000
    )
    assert len(result) < len(messages)  # something was dropped by the token ceiling alone
    assert loop_state["dropped_count"] > 0
    assert result[0] == {"role": "system", "content": "sys"} and result[1] == _TASK
    assert result[2]["content"].startswith(tick.GUARDIAN_BREADCRUMB_PREFIX)
    # Most-recent turn is always kept.
    assert result[-1]["content"].startswith("turn-5-")
    # And the compacted result actually fits under the ceiling now.
    assert tick.guardian_tick_estimate_input_tokens(result) <= 3000 or len(result) <= 3


def test_compact_plan_token_budget_triggers_needed_under_count_cap():
    """The real-compaction planner (`guardian_tick_compact_plan`) must ALSO
    report needed=True on a token-over-budget-but-count-under-cap transcript,
    so `guardian_tick_attempt_compaction` honors the same ceiling."""
    messages = [{"role": "system", "content": "sys"}] + [
        {"role": "user", "content": "turn-{}-".format(i) + "x" * 5000} for i in range(6)
    ]
    plan = tick.guardian_tick_compact_plan(messages, batch_cap=25, max_input_tokens=3000)
    assert plan["needed"] is True
    assert len(plan["dropped"]) > 0
    assert plan["kept"][-1]["content"].startswith("turn-5-")


def test_compact_plan_no_token_ceiling_stays_count_only():
    """With no token ceiling, an under-count transcript is not compacted --
    proving the token trigger is purely additive."""
    messages = [{"role": "system", "content": "sys"}] + [
        {"role": "user", "content": "x" * 5000} for _ in range(6)
    ]
    plan = tick.guardian_tick_compact_plan(messages, batch_cap=25, max_input_tokens=None)
    assert plan["needed"] is False


# --- guardian_reasoning_tick_run: full integration scenarios -------------------


def test_tick0_init_and_final_answer_same_invocation(monkeypatch):
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler("SYSTEM PROMPT TEXT"),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": _llm_handler_sequence([_completion(content="Verdict: benign")]),
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    assert "Guardian Agent Loop starting" in outcome["narration"]
    assert "concluded at tick 0" in outcome["narration"]
    assert "Verdict: benign" in outcome["narration"]

    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "done"
    assert loop["tick"] == 1
    assert loop["messages"][0] == {"role": "system", "content": "SYSTEM PROMPT TEXT"}
    # Tick 0 pins the current incident (id 999 from _install) as a TRUSTED system message, inserted
    # between the system prompt and the untrusted case data, so the model always targets the right
    # incident id instead of guessing one.
    assert loop["messages"][1]["role"] == "system"
    assert "999" in loop["messages"][1]["content"]
    assert tick.GUARDIAN_UNTRUSTED_OPEN in loop["messages"][2]["content"]
    assert "Investigate 8.8.8.8" in loop["messages"][2]["content"]
    assert loop["messages"][3]["content"] == "Verdict: benign"


def test_incident_context_message_pins_id_and_instruction(monkeypatch):
    monkeypatch.setattr(
        tick.demisto,
        "incident",
        lambda: {
            "id": "29676",
            "name": "Credential phishing - ACME",
            "type": "Phishing",
            "severity": 3,
            "status": 1,
            "details": "user submitted creds to fake SSO portal",
        },
    )
    msg = tick.guardian_tick_incident_context_message()
    assert msg is not None
    assert msg["role"] == "system"
    # The exact incident id must appear so the model targets THIS incident, and the instruction must
    # forbid inventing/looking-up ids.
    assert "29676" in msg["content"]
    assert "NEVER invent" in msg["content"]
    assert "getIncidents" in msg["content"]
    assert "Credential phishing - ACME" in msg["content"]


def test_incident_context_message_is_none_without_incident(monkeypatch):
    # Playground / no-incident context: demisto.incident() is {} -> nothing to pin.
    monkeypatch.setattr(tick.demisto, "incident", lambda: {})
    assert tick.guardian_tick_incident_context_message() is None

    # Also resilient when demisto.incident() itself raises.
    def _boom():
        raise RuntimeError("no incident context available")

    monkeypatch.setattr(tick.demisto, "incident", _boom)
    assert tick.guardian_tick_incident_context_message() is None


def test_incident_context_message_truncates_long_details(monkeypatch):
    monkeypatch.setattr(
        tick.demisto,
        "incident",
        lambda: {"id": "42", "name": "n", "details": "x" * 5000},
    )
    msg = tick.guardian_tick_incident_context_message()
    assert msg is not None
    assert "…[truncated]" in msg["content"]
    # Body never carries the full 5000-char blob -- check the longest consecutive run of "x"
    # rather than a whole-message count, which is a fragile proxy: unrelated prose elsewhere in
    # the message (e.g. the word "text") can legitimately contain the letter "x" too.
    assert "x" * 2001 not in msg["content"]
    assert "x" * 2000 in msg["content"]


def test_incident_context_message_adds_mission_scope_when_trigger_source_blank(monkeypatch):
    # A genuinely-fetched incident (SplunkPy fetch, or a manual/ad-hoc investigation) never gets
    # guardiantriggersource tagged -- this is the case the sweep-vs-single-incident fix targets.
    monkeypatch.setattr(
        tick.demisto,
        "incident",
        lambda: {"id": "10", "name": "Data Exfil", "CustomFields": {}},
    )
    msg = tick.guardian_tick_incident_context_message()
    assert msg is not None
    assert "MISSION SCOPE FOR THIS RUN" in msg["content"]
    assert "do not run a general sweep" in msg["content"]
    assert "#10" in msg["content"].split("MISSION SCOPE")[1]


def test_incident_context_message_adds_mission_scope_when_custom_fields_missing_entirely(monkeypatch):
    # Same as above but CustomFields key absent altogether, not just empty -- both must behave
    # identically (an incident with no CustomFields dict at all is not a signal of anything).
    monkeypatch.setattr(tick.demisto, "incident", lambda: {"id": "11", "name": "n"})
    msg = tick.guardian_tick_incident_context_message()
    assert msg is not None
    assert "MISSION SCOPE FOR THIS RUN" in msg["content"]


@pytest.mark.parametrize("trigger_source", ["job:intake-sweep", "eval", "simulate"])
def test_incident_context_message_skips_mission_scope_for_known_sweep_sources(monkeypatch, trigger_source):
    # Guardian's own sweep-dependent flows (the periodic intake Job, the eval harness whose driver
    # incidents rely on the sweep DISCOVERING them, and GuardianSimulateIncidents) must keep getting
    # the unmodified sweep prompt -- anchoring these to a single incident would break them.
    monkeypatch.setattr(
        tick.demisto,
        "incident",
        lambda: {"id": "1", "name": "n", "CustomFields": {"guardiantriggersource": trigger_source}},
    )
    msg = tick.guardian_tick_incident_context_message()
    assert msg is not None
    assert "MISSION SCOPE FOR THIS RUN" not in msg["content"]


def test_incident_context_message_skips_mission_scope_for_any_nonblank_trigger_source(monkeypatch):
    # The check is a blank/missing-value ALLOWLIST, not a denylist of the three known sweep
    # sources -- ANY non-blank guardiantriggersource, including one this fix doesn't know about
    # yet, skips the addendum. This is intentional: every Guardian-owned incident creator in this
    # pack tags the field, so a non-blank value always means "Guardian itself created this," which
    # by construction is never the genuine-external-fetch case the addendum targets.
    monkeypatch.setattr(
        tick.demisto,
        "incident",
        lambda: {"id": "12", "name": "n", "CustomFields": {"guardiantriggersource": "some-future-source"}},
    )
    msg = tick.guardian_tick_incident_context_message()
    assert msg is not None
    assert "MISSION SCOPE FOR THIS RUN" not in msg["content"]


def test_tick0_builds_tool_catalog_exactly_once(monkeypatch):
    # Review round-1 IMPORTANT-3 regression: tick 0 used to call
    # GuardianToolCatalogBuilder once during init and then, unable to see its
    # own write via `demisto.context()` within the SAME execution (the known
    # same-execution snapshot staleness bug), call it a SECOND time at the
    # "ensure tool catalogue" step. It must now be invoked exactly once.
    catalog_handler = _catalog_builder_handler_counting([{"type": "function", "function": {"name": "ip"}}])
    _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": catalog_handler,
            "guardian-llm-chat": _llm_handler_sequence([_completion(content="Verdict: benign")]),
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    assert len(catalog_handler.calls) == 1


def test_tick0_offers_only_tier0_tools_when_catalog_is_wide(monkeypatch):
    # End-to-end wiring check: a tick with no prior evidence and a wide
    # catalogue must only ever see the tier-0 subset in the actual
    # guardian-llm-chat request -- not just in the unit-level
    # guardian_tick_select_catalog_tier tests above.
    llm_handler = _llm_handler_sequence([_completion(content="Verdict: benign")])
    _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler(
                _catalog("GuardianSkillRead", "getIncidents", "getEntries", "splunk-search", "ip", "domain", "url", "file")
            ),
            "guardian-llm-chat": llm_handler,
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    sent_names = {e["function"]["name"] for e in llm_handler.calls[0]["tools"]}
    assert sent_names == {"GuardianSkillRead", "getIncidents", "getEntries", "splunk-search"}
    assert "ip" not in sent_names and "domain" not in sent_names


def test_missing_prompt_on_first_tick_fails_no_reschedule(monkeypatch):
    _install(monkeypatch)
    outcome = tick.guardian_reasoning_tick_run({})
    assert outcome["reschedule"] is False
    assert "'prompt' is required" in outcome["narration"]


def test_tool_dispatch_loop_reschedules_and_persists_state(monkeypatch):
    tc = _tool_call("call_1", "ip", {"ip": "8.8.8.8"})
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": _llm_handler_sequence([_completion(tool_calls=[tc])]),
            "GuardianToolBridge": _tool_bridge_handler(
                default_result={"status": "ok", "ok": True, "result": {"Score": 1}, "error": None}
            ),
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is True
    assert outcome["cadence"] == DEFAULT_SETTINGS["tick_cadence_seconds"]
    assert "called 1 tool" in outcome["narration"]

    loop = ctx["Guardian"]["Loop"]
    assert loop["tick"] == 1
    assert loop["status"] == "running"
    # system + incident-context + user + assistant + tool = 5 messages after one tool-calling
    # tick (the incident-context system message is seeded at tick 0 when demisto.incident() has an
    # id -- here _install's default incident_id="999").
    assert len(loop["messages"]) == 5
    assert loop["messages"][-1]["role"] == "tool"
    assert loop["messages"][-1]["tool_call_id"] == "call_1"


def _two_call_turn_install(monkeypatch, settings):
    calls = []
    bridge = _tool_bridge_handler(default_result={"status": "ok", "ok": True, "result": {"Score": 1}, "error": None})

    def recording_bridge(args):
        calls.append(args.get("tool_name"))
        return bridge(args)

    ctx = _install(
        monkeypatch,
        settings=settings,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": _llm_handler_sequence(
                [_completion(tool_calls=[_tool_call("call_1", "ip", {"ip": "8.8.8.8"}), _tool_call("call_2", "domain", {"domain": "a.example"})])]
            ),
            "GuardianToolBridge": recording_bridge,
        },
    )
    return ctx, calls


def test_tool_calls_per_turn_limit_runs_only_the_first_call_and_tells_the_model(monkeypatch):
    ctx, bridge_calls = _two_call_turn_install(monkeypatch, dict(DEFAULT_SETTINGS, max_tool_calls_per_turn=1))
    tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert bridge_calls == ["ip"]
    messages = ctx["Guardian"]["Loop"]["messages"]
    assistant = [m for m in messages if m.get("role") == "assistant"][-1]
    assert [tc["id"] for tc in assistant["tool_calls"]] == ["call_1"]
    tool_replies = [m for m in messages if m.get("role") == "tool"]
    assert [m["tool_call_id"] for m in tool_replies] == ["call_1"]
    assert messages[-1]["role"] == "user"
    assert "domain" in messages[-1]["content"] and "NOT run" in messages[-1]["content"]


def test_without_a_limit_every_call_in_the_turn_still_runs(monkeypatch):
    ctx, bridge_calls = _two_call_turn_install(monkeypatch, dict(DEFAULT_SETTINGS, model_tier="large"))
    tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert bridge_calls == ["ip", "domain"]
    assert ctx["Guardian"]["Loop"]["messages"][-1]["role"] == "tool"


def test_preflight_max_input_tokens_compacts_before_model_turn(monkeypatch):
    """FIX C end-to-end: a resumed tick whose persisted transcript is over a
    positive max_input_tokens ceiling (but under batch_cap by count) must
    compact the transcript BEFORE the model turn -- the messages the LLM is
    actually called with are fewer than what was persisted, and carry the
    drop-oldest breadcrumb."""
    llm_handler = _llm_handler_sequence([_completion(content="Final verdict: benign")])
    ctx = _install(
        monkeypatch,
        settings={"MAX_TICKS": 25, "tick_cadence_seconds": 12, "batch_cap": 25, "max_input_tokens": 3000},
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": llm_handler,
        },
    )

    # Seed a RESUMED loop (has messages -> tick-0 init is skipped): 6 big user
    # turns (~1250 tokens each) under batch_cap=25 by count but far over the
    # 3000-token ceiling. ToolCatalog is seeded so Step 6 finds it.
    big_transcript = [{"role": "system", "content": "sys"}] + [
        {"role": "user", "content": "turn-{}-".format(i) + "x" * 5000} for i in range(6)
    ]
    ctx["Guardian"] = {
        "Loop": {
            "run_id": "run-xyz",
            "tick": 3,
            "status": "running",
            "messages": big_transcript,
            "dropped_count": 0,
            "empty_turns": 0,
            "pending_user_input": [],
            "awaiting_analyst": None,
            "awaiting_ticks": 0,
            "cost_usd": 0.0,
            "cost_tokens_total": 0,
            "executed_calls": {},
            "repeat_calls": 0,
            "force_conclude": False,
            "force_conclude_reason": None,
            "compact_cooldown": 0,
        },
        "ToolCatalog": [],
    }

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    # The transcript the model was actually called with this tick.
    assert len(llm_handler.calls) == 1
    sent_messages = llm_handler.calls[0]["messages"]
    assert len(sent_messages) < len(big_transcript)  # compacted before the turn
    assert sent_messages[0] == {"role": "system", "content": "sys"}
    assert any(
        str(m.get("content", "")).startswith(tick.GUARDIAN_BREADCRUMB_PREFIX) for m in sent_messages
    )
    assert "Input budget" in outcome["narration"]


def test_preflight_max_input_tokens_noop_when_disabled(monkeypatch):
    """Same seeded big transcript, but max_input_tokens absent (disabled):
    the pre-flight guard must NOT fire -- the full transcript is sent."""
    llm_handler = _llm_handler_sequence([_completion(content="Final verdict: benign")])
    ctx = _install(
        monkeypatch,
        settings={"MAX_TICKS": 25, "tick_cadence_seconds": 12, "batch_cap": 25},
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": llm_handler,
        },
    )
    big_transcript = [{"role": "system", "content": "sys"}] + [
        {"role": "user", "content": "turn-{}-".format(i) + "x" * 5000} for i in range(6)
    ]
    ctx["Guardian"] = {
        "Loop": {
            "run_id": "run-xyz",
            "tick": 3,
            "status": "running",
            "messages": big_transcript,
            "dropped_count": 0,
            "empty_turns": 0,
            "pending_user_input": [],
            "awaiting_analyst": None,
            "awaiting_ticks": 0,
            "cost_usd": 0.0,
            "cost_tokens_total": 0,
            "executed_calls": {},
            "repeat_calls": 0,
            "force_conclude": False,
            "force_conclude_reason": None,
            "compact_cooldown": 0,
        },
        "ToolCatalog": [],
    }

    tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    sent_messages = llm_handler.calls[0]["messages"]
    # No pre-flight compaction: all 7 seeded messages sent as-is (under
    # batch_cap by count, and the token ceiling is disabled).
    assert len(sent_messages) == len(big_transcript)
    assert not any(
        str(m.get("content", "")).startswith(tick.GUARDIAN_BREADCRUMB_PREFIX) for m in sent_messages
    )


def test_multi_tick_state_survives_reentry_and_concludes(monkeypatch):
    tc = _tool_call("call_1", "ip", {"ip": "8.8.8.8"})
    llm_handler = _llm_handler_sequence(
        [_completion(tool_calls=[tc]), _completion(content="Final verdict: benign")]
    )
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": llm_handler,
            "GuardianToolBridge": _tool_bridge_handler(
                default_result={"status": "ok", "ok": True, "result": {"Score": 1}, "error": None}
            ),
        },
    )

    first = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert first["reschedule"] is True
    assert ctx["Guardian"]["Loop"]["tick"] == 1

    # Second tick re-enters against the SAME persisted context, exactly like
    # a real ScheduledCommand re-invocation would (args are ignored/inert).
    second = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert second["reschedule"] is False
    assert "Final verdict: benign" in second["narration"]

    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "done"
    assert loop["tick"] == 2
    # system + incident-context + user + assistant1 + tool1 + assistant2(final) = 6 messages
    # (the incident-context system message is seeded at tick 0 when demisto.incident() has an id).
    assert len(loop["messages"]) == 6


def test_ceiling_exit_forces_no_tools_summary(monkeypatch):
    llm_handler = _llm_handler_sequence([_completion(content="Forced summary text")])
    _install(
        monkeypatch,
        settings={"MAX_TICKS": 1, "tick_cadence_seconds": 12, "batch_cap": 25},
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": llm_handler,
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    assert "reached its tick ceiling" in outcome["narration"]
    assert "Forced summary text" in outcome["narration"]
    assert outcome["loop_state"]["status"] == "done"
    # The forced summary turn must NOT be offered tools.
    assert "tools" not in llm_handler.calls[0]
    assert llm_handler.calls[0]["tool_choice"] == "none"
    # Review round-1 MINOR-5 regression: the forced summary must be appended
    # to the persisted transcript, not just narrated in the War Room --
    # otherwise Context and the War Room diverge on what the loop concluded.
    assert outcome["loop_state"]["messages"][-1] == {"role": "assistant", "content": "Forced summary text"}


def test_ceiling_exit_still_writes_a_valid_verdict_block(monkeypatch):
    # A forced conclusion (MAX_TICKS ceiling or force_conclude) can still
    # carry a perfectly usable terminal verdict block -- this must reach the
    # incident's guardian* fields exactly like Step 9's natural conclusion
    # does (see test_tick_conclusion_writes_verdict_telemetry), not be
    # silently dropped just because the run was forced rather than natural.
    verdict_text = (
        "Reached the tick ceiling before further evidence could be gathered.\n```json\n"
        '{"verdict":"Inconclusive","confidence":20,"techniques":[],'
        '"summary":"No concrete indicator was present in the incident record within the tick budget."}\n'
        "```"
    )
    captured = {}
    monkeypatch.setattr(
        tick,
        "guardian_set_incident_fields",
        lambda iid, fields: captured.update(iid=iid, fields=fields) or {"ok": True, "data": {}},
    )
    _install(
        monkeypatch,
        settings={"MAX_TICKS": 1, "tick_cadence_seconds": 12, "batch_cap": 25},
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": _llm_handler_sequence([_completion(content=verdict_text)]),
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    assert captured.get("iid") == "999"
    assert captured.get("fields") == {
        "guardianverdict": "Inconclusive",
        "guardianconfidence": 20,
        "guardianattacktechniques": [],
        "guardianblastradius": "No concrete indicator was present in the incident record within the tick budget.",
    }


def test_kill_switch_exit_before_any_other_dispatch(monkeypatch):
    ctx = _install(monkeypatch, kill_switch={"enabled": True})
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    assert "halted by kill switch" in outcome["narration"]
    assert ctx["Guardian"]["Loop"]["status"] == "stopped"


def test_job_guard_exit_before_any_other_dispatch_for_a_job_spawned_run(monkeypatch):
    """Task 3.4 follow-up wiring, Step 1b: a job-spawned run
    (guardiantriggersource=job:intake-sweep) whose JobGuard action=check
    says proceed=False must halt immediately, exactly like a kill-switch
    halt -- before settings/prompt-builder/tool-catalogue or any other
    dispatch."""
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianJobGuard": lambda args: [{"Type": 1, "Contents": {"proceed": False, "reason": "job_disabled"}}],
        },
    )
    monkeypatch.setattr(
        tick.demisto,
        "incident",
        lambda: {"id": "999", "CustomFields": {"guardiantriggersource": "job:intake-sweep"}},
    )

    outcome = tick.guardian_reasoning_tick_run({"prompt": "SOC intake sweep"})

    assert outcome["reschedule"] is False
    assert "halted by GuardianJobGuard" in outcome["narration"]
    assert "job_disabled" in outcome["narration"]
    assert outcome["report_job_guard"] is False  # never double-report against the threshold that just tripped
    assert ctx["Guardian"]["Loop"]["status"] == "stopped"


def test_job_guard_does_not_engage_for_a_non_job_spawned_run(monkeypatch):
    """A manually-created / eval / SOC-Agent-created run has no real Job to
    protect -- GuardianJobGuard must never even be called, even though the
    run otherwise proceeds normally through a full tick."""
    job_guard_calls = []
    _install(
        monkeypatch,
        settings={"MAX_TICKS": 1, "tick_cadence_seconds": 12, "batch_cap": 25},
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": _llm_handler_sequence([_completion(content="Forced summary text")]),
            "GuardianJobGuard": lambda args: job_guard_calls.append(args)
            or [{"Type": 1, "Contents": {"ok": True}}],
        },
    )
    monkeypatch.setattr(tick.demisto, "incident", lambda: {"id": "999", "CustomFields": {}})

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    assert "halted by GuardianJobGuard" not in outcome["narration"]
    assert job_guard_calls == []


def test_kill_switch_exit_mid_run_preserves_prior_state(monkeypatch):
    # Seed an in-progress loop, then flip the kill switch and re-enter.
    ctx = _install(monkeypatch, kill_switch={"enabled": True})
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "x"}],
            "tick": 3,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "dropped_count": 0,
        }
    }
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert outcome["reschedule"] is False
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "stopped"
    assert loop["tick"] == 3  # untouched, only status overlaid


def _two_empties_then(monkeypatch, final_completion):
    llm = _llm_handler_sequence([_completion(content=None), _completion(content=None), final_completion])
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": llm,
        },
    )
    return llm, ctx


def test_two_empty_replies_ask_for_a_conclusion_without_tools_instead_of_ending_the_run(monkeypatch):
    """Live: the same request returned the same nothing every time (a tool call the server could not parse),
    but the same model answered in plain text when asked without tools. So the run must not die with no verdict."""
    verdict = ('Routine activity, nothing to escalate.\n```json\n{"verdict":"Benign","confidence":80,"techniques":[],'
               '"summary":"Approved scanner traffic from a known host, no escalation needed."}\n```')
    llm, ctx = _two_empties_then(monkeypatch, _completion(content=verdict))
    written = []
    monkeypatch.setattr(tick, "guardian_set_incident_fields", lambda iid, fields: written.append(fields) or {"ok": True, "data": {}})

    first = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert first["reschedule"] is True
    assert "empty turn twice in a row" in first["narration"] and "without tools on the next turn" in first["narration"]
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "running" and loop["force_conclude"] is True and loop["empty_turns"] == 2
    assert len(llm.calls) == 2 and llm.calls[1]["tool_choice"] == "required"

    second = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert second["reschedule"] is False
    assert len(llm.calls) == 3
    assert llm.calls[2]["tool_choice"] == "none" and "tools" not in llm.calls[2]  # the no-tools conclusion turn
    assert "stopped early at tick" in second["narration"] and "empty turn twice" in second["narration"]
    assert "repeated-call loop broken" not in second["narration"]
    assert ctx["Guardian"]["Loop"]["status"] == "done"
    assert [f["guardianverdict"] for f in written if "guardianverdict" in f] == ["Benign"]  # and the verdict is recorded


def test_if_the_conclusion_turn_is_empty_too_the_run_still_ends_cleanly(monkeypatch):
    llm, ctx = _two_empties_then(monkeypatch, _completion(content=None))
    tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    second = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert second["reschedule"] is False
    assert ctx["Guardian"]["Loop"]["status"] == "done"
    assert "The model did not conclude within 2 turn(s)" in second["narration"] and "no verdict" in second["narration"]
    assert len(llm.calls) == 4 and llm.calls[3]["tool_choice"] == "none"  # one retry of the conclusion turn, then the fallback


def test_identical_fail_short_circuit_stops_after_second_repeat(monkeypatch):
    tc = _tool_call("call_1", "denied_cmd", {"x": 1})
    llm_handler = _llm_handler_sequence([_completion(tool_calls=[tc])])  # same completion every call
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler(
                [{"type": "function", "function": {"name": "denied_cmd"}}]
            ),
            "guardian-llm-chat": llm_handler,
            "GuardianToolBridge": _tool_bridge_handler(
                default_result={"status": "denied", "ok": False, "result": None, "error": "denied by policy"}
            ),
        },
    )

    first = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert first["reschedule"] is True  # first failure alone never stops the loop
    assert ctx["Guardian"]["Loop"]["consec_fails"] == 1

    second = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert second["reschedule"] is True  # no more tool calls, but the run is not thrown away
    assert "repeated the identical failing tool call" in second["narration"]
    assert "final conclusion without tools" in second["narration"]
    assert ctx["Guardian"]["Loop"]["status"] == "running" and ctx["Guardian"]["Loop"]["force_conclude"] is True
    assert ctx["Guardian"]["Loop"]["consec_fails"] == 2


def test_identical_fail_short_circuit_stops_on_reworded_repeat(monkeypatch):
    """End-to-end: the SAME failing tool call, narrated with DIFFERENT
    wording each tick (so the byte-exact fingerprint differs), must still
    trip the short-circuit via the near-duplicate content check -- this is
    the live gap the fix closes (a model that stalls by rephrasing the
    identical stuck narration was previously invisible to this guard)."""
    tc = _tool_call("call_1", "denied_cmd", {"x": 1})
    llm_handler = _llm_handler_sequence(
        [
            _completion(
                content="No concrete indicators were found linking this host to malicious activity.",
                tool_calls=[tc],
            ),
            _completion(
                content="No concrete indicators found linking the host to any malicious activity.",
                tool_calls=[tc],
            ),
        ]
    )
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler(
                [{"type": "function", "function": {"name": "denied_cmd"}}]
            ),
            "guardian-llm-chat": llm_handler,
            "GuardianToolBridge": _tool_bridge_handler(
                default_result={"status": "denied", "ok": False, "result": None, "error": "denied by policy"}
            ),
        },
    )

    first = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert first["reschedule"] is True
    assert ctx["Guardian"]["Loop"]["consec_fails"] == 1

    second = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert second["reschedule"] is True  # no more tool calls, but the run is not thrown away
    assert "repeated the identical failing tool call" in second["narration"]
    assert "final conclusion without tools" in second["narration"]
    assert ctx["Guardian"]["Loop"]["status"] == "running" and ctx["Guardian"]["Loop"]["force_conclude"] is True
    assert ctx["Guardian"]["Loop"]["consec_fails"] == 2


def test_pending_approval_short_circuits_without_model_turn(monkeypatch):
    ctx = _install(monkeypatch)
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "x"}, {"role": "user", "content": "y"}],
            "tick": 2,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": {"tool_call_id": "call_1"},
            "dropped_count": 0,
        },
        "ToolCatalog": [],
    }
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert outcome["reschedule"] is True
    assert "pending human approval" in outcome["narration"]
    # No guardian-llm-chat/GuardianToolBridge handler was wired at all --
    # if this function tried to call either, _install's fake_execute would
    # have raised AssertionError, which pytest would report as a failure.


def test_pending_approval_still_terminates_at_max_ticks(monkeypatch):
    # Review round-1 IMPORTANT-2 regression: a loop_state stuck with `pending`
    # set must still terminate at the MAX_TICKS ceiling, rather than the
    # pending short-circuit returning reschedule=True forever because it used
    # to be checked (and return) BEFORE the ceiling check ever ran.
    llm_handler = _llm_handler_sequence([_completion(content="Forced summary despite pending")])
    ctx = _install(
        monkeypatch,
        settings={"MAX_TICKS": 1, "tick_cadence_seconds": 12, "batch_cap": 25},
        command_handlers={"guardian-llm-chat": llm_handler},
    )
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "x"}, {"role": "user", "content": "y"}],
            "tick": 0,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": {"tool_call_id": "call_1"},
            "pending_ticks": 0,
            "dropped_count": 0,
        },
        "ToolCatalog": [],
    }
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    assert "reached its tick ceiling" in outcome["narration"]
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "done"
    # The forced no-tools summary call must have actually been made (proves
    # the ceiling branch ran instead of the pending short-circuit returning
    # first).
    assert len(llm_handler.calls) == 1
    assert llm_handler.calls[0]["tool_choice"] == "none"


def test_pending_approval_force_exits_after_pending_ticks_limit(monkeypatch):
    # Review round-1 IMPORTANT-2 regression, now Task 3.1's real SLA/cap:
    # even below the MAX_TICKS ceiling, a `pending` that never resolves must
    # not reschedule forever -- GUARDIAN_MAX_PENDING_TICKS bounds it to a
    # "stopped" (hold+escalate) force-exit, and the ledger row is marked
    # "expired" (never auto-executed).
    ledger = [{"approval_id": "approval-1", "kind": "tool", "tool_name": "setIncident", "status": "pending"}]
    ctx = _install(monkeypatch, approvals_ledger=ledger)
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "x"}, {"role": "user", "content": "y"}],
            "tick": 2,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": {"approval_id": "approval-1", "kind": "tool"},
            "pending_ticks": 0,
            "dropped_count": 0,
        },
        "ToolCatalog": [],
    }

    outcome = None
    for _ in range(tick.GUARDIAN_MAX_PENDING_TICKS):
        outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
        if not outcome["reschedule"]:
            break

    assert outcome["reschedule"] is False
    assert "ESCALATED" in outcome["narration"]
    assert "approval-1" in outcome["narration"]
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "stopped"
    assert loop["pending"] is None
    assert loop["pending_ticks"] >= tick.GUARDIAN_MAX_PENDING_TICKS
    assert ledger[0]["status"] == "expired"
    assert ledger[0]["resolved_by"] == "system:sla_cap"


def test_pending_approval_becomes_approved_during_cap_breach_window_still_executes(monkeypatch):
    """Task 3.1 security-review fix (FIX 3) regression: if the ledger row
    resolves to "approved" in the narrow window between this tick's OWN
    top-of-Step-5 read (which still finds it "pending") and the cap-breach
    branch's own fresh re-check a moment later, the action must still
    redispatch and EXECUTE this tick -- never silently expired/discarded
    with the loop stopped, which would orphan a genuinely-approved action
    forever (nothing left in loop_state would ever point back at this
    approval_id again once status="stopped"). The fixture's `getList`
    handler returns "pending" on the FIRST guardian_approvals_ledger read
    (Step 5's own top-of-tick check) and "approved" on every read
    thereafter (the cap-breach branch's fresh re-check), modeling a human's
    !guardian-approve landing in exactly that window.
    """
    pending_row = {
        "approval_id": "approval-1",
        "kind": "tool",
        "tool_name": "setIncident",
        "tool_args": {"id": "1", "severity": 4},
        "status": "pending",
    }
    approved_row = dict(pending_row, status="approved", resolved_by="alice")

    read_count = {"n": 0}

    def racy_get_list(args):
        name = args["listName"]
        if name == "guardian_approvals_ledger":
            read_count["n"] += 1
            row = pending_row if read_count["n"] == 1 else approved_row
            return [{"Type": 1, "Contents": json.dumps([row])}]
        if name == "guardian_kill_switch":
            return [{"Type": 1, "Contents": json.dumps(DEFAULT_KILL_SWITCH)}]
        if name == "guardian_settings":
            return [{"Type": 1, "Contents": json.dumps(DEFAULT_SETTINGS)}]
        raise AssertionError("no fixture wired for getList listName={}".format(name))

    llm_handler = _llm_handler_sequence([_completion(content="Proceeding now that the field was updated.")])

    def bridge_handler(args):
        assert args.get("approval_id") == "approval-1"
        assert args.get("tool_name") == "setIncident"
        result = {
            "tool_call_id": None,
            "tool_name": "setIncident",
            "status": "ok",
            "ok": True,
            "result": {"id": "1"},
            "error": None,
        }
        return [{"Type": 1, "Contents": {"tool_result": result, "audit": {}}}]

    ctx = _install(
        monkeypatch,
        command_handlers={
            "guardian-llm-chat": llm_handler,
            "GuardianToolBridge": bridge_handler,
            "getList": racy_get_list,
        },
    )
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 4,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": {"approval_id": "approval-1", "kind": "tool"},
            # This tick's own +1 lands exactly on the cap.
            "pending_ticks": tick.GUARDIAN_MAX_PENDING_TICKS - 1,
            "dropped_count": 0,
        },
        "ToolCatalog": [],
    }

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    # Must NOT be orphaned: the action executed, the loop is NOT stopped, and
    # a real model turn happened this same tick.
    assert "ESCALATED" not in outcome["narration"]
    assert len(llm_handler.calls) == 1
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "done"
    assert loop["pending"] is None
    assert loop["pending_ticks"] == 0
    system_notes = [
        m for m in loop["messages"] if isinstance(m.get("content"), str) and "was APPROVED by alice" in m["content"]
    ]
    assert len(system_notes) == 1
    assert "EXECUTED" in system_notes[0]["content"]


def test_stray_reentry_of_terminal_loop_is_a_no_op(monkeypatch):
    ctx = _install(monkeypatch)
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "x"}],
            "tick": 5,
            "run_id": "999",
            "status": "done",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "dropped_count": 0,
        }
    }
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert outcome["reschedule"] is False
    assert "already done" in outcome["narration"]


def test_content_filter_stops_loop(monkeypatch):
    llm_handler = _llm_handler_sequence([_completion(content_filter=True)])
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": llm_handler,
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert outcome["reschedule"] is False
    assert "content filter" in outcome["narration"]
    assert ctx["Guardian"]["Loop"]["status"] == "error"


def test_guardian_llm_chat_transport_failure_retries_then_stops(monkeypatch):
    def broken(args):
        return [{"Type": 4, "Contents": "connection reset"}]

    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": broken,
        },
    )
    first = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert first["reschedule"] is True
    assert "will retry next tick" in first["narration"]
    assert ctx["Guardian"]["Loop"]["consec_fails"] == 1

    second = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert second["reschedule"] is False
    assert ctx["Guardian"]["Loop"]["status"] == "error"
    assert ctx["Guardian"]["Loop"]["consec_fails"] == 2


def test_repeated_tool_call_in_one_turn_is_deduped(monkeypatch):
    tc1 = _tool_call("call_1", "ip", {"ip": "8.8.8.8"})
    tc2 = _tool_call("call_2", "ip", {"ip": "8.8.8.8"})  # identical name+args, different call id
    dispatch_count = {"n": 0}

    def bridge_handler(args):
        dispatch_count["n"] += 1
        result = {
            "tool_call_id": args.get("tool_call_id"),
            "tool_name": args.get("tool_name"),
            "status": "ok",
            "ok": True,
            "result": {"Score": 1},
            "error": None,
        }
        return [{"Type": 1, "Contents": {"tool_result": result, "audit": {}}}]

    ctx = _install(
        monkeypatch,
        settings=dict(DEFAULT_SETTINGS, model_tier="large"),
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": _llm_handler_sequence([_completion(tool_calls=[tc1, tc2])]),
            "GuardianToolBridge": bridge_handler,
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert outcome["reschedule"] is True
    # The bridge should only have been dispatched ONCE for the two identical
    # (name, arguments) tool_calls in this one turn -- the per-tick memo.
    assert dispatch_count["n"] == 1

    # Review round-1 CRITICAL-1 regression: even though the bridge was only
    # dispatched once, EVERY tool_call in the turn must still get its own
    # role:"tool" reply carrying ITS OWN id -- reusing the memoized result's
    # cached tool_call_id verbatim for both would leave call_2 with no reply
    # at all (and stamp call_1's id on both), violating the "every assistant
    # tool_calls[].id needs exactly one matching tool message" contract.
    tool_messages = [m for m in ctx["Guardian"]["Loop"]["messages"] if m.get("role") == "tool"]
    assert len(tool_messages) == 2
    tool_call_ids = {m["tool_call_id"] for m in tool_messages}
    assert tool_call_ids == {"call_1", "call_2"}


def test_main_reschedules_with_bare_command_name_and_original_args(monkeypatch):
    tc = _tool_call("call_1", "ip", {"ip": "8.8.8.8"})
    _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": _llm_handler_sequence([_completion(tool_calls=[tc])]),
            "GuardianToolBridge": _tool_bridge_handler(
                default_result={"status": "ok", "ok": True, "result": {"Score": 1}, "error": None}
            ),
        },
    )
    original_args = {"prompt": "Investigate 8.8.8.8", "skill": None}
    monkeypatch.setattr(tick.demisto, "args", lambda: original_args)

    import CommonServerPython as csp

    csp.RESULTS.clear()
    tick.main()

    assert len(csp.RESULTS) == 1
    result = csp.RESULTS[0]
    assert result.scheduled_command is not None
    # ScheduledCommand only exposes these via private attributes (no public
    # getters/properties in CommonServerPython) -- to_results() is the only
    # public read path, and only round-trips as PollingCommand/PollingArgs/
    # NextRun strings, so asserting the constructor's own inputs directly is
    # clearer here than decoding that dict.
    # STEP-0 finding: bare command name, no leading "!".
    assert result.scheduled_command._command == "GuardianReasoningTick"
    assert result.scheduled_command._next_run == str(DEFAULT_SETTINGS["tick_cadence_seconds"])
    assert result.scheduled_command._args == original_args


def test_main_returns_no_outputs_while_the_run_reschedules_itself(monkeypatch):
    tc = _tool_call("call_1", "ip", {"ip": "8.8.8.8"})
    _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": _llm_handler_sequence([_completion(tool_calls=[tc])]),
            "GuardianToolBridge": _tool_bridge_handler(default_result={"status": "ok", "ok": True, "result": {"Score": 1}, "error": None}),
        },
    )
    monkeypatch.setattr(tick.demisto, "args", lambda: {"prompt": "Investigate 8.8.8.8"})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    tick.main()
    assert csp.RESULTS[0].scheduled_command is not None
    assert csp.RESULTS[0].outputs is None and csp.RESULTS[0].outputs_prefix is None


def test_main_returns_small_outputs_keyed_by_run_id_when_the_run_concludes(monkeypatch):
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": _llm_handler_sequence([_completion(content="done")]),
        },
    )
    monkeypatch.setattr(tick.demisto, "args", lambda: {"prompt": "Investigate 8.8.8.8"})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    tick.main()
    result, loop = csp.RESULTS[0], ctx["Guardian"]["Loop"]
    assert result.outputs_prefix == "Guardian.Loop" and result.outputs_key_field == "run_id"
    assert result.outputs["run_id"] == loop["run_id"] and result.outputs["status"] == "done"
    # the key is in the context object the outputs merge into, and nothing large is returned
    assert set(result.outputs) <= set(loop) | {"verdict"}
    for large in ("messages", "executed_calls", "conclusion", "triage_block", "evidence"):
        assert large not in result.outputs


def test_concluding_outputs_carry_only_the_run_level_fields_and_the_verdicts_own_fields():
    state = {"run_id": "7", "status": "done", "tick": 3, "assessment_mode": "verdict", "skill": "s", "cost_usd": 0.0, "cost_tokens_total": 10,
             "messages": [{"role": "system", "content": "x" * 1000}], "executed_calls": {"a": 1}, "conclusion": "long text",
             "verdict": {"verdict": "Suspicious", "confidence": 55, "techniques": ["T1078"], "summary": "why", "stray": "dropped"}}
    out = tick.guardian_tick_concluding_outputs(state)
    assert out == {"run_id": "7", "status": "done", "tick": 3, "assessment_mode": "verdict", "skill": "s", "cost_usd": 0.0,
                   "cost_tokens_total": 10, "verdict": {"verdict": "Suspicious", "confidence": 55, "techniques": ["T1078"], "summary": "why"}}
    assert tick.guardian_tick_concluding_outputs({"status": "done"}) is None and tick.guardian_tick_concluding_outputs(None) is None
    assert "verdict" not in tick.guardian_tick_concluding_outputs({"run_id": "7", "status": "done", "verdict": "Benign"})


def test_main_final_answer_does_not_reschedule(monkeypatch):
    _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": _llm_handler_sequence([_completion(content="done")]),
        },
    )
    monkeypatch.setattr(tick.demisto, "args", lambda: {"prompt": "Investigate 8.8.8.8"})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    tick.main()

    assert len(csp.RESULTS) == 1
    assert csp.RESULTS[0].scheduled_command is None


def test_main_reports_job_guard_success_when_a_job_spawned_run_concludes_done(monkeypatch):
    """Task 3.4 follow-up wiring: main()'s report call, keyed off
    outcome["loop_state"] (this execution's OWN return value, never a
    fresh -- and stale -- demisto.context() re-read)."""
    job_guard_calls = []
    _install(
        monkeypatch,
        settings={"MAX_TICKS": 1, "tick_cadence_seconds": 12, "batch_cap": 25},
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": _llm_handler_sequence([_completion(content="Forced summary text")]),
            "GuardianJobGuard": lambda args: job_guard_calls.append(args)
            or [{"Type": 1, "Contents": {"ok": True}}],
        },
    )
    monkeypatch.setattr(tick.demisto, "args", lambda: {"prompt": "SOC intake sweep"})
    monkeypatch.setattr(
        tick.demisto,
        "incident",
        lambda: {"id": "999", "CustomFields": {"guardiantriggersource": "job:intake-sweep"}},
    )

    import CommonServerPython as csp

    csp.RESULTS.clear()
    tick.main()

    assert len(csp.RESULTS) == 1
    # Step 1b's own check fires first (proceed=True, since the fixture
    # handler doesn't set proceed=False), then main()'s report on conclusion.
    assert job_guard_calls == [
        {"action": "check", "job_name": "GuardianIntakeSweep"},
        {"action": "report", "job_name": "GuardianIntakeSweep", "outcome": "success"},
    ]


def test_main_reports_job_guard_failure_when_a_job_spawned_run_is_kill_switch_halted(monkeypatch):
    job_guard_calls = []
    _install(
        monkeypatch,
        kill_switch={"enabled": True},
        command_handlers={
            "GuardianJobGuard": lambda args: job_guard_calls.append(args)
            or [{"Type": 1, "Contents": {"ok": True}}],
        },
    )
    monkeypatch.setattr(tick.demisto, "args", lambda: {"prompt": "SOC intake sweep"})
    monkeypatch.setattr(
        tick.demisto,
        "incident",
        lambda: {"id": "999", "CustomFields": {"guardiantriggersource": "job:intake-sweep"}},
    )

    import CommonServerPython as csp

    csp.RESULTS.clear()
    tick.main()

    assert job_guard_calls == [{"action": "report", "job_name": "GuardianIntakeSweep", "outcome": "failure"}]


def test_main_does_not_double_report_when_job_guard_itself_halted_the_run(monkeypatch):
    """The run never actually attempted anything -- JobGuard's own check
    already said "don't proceed, already disabled". Reporting a failure
    back to the SAME registry entry would double-count against the
    threshold that just tripped it."""
    job_guard_calls = []
    _install(
        monkeypatch,
        command_handlers={
            "GuardianJobGuard": lambda args: job_guard_calls.append(args)
            or [{"Type": 1, "Contents": {"proceed": False, "reason": "job_disabled"}}],
        },
    )
    monkeypatch.setattr(tick.demisto, "args", lambda: {"prompt": "SOC intake sweep"})
    monkeypatch.setattr(
        tick.demisto,
        "incident",
        lambda: {"id": "999", "CustomFields": {"guardiantriggersource": "job:intake-sweep"}},
    )

    import CommonServerPython as csp

    csp.RESULTS.clear()
    tick.main()

    assert job_guard_calls == [{"action": "check", "job_name": "GuardianIntakeSweep"}]  # check only, no report


# --- Task 1.7 PART A: guardian_tick_charge_turn_cost / cost accounting --------


def test_cost_charged_once_per_llm_turn_and_field_written(monkeypatch):
    cost_calls = []

    def counting_cost_ledger(args):
        cost_calls.append(args)
        return _default_cost_ledger_handler(args)

    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": _llm_handler_sequence(
                [
                    _completion(
                        content="Verdict: benign",
                        usage={"prompt_tokens": 1000, "completion_tokens": 200, "total_tokens": 1200},
                    )
                ]
            ),
            "GuardianCostLedger": counting_cost_ledger,
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    # Exactly one guardian-llm-chat turn happened this tick -> exactly one
    # GuardianCostLedger call (the brief's "cost ledger called once per llm
    # turn" test requirement).
    assert len(cost_calls) == 1
    assert json.loads(cost_calls[0]["usage"]) == {"prompt_tokens": 1000, "completion_tokens": 200, "total_tokens": 1200}

    # Task D1: guardiancostusd/guardiantickcount actually land on the
    # incident's own CustomFields via the REST full-object merge
    # (guardian_set_incident_fields) -- not just accumulated in Context --
    # and as real numbers, never strings (the field defs are `type:number`).
    custom_fields = ctx["_incidents"]["999"]["CustomFields"]
    assert custom_fields["guardiancostusd"] > 0
    assert isinstance(custom_fields["guardiancostusd"], float)
    assert custom_fields["guardiantickcount"] == 1
    assert isinstance(custom_fields["guardiantickcount"], int)
    assert not isinstance(custom_fields["guardiantickcount"], bool)

    loop = ctx["Guardian"]["Loop"]
    assert loop["cost_usd"] > 0
    assert loop["cost_tokens_total"] == 1200
    assert "Run cost:" in outcome["narration"]
    assert "turn cost:" in outcome["narration"]


def test_cost_charged_for_both_calls_on_empty_turn_retry(monkeypatch):
    """Fix (review round-1, "cost undercount on empty-turn retry"): when the
    first `guardian-llm-chat` call comes back `kind=="empty"`,
    `guardian_tick_model_turn_with_retry` makes a SECOND real, billable
    provider call (the `tool_choice="required"` retry). Both are real,
    distinct provider calls, each with its own `usage` -- the tick must
    charge `GuardianCostLedger` for BOTH, not just the retry's result, or
    the first (empty) call's tokens are silently dropped from cost
    accounting and `guardiancostusd` under-reports.
    """
    cost_calls = []

    def counting_cost_ledger(args):
        cost_calls.append(args)
        return _default_cost_ledger_handler(args)

    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": _llm_handler_sequence(
                [
                    _completion(
                        content=None,
                        usage={"prompt_tokens": 100, "completion_tokens": 0, "total_tokens": 100},
                    ),
                    _completion(
                        content="Verdict: benign",
                        usage={"prompt_tokens": 120, "completion_tokens": 30, "total_tokens": 150},
                    ),
                ]
            ),
            "GuardianCostLedger": counting_cost_ledger,
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    # Two real guardian-llm-chat calls happened this tick (the empty first
    # try, then the tool_choice=required retry that produced the final
    # answer) -> TWO GuardianCostLedger calls, one per distinct provider
    # call -- not just the one turn this tick ultimately acts on.
    assert len(cost_calls) == 2
    assert json.loads(cost_calls[0]["usage"]) == {"prompt_tokens": 100, "completion_tokens": 0, "total_tokens": 100}
    assert json.loads(cost_calls[1]["usage"]) == {"prompt_tokens": 120, "completion_tokens": 30, "total_tokens": 150}

    loop = ctx["Guardian"]["Loop"]
    assert loop["cost_tokens_total"] == 100 + 150
    assert outcome["reschedule"] is False
    assert "concluded at tick 0" in outcome["narration"]


def test_cost_accumulates_across_ticks(monkeypatch):
    tc = _tool_call("call_1", "ip", {"ip": "8.8.8.8"})
    llm_handler = _llm_handler_sequence(
        [
            _completion(tool_calls=[tc], usage={"prompt_tokens": 500, "completion_tokens": 50, "total_tokens": 550}),
            _completion(
                content="Final verdict: benign",
                usage={"prompt_tokens": 600, "completion_tokens": 60, "total_tokens": 660},
            ),
        ]
    )
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": llm_handler,
            "GuardianToolBridge": _tool_bridge_handler(
                default_result={"status": "ok", "ok": True, "result": {"Score": 1}, "error": None}
            ),
        },
    )
    first = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert first["reschedule"] is True
    first_cost = ctx["Guardian"]["Loop"]["cost_usd"]
    assert first_cost > 0

    second = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert second["reschedule"] is False

    loop = ctx["Guardian"]["Loop"]
    assert loop["cost_usd"] > first_cost
    assert loop["cost_tokens_total"] == 550 + 660


def test_cost_ledger_failure_does_not_break_loop(monkeypatch):
    def broken_cost_ledger(args):
        return [{"Type": 4, "Contents": "GuardianCostLedger exploded"}]

    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": _llm_handler_sequence([_completion(content="Verdict: benign")]),
            "GuardianCostLedger": broken_cost_ledger,
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    assert "concluded at tick 0" in outcome["narration"]
    assert ctx["Guardian"]["Loop"]["status"] == "done"
    assert ctx["Guardian"]["Loop"]["cost_usd"] == 0.0


def test_incident_field_write_failure_is_visible_in_narration_not_just_logged(monkeypatch):
    # A GuardianCostLedger success followed by a guardian_set_incident_fields
    # (REST /incident write) failure must still not break the loop -- but,
    # unlike a plain demisto.error call (invisible outside server logs, and
    # there's no GuardianAuditWrite row for this internal, non-tool-call
    # write), the failure must be visible in the War Room narration so an
    # operator can actually diagnose it.
    def broken_demisto_api_post(args):
        uri = args.get("uri")
        if uri == "/incidents/search":
            return [
                {
                    "Type": 1,
                    "Contents": {
                        "response": {
                            "total": 1,
                            "data": [{"id": "999", "version": 1, "CustomFields": {}}],
                        }
                    },
                }
            ]
        if uri == "/incident":
            return [{"Type": 4, "Contents": "field not associated with this incident type"}]
        raise AssertionError("unexpected demisto-api-post uri={}".format(uri))

    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": _llm_handler_sequence(
                [_completion(content="Verdict: benign", usage={"prompt_tokens": 100, "completion_tokens": 20})]
            ),
            "demisto-api-post": broken_demisto_api_post,
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    # The cost was still computed and accumulated in Context even though the
    # incident-field write failed -- the two are independent side effects.
    assert ctx["Guardian"]["Loop"]["cost_usd"] > 0
    assert outcome["narration"].count("Custom issue fields could not be written on this tenant") == 1
    assert "Field writes are off for this run" in outcome["narration"]
    assert "field not associated with this incident type" in outcome["narration"]
    assert ctx["Guardian"]["Loop"]["field_writes_off"] is True


def test_forced_ceiling_summary_also_charges_cost(monkeypatch):
    cost_calls = []

    def counting_cost_ledger(args):
        cost_calls.append(args)
        return _default_cost_ledger_handler(args)

    ctx = _install(
        monkeypatch,
        settings={"MAX_TICKS": 1, "tick_cadence_seconds": 12, "batch_cap": 25},
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": _llm_handler_sequence([_completion(content="Forced summary text")]),
            "GuardianCostLedger": counting_cost_ledger,
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    assert len(cost_calls) == 1
    assert ctx["Guardian"]["Loop"]["cost_usd"] > 0
    assert "Run cost so far:" in outcome["narration"]


# --- Task 1.7 PART B: guardian_tick_call_fingerprint / guardian_tick_build_repeat_note --


def test_call_fingerprint_stable_regardless_of_key_order():
    fp1 = tick.guardian_tick_call_fingerprint("ip", json.dumps({"ip": "8.8.8.8", "verbose": True}))
    fp2 = tick.guardian_tick_call_fingerprint("ip", json.dumps({"verbose": True, "ip": "8.8.8.8"}))
    assert fp1 == fp2


def test_call_fingerprint_differs_for_different_tool_or_args():
    fp_a = tick.guardian_tick_call_fingerprint("ip", json.dumps({"ip": "8.8.8.8"}))
    fp_b = tick.guardian_tick_call_fingerprint("ip", json.dumps({"ip": "1.1.1.1"}))
    fp_c = tick.guardian_tick_call_fingerprint("whois", json.dumps({"ip": "8.8.8.8"}))
    assert len({fp_a, fp_b, fp_c}) == 3


def _catalog(*names):
    return [{"type": "function", "function": {"name": n}} for n in names]


def test_select_catalog_tier_narrows_to_tier0_when_no_evidence_yet():
    catalog = _catalog("GuardianSkillRead", "getIncidents", "getEntries", "splunk-search", "ip", "domain", "url", "file")
    loop_state = {"executed_calls": {}}
    tiered = tick.guardian_tick_select_catalog_tier(catalog, loop_state)
    names = {e["function"]["name"] for e in tiered}
    assert names == {"GuardianSkillRead", "getIncidents", "getEntries", "splunk-search"}


def test_select_catalog_tier_ignores_search_incidents_v2_absent_from_catalog():
    # SearchIncidentsV2 is part of GUARDIAN_TICK_TIER0_COMMANDS but simply
    # isn't in this catalogue -- must not error, must not appear.
    catalog = _catalog("GuardianSkillRead", "getIncidents", "ip")
    tiered = tick.guardian_tick_select_catalog_tier(catalog, {"executed_calls": {}})
    assert {e["function"]["name"] for e in tiered} == {"GuardianSkillRead", "getIncidents"}


def test_select_catalog_tier_unlocks_full_catalog_after_real_evidence_call():
    catalog = _catalog("GuardianSkillRead", "getIncidents", "getEntries", "splunk-search", "ip", "domain")
    loop_state = {"executed_calls": {"splunk-search|{}": {"count": 1}}}
    tiered = tick.guardian_tick_select_catalog_tier(catalog, loop_state)
    assert tiered is catalog


def test_select_catalog_tier_skill_read_alone_does_not_unlock_full_catalog():
    # GuardianSkillRead is bootstrap, not evidence -- calling only it must
    # NOT widen the catalogue back out to ip/domain/url/file.
    catalog = _catalog("GuardianSkillRead", "getIncidents", "ip")
    loop_state = {"executed_calls": {"GuardianSkillRead|{}": {"count": 1}}}
    tiered = tick.guardian_tick_select_catalog_tier(catalog, loop_state)
    assert {e["function"]["name"] for e in tiered} == {"GuardianSkillRead", "getIncidents"}


def test_select_catalog_tier_falls_back_to_full_catalog_if_tier0_would_be_empty():
    # A catalogue containing none of the tier-0 names -- narrowing would
    # leave nothing offered, which must never happen.
    catalog = _catalog("ip", "domain")
    tiered = tick.guardian_tick_select_catalog_tier(catalog, {"executed_calls": {}})
    assert tiered is catalog


def test_select_catalog_tier_passes_through_non_list_or_empty_catalog():
    assert tick.guardian_tick_select_catalog_tier(None, {"executed_calls": {}}) is None
    assert tick.guardian_tick_select_catalog_tier([], {"executed_calls": {}}) == []


def test_build_repeat_note_preserves_result_restamps_id_adds_note():
    prior_result = {
        "tool_call_id": "call_1",
        "tool_name": "ip",
        "status": "ok",
        "ok": True,
        "result": {"Score": 1},
        "error": None,
    }
    reused = tick.guardian_tick_build_repeat_note(prior_result, "call_2")

    assert reused["tool_call_id"] == "call_2"
    assert reused["result"] == {"Score": 1}
    assert reused["status"] == "ok"
    assert "note" in reused
    assert "already executed" in reused["note"]
    # A shallow copy, not a mutation of the cached original.
    assert prior_result["tool_call_id"] == "call_1"
    assert "note" not in prior_result


# --- Task 1.7 PART B: full integration -- the #26 repeated-successful-call guard --


def test_repeated_successful_call_not_redispatched_across_ticks(monkeypatch):
    tc1 = _tool_call("call_1", "ip", {"ip": "8.8.8.8"})
    tc2 = _tool_call("call_2", "ip", {"ip": "8.8.8.8"})  # identical tool+args, later tick, DIFFERENT id
    llm_handler = _llm_handler_sequence([_completion(tool_calls=[tc1]), _completion(tool_calls=[tc2])])
    dispatch_count = {"n": 0}

    def bridge_handler(args):
        dispatch_count["n"] += 1
        result = {
            "tool_call_id": args.get("tool_call_id"),
            "tool_name": args.get("tool_name"),
            "status": "ok",
            "ok": True,
            "result": {"Score": 1},
            "error": None,
        }
        return [{"Type": 1, "Contents": {"tool_result": result, "audit": {}}}]

    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": llm_handler,
            "GuardianToolBridge": bridge_handler,
        },
    )

    first = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert first["reschedule"] is True
    assert dispatch_count["n"] == 1

    second = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert second["reschedule"] is True
    # The bridge must NOT be re-dispatched for the identical repeated call
    # across ticks -- this IS the #26 fix.
    assert dispatch_count["n"] == 1

    loop = ctx["Guardian"]["Loop"]
    assert loop["repeat_calls"] == 1
    fp = tick.guardian_tick_call_fingerprint("ip", json.dumps({"ip": "8.8.8.8"}))
    assert loop["executed_calls"][fp]["count"] == 2

    # Every tool_call across both ticks still got its own role:"tool" reply
    # with its OWN id (call_2's reply must carry call_2's id, not call_1's).
    tool_messages = [m for m in loop["messages"] if m.get("role") == "tool"]
    assert len(tool_messages) == 2
    assert tool_messages[0]["tool_call_id"] == "call_1"
    assert tool_messages[1]["tool_call_id"] == "call_2"

    # The reused reply carries the "already executed" note.
    second_payload = json.loads(tool_messages[1]["content"])
    assert "note" in second_payload
    assert "already executed" in second_payload["note"]
    # The FIRST (real dispatch) reply does NOT carry that note.
    first_payload = json.loads(tool_messages[0]["content"])
    assert "note" not in first_payload


def test_repeated_call_threshold_forces_conclusion_and_exit(monkeypatch):
    tc = _tool_call("call_x", "ip", {"ip": "8.8.8.8"})
    llm_handler = _llm_handler_sequence(
        [
            _completion(tool_calls=[tc]),  # tick 0: real dispatch -> executed_calls[fp].count == 1
            _completion(tool_calls=[tc]),  # tick 1: reused -> count == 2, repeat_calls == 1
            _completion(tool_calls=[tc]),  # tick 2: reused -> count == 3 (>= GUARDIAN_MAX_SAME_CALL) -> force_conclude
            _completion(content="Concluding: repeated calls, nothing new to add."),  # tick 3: forced no-tools summary
        ]
    )
    dispatch_count = {"n": 0}

    def bridge_handler(args):
        dispatch_count["n"] += 1
        result = {
            "tool_call_id": args.get("tool_call_id"),
            "tool_name": args.get("tool_name"),
            "status": "ok",
            "ok": True,
            "result": {"Score": 1},
            "error": None,
        }
        return [{"Type": 1, "Contents": {"tool_result": result, "audit": {}}}]

    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": llm_handler,
            "GuardianToolBridge": bridge_handler,
        },
    )

    outcomes = [tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"}) for _ in range(4)]

    # tick 0/1/2 all still reschedule -- the threshold trip on tick 2 defers
    # its forced conclusion to "next tick" rather than cutting the loop off
    # synchronously in the same tick it tripped.
    assert [o["reschedule"] for o in outcomes[:3]] == [True, True, True]
    assert ctx["Guardian"]["Loop"]["force_conclude"] is True
    assert ctx["Guardian"]["Loop"]["executed_calls"][
        tick.guardian_tick_call_fingerprint("ip", json.dumps({"ip": "8.8.8.8"}))
    ]["count"] == 3

    # tick 3 performs the forced no-tools conclusion and exits.
    final_outcome = outcomes[3]
    assert final_outcome["reschedule"] is False
    assert "repeated-call loop broken" in final_outcome["narration"]
    assert "Concluding: repeated calls" in final_outcome["narration"]
    assert ctx["Guardian"]["Loop"]["status"] == "done"

    # The bridge was dispatched only ONCE across all four ticks -- every
    # repeat reused the cached result instead of re-executing.
    assert dispatch_count["n"] == 1

    # The forced conclusion turn was a genuine no-tools call.
    assert llm_handler.calls[-1]["tool_choice"] == "none"
    assert "tools" not in llm_handler.calls[-1]


def test_repeat_calls_run_level_threshold_also_forces_conclusion(monkeypatch):
    # Four DIFFERENT tools, each repeated exactly once (so no single
    # fingerprint ever reaches GUARDIAN_MAX_SAME_CALL=3) -- but the RUN-LEVEL
    # repeat_calls counter still crosses GUARDIAN_MAX_REPEATS=4 once all four
    # have been reused, and that alone must also force a conclusion.
    tool_names = ["ip", "whois", "domain", "url"]
    first_calls = [_tool_call("call_{}_a".format(n), n, {"value": n}) for n in tool_names]
    repeat_calls_msgs = [_tool_call("call_{}_b".format(n), n, {"value": n}) for n in tool_names]

    completions = [_completion(tool_calls=[tc]) for tc in first_calls]
    completions += [_completion(tool_calls=[tc]) for tc in repeat_calls_msgs]
    completions.append(_completion(content="Concluding after many repeats."))
    llm_handler = _llm_handler_sequence(completions)

    def bridge_handler(args):
        result = {
            "tool_call_id": args.get("tool_call_id"),
            "tool_name": args.get("tool_name"),
            "status": "ok",
            "ok": True,
            "result": {"Score": 1},
            "error": None,
        }
        return [{"Type": 1, "Contents": {"tool_result": result, "audit": {}}}]

    catalog = [{"type": "function", "function": {"name": n}} for n in tool_names]
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler(catalog),
            "guardian-llm-chat": llm_handler,
            "GuardianToolBridge": bridge_handler,
        },
    )

    # 4 ticks with the ORIGINAL calls, then 4 ticks repeating each tool once.
    outcomes = [tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"}) for _ in range(8)]
    assert all(o["reschedule"] for o in outcomes)  # none of these alone hit any single fingerprint's own limit
    assert ctx["Guardian"]["Loop"]["repeat_calls"] == 4
    assert ctx["Guardian"]["Loop"]["force_conclude"] is True

    final_outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert final_outcome["reschedule"] is False
    assert "repeated-call loop broken" in final_outcome["narration"]
    assert ctx["Guardian"]["Loop"]["status"] == "done"


def test_max_same_call_and_max_repeats_are_settings_readable(monkeypatch):
    # A tighter max_same_call=2 (from guardian_settings) must trip the guard
    # a tick EARLIER than the default=3 would.
    tc = _tool_call("call_x", "ip", {"ip": "8.8.8.8"})
    llm_handler = _llm_handler_sequence(
        [
            _completion(tool_calls=[tc]),  # tick 0: real dispatch -> count == 1
            _completion(tool_calls=[tc]),  # tick 1: reused -> count == 2 (>= configured max_same_call=2)
            _completion(content="Concluding early due to tighter threshold."),  # tick 2: forced summary
        ]
    )

    def bridge_handler(args):
        result = {
            "tool_call_id": args.get("tool_call_id"),
            "tool_name": args.get("tool_name"),
            "status": "ok",
            "ok": True,
            "result": {"Score": 1},
            "error": None,
        }
        return [{"Type": 1, "Contents": {"tool_result": result, "audit": {}}}]

    ctx = _install(
        monkeypatch,
        settings={
            "MAX_TICKS": 25,
            "tick_cadence_seconds": 12,
            "batch_cap": 25,
            "max_same_call": 2,
            "max_repeats": 4,
        },
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": llm_handler,
            "GuardianToolBridge": bridge_handler,
        },
    )

    outcomes = [tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"}) for _ in range(3)]
    assert outcomes[0]["reschedule"] is True
    assert outcomes[1]["reschedule"] is True
    assert ctx["Guardian"]["Loop"]["force_conclude"] is True
    assert outcomes[2]["reschedule"] is False
    assert ctx["Guardian"]["Loop"]["status"] == "done"


# --- Task 1.8: guardian_tick_load_settings new fields -------------------------


def test_load_settings_compact_fields_use_defaults_when_unreadable(monkeypatch):
    def broken_getlist(args):
        return [{"Type": 4, "Contents": "boom"}]

    monkeypatch.setattr(tick.demisto, "executeCommand", broken_getlist)
    monkeypatch.setattr(tick.demisto, "error", lambda msg: None)
    settings = tick.guardian_tick_load_settings()
    assert settings["compact_after_dropped"] == tick.GUARDIAN_DEFAULT_COMPACT_AFTER_DROPPED


def test_load_settings_compact_fields_honor_configured_values(monkeypatch):
    _install(monkeypatch, settings={"MAX_TICKS": 25, "batch_cap": 25, "compact_after_dropped": 3,
                                     "output_reserve_tokens": 4096})
    settings = tick.guardian_tick_load_settings()
    assert settings["compact_after_dropped"] == 3


def test_load_settings_does_not_load_output_reserve_tokens(monkeypatch):
    """output_reserve_tokens's only real consumer is GuardianProbeModel (read
    live at calibration time to derive max_input_tokens); this tick only
    ever needs to enforce the already-derived max_input_tokens itself, so
    guardian_tick_load_settings must not carry the raw reserve field --
    pins the Backlog Board 'output_reserve_tokens is dead configuration'
    fix so it can't silently regress back to unused dict weight."""
    _install(monkeypatch, settings={"MAX_TICKS": 25, "batch_cap": 25, "output_reserve_tokens": 4096})
    settings = tick.guardian_tick_load_settings()
    assert "output_reserve_tokens" not in settings


# --- FIX C: max_input_tokens settings field -----------------------------------


def test_load_settings_max_input_tokens_disabled_by_default(monkeypatch):
    """The pack ships max_input_tokens=null -- it must load as None
    (disabled), never coerced to a positive ceiling."""
    _install(monkeypatch, settings={"MAX_TICKS": 25, "batch_cap": 25, "max_input_tokens": None})
    settings = tick.guardian_tick_load_settings()
    assert settings["max_input_tokens"] is None


def test_load_settings_max_input_tokens_honors_positive_value(monkeypatch):
    _install(monkeypatch, settings={"MAX_TICKS": 25, "batch_cap": 25, "max_input_tokens": 120000})
    settings = tick.guardian_tick_load_settings()
    assert settings["max_input_tokens"] == 120000


def test_load_settings_max_input_tokens_nonpositive_disables(monkeypatch):
    """A stray 0/negative value must disable the ceiling (None), never turn
    into a ceiling of 0 that would compact every single turn to nothing."""
    _install(monkeypatch, settings={"MAX_TICKS": 25, "batch_cap": 25, "max_input_tokens": 0})
    settings = tick.guardian_tick_load_settings()
    assert settings["max_input_tokens"] is None


# --- guardian_tick_compact_plan (Task 1.8) --------------------------------------


def test_compact_plan_no_op_under_cap():
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}]
    plan = tick.guardian_tick_compact_plan(messages, batch_cap=25)
    assert plan["needed"] is False
    assert plan["dropped"] == []
    assert plan["kept"] == []


def test_compact_plan_computes_boundary_aware_split():
    messages = [{"role": "system", "content": "sys"}, _TASK] + _long_transcript(10)
    plan = tick.guardian_tick_compact_plan(messages, batch_cap=5)
    assert plan["needed"] is True
    assert plan["system_message"] == {"role": "system", "content": "sys"}
    assert plan["head"] == [{"role": "system", "content": "sys"}, _TASK]   # never part of dropped or kept
    assert plan["prior_checkpoint"] is None
    assert len(plan["dropped"]) + len(plan["kept"]) == 10
    assert plan["kept"][-1]["content"] == "turn-9"
    assert plan["dropped"][0]["content"] == "turn-0"


def test_compact_plan_extracts_leading_prior_checkpoint():
    checkpoint = {"role": "system", "content": "old", "guardian_checkpoint": True, "covers_until": 3}
    messages = [{"role": "system", "content": "sys"}, checkpoint] + _long_transcript(10)
    plan = tick.guardian_tick_compact_plan(messages, batch_cap=5)
    assert plan["prior_checkpoint"] == checkpoint
    assert checkpoint not in plan["dropped"]
    assert checkpoint not in plan["kept"]


def test_compact_plan_never_orphans_tool_reply_at_recent_window_start():
    messages = [{"role": "system", "content": "sys"}]
    for i in range(6):
        messages.append({"role": "user", "content": "user-{}".format(i)})
        messages.append(
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {"id": "call-{}".format(i), "type": "function", "function": {"name": "ip", "arguments": "{}"}}
                ],
            }
        )
        messages.append({"role": "tool", "tool_call_id": "call-{}".format(i), "content": "result-{}".format(i)})

    plan = tick.guardian_tick_compact_plan(messages, batch_cap=6)
    assert plan["kept"][0]["role"] != "tool"

    seen_call_ids = set()
    for msg in plan["dropped"]:
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            for call in msg["tool_calls"]:
                seen_call_ids.add(call["id"])
    for msg in plan["kept"]:
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            for call in msg["tool_calls"]:
                seen_call_ids.add(call["id"])
        elif msg.get("role") == "tool":
            assert msg["tool_call_id"] in seen_call_ids


# --- guardian_tick_call_compact (Task 1.8) --------------------------------------


def test_call_compact_sends_dropped_plus_kept_with_correct_keep_recent(monkeypatch):
    handler = _compact_handler(kept_messages=[{"role": "user", "content": "recent-1"}])
    _install(monkeypatch, command_handlers={"GuardianCompact": handler})
    plan = {
        "needed": True,
        "system_message": {"role": "system", "content": "sys"},
        "prior_checkpoint": None,
        "dropped": [{"role": "user", "content": "old-1"}, {"role": "user", "content": "old-2"}],
        "kept": [{"role": "user", "content": "recent-1"}],
    }
    result = tick.guardian_tick_call_compact(plan)
    assert result["ok"] is True
    sent = handler.calls[0]
    assert sent["messages"] == plan["dropped"] + plan["kept"]
    assert sent["keep_recent"] == 1


def test_call_compact_includes_prior_checkpoint_when_present(monkeypatch):
    checkpoint = {"role": "system", "content": "old summary", "guardian_checkpoint": True, "covers_until": 2}
    handler = _compact_handler()
    _install(monkeypatch, command_handlers={"GuardianCompact": handler})
    plan = {
        "needed": True,
        "system_message": {"role": "system", "content": "sys"},
        "prior_checkpoint": checkpoint,
        "dropped": [{"role": "user", "content": "old-1"}],
        "kept": [{"role": "user", "content": "recent-1"}],
    }
    tick.guardian_tick_call_compact(plan)
    sent = handler.calls[0]
    assert sent["messages"][0] == checkpoint


def test_call_compact_propagates_failure(monkeypatch):
    _install(monkeypatch, command_handlers={"GuardianCompact": _compact_failure_handler("boom")})
    plan = {
        "needed": True,
        "system_message": {"role": "system", "content": "sys"},
        "prior_checkpoint": None,
        "dropped": [{"role": "user", "content": "old-1"}],
        "kept": [],
    }
    result = tick.guardian_tick_call_compact(plan)
    assert result["ok"] is False
    assert "boom" in result["error"]


def test_call_compact_malformed_response_is_an_error(monkeypatch):
    def handle(args):
        return [{"Type": 1, "Contents": {"not_a_checkpoint": True}}]

    _install(monkeypatch, command_handlers={"GuardianCompact": handle})
    plan = {
        "needed": True,
        "system_message": {"role": "system", "content": "sys"},
        "prior_checkpoint": None,
        "dropped": [{"role": "user", "content": "old-1"}],
        "kept": [],
    }
    result = tick.guardian_tick_call_compact(plan)
    assert result["ok"] is False
    assert "malformed" in result["error"]


# --- guardian_tick_prune_executed_calls (Task 1.8, Task-1.7 follow-up) ----------


def test_prune_executed_calls_keeps_only_referenced_fingerprints():
    ip_fp = tick.guardian_tick_call_fingerprint("ip", "{}")
    whois_fp = tick.guardian_tick_call_fingerprint("whois", "{}")
    loop_state = {
        "executed_calls": {
            ip_fp: {"count": 2, "first_tick": 0, "last_result": {"ok": True}},
            whois_fp: {"count": 1, "first_tick": 1, "last_result": {"ok": True}},
        }
    }
    new_messages = [
        {"role": "system", "content": "sys"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "ip", "arguments": "{}"}}],
        },
        {"role": "tool", "tool_call_id": "c1", "content": "result"},
    ]
    tick.guardian_tick_prune_executed_calls(loop_state, new_messages)
    assert ip_fp in loop_state["executed_calls"]
    assert whois_fp not in loop_state["executed_calls"]


def test_prune_executed_calls_noop_when_empty():
    loop_state = {"executed_calls": {}}
    tick.guardian_tick_prune_executed_calls(loop_state, [{"role": "system", "content": "sys"}])
    assert loop_state["executed_calls"] == {}


def test_prune_executed_calls_drops_everything_when_nothing_referenced():
    ip_fp = tick.guardian_tick_call_fingerprint("ip", "{}")
    loop_state = {"executed_calls": {ip_fp: {"count": 1, "first_tick": 0, "last_result": {}}}}
    tick.guardian_tick_prune_executed_calls(loop_state, [{"role": "system", "content": "sys"}])
    assert loop_state["executed_calls"] == {}


# --- guardian_tick_attempt_compaction (Task 1.8) --------------------------------


def test_attempt_compaction_below_threshold_skips_without_calling_compact(monkeypatch):
    _install(monkeypatch)  # GuardianCompact intentionally NOT wired -- must not be called
    messages = [{"role": "system", "content": "sys"}] + _long_transcript(10)
    loop_state = {"compact_cooldown": 0}
    settings = _full_settings(batch_cap=5, compact_after_dropped=100)
    new_messages, note = tick.guardian_tick_attempt_compaction(messages, settings, loop_state, "run-1", "trig")
    assert new_messages is None
    assert note == ""


def test_attempt_compaction_in_cooldown_skips_and_counts_down(monkeypatch):
    _install(monkeypatch)  # GuardianCompact intentionally NOT wired -- must not be called
    messages = [{"role": "system", "content": "sys"}] + _long_transcript(10)
    loop_state = {"compact_cooldown": 3}
    settings = _full_settings(batch_cap=5, compact_after_dropped=1)
    new_messages, note = tick.guardian_tick_attempt_compaction(messages, settings, loop_state, "run-1", "trig")
    assert new_messages is None
    assert note == ""
    assert loop_state["compact_cooldown"] == 2


def test_attempt_compaction_success_rebuilds_charges_and_prunes(monkeypatch):
    ip_fp = tick.guardian_tick_call_fingerprint("ip", "{}")
    stale_fp = tick.guardian_tick_call_fingerprint("stale_tool", "{}")
    messages = [{"role": "system", "content": "sys"}, _TASK] + _long_transcript(10)
    # The recent (kept) window will include one live tool call referencing
    # `ip_fp` -- the compact handler below returns THIS as its
    # `kept_messages`, so pruning should keep ip_fp and drop stale_fp.
    kept_messages = [
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "ip", "arguments": "{}"}}],
        },
        {"role": "tool", "tool_call_id": "c1", "content": "kept result"},
    ]
    usage = {"prompt_tokens": 900, "completion_tokens": 300, "total_tokens": 1200}
    handler = _compact_handler(
        summary_text="8.8.8.8 and 1.1.1.1 were checked", kept_messages=kept_messages, usage=usage
    )
    _install(monkeypatch, command_handlers={"GuardianCompact": handler})

    loop_state = {
        "compact_cooldown": 0,
        "cost_usd": 0.0,
        "cost_tokens_total": 0,
        "dropped_count": 0,
        "executed_calls": {
            ip_fp: {"count": 1, "first_tick": 0, "last_result": {"ok": True}},
            stale_fp: {"count": 1, "first_tick": 0, "last_result": {"ok": True}},
        },
    }
    settings = _full_settings(batch_cap=5, compact_after_dropped=1)
    new_messages, note = tick.guardian_tick_attempt_compaction(messages, settings, loop_state, "run-1", "trig")

    assert new_messages is not None
    assert new_messages[0] == {"role": "system", "content": "sys"} and new_messages[1] == _TASK   # verbatim, not summarized
    assert new_messages[2]["guardian_checkpoint"] is True
    assert "8.8.8.8 and 1.1.1.1 were checked" in new_messages[2]["content"]
    assert new_messages[3:] == kept_messages
    assert _TASK not in handler.calls[0]["messages"]   # and never sent to the summarizer
    assert "compacted" in note

    # Cost was charged for the summarization call.
    assert loop_state["cost_usd"] > 0.0
    assert loop_state["cost_tokens_total"] == 1200

    # executed_calls pruned down to only what the rebuilt transcript
    # references.
    assert ip_fp in loop_state["executed_calls"]
    assert stale_fp not in loop_state["executed_calls"]

    # Cooldown reset, dropped_count incremented by what was summarized.
    assert loop_state["compact_cooldown"] == 0
    assert loop_state["dropped_count"] > 0


def test_attempt_compaction_failure_sets_cooldown_and_falls_back(monkeypatch):
    _install(monkeypatch, command_handlers={"GuardianCompact": _compact_failure_handler("provider down")})
    messages = [{"role": "system", "content": "sys"}] + _long_transcript(10)
    loop_state = {"compact_cooldown": 0}
    settings = _full_settings(batch_cap=5, compact_after_dropped=1)
    new_messages, note = tick.guardian_tick_attempt_compaction(messages, settings, loop_state, "run-1", "trig")
    assert new_messages is None
    assert "compaction skipped" in note
    assert loop_state["compact_cooldown"] == tick.GUARDIAN_DEFAULT_COMPACT_COOLDOWN_TICKS


# --- guardian_tick_persist_dropped_transcript (harvest candidate #14) ------------


def _dropped_transcript_execute_stub(monkeypatch, existing_rows=None, get_time_ok=True, create_ok=True):
    """Mocks tick.guardian_execute for GetTime/getList/createList against
    GUARDIAN_DROPPED_TRANSCRIPT_LIST_NAME specifically. `calls` records every
    dispatched (command, args) pair in order."""
    calls = []

    def fake_execute(command, args, using=None):
        calls.append((command, args))
        if command == "GetTime":
            if not get_time_ok:
                return {"ok": False, "error": "GetTime unavailable", "retryable": True, "is_auth_error": False}
            return {"ok": True, "data": [{"Type": 1, "Contents": "2026-08-25T12:00:00Z"}], "error": None, "retryable": False, "is_auth_error": False}
        if command == "getList" and args["listName"] == tick.GUARDIAN_DROPPED_TRANSCRIPT_LIST_NAME:
            if existing_rows is None:
                return {"ok": False, "error": "Item not found (8) on list [...]", "retryable": False, "is_auth_error": False}
            return {
                "ok": True,
                "data": [{"Type": 1, "Contents": json.dumps(existing_rows)}],
                "error": None,
                "retryable": False,
                "is_auth_error": False,
            }
        if command == "createList" and args["listName"] == tick.GUARDIAN_DROPPED_TRANSCRIPT_LIST_NAME:
            if not create_ok:
                return {"ok": False, "error": "list write conflict", "retryable": True, "is_auth_error": False}
            return {"ok": True, "data": [{"Type": 1, "Contents": "Done"}], "error": None, "retryable": False, "is_auth_error": False}
        raise AssertionError("unexpected command in test: {} {}".format(command, args))

    monkeypatch.setattr(tick, "guardian_execute", fake_execute)
    return calls


def test_persist_dropped_transcript_noop_when_dropped_empty(monkeypatch):
    calls = _dropped_transcript_execute_stub(monkeypatch)
    tick.guardian_tick_persist_dropped_transcript([], "run-1", 3)
    assert calls == []


def test_persist_dropped_transcript_creates_list_on_first_write(monkeypatch):
    calls = _dropped_transcript_execute_stub(monkeypatch, existing_rows=None)
    monkeypatch.setattr(tick.demisto, "incident", lambda: {"id": "555"})

    dropped = [{"role": "user", "content": "turn 1"}, {"role": "assistant", "content": "turn 2"}]
    tick.guardian_tick_persist_dropped_transcript(dropped, "run-1", 3)

    create_calls = [c for c in calls if c[0] == "createList"]
    assert len(create_calls) == 1
    rows = json.loads(create_calls[0][1]["listData"])
    assert len(rows) == 1
    assert rows[0]["run_id"] == "run-1"
    assert rows[0]["incident_id"] == "555"
    assert rows[0]["tick"] == 3
    assert rows[0]["ts"] == "2026-08-25T12:00:00Z"
    assert rows[0]["dropped_messages"] == dropped  # verbatim, not summarized


def test_persist_dropped_transcript_appends_to_existing_rows(monkeypatch):
    existing = [{"run_id": "run-0", "incident_id": "1", "tick": 1, "ts": "x", "dropped_messages": []}]
    calls = _dropped_transcript_execute_stub(monkeypatch, existing_rows=existing)
    monkeypatch.setattr(tick.demisto, "incident", lambda: {"id": "555"})

    tick.guardian_tick_persist_dropped_transcript([{"role": "user", "content": "new"}], "run-1", 4)

    create_calls = [c for c in calls if c[0] == "createList"]
    rows = json.loads(create_calls[0][1]["listData"])
    assert len(rows) == 2
    assert rows[0]["run_id"] == "run-0"  # prior row preserved
    assert rows[1]["run_id"] == "run-1"  # new row appended, not prepended


def test_persist_dropped_transcript_trims_to_max_rows(monkeypatch):
    existing = [
        {"run_id": "run-{}".format(i), "incident_id": "1", "tick": i, "ts": "x", "dropped_messages": []}
        for i in range(tick.GUARDIAN_DROPPED_TRANSCRIPT_MAX_ROWS)
    ]
    calls = _dropped_transcript_execute_stub(monkeypatch, existing_rows=existing)
    monkeypatch.setattr(tick.demisto, "incident", lambda: {"id": "555"})

    tick.guardian_tick_persist_dropped_transcript([{"role": "user", "content": "new"}], "run-new", 99)

    create_calls = [c for c in calls if c[0] == "createList"]
    rows = json.loads(create_calls[0][1]["listData"])
    assert len(rows) == tick.GUARDIAN_DROPPED_TRANSCRIPT_MAX_ROWS  # still capped, not MAX+1
    assert rows[0]["run_id"] == "run-1"  # oldest (run-0) trimmed off
    assert rows[-1]["run_id"] == "run-new"  # newest always kept


def test_persist_dropped_transcript_no_incident_context_leaves_incident_id_none(monkeypatch):
    calls = _dropped_transcript_execute_stub(monkeypatch, existing_rows=None)
    monkeypatch.setattr(tick.demisto, "incident", lambda: {})  # Playground: no incident

    tick.guardian_tick_persist_dropped_transcript([{"role": "user", "content": "x"}], "run-1", 1)

    create_calls = [c for c in calls if c[0] == "createList"]
    rows = json.loads(create_calls[0][1]["listData"])
    assert rows[0]["incident_id"] is None


def test_persist_dropped_transcript_still_writes_when_get_time_fails(monkeypatch):
    """GetTime failing must not block the archive write -- ts just stays
    None, exactly like GuardianToolBridge's own get-server-time fallback
    philosophy elsewhere in this pack."""
    calls = _dropped_transcript_execute_stub(monkeypatch, existing_rows=None, get_time_ok=False)
    monkeypatch.setattr(tick.demisto, "incident", lambda: {"id": "555"})

    tick.guardian_tick_persist_dropped_transcript([{"role": "user", "content": "x"}], "run-1", 1)

    create_calls = [c for c in calls if c[0] == "createList"]
    assert len(create_calls) == 1
    rows = json.loads(create_calls[0][1]["listData"])
    assert rows[0]["ts"] is None


def test_persist_dropped_transcript_write_failure_is_logged_never_raised(monkeypatch):
    _dropped_transcript_execute_stub(monkeypatch, existing_rows=None, create_ok=False)
    monkeypatch.setattr(tick.demisto, "incident", lambda: {"id": "555"})
    errors = []
    monkeypatch.setattr(tick.demisto, "error", lambda msg: errors.append(msg))

    tick.guardian_tick_persist_dropped_transcript([{"role": "user", "content": "x"}], "run-1", 1)  # must not raise

    assert any("list write conflict" in e for e in errors)


def test_persist_dropped_transcript_swallows_unexpected_exception(monkeypatch):
    def fake_execute(command, args, using=None):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(tick, "guardian_execute", fake_execute)
    errors = []
    monkeypatch.setattr(tick.demisto, "error", lambda msg: errors.append(msg))

    tick.guardian_tick_persist_dropped_transcript([{"role": "user", "content": "x"}], "run-1", 1)  # must not raise

    assert any("kaboom" in e for e in errors)


# --- guardian_tick_annotate_intake_sweep_repeat (harvest candidate #13 part 2) ----


def _intake_sweep_execute_stub(monkeypatch, prior_content=None, create_ok=True):
    """Mocks tick.guardian_execute for getList/createList against
    GUARDIAN_INTAKE_SWEEP_NARRATION_LIST_NAME specifically. `calls` records
    every dispatched (command, args) pair in order. `prior_content=None`
    mirrors a genuinely first-ever sweep (List not found yet)."""
    calls = []

    def fake_execute(command, args, using=None):
        calls.append((command, args))
        if command == "getList" and args["listName"] == tick.GUARDIAN_INTAKE_SWEEP_NARRATION_LIST_NAME:
            if prior_content is None:
                return {"ok": False, "error": "Item not found (8) on list [...]", "retryable": False, "is_auth_error": False}
            return {
                "ok": True,
                "data": [{"Type": 1, "Contents": json.dumps({"content": prior_content, "run_id": "prior-run"})}],
                "error": None,
                "retryable": False,
                "is_auth_error": False,
            }
        if command == "createList" and args["listName"] == tick.GUARDIAN_INTAKE_SWEEP_NARRATION_LIST_NAME:
            if not create_ok:
                return {"ok": False, "error": "list write conflict", "retryable": True, "is_auth_error": False}
            return {"ok": True, "data": [{"Type": 1, "Contents": "Done"}], "error": None, "retryable": False, "is_auth_error": False}
        raise AssertionError("unexpected command in test: {} {}".format(command, args))

    monkeypatch.setattr(tick, "guardian_execute", fake_execute)
    return calls


def test_annotate_intake_sweep_repeat_noop_for_non_sweep_trigger_source(monkeypatch):
    calls = _intake_sweep_execute_stub(monkeypatch, prior_content="Queue is quiet, nothing urgent.")
    for trigger_source in (None, "", "manual", "eval", "simulate"):
        result = tick.guardian_tick_annotate_intake_sweep_repeat("Queue is quiet, nothing urgent.", trigger_source, "run-1")
        assert result == "Queue is quiet, nothing urgent."
    assert calls == []  # never even reads/writes the List for a non-sweep run


def test_annotate_intake_sweep_repeat_first_sweep_has_nothing_to_compare_against(monkeypatch):
    calls = _intake_sweep_execute_stub(monkeypatch, prior_content=None)
    conclusion = "No urgent items in the queue right now."
    result = tick.guardian_tick_annotate_intake_sweep_repeat(conclusion, tick.GUARDIAN_INTAKE_SWEEP_TRIGGER_SOURCE, "run-1")
    assert result == conclusion  # unannotated -- nothing to compare against yet
    create_calls = [c for c in calls if c[0] == "createList"]
    assert len(create_calls) == 1
    saved = json.loads(create_calls[0][1]["listData"])
    assert saved == {"content": conclusion, "run_id": "run-1"}


def test_annotate_intake_sweep_repeat_flags_reworded_near_duplicate(monkeypatch):
    prior = "No urgent incidents found. The queue looks quiet with nothing requiring escalation."
    curr = "The queue looks quiet with nothing requiring escalation. No urgent incidents were found."
    _intake_sweep_execute_stub(monkeypatch, prior_content=prior)

    result = tick.guardian_tick_annotate_intake_sweep_repeat(curr, tick.GUARDIAN_INTAKE_SWEEP_TRIGGER_SOURCE, "run-2")

    assert result.startswith(tick.GUARDIAN_INTAKE_SWEEP_REPEAT_NOTE.format("run-2"))
    assert result.endswith(curr)  # the real conclusion is still present verbatim, never shortened


def test_annotate_intake_sweep_repeat_does_not_flag_genuinely_different_conclusion(monkeypatch):
    prior = "No urgent incidents found. The queue looks quiet."
    curr = "Escalating three critical incidents involving suspected ransomware on the finance segment."
    _intake_sweep_execute_stub(monkeypatch, prior_content=prior)

    result = tick.guardian_tick_annotate_intake_sweep_repeat(curr, tick.GUARDIAN_INTAKE_SWEEP_TRIGGER_SOURCE, "run-3")

    assert result == curr  # no repeat note prepended


def test_annotate_intake_sweep_repeat_always_persists_this_runs_own_conclusion(monkeypatch):
    # Whether or not THIS run was flagged as a repeat, its own conclusion becomes
    # the new "last" row for the NEXT sweep to compare against.
    prior = "No urgent incidents found. The queue looks quiet."
    curr = "No urgent incidents found. The queue looks quiet."  # identical -> will be flagged
    calls = _intake_sweep_execute_stub(monkeypatch, prior_content=prior)

    tick.guardian_tick_annotate_intake_sweep_repeat(curr, tick.GUARDIAN_INTAKE_SWEEP_TRIGGER_SOURCE, "run-4")

    create_calls = [c for c in calls if c[0] == "createList"]
    assert len(create_calls) == 1
    saved = json.loads(create_calls[0][1]["listData"])
    assert saved == {"content": curr, "run_id": "run-4"}  # THIS run's raw conclusion, not the annotated text


def test_annotate_intake_sweep_repeat_write_failure_is_logged_never_raised(monkeypatch):
    _intake_sweep_execute_stub(monkeypatch, prior_content=None, create_ok=False)
    errors = []
    monkeypatch.setattr(tick.demisto, "error", lambda msg: errors.append(msg))

    result = tick.guardian_tick_annotate_intake_sweep_repeat(
        "Some conclusion.", tick.GUARDIAN_INTAKE_SWEEP_TRIGGER_SOURCE, "run-5"
    )  # must not raise

    assert result == "Some conclusion."
    assert any("list write conflict" in e for e in errors)


def test_annotate_intake_sweep_repeat_swallows_unexpected_exception(monkeypatch):
    def fake_execute(command, args, using=None):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(tick, "guardian_execute", fake_execute)
    errors = []
    monkeypatch.setattr(tick.demisto, "error", lambda msg: errors.append(msg))

    result = tick.guardian_tick_annotate_intake_sweep_repeat(
        "Some conclusion.", tick.GUARDIAN_INTAKE_SWEEP_TRIGGER_SOURCE, "run-6"
    )  # must not raise

    assert result == "Some conclusion."
    assert any("kaboom" in e for e in errors)


def test_tick_conclude_wires_intake_sweep_annotation_for_sweep_trigger_source(monkeypatch):
    """End-to-end: a sweep-triggered incident's final conclude path must call
    guardian_tick_annotate_intake_sweep_repeat with THIS run's own conclusion,
    the incident's real guardiantriggersource, and the real run_id -- and the
    War Room narration must reflect whatever it returns."""
    llm_handler = _llm_handler_sequence([_completion(content="Queue triage: nothing urgent this cycle.")])
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": llm_handler,
        },
    )
    monkeypatch.setattr(
        tick.demisto,
        "incident",
        lambda: {"id": "999", "CustomFields": {"guardiantriggersource": "job:intake-sweep"}},
    )
    recorded = {}

    def fake_annotate(conclusion, trigger_source, run_id):
        recorded["conclusion"] = conclusion
        recorded["trigger_source"] = trigger_source
        recorded["run_id"] = run_id
        return "[STUBBED-ANNOTATION]" + conclusion

    monkeypatch.setattr(tick, "guardian_tick_annotate_intake_sweep_repeat", fake_annotate)

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    assert recorded["conclusion"] == "Queue triage: nothing urgent this cycle."
    assert recorded["trigger_source"] == "job:intake-sweep"
    assert recorded["run_id"] == ctx["Guardian"]["Loop"]["run_id"]
    assert "[STUBBED-ANNOTATION]Queue triage: nothing urgent this cycle." in outcome["narration"]


def test_tick_conclude_passes_none_trigger_source_for_an_ordinary_investigation(monkeypatch):
    # _install's default fake incident carries no CustomFields at all -- an
    # ordinary (non-sweep) investigation must read as trigger_source=None,
    # never accidentally match GUARDIAN_INTAKE_SWEEP_TRIGGER_SOURCE.
    llm_handler = _llm_handler_sequence([_completion(content="Verdict: benign, closing out.")])
    _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": llm_handler,
        },
    )
    recorded = {}

    def fake_annotate(conclusion, trigger_source, run_id):
        recorded["trigger_source"] = trigger_source
        return conclusion

    monkeypatch.setattr(tick, "guardian_tick_annotate_intake_sweep_repeat", fake_annotate)

    tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert recorded["trigger_source"] is None


# --- guardian_tick_compact_or_drop (Task 1.8) ------------------------------------


def test_compact_or_drop_falls_back_to_plain_drop_below_threshold(monkeypatch):
    _install(monkeypatch)  # GuardianCompact intentionally NOT wired
    messages = [{"role": "system", "content": "sys"}, _TASK] + _long_transcript(10)
    loop_state = {"compact_cooldown": 0, "dropped_count": 0}
    settings = _full_settings(batch_cap=5, compact_after_dropped=100)
    new_messages, note = tick.guardian_tick_compact_or_drop(messages, settings, loop_state, "run-1", "trig")
    assert note == ""
    assert new_messages[0] == {"role": "system", "content": "sys"} and new_messages[1] == _TASK
    assert new_messages[2]["content"].startswith(tick.GUARDIAN_BREADCRUMB_PREFIX)


def test_compact_or_drop_uses_real_compaction_over_threshold(monkeypatch):
    messages = [{"role": "system", "content": "sys"}, _TASK] + _long_transcript(10)
    handler = _compact_handler(kept_messages=[{"role": "user", "content": "turn-9"}])
    _install(monkeypatch, command_handlers={"GuardianCompact": handler})
    loop_state = {"compact_cooldown": 0, "cost_usd": 0.0, "cost_tokens_total": 0, "dropped_count": 0}
    settings = _full_settings(batch_cap=5, compact_after_dropped=1)
    new_messages, note = tick.guardian_tick_compact_or_drop(messages, settings, loop_state, "run-1", "trig")
    assert len(handler.calls) == 1
    assert new_messages[1] == _TASK and new_messages[2]["guardian_checkpoint"] is True
    assert "compacted" in note


# --- Full-loop integration: Task 1.8 real compaction ----------------------------


def test_full_loop_compacts_via_guardian_compact_with_no_split_pair(monkeypatch):
    # Build a transcript that will cross a tight batch_cap via several
    # tool-calling ticks, then confirm the rebuilt transcript is
    # [system, checkpoint, ...kept] with no orphaned tool reply.
    tool_calls_by_tick = [_tool_call("call_{}".format(i), "ip", {"ip": "8.8.8.{}".format(i)}) for i in range(6)]
    completions = [_completion(tool_calls=[tc]) for tc in tool_calls_by_tick] + [
        _completion(content="Final verdict: benign")
    ]
    llm_handler = _llm_handler_sequence(completions)
    compact_handler = _compact_handler(kept_messages=[{"role": "user", "content": "placeholder-kept"}])

    ctx = _install(
        monkeypatch,
        settings={
            "MAX_TICKS": 25,
            "tick_cadence_seconds": 12,
            "batch_cap": 6,
            "compact_after_dropped": 2,
        },
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": llm_handler,
            "GuardianToolBridge": _tool_bridge_handler(
                default_result={"status": "ok", "ok": True, "result": {"Score": 1}, "error": None}
            ),
            "GuardianCompact": compact_handler,
        },
    )

    outcome = None
    for _ in range(6):
        outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate several IPs"})
        if not outcome["reschedule"]:
            break

    assert len(compact_handler.calls) >= 1
    loop = ctx["Guardian"]["Loop"]
    messages = loop["messages"]
    assert messages[0]["role"] == "system"
    # A real checkpoint appears somewhere in the rebuilt transcript.
    assert any(m.get("guardian_checkpoint") is True for m in messages)
    # No orphaned tool reply: every kept tool message's owning
    # assistant+tool_calls message is present earlier in the SAME list (or
    # it is the synthetic placeholder-kept message GuardianCompact returned).
    seen_call_ids = set()
    for msg in messages:
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            for call in msg["tool_calls"]:
                seen_call_ids.add(call["id"])
        elif msg.get("role") == "tool":
            assert msg.get("tool_call_id") in seen_call_ids


def test_full_loop_compaction_failure_sets_cooldown_not_retried_next_tick(monkeypatch):
    tool_calls_by_tick = [_tool_call("call_{}".format(i), "ip", {"ip": "8.8.8.{}".format(i)}) for i in range(4)]
    completions = [_completion(tool_calls=[tc]) for tc in tool_calls_by_tick]
    llm_handler = _llm_handler_sequence(completions)
    failing_compact = _compact_failure_handler("summarizer overloaded")

    ctx = _install(
        monkeypatch,
        settings={
            "MAX_TICKS": 25,
            "tick_cadence_seconds": 12,
            "batch_cap": 4,
            "compact_after_dropped": 1,
        },
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": llm_handler,
            "GuardianToolBridge": _tool_bridge_handler(
                default_result={"status": "ok", "ok": True, "result": {"Score": 1}, "error": None}
            ),
            "GuardianCompact": failing_compact,
        },
    )

    # tick 0 and tick 1: transcript grows past batch_cap, compaction is
    # attempted and fails both times it's actually tried, but the cooldown
    # set after the FIRST failure must prevent every subsequent tick from
    # paying for another attempt.
    tick.guardian_reasoning_tick_run({"prompt": "Investigate several IPs"})
    tick.guardian_reasoning_tick_run({"prompt": "Investigate several IPs"})
    tick.guardian_reasoning_tick_run({"prompt": "Investigate several IPs"})

    # GuardianCompact was attempted exactly ONCE across all three ticks --
    # the transcript crosses batch_cap on both tick 1 and tick 2, but the
    # cooldown set after tick 1's failure suppresses tick 2's retry.
    assert len(failing_compact.calls) == 1
    loop = ctx["Guardian"]["Loop"]
    assert loop["compact_cooldown"] > 0
    # The loop is still alive (falls back to the free drop path, never
    # crashes) -- transcript still starts with the system message.
    assert loop["messages"][0]["role"] == "system"


def test_full_loop_compaction_cost_is_charged_into_run_total(monkeypatch):
    tool_calls_by_tick = [_tool_call("call_{}".format(i), "ip", {"ip": "8.8.8.{}".format(i)}) for i in range(6)]
    completions = [_completion(tool_calls=[tc]) for tc in tool_calls_by_tick] + [
        _completion(content="Final verdict: benign")
    ]
    llm_handler = _llm_handler_sequence(completions)
    compact_usage = {"prompt_tokens": 2000, "completion_tokens": 500, "total_tokens": 2500}
    compact_handler = _compact_handler(
        kept_messages=[{"role": "user", "content": "placeholder-kept"}], usage=compact_usage
    )

    ctx = _install(
        monkeypatch,
        settings={
            "MAX_TICKS": 25,
            "tick_cadence_seconds": 12,
            "batch_cap": 6,
            "compact_after_dropped": 2,
        },
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "ip"}}]),
            "guardian-llm-chat": llm_handler,
            "GuardianToolBridge": _tool_bridge_handler(
                default_result={"status": "ok", "ok": True, "result": {"Score": 1}, "error": None}
            ),
            "GuardianCompact": compact_handler,
        },
    )

    for _ in range(6):
        outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate several IPs"})
        if not outcome["reschedule"]:
            break

    assert len(compact_handler.calls) >= 1
    loop = ctx["Guardian"]["Loop"]
    # The compaction call's own usage (2500 tokens) must be reflected in the
    # run's cumulative cost_tokens_total, on top of whatever the ordinary
    # model turns already charged.
    ordinary_turns = len(tool_calls_by_tick) + 1
    # Each ordinary turn's default usage (from _completion) is 15 tokens
    # (see _completion's own default usage); the compaction call adds 2500
    # more at least once.
    assert loop["cost_tokens_total"] >= compact_usage["total_tokens"]


# --- Task 2.2: analyst<->agent collaboration (pending_user_input / awaiting_analyst) ---


def test_load_settings_awaiting_ticks_default_and_configured(monkeypatch):
    _install(monkeypatch)
    settings = tick.guardian_tick_load_settings()
    assert settings["max_awaiting_ticks"] == tick.GUARDIAN_DEFAULT_MAX_AWAITING_TICKS

    _install(
        monkeypatch,
        settings={"MAX_TICKS": 25, "tick_cadence_seconds": 12, "batch_cap": 25, "max_awaiting_ticks": 3},
    )
    settings2 = tick.guardian_tick_load_settings()
    assert settings2["max_awaiting_ticks"] == 3


def test_load_settings_max_ask_analyst_per_run_default_and_configured(monkeypatch):
    # harvest candidate #13.
    _install(monkeypatch)
    settings = tick.guardian_tick_load_settings()
    assert settings["max_ask_analyst_per_run"] == tick.GUARDIAN_DEFAULT_MAX_ASK_ANALYST_PER_RUN

    _install(
        monkeypatch,
        settings={"MAX_TICKS": 25, "tick_cadence_seconds": 12, "batch_cap": 25, "max_ask_analyst_per_run": 1},
    )
    settings2 = tick.guardian_tick_load_settings()
    assert settings2["max_ask_analyst_per_run"] == 1


def test_default_loop_state_seeds_task_2_2_fields():
    state = tick.guardian_tick_default_loop_state([{"role": "system", "content": "x"}], "999", None)
    assert state["pending_user_input"] == []
    assert state["awaiting_analyst"] is None
    assert state["awaiting_ticks"] == 0
    assert state["ask_analyst_count"] == 0


def test_drain_pending_user_input_appends_analyst_messages_and_clears_queue(monkeypatch):
    llm_handler = _llm_handler_sequence([_completion(content="Final answer incorporating analyst input.")])
    ctx = _install(monkeypatch, command_handlers={"guardian-llm-chat": llm_handler})
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 2,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "pending_ticks": 0,
            "dropped_count": 0,
            "awaiting_analyst": None,
            "awaiting_ticks": 0,
            "pending_user_input": ["first message", "second message"],
        },
        "ToolCatalog": [],
    }

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert "Analyst input received" in outcome["narration"]
    loop = ctx["Guardian"]["Loop"]
    assert loop["pending_user_input"] == []
    messages = loop["messages"]
    analyst_messages = [m for m in messages if isinstance(m.get("content"), str) and m.get("content").startswith("[Analyst]:")]
    assert [m["content"] for m in analyst_messages] == ["[Analyst]: first message", "[Analyst]: second message"]
    assert all(m["role"] == "user" for m in analyst_messages)
    # The drained messages must precede the model turn that answers them.
    assert messages.index(analyst_messages[-1]) < len(messages) - 1


def test_drain_ignores_blank_or_non_string_queue_entries(monkeypatch):
    llm_handler = _llm_handler_sequence([_completion(content="ok")])
    ctx = _install(monkeypatch, command_handlers={"guardian-llm-chat": llm_handler})
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 0,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "pending_ticks": 0,
            "dropped_count": 0,
            "awaiting_analyst": None,
            "awaiting_ticks": 0,
            "pending_user_input": ["  ", "", "real message", None, 42],
        },
        "ToolCatalog": [],
    }

    tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    loop = ctx["Guardian"]["Loop"]
    analyst_messages = [m for m in loop["messages"] if isinstance(m.get("content"), str) and m.get("content").startswith("[Analyst]:")]
    assert [m["content"] for m in analyst_messages] == ["[Analyst]: real message"]


def test_drain_clears_awaiting_analyst_and_resumes_model_turn_same_tick(monkeypatch):
    llm_handler = _llm_handler_sequence([_completion(content="Contained per analyst approval.")])
    ctx = _install(monkeypatch, command_handlers={"guardian-llm-chat": llm_handler})
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 3,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "pending_ticks": 0,
            "dropped_count": 0,
            "awaiting_analyst": {"question": "Should I contain host-42?", "since_tick": 2},
            "awaiting_ticks": 1,
            "pending_user_input": ["Yes, contain it."],
        },
        "ToolCatalog": [],
    }

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    # The model turn actually ran THIS tick (proves Step 5b did not
    # short-circuit -- the drain cleared awaiting_analyst before Step 5b ran).
    assert len(llm_handler.calls) == 1
    loop = ctx["Guardian"]["Loop"]
    assert loop["awaiting_analyst"] is None
    assert loop["awaiting_ticks"] == 0
    assert loop["status"] == "done"
    assert "Contained per analyst approval." in outcome["narration"]


def test_awaiting_analyst_short_circuits_without_model_turn(monkeypatch):
    ctx = _install(monkeypatch)
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 4,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "pending_ticks": 0,
            "dropped_count": 0,
            "awaiting_analyst": {"question": "Should I contain host-42?", "since_tick": 3},
            "awaiting_ticks": 0,
            "pending_user_input": [],
        },
        "ToolCatalog": [],
    }

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is True
    assert "awaiting an analyst response" in outcome["narration"]
    loop = ctx["Guardian"]["Loop"]
    assert loop["awaiting_ticks"] == 1
    assert loop["awaiting_analyst"] == {"question": "Should I contain host-42?", "since_tick": 3}
    # No guardian-llm-chat/GuardianToolBridge handler was wired at all -- if
    # this function tried to call either, _install's fake_execute would have
    # raised AssertionError, which pytest would report as a failure.


def test_awaiting_analyst_still_terminates_at_max_ticks(monkeypatch):
    # Mirrors test_pending_approval_still_terminates_at_max_ticks: the
    # ceiling (Step 4) must win regardless of an unresolved awaiting_analyst
    # pause, exactly like it wins over `pending` -- checked BEFORE Step 5b.
    llm_handler = _llm_handler_sequence([_completion(content="Forced summary despite awaiting_analyst")])
    ctx = _install(
        monkeypatch,
        settings={"MAX_TICKS": 1, "tick_cadence_seconds": 12, "batch_cap": 25},
        command_handlers={"guardian-llm-chat": llm_handler},
    )
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 0,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "pending_ticks": 0,
            "dropped_count": 0,
            "awaiting_analyst": {"question": "Should I contain host-42?", "since_tick": 0},
            "awaiting_ticks": 0,
            "pending_user_input": [],
        },
        "ToolCatalog": [],
    }

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    assert "reached its tick ceiling" in outcome["narration"]
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "done"
    assert len(llm_handler.calls) == 1
    assert llm_handler.calls[0]["tool_choice"] == "none"


def test_awaiting_analyst_cap_falls_through_to_normal_turn_and_clears(monkeypatch):
    llm_handler = _llm_handler_sequence([_completion(content="Proceeding without analyst input.")])
    ctx = _install(
        monkeypatch,
        settings={"MAX_TICKS": 25, "tick_cadence_seconds": 12, "batch_cap": 25, "max_awaiting_ticks": 2},
        command_handlers={"guardian-llm-chat": llm_handler},
    )
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 5,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "pending_ticks": 0,
            "dropped_count": 0,
            "awaiting_analyst": {"question": "Contain host-42?", "since_tick": 4},
            "awaiting_ticks": 0,
            "pending_user_input": [],
        },
        "ToolCatalog": [],
    }

    # Tick A: below the cap -- still waiting, no model turn.
    outcome_a = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert outcome_a["reschedule"] is True
    assert len(llm_handler.calls) == 0
    assert ctx["Guardian"]["Loop"]["awaiting_ticks"] == 1
    assert ctx["Guardian"]["Loop"]["awaiting_analyst"] is not None

    # Tick B: cap exhausted -- gives up waiting, notes it, and proceeds with
    # an ORDINARY model turn (never a hard "stopped" exit).
    outcome_b = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert "No analyst response" in outcome_b["narration"]
    assert len(llm_handler.calls) == 1
    loop = ctx["Guardian"]["Loop"]
    assert loop["awaiting_analyst"] is None
    assert loop["awaiting_ticks"] == 0
    assert loop["status"] == "done"
    system_notes = [m for m in loop["messages"] if isinstance(m.get("content"), str) and m.get("content").startswith("[System]: No analyst response")]
    assert len(system_notes) == 1
    assert "Contain host-42?" in system_notes[0]["content"]


def test_ask_analyst_tool_call_sets_awaiting_analyst(monkeypatch):
    ask_tool_call = _tool_call("call_ask_1", "GuardianAskAnalyst", {"question": "Should I contain host-42?"})
    llm_handler = _llm_handler_sequence([_completion(tool_calls=[ask_tool_call])])
    ctx = _install(
        monkeypatch,
        command_handlers={
            "guardian-llm-chat": llm_handler,
            "GuardianToolBridge": _tool_bridge_handler(
                result_by_tool_name={
                    "GuardianAskAnalyst": {
                        "status": "ok",
                        "ok": True,
                        "result": {
                            "status": "awaiting_analyst",
                            "question": "Should I contain host-42?",
                            "posted_to_war_room": True,
                        },
                        "error": None,
                    }
                }
            ),
        },
    )
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 1,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "pending_ticks": 0,
            "dropped_count": 0,
            "awaiting_analyst": None,
            "awaiting_ticks": 0,
            "pending_user_input": [],
        },
        "ToolCatalog": [],
    }

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is True  # ordinary Step-8 reschedule, unaffected
    loop = ctx["Guardian"]["Loop"]
    assert loop["awaiting_analyst"] == {"question": "Should I contain host-42?", "since_tick": 1}
    assert loop["ask_analyst_count"] == 1  # harvest candidate #13


def test_ask_analyst_tool_call_failure_does_not_set_awaiting_analyst(monkeypatch):
    ask_tool_call = _tool_call("call_ask_1", "GuardianAskAnalyst", {"question": "Should I contain host-42?"})
    llm_handler = _llm_handler_sequence([_completion(tool_calls=[ask_tool_call])])
    ctx = _install(
        monkeypatch,
        command_handlers={
            "guardian-llm-chat": llm_handler,
            "GuardianToolBridge": _tool_bridge_handler(
                result_by_tool_name={
                    "GuardianAskAnalyst": {
                        "status": "denied",
                        "ok": False,
                        "result": None,
                        "error": "not on allowlist",
                    }
                }
            ),
        },
    )
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 1,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "pending_ticks": 0,
            "dropped_count": 0,
            "awaiting_analyst": None,
            "awaiting_ticks": 0,
            "pending_user_input": [],
        },
        "ToolCatalog": [],
    }

    tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert ctx["Guardian"]["Loop"]["awaiting_analyst"] is None


def test_ask_analyst_cap_exhausted_blocks_pause_and_continues_the_turn(monkeypatch):
    # harvest candidate #13: once this run has already spent its per-run
    # interruption budget (default 3), a further successful GuardianAskAnalyst
    # dispatch must NOT set awaiting_analyst -- the tick proceeds as an
    # ordinary turn instead of pausing to wait on a reply.
    ask_tool_call = _tool_call("call_ask_4", "GuardianAskAnalyst", {"question": "One more thing?"})
    llm_handler = _llm_handler_sequence([_completion(tool_calls=[ask_tool_call])])
    ctx = _install(
        monkeypatch,
        command_handlers={
            "guardian-llm-chat": llm_handler,
            "GuardianToolBridge": _tool_bridge_handler(
                result_by_tool_name={
                    "GuardianAskAnalyst": {
                        "status": "ok",
                        "ok": True,
                        "result": {
                            "status": "awaiting_analyst",
                            "question": "One more thing?",
                            "posted_to_war_room": True,
                        },
                        "error": None,
                    }
                }
            ),
        },
    )
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 5,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "pending_ticks": 0,
            "dropped_count": 0,
            "awaiting_analyst": None,
            "awaiting_ticks": 0,
            "pending_user_input": [],
            "ask_analyst_count": tick.GUARDIAN_DEFAULT_MAX_ASK_ANALYST_PER_RUN,  # budget already spent
        },
        "ToolCatalog": [],
    }

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is True  # an ordinary turn, not an awaiting-analyst park
    loop = ctx["Guardian"]["Loop"]
    assert loop["awaiting_analyst"] is None
    # Not incremented further past the cap.
    assert loop["ask_analyst_count"] == tick.GUARDIAN_DEFAULT_MAX_ASK_ANALYST_PER_RUN


def test_ask_analyst_per_run_cap_is_settings_readable(monkeypatch):
    # A tighter max_ask_analyst_per_run=1 (from guardian_settings) must block
    # the SECOND pause this run, even though the default of 3 would allow it.
    ask_tool_call = _tool_call("call_ask_5", "GuardianAskAnalyst", {"question": "Contain host-77?"})
    llm_handler = _llm_handler_sequence([_completion(tool_calls=[ask_tool_call])])
    ctx = _install(
        monkeypatch,
        settings={"MAX_TICKS": 25, "tick_cadence_seconds": 12, "batch_cap": 25, "max_ask_analyst_per_run": 1},
        command_handlers={
            "guardian-llm-chat": llm_handler,
            "GuardianToolBridge": _tool_bridge_handler(
                result_by_tool_name={
                    "GuardianAskAnalyst": {
                        "status": "ok",
                        "ok": True,
                        "result": {
                            "status": "awaiting_analyst",
                            "question": "Contain host-77?",
                            "posted_to_war_room": True,
                        },
                        "error": None,
                    }
                }
            ),
        },
    )
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 2,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "pending_ticks": 0,
            "dropped_count": 0,
            "awaiting_analyst": None,
            "awaiting_ticks": 0,
            "pending_user_input": [],
            "ask_analyst_count": 1,  # already asked once this run -- at the configured cap of 1
        },
        "ToolCatalog": [],
    }

    tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    loop = ctx["Guardian"]["Loop"]
    assert loop["awaiting_analyst"] is None
    assert loop["ask_analyst_count"] == 1


def test_tick0_carries_forward_prior_pending_user_input(monkeypatch):
    # An analyst can !guardian-chat BEFORE GuardianAgentLoop ever starts --
    # GuardianChatCommand queues it into a minimal skeleton with no
    # "messages"/"status" key. Tick 0 must not silently discard that queue
    # when it builds the fresh default loop state.
    llm_handler = _llm_handler_sequence([_completion(content="Acknowledged, investigating.")])
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": llm_handler,
        },
    )
    ctx["Guardian"] = {"Loop": {"pending_user_input": ["queued before the loop even started"]}}

    tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    loop = ctx["Guardian"]["Loop"]
    assert loop["pending_user_input"] == []
    analyst_messages = [m for m in loop["messages"] if isinstance(m.get("content"), str) and m.get("content").startswith("[Analyst]:")]
    assert analyst_messages == [{"role": "user", "content": "[Analyst]: queued before the loop even started"}]


def test_full_round_trip_ask_pause_chat_reply_changes_conclusion(monkeypatch):
    """End-to-end (within this test file) proof of the O4 acceptance shape:
    the model asks the analyst, the loop pauses, a queued reply resumes it,
    and the reply's CONTENT changes what the model concludes -- the same
    mechanism the live server round-trip (task report) exercises for real.
    """
    ask_tool_call = _tool_call("call_ask_1", "GuardianAskAnalyst", {"question": "Should I contain host-42?"})

    def branch_sensitive_llm_handler(args):
        msgs = args.get("messages") or []
        has_analyst_reply = any(
            isinstance(m, dict) and m.get("role") == "user" and "[Analyst]:" in (m.get("content") or "")
            for m in msgs
        )
        if not has_analyst_reply:
            return [{"Type": 1, "Contents": _completion(tool_calls=[ask_tool_call])}]
        return [{"Type": 1, "Contents": _completion(content="Contained host-42 per analyst approval.")}]

    ctx = _install(
        monkeypatch,
        command_handlers={
            "guardian-llm-chat": branch_sensitive_llm_handler,
            "GuardianToolBridge": _tool_bridge_handler(
                result_by_tool_name={
                    "GuardianAskAnalyst": {
                        "status": "ok",
                        "ok": True,
                        "result": {
                            "status": "awaiting_analyst",
                            "question": "Should I contain host-42?",
                            "posted_to_war_room": True,
                        },
                        "error": None,
                    }
                }
            ),
        },
    )
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate host-42"}],
            "tick": 0,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "pending_ticks": 0,
            "dropped_count": 0,
            "awaiting_analyst": None,
            "awaiting_ticks": 0,
            "pending_user_input": [],
        },
        "ToolCatalog": [],
    }

    # Tick 1: the model asks the analyst -- the loop pauses.
    outcome_1 = tick.guardian_reasoning_tick_run({"prompt": "Investigate host-42"})
    assert outcome_1["reschedule"] is True
    loop = ctx["Guardian"]["Loop"]
    assert loop["awaiting_analyst"] == {"question": "Should I contain host-42?", "since_tick": 0}
    assert loop["status"] == "running"

    # GuardianChatCommand's own effect, simulated directly here (that
    # script's OWN behavior is covered by GuardianChatCommand_test.py) --
    # the analyst's reply lands in the SAME queue GuardianChatCommand
    # writes to.
    loop["pending_user_input"] = ["Yes, contain it -- the segment is already isolated."]

    # Tick 2: the reply is drained, the pause clears, the model resumes --
    # and its conclusion is DIFFERENT because of what the analyst said.
    outcome_2 = tick.guardian_reasoning_tick_run({"prompt": "Investigate host-42"})
    assert outcome_2["reschedule"] is False
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "done"
    assert loop["awaiting_analyst"] is None
    assert "Contained host-42 per analyst approval." in outcome_2["narration"]
    analyst_messages = [m for m in loop["messages"] if isinstance(m.get("content"), str) and m.get("content").startswith("[Analyst]:")]
    assert analyst_messages == [
        {"role": "user", "content": "[Analyst]: Yes, contain it -- the segment is already isolated."}
    ]


# --- Review fix (2.2): chat-write race -- a late !guardian-chat write must survive
# this tick's own end-of-tick whole-`Guardian.Loop` persist, not be clobbered by it. ---


def test_late_analyst_chat_write_is_merged_not_dropped_at_final_persist(monkeypatch):
    """The core regression test for the fix: simulate `GuardianChatCommand`'s
    own concurrent read-modify-write landing WHILE this tick is mid-execution
    (its LLM call). By the time this tick does its final fresh re-read (via
    the `getContext` command, immediately before persisting), the SERVER's
    `Guardian.Loop.pending_user_input` already holds the pre-tick queue PLUS
    the analyst's new message appended after it -- exactly what
    `GuardianChatCommand` would have produced by reading the SAME pre-tick
    queue this tick started with and appending its own message. The already
    -drained item must NOT reappear (no duplication/re-drain); the late item
    MUST be preserved, undrained, for the model's next turn.
    """
    late_queue_seen_by_fresh_read = [
        "already queued before this tick",
        "late analyst message landed mid-tick",
    ]

    def fake_get_context(args):
        return [
            {
                "Type": 1,
                "Contents": {
                    "cacheVersn": 0,
                    "context": {"Guardian": {"Loop": {"pending_user_input": late_queue_seen_by_fresh_read}}},
                },
            }
        ]

    ctx = _install(
        monkeypatch,
        command_handlers={
            "guardian-llm-chat": _llm_handler_sequence([_completion(content="All clear, concluding.")]),
            "getContext": fake_get_context,
        },
    )
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 3,
            "run_id": "run-late-chat",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "pending_ticks": 0,
            "dropped_count": 0,
            "awaiting_analyst": None,
            "awaiting_ticks": 0,
            # THIS tick's own tick-top snapshot -- one item, already part of
            # what the fresh getContext read above also carries as its first
            # element (the concurrent writer read this SAME 1-item queue
            # before appending its own message).
            "pending_user_input": ["already queued before this tick"],
        },
        "ToolCatalog": [],
    }

    outcome = tick.guardian_reasoning_tick_run({})

    assert outcome["reschedule"] is False
    persisted = outcome["loop_state"]
    # The late item survived this tick's own end-of-tick persist instead of
    # being clobbered back to whatever the tick's in-memory state held.
    assert persisted["pending_user_input"] == ["late analyst message landed mid-tick"]
    # The already-drained item is not re-added/duplicated.
    assert persisted["pending_user_input"].count("already queued before this tick") == 0
    # Step 3.5's own drain ran normally this tick (unaffected by the fix) --
    # the tick-top item made it into the transcript.
    analyst_messages = [
        m
        for m in persisted["messages"]
        if isinstance(m.get("content"), str) and m.get("content").startswith("[Analyst]:")
    ]
    assert analyst_messages == [{"role": "user", "content": "[Analyst]: already queued before this tick"}]
    # Persisted straight to Context too (not just the returned outcome dict).
    assert ctx["Guardian"]["Loop"]["pending_user_input"] == ["late analyst message landed mid-tick"]
    # Termination is unaffected by the fix: this tick still concluded.
    assert persisted["status"] == "done"


def test_no_concurrent_chat_write_leaves_pending_user_input_untouched(monkeypatch):
    """Sanity companion to the regression test above: when the fresh
    `getContext` re-read shows NO late arrivals (the common case -- no
    concurrent chat write happened), the merge must be a true no-op --
    `pending_user_input` stays `[]` post-drain, never reintroducing anything.
    """
    ctx = _install(
        monkeypatch,
        command_handlers={
            "guardian-llm-chat": _llm_handler_sequence([_completion(content="All clear, concluding.")]),
            # No custom "getContext" handler -- exercises the DEFAULT stub
            # (_default_get_context_handler), which mirrors the live `ctx`
            # dict exactly as the tick itself sees it.
        },
    )
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 3,
            "run_id": "run-no-race",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "pending_ticks": 0,
            "dropped_count": 0,
            "awaiting_analyst": None,
            "awaiting_ticks": 0,
            "pending_user_input": [],
        },
        "ToolCatalog": [],
    }

    outcome = tick.guardian_reasoning_tick_run({})

    assert outcome["loop_state"]["pending_user_input"] == []
    assert ctx["Guardian"]["Loop"]["pending_user_input"] == []


def test_merge_late_pending_input_skips_cleanly_when_fresh_read_fails(monkeypatch):
    """`guardian_tick_merge_late_pending_input` must never block the tick's
    own persist -- a failing/unwired `getContext` call is logged and
    swallowed, leaving `loop_state` unchanged, not raised.
    """

    def broken_get_context(args):
        return [{"Type": 4, "Contents": "getContext boom"}]

    _install(monkeypatch, command_handlers={"getContext": broken_get_context})
    loop_state = {"pending_user_input": ["untouched"]}

    result = tick.guardian_tick_merge_late_pending_input(loop_state, 0, "999")

    assert result is loop_state
    assert result["pending_user_input"] == ["untouched"]


def test_merge_late_pending_input_appends_only_items_beyond_tick_top_count(monkeypatch):
    """Unit-level proof of the merge rule itself, independent of a full tick
    run: given a fresh queue longer than what this tick started with, only
    the items BEYOND `tick_top_pending_count` are appended -- already
    -accounted-for items are never re-added.
    """
    loop_state = {"pending_user_input": []}
    fresh_queue = ["first (already drained)", "second (already drained)", "third (late arrival)"]

    def fake_read_fresh(incident_id):
        return tick.guardian_envelope(True, data={"Guardian": {"Loop": {"pending_user_input": fresh_queue}}})

    monkeypatch.setattr(tick, "guardian_tick_read_context_fresh", fake_read_fresh)

    result = tick.guardian_tick_merge_late_pending_input(loop_state, 2, "999")

    assert result["pending_user_input"] == ["third (late arrival)"]


# --- Task 3.1: the real approval gate (ledger read/resolve + Loop.pending) ---


def test_extract_pending_recognizes_bridge_pending_approval():
    tool_result = {
        "status": "pending_approval",
        "ok": False,
        "result": {"approval_id": "abc", "risk_tier": "soft", "tool_name": "setIncident", "tool_args": {"id": "1"}},
        "error": "approval required",
    }
    payload = tick.guardian_tick_extract_pending(tool_result)
    assert payload == tool_result["result"]


def test_extract_pending_recognizes_nested_plan_pending_approval():
    tool_result = {
        "status": "ok",
        "ok": True,
        "result": {
            "status": "pending_approval",
            "kind": "plan",
            "approval_id": "plan-1",
            "risk_tier": "destructive",
            "steps": [{"tool_name": "setIncident", "tool_args": {}}],
        },
        "error": None,
    }
    payload = tick.guardian_tick_extract_pending(tool_result)
    assert payload["kind"] == "plan"
    assert payload["approval_id"] == "plan-1"


def test_extract_pending_returns_none_for_ordinary_ok_result():
    tool_result = {"status": "ok", "ok": True, "result": {"score": 1}, "error": None}
    assert tick.guardian_tick_extract_pending(tool_result) is None


def test_extract_pending_returns_none_for_denied_result():
    tool_result = {"status": "denied", "ok": False, "result": None, "error": "nope"}
    assert tick.guardian_tick_extract_pending(tool_result) is None


def test_extract_pending_returns_none_for_malformed_input():
    assert tick.guardian_tick_extract_pending(None) is None
    assert tick.guardian_tick_extract_pending("not a dict") is None
    assert tick.guardian_tick_extract_pending({"status": "ok", "result": "not a dict"}) is None


def test_build_denial_note_wording_differs_for_tool_and_plan():
    tool_note = tick.guardian_tick_build_denial_note(
        {"kind": "tool", "tool_name": "setIncident", "approval_id": "abc", "resolved_by": "alice", "reason": "not needed"}
    )
    plan_note = tick.guardian_tick_build_denial_note(
        {"kind": "plan", "approval_id": "plan-1", "resolved_by": "bob", "reason": "too risky"}
    )
    assert "DENIED" in tool_note and "setIncident" in tool_note and "alice" in tool_note and "not needed" in tool_note
    assert "DENIED" in plan_note and "plan-1" in plan_note and "bob" in plan_note and "too risky" in plan_note
    assert "None of its steps were executed" in plan_note


def test_step8_sets_pending_on_require_approval_park(monkeypatch):
    """The core Task 3.1 wiring: a bridge require_approval park (top-level
    `status:"pending_approval"`) must set `Loop.pending` -- previously
    (Phase 1 groundwork) nothing ever did this."""
    set_incident_call = _tool_call("call_1", "setIncident", {"id": "1", "severity": 4})
    llm_handler = _llm_handler_sequence([_completion(tool_calls=[set_incident_call])])

    def bridge_handler(args):
        assert args.get("approval_id") is None  # this is the FRESH ask, no token yet
        result = {
            "tool_call_id": args.get("tool_call_id"),
            "tool_name": "setIncident",
            "status": "pending_approval",
            "ok": False,
            "result": {
                "status": "pending_approval",
                "approval_id": "approval-xyz",
                "risk_tier": "soft",
                "tool_name": "setIncident",
                "tool_args": {"id": "1", "severity": 4},
            },
            "error": "approval required",
        }
        return [{"Type": 1, "Contents": {"tool_result": result, "audit": {}}}]

    ctx = _install(monkeypatch, command_handlers={"guardian-llm-chat": llm_handler, "GuardianToolBridge": bridge_handler})
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 1,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "pending_ticks": 0,
            "dropped_count": 0,
        },
        "ToolCatalog": [],
    }

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is True
    loop = ctx["Guardian"]["Loop"]
    assert loop["pending"] == {"approval_id": "approval-xyz", "kind": "tool", "risk_tier": "soft", "since_tick": 1}


def test_step8_sets_pending_kind_plan_on_nested_pending_approval(monkeypatch):
    plan_call = _tool_call("call_1", "GuardianPlanApprove", {"steps": "[]", "summary": "close it out"})
    llm_handler = _llm_handler_sequence([_completion(tool_calls=[plan_call])])

    def bridge_handler(args):
        result = {
            "tool_call_id": args.get("tool_call_id"),
            "tool_name": "GuardianPlanApprove",
            "status": "ok",
            "ok": True,
            "result": {
                "status": "pending_approval",
                "kind": "plan",
                "approval_id": "plan-77",
                "risk_tier": "destructive",
                "step_count": 2,
            },
            "error": None,
        }
        return [{"Type": 1, "Contents": {"tool_result": result, "audit": {}}}]

    ctx = _install(monkeypatch, command_handlers={"guardian-llm-chat": llm_handler, "GuardianToolBridge": bridge_handler})
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 2,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": None,
            "pending_ticks": 0,
            "dropped_count": 0,
        },
        "ToolCatalog": [],
    }

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is True
    loop = ctx["Guardian"]["Loop"]
    assert loop["pending"] == {"approval_id": "plan-77", "kind": "plan", "risk_tier": "destructive", "since_tick": 2}


def test_pending_still_pending_reschedules_without_model_turn_or_bridge_call(monkeypatch):
    ledger = [{"approval_id": "approval-1", "kind": "tool", "tool_name": "setIncident", "status": "pending"}]
    ctx = _install(monkeypatch, approvals_ledger=ledger)
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 3,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": {"approval_id": "approval-1", "kind": "tool"},
            "pending_ticks": 2,
            "dropped_count": 0,
        },
        "ToolCatalog": [],
    }
    # No guardian-llm-chat/GuardianToolBridge handler wired -- if this tick
    # tried either, _install's fake_execute raises AssertionError.

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is True
    assert "still pending human approval" in outcome["narration"]
    loop = ctx["Guardian"]["Loop"]
    assert loop["pending"] == {"approval_id": "approval-1", "kind": "tool"}
    assert loop["pending_ticks"] == 3
    assert loop["status"] == "running"


def test_pending_missing_ledger_row_treated_as_still_pending(monkeypatch):
    """A ledger row that vanished/was never found is NOT treated as a green
    light to execute -- it's treated exactly like "still pending", bounded
    by the same cap."""
    ctx = _install(monkeypatch, approvals_ledger=[])  # no row at all
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 3,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": {"approval_id": "ghost-id", "kind": "tool"},
            "pending_ticks": 0,
            "dropped_count": 0,
        },
        "ToolCatalog": [],
    }

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is True
    assert ctx["Guardian"]["Loop"]["pending_ticks"] == 1


def test_pending_approved_tool_reexecutes_and_falls_through_to_same_tick_turn(monkeypatch):
    """The full approve -> re-dispatch -> execute -> resume flow, single
    tool: the ledger row is `approved`, this tick re-dispatches through
    GuardianToolBridge WITH the token, the result is fed back as a
    `[System]` note, `Loop.pending` clears, and a REAL model turn happens in
    THIS SAME tick (no extra idle tick)."""
    ledger = [
        {
            "approval_id": "approval-1",
            "kind": "tool",
            "tool_name": "setIncident",
            "tool_args": {"id": "1", "severity": 4},
            "status": "approved",
            "resolved_by": "alice",
        }
    ]
    llm_handler = _llm_handler_sequence([_completion(content="Proceeding now that the field was updated.")])

    def bridge_handler(args):
        assert args.get("approval_id") == "approval-1"
        assert args.get("tool_name") == "setIncident"
        assert args.get("tool_args") == {"id": "1", "severity": 4}
        result = {
            "tool_call_id": None,
            "tool_name": "setIncident",
            "status": "ok",
            "ok": True,
            "result": {"id": "1"},
            "error": None,
        }
        return [{"Type": 1, "Contents": {"tool_result": result, "audit": {}}}]

    ctx = _install(
        monkeypatch,
        approvals_ledger=ledger,
        command_handlers={"guardian-llm-chat": llm_handler, "GuardianToolBridge": bridge_handler},
    )
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 4,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": {"approval_id": "approval-1", "kind": "tool"},
            "pending_ticks": 3,
            "dropped_count": 0,
        },
        "ToolCatalog": [],
    }

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert len(llm_handler.calls) == 1  # the model turn ran THIS tick
    loop = ctx["Guardian"]["Loop"]
    assert loop["pending"] is None
    assert loop["pending_ticks"] == 0  # reset on resolution -- a future approval starts counting fresh
    assert loop["status"] == "done"
    system_notes = [
        m for m in loop["messages"] if isinstance(m.get("content"), str) and "was APPROVED by alice" in m["content"]
    ]
    assert len(system_notes) == 1
    assert "EXECUTED" in system_notes[0]["content"]
    assert "Proceeding now that the field was updated." in outcome["narration"]


def test_pending_denied_feeds_denial_and_falls_through_to_same_tick_turn(monkeypatch):
    ledger = [
        {
            "approval_id": "approval-2",
            "kind": "tool",
            "tool_name": "closeInvestigation",
            "tool_args": {"id": "1"},
            "status": "denied",
            "resolved_by": "bob",
            "reason": "still investigating",
        }
    ]
    llm_handler = _llm_handler_sequence([_completion(content="Understood, will not close yet.")])
    ctx = _install(monkeypatch, approvals_ledger=ledger, command_handlers={"guardian-llm-chat": llm_handler})
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 4,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": {"approval_id": "approval-2", "kind": "tool"},
            "pending_ticks": 1,
            "dropped_count": 0,
        },
        "ToolCatalog": [],
    }
    # No GuardianToolBridge handler wired -- a denial must NEVER dispatch.

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert len(llm_handler.calls) == 1
    loop = ctx["Guardian"]["Loop"]
    assert loop["pending"] is None
    assert loop["status"] == "done"
    denial_notes = [
        m for m in loop["messages"] if isinstance(m.get("content"), str) and "was DENIED by bob" in m["content"]
    ]
    assert len(denial_notes) == 1
    assert "still investigating" in denial_notes[0]["content"]


def test_pending_approved_plan_executes_every_step_and_falls_through(monkeypatch):
    ledger = [
        {
            "approval_id": "plan-9",
            "kind": "plan",
            "status": "approved",
            "resolved_by": "carol",
            "steps": [
                {"tool_name": "setIncident", "tool_args": {"id": "1"}, "consumed": False},
                {"tool_name": "closeInvestigation", "tool_args": {"id": "1"}, "consumed": False},
            ],
        }
    ]
    dispatched = []

    def bridge_handler(args):
        dispatched.append((args.get("tool_name"), args.get("plan_approval_id"), args.get("plan_step_index")))
        result = {
            "tool_call_id": None,
            "tool_name": args.get("tool_name"),
            "status": "ok",
            "ok": True,
            "result": {"done": True},
            "error": None,
        }
        return [{"Type": 1, "Contents": {"tool_result": result, "audit": {}}}]

    llm_handler = _llm_handler_sequence([_completion(content="Plan executed, concluding.")])
    ctx = _install(
        monkeypatch,
        approvals_ledger=ledger,
        command_handlers={"guardian-llm-chat": llm_handler, "GuardianToolBridge": bridge_handler},
    )
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "investigate"}],
            "tick": 5,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "pending": {"approval_id": "plan-9", "kind": "plan"},
            "pending_ticks": 0,
            "dropped_count": 0,
        },
        "ToolCatalog": [],
    }

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert dispatched == [("setIncident", "plan-9", 0), ("closeInvestigation", "plan-9", 1)]
    loop = ctx["Guardian"]["Loop"]
    assert loop["pending"] is None
    assert loop["status"] == "done"
    plan_notes = [
        m for m in loop["messages"] if isinstance(m.get("content"), str) and "plan approval_id=plan-9" in m["content"]
    ]
    assert len(plan_notes) == 1
    assert "executed 2 step(s)" in plan_notes[0]["content"]
    assert "step 0 (setIncident): ok" in plan_notes[0]["content"]
    assert "step 1 (closeInvestigation): ok" in plan_notes[0]["content"]


# --- guardian_tick_parse_verdict_block / guardian_tick_write_verdict_telemetry


def test_shipped_prompt_tail_instructs_the_default_production_path_to_end_with_a_verdict_block():
    """guardian_tick_parse_verdict_block requires the concluding message to end
    with a fenced ```json block -- before this fix, that instruction existed
    ONLY in playbook-GuardianEvalInvestigate.yml's own static prompt, never in
    guardian_prompt_tail (the prompt every default, non-eval production Agent
    Run actually gets). A production run on defaults therefore never told the
    model the required output shape, so guardianverdict/confidence/techniques
    silently never persisted -- no matter how thorough the investigation was.
    Pin that the shipped prompt tail now carries this instruction, so a future
    prompt edit can't silently drop it again."""
    rendered = _shipped_list_text("guardian_prompt_tail")
    assert "```json" in rendered
    assert "verdict" in rendered
    assert "Malicious|Suspicious|Benign|Inconclusive" in rendered
    assert "confidence" in rendered
    assert "techniques" in rendered
    assert "summary" in rendered


def test_shipped_investigation_skill_does_not_instruct_a_0_to_1_confidence_scale():
    """guardian_tick_parse_verdict_block does `int(float(confidence))` clamped
    to [0,100] -- a genuine 0..1 fraction (e.g. 0.8) truncates to exactly 0
    when persisted. list-guardian_skill_xsoar_case_investigation.json used to
    tell the model `guardianconfidence` was "0..1 confidence in that verdict",
    directly contradicting the parser and reproducing this truncation-to-0
    live symptom on every production Agent Run that followed the skill's own
    guidance. Pin that the shipped skill no longer says this."""
    rendered = _shipped_list_text("guardian_skill_xsoar_case_investigation")
    assert "0..1 confidence" not in rendered
    assert "0-100 confidence" in rendered


def test_shipped_investigation_skill_carries_the_investigation_discipline_guardrails():
    """The "Investigation discipline" guardrails (restate incident id, don't
    re-enrich RFC1918, don't repeat work, converge quickly, verify a
    correlation before stating it) used to exist only in
    list-guardian_skill_xsoar_case_triage.json -- absent from the skill
    actually bound to single-incident investigations and the eval playbook
    (INV-51/INV-80). Pin that the section is now ported into the
    investigation skill too, not just the triage one."""
    rendered = _shipped_list_text("guardian_skill_xsoar_case_investigation")
    assert "Investigation discipline" in rendered
    assert "RFC1918" in rendered
    assert "Do not repeat work" in rendered
    assert "Converge quickly" in rendered
    assert "Verify a claimed correlation" in rendered


def test_parse_verdict_block_valid_last_wins(monkeypatch):
    text = (
        'some reasoning\n```json\n{"verdict":"Suspicious","confidence":40,"techniques":["T1566"],'
        '"summary":"Early evidence did not yet confirm a malicious outcome."}\n```\nmore\n```json\n{"verdict":"Malicious","confidence":95,'
        '"techniques":["T1566","T1078.001"],"summary":"Credential-phishing evidence confirms compromise; escalate to the incident owner."}\n```'
    )
    out = tick.guardian_tick_parse_verdict_block(text)
    assert out["verdict"] == "Malicious"  # last block wins
    assert out["confidence"] == 95
    assert out["techniques"] == ["T1078", "T1566"]  # sorted, parent-collapsed
    assert out["summary"] == "Credential-phishing evidence confirms compromise; escalate to the incident owner."


def test_parse_verdict_block_rejects_bad_verdict_and_clamps(monkeypatch):
    out = tick.guardian_tick_parse_verdict_block(
        '```json\n{"verdict":"High","confidence":250,"techniques":["nope","T9999999"],"summary":"x"}\n```'
    )
    assert out is None  # "High" not in enum -> whole block dropped


def test_parse_verdict_block_clamps_confidence_and_filters_techniques():
    out = tick.guardian_tick_parse_verdict_block(
        '```json\n{"verdict":"Benign","confidence":250,"techniques":["t1059.001","bogus",""],"summary":"Signed administrative script explains the observed command activity; no escalation needed."}\n```'
    )
    assert out["verdict"] == "Benign"
    assert out["confidence"] == 100  # clamped to [0,100]
    assert out["techniques"] == ["T1059"]  # uppercased, parent-collapsed, junk dropped


def test_parse_verdict_block_absent_or_malformed_returns_none():
    assert tick.guardian_tick_parse_verdict_block("no json here") is None
    assert tick.guardian_tick_parse_verdict_block("```json\n{not valid}\n```") is None


def test_parse_verdict_block_rejects_blank_short_and_vague_justifications():
    for summary in ("", "x", "unknown", "Insufficient evidence"):
        text = (
            '```json\n{"verdict":"Inconclusive","confidence":30,"techniques":[],"summary":%s}\n```'
            % json.dumps(summary)
        )
        assert tick.guardian_tick_parse_verdict_block(text) is None


def test_write_verdict_telemetry_only_allowlisted_fields(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        tick,
        "guardian_set_incident_fields",
        lambda iid, fields: captured.update(iid=iid, fields=fields) or {"ok": True},
    )
    monkeypatch.setattr(tick, "guardian_execute", lambda *a, **k: {"ok": True, "data": []})
    # An injected extra key must NOT reach the write.
    text = (
        '```json\n{"verdict":"Malicious","confidence":90,"techniques":["T1566"],'
        '"summary":"Malicious phishing indicator was confirmed by the reputation lookup; escalate for containment.","owner":"attacker","CustomFields":{"x":1}}\n```'
    )
    wrote = tick.guardian_tick_write_verdict_telemetry(text, "42")
    assert wrote is True
    assert set(captured["fields"]) == {
        "guardianverdict",
        "guardianconfidence",
        "guardianattacktechniques",
        "guardianblastradius",
    }
    assert captured["fields"]["guardianverdict"] == "Malicious"


def test_write_verdict_telemetry_no_block_writes_nothing(monkeypatch):
    called = []
    monkeypatch.setattr(tick, "guardian_set_incident_fields", lambda *a, **k: called.append(a))
    assert tick.guardian_tick_write_verdict_telemetry("no verdict", "42") is False
    assert called == []


def test_tick_conclusion_writes_verdict_telemetry(monkeypatch):
    monkeypatch.setattr(tick, "guardian_tick_conclusion_gaps", lambda *a, **k: ([], False))  # gate has its own tests
    verdict_text = (
        "Investigation complete.\n```json\n"
        '{"verdict":"Malicious","confidence":85,"techniques":["T1566.001"],"summary":"Phishing message and malicious URL were confirmed; escalate the affected mailbox for containment."}\n'
        "```"
    )
    captured = {}
    monkeypatch.setattr(
        tick,
        "guardian_set_incident_fields",
        lambda iid, fields: captured.update(iid=iid, fields=fields) or {"ok": True, "data": {}},
    )
    _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler("SYSTEM PROMPT TEXT"),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": _llm_handler_sequence([_completion(content=verdict_text)]),
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    assert captured.get("iid") == "999"
    assert captured.get("fields") == {
        "guardianverdict": "Malicious",
        "guardianconfidence": 85,
        "guardianattacktechniques": ["T1566"],
        "guardianblastradius": "Phishing message and malicious URL were confirmed; escalate the affected mailbox for containment.",
    }


def test_step9_no_tool_calls_no_verdict_forces_one_corrective_retry(monkeypatch):
    # Live-testing finding: the model sometimes trails off mid-sentence with
    # no tool_calls and no verdict block (narrating a next action it never
    # actually calls). That must NOT be accepted as a silent, empty
    # conclusion -- it should force exactly one corrective nudge first.
    trailed_off = "The IP address `10.0.113.23` is a bogon. \n\n#### Enriching IP Address: 172.16.83.189"
    llm_handler = _llm_handler_sequence([_completion(content=trailed_off)])
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": llm_handler,
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is True
    assert "forcing corrective retry" in outcome["narration"]
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "running"
    assert loop["no_verdict_fails"] == 1
    assert loop["messages"][-1]["role"] == "user"
    assert "no tool call and no final" in loop["messages"][-1]["content"]


def test_step9_complete_sentence_without_verdict_block_also_forces_retry(monkeypatch):
    # Live-caught regression (2026-08-22, command-r 32B / medium tier): a
    # GRAMMATICALLY COMPLETE, properly-punctuated conclusion with no verdict
    # block must ALSO force the corrective retry -- not just text that looks
    # cut off. The old punctuation-based heuristic was blind to exactly this:
    # "I am unable to provide a verdict without further information." ends
    # in a period, so a "does this look trailed-off" check would wrongly
    # treat it as a legitimate terminal answer and silently drop
    # guardianverdict/confidence/etc. forever. Length alone is what must
    # gate this now, not sentence completeness.
    complete_but_verdictless = (
        "I am unable to access the incident details as the `getEntries` command returned an error. "
        "I have also checked the reputation of the IP addresses provided and found that they are not "
        "internet-routable. I am unable to provide a verdict without further information."
    )
    llm_handler = _llm_handler_sequence([_completion(content=complete_but_verdictless)])
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": llm_handler,
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is True
    assert "forcing corrective retry" in outcome["narration"]
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "running"
    assert loop["no_verdict_fails"] == 1


def test_step9_no_verdict_retry_exhausted_falls_through_to_done(monkeypatch):
    # A second consecutive no-tool-calls/no-verdict turn, with the retry
    # budget already spent, must fall through to today's unchanged terminal
    # behavior rather than nudging forever.
    trailed_off = (
        "The IP address `10.0.113.23` is a bogon, meaning it is a private IP address and not "
        "routable on the public Internet. Let's consider another potential"
    )
    llm_handler = _llm_handler_sequence([_completion(content=trailed_off)])
    ctx = _install(
        monkeypatch,
        command_handlers={"guardian-llm-chat": llm_handler},
    )
    ctx["Guardian"] = {
        "Loop": {
            "messages": [{"role": "system", "content": "x"}, {"role": "user", "content": "y"}],
            "tick": 5,
            "run_id": "999",
            "status": "running",
            "consec_fails": 0,
            "empty_turns": 0,
            "no_verdict_fails": tick.GUARDIAN_NO_VERDICT_RETRY_LIMIT,
            "pending": None,
            "pending_ticks": 0,
            "dropped_count": 0,
        },
        "ToolCatalog": [],
    }

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "done"
    assert loop["no_verdict_fails"] == tick.GUARDIAN_NO_VERDICT_RETRY_LIMIT  # not incremented again


def test_step9_playground_no_incident_id_skips_retry_gate(monkeypatch):
    # No current incident (Playground) -- guardian_tick_write_verdict_telemetry
    # can structurally never write there, so the retry gate must not force a
    # nudge the run could never satisfy; today's terminal behavior applies
    # immediately.
    trailed_off = (
        "The IP address `10.0.113.23` is a bogon, meaning it is a private IP address and not "
        "routable on the public Internet. Let's consider another potential"
    )
    llm_handler = _llm_handler_sequence([_completion(content=trailed_off)])
    ctx = _install(
        monkeypatch,
        incident_id=None,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": llm_handler,
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "done"
    assert loop.get("no_verdict_fails", 0) == 0


def test_step9_valid_verdict_block_still_terminates_immediately(monkeypatch):
    monkeypatch.setattr(tick, "guardian_tick_conclusion_gaps", lambda *a, **k: ([], False))  # gate has its own tests
    # Regression guard: a real conclusion (valid terminal verdict block) must
    # NOT get an unnecessary extra corrective-retry tick.
    verdict_text = (
        "Investigation complete.\n```json\n"
        '{"verdict":"Benign","confidence":90,"techniques":[],"summary":"No malicious activity found."}\n'
        "```"
    )
    monkeypatch.setattr(
        tick, "guardian_set_incident_fields", lambda iid, fields: {"ok": True, "data": {}}
    )
    llm_handler = _llm_handler_sequence([_completion(content=verdict_text)])
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": llm_handler,
        },
    )
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "done"
    assert loop.get("no_verdict_fails", 0) == 0
    assert len(llm_handler.calls) == 1


# --- verdict recovery (2026-09-24, command-r 35B eval: 2 of 20 correct verdicts were lost) ----


_VALID_SUMMARY = "Beaconing to a confirmed Cobalt Strike C2 address from WKS-FIN-0087; isolate the host."


def test_parse_verdict_block_accepts_a_plain_fence():
    """Live shape: an unfenced audit-style JSON echo, then the verdict inside plain ``` fences."""
    text = (
        'Guardian Case Note -- action=`GuardianCaseNote` status=`error` target=`{"content": "..."}`, '
        '"actor": "agent", "ts": "2026-09-24T03:34:13.761Z"}\n```\n\n'
        '{"verdict": "Malicious", "confidence": 100, "techniques": ["T1071", "T1059"], "summary": "%s"}\n```' % _VALID_SUMMARY
    )
    out = tick.guardian_tick_parse_verdict_block(text)
    assert out["verdict"] == "Malicious" and out["confidence"] == 100
    assert out["techniques"] == ["T1059", "T1071"]


def test_parse_verdict_block_skips_a_trailing_non_verdict_block():
    text = (
        '```json\n{"verdict":"Malicious","confidence":80,"techniques":[],"summary":"%s"}\n```\n'
        'Example lookup args:\n```json\n{"ip": "185.220.101.47"}\n```' % _VALID_SUMMARY
    )
    assert tick.guardian_tick_parse_verdict_block(text)["verdict"] == "Malicious"


def test_parse_verdict_block_never_falls_back_to_an_earlier_draft():
    """If the LAST verdict-bearing block is invalid, an earlier draft must not stand in for it."""
    text = (
        '```json\n{"verdict":"Benign","confidence":60,"techniques":[],"summary":"%s"}\n```\n'
        'On reflection:\n```json\n{"verdict":"Probably bad","confidence":90,"techniques":[],"summary":"%s"}\n```'
        % (_VALID_SUMMARY, _VALID_SUMMARY)
    )
    assert tick.guardian_tick_parse_verdict_block(text) is None


def test_parse_verdict_block_accepts_a_trailing_unfenced_verdict_object():
    text = 'Final assessment follows. {"verdict": "Suspicious", "confidence": 55, "techniques": ["T1021"], "summary": "%s"}' % _VALID_SUMMARY
    assert tick.guardian_tick_parse_verdict_block(text)["verdict"] == "Suspicious"


def _prose_conclusion():
    return ("The attacker used PsExec with a compromised local admin account to create the PSEXESVC service on "
            "six hosts. This is confirmed lateral movement and the activity is malicious; T1021 and T1569 apply.")


def _run_step9_with_retry_spent(monkeypatch, llm_completions, incident_id="999"):
    writes, audits = [], []
    monkeypatch.setattr(tick, "guardian_set_incident_fields", lambda iid, fields: writes.append((iid, fields)) or {"ok": True, "data": {}})
    llm = _llm_handler_sequence(llm_completions)
    ctx = _install(
        monkeypatch,
        incident_id=incident_id,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": llm,
            "GuardianAuditWrite": lambda args: audits.append(args) or [{"Type": 1, "Contents": "ok"}],
        },
    )
    ctx["Guardian"] = {"Loop": {
        "messages": [{"role": "system", "content": "x"}, {"role": "user", "content": "y"}], "tick": 3, "run_id": "999",
        "status": "running", "consec_fails": 0, "empty_turns": 0, "no_verdict_fails": tick.GUARDIAN_NO_VERDICT_RETRY_LIMIT,
        "pending": None, "pending_ticks": 0, "dropped_count": 0}, "ToolCatalog": []}
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate the case"})
    verdict_writes = [f for _iid, f in writes if "guardianverdict" in f]
    return outcome, llm, verdict_writes, audits


def test_prose_conclusion_gets_its_verdict_extracted_with_structured_output(monkeypatch):
    extracted = json.dumps({"verdict": "Malicious", "confidence": 90, "techniques": ["T1021", "T1569"], "summary": _VALID_SUMMARY})
    outcome, llm, verdict_writes, audits = _run_step9_with_retry_spent(
        monkeypatch, [_completion(content=_prose_conclusion()), _completion(content=extracted)])

    assert outcome["reschedule"] is False
    extraction_call = llm.calls[1]
    assert extraction_call["response_format"] == {"type": "json_object"}
    assert "tools" not in extraction_call  # a no-tools call: extraction can never act
    assert extraction_call["messages"][1]["content"] == _prose_conclusion()  # the conclusion only, not the transcript
    assert verdict_writes == [{"guardianverdict": "Malicious", "guardianconfidence": 90,
                               "guardianattacktechniques": ["T1021", "T1569"], "guardianblastradius": _VALID_SUMMARY}]
    verdict_audit = [a for a in audits if a.get("action") == "verdict_write"]
    assert json.loads(verdict_audit[0]["detail"])["source"] == "extracted"
    assert "recorded verdict **Malicious** (90) extracted from the conclusion" in outcome["narration"]


def test_extraction_retries_without_response_format_when_the_provider_rejects_it(monkeypatch):
    extracted = json.dumps({"verdict": "Malicious", "confidence": 70, "techniques": [], "summary": _VALID_SUMMARY})
    calls = []

    def llm(args):
        calls.append(args)
        if len(calls) == 1:
            return [{"Type": 1, "Contents": _completion(content=_prose_conclusion())}]
        if "response_format" in args:
            return [{"Type": 4, "Contents": "400 Bad Request: response_format is not supported"}]
        return [{"Type": 1, "Contents": _completion(content=extracted)}]

    writes = []
    monkeypatch.setattr(tick, "guardian_set_incident_fields", lambda iid, fields: writes.append(fields) or {"ok": True, "data": {}})
    ctx = _install(monkeypatch, command_handlers={
        "GuardianPromptBuilder": _prompt_builder_handler(), "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
        "guardian-llm-chat": llm})
    ctx["Guardian"] = {"Loop": {
        "messages": [{"role": "system", "content": "x"}, {"role": "user", "content": "y"}], "tick": 3, "run_id": "999",
        "status": "running", "consec_fails": 0, "empty_turns": 0, "no_verdict_fails": tick.GUARDIAN_NO_VERDICT_RETRY_LIMIT,
        "pending": None, "pending_ticks": 0, "dropped_count": 0}, "ToolCatalog": []}
    tick.guardian_reasoning_tick_run({"prompt": "Investigate the case"})

    assert [("response_format" in c) for c in calls[1:]] == [True, False]
    assert [f["guardianverdict"] for f in writes if "guardianverdict" in f] == ["Malicious"]


def test_reset_run_dispatch_counts_forgets_only_this_run(monkeypatch):
    written = []
    monkeypatch.setattr(tick, "guardian_tick_load_run_dispatch_counts", lambda: {"11": {"getIncidents": 3}, "12": {"x": 1}})
    monkeypatch.setattr(tick, "guardian_execute", lambda command, args: written.append((command, args)) or {"ok": True, "data": [], "error": None})

    tick.guardian_tick_reset_run_dispatch_counts("11")

    assert written and written[0][0] == "createList"
    assert json.loads(written[0][1]["listData"]) == {"12": {"x": 1}}
    written.clear()
    tick.guardian_tick_reset_run_dispatch_counts("99")  # nothing to forget -> no write
    assert written == []


def test_clear_stale_verdict_wipes_a_previous_runs_fields_only_when_present(monkeypatch):
    writes = []
    monkeypatch.setattr(tick, "guardian_set_incident_fields", lambda iid, fields: writes.append((iid, fields)) or {"ok": True})
    monkeypatch.setattr(
        tick.demisto, "incident",
        lambda: {"CustomFields": {"guardianverdict": "Suspicious", "guardianconfidence": 65}},
    )

    assert tick.guardian_tick_clear_stale_verdict("11") is True
    assert writes == [("11", {"guardianverdict": "", "guardianconfidence": 0, "guardianattacktechniques": [], "guardianblastradius": "", "guardiangateaction": ""})]

    writes.clear()
    monkeypatch.setattr(tick.demisto, "incident", lambda: {"CustomFields": {"guardianverdict": "", "guardianconfidence": 0}})
    assert tick.guardian_tick_clear_stale_verdict("11") is False  # nothing to clear -> no write
    assert writes == []


def test_incident_scope_message_allows_a_narrow_similar_incident_search(monkeypatch):
    monkeypatch.setattr(tick.demisto, "incident", lambda: {"id": "7", "name": "beacon", "type": "t", "severity": 1, "CustomFields": {}})
    content = tick.guardian_tick_incident_context_message()["content"]
    assert "similar earlier incidents" in content
    assert "to switch to another incident" in content


def test_a_scoped_run_may_not_read_another_incident():
    own = "12225"
    # listing the queue, another id, or no id at all for getIncidents: refused
    for args in ({"status": "1"}, {"id": "12230"}, {"id": ["12225", "12230"]}, {}, ""):
        assert "SCOPE" in tick.guardian_tick_scope_violation("getIncidents", args, own)
    assert "SCOPE" in tick.guardian_tick_scope_violation("getEntries", {"id": "12230"}, own)
    # its own id (any spelling), the unresolved placeholder, and getEntries with no id: allowed
    for args in ({"id": "12225"}, {"id": 12225}, '{"id": "12225"}', {"id": "${incident.id}"}):
        assert tick.guardian_tick_scope_violation("getIncidents", args, own) is None
    assert tick.guardian_tick_scope_violation("getEntries", {}, own) is None
    # other tools and unscoped runs are untouched
    assert tick.guardian_tick_scope_violation("SearchIncidentsV2", {"query": "x"}, own) is None
    assert tick.guardian_tick_scope_violation("getIncidents", {"status": "1"}, None) is None


def test_dispatch_refuses_a_scope_violation_without_calling_the_bridge(monkeypatch):
    called = []
    monkeypatch.setattr(tick, "guardian_execute", lambda command, args: called.append(command) or {"ok": True, "data": [], "error": None})
    call = {"id": "c1", "type": "function", "function": {"name": "getIncidents", "arguments": json.dumps({"status": "1"})}}
    result = tick.guardian_tick_dispatch_tool_call(call, 0, "12225", scope_incident="12225")
    assert result["ok"] is False and "SCOPE" in result["error"] and called == []


def test_verdict_write_failure_is_not_audited_as_ok(monkeypatch):
    """The field write returns an envelope instead of raising; a failed write must show up as an
    `error` audit row, not as `verdict_write ok` with empty summary fields. The return value says the verdict
    was produced (callers use it to decide on a corrective retry), not that the fields were saved."""
    audits = []
    monkeypatch.setattr(tick, "guardian_set_incident_fields", lambda iid, fields: {"ok": False, "error": "REST unavailable"})
    monkeypatch.setattr(tick, "guardian_execute", lambda command, args: audits.append(args) or {"ok": True, "data": [], "error": None})
    parsed = {"verdict": "Suspicious", "confidence": 70, "techniques": ["T1071"], "summary": "beacon"}

    assert tick.guardian_tick_write_parsed_verdict(parsed, "42") is True  # a valid verdict was produced and audited
    verdict_audits = [a for a in audits if a.get("action") == "verdict_write"]
    assert [a["status"] for a in verdict_audits] == ["error"]
    detail = json.loads(verdict_audits[0]["detail"])
    assert detail["verdict"] == "Suspicious" and detail["confidence"] == 70 and detail["techniques"] == ["T1071"]
    assert "REST unavailable" in detail["reason"]


def test_extraction_that_finds_no_valid_verdict_writes_nothing(monkeypatch):
    outcome, llm, verdict_writes, _ = _run_step9_with_retry_spent(
        monkeypatch, [_completion(content=_prose_conclusion()), _completion(content='{"verdict": "Unclear"}')])
    assert outcome["reschedule"] is False
    assert verdict_writes == []


def test_a_valid_verdict_block_never_triggers_extraction(monkeypatch):
    monkeypatch.setattr(tick, "guardian_tick_conclusion_gaps", lambda *a, **k: ([], False))  # gate has its own tests
    text = 'Done.\n```json\n{"verdict":"Malicious","confidence":85,"techniques":[],"summary":"%s"}\n```' % _VALID_SUMMARY
    _outcome, llm, verdict_writes, audits = _run_step9_with_retry_spent(monkeypatch, [_completion(content=text)])
    assert len(llm.calls) == 1
    assert [w["guardianverdict"] for w in verdict_writes] == ["Malicious"]
    assert "source" not in json.loads([a for a in audits if a.get("action") == "verdict_write"][0]["detail"])



def _echoed_audit_conclusion():
    """Live shape (#46448): a regurgitated audit record instead of a conclusion -- no reasoning."""
    record = json.dumps({"ts": "2026-09-24T04:04:20.459Z", "actor": "agent", "action": "ip",
                         "target": '{"ip": "185.220.101.47"}', "status": "ok",
                         "detail": {"policy_decision": "allow", "risk_tier": "soft", "would_require_approval": False}}, indent=2)
    entry = '**Guardian Case Note** -- action=`ip` status=`ok` target=`{"ip": "185.220.101.47"}` actor=`agent`\n```json\n' + record + '\n```\n\n'
    return entry * 3


def test_no_extraction_from_an_answer_with_no_written_conclusion(monkeypatch):
    """The regurgitated-record 'conclusion' that extraction once turned into Benign/100 on a
    confirmed C2 case: no extraction call may be made, and nothing may be written."""
    outcome, llm, verdict_writes, _ = _run_step9_with_retry_spent(
        monkeypatch, [_completion(content=_echoed_audit_conclusion()),
                      _completion(content=json.dumps({"verdict": "Benign", "confidence": 100, "techniques": [], "summary": _VALID_SUMMARY}))])
    assert len(llm.calls) == 1  # the final turn only -- no extraction call
    assert verdict_writes == []
    assert "no written conclusion" in outcome["narration"]


def test_an_extracted_verdict_the_conclusion_never_states_is_discarded(monkeypatch):
    """The prose says malicious; an extraction that answers Benign is not grounded and is dropped."""
    outcome, llm, verdict_writes, _ = _run_step9_with_retry_spent(
        monkeypatch, [_completion(content=_prose_conclusion()),
                      _completion(content=json.dumps({"verdict": "Benign", "confidence": 95, "techniques": [], "summary": _VALID_SUMMARY}))])
    assert len(llm.calls) == 2
    assert verdict_writes == []
    assert "not stated in the conclusion" in outcome["narration"]


def test_conclusion_prose_strips_echoed_records():
    assert tick.guardian_tick_conclusion_prose(_echoed_audit_conclusion()) == ""
    mixed = "Verdict reasoning: the host beaconed to known C2, so this is malicious.\n```json\n{\"a\": 1}\n```"
    assert tick.guardian_tick_conclusion_prose(mixed) == "Verdict reasoning: the host beaconed to known C2, so this is malicious."


# --- Guardian's own audit entries never reach the model (root cause of the echoed answers) ------


_AUDIT_ENTRY = '**Guardian Audit** -- action=`ip` status=`ok` target=`{"ip": "185.220.101.47"}` actor=`agent`\n```json\n{"action": "ip"}\n```'
_ANALYST_NOTE = "Analyst note: the host owner confirmed they did not run this binary."


def test_get_entries_tool_message_drops_guardians_own_audit_entries():
    tool_result = {"tool_name": "getEntries", "tool_call_id": "c1", "status": "ok",
                   "result": [_AUDIT_ENTRY, _ANALYST_NOTE, {"Contents": _AUDIT_ENTRY}, {"Contents": "Incident created"}]}
    msg = tick.guardian_tick_tool_message(tool_result, 16384)
    body = json.loads(msg["content"])
    assert body["result"] == [_ANALYST_NOTE, {"Contents": "Incident created"}]
    assert body["omitted_own_audit_entries"].startswith("2 of Guardian's own audit entries were omitted")
    assert "Guardian Audit" not in msg["content"]
    assert tool_result["result"][0] == _AUDIT_ENTRY  # the caller's dict is not mutated


def test_other_tools_and_clean_get_entries_results_pass_through_unchanged():
    ip_result = {"tool_name": "ip", "tool_call_id": "c2", "status": "ok", "result": _AUDIT_ENTRY}
    assert json.loads(tick.guardian_tick_tool_message(ip_result, 16384)["content"]) == ip_result
    clean = {"tool_name": "getEntries", "tool_call_id": "c3", "status": "ok", "result": [_ANALYST_NOTE]}
    assert json.loads(tick.guardian_tick_tool_message(clean, 16384)["content"]) == clean


def test_single_entry_get_entries_result_that_is_an_audit_row_is_dropped():
    one = {"tool_name": "getEntries", "tool_call_id": "c4", "status": "ok", "result": _AUDIT_ENTRY}
    body = json.loads(tick.guardian_tick_tool_message(one, 16384)["content"])
    assert body["result"] is None and "1 of Guardian's own audit entries" in body["omitted_own_audit_entries"]


# --- playbook-built prompt and tool list (use_prebuilt) ------------------------------------------
# The playbook's earlier tasks build the system prompt and tool list into context; the model session
# prefers them when started with use_prebuilt=true, and otherwise builds them itself exactly as before.

_CONCLUSION = _completion(content="No further action is needed; this is routine activity.")
_PREBUILT_TOOLS = [{"type": "function", "function": {"name": "ip", "description": "IP reputation", "parameters": {"type": "object", "properties": {}}}}]


def _run_tick0(monkeypatch, args, ctx_guardian=None, handlers=None):
    """Run tick 0 with a conclusion-only model, returning (outcome, ctx, llm, tier_check_calls)."""
    tier_calls = []
    monkeypatch.setattr(tick, "guardian_tick_check_model_tier_consistency", lambda t, *a, **k: tier_calls.append(t) or None)
    llm = _llm_handler_sequence([_CONCLUSION])
    command_handlers = {"guardian-llm-chat": llm}
    command_handlers.update(handlers or {})
    ctx = _install(monkeypatch, command_handlers=command_handlers)
    if ctx_guardian:
        ctx["Guardian"] = ctx_guardian
    outcome = tick.guardian_reasoning_tick_run(args)
    return outcome, ctx, llm, tier_calls


def test_prebuilt_prompt_and_tools_from_context_are_used_without_calling_the_builders(monkeypatch):
    outcome, ctx, llm, tier_calls = _run_tick0(
        monkeypatch,
        {"prompt": "Investigate the host", "use_prebuilt": "true"},
        ctx_guardian={"SystemPrompt": "PLAYBOOK-BUILT PROMPT", "ToolCatalog": _PREBUILT_TOOLS},
    )  # no GuardianPromptBuilder / GuardianToolCatalogBuilder handlers: calling either would raise
    assert llm.calls[0]["messages"][0] == {"role": "system", "content": "PLAYBOOK-BUILT PROMPT"}
    assert [t["function"]["name"] for t in llm.calls[0]["tools"]] == ["ip"]
    assert "System prompt: built by the playbook's 'Build system prompt' task (21 chars)." in outcome["narration"]
    assert "Tool list: built by the playbook's 'Build tool list' task (1 tools)." in outcome["narration"]
    assert tier_calls == []  # the playbook's tier-check task already did this comparison


def test_missing_prebuilt_prompt_falls_back_to_building_it_and_says_so(monkeypatch):
    builder = _prompt_builder_handler("TICK-BUILT PROMPT")
    outcome, ctx, llm, _ = _run_tick0(
        monkeypatch,
        {"prompt": "Investigate the host", "use_prebuilt": "true"},
        ctx_guardian={"ToolCatalog": _PREBUILT_TOOLS},
        handlers={"GuardianPromptBuilder": builder},
    )
    assert llm.calls[0]["messages"][0]["content"] == "TICK-BUILT PROMPT"
    assert "System prompt: built by this tick (the playbook's prompt was missing from context)." in outcome["narration"]
    assert "Tool list: built by the playbook's 'Build tool list' task" in outcome["narration"]


def test_malformed_prebuilt_tool_list_falls_back_to_building_it(monkeypatch):
    for bad in ("not a list", [], ["not a dict"], None):
        counting = _catalog_builder_handler_counting([{"type": "function", "function": {"name": "getIncidents"}}])
        outcome, ctx, llm, _ = _run_tick0(
            monkeypatch,
            {"prompt": "Investigate the host", "use_prebuilt": "true"},
            ctx_guardian={"SystemPrompt": "P", "ToolCatalog": bad},
            handlers={"GuardianToolCatalogBuilder": counting},
        )
        assert len(counting.calls) == 1, bad
        assert [t["function"]["name"] for t in llm.calls[0]["tools"]] == ["getIncidents"], bad
        assert "Tool list: built by this tick (the playbook's list was missing from context)." in outcome["narration"]


def test_without_the_flag_stale_context_is_ignored_and_the_tick_builds_everything(monkeypatch):
    """A previous run's prompt/tool list may still sit in context; only a playbook that just built
    fresh ones (and says so with the flag) may have them used."""
    for flag in ({}, {"use_prebuilt": "false"}, {"use_prebuilt": ""}, {"use_prebuilt": "no-idea"}):
        outcome, ctx, llm, tier_calls = _run_tick0(
            monkeypatch,
            dict({"prompt": "Investigate the host"}, **flag),
            ctx_guardian={"SystemPrompt": "STALE PROMPT", "ToolCatalog": _PREBUILT_TOOLS},
            handlers={"GuardianPromptBuilder": _prompt_builder_handler("FRESH PROMPT"),
                      "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "getIncidents"}}])},
        )
        assert llm.calls[0]["messages"][0]["content"] == "FRESH PROMPT", flag
        assert [t["function"]["name"] for t in llm.calls[0]["tools"]] == ["getIncidents"], flag
        assert "System prompt: built by this tick." in outcome["narration"], flag
        assert len(tier_calls) == 1, flag  # the standalone path still runs its own tier comparison


def test_prebuilt_flag_only_matters_on_tick_zero(monkeypatch):
    """The self-reschedule passes the same args to every later tick; once the loop exists the flag
    must change nothing (the prompt already lives in the loop state)."""
    ctx = _install(monkeypatch, command_handlers={"guardian-llm-chat": _llm_handler_sequence([_CONCLUSION])})
    ctx["Guardian"] = {
        "Loop": {"messages": [{"role": "system", "content": "EXISTING"}, {"role": "user", "content": "q"}], "tick": 2,
                 "run_id": "999", "status": "running", "consec_fails": 0, "empty_turns": 0, "pending": None,
                 "pending_ticks": 0, "dropped_count": 0},
        "ToolCatalog": _PREBUILT_TOOLS,
        "SystemPrompt": "SOMETHING ELSE",
    }
    outcome = tick.guardian_reasoning_tick_run({"prompt": "ignored after tick 0", "use_prebuilt": "true"})
    assert ctx["Guardian"]["Loop"]["messages"][0]["content"] == "EXISTING"
    assert "System prompt:" not in outcome["narration"]


# --- the playbook shape: everything before the model session is its own task -----------------------


def test_playbooks_prepare_in_separate_tasks_and_keep_one_model_session_task():
    import pathlib

    import yaml

    playbooks = pathlib.Path(__file__).resolve().parents[2] / "Playbooks"
    graphs = []
    for name in ("GuardianAgentLoop", "GuardianEvalInvestigate"):
        pb = yaml.safe_load((playbooks / "playbook-{}.yml".format(name)).read_text())
        tasks = pb["tasks"]
        scripts = {tid: t["task"].get("script") for tid, t in tasks.items() if t.get("type") == "regular"}
        order, cur = [], pb["starttaskid"]
        while True:  # walk the default path from start to the end
            nxt = tasks[cur].get("nexttasks") or {}
            nxt_ids = nxt.get("#none#") or nxt.get("#default#") or []
            if not nxt_ids:
                break
            cur = nxt_ids[0]
            order.append(tasks[cur]["task"].get("script") or tasks[cur]["task"]["name"])
        assert order == ["GuardianKillSwitchCheck", "Kill switch on?", "GuardianJobGuardCheck", "Job disabled?",
                         "GuardianModelProfileCheck", "GuardianPromptBuilder", "GuardianToolCatalogBuilder",
                         "Preload skill?", "GuardianReasoningTick", "Done"], (name, order)
        # the optional skill load: taken only when the skill input is set, never blocks the run, rejoins the session
        skill_cond = tasks["10"]
        assert skill_cond["nexttasks"] == {"#default#": ["8"], "skill": ["11"]}
        op = skill_cond["conditions"][0]["condition"][0][0]
        assert op["operator"] == "isEqualString" and op["left"]["value"]["simple"] == "inputs.preload_skill"
        assert op["right"]["value"]["simple"] == "true"
        assert next(i for i in pb["inputs"] if i["key"] == "preload_skill")["value"]["simple"] == "false"  # off by default
        load = tasks["11"]
        assert load["task"]["script"] == "GuardianSkillRead" and load["continueonerror"] is True
        assert load["scriptarguments"]["name"] == {"simple": "${inputs.skill}"}
        assert load["nexttasks"] == {"#none#": ["8"]}
        # exactly ONE task talks to the model: the whole session is one task
        assert list(scripts.values()).count("GuardianReasoningTick") == 1
        session = next(t for t in tasks.values() if t["task"].get("script") == "GuardianReasoningTick")
        assert session["scriptarguments"]["use_prebuilt"] == {"simple": "true"}
        assert session["scriptarguments"]["prompt"] == {"simple": "${inputs.prompt}"}
        # the kill-switch and job-guard branches halt only on an explicit "false"; a missing value (a
        # failed preflight task) takes the default path and the run continues (fail-open, like the loop)
        for cond_id in ("2", "4"):
            cond = tasks[cond_id]
            assert set(cond["nexttasks"]) == {"#default#", "halted"}
            op = cond["conditions"][0]["condition"][0][0]
            assert op["operator"] == "isEqualString" and op["right"]["value"]["simple"] == "false"
            assert tasks[cond["nexttasks"]["halted"][0]]["type"] == "title"
        # the three checks never stop the run on their own failure
        for tid, script in scripts.items():
            if script in ("GuardianKillSwitchCheck", "GuardianJobGuardCheck", "GuardianModelProfileCheck"):
                assert tasks[tid].get("continueonerror") is True, script
        graphs.append(tasks)
    assert graphs[0] == graphs[1]  # the two playbooks differ only in their prompt inputs


def test_stray_reentry_message_says_how_to_run_again_and_starts_nothing(monkeypatch):
    llm = _llm_handler_sequence([_CONCLUSION])
    ctx = _install(monkeypatch, command_handlers={"guardian-llm-chat": llm})
    ctx["Guardian"] = {"Loop": {"messages": [{"role": "system", "content": "x"}], "tick": 0, "run_id": "999",
                                "status": "error", "consec_fails": 0, "empty_turns": 2, "pending": None,
                                "pending_ticks": 0, "dropped_count": 0}}
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate", "use_prebuilt": "true"})
    assert outcome["reschedule"] is False
    assert "loop already error -- ignoring stray re-entry (tick 0)." in outcome["narration"]
    assert "!DeleteContext key=Guardian" in outcome["narration"] and "start a new incident" in outcome["narration"]
    assert llm.calls == []  # nothing was started, and the saved loop was not cleared for the operator
    assert ctx["Guardian"]["Loop"]["status"] == "error"


# --- the playbook's 'Load skill' task: the `skill` input does something now ---------------------------


_SKILL_BODY = "Triage rule: escalate when two independent sources agree. " * 40  # ~2.4K chars -> ~600 tokens


def _skill_ctx(name="xsoar_case_triage", body=_SKILL_BODY):
    return {"SystemPrompt": "BASE PROMPT", "ToolCatalog": _PREBUILT_TOOLS, "SkillName": name, "SkillBody": body}


def test_requested_skill_in_context_is_added_to_the_system_prompt_and_narrated(monkeypatch):
    outcome, ctx, llm, _ = _run_tick0(
        monkeypatch, {"prompt": "Investigate", "skill": "xsoar_case_triage", "use_prebuilt": "true"}, ctx_guardian=_skill_ctx())
    system = llm.calls[0]["messages"][0]["content"]
    assert system.startswith("BASE PROMPT") and "## ACTIVE SKILL: xsoar_case_triage" in system and _SKILL_BODY.strip() in system
    assert "Skill: 'xsoar_case_triage'" in outcome["narration"] and "added to the system prompt" in outcome["narration"]


def test_a_skill_over_the_budget_share_is_not_added_and_the_model_is_told_how_to_get_it(monkeypatch):
    big = "word " * 20000  # ~25K tokens
    outcome, ctx, llm, _ = _run_tick0(
        monkeypatch, {"prompt": "Investigate", "skill": "xsoar_case_investigation", "use_prebuilt": "true"},
        ctx_guardian=_skill_ctx("xsoar_case_investigation", big))
    assert llm.calls[0]["messages"][0]["content"] == "BASE PROMPT"
    assert "over this model's preload limit" in outcome["narration"] and "GuardianSkillRead" in outcome["narration"]


def test_the_skill_limit_scales_with_the_input_budget(monkeypatch):
    """15% of the input budget; a fixed default when no budget is set. A ~2.4K-token skill fits a 28K
    budget (limit 4.2K) but not a 12K one (limit 1.8K)."""
    body = "Triage rule: escalate when two independent sources agree. " * 160  # ~9.6K chars -> ~2.4K tokens
    monkeypatch.setattr(tick, "guardian_ctx_read", lambda key, default=None: {"SkillBody": body, "SkillName": "s"}.get(key, default))
    section, line = tick.guardian_tick_prebuilt_skill_text("s", 28102)
    assert section and "added to the system prompt" in line
    section, line = tick.guardian_tick_prebuilt_skill_text("s", 12000)
    assert section is None and "preload limit (~1800 tokens, 15%" in line
    assert tick.guardian_tick_prebuilt_skill_text("s", None)[0]  # no budget set: the 4,000-token default applies


def test_a_different_or_stale_skill_in_context_is_never_used(monkeypatch):
    # context holds a skill from an earlier run, but this run asked for another one (or none)
    for asked in ("xsoar_platform_reference", "", None):
        args = {"prompt": "Investigate", "use_prebuilt": "true"}
        if asked is not None:
            args["skill"] = asked
        outcome, ctx, llm, _ = _run_tick0(monkeypatch, args, ctx_guardian=_skill_ctx("xsoar_case_triage"))
        assert llm.calls[0]["messages"][0]["content"] == "BASE PROMPT", asked
        assert "ACTIVE SKILL" not in llm.calls[0]["messages"][0]["content"], asked


def test_without_the_playbook_flag_the_skill_argument_stays_a_label(monkeypatch):
    outcome, ctx, llm, _ = _run_tick0(
        monkeypatch, {"prompt": "Investigate", "skill": "xsoar_case_triage"}, ctx_guardian=_skill_ctx(),
        handlers={"GuardianPromptBuilder": _prompt_builder_handler("FRESH"),
                  "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "getIncidents"}}])})
    assert llm.calls[0]["messages"][0]["content"] == "FRESH"


def test_identical_failing_calls_end_in_a_recorded_verdict_not_a_bare_error(monkeypatch):
    """Live: a run that had already gathered evidence died on a repeated failing call with no verdict. Now the next
    turn is a no-tools conclusion, and its verdict block is written."""
    tc = _tool_call("call_1", "denied_cmd", {"x": 1})
    verdict = ('The enrichment call was denied, but the case details already show the scanner is approved.\n```json\n'
               '{"verdict":"Benign","confidence":70,"techniques":[],"summary":"Approved scanner traffic per the case details; no escalation needed."}\n```')
    llm = _llm_handler_sequence([_completion(tool_calls=[tc]), _completion(tool_calls=[tc]), _completion(content=verdict)])
    written = []
    monkeypatch.setattr(tick, "guardian_set_incident_fields", lambda iid, fields: written.append(fields) or {"ok": True, "data": {}})
    ctx = _install(monkeypatch, command_handlers={
        "GuardianPromptBuilder": _prompt_builder_handler(),
        "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "denied_cmd"}}]),
        "guardian-llm-chat": llm,
        "GuardianToolBridge": _tool_bridge_handler(default_result={"status": "denied", "ok": False, "result": None, "error": "denied by policy"}),
    })
    tick.guardian_reasoning_tick_run({"prompt": "Investigate"})
    tick.guardian_reasoning_tick_run({"prompt": "Investigate"})   # the repeat: tool calls stop, a conclusion is asked for
    final = tick.guardian_reasoning_tick_run({"prompt": "Investigate"})

    assert final["reschedule"] is False
    assert llm.calls[2]["tool_choice"] == "none" and "tools" not in llm.calls[2]
    assert ctx["Guardian"]["Loop"]["status"] == "done"
    assert "stopped early at tick" in final["narration"] and "identical failing tool call" in final["narration"]
    assert [f["guardianverdict"] for f in written if "guardianverdict" in f] == ["Benign"]


# --- measured model profile: one set of numbers per run ----------------------------------------------

_MEDIUM_SETTINGS = dict(DEFAULT_SETTINGS, model_tier="medium", max_input_tokens=28258)


def _profile_list(measured, **overrides):
    return {"active": "GuardianCohere:lab", "overrides": overrides, "profiles": {"GuardianCohere:lab": {
        "model": "command-r:35b", "instance_name": "lab", "max_input_tokens": measured,
        "probed_at": "2026-10-01T03:00:00Z", "window": 32768}}}


def _run_with_profile(monkeypatch, args, model_profile, ctx_guardian=None, settings=None):
    monkeypatch.setattr(tick, "guardian_tick_check_model_tier_consistency", lambda t, *a, **k: None)
    llm = _llm_handler_sequence([_CONCLUSION])
    ctx = _install(monkeypatch, settings=settings or _MEDIUM_SETTINGS, model_profile=model_profile,
                   command_handlers={"guardian-llm-chat": llm, "GuardianPromptBuilder": _prompt_builder_handler(),
                                     "GuardianToolCatalogBuilder": _catalog_builder_handler(_PREBUILT_TOOLS)})
    if ctx_guardian:
        ctx["Guardian"] = ctx_guardian
    return tick.guardian_reasoning_tick_run(args), ctx


def test_tick0_uses_the_measured_budget_and_says_where_each_number_came_from(monkeypatch):
    outcome, ctx = _run_with_profile(monkeypatch, {"prompt": "Investigate"}, _profile_list(9000))
    params = ctx["Guardian"]["Loop"]["model_params"]
    assert (params["tier"], params["max_input_tokens"], params["max_input_tokens_source"]) == ("medium", 9000, "measured")
    assert "Model profile (resolved): size medium (guardian_settings); input budget 9000 (measured)" in outcome["narration"]
    assert "measured on command-r:35b" in outcome["narration"]


def test_without_a_profile_the_tick_uses_guardian_settings_as_before(monkeypatch):
    outcome, ctx = _run_with_profile(monkeypatch, {"prompt": "Investigate"}, None)
    params = ctx["Guardian"]["Loop"]["model_params"]
    assert (params["max_input_tokens"], params["max_input_tokens_source"]) == (28258, "guardian_settings")
    assert "input budget 28258 (guardian_settings)" in outcome["narration"] and "no measured profile" in outcome["narration"]


def test_an_operator_override_in_the_profile_list_wins_on_tick0(monkeypatch):
    outcome, ctx = _run_with_profile(monkeypatch, {"prompt": "Investigate"}, _profile_list(9000, max_input_tokens=7000, model_tier="large"))
    params = ctx["Guardian"]["Loop"]["model_params"]
    assert (params["tier"], params["max_input_tokens"]) == ("large", 7000)


def test_the_playbook_snapshot_is_used_only_with_use_prebuilt(monkeypatch):
    snap = {"tier": "large", "tier_source": "override", "max_input_tokens": 5000, "max_input_tokens_source": "override",
            "max_tool_def_tokens": 3000, "max_tool_def_tokens_source": "override", "profile": None,
            "max_ticks": 60, "max_ticks_source": "tier", "limits": tick.guardian_derive_limits(5000)}
    guardian_ctx = {"SystemPrompt": "P", "ToolCatalog": _PREBUILT_TOOLS, "ModelProfile": snap}
    outcome, ctx = _run_with_profile(monkeypatch, {"prompt": "Investigate", "use_prebuilt": "true"}, _profile_list(9000), dict(guardian_ctx))
    assert ctx["Guardian"]["Loop"]["model_params"]["max_input_tokens"] == 5000
    assert "Model profile (snapshot)" in outcome["narration"]
    # run by hand: a snapshot left over from an earlier run is not trusted
    outcome, ctx = _run_with_profile(monkeypatch, {"prompt": "Investigate"}, _profile_list(9000), dict(guardian_ctx))
    assert ctx["Guardian"]["Loop"]["model_params"]["max_input_tokens"] == 9000
    assert "Model profile (resolved)" in outcome["narration"]


def test_an_unreadable_profile_list_falls_back_and_says_so(monkeypatch):
    outcome, ctx = _run_with_profile(monkeypatch, {"prompt": "Investigate"}, "{not json")
    assert ctx["Guardian"]["Loop"]["model_params"]["max_input_tokens"] == 28258
    assert "profile list unreadable" in outcome["narration"]


def _running_loop(**extra):
    state = {"messages": [{"role": "system", "content": "S"}, {"role": "user", "content": "go"}], "tick": 1,
             "run_id": "r1", "status": "running", "consec_fails": 0, "empty_turns": 0, "pending": None,
             "pending_ticks": 0, "dropped_count": 0}
    state.update(extra)
    return {"Loop": state, "ToolCatalog": _PREBUILT_TOOLS}


def test_later_ticks_keep_the_numbers_tick0_chose_even_if_the_list_changes(monkeypatch):
    stored = {"tier": "medium", "tier_source": "guardian_settings", "max_input_tokens": 5000,
              "max_input_tokens_source": "measured", "max_tool_def_tokens": 3000,
              "max_tool_def_tokens_source": "tier", "profile": None, "max_ticks": 40, "max_ticks_source": "tier",
              "limits": tick.guardian_derive_limits(5000)}
    outcome, ctx = _run_with_profile(monkeypatch, {"prompt": "x"}, _profile_list(9000),
                                     ctx_guardian=_running_loop(model_params=stored))
    assert ctx["Guardian"]["Loop"]["model_params"] == stored


def test_a_loop_saved_before_this_field_existed_resolves_it_once(monkeypatch):
    outcome, ctx = _run_with_profile(monkeypatch, {"prompt": "x"}, _profile_list(9000), ctx_guardian=_running_loop())
    assert ctx["Guardian"]["Loop"]["model_params"]["max_input_tokens"] == 9000


def test_apply_model_params_overlays_only_tier_and_input_budget():
    settings = {"tier": "small", "tier_profile": {}, "max_input_tokens": 1, "max_ticks": 25, "raw": {}}
    params = {"tier": "large", "max_input_tokens": None}
    tick.guardian_tick_apply_model_params(settings, params)
    assert settings["tier"] == "large" and settings["tier_profile"] is tick.GUARDIAN_TIER_PROFILES["large"]
    assert settings["max_input_tokens"] is None and settings["max_ticks"] == 25


# --- conclusion-quality gate: required steps and uncorroborated Benign/Malicious ----------------------------


def _catalog_with(*names):
    return [{"type": "function", "function": {"name": n, "parameters": {}}} for n in names]


def test_record_evidence_tracks_memory_store_case_note_and_corroboration():
    state = {}
    ok = {"status": "ok", "result": {}}
    tick.guardian_tick_record_evidence(state, "GuardianMemory", '{"op": "search"}', ok)
    tick.guardian_tick_record_evidence(state, "getIncidents", "{}", ok)
    tick.guardian_tick_record_evidence(state, "GuardianKBSearch", "{}", {"status": "ok", "result": {"count": 0}})
    assert state["evidence"] == {}
    tick.guardian_tick_record_evidence(state, "GuardianMemory", '{"op": "store"}', ok)
    tick.guardian_tick_record_evidence(state, "GuardianCaseNote", "{}", ok)
    tick.guardian_tick_record_evidence(state, "ip", '{"ip": "1.2.3.4"}', {"status": "error", "result": None})
    assert state["evidence"] == {"memory_stored": True, "case_noted": True}
    tick.guardian_tick_record_evidence(state, "GuardianKBSearch", "{}", {"status": "ok", "result": {"count": 2}})
    assert "corroborated" not in state["evidence"]  # a knowledge-base hit is general guidance, not a fact about the case


def test_record_evidence_counts_an_enrichment_tool_as_corroboration():
    state = {}
    tick.guardian_tick_record_evidence(state, "ip", {"ip": "1.2.3.4"}, {"status": "ok", "result": {}})
    assert state["evidence"]["corroborated"] is True


def test_conclusion_gaps_lists_missing_steps_only_when_offered_and_checked():
    catalog = _catalog_with("GuardianCaseNote", "GuardianMemory")
    steps, unsupported = tick.guardian_tick_conclusion_gaps({}, None, catalog, True)
    assert len(steps) == 2 and unsupported is False
    assert tick.guardian_tick_conclusion_gaps({}, None, catalog, False) == ([], False)
    assert tick.guardian_tick_conclusion_gaps({}, None, _catalog_with("GuardianMemory"), True)[0] == [
        "store a durable memory entry (GuardianMemory with op=store)"
    ]
    done = {"evidence": {"case_noted": True, "memory_stored": True}}
    assert tick.guardian_tick_conclusion_gaps(done, None, catalog, True) == ([], False)


def test_conclusion_gaps_flags_uncorroborated_benign_and_malicious_only_above_the_threshold():
    benign90 = {"verdict": "Benign", "confidence": 90}
    assert tick.guardian_tick_conclusion_gaps({}, benign90, [], False) == ([], True)
    assert tick.guardian_tick_conclusion_gaps({}, {"verdict": "Malicious", "confidence": 71}, [], False)[1] is True
    assert tick.guardian_tick_conclusion_gaps({}, {"verdict": "Malicious", "confidence": 70}, [], False)[1] is False
    assert tick.guardian_tick_conclusion_gaps({}, {"verdict": "Suspicious", "confidence": 95}, [], False)[1] is False
    assert tick.guardian_tick_conclusion_gaps({"evidence": {"corroborated": True}}, benign90, [], False)[1] is False


def test_uncorroborated_benign_gets_one_corrective_turn_then_is_downgraded(monkeypatch):
    text = 'Done.\n```json\n{"verdict":"Benign","confidence":90,"techniques":[],"summary":"%s"}\n```' % _VALID_SUMMARY
    writes = []
    monkeypatch.setattr(tick, "guardian_set_incident_fields", lambda iid, fields: writes.append(fields) or {"ok": True, "data": {}})
    llm_handler = _llm_handler_sequence([_completion(content=text), _completion(content=text)])
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": llm_handler,
        },
    )
    first = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert first["reschedule"] is True and not [w for w in writes if "guardianverdict" in w]
    assert "nothing you looked up corroborates it" in ctx["Guardian"]["Loop"]["messages"][-1]["content"]
    ctx2_args = first["next_args"]
    second = tick.guardian_reasoning_tick_run(ctx2_args)
    assert second["reschedule"] is False
    assert [(w["guardianverdict"], w["guardianconfidence"]) for w in writes if "guardianverdict" in w] == [("Suspicious", 65)]
    assert "Guardian calibration" in second["narration"]


# --- run-activity telemetry (dashboard fields) ----------------------------------------------------------------


def test_activity_records_calls_failures_approvals_and_tool_names_in_order():
    state = {}
    tick.guardian_tick_record_activity(state, "getIncidents", {"status": "ok"})
    tick.guardian_tick_record_activity(state, "ip", {"status": "error"})
    tick.guardian_tick_record_activity(state, "setIncident", {"status": "pending_approval"})
    tick.guardian_tick_record_activity(state, "closeInvestigation", {"status": "denied"})
    assert state["activity"] == {
        "calls": 4, "failures": 2, "approvals": 1, "tools": ["getIncidents", "ip", "setIncident", "closeInvestigation"],
        "outcomes": [["getIncidents", "ok"], ["ip", "error"], ["setIncident", "pending_approval"], ["closeInvestigation", "denied"]]}


def test_activity_fields_carry_the_model_and_only_report_counts_once_something_ran():
    assert tick.guardian_tick_activity_fields({}, "gpt-oss-120b") == {"guardianmodel": "gpt-oss-120b"}
    assert tick.guardian_tick_activity_fields({}, "") == {}
    state = {"activity": {"calls": 3, "failures": 1, "approvals": 0, "tools": ["a", "b", "a"]}}
    assert tick.guardian_tick_activity_fields(state, "m") == {
        "guardianmodel": "m", "guardiantoolcalls": 3, "guardiantoolfailures": 1,
        "guardianapprovalsrequested": 0, "guardiantoolsused": "a,b,a",
    }


def test_activity_tool_list_is_capped():
    state = {"activity": {"calls": 500, "failures": 0, "approvals": 0, "tools": ["GuardianMemory"] * 500}}
    assert len(tick.guardian_tick_activity_fields(state, "")["guardiantoolsused"]) == tick.GUARDIAN_ACTIVITY_TOOLS_MAX_CHARS


def test_held_verdict_is_recorded_downgraded_when_the_corrective_turn_yields_no_verdict(monkeypatch):
    text = 'Done.\n```json\n{"verdict":"Malicious","confidence":95,"techniques":[],"summary":"%s"}\n```' % _VALID_SUMMARY
    writes = []
    monkeypatch.setattr(tick, "guardian_set_incident_fields", lambda iid, fields: writes.append(fields) or {"ok": True, "data": {}})
    llm_handler = _llm_handler_sequence([_completion(content=text), _completion(content="<|start|>assistant<|channel|>commentary to=functions.ip <|call|>")])
    _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": llm_handler,
        },
    )
    first = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert first["reschedule"] is True
    second = tick.guardian_reasoning_tick_run(first["next_args"])
    assert second["reschedule"] is False
    assert [(w["guardianverdict"], w["guardianconfidence"]) for w in writes if "guardianverdict" in w] == [("Suspicious", 65)]
    assert "verdict held back by the conclusion gate" in second["narration"]


def test_held_verdict_helper_keeps_a_corroborated_verdict_as_stated(monkeypatch):
    writes = []
    monkeypatch.setattr(tick, "guardian_set_incident_fields", lambda iid, fields: writes.append(fields) or {"ok": True, "data": {}})
    state = {"held_verdict": {"verdict": "Benign", "confidence": 90, "techniques": [], "summary": _VALID_SUMMARY}, "evidence": {"corroborated": True}}
    assert "held back" in tick.guardian_tick_write_held_verdict(state, "7")
    assert [(w["guardianverdict"], w["guardianconfidence"]) for w in writes if "guardianverdict" in w] == [("Benign", 90)]
    assert tick.guardian_tick_write_held_verdict({}, "7") == ""


# --- custom issue fields: failure detection and the incident_fields_enabled setting -------------------------


_FIELDS_VERDICT_TEXT = (
    'Investigation complete.\n```json\n{"verdict":"Suspicious","confidence":60,"techniques":["T1566"],"summary":"%s"}\n```'
    % _VALID_SUMMARY
)
_FIELD_ERROR = "field not associated with this incident type"


def _field_writes(monkeypatch, ok=True, error=_FIELD_ERROR):
    """Replace the loop's issue-field write with a recording fake; returns the list of (incident_id, fields) calls."""
    calls = []

    def fake(incident_id, fields):
        calls.append((incident_id, dict(fields)))
        return {"ok": True, "data": {}} if ok else {"ok": False, "error": error}

    monkeypatch.setattr(tick, "guardian_set_incident_fields", fake)
    return calls


def _fields_install(monkeypatch, completions, settings=None, incident_id="999", catalog=None, stub_gate=True):
    audits = []
    llm = _llm_handler_sequence(completions)
    ctx = _install(
        monkeypatch,
        settings=settings,
        incident_id=incident_id,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler(catalog if catalog is not None else []),
            "guardian-llm-chat": llm,
            "GuardianToolBridge": _tool_bridge_handler(
                default_result={"status": "ok", "ok": True, "result": {"Score": 1}, "error": None}
            ),
            "GuardianAuditWrite": lambda args: audits.append(args) or [{"Type": 1, "Contents": "ok"}],
        },
    )
    if stub_gate:
        monkeypatch.setattr(tick, "guardian_tick_conclusion_gaps", lambda *a, **k: ([], False))  # the gate has its own tests
    return ctx, llm, audits


def _verdict_audits(audits):
    return [a for a in audits if a.get("action") == "verdict_write"]


def test_a_failed_field_write_at_the_conclusion_is_not_a_missing_verdict(monkeypatch):
    calls = _field_writes(monkeypatch, ok=False)
    ctx, llm, audits = _fields_install(monkeypatch, [_completion(content=_FIELDS_VERDICT_TEXT)])

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    narration = outcome["narration"]
    assert outcome["reschedule"] is False
    assert len(llm.calls) == 1  # no corrective retry turn and no extraction call
    assert "forcing corrective retry" not in narration
    assert "No verdict block" not in narration and "could not be written." not in narration
    verdict_audit = _verdict_audits(audits)
    assert [a["status"] for a in verdict_audit] == ["error"]
    detail = json.loads(verdict_audit[0]["detail"])
    assert (detail["verdict"], detail["confidence"], detail["techniques"]) == ("Suspicious", 60, ["T1566"])
    assert _FIELD_ERROR in detail["reason"]
    assert narration.count("Verdict recorded in the conclusion and guardian_audit; not saved to the issue fields") == 1
    assert narration.count("Custom issue fields could not be written on this tenant") == 1
    assert len(calls) == 1  # only the first (cost) write was tried; the verdict write was skipped after it failed
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "done"
    assert {k: loop["verdict"][k] for k in ("verdict", "confidence", "techniques")} == {"verdict": "Suspicious", "confidence": 60, "techniques": ["T1566"]}
    assert loop["verdict"]["summary"]  # kept so GuardianRunCapture can remember the outcome
    assert loop["field_writes_off"] is True and _FIELD_ERROR in loop["field_writes_off_reason"]


def test_the_first_failed_per_turn_write_warns_once_and_later_turns_write_nothing(monkeypatch):
    calls = _field_writes(monkeypatch, ok=False)
    tc = _tool_call("call_1", "ip", {"ip": "8.8.8.8"})
    ctx, llm, _audits = _fields_install(
        monkeypatch,
        [_completion(tool_calls=[tc]), _completion(tool_calls=[tc]), _completion(content="Final verdict: benign")],
        catalog=[{"type": "function", "function": {"name": "ip"}}],
    )

    first = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert first["reschedule"] is True
    assert first["narration"].count("Custom issue fields could not be written on this tenant") == 1
    assert len(calls) == 1
    cost_after_first = ctx["Guardian"]["Loop"]["cost_usd"]
    assert ctx["Guardian"]["Loop"]["field_writes_off"] is True  # the flag is part of the persisted loop state

    second = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    third = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert third["reschedule"] is False
    for later in (second, third):
        assert "Custom issue fields could not be written" not in later["narration"]
        assert "WARNING" not in later["narration"]
    assert len(calls) == 1  # no field write at all on the later turns
    assert ctx["Guardian"]["Loop"]["cost_usd"] > cost_after_first  # cost is still tracked in the loop state


def test_incident_fields_enabled_false_writes_no_field_and_does_not_warn(monkeypatch):
    calls = _field_writes(monkeypatch, ok=True)
    settings = dict(DEFAULT_SETTINGS, incident_fields_enabled=False)
    ctx, llm, audits = _fields_install(monkeypatch, [_completion(content=_FIELDS_VERDICT_TEXT)], settings=settings)
    # A previous run's verdict is on the incident: the tick-0 clear would normally write it away.
    monkeypatch.setattr(
        tick.demisto, "incident", lambda: {"id": "999", "CustomFields": {"guardianverdict": "Benign", "guardianconfidence": 40}}
    )

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    narration = outcome["narration"]
    assert calls == []  # no write of any kind: not cost, not the clear, not the verdict
    assert outcome["reschedule"] is False and len(llm.calls) == 1
    assert "WARNING" not in narration and "Custom issue fields could not be written" not in narration
    assert [a["status"] for a in _verdict_audits(audits)] == ["skipped"]
    assert json.loads(_verdict_audits(audits)[0]["detail"])["verdict"] == "Suspicious"
    assert narration.count("not saved to the issue fields (incident_fields_enabled is false") == 1
    loop = ctx["Guardian"]["Loop"]
    assert loop["verdict"]["verdict"] == "Suspicious" and not loop.get("field_writes_off")


def test_a_successful_field_write_is_unchanged(monkeypatch):
    calls = _field_writes(monkeypatch, ok=True)
    ctx, llm, audits = _fields_install(monkeypatch, [_completion(content=_FIELDS_VERDICT_TEXT)])

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    narration = outcome["narration"]
    assert outcome["reschedule"] is False and len(llm.calls) == 1
    assert [a["status"] for a in _verdict_audits(audits)] == ["ok"]
    assert "not saved" not in narration and "WARNING" not in narration
    assert "guardiancostusd" in calls[0][1]
    verdict_writes = [f for _iid, f in calls if "guardianverdict" in f]
    assert [w["guardianverdict"] for w in verdict_writes] == ["Suspicious"]
    loop = ctx["Guardian"]["Loop"]
    assert not loop.get("field_writes_off") and loop["verdict_save"]["status"] == "ok"


def test_a_failed_write_does_not_trigger_the_held_verdict_extraction_or_retry(monkeypatch):
    calls = _field_writes(monkeypatch, ok=False)
    held_text = 'Done.\n```json\n{"verdict":"Malicious","confidence":95,"techniques":[],"summary":"%s"}\n```' % _VALID_SUMMARY
    ctx, llm, audits = _fields_install(
        monkeypatch,
        [_completion(content=held_text), _completion(content="<|start|>assistant<|channel|>commentary to=functions.ip <|call|>")],
        stub_gate=False,  # the real gate holds back a Malicious 95 that nothing corroborates
    )
    first = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    second = tick.guardian_reasoning_tick_run(first["next_args"])

    assert second["reschedule"] is False
    assert len(llm.calls) == 2  # the corrective turn, and nothing after it: no retry, no extraction
    assert "verdict held back by the conclusion gate" in second["narration"]
    assert "forcing corrective retry" not in second["narration"]
    assert [a["status"] for a in _verdict_audits(audits)] == ["error"]
    assert second["narration"].count("not saved to the issue fields") == 1
    assert len(calls) == 1


def test_a_forced_conclusion_with_a_failed_write_says_so_once_and_asks_for_no_extraction(monkeypatch):
    _field_writes(monkeypatch, ok=False)
    ctx, llm, audits = _fields_install(
        monkeypatch,
        [_completion(content=_FIELDS_VERDICT_TEXT)],
        settings={"MAX_TICKS": 1, "tick_cadence_seconds": 12, "batch_cap": 25},
    )

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert outcome["reschedule"] is False and "tick ceiling" in outcome["narration"]
    assert len(llm.calls) == 1
    assert [a["status"] for a in _verdict_audits(audits)] == ["error"]
    assert outcome["narration"].count("not saved to the issue fields") == 1


def test_an_extracted_verdict_with_a_failed_write_is_recorded_not_reported_as_unwritable(monkeypatch):
    _field_writes(monkeypatch, ok=False)
    extracted = json.dumps({"verdict": "Malicious", "confidence": 90, "techniques": ["T1021"], "summary": _VALID_SUMMARY})
    ctx, llm, audits = _fields_install(monkeypatch, [_completion(content=_prose_conclusion()), _completion(content=extracted)])
    ctx["Guardian"] = {"Loop": {
        "messages": [{"role": "system", "content": "x"}, {"role": "user", "content": "y"}], "tick": 3, "run_id": "999",
        "status": "running", "consec_fails": 0, "empty_turns": 0, "no_verdict_fails": tick.GUARDIAN_NO_VERDICT_RETRY_LIMIT,
        "pending": None, "pending_ticks": 0, "dropped_count": 0}, "ToolCatalog": []}

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate the case"})

    assert "recorded verdict **Malicious** (90) extracted from the conclusion" in outcome["narration"]
    assert "could not be written." not in outcome["narration"]
    assert outcome["narration"].count("not saved to the issue fields") == 1
    audit = _verdict_audits(audits)[0]
    assert audit["status"] == "error" and json.loads(audit["detail"])["source"] == "extracted"


def test_without_an_incident_the_field_writes_are_skipped_silently(monkeypatch):
    calls = _field_writes(monkeypatch, ok=False)
    ctx, llm, _audits = _fields_install(monkeypatch, [_completion(content="Final verdict: benign")], incident_id=None)

    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})

    assert calls == []
    assert "WARNING" not in outcome["narration"]
    assert not ctx["Guardian"]["Loop"].get("field_writes_off")


def test_field_write_helper_statuses(monkeypatch):
    calls = _field_writes(monkeypatch, ok=True)
    state = {}
    assert tick.guardian_tick_field_write(state, "7", {"guardiancostusd": 1}) == ("ok", "")
    assert tick.guardian_tick_field_write(state, "", {"guardiancostusd": 1})[0] == "skipped"  # no incident
    assert tick.guardian_tick_field_write({"incident_fields_enabled": False}, "7", {"x": 1})[0] == "skipped"
    assert len(calls) == 1 and "field_writes_off" not in state

    def boom(incident_id, fields):
        raise RuntimeError("rest down")

    monkeypatch.setattr(tick, "guardian_set_incident_fields", boom)
    assert tick.guardian_tick_field_write(state, "7", {"x": 1}) == ("error", "rest down")
    assert state["field_writes_off"] is True and state["field_writes_off_reason"] == "rest down"

    again = _field_writes(monkeypatch, ok=True)
    assert tick.guardian_tick_field_write(state, "7", {"x": 1}) == ("error", "rest down")
    assert again == []  # once off, never tried again in this run


def test_load_settings_reads_incident_fields_enabled(monkeypatch):
    for value, expected in ((None, True), (True, True), (False, False), ("false", True), (0, True)):
        settings = dict(DEFAULT_SETTINGS)
        if value is not None:
            settings["incident_fields_enabled"] = value
        _install(monkeypatch, settings=settings)
        assert tick.guardian_tick_load_settings()["incident_fields_enabled"] is expected, value


def test_the_shipped_settings_list_enables_incident_fields_by_default():
    path = REPO_ROOT / "Packs" / "GuardianXSIAM" / "Lists" / "list-guardian_settings.json"
    data = json.loads(json.loads(path.read_text())["data"])
    assert data["incident_fields_enabled"] is True
    assert data["_comment_incident_fields_enabled"]


# --- the model profile line says where the figure comes from (documented, confirmed, quota, measured) ------------


def _params(profile, source="measured"):
    return {"tier": "medium", "tier_source": "guardian_settings", "max_input_tokens": 173400,
            "max_input_tokens_source": source, "max_tool_def_tokens": 16000, "max_tool_def_tokens_source": "tier",
            "max_tool_calls_per_turn": 0, "profile": profile}


def test_the_profile_line_calls_a_documented_record_documented_not_measured():
    profile = {"model": "gpt-5-mini", "source": "documented", "catalog_checked": "2026-10-09"}
    line = tick.guardian_tick_model_profile_line(
        tick.guardian_tick_label_profile(_params(profile, "documented, catalogue 2026-10-09")), "snapshot")
    assert "documented limits (model catalogue 2026-10-09) for gpt-5-mini" in line
    assert "input budget 173400 (documented, catalogue 2026-10-09)" in line
    assert "measured" not in line


def test_the_profile_line_words_confirmed_quota_and_measured_records():
    confirmed = tick.guardian_tick_model_profile_line(
        tick.guardian_tick_label_profile(_params({"model": "m", "source": "confirmed"})), "snapshot")
    assert "documented limits, confirmed by a probe for m" in confirmed and "(confirmed by a probe, documented limit used)" in confirmed
    quota = tick.guardian_tick_model_profile_line(
        tick.guardian_tick_label_profile(_params({"model": "m", "source": "quota", "catalog_checked": "2026-10-09"})), "snapshot")
    assert "a probe hit a quota limit" in quota and "measured" not in quota
    measured = tick.guardian_tick_model_profile_line(
        tick.guardian_tick_label_profile(_params({"model": "m", "source": "measured", "probed_at": "2026-10-08T03:00:00Z"})), "snapshot")
    assert "measured on m 2026-10-08T03:00:00Z" in measured and "input budget 173400 (measured)" in measured


def test_a_record_with_no_source_is_an_old_probe_record_and_stays_measured(monkeypatch):
    monkeypatch.setattr(tick, "guardian_load_model_profile_list", lambda: {"ok": True, "error": None, "data": {
        "active": "P:i", "profiles": {"P:i": {"model": "command-r:35b", "probed_at": "2026-10-01T03:00:00Z"}}}})
    profile = {"model": "command-r:35b", "probed_at": "2026-10-01T03:00:00Z"}
    line = tick.guardian_tick_model_profile_line(tick.guardian_tick_label_profile(_params(profile)), "resolved")
    assert "measured on command-r:35b 2026-10-01T03:00:00Z" in line and "input budget 173400 (measured)" in line
    assert "no measured profile" in tick.guardian_tick_model_profile_line(_params(None, "guardian_settings"), "resolved")


def test_numbers_the_tick_resolved_itself_get_their_source_from_the_profile_list(monkeypatch):
    # no snapshot: the resolver's summary has no source, so the active record is read once
    monkeypatch.setattr(tick, "guardian_load_model_profile_list", lambda: {"ok": True, "error": None, "data": {
        "active": "P:i", "profiles": {"P:i": {"model": "gpt-5-mini", "source": "documented", "catalog_checked": "2026-10-09"}}}})
    line = tick.guardian_tick_model_profile_line(
        tick.guardian_tick_label_profile(_params({"model": "gpt-5-mini", "probed_at": None})), "resolved")
    assert "(documented, catalogue 2026-10-09)" in line and "documented limits (model catalogue 2026-10-09) for gpt-5-mini" in line
    # an unreadable list leaves the numbers as they were
    monkeypatch.setattr(tick, "guardian_load_model_profile_list", lambda: {"ok": False, "error": "boom", "data": {}})
    again = tick.guardian_tick_model_profile_line(tick.guardian_tick_label_profile(_params({"model": "x"})), "resolved")
    assert "measured on x" in again


# --- limits that scale with the model's input budget ------------------------------------------------------
# A large model gets large limits; the history is bounded by TOKENS against the budget; and no request the
# tick sends may exceed the budget, whatever the shares of the budget (tool list, skill, incident details,
# tool results) add up to.

_GPT5_MINI_BUDGET = 173400   # int(272000 x 0.85 x 3.0 / 4): the documented budget of gpt-5-mini
_FALLBACK_BUDGET = 28258     # guardian_settings.max_input_tokens as shipped
_AUTO_SETTINGS = {"tick_cadence_seconds": 12, "model_tier": "auto"}   # like the shipped settings: no MAX_TICKS


def _shipped_catalog():
    path = Path(__file__).resolve().parents[2] / "Lists" / "list-guardian_model_catalog.json"   # this pack's own list
    return json.loads(json.loads(path.read_text())["data"])


def _est(messages, tools=None):
    return tick.guardian_tick_estimate_input_tokens(messages, tools)


def _tools_of_tokens(tokens, count=20, gate_tools=False):
    """A tool list whose estimate is about `tokens`. With `gate_tools` the last two are GuardianCaseNote and
    GuardianMemory, the tools the conclusion gate requires (at the tail, where the allowlist puts them)."""
    per_tool = max((tokens * 4) // count - 120, 10)
    names = ["tool{}".format(i) for i in range(count)]
    if gate_tools:
        names[-2:] = ["GuardianCaseNote", "GuardianMemory"]
    return [{"type": "function", "function": {"name": name, "description": "d" * per_tool,
                                              "parameters": {"type": "object", "properties": {}}}} for name in names]


def _tool_exchange(index, ceiling, result_chars):
    call_id = "call{}".format(index)
    return [
        {"role": "assistant", "content": None, "tool_calls": [_tool_call(call_id, "getIncidents", {"id": str(index)})]},
        tick.guardian_tick_tool_message(
            {"tool_call_id": call_id, "tool_name": "getIncidents", "status": "ok", "ok": True,
             "result": "r{}-".format(index) + "x" * result_chars}, ceiling),
    ]


#: The fixed system prompt (before any skill) of a real run is about 13,000 tokens: 17,000 on the small tier with the
#: tool list in it (docs/MODEL_SETUP.md), which is about 4,000 of them.
_REAL_PROMPT_CHARS = 13000 * 4


def _loop_at_budget(budget, settings=None, record=None, size=None, exchanges=6, result_chars=400000, small_msgs=0,
                    skill_share_chars=None, details_chars=None, prompt_chars=_REAL_PROMPT_CHARS, gate_tools=False, **extra):
    """(guardian_ctx, params, settings, plist) for a running loop whose history holds `exchanges` tool results,
    every other share of the budget at its maximum."""
    settings = dict(_AUTO_SETTINGS, max_input_tokens=budget) if settings is None else settings
    plist = {"active": "P:i", "profiles": {"P:i": dict(record or {"model": "x"}, max_input_tokens=budget)}}
    params = tick.guardian_resolve_model_params(settings, plist, size)
    limits = params["limits"]
    skill_chars = skill_share_chars if skill_share_chars is not None else int(budget * tick.GUARDIAN_TICK_SKILL_MAX_BUDGET_SHARE) * 4
    details = details_chars if details_chars is not None else limits["incident_details_chars"]
    messages = [{"role": "system", "content": "S" * prompt_chars + "K" * skill_chars},
                {"role": "system", "content": "YOU ARE ALREADY WORKING THIS INCIDENT -- id 999\n" + "I" * details},
                {"role": "user", "content": "<untrusted-case-data>go</untrusted-case-data>"}]
    for i in range(small_msgs):
        messages.append({"role": "user" if i % 2 == 0 else "assistant", "content": "note {}".format(i)})
    for i in range(exchanges):
        messages.extend(_tool_exchange(i, limits["evidence_truncate_bytes"], result_chars))
    catalog = _tools_of_tokens(params["max_tool_def_tokens"], gate_tools=gate_tools)
    state = {"messages": messages, "tick": 3, "run_id": "999", "status": "running", "consec_fails": 0, "empty_turns": 0,
             "pending": None, "pending_ticks": 0, "dropped_count": 0, "model_params": params}
    state.update(extra)
    return {"Loop": state, "ToolCatalog": catalog}, params, settings, plist


def _snapshotting(handler):
    """A copy of the arguments is what the handler records: the tick appends the model's reply to the very list it
    sent, and the XSOAR 6 edition hands the list over as it is, so a by-reference record would show the request
    plus that reply."""
    import copy

    def handle(args):
        return handler(copy.deepcopy(args))

    handle.calls = handler.calls
    return handle


def _run_one_tick(monkeypatch, guardian_ctx, settings, plist, completions, extra_handlers=None):
    llm = _llm_handler_sequence(completions)
    handlers = {"guardian-llm-chat": _snapshotting(llm)}
    handlers.update(extra_handlers or {})
    ctx = _install(monkeypatch, settings=settings, model_profile=plist, command_handlers=handlers,
                   extra_lists={"guardian_model_catalog": _shipped_catalog()})
    ctx["Guardian"] = guardian_ctx
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate"})
    return outcome, ctx, llm


_LARGE_SIZE = {"model_id": "gpt-5-mini", "size_class": "large", "params_b": None}
_MEDIUM_SIZE = {"model_id": "command-r-08-2024", "size_class": "medium", "params_b": 32}

#: (budget, catalogue size, explicit tool-list budget): B=28,258 as a small, a medium and a large model, B=173,400 as
#: a large one, and each with a tool-list budget far above what the window holds (capped at 60% of B).
_BUDGET_CASES = [
    pytest.param(_FALLBACK_BUDGET, None, None, id="28258-small"),
    pytest.param(_FALLBACK_BUDGET, _MEDIUM_SIZE, None, id="28258-medium"),
    pytest.param(_FALLBACK_BUDGET, _LARGE_SIZE, None, id="28258-large"),
    pytest.param(_GPT5_MINI_BUDGET, _LARGE_SIZE, None, id="173400-large"),
    pytest.param(_FALLBACK_BUDGET, _MEDIUM_SIZE, 500000, id="28258-medium-oversized-tools"),
    pytest.param(_GPT5_MINI_BUDGET, _LARGE_SIZE, 500000, id="173400-large-oversized-tools"),
]


def _assert_request_keeps_head_and_newest_result(sent_messages, newest_call_id, exchanges):
    """The request still carries the system prompt, the incident pin, the task and the newest result."""
    assert sent_messages[0]["content"].startswith("S")                                  # the system prompt (with the skill)
    assert sent_messages[1]["content"].startswith("YOU ARE ALREADY WORKING THIS INCIDENT")   # the incident pin
    assert sent_messages[2]["role"] == "user" and sent_messages[2]["content"].startswith("<untrusted-case-data>")   # the task
    newest = [m for m in sent_messages if m.get("role") == "tool" and m.get("tool_call_id") == newest_call_id]
    assert len(newest) == 1 and newest[0]["content"].startswith('{"')                   # the newest result (cut to fit if needed)
    owner = [m for m in sent_messages if m.get("tool_calls") and m["tool_calls"][0]["id"] == newest_call_id]
    assert len(owner) == 1                                                              # and the call it answers
    return newest[0]


@pytest.mark.parametrize("budget,size,tool_budget", _BUDGET_CASES)
def test_a_request_never_exceeds_the_input_budget_and_keeps_the_pin_the_task_and_the_newest_result(
        monkeypatch, budget, size, tool_budget):
    settings = dict(_AUTO_SETTINGS, max_input_tokens=budget)
    if tool_budget:
        settings["max_tool_def_tokens"] = tool_budget
    ctx_guardian, params, settings, plist = _loop_at_budget(budget, settings=settings, size=size, exchanges=6)
    if tool_budget:
        assert params["max_tool_def_tokens"] == int(budget * 0.6)   # the 60% cap, the worst case
    messages = ctx_guardian["Loop"]["messages"]
    limits = params["limits"]
    # the premise: at least four results at the per-result ceiling, and the whole transcript far over the budget
    big = [m for m in messages if m["role"] == "tool" and len(m["content"]) >= limits["evidence_truncate_bytes"] - 200]
    assert len(big) >= 4 and _est(messages, ctx_guardian["ToolCatalog"]) > budget
    outcome, ctx, llm = _run_one_tick(monkeypatch, ctx_guardian, settings, plist, [_completion(content="done")])
    sent = llm.calls[0]
    assert _est(sent["messages"], sent.get("tools")) <= budget
    newest = _assert_request_keeps_head_and_newest_result(sent["messages"], "call5", 6)
    assert len(newest["content"]) >= tick.GUARDIAN_TICK_MIN_FIT_RESULT_CHARS
    assert len(sent["tools"]) >= 1
    if params["max_tool_def_tokens"] > 8000 and budget == _FALLBACK_BUDGET:
        # the window cannot hold the fixed prompt, this tool list and a full result: tools give first
        assert len(sent["tools"]) < len(ctx_guardian["ToolCatalog"])
        assert "lowest-priority tool(s) were left out of this turn" in outcome["narration"]


@pytest.mark.parametrize("budget,size,tool_budget", [c for c in _BUDGET_CASES if c.values[2] is None])
def test_a_forced_summary_turn_is_also_held_to_the_input_budget(monkeypatch, budget, size, tool_budget):
    """The turn after a stop (a repeated failing call, two empty turns) is sent without a pre-flight of its own
    further down; a transcript saved over the budget must be brought under it first, keeping the pin, the task and
    the newest result."""
    ctx_guardian, params, settings, plist = _loop_at_budget(budget, size=size, exchanges=6, force_conclude=True,
                                                            force_conclude_reason="the model repeated a call")
    assert _est(ctx_guardian["Loop"]["messages"]) > budget
    outcome, ctx, llm = _run_one_tick(monkeypatch, ctx_guardian, settings, plist, [_completion(content="forced summary")])
    sent = llm.calls[0]
    assert sent["tool_choice"] == "none" and "tools" not in sent
    assert _est(sent["messages"]) <= budget
    _assert_request_keeps_head_and_newest_result(sent["messages"], "call5", 6)
    assert "forced summary" in outcome["narration"]


@pytest.mark.parametrize("budget,size,tool_budget", [c for c in _BUDGET_CASES if c.values[2] is None])
def test_the_saved_transcript_plus_tool_list_fits_the_budget_after_a_tick_of_large_results(monkeypatch, budget, size, tool_budget):
    """A model that asks for three tools whose results are each far over the ceiling: the results are cut to the
    room the request has left, the pin and the task stay, and what is saved for the next tick (with the tool list
    it was sent with) fits the budget."""
    ctx_guardian, params, settings, plist = _loop_at_budget(budget, size=size, exchanges=2)
    calls = [_tool_call("n{}".format(i), "getIncidents", {"id": "n{}".format(i)}) for i in range(3)]
    huge = {"status": "ok", "ok": True, "result": "Z" * 900000}
    seen = []

    def bridge(args):
        seen.append(args)
        return _tool_bridge_handler(default_result=huge)(args)

    outcome, ctx, llm = _run_one_tick(
        monkeypatch, ctx_guardian, settings, plist, [_completion(tool_calls=calls)], {"GuardianToolBridge": bridge})
    saved = ctx["Guardian"]["Loop"]["messages"]
    sent_tools = llm.calls[0].get("tools") or ctx_guardian["ToolCatalog"]
    ceiling = params["limits"]["evidence_truncate_bytes"]
    new_results = [m for m in saved if m.get("role") == "tool" and m["tool_call_id"].startswith("n")]
    expected = 3 if size and size["size_class"] == "large" else 1   # small and medium models run one call per turn
    assert len(new_results) == expected and all(len(m["content"]) <= ceiling + 100 for m in new_results)
    turn_share = budget * 4 * tick.GUARDIAN_TICK_TURN_RESULTS_BUDGET_SHARE_PERCENT // 100
    assert sum(len(m["content"]) for m in new_results) <= max(turn_share, ceiling) + 600
    assert saved[0]["content"].startswith("S") and saved[1]["content"].startswith("YOU ARE ALREADY WORKING")
    assert saved[2]["content"].startswith("<untrusted-case-data>")
    assert _est(saved, sent_tools) <= budget
    # the bridge was handed the SAME number the tick cut at: no result is cut by the tick alone
    room = tick.guardian_tick_result_room_chars(ctx_guardian["Loop"]["messages"], sent_tools, budget)
    assert {a["evidence_truncate_bytes"] for a in seen} == {tick.guardian_tick_result_cap_for_turn(
        {"evidence_truncate_bytes": ceiling, "max_input_tokens": budget}, expected, room)}


def test_a_single_result_over_the_ceiling_is_cut_to_the_ceiling_with_head_and_tail():
    ceiling = tick.guardian_derive_limits(_GPT5_MINI_BUDGET)["evidence_truncate_bytes"]
    assert ceiling == 138720
    payload = "HEAD-" + "m" * 600000 + "-TAIL"
    message = tick.guardian_tick_tool_message({"tool_call_id": "c", "tool_name": "ip", "status": "ok", "result": payload}, ceiling)
    content = message["content"]
    assert len(content) <= ceiling + 100 and "tool message truncated" in content
    assert content.startswith('{"tool_call_id"') and '-TAIL"' in content[-40:] and "HEAD-" in content[:200]


def test_history_far_under_the_budget_is_not_dropped_by_message_count(monkeypatch):
    for budget, size in ((_GPT5_MINI_BUDGET, {"model_id": "gpt-5-mini", "size_class": "large", "params_b": None}),
                         (_FALLBACK_BUDGET, None)):
        ctx_guardian, params, settings, plist = _loop_at_budget(budget, size=size, exchanges=0, small_msgs=70)
        assert params["limits"]["batch_cap"] is None
        outcome, ctx, llm = _run_one_tick(monkeypatch, ctx_guardian, settings, plist, [_completion(content="done")])
        assert len(llm.calls[0]["messages"]) == 73  # nothing was dropped (3 fixed messages + 70 notes)
        assert ctx["Guardian"]["Loop"]["dropped_count"] == 0


def test_an_explicit_batch_cap_in_settings_still_applies_by_count(monkeypatch):
    settings = dict(_AUTO_SETTINGS, max_input_tokens=_GPT5_MINI_BUDGET, batch_cap=20)
    ctx_guardian, params, settings, plist = _loop_at_budget(_GPT5_MINI_BUDGET, settings=settings, exchanges=0, small_msgs=60)
    assert params["limits"]["batch_cap"] == 20 and params["limits"]["batch_cap_source"] == "guardian_settings"
    outcome, ctx, llm = _run_one_tick(monkeypatch, ctx_guardian, settings, plist, [_completion(content="done")])
    assert ctx["Guardian"]["Loop"]["dropped_count"] > 0


def test_tick0_sizes_a_catalogued_model_from_the_catalogue_with_no_record_rewrite(monkeypatch):
    """A gpt-5-mini record written before sizes existed (no size field, no tier) gets "large" and large limits."""
    record = {"provider": "GuardianFoundry", "instance_name": "f1", "model": "gpt-5-mini", "source": "documented",
              "catalog_id": "gpt-5-mini", "catalog_checked": "2026-10-09", "max_input_tokens": _GPT5_MINI_BUDGET}
    plist = {"active": "GuardianFoundry:f1", "overrides": {}, "profiles": {"GuardianFoundry:f1": record}}
    settings = dict(_AUTO_SETTINGS, model_tier="small", max_input_tokens=_FALLBACK_BUDGET)  # an old explicit "small"
    llm = _llm_handler_sequence([_completion(content="No further action; routine activity.")])
    list_writes = []

    def record_set_list(args):
        list_writes.append(args["listName"])
        return [{"Type": 1, "Contents": "Done: list updated"}]

    ctx = _install(monkeypatch, settings=settings, model_profile=plist,
                   command_handlers={"guardian-llm-chat": llm, "GuardianPromptBuilder": _prompt_builder_handler(),
                                     "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
                                     "setList": record_set_list},
                   extra_lists={"guardian_model_catalog": _shipped_catalog()})
    monkeypatch.setattr(tick, "guardian_tick_check_model_tier_consistency", lambda *a, **k: None)
    monkeypatch.setattr(tick, "guardian_search_integrations", lambda: {"instances": [], "configurations": []})
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate"})
    params = ctx["Guardian"]["Loop"]["model_params"]
    assert (params["tier"], params["tier_source"]) == ("large", "catalogue (gpt-5-mini)")
    assert params["max_input_tokens"] == _GPT5_MINI_BUDGET
    assert params["max_tool_def_tokens"] == 43350
    assert params["limits"]["evidence_truncate_bytes"] == 138720 and params["limits"]["incident_details_chars"] == 34680
    assert "guardian_settings.model_tier (small) is not used: gpt-5-mini is a large model in the model catalogue" in outcome["narration"]
    assert "history compacted by tokens at 173,400" in outcome["narration"]
    assert "guardian_model_profile" not in list_writes   # the tick never writes the profile record


def test_tick0_finds_a_catalogued_model_with_no_record_through_the_configured_model(monkeypatch):
    instance = {"name": "lab", "brand": "GuardianCohere", "enabled": "true",
                "data": [{"name": "model", "value": "command-r:35b"}]}
    response = {"instances": [instance], "configurations": [{"name": "GuardianCohere", "integrationScript": {
        "commands": [{"name": "guardian-llm-chat"}]}}]}
    llm = _llm_handler_sequence([_completion(content="No further action; routine activity.")])
    ctx = _install(monkeypatch, settings=dict(_AUTO_SETTINGS, max_input_tokens=_FALLBACK_BUDGET),
                   command_handlers={"guardian-llm-chat": llm, "GuardianPromptBuilder": _prompt_builder_handler(),
                                     "GuardianToolCatalogBuilder": _catalog_builder_handler([])},
                   extra_lists={"guardian_model_catalog": _shipped_catalog()})
    monkeypatch.setattr(tick, "guardian_search_integrations", lambda: response)
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate"})
    params = ctx["Guardian"]["Loop"]["model_params"]
    assert (params["tier"], params["tier_source"]) == ("medium", "catalogue (command-r-08-2024)")
    assert params["max_tool_def_tokens"] == 16000


def test_the_builder_gets_the_ticks_numbers_so_tool_list_and_loop_cannot_disagree(monkeypatch):
    seen = []

    def builder(args):
        seen.append(args)
        return [{"Type": 1, "Contents": {"catalog": []}}]

    llm = _llm_handler_sequence([_completion(content="done")])
    _install(monkeypatch, settings=dict(_AUTO_SETTINGS, model_tier="medium", max_input_tokens=_FALLBACK_BUDGET),
             command_handlers={"guardian-llm-chat": llm, "GuardianPromptBuilder": _prompt_builder_handler(),
                               "GuardianToolCatalogBuilder": builder},
             extra_lists={"guardian_model_catalog": _shipped_catalog()})
    monkeypatch.setattr(tick, "guardian_tick_check_model_tier_consistency", lambda *a, **k: None)
    monkeypatch.setattr(tick, "guardian_search_integrations", lambda: {"instances": [], "configurations": []})
    tick.guardian_reasoning_tick_run({"prompt": "Investigate"})
    sent = json.loads(seen[0]["model_params"])
    assert (sent["tier"], sent["tier_source"], sent["max_tool_def_tokens"]) == ("medium", "guardian_settings", 16000)


def test_the_bridge_is_handed_the_ticks_per_result_ceiling(monkeypatch):
    ctx_guardian, params, settings, plist = _loop_at_budget(_GPT5_MINI_BUDGET, exchanges=0)
    seen = []

    def bridge(args):
        seen.append(args)
        return [{"Type": 1, "Contents": {"tool_result": {"tool_call_id": args["tool_call_id"], "tool_name": "ip",
                                                         "status": "ok", "ok": True, "result": "fine"}, "audit": {}}}]

    _run_one_tick(monkeypatch, ctx_guardian, settings, plist,
                  [_completion(tool_calls=[_tool_call("a", "ip", {"ip": "8.8.8.8"})])], {"GuardianToolBridge": bridge})
    assert seen[0]["evidence_truncate_bytes"] == 138720 and seen[0]["evidence_head_tail_bytes"] == 69296


def test_the_bridge_and_the_tick_cut_at_the_same_number_when_a_turn_makes_several_calls(monkeypatch):
    size = {"model_id": "gpt-5-mini", "size_class": "large", "params_b": None}   # a large model runs every call of a turn
    ctx_guardian, params, settings, plist = _loop_at_budget(_GPT5_MINI_BUDGET, size=size, exchanges=0)
    seen = []

    def bridge(args):
        seen.append(args)
        return [{"Type": 1, "Contents": {"tool_result": {"tool_call_id": args["tool_call_id"], "tool_name": "ip",
                                                         "status": "ok", "ok": True, "result": "R" * 100000}, "audit": {}}}]

    calls = [_tool_call(c, "ip", {"ip": "8.8.8.{}".format(i)}) for i, c in enumerate(("a", "b", "c"))]
    _outcome, ctx, _llm = _run_one_tick(monkeypatch, ctx_guardian, settings, plist, [_completion(tool_calls=calls)],
                                        {"GuardianToolBridge": bridge})
    split = _GPT5_MINI_BUDGET * 4 * tick.GUARDIAN_TICK_TURN_RESULTS_BUDGET_SHARE_PERCENT // 100 // 3
    assert split < 138720
    assert [a["evidence_truncate_bytes"] for a in seen] == [split] * 3
    assert [a["evidence_head_tail_bytes"] for a in seen] == [(split - 128) // 2] * 3
    saved = [m for m in ctx["Guardian"]["Loop"]["messages"] if m.get("role") == "tool"]
    assert len(saved) == 3 and all(len(m["content"]) <= split + 100 for m in saved)
    assert tick.guardian_tick_bridge_limits({"limits": params["limits"]}, 138720) == params["limits"]   # a single call: as is


def test_the_tool_list_is_trimmed_from_the_tail_only_when_the_fixed_prompt_would_crowd_out_the_conversation():
    catalog = _tools_of_tokens(16000, count=20)
    system = [{"role": "system", "content": "S" * (13000 * 4)}]
    kept, dropped = tick.guardian_tick_fit_catalog(catalog, system, 28258, 22606)
    assert dropped > 0 and kept == catalog[:len(kept)]          # a prefix: the highest-priority tools stay
    fixed = _est(system) + tick.guardian_tick_request_margin_tokens(28258)
    floor = tick._guardian_tick_result_reserve_tokens(tick.GUARDIAN_TICK_RESULT_RESERVE_FLOOR_BYTES)
    assert fixed + _est(kept) + floor <= 28258 < fixed + _est(catalog[:len(kept) + 1]) + floor
    assert tick.guardian_tick_fit_catalog(catalog, system, 173400) == (catalog, 0)     # fits: untouched
    assert tick.guardian_tick_fit_catalog(catalog, system, None) == (catalog, 0)       # no budget: untouched
    assert tick.guardian_tick_fit_catalog([], system, 28258) == ([], 0)
    huge_system = [{"role": "system", "content": "S" * (30000 * 4)}]
    assert tick.guardian_tick_fit_catalog(catalog, huge_system, 28258) == (catalog, 0)   # nothing a tool list can fix


def test_the_incident_details_limit_follows_the_budget():
    long_details = "Q" * 90000
    original = tick.demisto.incident
    try:
        tick.demisto.incident = lambda: {"id": "7", "name": "n", "details": long_details, "CustomFields": {"guardiantriggersource": "x"}}
        floor = tick.guardian_tick_incident_context_message()["content"]
        wide = tick.guardian_tick_incident_context_message(34680)["content"]
    finally:
        tick.demisto.incident = original
    assert floor.count("Q") == 2000 and wide.count("Q") == 34680 and "…[truncated]" in wide


def test_the_tier_check_compares_the_resolved_size_and_ignores_an_auto_dropdown(monkeypatch):
    _mock_integration_search(monkeypatch, instances=[_guardian_instance(model_tier="auto")])
    assert tick.guardian_tick_check_model_tier_consistency("large", None, "catalogue (gpt-5-mini)") is None
    # an old default "small" on an instance for a catalogued model: one short note, never the warning
    _mock_integration_search(monkeypatch, instances=[_guardian_instance(model_tier="small")])
    note = tick.guardian_tick_check_model_tier_consistency("large", None, "catalogue (gpt-5-mini)")
    assert note.startswith("Model size note:") and "\n" not in note and "WARNING" not in note
    assert 'declares "small"' in note and 'this run uses "large" (catalogue (gpt-5-mini))' in note
    # a size an operator set (settings or override) that the dropdown contradicts is still a warning
    for source in ("guardian_settings", "override", "default (model not in the catalogue; set model_tier in guardian_settings)"):
        warning = tick.guardian_tick_check_model_tier_consistency("large", None, source)
        assert "Model-tier configuration WARNING" in warning and 'declares "small"' in warning, source


def test_compaction_without_a_count_cap_is_driven_by_tokens_alone():
    messages = [{"role": "system", "content": "S"}] + [{"role": "user", "content": "u" * 400} for _ in range(60)]
    state = {}
    assert tick.guardian_tick_compact_messages(messages, None, state) is messages  # no cap, no budget: untouched
    assert tick.guardian_tick_compact_messages(messages, None, state, 100000) is messages
    cut = tick.guardian_tick_compact_messages(messages, None, state, 2000)
    assert len(cut) < len(messages) and _est(cut) <= 2000 and state["dropped_count"] > 0
    plan = tick.guardian_tick_compact_plan(messages, None, 100000)
    assert plan["needed"] is False and tick.guardian_tick_compact_plan(messages, None, 2000)["needed"] is True


# --- the conclusion keeps its analysis after the quality-gate nudge ----------------------------------------


_ANALYSIS = ("Evidence: the host WKS-FIN-0087 beaconed every 60 seconds to 185.220.101.47, a known Cobalt Strike "
             "C2 address. Rationale: the cadence and the process lineage match a staged loader.")


def _gate_run(monkeypatch, first, second):
    writes = []
    monkeypatch.setattr(tick, "guardian_set_incident_fields", lambda iid, fields: writes.append(fields) or {"ok": True, "data": {}})
    llm = _llm_handler_sequence([_completion(content=first), _completion(content=second)])
    _install(monkeypatch, command_handlers={"GuardianPromptBuilder": _prompt_builder_handler(),
                                            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
                                            "guardian-llm-chat": llm})
    first_outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    return first_outcome, writes


def test_after_a_nudge_the_posted_conclusion_is_the_held_analysis_then_the_final_reply(monkeypatch):
    block = '```json\n{"verdict":"Benign","confidence":90,"techniques":[],"summary":"%s"}\n```' % _VALID_SUMMARY
    final_block = '```json\n{"verdict":"Suspicious","confidence":60,"techniques":[],"summary":"%s"}\n```' % _VALID_SUMMARY
    first, writes = _gate_run(monkeypatch, _ANALYSIS + "\n" + block, "Revised: nothing corroborates Benign.\n" + final_block)
    assert first["reschedule"] is True
    loop = tick.guardian_ctx_read("Loop")
    assert loop["held_conclusion"] == _ANALYSIS  # the verdict block is not part of it
    second = tick.guardian_reasoning_tick_run(first["next_args"])
    narration = second["narration"]
    assert narration.count(_ANALYSIS) == 1
    assert narration.index(_ANALYSIS) < narration.index("Revised: nothing corroborates Benign.")
    assert _ANALYSIS + "\n\nRevised: nothing corroborates Benign." in narration
    assert "held_conclusion" not in tick.guardian_ctx_read("Loop")  # used once
    assert [(w["guardianverdict"], w["guardianconfidence"]) for w in writes if "guardianverdict" in w] == [("Suspicious", 60)]


def test_after_a_nudge_a_final_reply_that_already_has_the_analysis_is_not_duplicated(monkeypatch):
    block = '```json\n{"verdict":"Benign","confidence":90,"techniques":[],"summary":"%s"}\n```' % _VALID_SUMMARY
    final_block = '```json\n{"verdict":"Suspicious","confidence":60,"techniques":[],"summary":"%s"}\n```' % _VALID_SUMMARY
    first, _writes = _gate_run(monkeypatch, _ANALYSIS + "\n" + block, _ANALYSIS + "\nRevised.\n" + final_block)
    second = tick.guardian_reasoning_tick_run(first["next_args"])
    assert second["narration"].count(_ANALYSIS) == 1


def test_a_conclusion_without_a_nudge_is_unchanged(monkeypatch):
    monkeypatch.setattr(tick, "guardian_tick_conclusion_gaps", lambda *a, **k: ([], False))
    monkeypatch.setattr(tick, "guardian_set_incident_fields", lambda iid, fields: {"ok": True, "data": {}})
    text = _ANALYSIS + '\n```json\n{"verdict":"Malicious","confidence":95,"techniques":[],"summary":"%s"}\n```' % _VALID_SUMMARY
    llm = _llm_handler_sequence([_completion(content=text)])
    _install(monkeypatch, command_handlers={"GuardianPromptBuilder": _prompt_builder_handler(),
                                            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
                                            "guardian-llm-chat": llm})
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate 8.8.8.8"})
    assert outcome["reschedule"] is False and outcome["narration"].count(_ANALYSIS) == 1
    assert "held_conclusion" not in tick.guardian_ctx_read("Loop")


def test_the_held_verdict_path_also_keeps_the_analysis(monkeypatch):
    block = '```json\n{"verdict":"Malicious","confidence":95,"techniques":[],"summary":"%s"}\n```' % _VALID_SUMMARY
    first, writes = _gate_run(monkeypatch, _ANALYSIS + "\n" + block,
                              "<|start|>assistant<|channel|>commentary to=functions.ip <|call|>")
    second = tick.guardian_reasoning_tick_run(first["next_args"])
    assert "verdict held back by the conclusion gate" in second["narration"]
    assert second["narration"].count(_ANALYSIS) == 1 and second["narration"].startswith("Guardian Agent Loop concluded")
    assert [(w["guardianverdict"], w["guardianconfidence"]) for w in writes if "guardianverdict" in w] == [("Suspicious", 65)]


def test_the_held_conclusion_helpers():
    assert tick.guardian_tick_strip_verdict_block("Analysis.\n```json\n{\"verdict\": \"Benign\"}\n```") == "Analysis."
    assert tick.guardian_tick_strip_verdict_block('Analysis. {"verdict": "Benign", "confidence": 5}') == "Analysis."
    assert tick.guardian_tick_strip_verdict_block('Keep ```json\n{"other": 1}\n``` this') .endswith("this")
    assert tick.guardian_tick_hold_conclusion(None, "Long analysis here.\n```json\n{\"verdict\": \"X\"}\n```") == "Long analysis here."
    assert tick.guardian_tick_hold_conclusion("Long analysis here.", "Short.") == "Long analysis here."  # never replaced by less
    state = {"held_conclusion": "Held."}
    assert tick.guardian_tick_with_held_conclusion(state, "Final.") == "Held.\n\nFinal." and "held_conclusion" not in state
    assert tick.guardian_tick_with_held_conclusion({}, "Final.") == "Final."


def test_call_compact_passes_the_runs_budget_and_render_cap(monkeypatch):
    handler = _compact_handler(kept_messages=[{"role": "user", "content": "recent-1"}])
    _install(monkeypatch, command_handlers={"GuardianCompact": handler})
    plan = {"needed": True, "system_message": {"role": "system", "content": "sys"}, "prior_checkpoint": None,
            "dropped": [{"role": "user", "content": "old-1"}], "kept": [{"role": "user", "content": "recent-1"}]}
    settings = {"max_input_tokens": 173400, "limits": tick.guardian_derive_limits(173400)}
    assert tick.guardian_tick_call_compact(plan, settings)["ok"] is True
    assert handler.calls[0]["max_input_tokens"] == 173400 and handler.calls[0]["tool_render_chars"] == 17340
    # without settings the call is as before
    assert tick.guardian_tick_call_compact(plan)["ok"] is True
    assert "max_input_tokens" not in handler.calls[1] and "tool_render_chars" not in handler.calls[1]


def test_the_repeated_call_record_keeps_a_capped_copy_of_a_large_result():
    small = {"tool_name": "ip", "status": "ok", "result": {"a": 1}}
    assert tick.guardian_tick_cacheable_result(small) is small
    big = {"tool_name": "ip", "status": "ok", "result": "H" + "m" * 200000 + "T", "truncated": False}
    kept = tick.guardian_tick_cacheable_result(big)
    assert kept is not big and big["result"].startswith("H") and len(big["result"]) == 200002   # the caller's dict is untouched
    assert len(kept["result"]) < tick.GUARDIAN_TICK_EXECUTED_RESULT_MAX_CHARS + 200 and kept["truncated"] is True
    assert kept["result"].startswith("H") and kept["result"].endswith("T") and "characters omitted" in kept["result"]
    structured = tick.guardian_tick_cacheable_result({"result": [{"k": "v" * 100}] * 2000})
    assert len(structured["result"]) < tick.GUARDIAN_TICK_EXECUTED_RESULT_MAX_CHARS + 200


def test_executed_calls_stays_small_across_ticks_of_large_results(monkeypatch):
    ctx_guardian, params, settings, plist = _loop_at_budget(_GPT5_MINI_BUDGET, exchanges=0)
    huge = {"status": "ok", "ok": True, "result": "Z" * 900000}
    _outcome, ctx, _llm = _run_one_tick(
        monkeypatch, ctx_guardian, settings, plist,
        [_completion(tool_calls=[_tool_call("a", "getIncidents", {"id": "1"})])],
        {"GuardianToolBridge": _tool_bridge_handler(default_result=huge)})
    entries = ctx["Guardian"]["Loop"]["executed_calls"]
    assert len(entries) == 1
    assert len(json.dumps(next(iter(entries.values())))) < tick.GUARDIAN_TICK_EXECUTED_RESULT_MAX_CHARS + 1000


# --- compaction never drops the pinned head or the newest result -----------------------------------------------


def _first_turn_loop(budget, catalog_tokens, prompt_tokens=13000):
    lim = tick.guardian_derive_limits(budget)
    settings = {"max_input_tokens": budget, "batch_cap": lim["batch_cap"], "limits": lim}
    sysmsg = {"role": "system", "content": "S" * (prompt_tokens * 4)}
    pin = {"role": "system", "content": "YOU ARE ALREADY WORKING THIS INCIDENT -- id 42 " + "d" * lim["incident_details_chars"]}
    task = {"role": "user", "content": "<untrusted-case-data>Investigate incident 42</untrusted-case-data>"}
    asst = {"role": "assistant", "content": "", "tool_calls": [_tool_call("c1", "getEntries", {})]}
    res = {"tool_call_id": "c1", "tool_name": "getEntries", "status": "ok", "ok": True, "result": "Z" * 900000}
    tool = tick.guardian_tick_tool_message(res, lim["evidence_truncate_bytes"])
    catalog = [{"type": "function", "function": {"name": "t{}".format(i), "description": "x" * (catalog_tokens * 4 // 30)}}
               for i in range(30)]
    return settings, [sysmsg, pin, task, asst, tool], catalog


def test_a_medium_model_with_no_record_keeps_the_pin_the_task_and_its_first_result():
    """The reviewer's case: B=28,258 (no record, so the settings fallback), a ~13k-token system prompt, a 10k-token
    tool list and one first-turn result at the 22,606-byte ceiling. It used to compact to [system, breadcrumb]."""
    settings, messages, catalog = _first_turn_loop(_FALLBACK_BUDGET, 10000)
    head, _rest = tick.guardian_split_protected_head(messages)
    catalog, trimmed = tick.guardian_tick_fit_catalog(catalog, head, _FALLBACK_BUDGET, settings["limits"]["evidence_truncate_bytes"])
    assert trimmed > 0 and len(catalog) >= 1          # the tool list gives first
    out = tick.guardian_tick_compact_for_persist(messages, settings, {}, catalog)
    assert [m["role"] for m in out] == ["system", "system", "user", "assistant", "tool"]
    assert out[1]["content"].startswith("YOU ARE ALREADY WORKING") and out[2]["content"].startswith("<untrusted-case-data>")
    assert _est(out, catalog) <= _FALLBACK_BUDGET
    assert out[-1]["content"].startswith('{"tool_call_id"')


def test_when_the_fixed_part_and_one_result_cannot_fit_the_result_is_shrunk_not_the_pin():
    settings, messages, catalog = _first_turn_loop(_FALLBACK_BUDGET, 10000)
    out = tick.guardian_tick_compact_for_persist(messages, settings, {}, catalog)      # with the FULL tool list
    assert [m["role"] for m in out] == ["system", "system", "user", "assistant", "tool"]
    assert out[1] == messages[1] and out[2] == messages[2] and out[0] == messages[0]   # the head, verbatim
    assert len(out[-1]["content"]) < len(messages[-1]["content"]) and "cut to fit the input budget" in out[-1]["content"]
    assert _est(out, catalog) <= _FALLBACK_BUDGET


def test_the_head_is_split_by_position_and_a_checkpoint_or_breadcrumb_ends_it():
    sysmsg = {"role": "system", "content": "s"}
    pin = {"role": "system", "content": "YOU ARE ALREADY WORKING THIS INCIDENT"}
    task = {"role": "user", "content": "go"}
    crumb = {"role": "user", "content": tick.GUARDIAN_BREADCRUMB_PREFIX + "3 turns dropped"}
    checkpoint = {"role": "system", "content": "CONVERSATION CHECKPOINT", "guardian_checkpoint": True}
    other = {"role": "assistant", "content": "a"}
    assert tick.guardian_split_protected_head([sysmsg, pin, task, other]) == ([sysmsg, pin, task], [other])
    assert tick.guardian_split_protected_head([sysmsg, task, other]) == ([sysmsg, task], [other])
    assert tick.guardian_split_protected_head([sysmsg, pin, crumb, other]) == ([sysmsg, pin], [crumb, other])
    assert tick.guardian_split_protected_head([sysmsg, pin, task, checkpoint, other]) == ([sysmsg, pin, task], [checkpoint, other])
    assert tick.guardian_split_protected_head([sysmsg, checkpoint, task]) == ([sysmsg], [checkpoint, task])
    assert tick.guardian_split_protected_head([]) == ([], []) and tick.guardian_split_protected_head([sysmsg]) == ([sysmsg], [])
    assert tick.GUARDIAN_COMPACTION_BREADCRUMB_PREFIX == tick.GUARDIAN_BREADCRUMB_PREFIX


def test_the_result_ceiling_is_clamped_to_the_room_left_and_the_bridge_gets_the_same_number():
    settings, messages, catalog = _first_turn_loop(_FALLBACK_BUDGET, 10000)
    settings["evidence_truncate_bytes"] = settings["limits"]["evidence_truncate_bytes"]   # as the tick's settings carry it
    room = tick.guardian_tick_result_room_chars(messages, catalog, _FALLBACK_BUDGET)
    assert 0 < room < 22606                                       # the full tool list leaves less than the ceiling
    cap = tick.guardian_tick_result_cap_for_turn(settings, 1, room)
    assert cap == max(room, tick.GUARDIAN_TICK_MIN_RESULT_BYTES) and cap < 22606
    assert tick.guardian_tick_bridge_limits(settings, cap)["evidence_truncate_bytes"] == cap
    # plenty of room: the ceiling stands; no budget: no clamp
    assert tick.guardian_tick_result_cap_for_turn(settings, 1, 10 ** 6) == 22606
    assert tick.guardian_tick_result_cap_for_turn({"evidence_truncate_bytes": 16384}, 2, None) == 16384
    assert tick.guardian_tick_result_room_chars(messages, catalog, None) is None


def test_the_tool_list_is_trimmed_from_the_tail_to_leave_room_for_one_result_and_never_the_head():
    catalog = _tools_of_tokens(16000, count=20)
    head = [{"role": "system", "content": "S" * (13000 * 4)}, {"role": "system", "content": "YOU ARE ALREADY WORKING " + "d" * 20000},
            {"role": "user", "content": "<untrusted-case-data>x</untrusted-case-data>"}]
    kept, dropped = tick.guardian_tick_fit_catalog(catalog, head, 28258, 22606)
    fixed = _est(head) + tick.guardian_tick_request_margin_tokens(28258)
    floor = tick._guardian_tick_result_reserve_tokens(16384)
    assert dropped > 0 and kept == catalog[:len(kept)]
    assert fixed + _est(kept) + floor <= 28258 < fixed + _est(catalog[:len(kept) + 1]) + floor
    assert tick.guardian_tick_fit_catalog(catalog, head, 173400, 138720) == (catalog, 0)
    assert tick.guardian_tick_fit_catalog(catalog, head, None, 22606) == (catalog, 0)
    assert tick.guardian_tick_fit_catalog([], head, 28258, 22606) == ([], 0)
    crowded = [{"role": "system", "content": "S" * (30000 * 4)}]
    assert tick.guardian_tick_fit_catalog(catalog, crowded, 28258, 22606) == (catalog, 0)   # nothing a tool list can fix


def test_the_dropped_transcript_archive_is_bounded_by_bytes_and_each_message_by_the_result_ceiling():
    big = [{"role": "tool", "tool_call_id": "c{}".format(i), "content": "A" + "m" * 300000 + "Z"} for i in range(4)]
    capped = tick.guardian_tick_cap_archive_messages(big, 22606)
    assert all(len(m["content"]) < 22606 + 100 and m["content"].startswith("A") and m["content"].endswith("Z") for m in capped)
    assert "archive cut" in capped[0]["content"] and big[0]["content"].startswith("Amm")      # the original is untouched
    assert tick.guardian_tick_cap_archive_messages([{"role": "user", "content": "short"}], 22606) == [{"role": "user", "content": "short"}]
    assert tick.guardian_tick_cap_archive_messages(big, None)[0] is big[0]
    rows = [{"run_id": "r", "tick": i, "dropped_messages": capped} for i in range(40)]      # ~90 KB per row
    trimmed = tick.guardian_tick_trim_archive_rows(rows, 2 * 1024 * 1024)
    assert len(json.dumps(trimmed)) <= 2 * 1024 * 1024 and 0 < len(trimmed) < 40
    assert trimmed[-1]["tick"] == 39 and trimmed[0]["tick"] == 40 - len(trimmed)                # the OLDEST rows go
    one_huge = [{"run_id": "r", "tick": 1, "dropped_messages": big}]
    fitted = tick.guardian_tick_trim_archive_rows(one_huge, 100000)
    assert len(fitted) == 1 and len(json.dumps(fitted)) <= 100000                              # the newest row is cut, not lost


def test_persisting_the_archive_applies_the_message_cap_and_the_byte_cap(monkeypatch):
    stored = {}
    old_rows = [{"run_id": "old", "tick": i, "dropped_messages": [{"role": "user", "content": "q" * 50000}]} for i in range(60)]

    def create_list(args):
        stored["rows"] = json.loads(args["listData"])
        return [{"Type": 1, "Contents": "ok"}]

    _install(monkeypatch, command_handlers={"createList": create_list, "GetTime": lambda a: [{"Type": 1, "Contents": "2026-10-10T00:00:00Z"}],
                                            "getList": lambda a: [{"Type": 1, "Contents": json.dumps(old_rows)}]})
    tick.guardian_tick_persist_dropped_transcript([{"role": "tool", "content": "T" * 400000}], "run", 7, 22606, 300000)
    rows = stored["rows"]
    assert len(json.dumps(rows)) <= 300000 and rows[-1]["tick"] == 7
    assert all(len(m["content"]) < 22606 + 100 for m in rows[-1]["dropped_messages"])


def test_the_held_analysis_strip_cuts_the_verdict_wherever_the_parser_finds_it():
    v = ('{"verdict": "Malicious", "confidence": 90, "techniques": ["T1059"], "summary": "Encoded PowerShell from Word macro '
         'contacted 1.2.3.4 which is on a blocklist."}')
    cases = {
        "fenced": "Analysis A.\n```json\n" + v + "\n```",
        "trailing bare": "Analysis B.\n" + v,
        "mid bare + prose": "Analysis C.\n" + v + "\nNext I would check the host.",
        "fenced + trailing prose": "Analysis D.\n```\n" + v + "\n```\nThanks.",
    }
    for name, text in cases.items():
        assert tick.guardian_tick_parse_verdict_block(text), name
        stripped = tick.guardian_tick_strip_verdict_block(text)
        assert '"verdict"' not in stripped and "{" not in stripped, name          # the parser's verdict is gone
        assert stripped.startswith("Analysis"), name
    assert tick.guardian_tick_strip_verdict_block(cases["mid bare + prose"]) == "Analysis C.\n\nNext I would check the host."
    assert tick.guardian_tick_strip_verdict_block(cases["fenced + trailing prose"]).endswith("Thanks.")
    held = {"held_conclusion": tick.guardian_tick_hold_conclusion(None, cases["mid bare + prose"])}
    posted = tick.guardian_tick_with_held_conclusion(held, "Corrected.\n```json\n" + v + "\n```")
    assert posted.count("Malicious") == 1 and posted.startswith("Analysis C.")        # only the final reply's verdict remains


# --- the reserved result room shrinks before tools are cut; the gate's tools are never cut; the task is bounded -------


def test_the_reserved_result_room_shrinks_to_the_floor_before_any_tool_is_trimmed():
    head = [{"role": "system", "content": "S" * (13000 * 4)}]
    fixed = _est(head) + tick.guardian_tick_request_margin_tokens(28258)
    floor = tick._guardian_tick_result_reserve_tokens(16384)
    full = tick._guardian_tick_result_reserve_tokens(22606)
    assert full > floor
    # a tool list that fits next to the head with only the FLOOR reserved (but not with the full ceiling reserved)
    tools_that_fit = 28258 - fixed - floor - 400
    catalog = _tools_of_tokens(tools_that_fit, count=20)
    assert fixed + _est(catalog) + full > 28258 >= fixed + _est(catalog) + floor
    assert tick.guardian_tick_fit_catalog(catalog, head, 28258, 22606) == (catalog, 0)     # nothing trimmed
    # the next size up needs the tail trimmed, still with the floor reserved
    bigger = _tools_of_tokens(tools_that_fit + 1500, count=20)
    kept, dropped = tick.guardian_tick_fit_catalog(bigger, head, 28258, 22606)
    assert dropped > 0 and fixed + _est(kept) + floor <= 28258


def test_the_tools_the_gate_requires_are_never_trimmed_while_they_are_on_the_list():
    head = [{"role": "system", "content": "S" * (13000 * 4)}]
    catalog = _tools_of_tokens(12000, count=20, gate_tools=True)       # CaseNote and Memory are the last two
    kept, dropped = tick.guardian_tick_fit_catalog(catalog, head, 28258, 22606)
    names = [t["function"]["name"] for t in kept]
    assert dropped > 0 and "GuardianCaseNote" in names and "GuardianMemory" in names
    assert names[:-2] == [t["function"]["name"] for t in catalog][:len(names) - 2]      # the rest is cut from the tail
    assert tick.GUARDIAN_GATE_REQUIRED_TOOLS == ("GuardianCaseNote", "GuardianMemory")
    # the constant is exactly what the gate asks for when the tool was offered
    for name in tick.GUARDIAN_GATE_REQUIRED_TOOLS:
        steps, _ = tick.guardian_tick_conclusion_gaps({}, None, [{"function": {"name": name}}], True)
        assert len(steps) == 1


@pytest.mark.parametrize("size", [_MEDIUM_SIZE, None], ids=["medium", "small"])
def test_with_a_skill_preloaded_at_28258_the_gate_tools_stay_offered_and_the_request_fits(monkeypatch, size):
    ctx_guardian, params, settings, plist = _loop_at_budget(_FALLBACK_BUDGET, size=size, exchanges=6, gate_tools=True,
                                                            scope_incident="999")
    skill_tokens = int(_FALLBACK_BUDGET * tick.GUARDIAN_TICK_SKILL_MAX_BUDGET_SHARE)
    assert _est(ctx_guardian["Loop"]["messages"][:1]) > 13000 + skill_tokens - 50                     # the skill is in the prompt
    seen = []

    def bridge(args):
        seen.append(args)
        return [{"Type": 1, "Contents": {"tool_result": {"tool_call_id": args["tool_call_id"], "tool_name": "getIncidents",
                                                         "status": "ok", "ok": True, "result": "N" + "Z" * 900000}, "audit": {}}}]

    outcome, ctx, llm = _run_one_tick(monkeypatch, ctx_guardian, settings, plist,
                                      [_completion(tool_calls=[_tool_call("n0", "getIncidents", {"id": "999"})])],
                                      {"GuardianToolBridge": bridge})
    sent = llm.calls[0]
    names = [t["function"]["name"] for t in sent["tools"]]
    assert "GuardianCaseNote" in names and "GuardianMemory" in names            # so the gate keeps requiring both steps
    assert _est(sent["messages"], sent["tools"]) <= _FALLBACK_BUDGET
    _assert_request_keeps_head_and_newest_result(sent["messages"], "call5", 6)
    # the clamped number is what the bridge received, and it is not below the 16,384-byte floor
    assert seen and 16000 <= seen[0]["evidence_truncate_bytes"] <= params["limits"]["evidence_truncate_bytes"]
    saved = ctx["Guardian"]["Loop"]["messages"]
    new = [m for m in saved if m.get("tool_call_id") == "n0"][0]
    assert len(new["content"]) <= seen[0]["evidence_truncate_bytes"] + 100
    assert _est(saved, sent["tools"]) <= _FALLBACK_BUDGET


def test_a_large_model_at_173400_still_gets_every_tool_and_full_size_results(monkeypatch):
    ctx_guardian, params, settings, plist = _loop_at_budget(_GPT5_MINI_BUDGET, size=_LARGE_SIZE, exchanges=4, gate_tools=True)
    outcome, ctx, llm = _run_one_tick(monkeypatch, ctx_guardian, settings, plist, [_completion(content="done")])
    sent = llm.calls[0]
    assert len(sent["tools"]) == len(ctx_guardian["ToolCatalog"]) and "were left out" not in outcome["narration"]
    newest = _assert_request_keeps_head_and_newest_result(sent["messages"], "call3", 4)
    assert len(newest["content"]) >= 138000


def test_the_task_is_cut_to_the_incident_details_limit_with_head_and_tail():
    prompt = "START-" + "p" * 200000 + "-END"
    limit = tick.guardian_derive_limits(28258)["incident_details_chars"]            # 5,651
    cut = tick.guardian_tick_cut_task(prompt, limit, 28258)
    assert len(cut) < limit + 150 and cut.startswith("START-") and cut.endswith("-END") and "was cut to fit the input budget" in cut
    # never below the floor that keeps the shipped playbook prompts whole, and not at all without a budget
    short_prompt = "q" * 3500
    assert tick.guardian_tick_cut_task(short_prompt, 2000, 6000) == short_prompt
    assert tick.guardian_tick_cut_task(prompt, 5651, None) == prompt
    assert tick.guardian_tick_cut_task(prompt, None, 28258) == prompt
    assert tick.guardian_tick_cut_task("small", 5651, 28258) == "small"


def test_a_huge_prompt_cannot_make_the_pinned_head_exceed_the_budget(monkeypatch):
    llm = _llm_handler_sequence([_completion(content="No further action; routine activity.")])
    settings = dict(_AUTO_SETTINGS, max_input_tokens=_FALLBACK_BUDGET)
    ctx = _install(monkeypatch, settings=settings, command_handlers={
        "guardian-llm-chat": _snapshotting(llm), "GuardianPromptBuilder": _prompt_builder_handler("P" * 40000),
        "GuardianToolCatalogBuilder": _catalog_builder_handler([])}, extra_lists={"guardian_model_catalog": _shipped_catalog()})
    monkeypatch.setattr(tick, "guardian_search_integrations", lambda: {"instances": [], "configurations": []})
    huge = "HEAD-" + "x" * 2000000 + "-TAIL"
    outcome = tick.guardian_reasoning_tick_run({"prompt": huge})
    sent = llm.calls[0]["messages"]
    task = [m for m in sent if m["role"] == "user" and m["content"].startswith("<untrusted-case-data>")][0]
    assert "HEAD-" in task["content"] and "-TAIL" in task["content"] and len(task["content"]) < 6200
    assert _est(sent) <= _FALLBACK_BUDGET
    assert ctx["Guardian"]["Loop"]["messages"][2]["content"] == task["content"]


# --- the turn limit follows the model's size ------------------------------------------------------------------------


def _tick_at(monkeypatch, tick_number, size, settings_extra=None, overrides=None, completions=None):
    settings = dict(_AUTO_SETTINGS, max_input_tokens=_FALLBACK_BUDGET)
    settings.update(settings_extra or {})
    ctx_guardian, params, settings, plist = _loop_at_budget(_FALLBACK_BUDGET, settings=settings, size=size, exchanges=0,
                                                            tick=tick_number)
    if overrides:
        plist["overrides"] = overrides
        params = tick.guardian_resolve_model_params(settings, plist, size)
        ctx_guardian["Loop"]["model_params"] = params
    outcome, ctx, llm = _run_one_tick(monkeypatch, ctx_guardian, settings, plist, completions or [_completion(content="done")])
    return outcome, ctx, llm, params


@pytest.mark.parametrize("size,limit", [(None, 25), (_MEDIUM_SIZE, 40), (_LARGE_SIZE, 60)], ids=["small-25", "medium-40", "large-60"])
def test_the_forced_summary_comes_at_the_resolved_turn_limit(monkeypatch, size, limit):
    # one turn before the last: an ordinary model turn with tools
    outcome, _ctx, llm, params = _tick_at(monkeypatch, limit - 2, size)
    assert params["max_ticks"] == limit and llm.calls[0]["tool_choice"] != "none" and "ceiling" not in outcome["narration"]
    # the last turn: the forced, no-tools summary, and the narration names the limit
    outcome, ctx, llm, _p = _tick_at(monkeypatch, limit - 1, size)
    assert llm.calls[0]["tool_choice"] == "none" and "tools" not in llm.calls[0]
    assert "reached its tick ceiling (MAX_TICKS={})".format(limit) in outcome["narration"]
    assert ctx["Guardian"]["Loop"]["status"] == "done" and outcome["reschedule"] is False


def test_an_explicit_settings_value_and_an_override_beat_the_size(monkeypatch):
    # a large model with MAX_TICKS=10 in settings stops at 10, not 60
    outcome, _c, llm, params = _tick_at(monkeypatch, 9, _LARGE_SIZE, settings_extra={"MAX_TICKS": 10})
    assert (params["max_ticks"], params["max_ticks_source"]) == (10, "guardian_settings")
    assert llm.calls[0]["tool_choice"] == "none" and "(MAX_TICKS=10)" in outcome["narration"]
    # overrides.max_ticks in the profile List beats the settings value
    outcome, _c, llm, params = _tick_at(monkeypatch, 4, _LARGE_SIZE, settings_extra={"MAX_TICKS": 10}, overrides={"max_ticks": 5})
    assert (params["max_ticks"], params["max_ticks_source"]) == (5, "override")
    assert llm.calls[0]["tool_choice"] == "none" and "(MAX_TICKS=5)" in outcome["narration"]


def test_tick0_names_the_turn_limit_in_the_model_profile_line(monkeypatch):
    llm = _llm_handler_sequence([_completion(content="No further action; routine activity.")])
    ctx = _install(monkeypatch, settings=dict(_AUTO_SETTINGS, max_input_tokens=_FALLBACK_BUDGET),
                   command_handlers={"guardian-llm-chat": llm, "GuardianPromptBuilder": _prompt_builder_handler(),
                                     "GuardianToolCatalogBuilder": _catalog_builder_handler([])},
                   extra_lists={"guardian_model_catalog": _shipped_catalog()})
    monkeypatch.setattr(tick, "guardian_search_integrations", lambda: {"instances": [], "configurations": []})
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Investigate"})
    params = ctx["Guardian"]["Loop"]["model_params"]
    assert (params["max_ticks"], params["max_ticks_source"]) == (25, "tier")
    assert "Turn limit 25 (tier)." in outcome["narration"]


def test_the_polling_window_covers_the_turn_limit():
    small = {"model_params": {"max_ticks": 25}}
    large = {"model_params": {"max_ticks": 60}}
    assert tick.guardian_tick_poll_timeout(small, 15) == 25 * (15 + 120) == 3375
    assert tick.guardian_tick_poll_timeout(large, 15) == 8100 and tick.guardian_tick_poll_timeout(large, 15) > 60 * 40 * 2 // 1 - 1500
    assert tick.guardian_tick_poll_timeout({}, None) >= tick.GUARDIAN_TICK_POLL_TIMEOUT_SECONDS        # never below the floor
    assert tick.guardian_tick_poll_timeout(None, 15) == 25 * 135
    assert tick.guardian_tick_poll_timeout({"model_params": {"max_ticks": 1}}, 10) == tick.GUARDIAN_TICK_POLL_TIMEOUT_SECONDS


def test_main_reschedules_with_a_window_that_covers_a_60_turn_run(monkeypatch):
    seen = {}

    class FakeScheduled:
        def __init__(self, command, next_run_in_seconds, args, timeout_in_seconds):
            seen.update(command=command, next=next_run_in_seconds, timeout=timeout_in_seconds)

    monkeypatch.setattr(tick, "ScheduledCommand", FakeScheduled)
    monkeypatch.setattr(tick, "guardian_reasoning_tick_run", lambda args: tick.guardian_tick_outcome(
        "n", True, cadence=15, next_args={}, loop_state={"model_params": {"max_ticks": 60}}))
    monkeypatch.setattr(tick, "return_results", lambda r: None)
    monkeypatch.setattr(tick.demisto, "args", lambda: {})
    tick.main()
    assert seen["timeout"] == 8100 and seen["next"] == 15


@pytest.mark.parametrize("reader", ["core-get-issues", "core-get-cases", "core-get-case-extra-data", "core-get-issue-recommendations"])
def test_reading_the_issue_its_case_or_the_remediation_text_is_not_corroboration(reader):
    state = {}
    tick.guardian_tick_record_evidence(state, reader, {"issue_id": "1"}, {"status": "ok", "result": {}})
    assert "corroborated" not in state["evidence"]


# --- Ported from the Cortex platform edition: evidence packet, triage mode, turn cap, run totals, forced turn ---

VERDICT_TEXT = '```json\n{"verdict":"Benign","confidence":90,"techniques":[],"summary":"Expected maintenance by the owner team."}\n```'


TRIAGE_BLOCK = {
    "severity": "high",
    "investigation_type": "endpoint_threat",
    "confidence": 82,
    "likely_benign": False,
    "escalate": True,
    "summary": "A signed-looking binary on a finance laptop beacons to a new domain; high because it runs as an admin.",
    "key_entities": {"identities": ["jdoe"], "ips": [], "hosts": ["fin-lt-042"], "hashes": [], "domains": ["update-cdn.example"], "urls": [], "emails": []},
    "next_step": "Isolate the laptop and pull the binary for analysis.",
}


TRIAGE_ARGS = {"prompt": "Triage this issue", "assessment_mode": "triage", "max_ticks": "6"}


LONG_PROSE = "The binary named in the packet was first seen today on one laptop and contacts a newly registered domain. " * 2


EARLIER_SESSION = {"guardiantickcount": 3, "guardiancostusd": 0.0123, "guardiantoolcalls": 4, "guardiantoolfailures": 1,
                   "guardianapprovalsrequested": 0, "guardiantoolsused": "getIncidents,findIndicators"}


def _triage_install(monkeypatch, completions, route=None, incident_custom=None):
    llm = _llm_handler_sequence(completions)
    ctx = _install(
        monkeypatch,
        command_handlers={
            "GuardianPromptBuilder": _prompt_builder_handler(),
            "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
            "guardian-llm-chat": llm,
        },
    )
    if route:
        ctx["Guardian"] = {"Route": route}
    if incident_custom is not None:
        monkeypatch.setattr(tick.demisto, "incident", lambda: {"id": "999", "name": "n", "type": "t", "severity": 3,
                                                                "CustomFields": incident_custom})
    return ctx, llm


def _packet(incident_id="999", generated=1000, corroborated=False, rendered="EVIDENCE PACKET (pre-fetched)\nasset: dev"):
    return {"incident_id": incident_id, "generated": generated, "rendered": rendered, "calls": 4, "failures": 1, "corroborated": corroborated}


def _run_two_ticks(args):
    first = tick.guardian_reasoning_tick_run(dict({"prompt": "Investigate"}, **args))
    assert first["reschedule"] is True
    return tick.guardian_reasoning_tick_run(dict({"prompt": "Investigate"}, **args))


def _forced_setup(monkeypatch, completions, max_ticks="2", catalog=None):
    """Tick 0 calls getIncidents; tick 1 is the forced no-tools turn (max_ticks=2). Returns the recorders."""
    llm = _llm_handler_sequence(completions)
    bridge_calls, notes = [], []

    def bridge(args):
        bridge_calls.append(args.get("tool_name"))
        return _tool_bridge_handler(default_result={"ok": True, "status": "ok", "content": "{}"})(args)

    ctx = _install(monkeypatch, command_handlers={
        "GuardianPromptBuilder": _prompt_builder_handler(),
        "GuardianToolCatalogBuilder": _catalog_builder_handler(catalog if catalog is not None else [{"type": "function", "function": {"name": "getIncidents"}}]),
        "guardian-llm-chat": llm, "GuardianToolBridge": bridge,
        "GuardianCaseNote": lambda args: notes.append(args["content"]) or [{"Type": 1, "Contents": "ok"}],
    })
    written = []
    monkeypatch.setattr(tick, "guardian_set_incident_fields", lambda iid, fields: written.append(fields) or {"ok": True, "data": {}})
    return ctx, llm, bridge_calls, notes, written


def _tick0_with_packet(monkeypatch, packet):
    import time
    packet = dict(packet, generated=int(time.time()))
    return _run_tick0(
        monkeypatch,
        {"prompt": "Investigate", "use_prebuilt": "true"},
        ctx_guardian={"SystemPrompt": "PROMPT", "ToolCatalog": _PREBUILT_TOOLS, "Evidence": packet},
    )


def _triage_text(block=None, prose=LONG_PROSE):
    return "{}\n\n```json\n{}\n```".format(prose, json.dumps(block or TRIAGE_BLOCK))


def _tool_only(call_id="c9"):
    """What gpt-oss-120b answered a no-tools turn with: a recovered tool call and empty content."""
    return _completion(content="", tool_calls=[_tool_call(call_id, "getIncidents", {"id": "999"})])


def _run_second_session(monkeypatch, args, earlier=None):
    ctx = _install(monkeypatch, command_handlers={
        "GuardianPromptBuilder": _prompt_builder_handler(),
        "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
        "guardian-llm-chat": _llm_handler_sequence([_completion(content="Verdict: benign", usage={"prompt_tokens": 1000, "completion_tokens": 200, "total_tokens": 1200})]),
    })
    fields = dict(EARLIER_SESSION if earlier is None else earlier)
    ctx["_incidents"]["999"]["CustomFields"].update(fields)
    monkeypatch.setattr(tick.demisto, "incident", lambda: {"id": "999", "CustomFields": dict(fields)})
    tick.guardian_reasoning_tick_run(dict({"prompt": "Investigate"}, **args))
    return ctx












def test_evidence_packet_is_read_only_for_the_same_fresh_incident(monkeypatch):
    monkeypatch.setattr(tick, "guardian_ctx_read", lambda key, default=None: _packet() if key == "Evidence" else default)
    assert tick.guardian_tick_evidence_packet("999", now=1500)["incident_id"] == "999"
    assert tick.guardian_tick_evidence_packet(999, now=1500) is not None
    assert tick.guardian_tick_evidence_packet("1000", now=1500) is None          # another incident's packet
    assert tick.guardian_tick_evidence_packet("999", now=1000 + 7200) is None   # an earlier run's packet


def test_evidence_packet_and_route_survive_an_appended_second_copy(monkeypatch):
    # A packet built twice on one incident (the playbook run again) used to arrive as a list and was dropped silently.
    ctx = {"Evidence": [_packet(rendered="old packet"), _packet(rendered="new packet")],
           "Route": [{"family": "identity"}, {"family": "attack_path"}]}
    monkeypatch.setattr(tick, "guardian_ctx_read", lambda key, default=None: ctx.get(key, default))
    assert tick.guardian_tick_evidence_packet("999", now=1500)["rendered"] == "new packet"
    assert tick.guardian_tick_ctx_latest("Route") == {"family": "attack_path"}


@pytest.mark.parametrize("bad", [None, "text", {}, {"incident_id": "999"}, {"incident_id": "999", "rendered": "  "}, {"incident_id": "999", "rendered": 5}])
def test_evidence_packet_ignores_malformed_context(monkeypatch, bad):
    monkeypatch.setattr(tick, "guardian_ctx_read", lambda key, default=None: bad if key == "Evidence" else default)
    assert tick.guardian_tick_evidence_packet("999") is None


def test_tick0_pins_the_evidence_packet_after_the_incident_pin(monkeypatch):
    outcome, ctx, llm, _ = _tick0_with_packet(monkeypatch, _packet())
    sent = llm.calls[0]["messages"]
    assert sent[1]["content"].startswith("YOU ARE ALREADY WORKING")
    assert sent[2] == {"role": "system", "content": "EVIDENCE PACKET (pre-fetched)\nasset: dev"}
    assert tick.GUARDIAN_UNTRUSTED_OPEN in sent[3]["content"]
    assert "Evidence packet: pinned (4 calls, 1 failed)." in outcome["narration"]


def test_the_evidence_packet_survives_compaction_as_part_of_the_protected_head(monkeypatch):
    outcome, ctx, llm, _ = _tick0_with_packet(monkeypatch, _packet())
    head, rest = tick.guardian_split_protected_head(llm.calls[0]["messages"])
    assert [m["role"] for m in head] == ["system", "system", "system", "user"]
    assert head[2]["content"].startswith("EVIDENCE PACKET")


def test_a_corroborated_packet_counts_as_corroboration_for_the_gate(monkeypatch):
    outcome, ctx, llm, _ = _tick0_with_packet(monkeypatch, _packet(corroborated=True))
    assert ctx["Guardian"]["Loop"]["evidence"]["corroborated"] is True
    outcome, ctx, llm, _ = _tick0_with_packet(monkeypatch, _packet(corroborated=False))
    assert not ctx["Guardian"]["Loop"].get("evidence", {}).get("corroborated")


def test_no_packet_means_no_extra_message(monkeypatch):
    outcome, ctx, llm, _ = _run_tick0(
        monkeypatch, {"prompt": "Investigate", "use_prebuilt": "true"}, ctx_guardian={"SystemPrompt": "PROMPT", "ToolCatalog": _PREBUILT_TOOLS})
    assert [m["role"] for m in llm.calls[0]["messages"][:3]] == ["system", "system", "user"]
    assert "Evidence packet" not in outcome["narration"]


# --- Cortex platform readers in the gate and the tier-0 set ---------------------------------------


def test_triage_valid_block_ends_the_run_and_writes_no_verdict(monkeypatch):
    stale = {"guardianverdict": "Suspicious", "guardianconfidence": 65}
    ctx, llm = _triage_install(monkeypatch, [_completion(content=_triage_text())],
                               route={"family": "endpoint", "assessment_mode": "verdict"}, incident_custom=stale)
    outcome = tick.guardian_reasoning_tick_run(dict(TRIAGE_ARGS))

    assert outcome["reschedule"] is False
    assert len(llm.calls) == 1  # no corrective turn and no verdict-extraction call
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "done" and loop["assessment_mode"] == "triage"
    assert loop["triage_block"]["investigation_type"] == "endpoint_threat"
    assert loop["triage_block"]["severity"] == "high" and loop["triage_block"]["confidence"] == 82
    assert "newly registered domain" in loop["conclusion"] and '"investigation_type"' in loop["conclusion"]
    assert "Triage block: severity high, type endpoint_threat" in outcome["narration"]
    custom = ctx["_incidents"]["999"]["CustomFields"]
    assert not any(k.startswith("guardianverdict") or k in ("guardianblastradius", "guardiangateaction", "guardianattacktechniques")
                   for k in custom), custom  # neither a verdict write nor the tick-0 reset of an earlier verdict
    assert "guardianconfidence" not in custom


def test_triage_mode_pins_the_triage_block_instruction_not_the_routes(monkeypatch):
    ctx, llm = _triage_install(monkeypatch, [_completion(content=_triage_text())],
                               route={"family": "endpoint", "assessment_mode": "verdict"})
    tick.guardian_reasoning_tick_run(dict(TRIAGE_ARGS))
    pinned = [m["content"] for m in ctx["Guardian"]["Loop"]["messages"] if m.get("role") == "system" and "Assessment mode" in m["content"]]
    assert pinned and "Assessment mode: triage (end with the triage block)" in pinned[0]
    assert "end with the verdict block" not in pinned[0]


def test_the_triage_pin_overrides_the_shared_prompts_block_note_and_memory_steps(monkeypatch):
    ctx, _llm = _triage_install(monkeypatch, [_completion(content=_triage_text())],
                                route={"family": "endpoint", "assessment_mode": "verdict"})
    tick.guardian_reasoning_tick_run(dict(TRIAGE_ARGS))
    pinned = next(m["content"] for m in ctx["Guardian"]["Loop"]["messages"] if m.get("role") == "system" and "TRIAGE RUN" in m["content"])
    assert "REPLACES the verdict block" in pinned
    assert "Do NOT call GuardianCaseNote or GuardianMemory" in pinned
    for row in tick.guardian_triage_default_table()["types"]:
        assert row["name"] in pinned
    for key in ("severity", "investigation_type", "confidence", "likely_benign", "escalate", "summary", "key_entities", "next_step",
                "analysis", "recommendations", "complexity"):
        assert key in pinned
    assert "critical" in pinned and pinned.index("YOU ARE ALREADY WORKING") == 0  # still the protected pin message


def test_the_assessment_mode_arg_wins_over_the_route_and_without_it_the_route_is_used(monkeypatch):
    ctx, _llm = _triage_install(monkeypatch, [_completion(content="ok " * 50 + '\n```json\n{"verdict": "Benign", "confidence": 80, "techniques": [], "summary": "Known pipeline doing its usual job."}\n```')],
                                route={"family": "endpoint", "assessment_mode": "verdict"})
    tick.guardian_reasoning_tick_run({"prompt": "Investigate"})
    assert ctx["Guardian"]["Loop"]["assessment_mode"] == "verdict"
    assert tick.guardian_tick_effective_assessment_mode({"assessment_mode": "TRIAGE"}, {"assessment_mode": "verdict"}) == "triage"
    assert tick.guardian_tick_effective_assessment_mode({"assessment_mode": "bogus"}, {"assessment_mode": "verdict"}) == "verdict"
    assert tick.guardian_tick_effective_assessment_mode({"assessment_mode": "posture"}, None) is None  # no posture mode in this edition
    assert tick.guardian_tick_effective_assessment_mode({}, {"assessment_mode": "none"}) is None


def test_the_incident_pin_states_the_family_and_mode(monkeypatch):
    monkeypatch.setattr(tick.demisto, "incident", lambda: {"id": "7", "name": "n", "type": "t", "severity": 1, "CustomFields": {}})
    monkeypatch.setattr(tick, "guardian_ctx_read", lambda key, default=None: {"family": "identity", "assessment_mode": "verdict"} if key == "Route" else default)
    content = tick.guardian_tick_incident_context_message()["content"]
    assert "family: identity. Assessment mode: verdict (end with the verdict block)" in content


# --- triage mode --------------------------------------------------------------------------------------------------


def test_triage_missing_block_gets_one_corrective_nudge_then_accepts_the_block(monkeypatch):
    prose = "I looked at the packet. The storage account is public and holds production exports, which is serious."
    ctx, llm = _triage_install(monkeypatch, [
        _completion(content=prose),
        _completion(content="```json\n{}\n```".format(json.dumps(TRIAGE_BLOCK))),
    ])
    first = tick.guardian_reasoning_tick_run(dict(TRIAGE_ARGS))

    assert first["reschedule"] is True
    assert "no valid triage block -- forcing corrective retry (1/1)" in first["narration"]
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "running" and loop["no_verdict_fails"] == 1
    nudge = loop["messages"][-1]
    assert nudge["role"] == "user" and "triage block" in nudge["content"]
    assert "identity_threat" in nudge["content"] and "other" in nudge["content"] and "critical" in nudge["content"]
    assert "verdict" not in nudge["content"].lower()

    second = tick.guardian_reasoning_tick_run(dict(TRIAGE_ARGS))
    assert second["reschedule"] is False
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "done" and loop["triage_block"]["investigation_type"] == "endpoint_threat"
    assert "storage account is public" in loop["conclusion"]  # the first reply's analysis is kept
    assert len(llm.calls) == 2


def test_triage_still_invalid_after_the_nudge_ends_without_a_block_and_without_extraction(monkeypatch):
    bad = dict(TRIAGE_BLOCK, investigation_type="not_a_type")
    ctx, llm = _triage_install(monkeypatch, [_completion(content=_triage_text(bad)), _completion(content=_triage_text(bad))])
    tick.guardian_reasoning_tick_run(dict(TRIAGE_ARGS))
    second = tick.guardian_reasoning_tick_run(dict(TRIAGE_ARGS))

    assert second["reschedule"] is False
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "done" and loop["triage_block"] is None and loop["conclusion"]
    assert "No valid triage block" in second["narration"]
    assert len(llm.calls) == 2  # two model turns, no extraction call
    assert not any(k.startswith("guardianverdict") for k in ctx["_incidents"]["999"]["CustomFields"])


def test_a_short_invalid_triage_reply_is_still_nudged(monkeypatch):
    ctx, _llm = _triage_install(monkeypatch, [_completion(content='```json\n{"severity": "high"}\n```')])
    outcome = tick.guardian_reasoning_tick_run(dict(TRIAGE_ARGS))
    assert outcome["reschedule"] is True and "forcing corrective retry" in outcome["narration"]


def test_triage_forced_conclusion_at_the_turn_cap_parses_the_block_and_writes_no_verdict(monkeypatch):
    # max_ticks=1 -> the very first tick is the last one: a no-tools forced summary.
    ctx, llm = _triage_install(monkeypatch, [_completion(content=_triage_text())], incident_custom={"guardianverdict": "Benign"})
    outcome = tick.guardian_reasoning_tick_run({"prompt": "Triage this issue", "assessment_mode": "triage", "max_ticks": 1})

    assert outcome["reschedule"] is False and "tick ceiling" in outcome["narration"]
    assert len(llm.calls) == 1 and llm.calls[0]["tool_choice"] == "none"
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "done" and loop["triage_block"]["severity"] == "high"
    assert "newly registered domain" in loop["conclusion"]
    assert not any(k.startswith("guardianverdict") for k in ctx["_incidents"]["999"]["CustomFields"])


def test_triage_forced_conclusion_without_a_block_records_none_and_makes_no_extra_call(monkeypatch):
    ctx, llm = _triage_install(monkeypatch, [_completion(content="A long enough prose conclusion with no block at all. " * 4)])
    tick.guardian_reasoning_tick_run({"prompt": "Triage this issue", "assessment_mode": "triage", "max_ticks": 1})
    loop = ctx["Guardian"]["Loop"]
    assert loop["triage_block"] is None and "no block at all" in loop["conclusion"]
    assert len(llm.calls) == 1


def test_triage_uses_the_shipped_defaults_when_the_list_cannot_be_read(monkeypatch):
    # No getList fixture for guardian_triage_types is wired in `_install`, so the read fails and the built-in table is used.
    ctx, _llm = _triage_install(monkeypatch, [_completion(content=_triage_text())])
    tick.guardian_reasoning_tick_run(dict(TRIAGE_ARGS))
    assert ctx["Guardian"]["Loop"]["triage_block"]["investigation_type"] == "endpoint_threat"


def test_triage_validates_against_the_list_when_it_is_readable(monkeypatch):
    llm = _llm_handler_sequence([_completion(content=_triage_text())])
    only_other = {"severities": ["low", "medium", "high", "critical"],
                  "types": [{"name": "identity_threat", "description": "x", "domains": ["detection"], "sub_playbook": "P", "skill": "s"}]}
    ctx = _install(monkeypatch, command_handlers={
        "GuardianPromptBuilder": _prompt_builder_handler(), "GuardianToolCatalogBuilder": _catalog_builder_handler([]),
        "guardian-llm-chat": llm}, extra_lists={"guardian_triage_types": only_other})
    tick.guardian_reasoning_tick_run({"prompt": "t", "assessment_mode": "triage", "max_ticks": 1})
    assert ctx["Guardian"]["Loop"]["triage_block"] is None  # `misconfiguration` is not in this List


def test_the_max_ticks_arg_only_lowers_the_limit():
    assert tick.guardian_tick_apply_turn_cap({"max_ticks": 25}, {"max_ticks": "6"})["max_ticks"] == 6
    assert tick.guardian_tick_apply_turn_cap({"max_ticks": 25}, {"max_ticks": 6})["max_ticks"] == 6
    assert tick.guardian_tick_apply_turn_cap({"max_ticks": 4}, {"max_ticks": "6"})["max_ticks"] == 4
    for bad in ("", "abc", "0", "-3", None, True, "2.5"):
        assert tick.guardian_tick_apply_turn_cap({"max_ticks": 25}, {"max_ticks": bad})["max_ticks"] == 25, bad
    assert tick.guardian_tick_apply_turn_cap({"max_ticks": 25}, {})["max_ticks"] == 25


def test_the_max_ticks_arg_limits_a_running_triage_session(monkeypatch):
    # max_ticks=2: tick 0 calls a tool, tick 1 (>= limit - 1) is the forced summary with no tools.
    call = _tool_call("c1", "getIncidents", {"id": "999"})
    ctx, llm = _triage_install(monkeypatch, [_completion(tool_calls=[call]), _completion(content=_triage_text())])
    ctx_handlers = {"GuardianToolBridge": _tool_bridge_handler(default_result={"ok": True, "content": "{}"})}
    # re-install with the bridge wired
    ctx = _install(monkeypatch, command_handlers=dict({
        "GuardianPromptBuilder": _prompt_builder_handler(), "GuardianToolCatalogBuilder": _catalog_builder_handler([{"type": "function", "function": {"name": "getIncidents"}}]),
        "guardian-llm-chat": llm}, **ctx_handlers))
    first = tick.guardian_reasoning_tick_run({"prompt": "t", "assessment_mode": "triage", "max_ticks": "2"})
    assert first["reschedule"] is True
    second = tick.guardian_reasoning_tick_run({"prompt": "t", "assessment_mode": "triage", "max_ticks": "2"})
    assert second["reschedule"] is False and "tick ceiling" in second["narration"]
    assert llm.calls[-1]["tool_choice"] == "none"
    assert ctx["Guardian"]["Loop"]["triage_block"]["investigation_type"] == "endpoint_threat"


# --- continue_run_totals: a second model session continues the incident's run totals ----------------------------------


def test_continue_run_totals_is_off_by_default_and_the_second_session_starts_from_zero(monkeypatch):
    ctx = _run_second_session(monkeypatch, {})
    fields = ctx["_incidents"]["999"]["CustomFields"]
    assert fields["guardiantickcount"] == 1  # only this session
    assert 0 < fields["guardiancostusd"] < 0.0123
    assert "tick_base" not in ctx["Guardian"]["Loop"]


def test_continue_run_totals_continues_ticks_cost_and_activity(monkeypatch):
    first = _run_second_session(monkeypatch, {})["_incidents"]["999"]["CustomFields"]["guardiancostusd"]
    ctx = _run_second_session(monkeypatch, {"continue_run_totals": "true"})
    fields, loop = ctx["_incidents"]["999"]["CustomFields"], ctx["Guardian"]["Loop"]
    assert fields["guardiantickcount"] == 3 + 1  # the earlier 3 plus this session's one tick
    assert fields["guardiancostusd"] == pytest.approx(0.0123 + first)  # the earlier cost plus this session's turn
    assert loop["cost_usd"] == pytest.approx(0.0123 + first) and loop["tick_base"] == 3
    # the turn limit and the loop's own tick count are this session's, not the run's
    assert loop["tick"] == 1
    assert fields["guardiantoolcalls"] == 4 and fields["guardiantoolfailures"] == 1
    assert fields["guardiantoolsused"] == "getIncidents,findIndicators"


def test_continue_run_totals_keeps_the_other_first_tick_resets(monkeypatch):
    seen = {"verdict_cleared": 0, "dispatch_reset": 0}
    real_clear, real_reset = tick.guardian_tick_clear_stale_verdict, tick.guardian_tick_reset_run_dispatch_counts
    monkeypatch.setattr(tick, "guardian_tick_clear_stale_verdict", lambda *a, **k: seen.__setitem__("verdict_cleared", seen["verdict_cleared"] + 1) or real_clear(*a, **k))
    monkeypatch.setattr(tick, "guardian_tick_reset_run_dispatch_counts", lambda *a, **k: seen.__setitem__("dispatch_reset", seen["dispatch_reset"] + 1) or real_reset(*a, **k))
    _run_second_session(monkeypatch, {"continue_run_totals": "true"})
    assert seen == {"verdict_cleared": 1, "dispatch_reset": 1}


@pytest.mark.parametrize("raw, expected", [(None, False), ("", False), ("false", False), ("no", False), ("true", True), (True, True), ("yes", True), ("garbage", False)])
def test_continue_run_totals_argument_parsing(raw, expected):
    assert tick.guardian_tick_continue_run_totals({"continue_run_totals": raw}) is expected


def test_seed_run_totals_reads_only_sane_numbers_and_never_raises():
    state = {"cost_usd": 0.0}
    assert tick.guardian_tick_seed_run_totals(state, {"CustomFields": {"guardiantickcount": "5", "guardiancostusd": "0.5"}}) == (5, 0.5)
    assert state["tick_base"] == 5 and state["cost_usd"] == 0.5 and "activity" not in state
    for custom in ({"guardiantickcount": -4, "guardiancostusd": -1}, {"guardiantickcount": float("inf"), "guardiancostusd": float("nan")},
                   {"guardiantickcount": True, "guardiancostusd": "abc"}, {}, None):
        state = {"cost_usd": 0.0}
        tick.guardian_tick_seed_run_totals(state, {"CustomFields": custom})
        assert state["tick_base"] == 0 and state["cost_usd"] == 0.0
    tick.guardian_tick_seed_run_totals({}, None)
    tick.guardian_tick_seed_run_totals({}, "junk")


def test_the_yml_declares_continue_run_totals():
    import yaml
    from pathlib import Path
    doc = yaml.safe_load((Path(__file__).parent / "GuardianReasoningTick.yml").read_text())
    arg = {a["name"]: a for a in doc["args"]}["continue_run_totals"]
    assert arg["required"] is False and set(arg["predefined"]) == {"true", "false"}


def test_an_empty_or_unresolved_max_ticks_leaves_the_size_tier_or_settings_limit_alone():
    """The focused session of the triage playbook passes `${inputs.max_ticks}`, empty by default: it must get exactly the
    limit an investigation gets (25 / 40 / 60 by model size, or the settings and profile override)."""
    for limit in (25, 40, 60, 7):
        for raw in ("", "   ", "${inputs.max_ticks}", "${inputs.investigate_max_ticks}", "None", "null", None, [], {}, 0, "0"):
            assert tick.guardian_tick_apply_turn_cap({"max_ticks": limit}, {"max_ticks": raw})["max_ticks"] == limit, (limit, raw)
        assert tick.guardian_tick_apply_turn_cap({"max_ticks": limit}, {"max_ticks": "", "assessment_mode": "verdict"})["max_ticks"] == limit
    assert [tick.GUARDIAN_TIER_PROFILES[t]["max_ticks"] for t in ("small", "medium", "large")] == [25, 40, 60]


# --- the forced conclusion turn returns no text ---------------------------------------------------------------------


def test_a_forced_turn_that_returns_only_a_tool_call_is_asked_once_more_for_text_and_the_call_is_never_run(monkeypatch):
    ctx, llm, bridge_calls, notes, written = _forced_setup(monkeypatch, [
        _completion(tool_calls=[_tool_call("c1", "getIncidents", {"id": "999"})]), _tool_only(), _completion(content=VERDICT_TEXT)])
    second = _run_two_ticks({"max_ticks": "2"})
    assert second["reschedule"] is False and len(llm.calls) == 3
    assert bridge_calls == ["getIncidents"]  # tick 0's call only: the recovered call on the forced path never ran
    retry = [m for m in llm.calls[2]["messages"] if m.get("role") == "user"][-1]
    assert retry["role"] == "user" and "Tools are unavailable" in retry["content"] and "verdict" in retry["content"]
    assert llm.calls[1]["tool_choice"] == "none" and llm.calls[2]["tool_choice"] == "none"
    assert "tools" not in llm.calls[1] and "tools" not in llm.calls[2]
    assert [f["guardianverdict"] for f in written if "guardianverdict" in f] == ["Benign"]  # the retry's verdict block is recorded
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "done" and notes == []  # the model's own text concluded: no fallback note
    assert not any(m.get("tool_calls") for m in loop["messages"][-2:])  # the unanswered tool call is not left in the transcript


def test_a_forced_turn_that_returns_text_is_not_retried(monkeypatch):
    _ctx, llm, _bridge, notes, written = _forced_setup(monkeypatch, [
        _completion(tool_calls=[_tool_call("c1", "getIncidents", {"id": "999"})]), _completion(content=VERDICT_TEXT)])
    _run_two_ticks({"max_ticks": "2"})
    assert len(llm.calls) == 2 and notes == []


def test_text_beside_a_recovered_tool_call_on_the_forced_turn_is_the_conclusion_and_the_call_is_ignored(monkeypatch):
    both = _completion(content=VERDICT_TEXT, tool_calls=[_tool_call("c9", "getIncidents", {"id": "999"})])
    _ctx, llm, bridge_calls, _notes, written = _forced_setup(monkeypatch, [
        _completion(tool_calls=[_tool_call("c1", "getIncidents", {"id": "999"})]), both])
    _run_two_ticks({"max_ticks": "2"})
    assert len(llm.calls) == 2 and bridge_calls == ["getIncidents"]
    assert [f["guardianverdict"] for f in written if "guardianverdict" in f] == ["Benign"]


def test_when_the_retry_also_returns_no_text_a_deterministic_note_is_written_and_no_verdict_is_invented(monkeypatch):
    ctx, llm, bridge_calls, notes, written = _forced_setup(monkeypatch, [
        _completion(tool_calls=[_tool_call("c1", "getIncidents", {"id": "999"})]), _tool_only("c2"), _tool_only("c3")])
    second = _run_two_ticks({"max_ticks": "2"})
    assert len(llm.calls) == 3  # one forced turn and ONE retry, never more
    assert bridge_calls == ["getIncidents"]
    assert second["reschedule"] is False
    loop = ctx["Guardian"]["Loop"]
    assert loop["status"] == "done"
    assert not [f for f in written if "guardianverdict" in f]  # no verdict was invented
    assert len(notes) == 1
    note = notes[0]
    assert "did not conclude within 2 turn(s)" in note and "no verdict" in note
    assert "1 tool call(s), 0 failed" in note and "- getIncidents: ok" in note
    assert "The model did not conclude" in second["narration"] and "Posted as the case note" in second["narration"]
    assert loop["evidence"]["case_noted"] is True


def test_the_no_conclusion_note_is_not_written_twice_when_the_model_already_wrote_one(monkeypatch):
    state = {"evidence": {"case_noted": True}, "activity": {"calls": 0, "failures": 0, "approvals": 0, "tools": []}}
    monkeypatch.setattr(tick, "guardian_execute", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not write a second note")))
    assert tick.guardian_tick_write_no_conclusion_note(state, "999", "text") is False
    assert tick.guardian_tick_write_no_conclusion_note({}, "", "text") is False


def test_the_no_conclusion_text_lists_each_tool_with_its_status():
    state = {"activity": {"calls": 4, "failures": 1, "approvals": 0, "tools": [],
                          "outcomes": [["getIncidents", "ok"], ["getIncidents", "ok"], ["findIndicators", "error"], ["ip", "ok"]]}}
    text = tick.guardian_tick_no_conclusion_text(state, 7, "an empty reply")
    assert "within 7 turn(s)" in text and "4 tool call(s), 1 failed" in text
    assert "- getIncidents: ok x2" in text and "- findIndicators: error" in text and "- ip: ok" in text
    assert "No tool call was made" in tick.guardian_tick_no_conclusion_text({}, 1, "x")
    assert "verdict" not in tick.guardian_tick_no_conclusion_text({}, 1, "x").lower().replace("no verdict", "")


def test_a_held_verdict_is_still_recorded_when_the_model_never_concludes(monkeypatch):
    _ctx, llm, _bridge, notes, _written = _forced_setup(monkeypatch, [
        _completion(tool_calls=[_tool_call("c1", "getIncidents", {"id": "999"})]), _tool_only("c2"), _tool_only("c3")])
    monkeypatch.setattr(tick, "guardian_tick_write_held_verdict", lambda state, iid: "\n\n(held verdict recorded)")
    first = tick.guardian_reasoning_tick_run({"prompt": "Investigate", "max_ticks": "2"})
    loop = _ctx["Guardian"]["Loop"]
    loop["held_verdict"] = {"verdict": "Suspicious", "confidence": 50}
    second = tick.guardian_reasoning_tick_run({"prompt": "Investigate", "max_ticks": "2"})
    assert "held verdict recorded" in second["narration"] and first["reschedule"] is True and len(notes) == 1


def test_a_triage_run_whose_forced_turn_returns_no_text_retries_once_then_leaves_the_fallback_to_the_validation_step(monkeypatch):
    ctx, llm, bridge_calls, notes, written = _forced_setup(monkeypatch, [
        _completion(tool_calls=[_tool_call("c1", "getIncidents", {"id": "999"})]), _tool_only("c2"), _tool_only("c3")])
    second = _run_two_ticks({"max_ticks": "2", "assessment_mode": "triage"})
    assert len(llm.calls) == 3 and bridge_calls == ["getIncidents"] and second["reschedule"] is False
    retry = [m for m in llm.calls[2]["messages"] if m.get("role") == "user"][-1]
    assert "Tools are unavailable" in retry["content"] and "investigation_type" in retry["content"]  # the triage schema is restated
    loop = ctx["Guardian"]["Loop"]
    assert loop["conclusion"] == "" and loop["triage_block"] is None and loop["status"] == "done"
    assert notes == [] and not [f for f in written if "guardianverdict" in f]  # a triage run writes no note and no verdict


def test_a_triage_run_whose_retry_returns_the_block_is_structured(monkeypatch):
    ctx, llm, _bridge, notes, _written = _forced_setup(monkeypatch, [
        _completion(tool_calls=[_tool_call("c1", "getIncidents", {"id": "999"})]), _tool_only("c2"), _completion(content=_triage_text())])
    _run_two_ticks({"max_ticks": "2", "assessment_mode": "triage"})
    assert len(llm.calls) == 3 and ctx["Guardian"]["Loop"]["triage_block"]["investigation_type"] == "endpoint_threat" and notes == []


def test_a_content_filtered_forced_turn_is_not_retried(monkeypatch):
    _ctx, llm, _bridge, notes, _written = _forced_setup(monkeypatch, [
        _completion(tool_calls=[_tool_call("c1", "getIncidents", {"id": "999"})]), _completion(content=None, content_filter=True)])
    second = _run_two_ticks({"max_ticks": "2"})
    assert len(llm.calls) == 2 and "content filter" in second["narration"] and notes == []


def test_the_retry_message_names_the_block_of_the_runs_mode():
    assert "```json" in tick.guardian_tick_forced_retry_message(False)["content"] and '"verdict"' in tick.guardian_tick_forced_retry_message(False)["content"]
    table = tick.guardian_triage_default_table()
    assert '"investigation_type"' in tick.guardian_tick_forced_retry_message(True, table)["content"]


def test_the_pinned_incident_details_never_carry_guardians_own_details_section(monkeypatch):
    section = tick.GUARDIAN_ISSUE_SECTION_GAP + tick.GUARDIAN_ISSUE_SECTION_MARKER + "\nInvestigation: Benign, expected change"
    monkeypatch.setattr(tick.demisto, "incident", lambda: {"id": "7", "name": "n", "type": "t", "severity": 1, "details": "Original text." + section,
                                                          "CustomFields": {}})
    content = tick.guardian_tick_incident_context_message()["content"]
    assert "Original text." in content and "Benign, expected change" not in content and tick.GUARDIAN_ISSUE_SECTION_MARKER not in content


def test_a_triage_block_with_analysis_recommendations_and_complexity_is_stored_whole_and_a_block_without_them_is_still_accepted(monkeypatch):
    block = dict(TRIAGE_BLOCK, analysis="The sender domain was registered the day before the mail arrived.",
                 recommendations=["Block the sender domain"], complexity="medium")
    ctx, _llm = _triage_install(monkeypatch, [_completion(content=_triage_text(block))])
    tick.guardian_reasoning_tick_run(dict(TRIAGE_ARGS))
    stored = ctx["Guardian"]["Loop"]["triage_block"]
    assert stored["analysis"].startswith("The sender domain") and stored["recommendations"] == ["Block the sender domain"]
    assert stored["complexity"] == "medium"
    ctx, _llm = _triage_install(monkeypatch, [_completion(content=_triage_text())])
    tick.guardian_reasoning_tick_run(dict(TRIAGE_ARGS))
    stored = ctx["Guardian"]["Loop"]["triage_block"]
    assert stored["analysis"] == "" and stored["complexity"] == "" and ctx["Guardian"]["Loop"]["status"] == "done"


# --- model routing: the `model` argument of guardian-llm-chat -----------------------------------------------------------

def _snapshot(**extra):
    snap = {"tier": "medium", "tier_source": "guardian_settings", "max_input_tokens": 5000, "max_input_tokens_source": "measured",
            "max_tool_def_tokens": 3000, "max_tool_def_tokens_source": "tier", "profile": None, "max_ticks": 40, "max_ticks_source": "tier",
            "limits": tick.guardian_derive_limits(5000)}
    snap.update(extra)
    return snap


def _routing_run(monkeypatch, snapshot, handler, ctx_extra=None, args=None, tick_no=0):
    monkeypatch.setattr(tick, "guardian_tick_check_model_tier_consistency", lambda t, *a, **k: None)
    ledger_calls = []

    def ledger(call_args):
        ledger_calls.append(call_args)
        return _default_cost_ledger_handler(call_args)

    ctx = _install(monkeypatch, settings=_MEDIUM_SETTINGS, command_handlers={
        "guardian-llm-chat": handler, "GuardianPromptBuilder": _prompt_builder_handler(),
        "GuardianToolCatalogBuilder": _catalog_builder_handler(_PREBUILT_TOOLS), "GuardianCostLedger": ledger})
    guardian = {"SystemPrompt": "P", "ToolCatalog": _PREBUILT_TOOLS, "ModelProfile": snapshot}
    guardian.update(ctx_extra or {})
    ctx["Guardian"] = guardian
    outcome = tick.guardian_reasoning_tick_run(args or {"prompt": "Investigate", "use_prebuilt": "true"})
    return outcome, ctx, ledger_calls


def test_a_routed_snapshot_makes_every_chat_call_carry_the_model(monkeypatch):
    llm = _llm_handler_sequence([dict(_CONCLUSION, model="gpt-5-mini-2025")])
    outcome, ctx, ledger = _routing_run(monkeypatch, _snapshot(model="gpt-5-mini", routed=True), llm)
    assert [call.get("model") for call in llm.calls] == ["gpt-5-mini"]
    assert ctx["Guardian"]["Loop"]["model_params"]["model"] == "gpt-5-mini"
    assert ledger[0]["model"] == "gpt-5-mini-2025"  # the cost is priced by the model that served the call


def test_an_unrouted_or_old_snapshot_never_sends_a_model(monkeypatch):
    for extra in ({}, {"model": "gpt-4o", "routed": False}, {"model": "gpt-4o"}, {"model": "", "routed": True}):
        llm = _llm_handler_sequence([_CONCLUSION])
        _routing_run(monkeypatch, _snapshot(**extra), llm)
        assert "model" not in llm.calls[0], extra


def test_a_run_started_by_hand_without_the_snapshot_never_sends_a_model(monkeypatch):
    llm = _llm_handler_sequence([_CONCLUSION])
    _routing_run(monkeypatch, _snapshot(model="gpt-5-mini", routed=True), llm, args={"prompt": "Investigate", "use_prebuilt": "false"})
    assert "model" not in llm.calls[0]


class _RefusingProvider:
    """guardian-llm-chat that refuses any call carrying `model` with the given error, and answers the others."""

    def __init__(self, tag, completions):
        self.tag, self.completions, self.calls = tag, completions, []

    def __call__(self, args):
        self.calls.append(dict(args))
        if args.get("model"):
            return [{"Type": 4, "Contents": "{} model '{}' is not deployed in this Foundry resource.".format(self.tag, args["model"])}]
        index = len([c for c in self.calls if not c.get("model")]) - 1
        return [{"Type": 1, "Contents": self.completions[min(index, len(self.completions) - 1)]}]


@pytest.mark.parametrize("tag", ["MODEL_NOT_AVAILABLE:", "MODEL_SELECTION_UNSUPPORTED:"])
def test_a_refused_model_falls_back_once_to_the_instance_default_and_says_so(monkeypatch, tag):
    llm = _RefusingProvider(tag, [_CONCLUSION])
    outcome, ctx, _ledger = _routing_run(monkeypatch, _snapshot(model="gpt-5-mini", routed=True), llm)
    assert [c.get("model") for c in llm.calls] == ["gpt-5-mini", None]  # the same call is repeated without the model
    assert "Model routing" in outcome["narration"] and "gpt-5-mini" in outcome["narration"] and "configured model" in outcome["narration"]
    assert ctx["Guardian"]["Loop"]["model_route_dropped"].startswith(tag)
    assert ctx["Guardian"]["Loop"]["status"] == "done"  # the run carries on and concludes


def test_after_a_fallback_no_later_tick_asks_for_the_model_again(monkeypatch):
    loop = _running_loop(model_params=_snapshot(model="gpt-5-mini", routed=True), model_route_dropped="MODEL_NOT_AVAILABLE: x")
    llm = _RefusingProvider("MODEL_NOT_AVAILABLE:", [_CONCLUSION])
    _routing_run(monkeypatch, _snapshot(), llm, ctx_extra=loop, args={"prompt": "x"})
    assert [c.get("model") for c in llm.calls] == [None]


def test_a_routed_later_tick_keeps_sending_the_model_until_it_is_refused(monkeypatch):
    loop = _running_loop(model_params=_snapshot(model="gpt-5-mini", routed=True))
    llm = _llm_handler_sequence([_CONCLUSION])
    _routing_run(monkeypatch, _snapshot(), llm, ctx_extra=loop, args={"prompt": "x"})
    assert llm.calls[0]["model"] == "gpt-5-mini"


def test_an_unrelated_chat_failure_is_not_taken_for_a_refused_model(monkeypatch):
    def failing(args):
        return [{"Type": 4, "Contents": "HTTP 500 server error"}]
    calls = []
    outcome, ctx, _l = _routing_run(monkeypatch, _snapshot(model="gpt-5-mini", routed=True), lambda a: calls.append(a) or failing(a))
    assert len(calls) == 1 and "model_route_dropped" not in ctx["Guardian"]["Loop"]
