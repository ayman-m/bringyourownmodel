"""GuardianProbeModel unit tests -- exercise the probe logic against a SIMULATED provider (window W,
tokenizer ratio R) by monkeypatching guardian_probe_call, so no live model is needed."""
import json

import GuardianProbeModel as P

SIM_WINDOW = 30000
SIM_CHARS_PER_TOKEN = 3.0
NEEDLE = P.GUARDIAN_PROBE_NEEDLE
SIM_TIMEOUTS = []


def _sim_call(messages, tools=None, tool_choice=None, response_format=None, temperature=0, timeout=None):
    """Simulate a provider: window=SIM_WINDOW tokens, ratio=SIM_CHARS_PER_TOKEN chars/token.
    Truncates the OLDEST tokens (the needle at the start) when the input exceeds the window.
    Records every call's per-call `timeout` in SIM_TIMEOUTS."""
    SIM_TIMEOUTS.append(timeout)
    content = messages[0]["content"]
    sent_tokens = int(len(content) / SIM_CHARS_PER_TOKEN)
    if response_format is not None:
        return {"ok": True, "error": None,
                "completion": {"usage": {"prompt_tokens": sent_tokens},
                               "choices": [{"message": {"content": json.dumps({"verdict": "benign"})}}],
                               "finish_reason": "stop"}}
    if tools:
        return {"ok": True, "error": None,
                "completion": {"usage": {"prompt_tokens": sent_tokens},
                               "choices": [{"message": {"content": None,
                                            "tool_calls": [{"id": "c1", "type": "function",
                                                            "function": {"name": "get_ticket", "arguments": "{}"}}]}}],
                               "finish_reason": "tool_calls"}}
    if sent_tokens <= SIM_WINDOW:
        pt = sent_tokens
        reply = NEEDLE if NEEDLE in content else "OK"
    else:
        pt = SIM_WINDOW  # truncated to the window; the needle (oldest) is dropped
        reply = "OK"
    return {"ok": True, "error": None,
            "completion": {"usage": {"prompt_tokens": pt},
                           "choices": [{"message": {"content": reply}}], "finish_reason": "stop"}}


def _patch(monkeypatch):
    monkeypatch.setattr(P, "guardian_probe_call", _sim_call)


def test_padding_is_exact_length_and_varied():
    pad = P._guardian_probe_padding(5000)
    assert len(pad) == 5000
    assert pad[:100] != pad[100:200]  # not trivially repetitive


def test_ratio_two_point_recovers_simulated_ratio(monkeypatch):
    _patch(monkeypatch)
    r = P.guardian_probe_ratio()
    assert r["ok"]
    assert abs(r["chars_per_token"] - SIM_CHARS_PER_TOKEN) < 0.15  # ~3.0


def test_ratio_fails_when_provider_reports_no_tokens(monkeypatch):
    monkeypatch.setattr(P, "guardian_probe_call", lambda *a, **k: {
        "ok": True, "error": None, "completion": {"usage": {}, "choices": [{"message": {"content": "OK"}}]}})
    r = P.guardian_probe_ratio()
    assert not r["ok"] and "prompt_tokens" in r["error"]


def test_window_binary_search_converges_near_simulated_window(monkeypatch):
    _patch(monkeypatch)
    w = P.guardian_probe_window(SIM_CHARS_PER_TOKEN, 131072, 60)
    assert w["ok"]
    # within one binary-search resolution step of the true window
    assert SIM_WINDOW * 0.8 <= w["window"] <= SIM_WINDOW * 1.05
    assert not w["at_ceiling"]


def test_window_reports_at_ceiling_when_ceiling_below_window(monkeypatch):
    _patch(monkeypatch)
    w = P.guardian_probe_window(SIM_CHARS_PER_TOKEN, 10000, 60)  # ceiling under the 30k window
    assert w["ok"] and w["at_ceiling"] and w["window"] == 10000


def test_window_unreliable_when_needle_never_recalled(monkeypatch):
    monkeypatch.setattr(P, "guardian_probe_call", lambda *a, **k: {
        "ok": True, "error": None,
        "completion": {"usage": {"prompt_tokens": 500}, "choices": [{"message": {"content": "I don't know"}}]}})
    w = P.guardian_probe_window(3.0, 131072, 60)
    assert not w["ok"] and "unreliable" in w["error"]


def test_capabilities_detects_tools_and_structured(monkeypatch):
    _patch(monkeypatch)
    caps = P.guardian_probe_capabilities()
    assert caps["tools"] is True
    assert caps["structured_output"] is True


def test_run_end_to_end_recommends_compensated_budget(monkeypatch):
    _patch(monkeypatch)
    out = P.guardian_probe_run({"output_reserve": "4096", "safety_margin": "0.85"})
    assert out["ok"]
    d = out["data"]
    assert d["ratio"]["measured"] is True
    rec = d["recommendation"]["max_input_tokens"]
    # (window-reserve) * safety * (ratio/4) ~= (30000-4096)*0.85*0.75 ~= 16515
    assert 12000 <= rec <= 20000
    md = P.guardian_probe_render(d)
    assert "guardian_settings.max_input_tokens" in md and str(rec) in md


def test_run_falls_back_to_chars4_when_ratio_unavailable(monkeypatch):
    # provider reports no prompt_tokens -> ratio falls back to 4.0, window still works via needle
    def no_usage(messages, tools=None, tool_choice=None, response_format=None, temperature=0, timeout=None):
        c = messages[0]["content"]
        st = int(len(c) / 4.0)
        if tools or response_format:
            return {"ok": True, "error": None, "completion": {"usage": {}, "choices": [{"message": {"content": "{}"}}]}}
        reply = NEEDLE if (NEEDLE in c and st <= 20000) else "OK"
        return {"ok": True, "error": None, "completion": {"usage": {}, "choices": [{"message": {"content": reply}}]}}
    monkeypatch.setattr(P, "guardian_probe_call", no_usage)
    out = P.guardian_probe_run({})
    assert out["ok"]
    assert out["data"]["ratio"]["measured"] is False
    assert out["data"]["ratio"]["chars_per_token"] == 4.0


""" ------------------------- three-bucket latency classification ------------------------- """


def _slow_sim_call(delay_seconds):
    """Like _sim_call, but sleeps `delay_seconds` before answering -- for exercising the
    correct_fast/correct_slow split without real network latency."""
    import time as _time

    def _call(messages, tools=None, tool_choice=None, response_format=None, temperature=0, timeout=None):
        _time.sleep(delay_seconds)
        return _sim_call(messages, tools, tool_choice, response_format, temperature)
    return _call


def test_window_fits_correct_fast_when_within_budget(monkeypatch):
    monkeypatch.setattr(P, "guardian_probe_call", _sim_call)
    outcome, err, pt, elapsed, timeout_suspected = P._guardian_probe_window_fits(
        1000, SIM_CHARS_PER_TOKEN, max_response_seconds=5
    )
    assert outcome == "correct_fast"
    assert err is None
    assert timeout_suspected is False


def test_window_fits_correct_slow_when_recalled_but_over_budget(monkeypatch):
    monkeypatch.setattr(P, "guardian_probe_call", _slow_sim_call(0.05))
    outcome, err, pt, elapsed, timeout_suspected = P._guardian_probe_window_fits(
        1000, SIM_CHARS_PER_TOKEN, max_response_seconds=0.01
    )
    assert outcome == "correct_slow"
    assert elapsed >= 0.05
    assert timeout_suspected is False


def test_window_fits_failed_when_needle_not_recalled(monkeypatch):
    monkeypatch.setattr(P, "guardian_probe_call", lambda *a, **k: {
        "ok": True, "error": None,
        "completion": {"usage": {"prompt_tokens": 500}, "choices": [{"message": {"content": "I don't know"}}]}})
    outcome, err, pt, elapsed, timeout_suspected = P._guardian_probe_window_fits(1000, 3.0, 60)
    assert outcome == "failed"
    assert timeout_suspected is False


def test_window_fits_failed_flags_timeout_suspected_on_timeout_error(monkeypatch):
    monkeypatch.setattr(P, "guardian_probe_call", lambda *a, **k: {
        "ok": False, "error": "request timed out after 120s", "completion": None})
    outcome, err, pt, elapsed, timeout_suspected = P._guardian_probe_window_fits(1000, 3.0, 60)
    assert outcome == "failed"
    assert timeout_suspected is True


def test_window_fits_failed_does_not_flag_timeout_on_unrelated_error(monkeypatch):
    monkeypatch.setattr(P, "guardian_probe_call", lambda *a, **k: {
        "ok": False, "error": "rate limit exceeded (429)", "completion": None})
    outcome, err, pt, elapsed, timeout_suspected = P._guardian_probe_window_fits(1000, 3.0, 60)
    assert outcome == "failed"
    assert timeout_suspected is False  # retryable, but not evidence the MODEL itself is slow


""" ------------------------- guardian_probe_window: new behavior ------------------------- """


def test_window_search_steps_include_floor_and_ceiling_checks(monkeypatch):
    # Live-caught 2026-08-25: the old version only recorded bisection midpoints, silently dropping
    # the floor/ceiling boundary checks from `steps` whenever the search terminated at either one.
    _patch(monkeypatch)
    w = P.guardian_probe_window(SIM_CHARS_PER_TOKEN, 131072, 60)
    assert w["ok"]
    probed_tokens = [s["tokens"] for s in w["steps"]]
    assert P.GUARDIAN_PROBE_WINDOW_FLOOR_TOKENS in probed_tokens  # the floor check


def test_window_speed_limited_at_floor_is_distinct_from_correctness_failure(monkeypatch):
    # The model recalls fine at every size, but every call is slow -- this must NOT be reported as
    # the generic "could not recall a needle" correctness message.
    monkeypatch.setattr(P, "guardian_probe_call", _slow_sim_call(0.05))
    w = P.guardian_probe_window(SIM_CHARS_PER_TOKEN, 131072, max_response_seconds=0.01)
    assert w["ok"] is False
    assert w["speed_limited_at_floor"] is True
    assert "speed-limited" in w["error"].lower()
    assert "not context-limited" in w["error"].lower()


def test_window_truncates_honestly_when_deadline_exhausted_at_floor(monkeypatch):
    _patch(monkeypatch)
    w = P.guardian_probe_window(SIM_CHARS_PER_TOKEN, 131072, 60, deadline_check=lambda: False)
    assert w["ok"] is True
    assert w["truncated"] is True
    assert w["window"] == P.GUARDIAN_PROBE_WINDOW_FLOOR_TOKENS


def test_window_truncates_honestly_mid_search(monkeypatch):
    _patch(monkeypatch)
    calls = {"n": 0}

    def _deadline():
        calls["n"] += 1
        return calls["n"] <= 2  # allow floor + ceiling checks, then exhaust

    w = P.guardian_probe_window(SIM_CHARS_PER_TOKEN, 131072, 60, deadline_check=_deadline)
    assert w["ok"] is True
    assert w["truncated"] is True
    assert "confirmed floor" in w["note"]


def test_window_deadline_check_none_disables_truncation(monkeypatch):
    # None (no deadline_check passed) must behave exactly as before this feature -- used by tests
    # and any caller that doesn't care about the overall run budget.
    _patch(monkeypatch)
    w = P.guardian_probe_window(SIM_CHARS_PER_TOKEN, 131072, 60, deadline_check=None)
    assert w["ok"] is True
    assert "truncated" not in w or not w.get("truncated")


""" ------------------------- correctness_window derivation (in guardian_probe_run) ------------------------- """


def test_run_correctness_window_matches_latency_window_when_uniformly_fast(monkeypatch):
    _patch(monkeypatch)
    out = P.guardian_probe_run({"max_response_seconds": "60"})
    assert out["ok"]
    d = out["data"]
    # sim calls are instant -- correct_fast everywhere the needle is recalled, so the sampled
    # correctness_window should sit at or below the latency-bounded window, never wildly larger.
    assert d["correctness_window"] is not None
    assert d["correctness_window"] <= d["window"]["window"] * 1.1


def test_run_correctness_window_none_when_window_search_itself_failed(monkeypatch):
    monkeypatch.setattr(P, "guardian_probe_call", lambda *a, **k: {
        "ok": True, "error": None,
        "completion": {"usage": {"prompt_tokens": 500}, "choices": [{"message": {"content": "I don't know"}}]}})
    out = P.guardian_probe_run({"max_response_seconds": "60"})
    assert out["ok"]
    assert out["data"]["correctness_window"] is None


""" ------------------------- max_response_seconds resolution ------------------------- """


def test_resolve_max_response_seconds_prefers_explicit_arg():
    seconds, source = P._guardian_probe_resolve_max_response_seconds({"max_response_seconds": "42"}, None)
    assert (seconds, source) == (42, "arg")


def test_resolve_max_response_seconds_live_scales_and_clamps():
    instance = {"request_timeout": 200}
    seconds, source = P._guardian_probe_resolve_max_response_seconds({}, instance)
    assert source == "live"
    # 200 * 0.75 = 150, clamped to the ceiling (100) and to (live_timeout - 5 = 195) -- ceiling wins
    assert seconds == P.GUARDIAN_PROBE_MAX_MAX_RESPONSE_SECONDS


def test_resolve_max_response_seconds_live_respects_floor_clamp():
    instance = {"request_timeout": 10}  # 10 * 0.75 = 7.5 -> below the floor
    seconds, source = P._guardian_probe_resolve_max_response_seconds({}, instance)
    assert source == "live"
    assert seconds == P.GUARDIAN_PROBE_MIN_MAX_RESPONSE_SECONDS


def test_resolve_max_response_seconds_never_exceeds_live_timeout_minus_margin():
    instance = {"request_timeout": 20}  # 20*0.75=15 (floor), but also must stay < 20-5=15
    seconds, source = P._guardian_probe_resolve_max_response_seconds({}, instance)
    assert seconds <= 15


def test_resolve_max_response_seconds_falls_back_when_no_instance():
    seconds, source = P._guardian_probe_resolve_max_response_seconds({}, None)
    assert (seconds, source) == (P.GUARDIAN_PROBE_DEFAULT_MAX_RESPONSE_SECONDS, "fallback")


""" ------------------------- deadline check ------------------------- """


def test_deadline_check_true_when_budget_remains():
    check = P._guardian_probe_deadline_check(run_start=P.time.time(), per_call_seconds=1)
    assert check() is True


def test_deadline_check_false_once_exhausted():
    stale_start = P.time.time() - P.GUARDIAN_PROBE_RUN_DEADLINE_SECONDS
    check = P._guardian_probe_deadline_check(run_start=stale_start, per_call_seconds=1)
    assert check() is False


""" ------------------------- output_reserve: live-read wiring ------------------------- """


def _settings_execute_returning(output_reserve_tokens):
    """A minimal getList double for guardian_settings, returning a Contents dict with just the one
    field this code path cares about."""
    def _execute(command, args, using=None):
        if command == "getList" and args.get("listName") == P.GUARDIAN_PROBE_SETTINGS_LIST_NAME:
            payload = {} if output_reserve_tokens is None else {"output_reserve_tokens": output_reserve_tokens}
            return {"ok": True, "data": [{"Contents": json.dumps(payload)}], "retryable": False, "is_auth_error": False}
        return {"ok": False, "error": "unexpected command", "retryable": False, "is_auth_error": False}
    return _execute


def test_read_settings_output_reserve_happy_path(monkeypatch):
    monkeypatch.setattr(P, "guardian_execute", _settings_execute_returning(8192))
    assert P._guardian_probe_read_settings_output_reserve() == 8192


def test_read_settings_output_reserve_none_when_field_absent(monkeypatch):
    monkeypatch.setattr(P, "guardian_execute", _settings_execute_returning(None))
    assert P._guardian_probe_read_settings_output_reserve() is None


def test_read_settings_output_reserve_none_when_list_unreadable(monkeypatch):
    monkeypatch.setattr(P, "guardian_execute", lambda *a, **k: {
        "ok": False, "error": "boom", "retryable": False, "is_auth_error": False})
    assert P._guardian_probe_read_settings_output_reserve() is None


def test_read_settings_output_reserve_none_when_value_non_numeric(monkeypatch):
    def _execute(command, args, using=None):
        return {"ok": True, "data": [{"Contents": json.dumps({"output_reserve_tokens": "a lot"})}],
                "retryable": False, "is_auth_error": False}
    monkeypatch.setattr(P, "guardian_execute", _execute)
    assert P._guardian_probe_read_settings_output_reserve() is None


def test_read_settings_output_reserve_none_when_value_zero_or_negative(monkeypatch):
    for bad in (0, -100):
        monkeypatch.setattr(P, "guardian_execute", _settings_execute_returning(bad))
        assert P._guardian_probe_read_settings_output_reserve() is None


def test_resolve_output_reserve_prefers_explicit_arg(monkeypatch):
    monkeypatch.setattr(P, "guardian_execute", _settings_execute_returning(8192))
    reserve, source = P._guardian_probe_resolve_output_reserve({"output_reserve": "1234"})
    assert (reserve, source) == (1234, "arg")


def test_resolve_output_reserve_uses_live_value_when_no_explicit_arg(monkeypatch):
    # Live-caught 2026-08-25: this is the actual bug fix -- output_reserve_tokens was designed to be
    # the single source of truth GuardianProbeModel reads, but it never actually read it.
    monkeypatch.setattr(P, "guardian_execute", _settings_execute_returning(8192))
    reserve, source = P._guardian_probe_resolve_output_reserve({})
    assert (reserve, source) == (8192, "live")


def test_resolve_output_reserve_falls_back_when_live_read_fails(monkeypatch):
    monkeypatch.setattr(P, "guardian_execute", lambda *a, **k: {
        "ok": False, "error": "boom", "retryable": False, "is_auth_error": False})
    reserve, source = P._guardian_probe_resolve_output_reserve({})
    assert (reserve, source) == (P.GUARDIAN_PROBE_DEFAULT_OUTPUT_RESERVE, "fallback")


def test_yml_output_reserve_arg_carries_no_default_value():
    # Live-caught 2026-08-25: a yml `defaultValue` here would make the platform pre-fill this arg on
    # every unset-arg invocation, permanently short-circuiting the live-read tier above (the "arg"
    # branch would always win). Guard against silently reintroducing that.
    import pathlib
    import yaml
    yml_path = pathlib.Path(__file__).resolve().parent / "GuardianProbeModel.yml"
    spec = yaml.safe_load(yml_path.read_text())
    output_reserve_arg = next(a for a in spec["args"] if a["name"] == "output_reserve")
    assert "defaultValue" not in output_reserve_arg


def test_run_end_to_end_uses_live_output_reserve_and_records_source(monkeypatch):
    _patch(monkeypatch)
    calibration_writes = {}

    def fake_execute(command, args, using=None):
        if command == "getList" and args.get("listName") == P.GUARDIAN_PROBE_SETTINGS_LIST_NAME:
            return {"ok": True, "data": [{"Contents": json.dumps({"output_reserve_tokens": 8192})}],
                    "retryable": False, "is_auth_error": False}
        if command == "getList":  # calibration / instance-search fallbacks -- not under test here
            return {"ok": False, "error": "item not found", "retryable": False, "is_auth_error": False}
        if command in ("createList", "setList"):
            calibration_writes["called"] = True
            return {"ok": True, "data": [{"Contents": "ok"}], "retryable": False, "is_auth_error": False}
        return {"ok": False, "error": "unexpected command in test: {}".format(command),
                "retryable": False, "is_auth_error": False}

    monkeypatch.setattr(P, "guardian_execute", fake_execute)
    out = P.guardian_probe_run({"max_response_seconds": "60"})
    assert out["ok"]
    rec = out["data"]["recommendation"]
    assert rec["output_reserve"] == 8192
    assert rec["output_reserve_source"] == "live"
    md = P.guardian_probe_render(out["data"])
    assert "read live from guardian_settings.output_reserve_tokens" in md


""" ------------------------- guardian_model_calibration: key + read/merge/write ------------------------- """


def test_calibration_key_uses_all_three_components():
    assert P.guardian_model_calibration_key("GuardianCohere", "prod-1", "command-r") == \
        "GuardianCohere:prod-1:command-r"


def test_calibration_key_falls_back_to_unknown_sentinels():
    key = P.guardian_model_calibration_key(None, None, None)
    assert key == "{}:{}:{}".format(
        P.GUARDIAN_MODEL_CALIBRATION_UNKNOWN_PROVIDER,
        P.GUARDIAN_MODEL_CALIBRATION_UNKNOWN_INSTANCE,
        P.GUARDIAN_MODEL_CALIBRATION_UNKNOWN_MODEL,
    )


def _fake_list_store():
    """A tiny in-memory getList/setList/createList double, keyed by listName."""
    store = {}

    def _execute(command, args, using=None):
        name = args.get("listName")
        if command == "getList":
            if name not in store:
                return {"ok": False, "error": "Item not found (id: {})".format(name),
                         "retryable": False, "is_auth_error": False}
            return {"ok": True, "data": [{"Contents": store[name]}], "retryable": False, "is_auth_error": False}
        if command == "createList":
            store[name] = args.get("listData")
            return {"ok": True, "data": [{"Contents": "created"}], "retryable": False, "is_auth_error": False}
        if command == "setList":
            store[name] = args.get("listData")
            return {"ok": True, "data": [{"Contents": "saved"}], "retryable": False, "is_auth_error": False}
        return {"ok": False, "error": "unexpected command in test: {}".format(command),
                "retryable": False, "is_auth_error": False}
    return store, _execute


def test_calibration_load_bootstraps_missing_list(monkeypatch):
    store, execute = _fake_list_store()
    monkeypatch.setattr(P, "guardian_execute", execute)
    result = P.guardian_model_calibration_load()
    assert result["ok"] and result["data"] == {}
    assert P.GUARDIAN_MODEL_CALIBRATION_LIST_NAME in store  # bootstrap actually created it


def test_calibration_record_and_save_appends_not_overwrites(monkeypatch):
    store, execute = _fake_list_store()
    monkeypatch.setattr(P, "guardian_execute", execute)
    key_a = P.guardian_model_calibration_key("ProviderA", "inst1", "model-a")
    key_b = P.guardian_model_calibration_key("ProviderB", "inst2", "model-b")

    r1 = P.guardian_model_calibration_record_and_save(key_a, {"timestamp": "t1"})
    assert r1["ok"]
    r2 = P.guardian_model_calibration_record_and_save(key_b, {"timestamp": "t2"})
    assert r2["ok"]

    saved = json.loads(store[P.GUARDIAN_MODEL_CALIBRATION_LIST_NAME])
    assert key_a in saved and key_b in saved  # writing key_b did not clobber key_a's history
    assert saved[key_a] == [{"timestamp": "t1"}]
    assert saved[key_b] == [{"timestamp": "t2"}]


def test_calibration_record_and_save_trims_history_to_max():
    store, execute = _fake_list_store()
    P_execute_backup = P.guardian_execute
    try:
        P.guardian_execute = execute
        key = P.guardian_model_calibration_key("P", "i", "m")
        for n in range(P.GUARDIAN_MODEL_CALIBRATION_MAX_HISTORY + 5):
            P.guardian_model_calibration_record_and_save(key, {"n": n})
        saved = json.loads(store[P.GUARDIAN_MODEL_CALIBRATION_LIST_NAME])
        assert len(saved[key]) == P.GUARDIAN_MODEL_CALIBRATION_MAX_HISTORY
        assert saved[key][-1] == {"n": P.GUARDIAN_MODEL_CALIBRATION_MAX_HISTORY + 4}  # newest kept
        assert saved[key][0] == {"n": 5}  # oldest trimmed
    finally:
        P.guardian_execute = P_execute_backup


""" ------------------------- guardian_probe_ratio: observed_model ------------------------- """


def test_ratio_captures_observed_model_when_present(monkeypatch):
    def _call_with_model(messages, tools=None, tool_choice=None, response_format=None, temperature=0, timeout=None):
        r = _sim_call(messages, tools, tool_choice, response_format, temperature)
        r["completion"]["model"] = "command-r:35b-08-2024-q4_K_M"
        return r
    monkeypatch.setattr(P, "guardian_probe_call", _call_with_model)
    r = P.guardian_probe_ratio()
    assert r["ok"]
    assert r["observed_model"] == "command-r:35b-08-2024-q4_K_M"


def test_ratio_observed_model_none_when_absent(monkeypatch):
    _patch(monkeypatch)
    r = P.guardian_probe_ratio()
    assert r["ok"]
    assert r.get("observed_model") is None


""" ------------------------- end-to-end: deadline exhaustion skips capabilities honestly ------------------------- """


def test_run_skips_capabilities_when_deadline_already_exhausted(monkeypatch):
    _patch(monkeypatch)
    monkeypatch.setattr(
        P, "_guardian_probe_deadline_check",
        lambda run_start, max_response_seconds: (lambda: False),
    )
    out = P.guardian_probe_run({"max_response_seconds": "60"})
    assert out["ok"]
    caps = out["data"]["capabilities"]
    assert caps["skipped"] is True
    assert "budget exhausted" in caps["skip_reason"]


""" ------------------------- render: new sections ------------------------- """


def test_render_reports_speed_limited_not_context_limited(monkeypatch):
    _patch(monkeypatch)
    out = P.guardian_probe_run({"max_response_seconds": "60"})
    d = out["data"]
    # Force a divergence to exercise the render branch, without re-running a live search.
    d["correctness_window"] = int(d["window"]["window"] * 2)
    md = P.guardian_probe_render(d)
    assert "speed-limited" in md.lower() or "correctness window" in md.lower()


def test_render_reports_calibration_write_outcome(monkeypatch):
    _patch(monkeypatch)
    out = P.guardian_probe_run({"max_response_seconds": "60"})
    md = P.guardian_probe_render(out["data"])
    assert "guardian_model_calibration" in md


""" ------------------------- guardrail: calibration List is diagnostic-only ------------------------- """


def test_guardian_model_calibration_referenced_only_where_expected():
    # Live-caught-pattern guardrail (mirrors this session's risk-tier gate precedent): nothing may
    # wire guardian_model_calibration's recommended_max_input_tokens into GuardianReasoningTick or
    # GuardianBootstrap's ACTUAL runtime behavior without a deliberate, reviewed change -- the same
    # "over-trusted mis-tiered agent is an incident" principle GUARDIAN_TIER_PROFILES' own comment
    # states. Bootstrap may only SEED the List's shape (one line, checked below); GuardianProbeModel
    # owns all read/merge/write logic.
    import pathlib
    import subprocess

    # Live-caught 2026-08-25: this used to hardcode `parents[2]` as "the pack root", which only
    # holds when this file sits at its real repo depth. Copied flat into an isolated verification
    # directory (exactly what this session's own blob-surgery isolation workflow does before every
    # commit), `parents[2]` silently resolved to the filesystem ROOT, and `grep -r` against `/` hung
    # for minutes instead of failing fast. Walk UP from this file looking for an actual `.git` repo
    # root instead of assuming a fixed depth; skip (not fail, not hang) when none is found within a
    # few levels, since a test copied out of its repo genuinely cannot check "the whole pack".
    here = pathlib.Path(__file__).resolve()
    pack_root = None
    for ancestor in [here] + list(here.parents)[:6]:
        if (ancestor / ".git").exists():
            pack_root = ancestor
            break
    if pack_root is None:
        import pytest
        pytest.skip("no .git repo root found within a few levels of this file -- "
                    "likely running from an isolated copy, not a real checkout")

    result = subprocess.run(
        ["grep", "-rl", "guardian_model_calibration", str(pack_root / "Packs" / "Guardian")],
        capture_output=True, text=True,
    )
    hits = [line for line in result.stdout.splitlines() if line.strip() and "__pycache__" not in line]
    allowed_suffixes = (
        "GuardianProbeModel/GuardianProbeModel.py",
        "GuardianProbeModel/GuardianProbeModel.yml",  # the command's own arg/output docs -- expected
        "GuardianProbeModel/GuardianProbeModel_test.py",
        "GuardianBootstrap/GuardianBootstrap.py",
        "GuardianBootstrap/GuardianBootstrap.yml",  # the command description names the List it seeds
        "GuardianBootstrap/GuardianBootstrap_test.py",
        "Guardian/README.md",  # the pack's own top-level docs mentioning the List's existence/purpose
        "ReleaseNotes/1_0_1.md",  # the release notes describe the probe's record and the Job
        # is documentation, not behavior wiring -- see the README's own "Design notes" section.
    )
    unexpected = [h for h in hits if not any(h.endswith(suffix) for suffix in allowed_suffixes)]
    assert unexpected == [], "guardian_model_calibration referenced outside its owning scripts: {}".format(unexpected)


# --- per-call timeout: one runaway call can no longer outlive XSOAR's script timeout ---------


def test_every_probe_call_carries_a_hard_per_call_timeout(monkeypatch):
    """Live-caught 2026-09-24: a 35B model rambled for 5 minutes on one needle call; the only bound
    was the provider's 300s request timeout, and XSOAR killed the probe with no report. Every call
    of a full run must now send the contract's per-call `timeout`, at 1.25x max_response_seconds."""
    _patch(monkeypatch)
    SIM_TIMEOUTS.clear()
    P.guardian_probe_run({})
    mrs, _source = P._guardian_probe_resolve_max_response_seconds({}, None)
    assert SIM_TIMEOUTS, "the run made no model calls"
    # every measured call carries the 1.25x timeout; the throwaway warm-up has its own (longer) bound
    assert set(SIM_TIMEOUTS) == {P._guardian_probe_call_timeout(mrs), P.GUARDIAN_PROBE_WARM_UP_MAX_SECONDS}
    assert P._guardian_probe_call_timeout(mrs) >= mrs  # a correct-but-slow answer is still observable


def test_call_timeout_is_forwarded_to_guardian_llm_chat(monkeypatch):
    sent = []

    def fake_execute(command, args):
        sent.append((command, dict(args)))
        return {"ok": True, "data": [{"Type": 1, "Contents": {"choices": [{"message": {"content": "OK"}}]}}], "error": None}

    monkeypatch.setattr(P, "guardian_execute", fake_execute)
    P.guardian_probe_call([{"role": "user", "content": "hi"}], timeout=125)
    P.guardian_probe_call([{"role": "user", "content": "hi"}])
    assert sent[0][0] == "guardian-llm-chat" and sent[0][1]["timeout"] == 125
    assert "timeout" not in sent[1][1]  # unset stays unset: the provider default applies


def test_call_timeout_rounds_up_and_scales():
    assert P._guardian_probe_call_timeout(100) == 125
    assert P._guardian_probe_call_timeout(90) == 113
    assert P._guardian_probe_call_timeout(1) == 2


# --- window search order: grow from the floor, then bisect (2026-09-24) -----------------------


def test_window_grows_by_doubling_from_the_floor_then_bisects(monkeypatch):
    """Successes are cheap and failures past the real window are expensive, so the search doubles
    up from the floor and pays for ONE failure before bisecting -- it never jumps to the ceiling
    first (live: a 32K 35B spent its whole budget failing at 131K and 66K)."""
    _patch(monkeypatch)
    w = P.guardian_probe_window(SIM_CHARS_PER_TOKEN, 131072, 60)
    probed = [s["tokens"] for s in w["steps"]]
    floor = P.GUARDIAN_PROBE_WINDOW_FLOOR_TOKENS
    doubling = [floor * 2 ** i for i in range(6)]  # 1000 .. 32000
    assert probed[:6] == doubling
    assert 131072 not in probed  # the ceiling is never probed for a window well below it
    first_failure = next(i for i, s in enumerate(w["steps"]) if s["outcome"] != "correct_fast")
    assert all(s["tokens"] < probed[first_failure] for s in w["steps"][first_failure + 1:])  # then bisect below it
    assert SIM_WINDOW * 0.8 <= w["window"] <= SIM_WINDOW * 1.05


def test_window_truncated_mid_growth_still_reports_a_useful_floor(monkeypatch):
    _patch(monkeypatch)
    calls = {"n": 0}

    def _deadline():
        calls["n"] += 1
        return calls["n"] <= 4  # after the floor: room for four growth steps, then exhausted

    w = P.guardian_probe_window(SIM_CHARS_PER_TOKEN, 131072, 60, deadline_check=_deadline)
    assert w["truncated"] is True and "confirmed floor" in w["note"]
    assert w["window"] >= 8 * P.GUARDIAN_PROBE_WINDOW_FLOOR_TOKENS  # not the bare 1,000-token floor


def test_run_skips_the_window_search_when_the_ratio_calls_used_the_budget(monkeypatch):
    _patch(monkeypatch)
    monkeypatch.setattr(P, "_guardian_probe_deadline_check", lambda run_start, per_call_seconds: (lambda: False))
    out = P.guardian_probe_run({"max_response_seconds": "60"})
    window = out["data"]["window"]
    assert window["ok"] is False and window["steps"] == []
    assert "too slow to calibrate" in window["error"]


def test_deadline_check_budgets_with_the_hard_per_call_bound(monkeypatch):
    seen = {}
    real = P._guardian_probe_deadline_check

    def _spy(run_start, per_call_seconds):
        seen["per_call_seconds"] = per_call_seconds
        return real(run_start, per_call_seconds)

    _patch(monkeypatch)
    monkeypatch.setattr(P, "_guardian_probe_deadline_check", _spy)
    P.guardian_probe_run({"max_response_seconds": "60"})
    assert seen["per_call_seconds"] == P._guardian_probe_call_timeout(60)


def test_capabilities_skips_the_second_call_when_the_budget_runs_out(monkeypatch):
    _patch(monkeypatch)
    SIM_TIMEOUTS.clear()
    caps = P.guardian_probe_capabilities(call_timeout=30, deadline_check=lambda: False)
    assert caps["tools"] is True  # the first check always runs (the caller checked before it)
    assert caps["structured_output"] is False
    assert "budget exhausted" in caps["structured_error"]
    assert len(SIM_TIMEOUTS) == 1


def test_run_checks_capabilities_before_the_window_search(monkeypatch):
    """Two short calls that say whether the model honors tools at all run before the expensive
    window search, so a slow model's search can't leave them skipped."""
    order = []

    def _recording(messages, tools=None, tool_choice=None, response_format=None, temperature=0, timeout=None):
        content = messages[0]["content"]
        order.append("warm" if content == "Reply with exactly: OK" else
                     "caps" if (tools or response_format) else ("window" if NEEDLE in content else "ratio"))
        return _sim_call(messages, tools, tool_choice, response_format, temperature, timeout)

    monkeypatch.setattr(P, "guardian_probe_call", _recording)
    P.guardian_probe_run({"max_response_seconds": "60"})
    assert order[:5] == ["warm", "ratio", "ratio", "caps", "caps"]
    assert "window" in order[4:]


# --- warm-up and the record handed to GuardianModelProfileUpdate -------------------------------------


def test_the_run_warms_the_model_up_first_and_reports_it(monkeypatch):
    _patch(monkeypatch)
    result = P.guardian_probe_run({"max_response_seconds": "60"})
    assert result["ok"] and result["data"]["warm_up"]["ok"] is True
    assert "Warm-up:** the throwaway call took" in P.guardian_probe_render(result["data"])


def test_warm_up_can_be_skipped(monkeypatch):
    seen = []

    def _recording(messages, tools=None, tool_choice=None, response_format=None, temperature=0, timeout=None):
        seen.append(messages[0]["content"])
        return _sim_call(messages, tools, tool_choice, response_format, temperature, timeout)

    monkeypatch.setattr(P, "guardian_probe_call", _recording)
    result = P.guardian_probe_run({"max_response_seconds": "60", "warm_up": "false"})
    assert "Reply with exactly: OK" not in seen
    assert result["data"]["warm_up"]["skipped"] is True
    assert "skipped" in P.guardian_probe_render(result["data"])


def test_a_failed_warm_up_does_not_stop_the_probe(monkeypatch):
    def _failing_first(messages, tools=None, tool_choice=None, response_format=None, temperature=0, timeout=None):
        if messages[0]["content"] == "Reply with exactly: OK":
            return {"ok": False, "completion": None, "error": "model load timed out"}
        return _sim_call(messages, tools, tool_choice, response_format, temperature, timeout)

    monkeypatch.setattr(P, "guardian_probe_call", _failing_first)
    result = P.guardian_probe_run({"max_response_seconds": "60"})
    assert result["ok"] and result["data"]["warm_up"]["ok"] is False
    assert result["data"]["recommendation"]["max_input_tokens"] is not None
    assert "may include a cold start" in P.guardian_probe_render(result["data"])


def test_the_result_carries_the_calibration_record_the_profile_update_reads(monkeypatch):
    _patch(monkeypatch)
    data = P.guardian_probe_run({"max_response_seconds": "60"})["data"]
    rec = data["calibration_record"]
    assert rec["recommended_max_input_tokens"] == data["recommendation"]["max_input_tokens"]
    for key in ("provider", "instance_name", "model", "latency_bounded_window", "chars_per_token",
                "chars_per_token_measured", "capabilities", "capabilities_skipped", "truncated",
                "speed_limited_at_floor", "timestamp"):
        assert key in rec, key


""" ------------------------- model catalogue: lookup, limits, documented budget, the 20% rule ------------------------- """

import pathlib  # noqa: E402

import pytest  # noqa: E402

CATALOG = {
    "checked": "2026-10-09",
    "models": [
        {"id": "gpt-5-mini", "aliases": ["gpt-5-mini-2025-08-07"], "vendor": "OpenAI", "open_weight": False,
         "context_window": 400000, "max_input_tokens": 272000, "max_output_tokens": 128000,
         "supports_tools": True, "supports_structured_output": True, "probe": "skip",
         "provider_limits": [{"provider": "azure-foundry", "context_window": 400000, "max_input_tokens": 272000,
                              "max_output_tokens": 128000}]},
        {"id": "gpt-4.1", "aliases": ["gpt-4.1-2025-04-14"], "vendor": "OpenAI", "open_weight": False,
         "context_window": 1047576, "max_input_tokens": None, "max_output_tokens": 32768,
         "supports_tools": True, "supports_structured_output": True, "probe": "skip",
         "provider_limits": [{"provider": "azure-foundry", "context_window": 300000, "max_input_tokens": None,
                              "max_output_tokens": 32768}]},
        {"id": "command-a-03-2025", "aliases": ["hf:CohereLabs/c4ai-command-a-03-2025", "foundry:Cohere-command-a"],
         "vendor": "Cohere", "open_weight": True, "context_window": 256000, "max_input_tokens": None,
         "max_output_tokens": 8000, "supports_tools": True, "supports_structured_output": True, "probe": "confirm",
         "provider_limits": [{"provider": "azure-foundry", "context_window": None, "max_input_tokens": 131072,
                              "max_output_tokens": 8182}]},
        {"id": "gemini-2.5-pro", "aliases": ["vertex:gemini-2.5-pro"], "vendor": "Google", "open_weight": False,
         "context_window": 1048576, "max_input_tokens": None, "max_output_tokens": 65536, "probe": "skip",
         "provider_limits": []},
        {"id": "mistral-small-2506", "aliases": [], "vendor": "Mistral AI", "open_weight": True,
         "context_window": 131072, "max_input_tokens": None, "max_output_tokens": None, "probe": "confirm",
         "provider_limits": [{"provider": "vertex", "context_window": 32768, "max_input_tokens": None,
                              "max_output_tokens": 4096, "versions": ["mistral-small-2503"]}]},
        {"id": "command-r:35b", "aliases": ["ollama:command-r:35b"], "vendor": "Cohere", "open_weight": True,
         "context_window": 128000, "max_input_tokens": None, "max_output_tokens": 4000, "probe": "confirm",
         "provider_limits": []},
    ],
}


def _id(name):
    model = P.guardian_catalog_lookup(CATALOG, name)
    return model["id"] if model else None


def test_lookup_matches_the_id_an_alias_and_ignores_case():
    assert _id("gpt-5-mini") == "gpt-5-mini"
    assert _id("gpt-5-mini-2025-08-07") == "gpt-5-mini"          # an alias, exact
    assert _id("Cohere-command-a") == "command-a-03-2025"       # `foundry:` prefix removed from the alias, case ignored
    assert _id("COHERE-COMMAND-A") == "command-a-03-2025"
    assert _id("CohereLabs/c4ai-command-a-03-2025") == "command-a-03-2025"  # `hf:` prefix removed


def test_lookup_strips_a_dated_suffix_only_after_the_exact_name_fails():
    assert _id("gpt-4.1-2025-04-14") == "gpt-4.1"                # an alias, found exactly
    assert _id("gpt-5-mini-2026-01-02") == "gpt-5-mini"          # -YYYY-MM-DD
    assert _id("gpt-5-mini-20260102") == "gpt-5-mini"            # -YYYYMMDD
    assert _id("gemini-2.5-pro@20260102") == "gemini-2.5-pro"    # @YYYYMMDD
    assert _id("gpt-5-mini-0102") == "gpt-5-mini"                # -MMDD
    assert _id("mistral-small-2506") == "mistral-small-2506"     # an id: its -2506 is a year-month, not a date
    assert _id("gpt-5-mini-2506") is None                        # month 25 is not a date, so nothing is stripped


def test_lookup_strips_a_provider_prefix():
    assert _id("publishers/google/models/gemini-2.5-pro") == "gemini-2.5-pro"
    assert _id("models/gemini-2.5-pro") == "gemini-2.5-pro"
    assert _id("openai/gpt-5-mini") == "gpt-5-mini"
    assert _id("publishers/google/models/gemini-2.5-pro@20260102") == "gemini-2.5-pro"  # prefix and date together


def test_lookup_keeps_an_ollama_tag_together_and_returns_none_for_an_unknown_model():
    assert _id("command-r:35b") == "command-r:35b"
    assert _id("some-unknown-model") is None
    assert _id("") is None and _id(None) is None
    assert P.guardian_catalog_lookup(None, "gpt-5-mini") is None


def test_lookup_finds_a_versioned_release_by_its_exact_id():
    assert _id("mistral-small-2503") == "mistral-small-2506"


def test_platform_maps_only_the_two_cloud_integrations():
    assert P.guardian_catalog_platform("GuardianFoundry") == "azure-foundry"
    assert P.guardian_catalog_platform("Guardian Foundry") == "azure-foundry"
    assert P.guardian_catalog_platform("GuardianVertex") == "vertex"
    assert P.guardian_catalog_platform("GuardianCohere") is None  # Cohere North is self-hosted
    assert P.guardian_catalog_platform(None) is None and P.guardian_catalog_platform("Other") is None


def test_the_provider_cap_beats_the_vendor_figure_gpt_41_on_azure():
    model = P.guardian_catalog_lookup(CATALOG, "gpt-4.1")
    azure = P.guardian_catalog_limits(model, "azure-foundry", "gpt-4.1")
    assert azure["context_window"] == 300000 and azure["basis"] == "azure-foundry cap" and azure["managed"] is True
    vendor = P.guardian_catalog_limits(model, None, "gpt-4.1")
    assert vendor["context_window"] == 1047576 and vendor["basis"] == "vendor" and vendor["managed"] is False
    other = P.guardian_catalog_limits(model, "vertex", "gpt-4.1")   # a platform with no row for this model
    assert other["context_window"] == 1047576 and other["managed"] is False


def test_a_versioned_provider_row_applies_only_to_its_own_release():
    model = P.guardian_catalog_lookup(CATALOG, "mistral-small-2506")
    own = P.guardian_catalog_limits(model, "vertex", "mistral-small-2503")
    assert own["context_window"] == 32768 and own["managed"] is True
    other = P.guardian_catalog_limits(model, "vertex", "mistral-small-2506")
    assert other["context_window"] == 131072 and other["managed"] is False


def test_usable_input_takes_the_smaller_of_the_input_limit_and_the_window_less_the_reserve():
    both = {"context_window": 400000, "max_input_tokens": 272000}
    assert P.guardian_catalog_usable_input(both, 4096) == 272000
    assert P.guardian_catalog_usable_input({"context_window": 100000, "max_input_tokens": 99000}, 4096) == 95904
    assert P.guardian_catalog_usable_input({"max_input_tokens": 131072}, 4096) == 131072
    assert P.guardian_catalog_usable_input({"context_window": 300000}, 4096) == 295904
    assert P.guardian_catalog_usable_input({}, 4096) is None
    assert P.guardian_catalog_usable_input({"context_window": 3000}, 4096) is None  # the reserve eats the window


def test_documented_budget_uses_the_probes_formula_in_the_loops_units():
    limits = {"context_window": 300000, "max_input_tokens": None}
    assumed = P.guardian_catalog_documented_budget(limits, 4096, None)
    # (300000 - 4096) * 0.85 * (3.0 / 4): the assumed 3.0 characters per token, not the estimator's 4.0
    assert assumed["usable_input_tokens"] == 295904 and assumed["budget"] == int(295904 * 0.85 * 0.75)
    assert assumed["chars_per_token"] == 3.0 and assumed["chars_per_token_source"] == "assumed"
    measured = P.guardian_catalog_documented_budget(limits, 4096, 2.5)
    assert measured["budget"] == int(295904 * 0.85 * (2.5 / 4.0)) and measured["chars_per_token_source"] == "measured"
    assert measured["budget"] < assumed["budget"]
    assert P.GUARDIAN_CATALOG_ASSUMED_CHARS_PER_TOKEN == 3.0


def test_documented_budget_cap_limits_the_result_when_set():
    limits = {"context_window": 1000000, "max_input_tokens": None}
    free = P.guardian_catalog_documented_budget(limits, 4096, 3.0)
    capped = P.guardian_catalog_documented_budget(limits, 4096, 3.0, cap=200000)
    assert free["budget"] > 200000 and free["capped"] is False and free["cap"] is None
    assert capped["budget"] == 200000 and capped["capped"] is True and capped["cap"] == 200000
    under = P.guardian_catalog_documented_budget(limits, 4096, 3.0, cap=10 ** 9)
    assert under["budget"] == free["budget"] and under["capped"] is False
    assert P.guardian_catalog_documented_budget({}, 4096, 3.0)["budget"] is None


def _probe_record(window, **extra):
    record = {"latency_bounded_window": window, "at_ceiling": False, "truncated": False, "quota_limited": False,
              "recommended_max_input_tokens": int(max(0, (window or 0) - 4096) * 0.85 * 0.75), "chars_per_token": 3.0,
              "chars_per_token_measured": True, "limit_evidence": None}
    record.update(extra)
    return record


def test_twenty_percent_rule_confirms_a_window_within_80_percent_of_the_documented_limit():
    verdict = P.guardian_catalog_compare(100000, _probe_record(80000))
    assert verdict["verdict"] == "confirmed" and verdict["share"] == 0.8
    # the documented-derived budget, but never above what the measured window supports
    documented_budget = int(100000 * 0.85 * (3.0 / 4.0))
    assert verdict["budget"] == min(documented_budget, _probe_record(80000)["recommended_max_input_tokens"])
    full = P.guardian_catalog_compare(100000, _probe_record(100000, recommended_max_input_tokens=None))
    assert full["verdict"] == "confirmed" and full["budget"] == documented_budget     # no recommendation: the documented one


def test_a_confirmed_budget_never_exceeds_what_the_measured_window_supports():
    # vLLM serves a 123,904-token documented model at max length 100K: the probe measures 101,601 (82%)
    record = _probe_record(101601, recommended_max_input_tokens=60000, chars_per_token=3.6)
    verdict = P.guardian_catalog_compare(123904, record)
    assert verdict["verdict"] == "confirmed" and verdict["budget"] == 60000
    # with no recommendation (nothing to compare with) the documented figure stands
    none = P.guardian_catalog_compare(123904, _probe_record(101601, recommended_max_input_tokens=None, chars_per_token=3.6))
    assert none["verdict"] == "confirmed" and none["budget"] == int(123904 * 0.85 * 0.75)


def test_a_measured_ratio_never_raises_a_documented_or_confirmed_budget_above_the_assumed_one():
    limits = {"context_window": 300000, "max_input_tokens": None}
    prose = P.guardian_catalog_documented_budget(limits, 4096, 4.6)       # English prose, not the loop's JSON-heavy content
    assert prose["chars_per_token"] == 3.0 and prose["chars_per_token_source"] == "assumed"
    assert prose["budget"] == int(295904 * 0.85 * 0.75)
    dense = P.guardian_catalog_documented_budget(limits, 4096, 2.5)       # a denser tokenizer still lowers it
    assert dense["chars_per_token"] == 2.5 and dense["chars_per_token_source"] == "measured"
    verdict = P.guardian_catalog_compare(100000, _probe_record(100000, chars_per_token=4.6, recommended_max_input_tokens=None))
    assert verdict["budget"] == int(100000 * 0.85 * 0.75) and verdict["chars_per_token_source"] == "assumed"
    low = P.guardian_catalog_compare(100000, _probe_record(100000, chars_per_token=2.5, recommended_max_input_tokens=None))
    assert low["budget"] == int(100000 * 0.85 * (2.5 / 4.0)) and low["chars_per_token_source"] == "measured"


def test_a_quota_stop_on_a_self_hosted_model_is_sized_from_the_largest_size_that_answered():
    record = _probe_record(8000, quota_limited=True, quota_at_tokens=16000, chars_per_token=3.6)
    trusted = P.guardian_catalog_compare(123904, record, documented_trusted=True)
    assert trusted["verdict"] == "quota" and trusted["budget"] == int(123904 * 0.85 * 0.75)
    untrusted = P.guardian_catalog_compare(123904, record, documented_trusted=False)
    assert untrusted["verdict"] == "measured" and untrusted["budget"] == record["recommended_max_input_tokens"]
    assert "quota (tokens-per-minute) reached at 16000 tokens" in untrusted["evidence"] and "8000 tokens" in untrusted["evidence"]
    floor = _probe_record(None, quota_limited=True, quota_at_tokens=1000, recommended_max_input_tokens=None)
    assert P.guardian_catalog_compare(123904, floor, documented_trusted=False)["budget"] is None
    assert P.guardian_catalog_compare(123904, floor, documented_trusted=True)["budget"] == int(123904 * 0.85 * 0.75)


def test_the_documented_window_is_trusted_for_frontier_models_and_provider_caps_only():
    assert P.guardian_catalog_documented_trusted({"probe": "skip", "limits": {"managed": False}}) is True
    assert P.guardian_catalog_documented_trusted({"probe": "confirm", "limits": {"managed": True}}) is True
    assert P.guardian_catalog_documented_trusted({"probe": "confirm", "limits": {"managed": False}}) is False
    assert P.guardian_catalog_documented_trusted(None) is False


def test_twenty_percent_rule_uses_the_measured_figure_when_more_than_20_percent_below():
    record = _probe_record(79000, limit_evidence="past 79000 tokens the first response took 41.2 s, above the acceptable 30 s")
    verdict = P.guardian_catalog_compare(100000, record)
    assert verdict["verdict"] == "measured" and verdict["gap_percent"] == 21
    assert verdict["budget"] == record["recommended_max_input_tokens"]
    assert "above the acceptable 30 s" in verdict["evidence"]


def test_twenty_percent_rule_compares_real_tokens_never_the_recommended_budget():
    # The recommended budget (loop units) is far below the documented limit; the window is what is compared.
    record = _probe_record(100000)
    assert record["recommended_max_input_tokens"] < 0.8 * 100000
    assert P.guardian_catalog_compare(100000, record)["verdict"] == "confirmed"


def test_twenty_percent_rule_treats_reaching_the_ceiling_as_confirmed():
    record = _probe_record(60000, at_ceiling=True, probe_ceiling_tokens=60000)
    assert P.guardian_catalog_compare(100000, record)["verdict"] == "measured"      # the ceiling was a small one
    record = _probe_record(95000, at_ceiling=True, probe_ceiling_tokens=95000)
    assert P.guardian_catalog_compare(100000, record)["verdict"] == "confirmed"
    record = _probe_record(60000, at_ceiling=True)                                   # no ceiling recorded: at_ceiling counts
    assert P.guardian_catalog_compare(100000, record)["verdict"] == "confirmed"


def test_twenty_percent_rule_quota_keeps_the_documented_figure():
    record = _probe_record(8000, quota_limited=True, quota_at_tokens=16000)
    verdict = P.guardian_catalog_compare(100000, record)
    assert verdict["verdict"] == "quota"
    assert verdict["budget"] == int(100000 * 0.85 * 0.75)
    assert "quota (tokens-per-minute) reached at 16000 tokens; the window was not reached" == verdict["evidence"]


def test_twenty_percent_rule_flags_a_truncated_floor_below_the_threshold_in_the_evidence():
    verdict = P.guardian_catalog_compare(100000, _probe_record(16000, truncated=True))
    assert verdict["verdict"] == "measured" and "ran out of time" in verdict["evidence"]


def test_unknown_model_behaves_as_before_with_the_measured_verdict():
    record = _probe_record(30000)
    verdict = P.guardian_catalog_compare(None, record)
    assert verdict["verdict"] == "measured" and verdict["budget"] == record["recommended_max_input_tokens"]


def test_unmeasured_ratio_uses_the_conservative_assumed_one_in_the_documented_budget():
    record = _probe_record(100000, chars_per_token=4.0, chars_per_token_measured=False, recommended_max_input_tokens=None)
    verdict = P.guardian_catalog_compare(100000, record)
    assert verdict["chars_per_token_source"] == "assumed" and verdict["budget"] == int(100000 * 0.85 * 0.75)


def test_cap_limits_a_compared_budget_too():
    verdict = P.guardian_catalog_compare(1000000, _probe_record(1000000), cap=100000)
    assert verdict["budget"] == 100000 and verdict["capped"] is True


def test_configured_model_honours_the_foundry_dropdown():
    custom = P.GUARDIAN_CATALOG_CHOICE_CUSTOM
    assert P.guardian_catalog_configured_model([{"name": "model_choice", "value": "gpt-oss-120b"},
                                                {"name": "model", "value": "my-deployment"}]) == "gpt-oss-120b"
    assert P.guardian_catalog_configured_model([{"name": "model_choice", "value": custom},
                                                {"name": "model", "value": "my-deployment"}]) == "my-deployment"
    assert P.guardian_catalog_configured_model([{"name": "model", "value": " x "}]) == "x"
    assert P.guardian_catalog_configured_model([]) is None and P.guardian_catalog_configured_model(None) is None


def test_the_shipped_catalogue_list_parses_and_resolves_the_models_the_integrations_offer():
    path = pathlib.Path(__file__).resolve().parents[2] / "Lists" / "list-guardian_model_catalog.json"
    envelope = json.loads(path.read_text())
    catalog = P.guardian_catalog_parse(envelope["data"])
    assert catalog and catalog["checked"] and len(catalog["models"]) > 100
    assert P.guardian_catalog_lookup(catalog, "Cohere-command-a")["id"] == "command-a-03-2025"
    gpt41 = P.guardian_catalog_lookup(catalog, "gpt-4.1")
    assert P.guardian_catalog_limits(gpt41, "azure-foundry")["context_window"] == 300000
    assert P.guardian_catalog_limits(gpt41, None)["context_window"] == 1047576
    for model in catalog["models"]:   # every model says whether it needs a probe
        assert model["probe"] == ("confirm" if model["open_weight"] else "skip")


""" ------------------------- the block is one text in every script of both packs ------------------------- """


def test_the_catalogue_block_is_byte_identical_in_every_copy_in_both_packs():
    root = pathlib.Path(__file__).resolve().parents[4]
    start, end = "# <GUARDIAN_CATALOG>", "# </GUARDIAN_CATALOG>"
    copies = {}
    for pack in ("Guardian", "GuardianXSIAM"):
        for script in ("GuardianModelProfileCheck", "GuardianProbeModel", "GuardianModelProfileUpdate",
                       "GuardianModelCommand"):
            path = root / "Packs" / pack / "Scripts" / script / (script + ".py")
            text = path.read_text()
            assert text.count(start) == 1 and text.count(end) == 1, "{}: need exactly one block".format(path)
            copies[str(path.relative_to(root))] = text[text.index(start):text.index(end) + len(end)]
    assert len(copies) == 8
    assert len(set(copies.values())) == 1, "the catalogue block differs between: {}".format(
        sorted(copies))  # fix with: python3 scripts/sync_catalog_block.py
    canonical = (root / "scripts" / "guardian_catalog_block.py").read_text()
    assert next(iter(copies.values())) == canonical[canonical.index(start):canonical.index(end) + len(end)]


""" ------------------------- the probe with the catalogue: skip, force, ceiling, quota, latency, effort ------------------------- """


def _instance(model, brand="GuardianFoundry"):
    return {"provider": brand, "instance_name": "lab", "request_timeout": None, "model_tier": "medium",
            "declared_model": model}


def _catalogue_run(monkeypatch, instance, call=None, reported_model=None, **args):
    """A run against the simulated provider with the test catalogue and an enabled instance."""
    calls = []
    base = call or _sim_call

    def _call(messages, tools=None, tool_choice=None, response_format=None, temperature=0, timeout=None):
        calls.append(messages[0]["content"])
        result = base(messages, tools, tool_choice, response_format, temperature, timeout)
        if reported_model and result.get("ok"):
            result["completion"]["model"] = reported_model
        return result

    monkeypatch.setattr(P, "guardian_probe_call", _call)
    monkeypatch.setattr(P, "guardian_catalog_load", lambda: CATALOG)
    monkeypatch.setattr(P, "_guardian_probe_read_enabled_instance", lambda: instance)
    base_args = {"max_response_seconds": "60", "output_reserve": "4096"}
    base_args.update(args)
    out = P.guardian_probe_run(base_args)
    assert out["ok"]
    return out["data"], calls


def test_a_documented_frontier_model_gets_no_window_search_but_still_measures_the_ratio(monkeypatch):
    data, calls = _catalogue_run(monkeypatch, _instance("gpt-5-mini"))
    assert data["window"]["skipped"] is True and data["comparison"] is None
    assert not any(NEEDLE in c for c in calls)                       # no needle call at all
    assert data["ratio"]["measured"] is True
    rec = data["calibration_record"]
    assert rec["window_search_skipped"] is True and rec["latency_bounded_window"] is None
    assert rec["catalog"]["id"] == "gpt-5-mini" and rec["catalog"]["limits"]["basis"] == "azure-foundry cap"
    assert rec["catalog"]["usable_input_tokens"] == 272000
    # the simulated tokenizer measures about 3.0; a measured ratio never raises the budget above the assumed 3.0
    assert rec["catalog"]["documented_budget"] == int(272000 * 0.85 * (3.0 / 4.0))
    assert rec["catalog"]["budget_inputs"]["chars_per_token"] == 3.0
    assert rec["capabilities_skipped"] is False                        # the capability checks still run
    md = P.guardian_probe_render(data)
    assert "no window probe needed (documented)" in md and "Documented limits (model catalogue checked 2026-10-09)" in md


def test_force_searches_the_window_of_a_documented_model_up_to_its_documented_limit(monkeypatch):
    data, calls = _catalogue_run(monkeypatch, _instance("gpt-5-mini"), force="true")
    assert data["window"].get("skipped") is None and any(NEEDLE in c for c in calls)
    assert data["ceiling"] == {"max_probe_tokens": 272000, "source": "documented"}
    # the simulated window (30000) is far below 80% of 272000: the measured figure wins, with evidence
    comparison = data["comparison"]
    assert comparison["verdict"] == "measured" and comparison["budget"] == data["recommendation"]["max_input_tokens"]
    assert comparison["evidence"] and "tokens" in comparison["evidence"]
    assert "Documented vs measured" in P.guardian_probe_render(data)


def test_an_open_weight_model_is_searched_and_compared_with_its_documented_limit(monkeypatch):
    data, calls = _catalogue_run(monkeypatch, _instance("Cohere-command-a"))
    assert any(NEEDLE in c for c in calls)
    assert data["catalog"]["id"] == "command-a-03-2025" and data["catalog"]["probe"] == "confirm"
    assert data["catalog"]["limits"]["max_input_tokens"] == 131072          # the Azure cap row
    assert data["ceiling"]["max_probe_tokens"] == 131072 and data["ceiling"]["source"] == "documented"
    assert data["comparison"]["verdict"] == "measured"                      # the sim window is 30000


def test_the_model_the_provider_reports_is_tried_when_the_configured_name_is_not_listed(monkeypatch):
    data, _calls = _catalogue_run(monkeypatch, _instance("my-custom-deployment"), reported_model="gpt-5-mini-2025-08-07")
    assert data["catalog"]["id"] == "gpt-5-mini" and data["catalog"]["matched_by"] == "reported"
    assert data["catalog"]["matched_name"] == "gpt-5-mini-2025-08-07"
    assert data["window"]["skipped"] is True


def test_the_configured_name_wins_over_the_reported_one(monkeypatch):
    data, _calls = _catalogue_run(monkeypatch, _instance("gpt-4.1"), reported_model="gpt-5-mini-2025-08-07")
    assert data["catalog"]["id"] == "gpt-4.1" and data["catalog"]["matched_by"] == "configured"
    assert data["catalog"]["limits"]["context_window"] == 300000            # Azure cap, not the vendor 1M


def test_an_unknown_model_keeps_the_default_ceiling_and_says_how_to_raise_it(monkeypatch):
    data, _calls = _catalogue_run(monkeypatch, _instance("never-heard-of-it"))
    assert data["catalog"] is None and data["comparison"] is None
    assert data["ceiling"] == {"max_probe_tokens": P.GUARDIAN_PROBE_DEFAULT_MAX_PROBE_TOKENS, "source": "default"}
    md = P.guardian_probe_render(data)
    assert "not in `guardian_model_catalog`" in md and "max_probe_tokens" in md


def test_an_explicit_max_probe_tokens_beats_the_documented_ceiling(monkeypatch):
    data, _calls = _catalogue_run(monkeypatch, _instance("Cohere-command-a"), max_probe_tokens="20000")
    assert data["ceiling"] == {"max_probe_tokens": 20000, "source": "arg"}


def test_a_missing_catalogue_falls_back_to_the_old_behaviour(monkeypatch):
    _patch(monkeypatch)
    monkeypatch.setattr(P, "guardian_catalog_load", lambda: None)
    monkeypatch.setattr(P, "_guardian_probe_read_enabled_instance", lambda: _instance("gpt-5-mini"))
    out = P.guardian_probe_run({"max_response_seconds": "60"})
    assert out["ok"] and out["data"]["catalog"] is None and out["data"]["window"]["ok"] is True
    assert out["data"]["calibration_record"]["recommended_max_input_tokens"] is not None


def test_a_model_with_no_usable_documented_input_figure_is_probed_even_if_it_is_marked_skip(monkeypatch):
    catalog = {"checked": "2026-10-09", "models": [{"id": "retired-thing", "aliases": [], "vendor": "X", "open_weight": False,
                                                    "context_window": None, "max_input_tokens": None, "probe": "skip",
                                                    "provider_limits": []}]}
    monkeypatch.setattr(P, "guardian_catalog_load", lambda: catalog)
    monkeypatch.setattr(P, "_guardian_probe_read_enabled_instance", lambda: _instance("retired-thing"))
    _patch(monkeypatch)
    data = P.guardian_probe_run({"max_response_seconds": "60"})["data"]
    assert data["window"].get("skipped") is None and data["window"]["ok"] is True


""" ------------------------- quota errors are not context limits ------------------------- """


@pytest.mark.parametrize("text", [
    "HTTP 429 Too Many Requests",
    "Error code: 429 - {'error': {'code': 'RateLimitReached'}}",
    "Rate limit reached for gpt-5-mini in organization org-x on tokens per minute (TPM): Limit 30000",
    "You exceeded your current quota, please check your plan",
    "RateLimit exceeded",
    "Request too large ... tokens-per-minute",
])
def test_quota_errors_are_recognised_from_their_text(text):
    assert P._guardian_probe_is_quota_error(text) is True


@pytest.mark.parametrize("text", [
    None, "",
    "This model's maximum context length is 128000 tokens. However, your messages resulted in 142900 tokens.",
    "context_length_exceeded: 14290 tokens",
    "the request timed out after 90 s",
    "invalid api key",
])
def test_ordinary_errors_are_not_taken_for_quota(text):
    assert P._guardian_probe_is_quota_error(text) is False


def _quota_above(limit_tokens):
    """A provider that answers fine up to `limit_tokens` and then returns a 429 error."""
    def _call(messages, tools=None, tool_choice=None, response_format=None, temperature=0, timeout=None):
        sent = int(len(messages[0]["content"]) / SIM_CHARS_PER_TOKEN)
        if not tools and response_format is None and sent > limit_tokens:
            return {"ok": False, "completion": None, "error": "HTTP 429 Too Many Requests: tokens per minute limit"}
        return _sim_call(messages, tools, tool_choice, response_format, temperature, timeout)
    return _call


def test_a_quota_error_stops_the_search_and_uses_the_largest_size_that_answered(monkeypatch):
    monkeypatch.setattr(P, "guardian_probe_call", _quota_above(10000))
    w = P.guardian_probe_window(SIM_CHARS_PER_TOKEN, 131072, 60)
    assert w["ok"] is True and w["quota_limited"] is True
    assert w["window"] == 8000 and w["quota_at_tokens"] == 16000          # gallop 1k..8k answered, 16k hit the limit
    assert "quota reached at 16000 tokens (tokens-per-minute limit), not a context limit; the window was not reached" in w["note"]
    assert w["steps"][-1]["outcome"] == "quota"                            # the search stopped there


def test_a_quota_error_at_the_floor_is_reported_as_quota_not_as_an_unreliable_probe(monkeypatch):
    monkeypatch.setattr(P, "guardian_probe_call", _quota_above(0))
    w = P.guardian_probe_window(SIM_CHARS_PER_TOKEN, 131072, 60)
    assert w["ok"] is False and w["quota_limited"] is True and w["quota_at_tokens"] == 1000
    assert "not a context limit" in w["error"]


def test_a_quota_error_during_bisection_stops_it_too(monkeypatch):
    monkeypatch.setattr(P, "guardian_probe_call", _quota_above(20000))
    w = P.guardian_probe_window(SIM_CHARS_PER_TOKEN, 131072, 60)
    # 16000 answered, 32000 hit the limit (a 429, not a failed needle), so there is no bisection at all
    assert w["quota_limited"] is True and w["window"] == 16000 and w["quota_at_tokens"] == 32000


def test_the_run_records_quota_and_the_compare_keeps_the_documented_limit(monkeypatch):
    data, _calls = _catalogue_run(monkeypatch, _instance("Cohere-command-a"), call=_quota_above(10000))
    record = data["calibration_record"]
    assert record["quota_limited"] is True and record["quota_at_tokens"] == 16000
    assert data["comparison"]["verdict"] == "quota"
    assert data["comparison"]["budget"] == pytest.approx(131072 * 0.85 * (3.0 / 4.0), rel=0.001)
    md = P.guardian_probe_render(data)
    assert "QUOTA REACHED, not a context limit" in md and "quota reached at 16000 tokens" in md


""" ------------------------- latency is judged against the model's own small-prompt time ------------------------- """


def test_a_slow_first_response_is_fine_when_the_model_is_that_slow_on_a_tiny_prompt(monkeypatch):
    monkeypatch.setattr(P, "guardian_probe_call", _slow_sim_call(0.05))
    # allowance = the budget (0.01 s) alone: too slow ...
    outcome, *_ = P._guardian_probe_window_fits(1000, SIM_CHARS_PER_TOKEN, 0.01)
    assert outcome == "correct_slow"
    # ... but with the model's own small-prompt time added (0.01 + 0.2), the same call is fast
    outcome, *_ = P._guardian_probe_window_fits(1000, SIM_CHARS_PER_TOKEN, 0.01 + 0.2)
    assert outcome == "correct_fast"


def test_the_baseline_is_the_smaller_of_the_small_call_times_capped_at_the_budget():
    baseline = P._guardian_probe_latency_baseline
    assert baseline({"ok": True, "seconds": 20.0}, {"ok": True, "small_seconds": 8.0}, 60) == 8     # the warm-up may hold a cold load
    assert baseline({"ok": True, "seconds": 5.0}, {"ok": True, "small_seconds": 8.0}, 60) == 5
    assert baseline({"ok": True, "seconds": 500.0}, {"ok": False}, 60) == 60                         # capped at the budget
    assert baseline({"ok": False, "seconds": 3.0, "error": "x"}, {"ok": False}, 60) == 0             # nothing succeeded
    assert baseline({"ok": None, "seconds": 0, "skipped": True}, {"ok": True, "small_seconds": 0.3}, 60) == 0


def test_the_run_adds_the_baseline_to_the_allowance_and_keeps_the_hard_timeout_bounded(monkeypatch):
    _patch(monkeypatch)
    monkeypatch.setattr(P, "guardian_probe_warm_up", lambda *a, **k: {"ok": True, "seconds": 12.0, "error": None, "model": None})
    real_ratio = P.guardian_probe_ratio

    def _ratio(call_timeout=None):
        result = real_ratio(call_timeout)
        result["small_seconds"] = 9.0
        return result

    monkeypatch.setattr(P, "guardian_probe_ratio", _ratio)
    SIM_TIMEOUTS.clear()
    data = P.guardian_probe_run({"max_response_seconds": "60"})["data"]
    assert data["latency_budget"]["baseline_seconds"] == 9 and data["latency_budget"]["allowed_seconds"] == 69
    assert data["calibration_record"]["latency_allowed_seconds"] == 69
    assert P._guardian_probe_hard_timeout(69) == 87 and 87 in SIM_TIMEOUTS      # the window calls carry the larger bound
    assert max(t for t in SIM_TIMEOUTS if t != P.GUARDIAN_PROBE_WARM_UP_MAX_SECONDS) <= P.GUARDIAN_PROBE_MAX_HARD_CALL_SECONDS
    assert "small-prompt time is `9`s" in P.guardian_probe_render(data)


def test_the_hard_per_call_timeout_never_exceeds_the_cap_and_the_deadline_still_fits_a_call():
    assert P._guardian_probe_hard_timeout(60) == P._guardian_probe_call_timeout(60)       # unchanged without a baseline
    assert P._guardian_probe_hard_timeout(100) == 125
    assert P._guardian_probe_hard_timeout(300) == P.GUARDIAN_PROBE_MAX_HARD_CALL_SECONDS
    assert (P.GUARDIAN_PROBE_MAX_HARD_CALL_SECONDS + P.GUARDIAN_PROBE_DEADLINE_OVERHEAD_SECONDS
            < P.GUARDIAN_PROBE_RUN_DEADLINE_SECONDS)


def test_the_limit_evidence_names_the_first_size_past_the_window():
    slow = {"ok": True, "window": 16000, "steps": [
        {"tokens": 16000, "outcome": "correct_fast", "elapsed_seconds": 3.0},
        {"tokens": 32000, "outcome": "correct_slow", "elapsed_seconds": 41.2}]}
    assert P.guardian_probe_limit_evidence(slow, 30) == "past 16000 tokens the first response took 41.2 s, above the acceptable 30 s"
    failed = {"ok": True, "window": 16000, "steps": [
        {"tokens": 32000, "outcome": "failed", "elapsed_seconds": 2.0, "error": "context_length_exceeded:\n  too long",
         "timeout_suspected": False}]}
    assert P.guardian_probe_limit_evidence(failed, 30) == "requests above 16000 tokens failed: context_length_exceeded: too long"
    lost = {"ok": True, "window": 16000, "steps": [{"tokens": 32000, "outcome": "failed", "error": None}]}
    assert "lost the start of the prompt" in P.guardian_probe_limit_evidence(lost, 30)
    assert P.guardian_probe_limit_evidence({"ok": True, "window": 16000, "steps": []}, 30) is None
    assert P.guardian_probe_limit_evidence({"ok": False, "steps": []}, 30) is None


""" ------------------------- reasoning effort: lowest value, one fallback ------------------------- """


def _llm_chat_recorder(reject_effort=False, other_error=None):
    sent = []

    def fake_execute(command, args):
        sent.append(dict(args))
        if other_error is not None:
            return {"ok": False, "data": None, "error": other_error}
        if reject_effort and "reasoning_effort" in args:
            return {"ok": False, "data": None, "error": "Unsupported parameter: 'reasoning_effort' is not supported with this model"}
        return {"ok": True, "data": [{"Type": 1, "Contents": {"choices": [{"message": {"content": "OK"}}]}}], "error": None}

    return sent, fake_execute


def test_every_probe_call_asks_for_the_lowest_reasoning_effort(monkeypatch):
    P._GUARDIAN_PROBE_STATE["reasoning_effort"] = P.GUARDIAN_PROBE_REASONING_EFFORT
    sent, fake = _llm_chat_recorder()
    monkeypatch.setattr(P, "guardian_execute", fake)
    assert P.GUARDIAN_PROBE_REASONING_EFFORT == "low"
    assert P.guardian_probe_call([{"role": "user", "content": "hi"}])["ok"] is True
    assert sent[0]["reasoning_effort"] == "low"


def test_a_rejected_reasoning_effort_is_retried_once_without_it_and_then_dropped_for_the_run(monkeypatch):
    P._GUARDIAN_PROBE_STATE["reasoning_effort"] = P.GUARDIAN_PROBE_REASONING_EFFORT
    sent, fake = _llm_chat_recorder(reject_effort=True)
    monkeypatch.setattr(P, "guardian_execute", fake)
    first = P.guardian_probe_call([{"role": "user", "content": "hi"}])
    assert first["ok"] is True
    assert len(sent) == 2 and "reasoning_effort" in sent[0] and "reasoning_effort" not in sent[1]
    P.guardian_probe_call([{"role": "user", "content": "again"}])
    assert len(sent) == 3 and "reasoning_effort" not in sent[2]         # not sent again: no retry doubling
    P._GUARDIAN_PROBE_STATE["reasoning_effort"] = P.GUARDIAN_PROBE_REASONING_EFFORT


def test_an_unrelated_error_is_not_retried(monkeypatch):
    P._GUARDIAN_PROBE_STATE["reasoning_effort"] = P.GUARDIAN_PROBE_REASONING_EFFORT
    sent, fake = _llm_chat_recorder(other_error="HTTP 500 internal error")
    monkeypatch.setattr(P, "guardian_execute", fake)
    result = P.guardian_probe_call([{"role": "user", "content": "hi"}])
    assert result["ok"] is False and len(sent) == 1
    assert P._GUARDIAN_PROBE_STATE["reasoning_effort"] == "low"


def test_a_run_starts_with_the_effort_restored(monkeypatch):
    P._GUARDIAN_PROBE_STATE["reasoning_effort"] = None
    _patch(monkeypatch)
    P.guardian_probe_run({"max_response_seconds": "60"})
    assert P._GUARDIAN_PROBE_STATE["reasoning_effort"] == "low"


def test_the_probe_prompts_ask_for_a_one_word_answer(monkeypatch):
    seen = []

    def _recording(messages, tools=None, tool_choice=None, response_format=None, temperature=0, timeout=None):
        seen.append(messages[0]["content"])
        return _sim_call(messages, tools, tool_choice, response_format, temperature, timeout)

    monkeypatch.setattr(P, "guardian_probe_call", _recording)
    P.guardian_probe_run({"max_response_seconds": "60"})
    needle_prompts = [c for c in seen if NEEDLE in c]
    assert needle_prompts and all("(one word)" in c for c in needle_prompts)
    assert all("Reply with exactly: OK" in c for c in seen if NEEDLE not in c and "ticket" not in c and "JSON" not in c)


def test_the_yml_has_no_default_for_max_probe_tokens_and_offers_force():
    import yaml
    spec = yaml.safe_load((pathlib.Path(__file__).resolve().parent / "GuardianProbeModel.yml").read_text())
    arg = next(a for a in spec["args"] if a["name"] == "max_probe_tokens")
    assert "defaultValue" not in arg       # a default would hide whether the operator set it
    assert next(a for a in spec["args"] if a["name"] == "force")["defaultValue"] == "false"
