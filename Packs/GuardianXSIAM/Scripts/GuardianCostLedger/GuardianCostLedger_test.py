import json

import GuardianCostLedger as gcl


# --- fixtures / test harness --------------------------------------------------

DEFAULT_PRICING = {
    "gemini-2.5-flash": {"input_per_1m": 0.30, "output_per_1m": 2.50, "cached_input_per_1m": 0.075},
}


def _entries(contents):
    return [{"Type": 1, "Contents": contents}]


def _not_found(list_name):
    return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(list_name)}]


def _install(monkeypatch, pricing=None, rollup=None, command_handlers=None, incident_id="999", server_day="2026-07-05"):
    """Wires demisto.executeCommand/incident with a real-shaped fake --
    getList/setList/createList for guardian_pricing + guardian_cost_ledger,
    GetTime for the server-day helper. Any command dispatched that isn't
    wired here raises AssertionError.
    """
    state = {
        "guardian_pricing": pricing if pricing is not None else DEFAULT_PRICING,
        "guardian_cost_ledger": rollup if rollup is not None else {},
    }
    created = {"calls": []}
    saved = {"calls": []}

    def handle_get_list(args):
        name = args["listName"]
        if name not in state:
            return _not_found(name)
        payload = state[name]
        contents = payload if isinstance(payload, str) else json.dumps(payload)
        return _entries(contents)

    def handle_set_list(args):
        name = args["listName"]
        saved["calls"].append(dict(args))
        state[name] = json.loads(args["listData"])
        return _entries("Done: list {} was updated".format(name))

    def handle_create_list(args):
        name = args["listName"]
        created["calls"].append(dict(args))
        state[name] = json.loads(args["listData"])
        return _entries("Done: list {} was created".format(name))

    def handle_get_time(args):
        return _entries(server_day + "T12:00:00.000Z" if server_day else None)

    handlers = {
        "getList": handle_get_list,
        "setList": handle_set_list,
        "createList": handle_create_list,
        "GetTime": handle_get_time,
    }
    if command_handlers:
        handlers.update(command_handlers)

    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command dispatched: {} {}".format(command, args))
        return handlers[command](args)

    monkeypatch.setattr(gcl.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(gcl.demisto, "incident", lambda: {"id": incident_id} if incident_id else {})
    monkeypatch.setattr(gcl.demisto, "error", lambda msg: None)
    monkeypatch.setattr(gcl.demisto, "info", lambda msg: None)
    return state, created, saved


# --- guardian_cost_ledger_normalize_usage --------------------------------------


def test_normalize_usage_flat_cached_tokens():
    tokens = gcl.guardian_cost_ledger_normalize_usage(
        {"prompt_tokens": 1000, "completion_tokens": 200, "total_tokens": 1200, "cached_tokens": 300}
    )
    assert tokens == {"prompt_tokens": 1000, "completion_tokens": 200, "cached_tokens": 300, "total_tokens": 1200}


def test_normalize_usage_nested_prompt_tokens_details_cached():
    # task-1.7-context.md's own prose describes this nested OpenAI-native
    # shape -- accepted as a fallback even though GuardianLLM itself already
    # flattens cached_tokens.
    tokens = gcl.guardian_cost_ledger_normalize_usage(
        {"prompt_tokens": 500, "completion_tokens": 50, "prompt_tokens_details": {"cached_tokens": 100}}
    )
    assert tokens["cached_tokens"] == 100
    assert tokens["total_tokens"] == 550  # derived when total_tokens absent


def test_normalize_usage_json_string_input():
    tokens = gcl.guardian_cost_ledger_normalize_usage(json.dumps({"prompt_tokens": 10, "completion_tokens": 5}))
    assert tokens["prompt_tokens"] == 10
    assert tokens["completion_tokens"] == 5


def test_normalize_usage_none_never_crashes():
    tokens = gcl.guardian_cost_ledger_normalize_usage(None)
    assert tokens == {"prompt_tokens": 0, "completion_tokens": 0, "cached_tokens": 0, "total_tokens": 0}


def test_normalize_usage_malformed_json_string_never_crashes():
    tokens = gcl.guardian_cost_ledger_normalize_usage("not valid json{{{")
    assert tokens == {"prompt_tokens": 0, "completion_tokens": 0, "cached_tokens": 0, "total_tokens": 0}


def test_normalize_usage_cached_tokens_clamped_to_prompt_tokens():
    # A malformed/inconsistent payload claiming MORE cached than prompt
    # tokens must never make the non-cached leg of the cost formula negative.
    tokens = gcl.guardian_cost_ledger_normalize_usage({"prompt_tokens": 10, "cached_tokens": 999})
    assert tokens["cached_tokens"] == 10


def test_normalize_usage_negative_values_floor_to_zero():
    tokens = gcl.guardian_cost_ledger_normalize_usage({"prompt_tokens": -5, "completion_tokens": -1})
    assert tokens["prompt_tokens"] == 0
    assert tokens["completion_tokens"] == 0


# --- guardian_cost_ledger_price_for_model --------------------------------------


def test_price_for_model_found():
    price, warning = gcl.guardian_cost_ledger_price_for_model(DEFAULT_PRICING, "gemini-2.5-flash")
    assert price == {"input_per_1m": 0.30, "output_per_1m": 2.50, "cached_input_per_1m": 0.075}
    assert warning is None


def test_price_for_model_unknown_model_warns_not_crashes():
    price, warning = gcl.guardian_cost_ledger_price_for_model(DEFAULT_PRICING, "some-future-model")
    assert price == gcl.GUARDIAN_COST_LEDGER_ZERO_PRICE
    assert "not found in guardian_pricing" in warning


def test_price_for_model_missing_model_arg_warns_not_crashes():
    price, warning = gcl.guardian_cost_ledger_price_for_model(DEFAULT_PRICING, None)
    assert price == gcl.GUARDIAN_COST_LEDGER_ZERO_PRICE
    assert "no 'model' provided" in warning


def test_price_for_model_partial_entry_defaults_missing_fields_to_zero():
    pricing = {"partial-model": {"input_per_1m": 1.0}}
    price, warning = gcl.guardian_cost_ledger_price_for_model(pricing, "partial-model")
    assert price == {"input_per_1m": 1.0, "output_per_1m": 0.0, "cached_input_per_1m": 0.0}
    assert warning is None


# --- guardian_cost_ledger_compute_usd (the math, incl. cached discount) -------


def test_compute_usd_no_cached_tokens():
    tokens = {"prompt_tokens": 1_000_000, "completion_tokens": 1_000_000, "cached_tokens": 0, "total_tokens": 2_000_000}
    price = {"input_per_1m": 0.30, "output_per_1m": 2.50, "cached_input_per_1m": 0.075}
    usd = gcl.guardian_cost_ledger_compute_usd(tokens, price)
    assert usd == round(0.30 + 2.50, 8)


def test_compute_usd_applies_cached_discount():
    # 1M prompt tokens, HALF of which are cached: the cached half is priced
    # at the (cheaper) cached_input_per_1m rate, not the full input_per_1m
    # rate -- this is the discount the task brief calls out explicitly.
    tokens = {"prompt_tokens": 1_000_000, "completion_tokens": 0, "cached_tokens": 500_000, "total_tokens": 1_000_000}
    price = {"input_per_1m": 0.30, "output_per_1m": 2.50, "cached_input_per_1m": 0.075}
    usd = gcl.guardian_cost_ledger_compute_usd(tokens, price)
    expected = (500_000 * 0.30 / 1_000_000.0) + (500_000 * 0.075 / 1_000_000.0)
    assert usd == round(expected, 8)
    # Sanity: charging the cached half at the discount costs less than
    # charging the whole thing at the full input rate.
    assert usd < round(1_000_000 * 0.30 / 1_000_000.0, 8)


def test_compute_usd_zero_price_is_zero_cost():
    tokens = {"prompt_tokens": 5000, "completion_tokens": 500, "cached_tokens": 0, "total_tokens": 5500}
    usd = gcl.guardian_cost_ledger_compute_usd(tokens, gcl.GUARDIAN_COST_LEDGER_ZERO_PRICE)
    assert usd == 0.0


# --- guardian_cost_ledger_apply_increment (incremental rollup, not raw rows) --


def test_apply_increment_creates_fresh_bucket():
    rollup = {}
    tokens = {"prompt_tokens": 100, "completion_tokens": 20, "cached_tokens": 0, "total_tokens": 120}
    gcl.guardian_cost_ledger_apply_increment(rollup, "2026-07-05", "gemini-2.5-flash", "triage", tokens, 0.01)
    bucket = rollup["2026-07-05"]["gemini-2.5-flash"]["triage"]
    assert bucket == {
        "calls": 1,
        "prompt_tokens": 100,
        "completion_tokens": 20,
        "cached_tokens": 0,
        "total_tokens": 120,
        "usd": 0.01,
    }


def test_apply_increment_accumulates_not_overwrites():
    # This is the core incremental-rollup requirement: repeated calls to the
    # SAME day/model/trigger bucket must ADD onto the running totals, never
    # replace them (the fix for Guardian's own raw-row-summing/1000-row-cap
    # lesson -- see the module docstring).
    rollup = {}
    tokens_a = {"prompt_tokens": 100, "completion_tokens": 20, "cached_tokens": 0, "total_tokens": 120}
    tokens_b = {"prompt_tokens": 50, "completion_tokens": 10, "cached_tokens": 5, "total_tokens": 60}
    gcl.guardian_cost_ledger_apply_increment(rollup, "2026-07-05", "gemini-2.5-flash", "triage", tokens_a, 0.01)
    gcl.guardian_cost_ledger_apply_increment(rollup, "2026-07-05", "gemini-2.5-flash", "triage", tokens_b, 0.005)
    bucket = rollup["2026-07-05"]["gemini-2.5-flash"]["triage"]
    assert bucket["calls"] == 2
    assert bucket["prompt_tokens"] == 150
    assert bucket["completion_tokens"] == 30
    assert bucket["cached_tokens"] == 5
    assert bucket["total_tokens"] == 180
    assert bucket["usd"] == 0.015


def test_apply_increment_keeps_distinct_buckets_separate():
    rollup = {}
    tokens = {"prompt_tokens": 10, "completion_tokens": 1, "cached_tokens": 0, "total_tokens": 11}
    gcl.guardian_cost_ledger_apply_increment(rollup, "2026-07-05", "gemini-2.5-flash", "triage", tokens, 0.001)
    gcl.guardian_cost_ledger_apply_increment(rollup, "2026-07-05", "gemini-2.5-flash", "investigation", tokens, 0.001)
    gcl.guardian_cost_ledger_apply_increment(rollup, "2026-07-06", "gemini-2.5-flash", "triage", tokens, 0.001)
    assert rollup["2026-07-05"]["gemini-2.5-flash"]["triage"]["calls"] == 1
    assert rollup["2026-07-05"]["gemini-2.5-flash"]["investigation"]["calls"] == 1
    assert rollup["2026-07-06"]["gemini-2.5-flash"]["triage"]["calls"] == 1


def test_apply_increment_falls_back_to_placeholder_keys():
    rollup = {}
    tokens = {"prompt_tokens": 1, "completion_tokens": 1, "cached_tokens": 0, "total_tokens": 2}
    gcl.guardian_cost_ledger_apply_increment(rollup, None, None, None, tokens, 0.0)
    assert gcl.GUARDIAN_UNKNOWN_DAY in rollup
    assert gcl.GUARDIAN_UNKNOWN_MODEL in rollup[gcl.GUARDIAN_UNKNOWN_DAY]
    assert gcl.GUARDIAN_DEFAULT_TRIGGER in rollup[gcl.GUARDIAN_UNKNOWN_DAY][gcl.GUARDIAN_UNKNOWN_MODEL]


# --- guardian_cost_ledger_load_rollup: shape handling / self-bootstrap --------


def test_load_rollup_missing_list_self_bootstraps_empty_object(monkeypatch):
    _install(monkeypatch, rollup="__MISSING__")
    # Force a genuine "not found" response for guardian_cost_ledger.
    def handle_get_list(args):
        if args["listName"] == "guardian_cost_ledger":
            return _not_found("guardian_cost_ledger")
        return _entries(json.dumps(DEFAULT_PRICING))

    created = {"calls": []}

    def handle_create_list(args):
        created["calls"].append(dict(args))
        return _entries("Done: list {} was created".format(args["listName"]))

    monkeypatch.setattr(
        gcl.demisto,
        "executeCommand",
        lambda command, args: {
            "getList": handle_get_list,
            "createList": handle_create_list,
            "GetTime": lambda a: _entries("2026-07-05T00:00:00Z"),
        }[command](args)
        if command in ("getList", "createList", "GetTime")
        else (_ for _ in ()).throw(AssertionError("unexpected command {}".format(command))),
    )

    result = gcl.guardian_cost_ledger_load_rollup()
    assert result["ok"] is True
    assert result["data"] == {}
    assert len(created["calls"]) == 1
    assert json.loads(created["calls"][0]["listData"]) == {}


def test_load_rollup_normalizes_stale_empty_array_to_object(monkeypatch):
    # The pre-this-task GuardianBootstrap default was `[]` -- must be
    # tolerated and normalized to `{}`, not treated as a hard shape error.
    _install(monkeypatch, rollup="[]")
    result = gcl.guardian_cost_ledger_load_rollup()
    assert result["ok"] is True
    assert result["data"] == {}


def test_load_rollup_non_empty_array_is_a_hard_error(monkeypatch):
    _install(monkeypatch, rollup='[{"unexpected": "row"}]')
    result = gcl.guardian_cost_ledger_load_rollup()
    assert result["ok"] is False
    assert "non-empty JSON array" in result["error"]


def test_load_rollup_reads_existing_object(monkeypatch):
    existing = {"2026-07-04": {"gemini-2.5-flash": {"triage": {"calls": 3, "usd": 0.05}}}}
    _install(monkeypatch, rollup=existing)
    result = gcl.guardian_cost_ledger_load_rollup()
    assert result["ok"] is True
    assert result["data"] == existing


# --- guardian_cost_ledger_compute: full orchestration --------------------------


def test_compute_prices_known_model_and_updates_rollup(monkeypatch):
    state, created, saved = _install(monkeypatch)
    usage = {"prompt_tokens": 1000, "completion_tokens": 200, "cached_tokens": 0, "total_tokens": 1200}
    result = gcl.guardian_cost_ledger_compute(usage, "gemini-2.5-flash", run_id="42", trigger="triage")

    assert result["warning"] is None
    assert result["rollup_updated"] is True
    expected_usd = round((1000 * 0.30 / 1_000_000.0) + (200 * 2.50 / 1_000_000.0), 8)
    assert result["usd"] == expected_usd
    assert result["day"] == "2026-07-05"
    assert result["trigger"] == "triage"
    assert result["run_id"] == "42"

    # The shared List was actually persisted with the incremented bucket.
    persisted = state["guardian_cost_ledger"]
    bucket = persisted["2026-07-05"]["gemini-2.5-flash"]["triage"]
    assert bucket["calls"] == 1
    assert bucket["usd"] == expected_usd
    assert len(saved["calls"]) == 1


def test_compute_accumulates_across_multiple_calls(monkeypatch):
    state, _, _ = _install(monkeypatch)
    usage = {"prompt_tokens": 1000, "completion_tokens": 200, "cached_tokens": 0, "total_tokens": 1200}
    gcl.guardian_cost_ledger_compute(usage, "gemini-2.5-flash", run_id="42", trigger="triage")
    gcl.guardian_cost_ledger_compute(usage, "gemini-2.5-flash", run_id="42", trigger="triage")

    bucket = state["guardian_cost_ledger"]["2026-07-05"]["gemini-2.5-flash"]["triage"]
    assert bucket["calls"] == 2
    assert bucket["prompt_tokens"] == 2000


def test_compute_unknown_model_never_crashes_and_warns(monkeypatch):
    _install(monkeypatch)
    usage = {"prompt_tokens": 1000, "completion_tokens": 200}
    result = gcl.guardian_cost_ledger_compute(usage, "some-brand-new-model", run_id="42")

    assert result["usd"] == 0.0
    assert result["warning"] is not None
    assert "not found in guardian_pricing" in result["warning"]
    # Still rolled up (token counts preserved even though unpriced), just
    # under the model's own (unpriced) name.
    assert result["rollup_updated"] is True


def test_compute_defaults_run_id_to_current_incident(monkeypatch):
    _install(monkeypatch, incident_id="777")
    result = gcl.guardian_cost_ledger_compute({"prompt_tokens": 10, "completion_tokens": 5}, "gemini-2.5-flash")
    assert result["run_id"] == "777"


def test_compute_defaults_trigger_when_omitted(monkeypatch):
    _install(monkeypatch)
    result = gcl.guardian_cost_ledger_compute({"prompt_tokens": 10, "completion_tokens": 5}, "gemini-2.5-flash")
    assert result["trigger"] == gcl.GUARDIAN_DEFAULT_TRIGGER


def test_compute_unreadable_pricing_never_crashes(monkeypatch):
    def broken_get_list(args):
        if args["listName"] == "guardian_pricing":
            return [{"Type": 4, "Contents": "boom"}]
        return _entries(json.dumps({}))

    _install(monkeypatch, command_handlers={"getList": broken_get_list})
    result = gcl.guardian_cost_ledger_compute({"prompt_tokens": 10, "completion_tokens": 5}, "gemini-2.5-flash")
    assert result["usd"] == 0.0
    assert "guardian_pricing unreadable" in result["warning"]


def test_compute_unreadable_rollup_still_returns_usd_but_flags_not_updated(monkeypatch):
    def get_list_dispatch(args):
        name = args["listName"]
        if name == "guardian_cost_ledger":
            return [{"Type": 4, "Contents": "connection reset"}]
        return _entries(json.dumps(DEFAULT_PRICING))

    _install(monkeypatch, command_handlers={"getList": get_list_dispatch})
    result = gcl.guardian_cost_ledger_compute(
        {"prompt_tokens": 1000, "completion_tokens": 200}, "gemini-2.5-flash", trigger="triage"
    )
    assert result["usd"] > 0.0
    assert result["rollup_updated"] is False
    assert "guardian_cost_ledger unreadable" in result["warning"]


def test_compute_server_day_unobtainable_falls_back_to_incident_modified(monkeypatch):
    state, _, _ = _install(monkeypatch, server_day=None)

    def broken_get_time(args):
        return [{"Type": 4, "Contents": "GetTime disabled"}]

    monkeypatch.setattr(
        gcl.demisto,
        "executeCommand",
        lambda command, args: (
            broken_get_time(args)
            if command == "GetTime"
            else {
                "getList": lambda a: _entries(json.dumps(state[a["listName"]])) if a["listName"] in state else _not_found(a["listName"]),
                "setList": lambda a: (state.__setitem__(a["listName"], json.loads(a["listData"])), _entries("Done"))[1],
                "createList": lambda a: (state.__setitem__(a["listName"], json.loads(a["listData"])), _entries("Done"))[1],
            }[command](args)
        ),
    )
    monkeypatch.setattr(gcl.demisto, "incident", lambda: {"id": "999", "modified": "2026-07-03T10:00:00Z"})

    result = gcl.guardian_cost_ledger_compute({"prompt_tokens": 10, "completion_tokens": 5}, "gemini-2.5-flash")
    assert result["day"] == "2026-07-03"
    assert result["warning"] is not None
    assert "degraded server-time fallback" in result["warning"]


# --- main(): happy-path smoke test ----------------------------------------------


def test_main_happy_path_returns_command_results(monkeypatch):
    _install(monkeypatch)
    monkeypatch.setattr(
        gcl.demisto,
        "args",
        lambda: {"usage": json.dumps({"prompt_tokens": 100, "completion_tokens": 20}), "model": "gemini-2.5-flash",
                  "run_id": "1", "trigger": "triage"},
    )

    import CommonServerPython as csp

    csp.RESULTS.clear()
    gcl.main()

    assert len(csp.RESULTS) == 1
    result = csp.RESULTS[0]
    assert result.outputs_prefix == "Guardian.Cost"
    assert result.outputs["usd"] > 0
    assert "Guardian cost" in result.readable_output


def test_price_lookup_matches_a_dated_provider_model_name_to_the_operators_row():
    pricing = {"gpt-5": {"input_per_1m": 9.0}, "gpt-5-mini": {"input_per_1m": 0.25, "output_per_1m": 2.0}}
    price, warning = gcl.guardian_cost_ledger_price_for_model(pricing, "gpt-5-mini-2025-08-07")
    assert warning is None and price["input_per_1m"] == 0.25  # longest row wins, not `gpt-5`
    _price, warning = gcl.guardian_cost_ledger_price_for_model(pricing, "gpt-5mini")
    assert "not found in guardian_pricing" in warning  # no boundary -> no match
