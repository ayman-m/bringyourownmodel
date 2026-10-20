import json

import sys
from pathlib import Path

import GuardianModelProfileCheck as mtc

# The parity tests below import the loop's own implementation to compare answers.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "GuardianReasoningTick"))


def _instances(*pairs, chat_brand="GuardianCohere"):
    """An integration-search response: instances (name, brand, enabled, declared model_tier) plus the
    configuration that marks `chat_brand` as a guardian-llm-chat provider."""
    insts = []
    for name, brand, enabled, tier in pairs:
        data = [{"name": "model_tier", "value": tier}] if tier is not None else [{"name": "model_tier", "value": ""}]
        insts.append({"name": name, "brand": brand, "enabled": enabled, "data": data})
    conf = [{"name": chat_brand, "integrationScript": {"commands": [{"name": "guardian-llm-chat"}]}}]
    return {"instances": insts, "configurations": conf}


def _install(monkeypatch, settings, search_response, calls=None, profile=None, catalog=None, store=None, set_error=None):
    """`profile`: the guardian_model_profile List content (a dict), or None for a List that does not exist.
    `catalog`: the guardian_model_catalog content (a dict), or None for a List that does not exist.
    `store`: a dict that collects what the run writes ({"commands": [...], "profile": <last saved text>})."""
    monkeypatch.setattr(mtc.demisto, "error", lambda msg: None)
    written = {}

    def handler(command, args):
        if calls is not None:
            calls.append(command)
        if store is not None:
            store.setdefault("commands", []).append(command)
        if command == "getList" and args == {"listName": "guardian_settings"}:
            return [{"Type": 1, "Contents": json.dumps(settings)}]
        if command == "getList" and args == {"listName": "guardian_model_profile"}:
            if profile is None:
                return [{"Type": 4, "Contents": "Item not found (8)"}]
            return [{"Type": 1, "Contents": json.dumps(profile)}]
        if command == "getList" and args == {"listName": "guardian_model_catalog"}:
            if catalog is None:
                return [{"Type": 4, "Contents": "Item not found (8)"}]
            return [{"Type": 1, "Contents": json.dumps(catalog)}]
        if command == "GetTime":
            return [{"Type": 1, "Contents": "2026-10-09T10:00:00Z"}]
        if command == "createList" and args["listName"] == "guardian_model_profile":
            assert args["listData"] == "{}"
            return [{"Type": 1, "Contents": "ok"}]
        if command == "setList" and args["listName"] == "guardian_model_profile":
            if set_error:
                return [{"Type": 4, "Contents": set_error}]
            if store is not None:
                store["profile"] = args["listData"]
            return [{"Type": 1, "Contents": "ok"}]
        if command == "demisto-api-post":
            assert args["uri"] == "/settings/integration/search"
            return [{"Type": 1, "Contents": {"response": search_response}}]
        raise AssertionError("unexpected command {} {}".format(command, args))

    monkeypatch.setattr(mtc.demisto, "executeCommand", handler)
    monkeypatch.setattr(mtc.demisto, "setContext", lambda key, value: written.update({key: value}))
    return written


def _profile(probed_at="2026-10-01T03:00:00Z", tools=True):
    return {"active": "GuardianCohere:lab", "overrides": {}, "profiles": {"GuardianCohere:lab": {
        "model": "command-r:35b", "instance_name": "lab", "max_input_tokens": 28102, "window": 32768,
        "probed_at": probed_at, "tools": tools, "structured_output": True}}}


def test_agreeing_sizes_give_no_warning(monkeypatch):
    _install(monkeypatch, {"model_tier": "medium"}, _instances(("lab", "GuardianCohere", "true", "medium")))
    r = mtc.guardian_tiercheck_run()
    assert r["tier"] == "medium" and r["mismatch"] is False and r["warning"] is None


def test_a_disagreeing_enabled_instance_is_named_in_the_warning(monkeypatch):
    _install(monkeypatch, {"model_tier": "medium"}, _instances(("lab", "GuardianCohere", "true", "small")))
    r = mtc.guardian_tiercheck_run()
    assert r["mismatch"] is True and r["tier"] == "medium"
    assert 'lab declares "small"' in r["warning"] and "model size this run uses is \"medium\"" in r["warning"]


def test_a_disabled_instance_or_one_with_no_declared_size_is_ignored(monkeypatch):
    _install(monkeypatch, {"model_tier": "medium"}, _instances(("old", "GuardianCohere", "false", "small"), ("blank", "GuardianCohere", "true", None)))
    assert mtc.guardian_tiercheck_run()["mismatch"] is False


def test_an_unreadable_settings_list_resolves_to_the_safe_default(monkeypatch):
    monkeypatch.setattr(mtc.demisto, "error", lambda msg: None)
    monkeypatch.setattr(mtc.demisto, "executeCommand", lambda c, a: [{"Type": 4, "Contents": "boom"}])
    r = mtc.guardian_tiercheck_run()
    assert r["tier"] == "small" and r["mismatch"] is False  # and the failed search is just "nothing to compare"


def test_main_outputs_to_the_preflight_context_path_and_prints_the_warning(monkeypatch):
    captured = {}
    _install(monkeypatch, {"model_tier": "large"}, _instances(("lab", "GuardianCohere", "true", "small")))
    monkeypatch.setattr(mtc, "return_results", lambda res: captured.update(res=res))
    mtc.main()
    assert captured["res"].outputs_prefix == "Guardian.Preflight.ModelProfile"
    assert "Model-tier configuration WARNING" in captured["res"].readable_output


def test_same_answer_as_the_loops_own_check(monkeypatch):
    """The playbook task is a local copy of the loop's tick-0 check; both must agree on every fixture."""
    import GuardianReasoningTick as tick

    fixtures = [
        _instances(("a", "GuardianCohere", "true", "medium")),
        _instances(("a", "GuardianCohere", "true", "small")),
        _instances(("a", "GuardianCohere", "true", "tiny")),
        _instances(("a", "GuardianCohere", "false", "small")),
        _instances(("a", "GuardianVertex", "true", "large"), ("b", "GuardianCohere", "true", "medium")),
        {"instances": "not a list"},
        {},
    ]
    for response in fixtures:
        monkeypatch.setattr(tick.demisto, "error", lambda msg: None)
        monkeypatch.setattr(tick.demisto, "executeCommand", lambda c, a, r=response: [{"Type": 1, "Contents": {"response": r}}])
        loop_answer = tick.guardian_tick_check_model_tier_consistency("medium")
        monkeypatch.setattr(mtc.demisto, "executeCommand", lambda c, a, r=response: [{"Type": 1, "Contents": {"response": r}}])
        assert mtc.guardian_tiercheck_mismatch_warning("medium") == loop_answer, response


def test_the_run_snapshots_the_resolved_numbers_and_says_where_each_came_from(monkeypatch):
    written = _install(monkeypatch, {"model_tier": "medium", "max_input_tokens": 28258},
                       _instances(("lab", "GuardianCohere", "true", "medium")), profile=_profile())
    r = mtc.guardian_tiercheck_run()
    snap = written["Guardian.ModelProfile"]
    assert snap["tier"] == "medium" and snap["max_input_tokens"] == 28102
    assert snap["max_input_tokens_source"] == "measured"
    assert (r["tier"], r["max_input_tokens"], r["max_tool_def_tokens"]) == ("medium", 28102, 16000)
    text = "\n".join(r["lines"])
    assert "28102 (measured)" in text and "command-r:35b" in text


def test_no_profile_falls_back_to_settings_and_says_so(monkeypatch):
    written = _install(monkeypatch, {"model_tier": "medium", "max_input_tokens": 28258},
                       _instances(("lab", "GuardianCohere", "true", "medium")))
    r = mtc.guardian_tiercheck_run()
    assert written["Guardian.ModelProfile"]["max_input_tokens"] == 28258
    assert "28258 (guardian_settings)" in "\n".join(r["lines"]) and "No measured profile yet" in "\n".join(r["lines"])
    assert r["warnings"] == []


def test_an_old_profile_and_a_model_without_tools_are_warned_about(monkeypatch):
    _install(monkeypatch, {"model_tier": "medium"}, _instances(("lab", "GuardianCohere", "true", "medium")),
             profile=_profile(probed_at="2020-01-01T00:00:00Z", tools=False))
    r = mtc.guardian_tiercheck_run()
    text = " ".join(r["warnings"])
    assert "days old" in text and "does not honor tool calls" in text
    assert r["profile_age_days"] > 3


def test_a_fresh_profile_gives_no_age_warning(monkeypatch):
    stamp = mtc.datetime.now(mtc.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _install(monkeypatch, {"model_tier": "medium"}, _instances(("lab", "GuardianCohere", "true", "medium")),
             profile=_profile(probed_at=stamp))
    r = mtc.guardian_tiercheck_run()
    assert r["warnings"] == [] and r["profile_age_days"] == 0


def test_an_unparseable_probe_time_is_ignored(monkeypatch):
    for bad in (None, "", "yesterday", 5):
        assert mtc.guardian_tiercheck_profile_age_days(bad) is None


def test_the_operator_override_wins_and_the_tier_mismatch_uses_it(monkeypatch):
    plist = _profile()
    plist["overrides"] = {"model_tier": "large", "max_input_tokens": 12000}
    _install(monkeypatch, {"model_tier": "small"}, _instances(("lab", "GuardianCohere", "true", "small")), profile=plist)
    r = mtc.guardian_tiercheck_run()
    assert r["tier"] == "large" and r["max_input_tokens"] == 12000 and r["mismatch"] is True


""" ------------------------- the model catalogue: a documented profile for a known model ------------------------- """

CATALOG = {
    "checked": "2026-10-09",
    "models": [
        {"id": "gpt-5-mini", "aliases": ["gpt-5-mini-2025-08-07"], "vendor": "OpenAI", "open_weight": False,
         "context_window": 400000, "max_input_tokens": 272000, "max_output_tokens": 128000,
         "supports_tools": True, "supports_structured_output": True, "probe": "skip",
         "provider_limits": [{"provider": "azure-foundry", "context_window": 400000, "max_input_tokens": 272000,
                              "max_output_tokens": 128000}]},
        {"id": "gpt-4.1", "aliases": [], "vendor": "OpenAI", "open_weight": False, "context_window": 1047576,
         "max_input_tokens": None, "max_output_tokens": 32768, "supports_tools": True,
         "supports_structured_output": True, "probe": "skip",
         "provider_limits": [{"provider": "azure-foundry", "context_window": 300000, "max_input_tokens": None,
                              "max_output_tokens": 32768}]},
        {"id": "command-a-03-2025", "aliases": ["foundry:Cohere-command-a"], "vendor": "Cohere", "open_weight": True,
         "context_window": 256000, "max_input_tokens": None, "max_output_tokens": 8000, "supports_tools": True,
         "supports_structured_output": True, "probe": "confirm",
         "provider_limits": [{"provider": "azure-foundry", "context_window": None, "max_input_tokens": 131072,
                              "max_output_tokens": 8182}]},
        {"id": "gemini-2.5-pro", "aliases": ["vertex:gemini-2.5-pro"], "vendor": "Google", "open_weight": False,
         "context_window": 1048576, "max_input_tokens": None, "max_output_tokens": 65536, "supports_tools": True,
         "supports_structured_output": True, "probe": "skip", "provider_limits": []},
        {"id": "command-r:35b", "aliases": [], "vendor": "Cohere", "open_weight": True, "context_window": 128000,
         "max_input_tokens": None, "max_output_tokens": 4000, "supports_tools": True,
         "supports_structured_output": True, "probe": "confirm", "provider_limits": []},
    ],
}
KEY = "GuardianFoundry:lab"


def _foundry(model="gpt-5-mini", choice=None, enabled="true"):
    """An integration-search response with one Foundry instance configured with `model` (and a dropdown `choice`)."""
    data = [{"name": "model_tier", "value": "medium"}, {"name": "model", "value": model}]
    if choice is not None:
        data.append({"name": "model_choice", "value": choice})
    conf = [{"name": "GuardianFoundry", "integrationScript": {"commands": [{"name": "guardian-llm-chat"}]}}]
    return {"instances": [{"name": "lab", "brand": "GuardianFoundry", "enabled": enabled, "data": data}], "configurations": conf}


def _record(source="measured", model="gpt-5-mini-2025-08-07", max_input=111111, **over):
    rec = {"provider": "GuardianFoundry", "instance_name": "lab", "model": model, "max_input_tokens": max_input,
           "window": 400000, "source": source, "tools": True, "structured_output": True}
    if source != "documented":
        rec["probed_at"] = "2026-10-08T03:00:00Z"
        rec["model_source"] = "observed"   # a probe records the name the provider reported
    rec.update(over)
    return rec


def _plist(rec, overrides=None, extra=None):
    profiles = {KEY: rec}
    profiles.update(extra or {})
    return {"active": KEY, "overrides": overrides or {}, "profiles": profiles}


GPT5_MINI_BUDGET = int(272000 * 0.85 * (3.0 / 4.0))


def test_a_known_model_gets_a_documented_profile_and_the_list_is_created_when_missing(monkeypatch):
    store = {}
    written = _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=CATALOG, store=store)
    r = mtc.guardian_tiercheck_run()
    assert store["commands"].count("createList") == 1 and store["commands"].index("createList") < store["commands"].index("setList")
    saved = json.loads(store["profile"])
    rec = saved["profiles"][KEY]
    assert saved["active"] == KEY and saved["overrides"] == {}
    assert rec["source"] == "documented" and rec["catalog_id"] == "gpt-5-mini" and rec["catalog_checked"] == "2026-10-09"
    assert rec["max_input_tokens"] == GPT5_MINI_BUDGET and rec["chars_per_token"] == 3.0
    assert rec["chars_per_token_basis"] == "assumed" and rec["documented_input_tokens"] == 272000
    assert rec["limits"]["basis"] == "azure-foundry cap" and rec["window"] == 400000
    assert "probed_at" not in rec and rec["documented_at"] == "2026-10-09T10:00:00Z"
    # the run resolves from the record just written, exactly as it would on the next run
    assert r["max_input_tokens"] == GPT5_MINI_BUDGET and r["profile_source"] == "documented" and r["catalog_action"] == "written"
    assert written["Guardian.ModelProfile"]["max_input_tokens"] == GPT5_MINI_BUDGET


def test_nothing_in_the_output_calls_a_documented_figure_measured_or_probed(monkeypatch):
    store = {}
    written = _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=CATALOG, store=store)
    r = mtc.guardian_tiercheck_run()
    text = "\n".join(r["lines"] + r["warnings"])
    assert "Documented profile: gpt-5-mini on lab" in text
    assert "Input budget (max_input_tokens): {} (documented, catalogue 2026-10-09)".format(GPT5_MINI_BUDGET) in text
    assert "easured" not in text.replace("No measured profile", "") and "robed" not in text.replace("No probe has", "")
    snapshot = written["Guardian.ModelProfile"]
    assert snapshot["max_input_tokens_source"] == "documented, catalogue 2026-10-09"
    assert snapshot["profile"]["source"] == "documented"


def test_a_measured_record_for_the_same_model_is_never_replaced(monkeypatch):
    # the provider-recorded name differs from the configured one, but they are one catalogue model
    for source in ("measured", "confirmed", "quota"):
        store = {}
        _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=CATALOG, store=store,
                 profile=_plist(_record(source=source)))
        r = mtc.guardian_tiercheck_run()
        assert "setList" not in store["commands"] and "createList" not in store["commands"], source
        assert r["max_input_tokens"] == 111111 and r["profile_source"] == source
        assert r["catalog_action"] == "none"


def test_a_record_for_a_different_model_is_rewritten_and_everything_else_is_kept(monkeypatch):
    store = {}
    other = {"provider": "GuardianCohere", "instance_name": "x", "model": "command-r:35b", "max_input_tokens": 5}
    old = _plist(_record(model="command-r:35b", source="measured"), overrides={"max_input_tokens": 9000},
                 extra={"GuardianCohere:x": other})
    old["updated_at"] = "2026-10-01T00:00:00Z"
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=CATALOG, store=store, profile=old)
    r = mtc.guardian_tiercheck_run()
    saved = json.loads(store["profile"])
    assert saved["profiles"][KEY]["source"] == "documented" and saved["profiles"][KEY]["model"] == "gpt-5-mini"
    assert saved["profiles"]["GuardianCohere:x"] == other and saved["overrides"] == {"max_input_tokens": 9000}
    assert "createList" not in store["commands"]
    assert r["max_input_tokens"] == 9000  # the operator's override still wins over the new record


def test_nothing_is_written_when_nothing_would_change(monkeypatch):
    store = {}
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=CATALOG, store=store)
    mtc.guardian_tiercheck_run()
    again = {}
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=CATALOG, store=again, profile=json.loads(store["profile"]))
    r = mtc.guardian_tiercheck_run()
    assert "setList" not in again["commands"] and "createList" not in again["commands"]
    assert r["catalog_action"] == "none" and r["profile_source"] == "documented"


def test_a_documented_record_is_refreshed_when_the_catalogue_or_the_cap_changed(monkeypatch):
    first = {}
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=CATALOG, store=first)
    mtc.guardian_tiercheck_run()
    plist = json.loads(first["profile"])
    newer = dict(CATALOG, checked="2026-12-01")
    store = {}
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=newer, store=store, profile=plist)
    mtc.guardian_tiercheck_run()
    assert json.loads(store["profile"])["profiles"][KEY]["catalog_checked"] == "2026-12-01"
    store = {}
    _install(monkeypatch, {"model_tier": "medium", "max_input_tokens_cap": 100000}, _foundry(), catalog=CATALOG, store=store, profile=plist)
    mtc.guardian_tiercheck_run()
    rec = json.loads(store["profile"])["profiles"][KEY]
    assert rec["max_input_tokens"] == 100000 and rec["capped"] is True


def test_a_self_hosted_open_weight_model_is_not_written_automatically_and_the_report_says_a_probe_is_needed(monkeypatch):
    store = {}
    cohere = {"instances": [{"name": "lab", "brand": "GuardianCohere", "enabled": "true",
                             "data": [{"name": "model_tier", "value": "medium"}, {"name": "model", "value": "command-r:35b"}]}],
              "configurations": [{"name": "GuardianCohere", "integrationScript": {"commands": [{"name": "guardian-llm-chat"}]}}]}
    _install(monkeypatch, {"model_tier": "medium"}, cohere, catalog=CATALOG, store=store)
    r = mtc.guardian_tiercheck_run()
    assert "setList" not in store["commands"] and "createList" not in store["commands"]
    text = "\n".join(r["lines"])
    assert "command-r:35b" in text and "123,904" in text and "open-weight" in text
    assert "!guardian-probe-model" in text and "served window" in text
    assert r["catalog_action"] == "none"


def test_an_open_weight_model_with_a_provider_cap_row_is_written(monkeypatch):
    store = {}
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(model="Cohere-command-a"), catalog=CATALOG, store=store)
    mtc.guardian_tiercheck_run()
    rec = json.loads(store["profile"])["profiles"][KEY]
    assert rec["catalog_id"] == "command-a-03-2025" and rec["documented_input_tokens"] == 131072
    assert rec["limits"]["managed"] is True


def test_a_probed_open_weight_record_silences_the_self_hosted_note(monkeypatch):
    cohere = {"instances": [{"name": "lab", "brand": "GuardianCohere", "enabled": "true",
                             "data": [{"name": "model", "value": "command-r:35b"}]}],
              "configurations": [{"name": "GuardianCohere", "integrationScript": {"commands": [{"name": "guardian-llm-chat"}]}}]}
    plist = {"active": "GuardianCohere:lab", "overrides": {}, "profiles": {"GuardianCohere:lab": {
        "model": "command-r:35b", "max_input_tokens": 28102, "probed_at": "2026-10-08T03:00:00Z"}}}
    _install(monkeypatch, {"model_tier": "medium"}, cohere, catalog=CATALOG, profile=plist)
    r = mtc.guardian_tiercheck_run()
    assert not any("open-weight" in line for line in r["lines"])


def test_the_recorded_model_name_is_tried_when_the_configured_one_is_not_in_the_catalogue(monkeypatch):
    store = {}
    # a custom deployment name; an earlier probe recorded what the provider reported for it
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(model="prod-chat"), catalog=CATALOG, store=store,
             profile=_plist(_record(source="measured")))
    r = mtc.guardian_tiercheck_run()
    assert "setList" not in store["commands"] and r["profile_source"] == "measured"   # same model: not replaced
    store = {}
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(model="prod-chat"), catalog=CATALOG, store=store)
    r = mtc.guardian_tiercheck_run()      # nothing recorded and not listed: nothing to document
    assert "setList" not in store["commands"] and r["catalog_action"] == "none"


def test_the_foundry_model_dropdown_is_honoured(monkeypatch):
    store = {}
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(model="ignored-name", choice="gpt-4.1"), catalog=CATALOG, store=store)
    mtc.guardian_tiercheck_run()
    rec = json.loads(store["profile"])["profiles"][KEY]
    assert rec["catalog_id"] == "gpt-4.1" and rec["limits"]["context_window"] == 300000     # the Azure cap, not the vendor 1M
    store = {}
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(model="gpt-4.1", choice="Custom (use the deployment name below)"),
             catalog=CATALOG, store=store)
    mtc.guardian_tiercheck_run()
    assert json.loads(store["profile"])["profiles"][KEY]["catalog_id"] == "gpt-4.1"


def test_a_missing_catalogue_or_a_disabled_instance_changes_nothing(monkeypatch):
    for response, catalog in ((_foundry(), None), (_foundry(enabled="false"), CATALOG), ({"instances": []}, CATALOG)):
        store = {}
        _install(monkeypatch, {"model_tier": "medium", "max_input_tokens": 28258}, response, catalog=catalog, store=store)
        r = mtc.guardian_tiercheck_run()
        assert "setList" not in store["commands"] and "createList" not in store["commands"]
        assert r["max_input_tokens"] == 28258 and r["catalog_action"] == "none"


def test_a_failed_write_is_a_warning_and_the_run_goes_on(monkeypatch):
    store = {}
    _install(monkeypatch, {"model_tier": "medium", "max_input_tokens": 28258}, _foundry(), catalog=CATALOG, store=store,
             set_error="boom", profile={})
    r = mtc.guardian_tiercheck_run()
    assert r["catalog_action"] == "failed" and r["max_input_tokens"] == 28258          # falls back to guardian_settings
    assert any("could not be saved" in w for w in r["warnings"])


def test_an_unreadable_profile_list_is_never_overwritten(monkeypatch):
    store = {}
    monkeypatch.setattr(mtc.demisto, "error", lambda msg: None)
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=CATALOG, store=store, profile=None)
    real = mtc.demisto.executeCommand

    def broken(command, args):
        if command == "getList" and args == {"listName": "guardian_model_profile"}:
            return [{"Type": 1, "Contents": "{not json"}]
        return real(command, args)

    monkeypatch.setattr(mtc.demisto, "executeCommand", broken)
    r = mtc.guardian_tiercheck_run()
    assert "setList" not in store["commands"] and "createList" not in store["commands"]
    assert any("profile list unreadable" in w for w in r["warnings"])


def test_a_documented_record_never_triggers_the_stale_profile_warning(monkeypatch):
    store = {}
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=CATALOG, store=store)
    mtc.guardian_tiercheck_run()
    again = {}
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=CATALOG, store=again, profile=json.loads(store["profile"]))
    r = mtc.guardian_tiercheck_run()
    assert r["profile_age_days"] is None and not any("days old" in w for w in r["warnings"])


def test_a_catalogue_model_without_tool_support_is_warned_about_in_catalogue_words(monkeypatch):
    catalog = json.loads(json.dumps(CATALOG))
    catalog["models"][0]["supports_tools"] = False
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=catalog, store={})
    r = mtc.guardian_tiercheck_run()
    assert any("model catalogue lists this model as not supporting tool calls" in w for w in r["warnings"])
    assert not any("the probe found" in w for w in r["warnings"])


def test_the_run_makes_one_integration_search_for_both_checks(monkeypatch):
    calls = []
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=CATALOG, calls=calls, store={})
    mtc.guardian_tiercheck_run()
    assert calls.count("demisto-api-post") == 1
    assert calls.count("getList") == 3      # guardian_settings, guardian_model_profile, guardian_model_catalog: one read each


def test_a_documented_record_written_by_the_profile_update_after_a_probe_is_left_alone(monkeypatch):
    """GuardianModelProfileUpdate writes the model name the provider reported and a measured ratio; the next
    run of this task must see the same figures and write nothing (no flip-flop between the two writers)."""
    rec = {"provider": "GuardianFoundry", "instance_name": "lab", "model": "gpt-5-mini-2025-08-07", "source": "documented",
           "catalog_id": "gpt-5-mini", "catalog_checked": "2026-10-09",
           "limits": {"context_window": 400000, "max_input_tokens": 272000, "max_output_tokens": 128000,
                      "basis": "azure-foundry cap", "managed": True},
           "documented_input_tokens": 272000, "window": 400000, "at_ceiling": False,
           "max_input_tokens": int(272000 * 0.85 * (2.5 / 4.0)), "output_reserve": 4096, "chars_per_token": 2.5,
           "chars_per_token_basis": "measured", "tools": True, "structured_output": False, "truncated": False,
           "documented_at": "2026-10-08T03:00:00Z"}
    store = {}
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=CATALOG, store=store, profile=_plist(rec))
    r = mtc.guardian_tiercheck_run()
    assert "setList" not in store["commands"] and r["catalog_action"] == "none"
    assert r["max_input_tokens"] == int(272000 * 0.85 * (2.5 / 4.0))


def test_a_documented_record_does_not_hide_that_the_instance_was_switched_to_an_unlisted_model(monkeypatch):
    first = {}
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=CATALOG, store=first)
    mtc.guardian_tiercheck_run()
    old_record = json.loads(first["profile"])
    assert old_record["profiles"][KEY]["model_source"] == "configured"
    store = {}
    # the operator switches the instance from gpt-5-mini to a deployment the catalogue does not list
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(model="prod-chat"), catalog=CATALOG, store=store, profile=old_record)
    r = mtc.guardian_tiercheck_run()
    assert "setList" not in store["commands"]
    text = "\n".join(r["lines"])
    assert "the profile on record is for `gpt-5-mini`" in text and "configured with `prod-chat`" in text
    assert "!guardian-probe-model" in text


def test_a_name_the_catalogue_cannot_place_never_makes_an_observed_record_look_like_another_model(monkeypatch):
    store = {}
    rec = _record(source="measured", model="mystery-deployment-eastus")      # model_source: observed
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=CATALOG, store=store, profile=_plist(rec))
    r = mtc.guardian_tiercheck_run()
    assert "setList" not in store["commands"] and r["profile_source"] == "measured"
    # ... but a record that only carries the configured name of an earlier model is replaced
    store = {}
    rec = _record(source="measured", model="other-model")
    rec["model_source"] = "declared"
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=CATALOG, store=store, profile=_plist(rec))
    mtc.guardian_tiercheck_run()
    assert json.loads(store["profile"])["profiles"][KEY]["source"] == "documented"


def test_the_documented_record_carries_the_inputs_of_its_budget(monkeypatch):
    store = {}
    _install(monkeypatch, {"model_tier": "medium", "max_input_tokens_cap": 100000}, _foundry(), catalog=CATALOG, store=store)
    mtc.guardian_tiercheck_run()
    inputs = json.loads(store["profile"])["profiles"][KEY]["budget_inputs"]
    assert inputs == {"usable_input_tokens": 272000, "output_reserve": 4096, "chars_per_token": 3.0,
                      "chars_per_token_source": "assumed", "safety_margin": 0.85, "cap": 100000, "capped": True}


def _vertex(model="gemini-2.5-pro"):
    conf = [{"name": "GuardianVertex", "integrationScript": {"commands": [{"name": "guardian-llm-chat"}]}}]
    return {"instances": [{"name": "v1", "brand": "GuardianVertex", "enabled": "true",
                           "data": [{"name": "model", "value": model}]}], "configurations": conf}


def _run(monkeypatch, response, plist, settings=None):
    store = {}
    _install(monkeypatch, settings or {"model_tier": "medium"}, response, catalog=CATALOG, store=store, profile=plist)
    result = mtc.guardian_tiercheck_run()
    saved = json.loads(store["profile"]) if "profile" in store else plist
    return result, saved, store


def test_switching_back_to_an_instance_makes_its_record_the_active_one_again(monkeypatch):
    # Foundry gpt-5-mini, then Vertex gemini-2.5-pro, then back to Foundry
    first, plist, _ = _run(monkeypatch, _foundry(), None)
    assert plist["active"] == KEY and first["max_input_tokens"] == GPT5_MINI_BUDGET
    second, plist, _ = _run(monkeypatch, _vertex(), plist)
    assert plist["active"] == "GuardianVertex:v1"
    assert second["max_input_tokens"] == int((1048576 - 4096) * 0.85 * 0.75) == 665856
    third, plist, store = _run(monkeypatch, _foundry(), plist)
    assert third["catalog_action"] == "activated" and plist["active"] == KEY
    assert third["max_input_tokens"] == GPT5_MINI_BUDGET                    # not the Vertex budget
    assert store["commands"].count("setList") == 1 and "createList" not in store["commands"]
    assert set(plist["profiles"]) == {KEY, "GuardianVertex:v1"}             # both records kept
    # and the run after that has nothing to do
    fourth, _plist, store = _run(monkeypatch, _foundry(), plist)
    assert fourth["catalog_action"] == "none" and "setList" not in store["commands"]


def test_activation_changes_only_active_and_updated_at(monkeypatch):
    _first, plist, _ = _run(monkeypatch, _foundry(), None)
    _second, plist, _ = _run(monkeypatch, _vertex(), plist)
    plist["overrides"] = {"max_input_tokens": 9000}
    before = json.loads(json.dumps(plist))
    _third, after, _ = _run(monkeypatch, _foundry(), plist)
    for key in ("profiles", "overrides", "_help"):
        assert after[key] == before[key]
    assert after["active"] == KEY and after["updated_at"] == "2026-10-09T10:00:00Z"


def test_a_measured_record_for_the_same_model_is_activated_too_but_never_rewritten(monkeypatch):
    plist = _plist(_record(source="measured"))
    plist["active"] = "GuardianVertex:v1"
    plist["profiles"]["GuardianVertex:v1"] = {"model": "gemini-2.5-pro", "max_input_tokens": 665856, "source": "documented"}
    result, after, store = _run(monkeypatch, _foundry(), plist)
    assert after["active"] == KEY and after["profiles"][KEY] == plist["profiles"][KEY]
    assert result["max_input_tokens"] == 111111 and result["profile_source"] == "measured"
    assert result["catalog_action"] == "activated"


def test_an_unlisted_model_with_its_own_probed_record_is_activated_when_switching_back(monkeypatch):
    cohere = {"instances": [{"name": "lab", "brand": "GuardianCohere", "enabled": "true",
                             "data": [{"name": "model", "value": "command-r:35b"}]}],
              "configurations": [{"name": "GuardianCohere", "integrationScript": {"commands": [{"name": "guardian-llm-chat"}]}}]}
    plist = {"active": KEY, "overrides": {}, "profiles": {
        KEY: {"model": "gpt-5-mini", "max_input_tokens": 173400, "source": "documented"},
        "GuardianCohere:lab": {"model": "command-r:35b", "model_source": "declared", "max_input_tokens": 28102,
                               "probed_at": "2026-10-08T03:00:00Z"}}}
    result, after, _ = _run(monkeypatch, cohere, plist)
    assert after["active"] == "GuardianCohere:lab" and result["max_input_tokens"] == 28102


def test_a_failed_activation_is_a_warning_and_the_run_goes_on(monkeypatch):
    plist = _plist(_record(source="measured"))
    plist["active"] = "GuardianVertex:v1"
    _install(monkeypatch, {"model_tier": "medium"}, _foundry(), catalog=CATALOG, store={}, profile=plist, set_error="boom")
    result = mtc.guardian_tiercheck_run()
    assert any("could not be made the active one" in w for w in result["warnings"])


# --- the model's size follows the catalogue ------------------------------------------------------------------------

SHIPPED_CATALOG = json.loads(json.loads(
    (Path(__file__).resolve().parents[2] / "Lists" / "list-guardian_model_catalog.json").read_text())["data"])


def _cohere(model="command-r:35b", dropdown="auto"):
    conf = [{"name": "GuardianCohere", "integrationScript": {"commands": [{"name": "guardian-llm-chat"}]}}]
    data = [{"name": "model_tier", "value": dropdown}, {"name": "model", "value": model}]
    return {"instances": [{"name": "lab", "brand": "GuardianCohere", "enabled": "true", "data": data}], "configurations": conf}


def _run_shipped(monkeypatch, response, plist, settings):
    store = {}
    written = _install(monkeypatch, settings, response, catalog=SHIPPED_CATALOG, store=store, profile=plist)
    return mtc.guardian_tiercheck_run(), store, written


def test_a_catalogued_closed_model_is_large_and_an_old_explicit_setting_is_reported_not_used(monkeypatch):
    r, store, written = _run_shipped(monkeypatch, _foundry("gpt-5-mini"), None, {"model_tier": "small", "max_input_tokens": 28258})
    assert (r["tier"], r["tier_source"]) == ("large", "catalogue (gpt-5-mini)")
    assert r["max_input_tokens"] == GPT5_MINI_BUDGET and r["max_tool_def_tokens"] == GPT5_MINI_BUDGET * 25 // 100
    text = "\n".join(r["lines"])
    note = ("guardian_settings.model_tier (small) is not used: gpt-5-mini is a large model in the model catalogue; "
            "to force a size use overrides.model_tier in guardian_model_profile.")
    assert text.count(note) == 1
    assert "Tool result limit: 138,720 bytes per result (20% of the input budget)." in text
    assert "History: compacted by tokens at {:,}.".format(GPT5_MINI_BUDGET) in text
    snapshot = written["Guardian.ModelProfile"]
    assert snapshot["tier"] == "large" and snapshot["limits"]["evidence_truncate_bytes"] == 138720
    assert mtc.guardian_model_params_valid(snapshot)
    saved = json.loads(store["profile"])
    assert "size_class" not in saved["profiles"][KEY] and "tier" not in saved["profiles"][KEY]  # nothing new is stored


def test_a_record_written_before_sizes_existed_gets_its_size_with_no_rewrite(monkeypatch):
    # a measured/confirmed/quota record is never rewritten by this task, and it carries no size field of any kind
    for source in ("measured", "confirmed", "quota"):
        old = _plist(_record(source=source, model="gpt-5-mini", catalog_id="gpt-5-mini", max_input=GPT5_MINI_BUDGET))
        before = json.dumps(old, sort_keys=True)
        r, store, _written = _run_shipped(monkeypatch, _foundry("gpt-5-mini"), old, {"model_tier": "auto", "max_input_tokens": 28258})
        assert (r["tier"], r["tier_source"]) == ("large", "catalogue (gpt-5-mini)"), source
        assert "setList" not in store["commands"] and "createList" not in store["commands"], source   # nothing was written
        assert json.dumps(old, sort_keys=True) == before and r["profile_source"] == source
    # a record found by the name the provider reported (no catalogue id) is sized the same way
    named = _plist(_record(source="measured", model="gpt-5-mini-2025-08-07"))
    r, store, _written = _run_shipped(monkeypatch, _foundry("gpt-5-mini"), named, {"model_tier": "auto"})
    assert r["tier"] == "large" and "setList" not in store["commands"]


def test_a_documented_record_the_task_rewrites_still_carries_no_size_field(monkeypatch):
    old = _plist(_record(source="documented", model="gpt-5-mini", catalog_id="gpt-5-mini", max_input=GPT5_MINI_BUDGET,
                         catalog_checked="2026-10-01", documented_input_tokens=272000, limits={"basis": "azure-foundry cap"}))
    r, store, _written = _run_shipped(monkeypatch, _foundry("gpt-5-mini"), old, {"model_tier": "auto", "max_input_tokens": 28258})
    assert (r["tier"], r["tier_source"]) == ("large", "catalogue (gpt-5-mini)")
    rewritten = json.loads(store["profile"])["profiles"][KEY]   # its inputs changed (catalogue date), so it is rewritten
    assert rewritten["catalog_id"] == "gpt-5-mini" and "size_class" not in rewritten and "tier" not in rewritten


def test_a_catalogued_open_weight_model_with_no_record_gets_its_size_from_the_configured_name(monkeypatch):
    r, store, _written = _run_shipped(monkeypatch, _cohere("command-r:35b"), None, {"model_tier": "auto", "max_input_tokens": 28258})
    assert (r["tier"], r["tier_source"]) == ("medium", "catalogue (command-r-08-2024)")
    assert r["max_input_tokens"] == 28258 and r["max_tool_def_tokens"] == 16000
    assert "setList" not in store["commands"]   # a self-hosted open-weight model is never written automatically


def test_an_unknown_model_uses_the_settings_value_then_small(monkeypatch):
    r, _s, _w = _run_shipped(monkeypatch, _cohere("some-private-model"), None, {"model_tier": "medium", "max_input_tokens": 28258})
    assert (r["tier"], r["tier_source"]) == ("medium", "guardian_settings")
    r, _s, _w = _run_shipped(monkeypatch, _cohere("some-private-model"), None, {"model_tier": "auto", "max_input_tokens": 28258})
    assert (r["tier"], r["tier_source"]) == ("small", "default (model not in the catalogue; set model_tier in guardian_settings)")
    assert (r["max_tool_def_tokens"], r["limits"]["evidence_truncate_bytes"]) == (4000, 22606)


def test_an_operator_pin_beats_the_catalogue(monkeypatch):
    plist = {"active": None, "profiles": {}, "overrides": {"model_tier": "small"}}
    r, _s, _w = _run_shipped(monkeypatch, _foundry("gpt-5-mini"), plist, {"model_tier": "auto", "max_input_tokens": 28258})
    assert (r["tier"], r["tier_source"]) == ("small", "override")
    assert not [line for line in r["lines"] if "is not used" in line]


def test_the_dropdown_is_compared_with_the_resolved_size_and_auto_is_no_declaration(monkeypatch):
    r, _s, _w = _run_shipped(monkeypatch, _cohere("command-r:35b", dropdown="medium"), None, {"model_tier": "auto"})
    assert r["tier"] == "medium" and r["mismatch"] is False
    r, _s, _w = _run_shipped(monkeypatch, _cohere("command-r:35b", dropdown="auto"), None, {"model_tier": "auto"})
    assert r["mismatch"] is False
    r, _s, _w = _run_shipped(monkeypatch, _cohere("command-r:35b", dropdown="small"), None, {"model_tier": "auto"})
    # a stale dropdown on a catalogue-sized model is one short note, not a configuration warning
    assert r["mismatch"] is False and r["warning"].startswith("Model size note:") and "WARNING" not in r["warning"]
    assert 'lab declares "small"' in r["warning"] and 'this run uses "medium" (catalogue (command-r-08-2024))' in r["warning"]
    assert r["warning"] in r["warnings"] and "\n" not in r["warning"]
    # a size the operator set that the dropdown contradicts is still the warning
    r, _s, _w = _run_shipped(monkeypatch, _cohere("some-private-model", dropdown="small"), None, {"model_tier": "large"})
    assert r["mismatch"] is True and "Model-tier configuration WARNING" in r["warning"]
    assert mtc.guardian_tiercheck_mismatch_warning("medium", _cohere(dropdown="AUTO")) is None


def test_the_turn_limit_follows_the_size_and_is_reported_and_snapshotted(monkeypatch):
    r, _store, written = _run_shipped(monkeypatch, _foundry("gpt-5-mini"), None, {"model_tier": "auto", "max_input_tokens": 28258})
    assert "Turn limit (MAX_TICKS): 60 (tier)." in r["lines"] and written["Guardian.ModelProfile"]["max_ticks"] == 60
    r, _store, written = _run_shipped(monkeypatch, _cohere("command-r:35b"), None, {"model_tier": "auto", "max_input_tokens": 28258})
    assert "Turn limit (MAX_TICKS): 40 (tier)." in r["lines"]
    r, _store, written = _run_shipped(monkeypatch, _cohere("some-private-model"), None, {"model_tier": "auto", "max_input_tokens": 28258})
    assert "Turn limit (MAX_TICKS): 25 (tier)." in r["lines"]
    r, _store, written = _run_shipped(monkeypatch, _foundry("gpt-5-mini"), None, {"model_tier": "auto", "MAX_TICKS": 30})
    assert "Turn limit (MAX_TICKS): 30 (guardian_settings)." in r["lines"] and written["Guardian.ModelProfile"]["max_ticks"] == 30
    plist = {"active": None, "profiles": {}, "overrides": {"max_ticks": 12}}
    r, _store, _w = _run_shipped(monkeypatch, _foundry("gpt-5-mini"), plist, {"model_tier": "auto", "MAX_TICKS": 30})
    assert "Turn limit (MAX_TICKS): 12 (override)." in r["lines"]
