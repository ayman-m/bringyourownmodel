import json
import GuardianModelCommand as model_cmd


# --- fixtures / test harness --------------------------------------------------


def _rest_ok(response_obj):
    def handler(args):
        return [{"Type": 1, "Contents": {"response": response_obj}}]

    return handler


def _rest_error(message):
    def handler(args):
        return [{"Type": 4, "Contents": message}]

    return handler


def _install(monkeypatch, rest_post_handler=None, profile=None, catalog=None):
    """FIX C: GuardianModelCommand is now READ-ONLY -- it only ever issues a
    `/settings/integration/search` REST read; there is no getList/setList
    path left. Any command other than the REST post is an unexpected
    dispatch (a regression), so `fake_execute` asserts loudly on one."""
    rest_handler = rest_post_handler or _rest_ok({"instances": []})

    def fake_execute(command, args):
        if command in ("demisto-api-post", "core-api-post"):
            return rest_handler(args)
        if command == "getList" and args.get("listName") == "guardian_settings":
            return [{"Type": 1, "Contents": json.dumps({"model_tier": "medium", "max_input_tokens": 28258})}]
        if command == "getList" and args.get("listName") == "guardian_model_profile":
            if profile is not None:
                return [{"Type": 1, "Contents": json.dumps(profile)}]
            return [{"Type": 4, "Contents": "Item not found (8)"}]  # the optional measured profile
        if command == "getList" and args.get("listName") == "guardian_model_catalog":
            if catalog is not None:
                return [{"Type": 1, "Contents": json.dumps(catalog)}]
            return [{"Type": 4, "Contents": "Item not found (8)"}]  # the optional model catalogue
        raise AssertionError("unexpected command dispatched: {} {}".format(command, args))

    monkeypatch.setattr(model_cmd.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(model_cmd.demisto, "error", lambda msg: None)
    monkeypatch.setattr(model_cmd.demisto, "info", lambda msg: None)


def _instance(
    name, enabled="true", provider="vertex", model="gemini-2.5-flash", model_tier=None, brand="GuardianVertex"
):
    data = []
    if provider is not None:
        data.append({"name": "provider", "value": provider})
    if model is not None:
        data.append({"name": "model", "value": model})
    if model_tier is not None:
        data.append({"name": "model_tier", "value": model_tier})
    return {"name": name, "brand": brand, "enabled": enabled, "data": data}


# --- guardian_model_cmd_integration_enabled --------------------------------------


def test_enabled_string_true_and_false():
    assert model_cmd.guardian_model_cmd_integration_enabled({"enabled": "true"}) is True
    assert model_cmd.guardian_model_cmd_integration_enabled({"enabled": "false"}) is False
    assert model_cmd.guardian_model_cmd_integration_enabled({"enabled": True}) is True
    assert model_cmd.guardian_model_cmd_integration_enabled({}) is False


# --- guardian_model_cmd_param_values ----------------------------------------------


def test_param_values_extracted():
    inst = _instance("guardian_llm_1", provider="vertex", model="gemini-2.5-pro", model_tier="large")
    values = model_cmd.guardian_model_cmd_param_values(inst)
    assert values == {"provider": "vertex", "model": "gemini-2.5-pro", "model_tier": "large"}


def _foundry_instance(model_choice=None, model=None):
    data = [{"name": "provider", "value": "foundry"}]
    if model_choice is not None:
        data.append({"name": "model_choice", "value": model_choice})
    if model is not None:
        data.append({"name": "model", "value": model})
    return {"name": "guardian_foundry_1", "brand": "GuardianFoundry", "enabled": "true", "data": data}


def test_param_values_foundry_dropdown_set_deployment_empty():
    values = model_cmd.guardian_model_cmd_param_values(_foundry_instance(model_choice="gpt-5-mini", model=""))
    assert values["model"] == "gpt-5-mini"


def test_param_values_foundry_dropdown_wins_over_deployment():
    values = model_cmd.guardian_model_cmd_param_values(_foundry_instance(model_choice="gpt-5-mini", model="old-deployment"))
    assert values["model"] == "gpt-5-mini"


def test_param_values_foundry_custom_uses_deployment():
    values = model_cmd.guardian_model_cmd_param_values(
        _foundry_instance(model_choice="Custom (use the deployment name below)", model="my-deployment")
    )
    assert values["model"] == "my-deployment"


def test_param_values_foundry_without_dropdown_uses_deployment():
    # an instance saved before Guardian 1.0.3 has no model_choice param at all
    values = model_cmd.guardian_model_cmd_param_values(_foundry_instance(model="legacy-deployment"))
    assert values["model"] == "legacy-deployment"


def test_param_values_foundry_custom_label_matches_integration():
    # the label is duplicated on purpose (no cross-script imports): keep it identical to the integration's
    import re
    import os

    path = os.path.join(os.path.dirname(__file__), "..", "..", "Integrations", "GuardianFoundry", "GuardianFoundry.py")
    if not os.path.exists(path):  # e.g. a per-script docker run that mounts only this script
        return
    with open(path) as handle:
        match = re.search(r'^MODEL_CHOICE_CUSTOM = "(.*)"$', handle.read(), re.M)
    assert match and match.group(1) == model_cmd.GUARDIAN_MODEL_CMD_CHOICE_CUSTOM


def test_param_values_vertex_instance_unchanged():
    values = model_cmd.guardian_model_cmd_param_values(_instance("v", provider="vertex", model="gemini-2.5-flash"))
    assert values == {"provider": "vertex", "model": "gemini-2.5-flash", "model_tier": None}


def test_param_values_missing_data():
    assert model_cmd.guardian_model_cmd_param_values({}) == {"provider": None, "model": None, "model_tier": None}


# --- guardian_model_cmd_load_instances --------------------------------------------


def test_load_instances_filters_by_brand(monkeypatch):
    _install(
        monkeypatch,
        rest_post_handler=_rest_ok(
            {
                "instances": [
                    _instance("guardian_llm_1"),
                    {"name": "splunk_1", "brand": "SplunkPy", "enabled": "true", "data": []},
                ]
            }
        ),
    )
    result = model_cmd.guardian_model_cmd_load_instances()
    assert result["ok"] is True
    assert len(result["data"]) == 1
    assert result["data"][0]["instance_name"] == "guardian_llm_1"
    assert result["data"][0]["provider"] == "vertex"
    assert result["data"][0]["model"] == "gemini-2.5-flash"


def test_load_instances_none_configured(monkeypatch):
    _install(monkeypatch, rest_post_handler=_rest_ok({"instances": []}))
    result = model_cmd.guardian_model_cmd_load_instances()
    assert result["ok"] is True
    assert result["data"] == []


def test_load_instances_rest_failure(monkeypatch):
    _install(monkeypatch, rest_post_handler=_rest_error("connection refused"))
    result = model_cmd.guardian_model_cmd_load_instances()
    assert result["ok"] is False


def test_load_instances_enabled_sorted_first(monkeypatch):
    _install(
        monkeypatch,
        rest_post_handler=_rest_ok(
            {
                "instances": [
                    _instance("z_disabled", enabled="false"),
                    _instance("a_enabled", enabled="true"),
                ]
            }
        ),
    )
    result = model_cmd.guardian_model_cmd_load_instances()
    names = [row["instance_name"] for row in result["data"]]
    assert names == ["a_enabled", "z_disabled"]


# --- guardian_model_cmd_run (end to end) -------------------------------------------


def test_run_read_only_shows_instances(monkeypatch):
    """FIX C: run() takes no args, writes nothing, and returns just the
    live instance table -- no settings read, no set_result."""
    _install(monkeypatch, rest_post_handler=_rest_ok({"instances": [_instance("guardian_llm_1")]}))
    result = model_cmd.guardian_model_cmd_run()
    assert result["ok"] is True
    assert len(result["data"]["instances"]) == 1
    assert "set_result" not in result["data"]  # write path is gone
    assert "settings_model" not in result["data"]


def test_run_no_setlist_getlist_ever_dispatched(monkeypatch):
    """Proves the read-only guarantee at the dispatch layer: `_install`'s
    fake_execute raises AssertionError if anything other than the REST post
    is dispatched, so this passing is itself proof no getList/setList runs."""
    _install(monkeypatch, rest_post_handler=_rest_ok({"instances": []}))
    result = model_cmd.guardian_model_cmd_run()
    assert result["ok"] is True
    assert result["data"]["instances"] == []


def test_run_instances_load_failure_is_hard_error(monkeypatch):
    _install(monkeypatch, rest_post_handler=_rest_error("connection refused"))
    result = model_cmd.guardian_model_cmd_run()
    assert result["ok"] is False


# --- guardian_model_cmd_render -----------------------------------------------------


def test_render_shows_instance_table():
    data = {
        "instances": [
            {
                "instance_name": "guardian_llm_1",
                "enabled": True,
                "provider": "vertex",
                "model": "gemini-2.5-flash",
                "model_tier": "large",
            }
        ],
    }
    text = model_cmd.guardian_model_cmd_render(data)
    assert "guardian_llm_1" in text
    assert "gemini-2.5-flash" in text
    assert "large" in text
    assert "READ-ONLY" in text


def test_dropdown_text_says_display_only_and_that_the_size_comes_from_the_catalogue():
    for blank in (None, "", "auto", "AUTO", " auto "):
        text = model_cmd.guardian_model_cmd_dropdown_text(blank)
        assert text == "auto (display-only; the size comes from the model catalogue)"
    assert model_cmd.guardian_model_cmd_dropdown_text("small") == "small (display-only)"
    assert "fails safe" not in model_cmd.guardian_model_cmd_dropdown_text(None)


def test_render_shows_not_set_for_missing_model_tier():
    # An instance predating the "Model size" param (or set via raw REST that
    # omitted it) must render a clear fallback, not a raw None or a KeyError.
    data = {
        "instances": [
            {
                "instance_name": "guardian_llm_1",
                "enabled": True,
                "provider": "vertex",
                "model": "gemini-2.5-flash",
                "model_tier": None,
            }
        ],
    }
    text = model_cmd.guardian_model_cmd_render(data)
    assert "auto (display-only; the size comes from the model catalogue)" in text and "fails safe" not in text


def test_render_no_instances():
    data = {"instances": []}
    text = model_cmd.guardian_model_cmd_render(data)
    assert "No Guardian LLM provider integration" in text


def test_render_notes_read_only_and_where_to_change_model():
    data = {"instances": []}
    text = model_cmd.guardian_model_cmd_render(data)
    assert "READ-ONLY" in text
    assert "integration instance" in text


# --- main() smoke tests --------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    _install(monkeypatch, rest_post_handler=_rest_ok({"instances": [_instance("guardian_llm_1")]}))
    monkeypatch.setattr(model_cmd.demisto, "args", lambda: {})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    model_cmd.main()

    assert len(csp.RESULTS) == 1
    assert len(csp.RESULTS[0].outputs["instances"]) == 1


def test_main_hard_error_calls_return_error(monkeypatch):
    import pytest

    _install(monkeypatch, rest_post_handler=_rest_error("connection refused"))
    monkeypatch.setattr(model_cmd.demisto, "args", lambda: {})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    with pytest.raises(SystemExit):
        model_cmd.main()
    assert len(csp.RESULTS) == 0


# --- the numbers an investigation would use ---------------------------------------------------------


def test_run_reports_the_effective_model_numbers_with_their_sources(monkeypatch):
    _install(monkeypatch, rest_post_handler=_rest_ok({"instances": [_instance("guardian_llm_1")]}))
    data = model_cmd.guardian_model_cmd_run()["data"]
    assert data["effective"]["tier"] == "medium" and data["effective"]["max_input_tokens"] == 28258
    text = model_cmd.guardian_model_cmd_render(data)
    assert "What an investigation started now would use" in text
    assert "Model size: medium (guardian_settings)" in text
    assert "28258 (guardian_settings)" in text


def test_effective_numbers_are_left_out_when_settings_cannot_be_read(monkeypatch):
    def fake_execute(command, args):
        if command in ("demisto-api-post", "core-api-post"):
            return _rest_ok({"instances": []})(args)
        return [{"Type": 4, "Contents": "boom"}]

    monkeypatch.setattr(model_cmd.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(model_cmd.demisto, "error", lambda msg: None)
    data = model_cmd.guardian_model_cmd_run()["data"]
    assert data["effective"] is None
    assert "What an investigation started now" not in model_cmd.guardian_model_cmd_render(data)


# --- where each figure comes from: documented, confirmed, measured, quota, override ----------------------------------

CATALOG = {"checked": "2026-10-09", "models": [
    {"id": "gpt-5-mini", "aliases": ["gpt-5-mini-2025-08-07"], "vendor": "OpenAI", "open_weight": False,
     "context_window": 400000, "max_input_tokens": 272000, "max_output_tokens": 128000, "probe": "skip",
     "provider_limits": [{"provider": "azure-foundry", "context_window": 400000, "max_input_tokens": 272000,
                          "max_output_tokens": 128000}]}]}


def _plist(record, overrides=None):
    return {"active": "GuardianFoundry:lab", "overrides": overrides or {}, "profiles": {"GuardianFoundry:lab": record}}


def _effective_text(monkeypatch, plist, catalog=None):
    _install(monkeypatch, rest_post_handler=_rest_ok({"instances": [_instance("guardian_llm_1")]}), profile=plist,
             catalog=catalog)
    data = model_cmd.guardian_model_cmd_run()["data"]
    return data, model_cmd.guardian_model_cmd_render(data)


def test_a_documented_figure_is_shown_with_the_catalogue_date_and_never_as_measured(monkeypatch):
    record = {"provider": "GuardianFoundry", "instance_name": "lab", "model": "gpt-5-mini", "source": "documented",
              "catalog_id": "gpt-5-mini", "catalog_checked": "2026-10-09", "max_input_tokens": 173400,
              "documented_input_tokens": 272000, "limits": {"basis": "azure-foundry cap"}, "window": 400000}
    data, text = _effective_text(monkeypatch, _plist(record))
    assert "173400 (documented, catalogue 2026-10-09)" in text
    assert "Documented profile: gpt-5-mini on lab, from the model catalogue checked 2026-10-09 (azure-foundry cap)" in text
    assert "easured" not in text.replace("No measured", "") and "probed" not in text
    assert data["effective"]["max_input_tokens_source"] == "documented, catalogue 2026-10-09"


def test_a_confirmed_figure_says_the_probe_agreed_with_the_documented_limit(monkeypatch):
    record = {"provider": "GuardianFoundry", "instance_name": "lab", "model": "m", "source": "confirmed",
              "max_input_tokens": 100, "window": 90000, "documented_input_tokens": 100000,
              "probed_at": "2026-10-08T03:00:00Z"}
    _data, text = _effective_text(monkeypatch, _plist(record))
    assert "(confirmed by a probe, documented limit used)" in text
    assert "Confirmed profile: m on lab, probed 2026-10-08T03:00:00Z. The measured window (90000) is within 20%" in text


def test_a_measured_figure_shows_its_gap_from_the_documented_limit_and_the_evidence(monkeypatch):
    record = {"provider": "GuardianFoundry", "instance_name": "lab", "model": "m", "source": "measured",
              "max_input_tokens": 24000, "window": 60000, "documented_input_tokens": 100000,
              "evidence": "past 60000 tokens the first response took 41.2 s, above the acceptable 30 s",
              "probed_at": "2026-10-08T03:00:00Z"}
    _data, text = _effective_text(monkeypatch, _plist(record))
    assert "24000 (measured)" in text
    assert "The measured window (60,000) is 40% below the documented usable input limit (100,000)" in text
    assert "above the acceptable 30 s" in text


def test_a_quota_stopped_probe_is_shown_as_documented_with_the_quota_evidence(monkeypatch):
    record = {"provider": "GuardianFoundry", "instance_name": "lab", "model": "m", "source": "quota",
              "max_input_tokens": 70000, "window": 8000, "documented_input_tokens": 100000,
              "evidence": "quota (tokens-per-minute) reached at 16000 tokens; the window was not reached",
              "probed_at": "2026-10-08T03:00:00Z"}
    _data, text = _effective_text(monkeypatch, _plist(record))
    assert "(documented, a probe hit a quota limit)" in text
    assert "quota (tokens-per-minute) reached at 16000 tokens" in text


def test_an_older_measured_record_gets_its_documented_gap_from_the_catalogue(monkeypatch):
    record = {"provider": "GuardianFoundry", "instance_name": "lab", "model": "gpt-5-mini-2025-08-07",
              "max_input_tokens": 24000, "window": 100000, "output_reserve": 4096, "probed_at": "2026-10-08T03:00:00Z"}
    _data, text = _effective_text(monkeypatch, _plist(record), catalog=CATALOG)
    assert "24000 (measured)" in text and "is 63% below the documented usable input limit (272,000)" in text


def test_an_older_measured_record_for_an_unlisted_model_is_shown_as_before(monkeypatch):
    record = {"provider": "GuardianFoundry", "instance_name": "lab", "model": "unlisted", "max_input_tokens": 24000,
              "window": 32768, "probed_at": "2026-10-08T03:00:00Z"}
    _data, text = _effective_text(monkeypatch, _plist(record), catalog=CATALOG)
    assert "Measured profile: unlisted on lab, probed 2026-10-08T03:00:00Z." in text and "below the documented" not in text


def test_an_operator_override_is_still_called_an_override(monkeypatch):
    record = {"provider": "GuardianFoundry", "instance_name": "lab", "model": "m", "source": "documented",
              "max_input_tokens": 173400, "catalog_checked": "2026-10-09"}
    _data, text = _effective_text(monkeypatch, _plist(record, overrides={"max_input_tokens": 9000}))
    assert "9000 (override)" in text


# --- no profile saved yet: preview what the run's first task (GuardianModelProfileCheck) would save -------------------

OPEN_WEIGHT_CATALOG = {"checked": "2026-10-09", "models": [
    {"id": "llama-3.3-70b", "aliases": [], "vendor": "Meta", "open_weight": True, "context_window": 131072,
     "max_input_tokens": None, "max_output_tokens": 8192, "probe": "search", "provider_limits": []}]}


def _foundry_dropdown_instance(model_choice="gpt-5-mini"):
    # the exact tenant case: the Model dropdown is set, the free-text deployment and the `provider` param are not
    return {"name": "guardian_foundry_1", "brand": "GuardianFoundry", "enabled": "true",
            "data": [{"name": "model_choice", "value": model_choice}]}


def _recording_install(monkeypatch, instance, plist=None, catalog=None, settings=None):
    """`_install` plus a record of every command dispatched (nothing but getList and the REST read is expected)."""
    _install(monkeypatch, rest_post_handler=_rest_ok({"instances": [instance]}), profile=plist, catalog=catalog)
    inner = model_cmd.demisto.executeCommand
    calls = []

    def fake_execute(command, args):
        calls.append((command, args.get("listName")))
        if settings is not None and command == "getList" and args.get("listName") == "guardian_settings":
            return [{"Type": 1, "Contents": json.dumps(settings)}]
        return inner(command, args)

    monkeypatch.setattr(model_cmd.demisto, "executeCommand", fake_execute)
    return calls


def _preview_text(monkeypatch, instance, **kwargs):
    calls = _recording_install(monkeypatch, instance, **kwargs)
    data = model_cmd.guardian_model_cmd_run()["data"]
    return data, model_cmd.guardian_model_cmd_render(data), calls


def test_no_profile_yet_previews_the_documented_budget_the_first_task_would_save(monkeypatch):
    data, text, calls = _preview_text(monkeypatch, _foundry_dropdown_instance(), catalog=CATALOG)
    assert data["effective"]["max_input_tokens"] == 173400  # int(272000 x 0.85 x 3.0 / 4)
    assert data["effective"]["max_input_tokens_source"] == "documented, catalogue 2026-10-09; saved by the run's first task"
    assert "- Input budget (max_input_tokens): 173400 (documented, catalogue 2026-10-09; saved by the run's first task)." in text
    assert ("- No profile saved yet. `gpt-5-mini` is in the model catalogue (checked 2026-10-09, azure-foundry cap: "
            "context window 400,000, usable input 272,000 tokens). An investigation's first task (Resolve model "
            "profile) saves a documented profile with this budget; run `!GuardianModelProfileCheck` to save it now. "
            "No probe is needed.") in text
    assert "No measured profile yet" not in text and "GuardianModelAdaptation" not in text
    assert data["effective"]["profile"] is None
    # read-only: the settings, the profile list and the catalogue are read, and nothing is written
    assert sorted(c for c in calls if c[0] != "demisto-api-post") == [
        ("getList", "guardian_model_catalog"), ("getList", "guardian_model_profile"), ("getList", "guardian_settings")]


def test_the_previewed_tool_list_budget_follows_the_previewed_input_budget(monkeypatch):
    settings = {"model_tier": "small", "max_input_tokens": 28258, "max_tool_def_tokens": 150000}
    data, text, _calls = _preview_text(monkeypatch, _foundry_dropdown_instance(), catalog=CATALOG, settings=settings)
    # the tool list is capped at a share of the input budget, here the previewed one rather than 28258
    assert data["effective"]["max_tool_def_tokens"] > int(28258 * model_cmd.GUARDIAN_TOOL_BUDGET_MAX_INPUT_FRACTION)
    assert data["effective"]["max_tool_def_tokens"] == int(173400 * model_cmd.GUARDIAN_TOOL_BUDGET_MAX_INPUT_FRACTION)


def test_no_profile_yet_an_open_weight_catalogue_model_keeps_the_settings_budget_and_asks_for_a_probe(monkeypatch):
    instance = {"name": "guardian_cohere_1", "brand": "GuardianCohere", "enabled": "true",
                "data": [{"name": "model", "value": "llama-3.3-70b"}]}
    data, text, _calls = _preview_text(monkeypatch, instance, catalog=OPEN_WEIGHT_CATALOG)
    assert "- Input budget (max_input_tokens): 28258 (guardian_settings)." in text
    assert ("- No profile saved yet. `llama-3.3-70b` is in the model catalogue (checked 2026-10-09) with a documented "
            "usable input of 126,976 tokens (vendor), but the window it is served with depends on the runtime: run "
            "`!guardian-probe-model` then `!GuardianModelProfileUpdate` to confirm it.") in text
    assert data["effective"]["max_input_tokens"] == 28258


def test_no_profile_yet_an_unlisted_model_keeps_the_settings_budget_and_does_not_rely_on_jobs(monkeypatch):
    data, text, _calls = _preview_text(monkeypatch, _foundry_dropdown_instance("some-unlisted-model"), catalog=CATALOG)
    assert "28258 (guardian_settings)" in text
    assert ("- No profile saved yet: run `!guardian-probe-model` then `!GuardianModelProfileUpdate` (or let the daily "
            "GuardianModelAdaptation Job do it, where Jobs are set up).") in text
    assert "No measured profile yet" not in text


def test_no_profile_yet_with_a_missing_catalogue_does_not_crash(monkeypatch):
    data, text, _calls = _preview_text(monkeypatch, _foundry_dropdown_instance(), catalog=None)
    assert "28258 (guardian_settings)" in text
    assert "No profile saved yet: run `!guardian-probe-model`" in text
    assert "| guardian_foundry_1 |" in text  # the instance table still renders


def test_no_profile_yet_with_no_enabled_instance_keeps_the_settings_numbers(monkeypatch):
    instance = dict(_foundry_dropdown_instance(), enabled="false")
    data, text, calls = _preview_text(monkeypatch, instance, catalog=CATALOG)
    assert "28258 (guardian_settings)" in text and "No profile saved yet: run `!guardian-probe-model`" in text
    assert ("getList", "guardian_model_catalog") not in calls  # nothing to look up


def test_a_catalogue_error_in_the_preview_never_raises(monkeypatch):
    def boom():
        raise RuntimeError("boom")

    _recording_install(monkeypatch, _foundry_dropdown_instance(), catalog=CATALOG)
    monkeypatch.setattr(model_cmd, "guardian_catalog_load", boom)
    data = model_cmd.guardian_model_cmd_run()["data"]
    assert data["effective"]["max_input_tokens"] == 28258
    assert "No profile saved yet: run `!guardian-probe-model`" in model_cmd.guardian_model_cmd_render(data)


def test_an_operator_override_of_the_input_budget_leaves_the_report_unchanged(monkeypatch):
    plist = {"active": None, "overrides": {"max_input_tokens": 9000}, "profiles": {}}
    data, text, calls = _preview_text(monkeypatch, _foundry_dropdown_instance(), plist=plist, catalog=CATALOG)
    assert "9000 (override)" in text and "catalog_preview" not in data["effective"]
    assert "No measured profile yet" in text and "No profile saved yet" not in text
    # the catalogue is read once, for the model's size; no preview is built on top of an overridden budget
    assert calls.count(("getList", "guardian_model_catalog")) == 1


def test_an_active_record_leaves_the_report_unchanged(monkeypatch):
    record = {"provider": "GuardianFoundry", "instance_name": "guardian_foundry_1", "model": "gpt-5-mini",
              "source": "documented", "catalog_checked": "2026-10-09", "max_input_tokens": 173400,
              "documented_input_tokens": 272000, "limits": {"basis": "azure-foundry cap"}}
    plist = {"active": "GuardianFoundry:guardian_foundry_1", "overrides": {},
             "profiles": {"GuardianFoundry:guardian_foundry_1": record}}
    data, text, _calls = _preview_text(monkeypatch, _foundry_dropdown_instance(), plist=plist, catalog=CATALOG)
    assert "173400 (documented, catalogue 2026-10-09)." in text and "saved by the run's first task" not in text
    assert "Documented profile: gpt-5-mini on guardian_foundry_1" in text and "No profile saved yet" not in text
    assert "catalog_preview" not in data["effective"]


def _profile_check_module():
    import importlib.util
    import os

    path = os.path.join(os.path.dirname(__file__), "..", "GuardianModelProfileCheck", "GuardianModelProfileCheck.py")
    if not os.path.exists(path):  # e.g. a per-script docker run that mounts only this script
        return None
    spec = importlib.util.spec_from_file_location("guardian_model_profile_check_for_preview", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_preview_budget_equals_what_the_profile_check_plan_would_save(monkeypatch):
    check = _profile_check_module()
    if check is None:
        return
    for settings in ({}, {"output_reserve_tokens": 8192}, {"max_input_tokens_cap": 50000}):
        for configured, brand, catalog in (("gpt-5-mini", "GuardianFoundry", CATALOG),
                                           ("gpt-5-mini-2025-08-07", "GuardianFoundry", CATALOG),
                                           ("llama-3.3-70b", "GuardianCohere", OPEN_WEIGHT_CATALOG)):
            _install(monkeypatch, catalog=catalog)
            preview = model_cmd.guardian_model_cmd_catalog_preview(
                settings, {"brand": brand, "instance_name": "lab", "model": configured})
            plan = check.guardian_tiercheck_documented_plan(
                catalog, {"brand": brand, "instance_name": "lab", "configured_model": configured}, {}, settings)
            assert preview["usable_input_tokens"] == plan["usable_input_tokens"]
            if plan["action"] == "write":
                assert preview["state"] == "documented"
                assert preview["budget"] == plan["record"]["max_input_tokens"]
            else:
                assert preview["state"] == "unconfirmed" and plan["action"] == "none"


# --- the model's size follows the catalogue ------------------------------------------------------------------------

import pathlib as _pathlib

SHIPPED_CATALOG = json.loads(json.loads(
    (_pathlib.Path(__file__).resolve().parents[2] / "Lists" / "list-guardian_model_catalog.json").read_text())["data"])


def test_a_catalogued_model_is_sized_from_the_catalogue_and_an_old_setting_is_reported_once(monkeypatch):
    settings = {"model_tier": "small", "max_input_tokens": 28258}
    data, text, _calls = _preview_text(monkeypatch, _foundry_dropdown_instance(), catalog=SHIPPED_CATALOG, settings=settings)
    assert (data["effective"]["tier"], data["effective"]["tier_source"]) == ("large", "catalogue (gpt-5-mini)")
    assert "- Model size: large (catalogue (gpt-5-mini))." in text
    assert text.count("guardian_settings.model_tier (small) is not used: gpt-5-mini is a large model in the model catalogue") == 1
    # the preview of the budget the first task would save carries the model's size, and every limit follows the new budget
    assert data["effective"]["catalog_preview"]["size_class"] == "large"
    assert "It is a large model in the catalogue, which sets the model size a run uses." in text
    assert "- Tool result limit: 138,720 bytes per result (20% of the input budget)." in text
    assert "- History: compacted by tokens at 173,400." in text


def test_auto_with_an_uncatalogued_model_is_small_and_says_how_to_change_it(monkeypatch):
    settings = {"model_tier": "auto", "max_input_tokens": 28258}
    data, text, _calls = _preview_text(monkeypatch, _foundry_dropdown_instance("some-unlisted-model"),
                                       catalog=SHIPPED_CATALOG, settings=settings)
    assert "- Model size: small (default (model not in the catalogue; set model_tier in guardian_settings))." in text
    assert "is not used" not in text
    settings["model_tier"] = "large"
    data, text, _calls = _preview_text(monkeypatch, _foundry_dropdown_instance("some-unlisted-model"),
                                       catalog=SHIPPED_CATALOG, settings=settings)
    assert "- Model size: large (guardian_settings)." in text


def test_a_record_with_a_catalogue_id_is_sized_without_a_new_field_and_the_footer_names_the_rule(monkeypatch):
    record = {"provider": "GuardianFoundry", "instance_name": "lab", "model": "gpt-5-mini", "catalog_id": "gpt-5-mini",
              "source": "documented", "catalog_checked": "2026-10-09", "max_input_tokens": 173400,
              "documented_input_tokens": 272000, "limits": {"basis": "azure-foundry cap"}}
    plist = _plist(record)
    before = json.dumps(plist, sort_keys=True)
    data, text, _calls = _preview_text(monkeypatch, _foundry_dropdown_instance(), plist=plist, catalog=SHIPPED_CATALOG,
                                       settings={"model_tier": "auto", "max_input_tokens": 28258})
    assert data["effective"]["tier"] == "large" and json.dumps(plist, sort_keys=True) == before
    assert "the model's size in the model catalogue, or `guardian_settings.model_tier` for a model that is not in the catalogue" in text


def test_the_effective_numbers_show_the_turn_limit_for_the_models_size(monkeypatch):
    data, text, _calls = _preview_text(monkeypatch, _foundry_dropdown_instance(), catalog=SHIPPED_CATALOG,
                                       settings={"model_tier": "auto", "max_input_tokens": 28258})
    assert data["effective"]["max_ticks"] == 60 and "- Turn limit (MAX_TICKS): 60 (tier)." in text
    data, text, _calls = _preview_text(monkeypatch, _foundry_dropdown_instance("some-unlisted-model"), catalog=SHIPPED_CATALOG,
                                       settings={"model_tier": "auto", "max_input_tokens": 28258})
    assert "- Turn limit (MAX_TICKS): 25 (tier)." in text
    data, text, _calls = _preview_text(monkeypatch, _foundry_dropdown_instance(), catalog=SHIPPED_CATALOG,
                                       settings={"model_tier": "auto", "max_input_tokens": 28258, "MAX_TICKS": 33})
    assert "- Turn limit (MAX_TICKS): 33 (guardian_settings)." in text
