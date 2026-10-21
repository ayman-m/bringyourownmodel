import json
import pathlib

import pytest
import yaml

import GuardianModelChoice as mc

ROUTING_FILE = pathlib.Path(__file__).resolve().parents[2] / "Lists" / "list-guardian_model_routing.json"
CATALOG = {"checked": "2026-10-09", "models": [
    {"id": "gpt-5-mini", "aliases": [], "vendor": "OpenAI", "open_weight": False, "context_window": 400000,
     "max_input_tokens": 272000, "max_output_tokens": 128000, "supports_tools": True, "supports_structured_output": True,
     "probe": "skip", "provider_limits": []},
    {"id": "gpt-5", "aliases": [], "vendor": "OpenAI", "open_weight": False, "context_window": 400000,
     "max_input_tokens": 272000, "max_output_tokens": 128000, "supports_tools": True, "supports_structured_output": True,
     "probe": "skip", "provider_limits": []},
]}


def _routing(**over):
    data = {"triage": "", "complexity": {"low": {"model": ""}, "medium": {"model": ""}, "high": {"model": ""}}}
    data.update(over)
    return data


def _parse(data):
    return mc.guardian_choice_parse_routing(json.dumps(data) if not isinstance(data, str) else data)


def _search(brand="GuardianFoundry", model="gpt-4o"):
    return {"instances": [{"name": "lab", "brand": brand, "enabled": "true", "data": [{"name": "model", "value": model}]}],
            "configurations": [{"name": brand, "integrationScript": {"commands": [{"name": "guardian-llm-chat"}]}}]}


@pytest.fixture
def world(monkeypatch):
    """Wires the routing List, the provider search and the catalogue; records the commands run."""
    state = {"routing": json.dumps(_routing()), "search": _search(), "catalog": CATALOG, "calls": [], "ctx": {}, "rest": 0}

    def execute(command, args):
        state["calls"].append((command, dict(args)))
        if command == "getList" and args["listName"] == "guardian_model_routing":
            if state["routing"] is None:
                return [{"Type": 4, "Contents": "Item not found (8)"}]
            return [{"Type": 1, "Contents": state["routing"]}]
        if command == "getList" and args["listName"] == "guardian_model_catalog":
            if state["catalog"] is None:
                return [{"Type": 4, "Contents": "Item not found (8)"}]
            return [{"Type": 1, "Contents": json.dumps(state["catalog"])}]
        if command == "demisto-api-post":
            state["rest"] += 1
            if state["search"] is None:
                return [{"Type": 4, "Contents": "down"}]
            return [{"Type": 1, "Contents": {"response": state["search"]}}]
        return [{"Type": 1, "Contents": "ok"}]

    monkeypatch.setattr(mc.demisto, "executeCommand", execute)
    monkeypatch.setattr(mc.demisto, "context", lambda: {"Guardian": state["ctx"]})
    monkeypatch.setattr(mc.demisto, "incident", lambda: {"id": "1001"})
    monkeypatch.setattr(mc.demisto, "setContext", lambda path, value: state.setdefault("written", {}).update({path: value}))
    return state


def _triage(**over):
    triage = {"status": "structured", "complexity": "low", "escalate": False, "severity": "medium", "confidence": 80}
    triage.update(over)
    return triage


# --- parsing ------------------------------------------------------------------------------------------------------

def test_the_shipped_list_is_empty_so_every_choice_is_the_default():
    wrapper = json.loads(ROUTING_FILE.read_text())
    assert wrapper["id"] == wrapper["name"] == "guardian_model_routing" and wrapper["type"] == "json" and wrapper["version"] == -1
    data = json.loads(wrapper["data"])
    assert data["triage"] == "" and set(data["complexity"]) == {"low", "medium", "high"}
    assert all(entry == {"model": ""} for entry in data["complexity"].values())
    routing = mc.guardian_choice_parse_routing(wrapper["data"])
    assert routing["warnings"] == [] and routing["triage"] == ""
    assert all(level == {"model": "", "max_ticks": None} for level in routing["levels"].values())


def test_a_full_list_is_parsed():
    routing = _parse(_routing(triage=" gpt-5-mini ", complexity={"low": {"model": "gpt-5-mini", "max_ticks": 15},
                                                                    "medium": {"model": "gpt-5"}, "high": {"model": "gpt-5", "max_ticks": "40"}}))
    assert routing["triage"] == "gpt-5-mini" and routing["warnings"] == []
    assert routing["levels"]["low"] == {"model": "gpt-5-mini", "max_ticks": 15}
    assert routing["levels"]["medium"] == {"model": "gpt-5", "max_ticks": None}
    assert routing["levels"]["high"]["max_ticks"] == 40


@pytest.mark.parametrize("contents", ["{not json", "[1, 2]", "5", '"text"'])
def test_a_list_that_is_not_an_object_is_ignored_with_a_warning(contents):
    routing = _parse(contents)
    assert routing["triage"] == "" and all(v["model"] == "" for v in routing["levels"].values()) and routing["warnings"]


@pytest.mark.parametrize("data, warning", [
    ({"triage": 5}, "`triage` must be a model name"),
    ({"complexity": [1]}, "`complexity` must be an object"),
    ({"complexity": {"low": "gpt-5"}}, "complexity.low must be an object"),
    ({"complexity": {"low": {"model": 7}}}, "complexity.low.model must be a model name"),
    ({"complexity": {"low": {"model": "m", "max_ticks": 0}}}, "complexity.low.max_ticks must be a whole number"),
    ({"complexity": {"low": {"model": "m", "max_ticks": "many"}}}, "complexity.low.max_ticks must be a whole number"),
    ({"complexity": {"low": {"model": "m", "max_ticks": True}}}, "complexity.low.max_ticks must be a whole number"),
])
def test_a_bad_value_is_ignored_with_a_warning_and_the_rest_still_counts(data, warning):
    routing = _parse(dict(_routing(), **data) if "complexity" not in data else data)
    assert any(warning in w for w in routing["warnings"]), routing["warnings"]
    assert routing["levels"]["low"]["max_ticks"] is None


def test_a_bad_level_does_not_hide_a_good_one():
    routing = _parse({"triage": "t", "complexity": {"low": 5, "high": {"model": "gpt-5"}, "extra": {"model": "x"}}})
    assert routing["triage"] == "t" and routing["levels"]["high"]["model"] == "gpt-5" and len(routing["warnings"]) == 1


def test_empty_or_missing_content_is_the_default_without_a_warning():
    for contents in (None, "", "  ", {}):
        routing = mc.guardian_choice_parse_routing(contents)
        assert routing["warnings"] == [] and routing["triage"] == ""


def test_an_unreadable_list_is_the_default_with_a_warning(world):
    world["routing"] = None
    routing = mc.guardian_choice_load_routing()
    assert routing["triage"] == "" and routing["warnings"] and "could not be read" in routing["warnings"][0]


# --- the level ----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("triage, apply_result, level", [
    (_triage(complexity="low"), None, "low"),
    (_triage(complexity="medium"), None, "medium"),
    (_triage(complexity="high"), None, "high"),
    (_triage(complexity=""), None, "medium"),           # no rating: medium
    (_triage(complexity="huge"), None, "medium"),
    (None, None, "medium"),                               # no triage result at all
    ({}, {}, "medium"),
    (_triage(complexity="low", escalate=True), None, "medium"),             # floor: escalate
    (_triage(complexity="low", severity="high"), None, "medium"),           # floor: severity
    (_triage(complexity="low", severity="critical"), None, "medium"),
    (_triage(complexity="low", severity="low"), {"severity_after": "high"}, "medium"),   # the severity the apply step left
    (_triage(complexity="high", escalate=True, severity="critical"), None, "high"),     # a floor never lowers
    (_triage(complexity="low", confidence=59), None, "medium"),             # low confidence: one up
    (_triage(complexity="medium", confidence=59), None, "high"),
    (_triage(complexity="high", confidence=10), None, "high"),
    (_triage(complexity="low", confidence=60), None, "low"),                # 60 is not under 60
    (_triage(complexity="low", escalate=True, confidence=40), None, "high"),  # floor, then one up
    (_triage(complexity="low", severity="high", confidence=40), None, "high"),
    (_triage(status="fallback", complexity="", confidence=0, severity=""), None, "high"),  # nothing usable: medium, then up
])
def test_the_level_from_the_triage_result(triage, apply_result, level):
    assert mc.guardian_choice_level(triage, apply_result)[0] == level


def test_a_confidence_that_is_not_a_number_is_not_low():
    for confidence in ("55", None, True):
        assert mc.guardian_choice_level(_triage(complexity="low", confidence=confidence), None)[0] == "low"


def test_the_why_text_names_each_step():
    level, why = mc.guardian_choice_level(_triage(complexity="low", escalate=True, confidence=40), None)
    assert level == "high" and "complexity low" in why and "raised to medium (escalate)" in why and "confidence 40 is under 60" in why


# --- the choice ---------------------------------------------------------------------------------------------------

def test_an_empty_list_chooses_the_default_without_asking_the_provider(world):
    for stage in ("triage", "investigation"):
        choice = mc.guardian_choice_run(stage, mc.guardian_choice_parse_routing(world["routing"]), _triage(), None)
        assert choice["model"] == "" and choice["max_ticks"] == "" and choice["warnings"] == []
        assert "configured model is used" in choice["reason"]
    assert world["rest"] == 0 and not [c for c in world["calls"] if c[0] == "getList"]  # no provider search, no catalogue read


def test_the_triage_stage_uses_the_triage_model(world):
    routing = _parse(_routing(triage="gpt-5-mini"))
    choice = mc.guardian_choice_run("triage", routing, None, None)
    assert (choice["stage"], choice["model"], choice["level"], choice["max_ticks"]) == ("triage", "gpt-5-mini", "", "")
    assert choice["provider"] == "GuardianFoundry" and choice["warnings"] == []


def test_the_investigation_stage_uses_the_model_of_its_level(world):
    routing = _parse(_routing(complexity={"low": {"model": "gpt-5-mini", "max_ticks": 15}, "medium": {"model": "gpt-5"}, "high": {"model": "gpt-5"}}))
    low = mc.guardian_choice_run("investigation", routing, _triage(complexity="low"), None)
    assert (low["level"], low["model"], low["max_ticks"]) == ("low", "gpt-5-mini", 15) and "max_ticks 15 from the routing" in low["reason"]
    high = mc.guardian_choice_run("investigation", routing, _triage(complexity="high"), None)
    assert (high["level"], high["model"], high["max_ticks"]) == ("high", "gpt-5", "")
    floored = mc.guardian_choice_run("investigation", routing, _triage(complexity="low", escalate=True), None)
    assert (floored["level"], floored["model"]) == ("medium", "gpt-5")


def test_the_level_max_ticks_applies_even_when_its_model_is_empty(world):
    routing = _parse(_routing(complexity={"low": {"model": "", "max_ticks": 12}}))
    choice = mc.guardian_choice_run("investigation", routing, _triage(complexity="low"), None)
    assert choice["model"] == "" and choice["max_ticks"] == 12 and world["rest"] == 0


def test_the_playbook_input_wins_over_the_level_max_ticks(world):
    routing = _parse(_routing(complexity={"low": {"model": "gpt-5-mini", "max_ticks": 15}}))
    choice = mc.guardian_choice_run("investigation", routing, _triage(complexity="low"), None, investigate_max_ticks="30")
    assert choice["max_ticks"] == 30 and "investigate_max_ticks" in choice["reason"]
    for junk in ("", None, "abc", "0", "-3"):
        assert mc.guardian_choice_run("investigation", routing, _triage(complexity="low"), None, junk)["max_ticks"] == 15
    triage_stage = mc.guardian_choice_run("triage", routing, None, None, investigate_max_ticks="30")
    assert triage_stage["max_ticks"] == ""


def test_the_playbook_input_alone_is_returned_when_the_list_has_no_max_ticks(world):
    choice = mc.guardian_choice_run("investigation", _parse(_routing()), _triage(), None, investigate_max_ticks=25)
    assert choice["model"] == "" and choice["max_ticks"] == 25


def test_a_cohere_provider_cannot_choose_a_model_so_the_default_is_kept(world):
    world["search"] = _search(brand="GuardianCohere", model="command-a")
    routing = _parse(_routing(triage="gpt-5-mini"))
    choice = mc.guardian_choice_run("triage", routing, None, None)
    assert choice["model"] == "" and choice["provider"] == "GuardianCohere"
    assert "cannot choose a model per call" in choice["reason"] and "default model is used" in choice["reason"]


def test_a_model_missing_from_the_catalogue_is_kept_with_a_warning(world):
    choice = mc.guardian_choice_run("triage", _parse(_routing(triage="brand-new-model")), None, None)
    assert choice["model"] == "brand-new-model"
    assert any("brand-new-model" in w and "not in the model catalogue" in w and "guessed" in w for w in choice["warnings"])
    known = mc.guardian_choice_run("triage", _parse(_routing(triage="gpt-5-mini")), None, None)
    assert known["warnings"] == []


def test_an_unreadable_catalogue_or_provider_search_keeps_the_model_with_warnings(world):
    world["catalog"], world["search"] = None, None
    choice = mc.guardian_choice_run("triage", _parse(_routing(triage="gpt-5-mini")), None, None)
    assert choice["model"] == "gpt-5-mini" and len(choice["warnings"]) == 2
    assert any("provider could not be looked up" in w for w in choice["warnings"]) and any("catalogue could not be read" in w for w in choice["warnings"])


def test_list_warnings_are_carried_into_the_choice(world):
    routing = _parse({"triage": 5})
    assert mc.guardian_choice_run("triage", routing, None, None)["warnings"] == routing["warnings"] and routing["warnings"]


# --- main ---------------------------------------------------------------------------------------------------------

def _main(monkeypatch, world, args):
    results, errors = [], []
    monkeypatch.setattr(mc.demisto, "args", lambda: args)
    monkeypatch.setattr(mc, "return_results", results.append)
    monkeypatch.setattr(mc, "return_error", errors.append)
    mc.main()
    return results, errors


def test_main_returns_outputs_keyed_by_stage_and_writes_the_flat_current_object(monkeypatch, world):
    world["routing"] = json.dumps(_routing(triage="gpt-5-mini"))
    results, errors = _main(monkeypatch, world, {"stage": "triage"})
    assert not errors and len(results) == 1
    out = results[0]
    assert out.outputs_prefix == "Guardian.ModelChoice" and out.outputs_key_field == "stage"
    assert set(out.outputs) == {"stage", "level", "model", "max_ticks", "reason", "warnings", "provider"}
    assert world["written"]["Guardian.ModelChoiceCurrent"] == out.outputs
    assert "Model choice for the triage: `gpt-5-mini`" in out.readable_output
    audit = [a for c, a in world["calls"] if c == "GuardianAuditWrite"]
    assert len(audit) == 1 and audit[0]["action"] == "GuardianModelChoice" and audit[0]["target"] == "1001"


def test_main_reads_the_newest_triage_even_when_the_context_holds_a_list(monkeypatch, world):
    world["routing"] = json.dumps(_routing(complexity={"high": {"model": "gpt-5"}, "low": {"model": "gpt-5-mini"}}))
    world["ctx"] = {"Triage": [_triage(complexity="low"), _triage(complexity="high")], "TriageApply": [{"severity_after": "low"}]}
    results, _e = _main(monkeypatch, world, {"stage": "investigation", "investigate_max_ticks": "20"})
    assert results[0].outputs["model"] == "gpt-5" and results[0].outputs["max_ticks"] == 20 and results[0].outputs["level"] == "high"


def test_main_with_the_default_list_changes_nothing(monkeypatch, world):
    results, _e = _main(monkeypatch, world, {"stage": "investigation"})
    out = results[0].outputs
    assert out["model"] == "" and out["max_ticks"] == "" and world["written"]["Guardian.ModelChoiceCurrent"]["model"] == ""
    assert "the configured model" in results[0].readable_output


def test_main_refuses_a_bad_stage(monkeypatch, world):
    results, errors = _main(monkeypatch, world, {"stage": "later"})
    assert errors and "stage must be" in errors[0] and not results


def _record_writes(monkeypatch, world):
    writes = []

    def set_context(path, value):
        writes.append((path, value))
        world.setdefault("written", {})[path] = value

    monkeypatch.setattr(mc.demisto, "setContext", set_context)
    return writes


def test_main_clears_the_current_choice_before_anything_else(monkeypatch, world):
    writes = _record_writes(monkeypatch, world)
    world["routing"] = json.dumps(_routing(triage="gpt-5-mini"))
    _main(monkeypatch, world, {"stage": "triage"})
    current = [value for path, value in writes if path == "Guardian.ModelChoiceCurrent"]
    assert writes[0] == ("Guardian.ModelChoiceCurrent", {}) and current[-1]["model"] == "gpt-5-mini"


def test_a_bad_stage_leaves_the_current_choice_empty(monkeypatch, world):
    writes = _record_writes(monkeypatch, world)
    world["written"] = {"Guardian.ModelChoiceCurrent": {"stage": "triage", "model": "gpt-5-mini"}}  # an earlier stage's choice
    results, errors = _main(monkeypatch, world, {"stage": "later"})
    assert errors and not results
    assert writes == [("Guardian.ModelChoiceCurrent", {})] and world["written"]["Guardian.ModelChoiceCurrent"] == {}


def test_a_failure_while_choosing_leaves_the_current_choice_empty(monkeypatch, world):
    writes = _record_writes(monkeypatch, world)

    def broken():
        raise RuntimeError("boom")

    monkeypatch.setattr(mc, "guardian_choice_load_routing", broken)
    results, errors = _main(monkeypatch, world, {"stage": "investigation"})
    assert errors and "failed unexpectedly" in errors[0] and not results
    assert {path for path, _v in writes} == {"Guardian.ModelChoiceCurrent"} and all(value == {} for _p, value in writes)
    assert world["written"]["Guardian.ModelChoiceCurrent"] == {}


def test_a_context_write_that_fails_still_reports_the_error(monkeypatch, world):
    def set_context(path, value):
        raise RuntimeError("context unavailable")

    monkeypatch.setattr(mc.demisto, "setContext", set_context)
    results, errors = _main(monkeypatch, world, {"stage": "triage"})
    assert errors and not results


def test_the_yml_matches_the_outputs():
    doc = yaml.safe_load((pathlib.Path(__file__).parent / "GuardianModelChoice.yml").read_text())
    args = {a["name"]: a for a in doc["args"]}
    assert args["stage"]["required"] is True and set(args["stage"]["predefined"]) == {"triage", "investigation"}
    assert args["investigate_max_ticks"]["required"] is False
    paths = {o["contextPath"] for o in doc["outputs"]}
    for key in ("stage", "level", "model", "max_ticks", "reason", "warnings", "provider"):
        assert "Guardian.ModelChoice." + key in paths and "Guardian.ModelChoiceCurrent." + key in paths
