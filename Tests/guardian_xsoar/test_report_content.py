"""Content checks for the XSOAR 6 edition's report step: the GuardianReportBuild automation, its prompt List and settings,
its place in the two playbooks, and that the script that builds the report and the layout script that draws it agree on
every enum, cap and length. Run with the script folders' own tests; it needs `demistomock` and `CommonServerPython` on the
path, like them.
"""
import importlib.util
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "Packs" / "Guardian"
LISTS = PACK / "Lists"
SCRIPTS = PACK / "Scripts"
PLAYBOOKS = PACK / "Playbooks"
PARENT = "GuardianTriageAndInvestigateIncident"
LOOP = "GuardianAgentLoop"


def _load(name):
    path = SCRIPTS / name / (name + ".py")
    spec = importlib.util.spec_from_file_location("content_test_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _list(name):
    return json.loads((LISTS / "list-{}.json".format(name)).read_text())


def _data(name):
    return json.loads(_list(name)["data"])


def _playbook(name):
    return yaml.safe_load((PLAYBOOKS / "playbook-{}.yml".format(name)).read_text())


def _by_name(doc):
    return {t["task"]["name"]: (key, t) for key, t in doc["tasks"].items()}


# --- the playbooks ---------------------------------------------------------------------------------------------------

def test_the_agent_loop_builds_the_report_after_the_model_session_and_before_done():
    doc = _playbook(LOOP)
    names = _by_name(doc)
    session, report, done = names["Run Guardian model session"], names["Build the Guardian report"], names["Done"]
    assert session[1]["nexttasks"]["#none#"] == [report[0]] and report[1]["nexttasks"]["#none#"] == [done[0]]
    task = report[1]
    assert report[0] == "12" and task["task"]["script"] == "GuardianReportBuild" and task["type"] == "regular"
    assert task["continueonerror"] is True and task["continueonerrortype"] == "continue" and task["separatecontext"] is False
    assert not task.get("scriptarguments") and task["task"]["description"]


def test_the_triage_parent_builds_the_report_after_the_investigation_conclusion_and_before_done():
    doc = _playbook(PARENT)
    names = _by_name(doc)
    conclusion, report, done = names["Write the investigation conclusion"], names["Build the Guardian report"], names["Done"]
    assert conclusion[1]["nexttasks"]["#none#"] == [report[0]] and report[1]["nexttasks"]["#none#"] == [done[0]]
    task = report[1]
    assert report[0] == "47" and task["task"]["script"] == "GuardianReportBuild" and task["type"] == "regular"
    assert task["continueonerror"] is True and task["continueonerrortype"] == "continue" and task["separatecontext"] is False
    assert not task.get("scriptarguments") and task["task"]["description"]


def test_the_report_task_sits_between_its_neighbours_and_has_its_own_id_and_task_id():
    for name, before, after in ((LOOP, "Run Guardian model session", "Done"),
                                (PARENT, "Write the investigation conclusion", "Done")):
        doc = _playbook(name)
        names = _by_name(doc)
        position = lambda key: json.loads(doc["tasks"][key]["view"])["position"]
        here = names["Build the Guardian report"][0]
        low, high = position(names[before][0]), position(names[after][0])
        assert min(low["y"], high["y"]) < position(here)["y"] < max(low["y"], high["y"]), name
        ids = [t["taskid"] for t in doc["tasks"].values()]
        assert len(ids) == len(set(ids)) and doc["tasks"][here]["task"]["id"] == doc["tasks"][here]["taskid"]
        assert doc["tasks"][here]["id"] == here


def test_no_other_playbook_builds_a_report():
    for path in PLAYBOOKS.glob("playbook-*.yml"):
        doc = yaml.safe_load(path.read_text())
        count = sum(1 for t in doc["tasks"].values() if t["task"].get("script") == "GuardianReportBuild")
        assert count == (1 if doc["name"] in (LOOP, PARENT) else 0), doc["name"]


# --- the script, its Lists and the settings --------------------------------------------------------------------------

def test_the_script_is_operator_owned_denylisted_and_never_a_tool():
    denylist, allowlist = _data("guardian_tool_denylist"), _data("guardian_tool_allowlist")
    assert "GuardianReportBuild" in denylist["denied"] and "GuardianReportBuild" not in allowlist["commands"]
    assert "guardian_prompt_report" in denylist["protected_lists"]
    for name in ("guardian_policy", "guardian_preapproved"):
        assert "GuardianReportBuild" not in _list(name)["data"]


def test_the_script_is_well_formed():
    folder = SCRIPTS / "GuardianReportBuild"
    doc = yaml.safe_load((folder / "GuardianReportBuild.yml").read_text())
    assert doc["commonfields"]["id"] == doc["name"] == "GuardianReportBuild" and doc["args"] == []
    assert doc["marketplaces"] == ["xsoar"] and doc["subtype"] == "python3" and doc["system"] is False and doc["tags"] == []
    assert doc["dockerimage"].startswith("demisto/python3:") and doc["fromversion"] == "6.10.0"
    assert {o["contextPath"] for o in doc["outputs"]} == {"Guardian.Report." + k for k in (
        "v", "run_id", "tick", "fingerprint", "generated_at", "model", "calls", "tokens", "cost_usd", "seconds", "report", "refs", "errors")}
    assert (folder / "README.md").exists() and (folder / "GuardianReportBuild_test.py").exists()
    source = (folder / "GuardianReportBuild.py").read_text()
    assert source.count("# <GUARDIAN_COMMON_INJECT>") == 1 and source.count("# </GUARDIAN_COMMON>") == 1


def test_the_prompt_list_and_the_settings_ship_in_the_pack_style():
    wrapper = _list("guardian_prompt_report")
    assert wrapper["id"] == wrapper["name"] == "guardian_prompt_report" and wrapper["type"] == "json"
    assert wrapper["version"] == -1 and wrapper["fromVersion"] == "6.10.0" and wrapper["description"]
    assert set(json.loads(wrapper["data"])) == {"rules", "core", "story", "close", "repair"}
    settings = _data("guardian_settings")
    assert settings["report_enabled"] is True and settings["report_max_calls"] == 3
    assert "_comment_report_enabled" in settings and "_comment_report_max_calls" in settings


# --- the script and the page agree -----------------------------------------------------------------------------------

def test_the_script_and_the_page_use_the_same_enums_caps_and_tactics():
    build, page = _load("GuardianReportBuild"), _load("GuardianLayoutAssessment")
    assert build.GUARDIAN_REPORT_CAPS == page.CAPS
    assert build.GUARDIAN_REPORT_ETYPES == page.ETYPES and build.GUARDIAN_REPORT_ROLES == page.ROLES
    assert build.GUARDIAN_REPORT_RELS == page.RELS and build.GUARDIAN_REPORT_SEVERITIES == page.SEVERITIES
    assert set(build.GUARDIAN_REPORT_REPS) == set(page.REP_COLOR) and set(build.GUARDIAN_REPORT_FLAGS) == set(page.FLAG_COLOR)
    assert set(build.GUARDIAN_REPORT_VERDICTS) == set(page.VERDICT_COLOR)
    assert build.GUARDIAN_REPORT_TACTICS == page.TACTIC_FULL and build.GUARDIAN_REPORT_TACTIC_ALIAS == page._TACTIC_ALIAS
    assert build.GUARDIAN_REPORT_ID_PATTERN.pattern == page._ID.pattern
    assert build.GUARDIAN_REPORT_ETYPES == tuple(page.ETAG) and set(page.TYPE_COL) == set(build.GUARDIAN_REPORT_ETYPES)
    assert set(page.REL_LABEL) == set(page.REL_PASSIVE) == set(build.GUARDIAN_REPORT_RELS)
    assert build.GUARDIAN_REPORT_MAX_EVIDENCE <= page.MAX_REFS


def test_what_the_script_validated_the_page_does_not_change():
    """The page applies the same caps and lengths again; on the script's output that must be a no-op."""
    build, page = _load("GuardianReportBuild"), _load("GuardianLayoutAssessment")
    evidence = [{"id": "t{}".format(i), "tool": "tool", "args": "{}", "body": "b", "grounding": ""} for i in range(1, 5)]
    inp = {"evidence": evidence, "grounding": "ws-0142 alpha beta", "conclusion_lower": "", "tool_names": {"domain"}}
    long = "word " * 120
    core, _dropped = build.guardian_report_normalize_core({
        "headline": long,
        "entities": [{"id": "e%d" % i, "type": "host", "value": "WS-0142 alpha beta", "rep": "malicious", "role": "victim",
                      "ref": ["t1", "t2", "t3", "t4", "t9"]} for i in range(40)],
        "edges": [{"from": "e%d" % i, "to": "e%d" % (i + 1), "rel": "ran", "time": long, "ref": ["t1"]} for i in range(39)]}, inp)
    ids = core["entities"]
    story = build.guardian_report_normalize_story({
        "attack": [{"tactic": "Execution", "tech": "T1059.001", "name": long, "time": long, "evidence": long,
                    "ents": ["e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7"], "ref": ["t1"]}] * 30,
        "timeline": [{"t": "2026-10-27T21:31:00Z", "event": long, "src": long, "ents": ["e0"], "tech": "T1059", "ref": ["t2"]}] * 40,
        "tree": [{"id": "n%d" % i, "parent": "n%d" % (i - 1) if i else None, "ent": "e0", "name": long, "cmd": long,
                  "pid": "1234567890123", "flag": "malicious", "tech": "T1059.001", "ref": ["t1"]} for i in range(50)]}, inp, ids)
    close = build.guardian_report_normalize_close({
        "findings": [{"text": long, "ref": ["t1"]}] * 20,
        "actions": [{"p": 2, "action": long, "owner": "guardian", "approval": False, "cmd": "domain " + long}] * 12,
        "gaps": [long] * 9}, inp)
    report = dict(core, **story)
    report.update(close)
    ctx = page._Ctx(dict(report, refs={e["id"]: {"tool": "tool", "summary": "{}"} for e in evidence}), {})
    for section in ("entities", "edges", "attack", "timeline", "tree", "findings", "actions"):
        ours, theirs = report[section], ctx.get(section)
        assert len(ours) == len(theirs), section
        for mine, drawn in zip(ours, theirs):
            for key, value in mine.items():
                assert drawn[key] == value, (section, key)
    assert ctx.get("gaps") == report["gaps"] and len(report["headline"]) == 140


# --- the layout: the assessment page is three sections --------------------------------------------------------------------

def _guardian_tab():
    layout = json.loads((PACK / "Layouts" / "layoutscontainer-GuardianAgentRunLayout.json").read_text())
    return [t for t in layout["detailsV2"]["tabs"] if t["id"] == "guardian"][0]["sections"]


def test_the_assessment_is_three_dynamic_sections_one_under_the_other_at_the_top_of_the_guardian_tab():
    sections = _guardian_tab()
    assert [(s["i"], s["name"], s["query"]) for s in sections[:3]] == [
        ("guardian-assessment-section", "Guardian Assessment", "GuardianLayoutAssessment"),
        ("guardian-story-section", "Guardian Attack Story", "GuardianLayoutAssessmentStory"),
        ("guardian-findings-section", "Guardian Findings", "GuardianLayoutAssessmentFindings")]
    for section in sections[:3]:
        assert section["type"] == "dynamic" and section["queryType"] == "script" and section["isVisible"] is True
        assert section["readOnly"] is True and section["x"] == 0 and section["w"] == 3 and section["description"]
        assert section["h"] >= 10


def test_no_two_sections_of_the_guardian_tab_overlap_and_the_rest_is_unchanged_in_order():
    sections = _guardian_tab()
    edge = 0
    for section in sections:
        assert section["y"] >= edge, section["i"]
        edge = section["y"] + section["h"]
    assert [s["i"] for s in sections[3:]] == [
        "guardian-fields-section", "guardian-recommended-actions-section", "guardian-approval-actions-section",
        "guardian-agent-actions-section", "guardian-trace-section", "guardian-tool-ledger-section"]
    by_id = {s["i"]: s for s in sections}
    assert (by_id["guardian-recommended-actions-section"]["h"], by_id["guardian-fields-section"]["h"]) == (6, 3)
    ids = [s["i"] for s in sections]
    assert len(ids) == len(set(ids))


def test_the_two_wrapper_scripts_are_listed_in_the_health_check_and_xsoar_only():
    import re

    source = (SCRIPTS / "GuardianHealthCheck" / "GuardianHealthCheck.py").read_text()
    for name in ("GuardianLayoutAssessmentStory", "GuardianLayoutAssessmentFindings"):
        assert '"{}"'.format(name) in source
        assert yaml.safe_load((SCRIPTS / name / (name + ".yml")).read_text())["tags"] == ["dynamic-section"]
        assert not (ROOT / "Packs" / "GuardianXSIAM" / "Scripts" / name).exists()
    contract = (ROOT / "scripts" / "test_layout_contract.py").read_text()
    assert re.search(r"XSOAR_ONLY = \{[^}]*GuardianLayoutAssessmentStory[^}]*GuardianLayoutAssessmentFindings", contract)
