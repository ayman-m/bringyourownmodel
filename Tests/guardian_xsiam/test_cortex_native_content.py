"""Content checks for the Cortex platform edition's model-facing text.

The skills, prompt head and tail, persona and the investigation playbooks are what the model reads. This edition
runs on the Cortex platform, whose commands and data model differ from XSOAR's, so these tests fail when XSOAR-only
commands creep back into that text, when a skill names a Cortex command that does not exist, or when the routing
table names a skill that is not shipped.
"""
import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "Packs" / "GuardianXSIAM"
LISTS = PACK / "Lists"
SNAPSHOT = json.loads((Path(__file__).parent / "cortex_command_names.json").read_text())["commands"]
GUARDIAN_SCRIPTS = {p.name for p in (PACK / "Scripts").iterdir() if p.is_dir()}

#: XSOAR-edition commands and concepts that must not appear in text the model reads on this platform. The allowlist
#: keeps some of them at its tail for tenants that have them; it is data, not model-facing text, and is not scanned.
BANNED = ("getIncidents", "SearchIncidentsV2", "setIncident", "findIndicators", "getEntries", "closeInvestigation",
          "splunk-", "on-prem", "War Room", "linked incident", "cortex_case_triage", "cortex_platform_reference")


def _list_data(name):
    return json.loads((LISTS / "list-{}.json".format(name)).read_text())["data"]


def _model_facing_texts():
    texts = {}
    for name in ("guardian_prompt_head", "guardian_prompt_tail", "guardian_persona", "guardian_skills_index"):
        texts[name] = _list_data(name)
    for path in sorted(LISTS.glob("list-guardian_skill_*.json")):
        texts[path.stem] = json.loads(path.read_text())["data"]
    for path in sorted((PACK / "Playbooks").glob("playbook-*.yml")):
        doc = yaml.safe_load(path.read_text())
        for item in doc.get("inputs") or []:
            value = item.get("value")
            value = value.get("simple") if isinstance(value, dict) else value
            if isinstance(value, str):
                texts["{}:{}".format(path.stem, item["key"])] = value
    return texts


@pytest.mark.parametrize("name", sorted(_model_facing_texts()))
def test_no_xsoar_only_text_in_what_the_model_reads(name):
    text = _model_facing_texts()[name]
    found = [word for word in BANNED if word in text]
    assert found == [], "{} mentions XSOAR-only text: {}".format(name, found)


def _named_commands(text):
    text = text.replace("*", "\u0000")  # a wildcard such as core-get-* names a family, not a command
    cortex = {m for m in re.findall(r"\b(?:core|xdr|asm)-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*\b(?!-?\u0000)", text)}
    guardian = {m for m in re.findall(r"\bGuardian[A-Z][A-Za-z]+\b", text)}
    return cortex, guardian



@pytest.mark.parametrize("name", sorted(_model_facing_texts()))
def test_every_command_a_text_names_exists(name):
    cortex, guardian = _named_commands(_model_facing_texts()[name])
    missing_cortex = sorted(c for c in cortex if c not in SNAPSHOT)
    missing_guardian = sorted(g for g in guardian if g not in GUARDIAN_SCRIPTS)
    assert missing_cortex == [], "{} names Cortex commands that do not exist: {}".format(name, missing_cortex)
    assert missing_guardian == [], "{} names Guardian automations that do not exist: {}".format(name, missing_guardian)


def test_every_cortex_command_on_the_allowlist_exists():
    commands = json.loads(_list_data("guardian_tool_allowlist"))["commands"]
    legacy_xdr = {"xdr-get-endpoints", "xdr-get-incidents", "xdr-get-alerts"}  # the Cortex XDR integration, not on every tenant
    missing = [c for c in commands if re.match(r"(core|xdr|asm)-", c) and c not in SNAPSHOT and c not in legacy_xdr]
    assert missing == []
    missing = [c for c in commands if c.startswith("Guardian") and c not in GUARDIAN_SCRIPTS]
    assert missing == []


def test_every_skill_the_routing_table_names_is_shipped_and_enabled():
    table = json.loads(_list_data("guardian_issue_routes"))
    index = {e["name"]: e for e in json.loads(_list_data("guardian_skills_index"))}
    skills = {r["skill"] for r in table["routes"] if r.get("skill")} | {table["default"]["skill"]}
    for skill in skills:
        assert skill in index and index[skill].get("enabled") is True, skill
        assert (LISTS / "list-guardian_skill_{}.json".format(skill)).exists(), skill


def test_every_indexed_skill_has_a_body_and_every_body_is_indexed():
    index = {e["name"] for e in json.loads(_list_data("guardian_skills_index"))}
    bodies = {p.stem.replace("list-guardian_skill_", "") for p in LISTS.glob("list-guardian_skill_*.json")}
    assert index == bodies


def test_family_skills_are_small_enough_to_preload_on_a_small_model():
    for path in LISTS.glob("list-guardian_skill_cortex_*.json"):
        body = json.loads(path.read_text())["data"]
        assert len(body) <= 12000, (path.name, len(body))  # about 3000 tokens


def test_every_family_skill_ends_with_a_conclusion_block():
    for name in ("cortex_detection_investigation", "cortex_posture_misconfiguration", "cortex_identity_risk",
                 "cortex_vulnerability_triage", "cortex_attack_path"):
        body = json.loads((LISTS / "list-guardian_skill_{}.json".format(name)).read_text())["data"]
        assert "## Conclude" in body and "GuardianCaseNote" in body and "```json" in body, name


def test_the_knowledge_base_has_the_cloud_and_posture_entries():
    kb = json.loads(_list_data("guardian_kb_soc_investigation"))
    cloud = [e for e in kb if e["category"] == "cloud-posture"]
    assert len(cloud) >= 12
    for entry in cloud:
        assert set(entry) == {"id", "technique", "category", "title", "tags", "body"}
        assert len(entry["body"].split()) <= 600, entry["id"]


def test_playbooks_reference_only_scripts_that_exist():
    for path in (PACK / "Playbooks").glob("playbook-*.yml"):
        doc = yaml.safe_load(path.read_text())
        for task in doc["tasks"].values():
            script = (task.get("task") or {}).get("script")
            if script and script != "-" and script.startswith("Guardian"):
                assert script in GUARDIAN_SCRIPTS, (path.name, script)


def test_the_investigation_playbook_graph_is_connected():
    doc = yaml.safe_load((PACK / "Playbooks" / "playbook-GuardianInvestigateIssue.yml").read_text())
    tasks = doc["tasks"]
    reachable, todo = set(), [doc["starttaskid"]]
    while todo:
        current = todo.pop()
        if current in reachable:
            continue
        reachable.add(current)
        for targets in (tasks[current].get("nexttasks") or {}).values():
            todo.extend(targets)
    assert reachable == set(tasks), sorted(set(tasks) - reachable)
    for task in tasks.values():
        for targets in (task.get("nexttasks") or {}).values():
            assert all(t in tasks for t in targets)
