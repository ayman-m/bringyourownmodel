"""Contract tests for the two packs' layouts: every section and button points at a real script with the
right tag, the layouts of the two editions stay in step, and every layout button is operator-only."""

import functools
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
PACKS = ("Guardian", "GuardianXSIAM")

#: layout script bindings: (layout group, section/item kind) -> the tag the script must carry
DYNAMIC_TAG = {"dynamic": "dynamic-section", "dynamicIndicator": "dynamic-indicator-section"}
BUTTON_TAG = {"incident": "incident-action-button", "indicator": "indicator-action-button"}


@functools.lru_cache(maxsize=None)
def _scripts(pack):
    """script id -> {"tags": [...], "dir": name} for every automation of a pack."""
    found = {}
    for yml in (ROOT / "Packs" / pack / "Scripts").glob("*/*.yml"):
        body = yaml.safe_load(yml.read_text())
        found[body["commonfields"]["id"]] = {"tags": body.get("tags") or [], "dir": yml.parent.name}
    return found


def _layout(pack, name):
    return json.loads((ROOT / "Packs" / pack / "Layouts" / f"layoutscontainer-{name}.json").read_text())


def _sections(layout):
    group = layout["group"]
    tabs = (layout.get("detailsV2") or {}).get("tabs") if group == "incident" else (layout.get("indicatorsDetails") or {}).get("tabs")
    for tab in tabs or []:
        for section in tab.get("sections") or []:
            yield section


def _bindings(layout):
    """Yield (kind, script_id, label) for every dynamic section query and every button."""
    for section in _sections(layout):
        if section.get("type") in DYNAMIC_TAG:
            yield section["type"], section["query"], section.get("name")
        for item in section.get("items") or []:
            if item.get("sectionItemType") == "button":
                yield "button", item["scriptId"], item.get("name")


@pytest.mark.parametrize("pack", PACKS)
@pytest.mark.parametrize("name", ["GuardianAgentRunLayout", "GuardianSocAgentLayout"])
def test_every_dynamic_section_and_button_has_a_script_with_the_right_tag(pack, name):
    layout = _layout(pack, name)
    scripts = _scripts(pack)
    seen = 0
    for kind, script_id, label in _bindings(layout):
        seen += 1
        assert script_id in scripts, "{}: '{}' -> unknown script '{}'".format(name, label, script_id)
        tags = scripts[script_id]["tags"]
        want = DYNAMIC_TAG.get(kind) or BUTTON_TAG[layout["group"]]
        assert want in tags, "{}: '{}' uses {} which lacks tag {} (has {})".format(name, label, script_id, want, tags)
    assert seen > 0


@pytest.mark.parametrize("pack", PACKS)
def test_layout_item_and_section_ids_are_unique_within_a_layout(pack):
    for name in ("GuardianAgentRunLayout", "GuardianSocAgentLayout"):
        layout = _layout(pack, name)
        section_ids = []
        item_ids = []
        for section in _sections(layout):
            section_ids.append(section.get("i"))
            item_ids += [item["id"] for item in section.get("items") or []]
        assert len(section_ids) == len(set(section_ids)), (name, section_ids)
        assert len(item_ids) == len(set(item_ids)), name


@pytest.mark.parametrize("pack", PACKS)
def test_the_run_layout_has_the_operator_buttons_with_mandatory_arguments_only(pack):
    layout = _layout(pack, "GuardianAgentRunLayout")
    scripts = _scripts(pack)
    buttons = {label: script_id for kind, script_id, label in _bindings(layout) if kind == "button"}
    assert buttons == {
        "Approve": "GuardianButtonApprove",
        "Approve (credential tier)": "GuardianButtonApproveCredential",
        "Deny": "GuardianButtonDeny",
        "Reply to agent": "GuardianButtonReply",
        "Compact transcript": "GuardianButtonCompact",
        "Pause all runs": "GuardianButtonPause",
        "Resume all runs": "GuardianButtonResume",
    }
    for script_id in buttons.values():
        yml = yaml.safe_load((ROOT / "Packs" / pack / "Scripts" / scripts[script_id]["dir"] / f"{scripts[script_id]['dir']}.yml").read_text())
        for arg in yml.get("args") or []:
            assert arg.get("required") is True, "{}.{} must be mandatory so the pop-up asks for it".format(script_id, arg["name"])


def test_the_two_editions_have_identical_layouts_apart_from_marketplace_and_wording():
    for name in ("GuardianAgentRunLayout", "GuardianSocAgentLayout"):
        xsoar = json.dumps(_layout("Guardian", name), sort_keys=True).replace("XSOAR commands", "Cortex platform commands")
        platform = json.dumps(_layout("GuardianXSIAM", name), sort_keys=True)
        assert json.loads(xsoar)["marketplaces"] == ["xsoar"] and json.loads(platform)["marketplaces"] == ["marketplacev2"]
        assert xsoar.replace('"xsoar"', '"M"') == platform.replace('"marketplacev2"', '"M"'), name


#: the scripts that are named after an incident on XSOAR 6 and after an issue on the Cortex platform
ISSUE_NAMES = {
    "GuardianIncidentDuplicateCheck": "GuardianIssueDuplicateCheck",
    "GuardianIncidentEvidence": "GuardianIssueEvidence",
    "GuardianIncidentRoute": "GuardianIssueRoute",
    "GuardianIncidentSummary": "GuardianIssueSummary",
}


#: automations the XSOAR 6 edition ships before the Cortex platform edition has them
XSOAR_ONLY = {"GuardianReportBuild", "GuardianLookup"}


def test_the_two_editions_have_the_same_layout_scripts_and_tags():
    for script_id, info in _scripts("Guardian").items():
        if script_id in XSOAR_ONLY:
            assert script_id not in _scripts("GuardianXSIAM")
            continue
        other = _scripts("GuardianXSIAM").get(ISSUE_NAMES.get(script_id, script_id))
        assert other is not None, script_id
        assert sorted(other["tags"]) == sorted(info["tags"]), script_id
