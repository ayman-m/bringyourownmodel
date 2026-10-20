"""Content checks for the deterministic triage use case (Part A: the taxonomy List, the triage skill, the scripts and
their guards). The taxonomy List `guardian_triage_types` is the single source of truth: the skill text the model
reads, the validator's built-in fallback table and the denylist must all agree with it.
"""
import ast
import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "Packs" / "GuardianXSIAM"
LISTS = PACK / "Lists"
SCRIPTS = PACK / "Scripts"


def _list_data(name):
    return json.loads((LISTS / "list-{}.json".format(name)).read_text())["data"]


def _taxonomy():
    return json.loads(_list_data("guardian_triage_types"))


def _skill_body():
    return _list_data("guardian_skill_cortex_triage")


def _common_constant(name):
    """A literal constant from the shared helper block, read from the source (no import needed)."""
    tree = ast.parse((SCRIPTS / "GuardianCommon" / "GuardianCommon.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError("{} not found in GuardianCommon".format(name))


# --- the List -----------------------------------------------------------------------------------------------------

def test_the_taxonomy_list_parses_with_the_outer_wrapper():
    wrapper = json.loads((LISTS / "list-guardian_triage_types.json").read_text())
    assert set(wrapper) == {"id", "version", "name", "description", "data", "type", "fromVersion"}
    assert wrapper["id"] == wrapper["name"] == "guardian_triage_types" and wrapper["type"] == "json" and wrapper["version"] == -1
    assert isinstance(wrapper["data"], str)
    data = json.loads(wrapper["data"])
    assert data["severities"] == ["low", "medium", "high", "critical"]
    assert isinstance(data["types"], list) and data["_comment"]


def test_type_names_are_unique_and_other_is_present():
    names = [t["name"] for t in _taxonomy()["types"]]
    assert len(names) == len(set(names)) == 10
    assert "other" in names
    assert all(re.fullmatch(r"[a-z][a-z_]*", n) for n in names)


def test_the_nine_types_and_other_match_the_plan():
    by_name = {t["name"]: t for t in _taxonomy()["types"]}
    assert set(by_name) == {"identity_threat", "cloud_change", "endpoint_threat", "data_exposure", "misconfiguration",
                            "vulnerability", "code_risk", "excessive_privilege", "attack_path", "other"}
    assert by_name["data_exposure"]["domains"] == ["detection", "posture"]
    assert by_name["data_exposure"]["skill"] == {"detection": "cortex_detection_investigation",
                                                 "posture": "cortex_posture_misconfiguration"}
    for name in ("identity_threat", "cloud_change", "endpoint_threat"):
        assert by_name[name]["domains"] == ["detection"] and by_name[name]["skill"] == "cortex_detection_investigation"
    for name in ("misconfiguration", "vulnerability", "code_risk", "excessive_privilege", "attack_path"):
        assert by_name[name]["domains"] == ["posture"]
    assert by_name["other"]["sub_playbook"] == "GuardianTriageOther" and by_name["other"]["skill"] == ""
    for name, row in by_name.items():
        if name != "other":
            assert row["sub_playbook"] == "GuardianTriage" + "".join(p.capitalize() for p in name.split("_"))


def test_every_row_is_well_formed_and_names_shipped_skills():
    index = {e["name"]: e for e in json.loads(_list_data("guardian_skills_index"))}
    for row in _taxonomy()["types"]:
        assert set(row) == {"name", "description", "domains", "sub_playbook", "skill"}
        assert row["description"] and "\n" not in row["description"] and len(row["description"]) <= 120
        assert row["domains"] and set(row["domains"]) <= {"detection", "posture"}
        skills = row["skill"].values() if isinstance(row["skill"], dict) else [row["skill"]]
        for skill in skills:
            if row["name"] == "other":
                assert skill == ""
            else:
                assert skill in index and index[skill]["enabled"] is True, (row["name"], skill)
        if isinstance(row["skill"], dict):
            assert set(row["skill"]) == set(row["domains"])


def test_the_built_in_fallback_table_equals_the_list():
    data = _taxonomy()
    assert _common_constant("GUARDIAN_TRIAGE_DEFAULT_TYPES") == data["types"]
    assert list(_common_constant("GUARDIAN_TRIAGE_SEVERITIES")) == data["severities"]


# --- the skill ----------------------------------------------------------------------------------------------------

def test_the_triage_skill_is_indexed_enabled_and_has_a_body():
    index = {e["name"]: e for e in json.loads(_list_data("guardian_skills_index"))}
    assert index["cortex_triage"]["enabled"] is True and index["cortex_triage"]["category"] == "workflows"
    assert _skill_body().startswith("---\nname: cortex_triage\n")


def test_the_skill_names_exactly_the_lists_types_with_their_description_and_domains():
    body = _skill_body()
    section = body.split("## Types", 1)[1].split("\n## ", 1)[0]
    lines = [l for l in section.splitlines() if l.startswith("- `")]
    expected = ["- `{}` ({}): {}".format(t["name"], " or ".join(t["domains"]), t["description"]) for t in _taxonomy()["types"]]
    assert lines == expected  # the same names, in the same order, with the same text
    named = set(re.findall(r"^- `([a-z_]+)`", section, re.MULTILINE))
    assert named == {t["name"] for t in _taxonomy()["types"]}


def test_the_skill_states_the_block_exactly_and_the_severity_values():
    body = _skill_body()
    block = re.search(r"```json\n(.*?)\n```", body, re.DOTALL).group(1)
    for key in ("severity", "investigation_type", "confidence", "likely_benign", "escalate", "summary", "key_entities", "next_step"):
        assert '"{}"'.format(key) in block, key
    for key in ("identities", "ips", "resources", "assets", "hosts", "hashes"):
        assert '"{}"'.format(key) in block, key
    assert "low|medium|high|critical" in block
    for level in _taxonomy()["severities"]:
        assert "`{}`".format(level) in body
    assert "nothing after it" in body and "`other`" in body
    assert "Happened is not the same as authorised" in body  # the likely_benign rule
    assert "critical" in body.split("## Severity", 1)[1].split("\n## ", 1)[0]


def test_the_skill_does_not_name_sub_playbooks_or_ask_for_a_note():
    body = _skill_body()
    assert "GuardianTriage" not in body
    assert "Do not write a case note or a memory row" in body


def test_the_skill_key_entity_lists_match_the_validator():
    assert set(_common_constant("GUARDIAN_TRIAGE_ENTITY_KEYS")) == {"identities", "ips", "resources", "assets", "hosts", "hashes"}


# --- guards on the scripts -----------------------------------------------------------------------------------------

def _denied():
    return set(json.loads(_list_data("guardian_tool_denylist"))["denied"])


def _allowed():
    return set(json.loads(_list_data("guardian_tool_allowlist"))["commands"])


def test_apply_is_denylisted_and_not_allowlisted():
    assert "GuardianTriageApply" in _denied()
    assert "GuardianTriageApply" not in _allowed()


def test_result_is_not_allowlisted_and_is_denylisted():
    assert "GuardianTriageResult" not in _allowed()
    assert "GuardianTriageResult" in _denied()


def test_no_triage_automation_is_allowlisted_and_core_update_issue_is_still_not():
    assert not [c for c in _allowed() if "Triage" in c]
    assert "core-update-issue" not in _allowed()
    policy = _list_data("guardian_policy")
    assert "core-update-issue" in policy  # still gated by the policy list for the model


@pytest.mark.parametrize("name", ["GuardianTriageResult", "GuardianTriageApply", "GuardianIssueSummary"])
def test_the_new_scripts_are_well_formed(name):
    folder = SCRIPTS / name
    doc = yaml.safe_load((folder / (name + ".yml")).read_text())
    assert doc["commonfields"]["id"] == name and doc["name"] == name
    assert doc["marketplaces"] == ["marketplacev2"] and doc["subtype"] == "python3" and doc["system"] is False
    assert doc["dockerimage"].startswith("demisto/python3:") and doc["fromversion"] == "6.10.0"
    source = (folder / (name + ".py")).read_text()
    assert source.count("# <GUARDIAN_COMMON_INJECT>") == 1 and source.count("# </GUARDIAN_COMMON>") == 1
    assert (folder / (name + "_test.py")).exists()


def test_the_issue_summary_is_operator_owned_denylisted_and_not_allowlisted():
    assert "GuardianIssueSummary" in _denied() and "GuardianIssueSummary" not in _allowed()
    policy = _list_data("guardian_policy")
    assert "GuardianIssueSummary" not in policy
    preapproved = _list_data("guardian_preapproved")
    assert "GuardianIssueSummary" not in preapproved


def test_the_issue_summary_writes_only_the_id_and_the_description():
    source = (SCRIPTS / "GuardianIssueSummary" / "GuardianIssueSummary.py").read_text()
    assert source.count("GUARDIAN_ISSUE_SUMMARY_UPDATE_COMMAND, {") == 1
    assert re.findall(r'GUARDIAN_ISSUE_SUMMARY_UPDATE_COMMAND, (\{.*?\})\)', source) == ['{"id": issue_id, "description": description}']
    assert "This script writes no name, type or status" in _flat(source)



def test_apply_writes_only_severity_and_phase():
    source = (SCRIPTS / "GuardianTriageApply" / "GuardianTriageApply.py").read_text()
    assert source.count("GUARDIAN_TRIAGE_APPLY_UPDATE_COMMAND, update_args") == 1
    for forbidden in ('"type"', '"description"', '"name"', '"status":', "resolution_status", "assigned_user"):
        assert not re.search(r"update_args\s*\[\s*{}".format(re.escape(forbidden)), source), forbidden
    assert re.findall(r'update_args = \{(.*?)\}', source) == ['"id": issue_id, "phase": phase']
    assert 'update_args["severity"] = new_severity' in source


def test_the_tick_declares_the_triage_arguments_and_outputs():
    doc = yaml.safe_load((SCRIPTS / "GuardianReasoningTick" / "GuardianReasoningTick.yml").read_text())
    args = {a["name"]: a for a in doc["args"]}
    assert args["assessment_mode"]["required"] is False and set(args["assessment_mode"]["predefined"]) == {"verdict", "posture", "triage"}
    assert args["max_ticks"]["required"] is False
    outputs = {o["contextPath"] for o in doc["outputs"]}
    assert {"Guardian.Loop.conclusion", "Guardian.Loop.triage_block", "Guardian.Loop.assessment_mode"} <= outputs


def test_the_result_yml_documents_every_triage_key():
    doc = yaml.safe_load((SCRIPTS / "GuardianTriageResult" / "GuardianTriageResult.yml").read_text())
    paths = {o["contextPath"] for o in doc["outputs"]}
    contract = {"status", "branch", "investigation_type", "severity", "original_severity", "confidence", "likely_benign", "escalate",
                "summary", "next_step", "domain", "assessment_mode", "sub_playbook", "skill", "reason", "inputs"}
    assert {"Guardian.Triage." + k for k in contract} <= paths


# --- Part B: the triage playbooks ------------------------------------------------------------------------------------

PLAYBOOKS = PACK / "Playbooks"
COMMAND_NAMES = set(json.loads((Path(__file__).resolve().parent / "cortex_command_names.json").read_text())["commands"])
#: Automations the platform ships (not pack scripts, not integration commands).
BUILTIN_SCRIPTS = {"DeleteContext", "Print", "Set", "SetAndHandleEmpty"}
PARENT = "GuardianTriageAndInvestigateIssue"

#: Where each command leaves its result in context (from the integration definitions). GuardianXQL leaves it at its
#: `context_key` argument instead.
COMMAND_CONTEXT = {
    "core-list-risky-users": "Core.RiskyUser",
    "core-list-risky-hosts": "Core.RiskyHost",
    "core-get-IP-analytics-prevalence": "Core.AnalyticsPrevalence.Ip",
    "core-get-hash-analytics-prevalence": "Core.AnalyticsPrevalence.Hash",
    "core-get-endpoints": "Core.Endpoint",
    "core-get-contributing-event": "Core.ContributingEvent",
    "core-search-assets": "Core.Asset",
    "asm-list-asset-internet-exposure": "ASM.AssetInternetExposure",
    "core-get-issues": "Core.Issue",
    "core-get-vulnerabilities": "Core.VulnerabilityIssue",
    "core-get-appsec-issues": "Core.AppsecIssue",
}


def _playbook(name):
    return yaml.safe_load((PLAYBOOKS / "playbook-{}.yml".format(name)).read_text())


def _sub_names():
    return [t["sub_playbook"] for t in _taxonomy()["types"]]


def _all_triage_names():
    return [PARENT] + _sub_names()


def _tasks(doc, kind=None):
    return [t for t in doc["tasks"].values() if kind is None or t["type"] == kind]


def _arg(task, name):
    spec = (task.get("scriptarguments") or {}).get(name) or {}
    return spec.get("simple")


def _script(task):
    return str((task.get("task") or {}).get("script") or "")


def _command_of(task):
    """The command or automation a regular task runs, without the `|||` marker."""
    return _script(task).replace("|||", "")


def _pack_scripts():
    return {p.name for p in SCRIPTS.iterdir() if p.is_dir()}


def test_every_triage_playbook_exists_and_is_well_formed():
    for name in _all_triage_names():
        doc = _playbook(name)
        assert doc["id"] == doc["name"] == name and doc["version"] == -1
        assert doc["adopted"] is True and doc["fromversion"] == "6.10.0" and doc["marketplaces"] == ["marketplacev2"]
        assert doc["description"] and str(doc["starttaskid"]) in doc["tasks"]
        ids = set(doc["tasks"])
        for key, task in doc["tasks"].items():
            assert task["id"] == key and task["task"]["id"] == task["taskid"] and task["task"]["description"] is not None
            for targets in (task.get("nexttasks") or {}).values():
                assert set(targets) <= ids, (name, key)
            assert json.loads(task["view"])["position"]["x"] is not None  # view is JSON, not YAML
        assert json.loads(doc["view"])["paper"]["dimensions"]
        assert len({t["taskid"] for t in doc["tasks"].values()}) == len(doc["tasks"])
        for task in doc["tasks"].values():
            if task.get("continueonerror"):
                # the value every live-tested Guardian playbook uses (the SDK schema would prefer "", but live behaviour wins)
                assert task["continueonerrortype"] == "continue", (name, key)


def test_the_parent_has_one_branch_per_type_pointing_at_that_types_sub_playbook():
    doc = _playbook(PARENT)
    conditions = [t for t in _tasks(doc, "condition") if t["task"]["name"] == "Which type?"]
    assert len(conditions) == 1
    branch = conditions[0]
    types = _taxonomy()["types"]
    labels = [c["label"] for c in branch["conditions"]]
    assert labels == [t["name"] for t in types] and len(set(labels)) == len(labels)
    for row in types:
        cond = [c for c in branch["conditions"] if c["label"] == row["name"]]
        assert len(cond) == 1
        rule = cond[0]["condition"][0][0]
        assert rule["operator"] == "isEqualString" and rule["left"]["value"]["simple"] == "Guardian.Triage.branch"
        assert rule["right"]["value"]["simple"] == row["name"]
        targets = branch["nexttasks"][row["name"]]
        assert len(targets) == 1
        target = doc["tasks"][targets[0]]
        assert target["type"] == "playbook" and target["task"]["playbookName"] == row["sub_playbook"]
    other_target = branch["nexttasks"]["#default#"]
    assert [doc["tasks"][t]["task"]["playbookName"] for t in other_target] == ["GuardianTriageOther"]
    called = [t["task"]["playbookName"] for t in _tasks(doc, "playbook")]
    assert sorted(called) == sorted(_sub_names())


def test_the_sub_playbook_names_match_their_files_and_the_list():
    for row in _taxonomy()["types"]:
        assert (PLAYBOOKS / "playbook-{}.yml".format(row["sub_playbook"])).exists(), row["sub_playbook"]
        assert _playbook(row["sub_playbook"])["name"] == row["sub_playbook"]


def test_the_playbook_files_have_no_tabs_and_block_scalar_views():
    for name in _all_triage_names():
        text = (PLAYBOOKS / "playbook-{}.yml".format(name)).read_text()
        assert "\t" not in text and "view: |-" in text


def test_every_command_a_triage_playbook_uses_exists():
    scripts, unknown = _pack_scripts(), []
    for name in _all_triage_names():
        for task in _tasks(_playbook(name), "regular"):
            command = _command_of(task)
            if command in scripts or command in BUILTIN_SCRIPTS or command in COMMAND_NAMES:
                continue
            unknown.append((name, command))
    assert not unknown, unknown
    # integration commands are written with the brandless marker, pack automations without
    for name in _all_triage_names():
        for task in _tasks(_playbook(name), "regular"):
            command = _command_of(task)
            assert _script(task).startswith("|||") == (command not in scripts and command not in BUILTIN_SCRIPTS), (name, command)
            assert task["task"]["iscommand"] == _script(task).startswith("|||")


def test_no_triage_playbook_uses_a_write_command():
    policy = {k for k in json.loads(_list_data("guardian_policy")) if not k.startswith("_")}
    denied = _denied()
    for name in _all_triage_names():
        for task in _tasks(_playbook(name), "regular"):
            command = _command_of(task)
            assert command not in policy, (name, command)
            assert command != "asm-start-remediation-confirmation-scan"
            if command in denied:
                # the only denylisted automations a triage playbook may run are the parent's own operator steps
                assert name == PARENT and command in ("GuardianTriageResult", "GuardianTriageApply", "GuardianIssueSummary"), (name, command)
            for blocked in ("core-update", "setIncident", "setList", "addToList", "xdr-", "isolate", "quarantine", "delete"):
                assert blocked not in command.lower() or command == "DeleteContext", (name, command)


def test_apply_and_result_are_run_once_and_only_by_the_parent():
    commands = {n: [_command_of(t) for t in _tasks(_playbook(n), "regular")] for n in _all_triage_names()}
    assert commands[PARENT].count("GuardianTriageApply") == 1 and commands[PARENT].count("GuardianTriageResult") == 1
    assert commands[PARENT].count("GuardianIssueSummary") == 2
    for name in _sub_names():
        for operator_step in ("GuardianTriageApply", "GuardianTriageResult", "GuardianIssueSummary"):
            assert operator_step not in commands[name]


def _predecessors(doc):
    pred = {}
    for key, task in doc["tasks"].items():
        for label, targets in (task.get("nexttasks") or {}).items():
            for target in targets:
                pred.setdefault(target, []).append((key, label))
    return pred


def _guards_of(doc, key):
    """The conditions a task sits behind: every condition reached on the way back from the task where the path left
    the condition by its `yes` label."""
    pred, found, seen, stack = _predecessors(doc), set(), set(), [key]
    while stack:
        current = stack.pop()
        for parent, label in pred.get(current, []):
            task = doc["tasks"][parent]
            if task["type"] == "condition":
                if label == "yes":
                    found.add(task["conditions"][0]["condition"][0][0]["left"]["value"]["simple"])
                    continue  # a yes branch ends the climb: the guard holds from here down
            if parent not in seen:
                seen.add(parent)
                stack.append(parent)
    return found


def _enrichment_tasks(doc):
    return [(k, t) for k, t in doc["tasks"].items()
            if t["type"] == "regular" and (_script(t).startswith("|||") or _command_of(t) == "GuardianXQL")]


def test_every_enrichment_task_is_guarded_by_its_input_and_continues_on_error():
    for name in _sub_names():
        if name == "GuardianTriageOther":
            continue
        doc = _playbook(name)
        tasks = _enrichment_tasks(doc)
        assert tasks, name
        for key, task in tasks:
            assert task["continueonerror"] is True, (name, key)
            references = {m for v in (task.get("scriptarguments") or {}).values()
                          for m in re.findall(r"Guardian\.Triage\.inputs\.[a-z_]+|Guardian\.Route\.signals(?:\.asset_ids)?",
                                              v.get("simple", "") or v.get("complex", {}).get("root", "") + "." + v.get("complex", {}).get("accessor", ""))}
            references.discard("Guardian.Triage.inputs.anchor_time")  # optional: an empty anchor only means "count back from now"
            guards = _guards_of(doc, key)
            for reference in references:
                assert any(g.startswith(reference) or reference.startswith(g) for g in guards), (name, key, reference, guards)
            if not references:  # only the issue's own id or name is used: those always exist
                assert any("${incident." in (v.get("simple") or "") for v in task["scriptarguments"].values()) or guards, (name, key)


def test_each_guard_is_a_deterministic_condition_with_a_yes_branch_and_a_default():
    for name in _sub_names():
        doc = _playbook(name)
        for key, task in doc["tasks"].items():
            if task["type"] != "condition":
                continue
            assert set(task["nexttasks"]) == {"yes", "#default#"}, (name, key)
            rule = task["conditions"][0]
            assert rule["label"] == "yes" and rule["condition"][0][0]["operator"] == "isNotEmpty"  # no regex operator anywhere


def _context_paths_written(doc):
    paths = []
    for task in _tasks(doc, "regular"):
        command = _command_of(task)
        if command == "GuardianXQL":
            paths.append(_arg(task, "context_key"))
        elif command in COMMAND_CONTEXT:
            paths.append(COMMAND_CONTEXT[command])
    return paths


def _covers(keys, path):
    return any(path == key or path.startswith(key + ".") for key in keys)


def test_each_sub_playbook_clears_and_appends_exactly_what_it_fetches():
    for name in _sub_names():
        if name == "GuardianTriageOther":
            continue
        doc = _playbook(name)
        tasks = _tasks(doc, "regular")
        clears = [t for t in tasks if _command_of(t) == "DeleteContext" and _arg(t, "key") != "Guardian.Loop"]
        appends = [t for t in tasks if _command_of(t) == "GuardianIssueEvidence"]
        assert len(clears) == 1 and len(appends) == 1, name
        keys = _arg(clears[0], "key").split(",")
        paths = _arg(appends[0], "paths").split(",")
        written = _context_paths_written(doc)
        assert _arg(appends[0], "mode") == "append" and _arg(clears[0], "subplaybook") == "no"
        assert set(paths) == set(written) and len(paths) == len(set(paths)), (name, paths, written)
        assert all(_covers(keys, p) for p in paths), (name, keys, paths)  # everything appended is cleared first
        assert all(any(_covers([k], p) for p in paths) for k in keys), (name, keys, paths)  # nothing else is cleared
        for path in paths:  # the script would refuse any other path
            assert path.split(".")[0] != "Guardian" or path.startswith(("Guardian.Enrich.", "Guardian.XQL"))
        # the clear comes first and the append after every fetch
        order = _flow_order(doc)
        fetches = [k for k, _ in _enrichment_tasks(doc)]
        clear_key = [k for k, t in doc["tasks"].items() if t is clears[0]][0]
        append_key = [k for k, t in doc["tasks"].items() if t is appends[0]][0]
        assert order.index(clear_key) < min(order.index(k) for k in fetches)
        assert order.index(append_key) > max(order.index(k) for k in fetches)


def _flow_order(doc):
    """Task keys in a valid execution order (a topological order of the graph; every playbook here is acyclic)."""
    indegree = {k: 0 for k in doc["tasks"]}
    for task in doc["tasks"].values():
        for targets in (task.get("nexttasks") or {}).values():
            for target in set(targets):
                indegree[target] += 1
    ready, order = [str(doc["starttaskid"])], []
    while ready:
        current = ready.pop(0)
        order.append(current)
        for targets in (doc["tasks"][current].get("nexttasks") or {}).values():
            for target in set(targets):
                indegree[target] -= 1
                if indegree[target] == 0:
                    ready.append(target)
    assert len(order) == len(doc["tasks"]), "the playbook has a cycle or an unreachable task"
    return order


def test_xql_tasks_use_shipped_templates_with_their_own_parameter_and_a_private_context_key():
    templates = {t["name"]: t for t in json.loads(_list_data("guardian_xql_templates"))["templates"]}
    seen = {}
    for name in _sub_names():
        doc = _playbook(name)
        keys = []
        for task in _tasks(doc, "regular"):
            if _command_of(task) != "GuardianXQL":
                continue
            template = templates[_arg(task, "template")]
            assert [p for p in template["params"] if _arg(task, p)] == template["params"]
            hours = int(_arg(task, "hours"))
            assert 1 <= hours <= template["max_hours"], (name, template["name"])
            key = _arg(task, "context_key")
            assert re.fullmatch(r"Guardian\.Enrich\.[A-Za-z][A-Za-z0-9_]*", key)
            keys.append(key)
            seen.setdefault(name, []).append(template["name"])
        assert len(keys) == len(set(keys)), (name, "two XQL results would share one context path")
    assert "resource_access_activity" in seen["GuardianTriageDataExposure"]
    assert templates["resource_access_activity"]["params"] == ["resource"] and templates["resource_access_activity"]["max_hours"] == 168


def test_plan_enrichment_per_type():
    """The deterministic tasks the plan table names for each type are present."""
    expected = {
        "GuardianTriageIdentityThreat": {"core-list-risky-users", "GuardianXQL:identity_activity", "core-get-IP-analytics-prevalence", "GuardianXQL:ip_activity"},
        "GuardianTriageCloudChange": {"GuardianXQL:resource_change_history", "GuardianXQL:identity_activity", "core-get-IP-analytics-prevalence", "core-search-assets"},
        "GuardianTriageEndpointThreat": {"core-get-endpoints", "core-list-risky-hosts", "core-get-hash-analytics-prevalence", "core-get-contributing-event"},
        "GuardianTriageDataExposure": {"asm-list-asset-internet-exposure", "GuardianXQL:resource_change_history", "GuardianXQL:resource_access_activity"},
        "GuardianTriageMisconfiguration": {"asm-list-asset-internet-exposure", "GuardianXQL:resource_change_history", "core-get-issues"},
        "GuardianTriageVulnerability": {"core-get-vulnerabilities", "asm-list-asset-internet-exposure", "core-get-issues"},
        "GuardianTriageCodeRisk": {"core-get-appsec-issues", "core-get-issues"},
        "GuardianTriageExcessivePrivilege": {"GuardianXQL:identity_unused_permissions", "GuardianXQL:identity_activity", "core-get-issues"},
        "GuardianTriageAttackPath": {"core-search-assets", "asm-list-asset-internet-exposure", "core-get-issues"},
    }
    for name, wanted in expected.items():
        found = set()
        for task in _tasks(_playbook(name), "regular"):
            command = _command_of(task)
            found.add("GuardianXQL:" + _arg(task, "template") if command == "GuardianXQL" else command)
        assert wanted <= found, (name, wanted - found)
    # per the plan the 72-hour and 6-hour windows
    cloud = _playbook("GuardianTriageCloudChange")
    windows = {_arg(t, "template"): _arg(t, "hours") for t in _tasks(cloud, "regular") if _command_of(t) == "GuardianXQL"}
    assert windows == {"resource_change_history": "72", "identity_activity": "6"}


def test_every_focused_prompt_says_an_empty_input_means_a_skipped_lookup_not_a_failed_one():
    """The model must not re-run a skipped lookup with a different kind of value (a VM name as an identity, a
    subscription id as an asset id), so each prompt shows the triage inputs its playbook used and says so."""
    for name in _sub_names():
        if name == "GuardianTriageOther":
            continue
        doc = _playbook(name)
        prompt = [i for i in doc["inputs"] if i["key"] == "prompt"][0]["value"]["simple"]
        task_text = json.dumps(doc["tasks"])
        used = sorted(set(re.findall(r"Guardian\.Triage\.inputs\.([a-z_0-9]+)", task_text)))
        assert used, name
        paragraph = re.search(r"The triage inputs this playbook used:.*?unless you state why\.", prompt, re.S)
        assert paragraph, name
        paragraph = paragraph.group(0)
        assert sorted(re.findall(r"\$\{Guardian\.Triage\.inputs\.([a-z_0-9]+)\}", paragraph)) == used, name  # shows exactly the inputs it uses
        assert "was skipped, not failed" in paragraph
        assert "a VM, host or resource name is not an identity" in paragraph and "a subscription id is not an asset id" in paragraph
        assert "say so in your report" in paragraph and "default window" in paragraph
        assert "was skipped, had nothing to return, or failed" in prompt and "that is unknown, not clean" in prompt
        assert prompt.index("READ THE EVIDENCE PACKET") < prompt.index("The triage inputs") < prompt.index("FOLLOW THE ACTIVE SKILL")


def test_every_xql_task_passes_the_anchor_time_and_the_prompt_explains_it():
    seen = 0
    for name in _sub_names():
        if name == "GuardianTriageOther":
            continue
        doc = _playbook(name)
        xql_tasks = [t for t in _tasks(doc, "regular") if _command_of(t) == "GuardianXQL"]
        for task in xql_tasks:
            assert _arg(task, "anchor_time") == "${Guardian.Triage.inputs.anchor_time}", name
            seen += 1
        prompt = [i for i in doc["inputs"] if i["key"] == "prompt"][0]["value"]["simple"]
        mentions = "anchor_time=`${Guardian.Triage.inputs.anchor_time}`" in prompt
        assert mentions == bool(xql_tasks), name  # shown exactly where the playbook runs an XQL lookup
        if xql_tasks:
            assert "count back from now" in prompt and "pass the same anchor_time" in prompt
    assert seen == 9


def test_triage_result_writes_the_anchor_time_and_the_skill_text_documents_it():
    doc = yaml.safe_load((SCRIPTS / "GuardianTriageResult" / "GuardianTriageResult.yml").read_text())
    inputs = [o for o in doc["outputs"] if o["contextPath"] == "Guardian.Triage.inputs"][0]
    assert "anchor_time" in inputs["description"] and "detection" in inputs["description"]
    skill = _list_data("guardian_skill_cortex_xql")
    assert "anchor_time=" in skill and "one hour after" in skill


def test_the_triage_skill_reserves_escalate_for_a_person_who_must_act_within_hours():
    skill = _skill_body()
    assert "`escalate` is `true` only when a person must act within hours" in skill
    for case in ("active compromise or hostile activity in progress", "an internet-exposed critical weakness in production",
                 "signs that a privileged identity is compromised or misused"):
        assert case in skill
    assert "a privileged identity at risk" not in skill
    assert ("A configuration weakness on a privileged account (delegatable, admin rights, unused permissions) is an ordinary "
            "posture finding for its owner, and is not an escalation by itself") in skill
    # the Apply script states the same meaning
    apply_text = (SCRIPTS / "GuardianTriageApply" / "GuardianTriageApply.py").read_text()
    assert "signs that a privileged identity is compromised or misused" in apply_text and "a privileged identity at risk" not in apply_text
    assert "not an escalation, and neither is a high severity on its own" in skill
    assert "must look at it soon" not in skill


#: The same meaning in every place `escalate` is defined: a blocked or failed attempt is not a sign of compromise.
BLOCKED_ATTEMPT_WORDING = ("attempt that was blocked or failed, with no sign it succeeded (for example a blocked phishing email or a "
                           "denied sign-in), does not escalate on its own")


def _flat(text):
    """Collapse whitespace so a wrapped line in a folded YAML scalar or a docstring does not hide a phrase."""
    return " ".join(text.split())


def test_a_blocked_or_failed_attempt_does_not_escalate_on_its_own_in_every_definition_of_escalate():
    sources = {
        "the triage skill": _skill_body(),
        "the repair prompt": (SCRIPTS / "GuardianTriageResult" / "GuardianTriageResult.py").read_text(),
        "the Apply docstring": (SCRIPTS / "GuardianTriageApply" / "GuardianTriageApply.py").read_text(),
        "the Apply description": yaml.safe_load((SCRIPTS / "GuardianTriageApply" / "GuardianTriageApply.yml").read_text())["comment"],
    }
    for where, text in sources.items():
        assert BLOCKED_ATTEMPT_WORDING in _flat(text), where
    skill = _skill_body()
    assert "An " + BLOCKED_ATTEMPT_WORDING + "." in skill
    # it sits in the escalate paragraph, before the block the skill ends with
    assert skill.index("`escalate` is `true` only when") < skill.index(BLOCKED_ATTEMPT_WORDING) < skill.index("## Conclude")


CASE_NOTE_LENGTH_WORDING = (
    "Keep the case note under 2500 characters. Notes over 4000 are rejected and cost a retry. Cut repetition and raw lists "
    "before findings: name each item once, summarise counts, and keep the verdict, key evidence and next steps.")
RESOURCE_ID_WORDING = ("When you cite a cloud resource, copy its full resource id exactly as it appears in the evidence. "
                       "Never shorten it with '...'.")
#: The wording this replaced: a soft target in a parenthesis, which small models read as optional.
OLD_CASE_NOTE_WORDINGS = ("aim for about 2500", "the tool rejects more than 4000", "4000 characters at most", "4,000-character limit",
                          "under 3000 characters")


def _case_note_prompts():
    for name in _sub_names() + ["GuardianInvestigateIssue"]:
        if name != "GuardianTriageOther":
            yield name, [i for i in _playbook(name)["inputs"] if i["key"] == "prompt"][0]["value"]["simple"]


def test_the_case_note_length_rule_and_the_full_resource_id_rule_are_stated_the_same_way_everywhere():
    """The tool rejects a note over 4000 characters (a retry), and the secret scrub masks the tail of an elided
    resource id, so every prompt and report format says to stay under 2500 and to copy a resource id whole."""
    prompts = list(_case_note_prompts())
    assert len(prompts) == 10  # the nine focused sessions and the general investigation
    for name, prompt in prompts:
        assert "in the report format the skill gives. {} {}".format(CASE_NOTE_LENGTH_WORDING, RESOURCE_ID_WORDING) in _flat(prompt), name
        for old in OLD_CASE_NOTE_WORDINGS:
            assert old not in prompt, (name, old)
    tail = json.loads(_list_data("guardian_prompt_tail"))["tail"]
    assert "has a hard length limit, and cannot create attachments. {} {} Ground every claim".format(
        CASE_NOTE_LENGTH_WORDING, RESOURCE_ID_WORDING) in tail
    skills = 0
    for path in sorted(LISTS.glob("list-guardian_skill_*.json")):
        body = json.loads(path.read_text())["data"]
        if "## Report format (GuardianCaseNote" in body:
            skills += 1
            assert "## Report format (GuardianCaseNote)\n{} {}\n```".format(CASE_NOTE_LENGTH_WORDING, RESOURCE_ID_WORDING) in body, path.name
        for old in OLD_CASE_NOTE_WORDINGS:
            assert old not in body, (path.name, old)
    assert skills == 5
    for old in OLD_CASE_NOTE_WORDINGS:
        assert old not in tail, old


def test_the_case_note_length_wording_matches_the_limit_the_tool_enforces():
    source = (SCRIPTS / "GuardianCaseNote" / "GuardianCaseNote.py").read_text()
    assert re.search(r"^GUARDIAN_CASE_NOTE_MAX_CONTENT_LEN = 4000$", source, re.MULTILINE)  # the "Notes over 4000" in the prompts
    target = int(re.search(r"under (\d+) characters", CASE_NOTE_LENGTH_WORDING).group(1))
    assert target == 2500 and "over 4000" in CASE_NOTE_LENGTH_WORDING


def test_the_triage_skill_limits_identities_to_principals_and_assets_to_cortex_asset_ids():
    skill = _skill_body()
    assert "never code-commit authors" in skill and "service principals" in skill
    assert "Cortex asset ids only, never a subscription or account id" in skill


def test_every_model_sub_playbook_runs_a_focused_session_after_clearing_loop_and_loading_its_skill():
    for name in _sub_names():
        if name == "GuardianTriageOther":
            continue
        doc = _playbook(name)
        ticks = [(k, t) for k, t in doc["tasks"].items() if t["type"] == "regular" and _command_of(t) == "GuardianReasoningTick"]
        assert len(ticks) == 1, name
        key, tick = ticks[0]
        assert _arg(tick, "skill") == "${Guardian.Triage.skill}" and _arg(tick, "assessment_mode") == "${Guardian.Triage.assessment_mode}"
        assert _arg(tick, "use_prebuilt") == "true" and _arg(tick, "scope_to_incident") == "true"
        assert _arg(tick, "max_ticks") == "${inputs.max_ticks}" and _arg(tick, "prompt") == "${inputs.prompt}"
        inputs = {i["key"]: i["value"]["simple"] for i in doc["inputs"]}
        # empty by default: the focused session gets the limit GuardianInvestigateIssue gets (model size tier or settings)
        assert inputs["max_ticks"] == "" and "${Guardian.Triage.investigation_type}" in inputs["prompt"]
        assert "${Guardian.Triage.severity}" in inputs["prompt"] and "${Guardian.Triage.assessment_mode}" in inputs["prompt"]
        assert "GuardianCaseNote" in inputs["prompt"] and "Do NOT change anything" in inputs["prompt"]
        order = _flow_order(doc)
        by_command = {}
        for k, t in doc["tasks"].items():
            if t["type"] == "regular":
                by_command.setdefault(_command_of(t), []).append(k)
        loop_clear = [k for k in by_command["DeleteContext"] if _arg(doc["tasks"][k], "key") == "Guardian.Loop"]
        assert "op=store" in inputs["prompt"] and "REMEMBER" in inputs["prompt"]  # scope_to_incident makes the gate require a memory row
        assert inputs["prompt"].index("DOCUMENT") < inputs["prompt"].index("REMEMBER") < inputs["prompt"].index("END with")
        assert len(loop_clear) == 1 and _arg(doc["tasks"][by_command["GuardianSkillRead"][0]], "name") == "${Guardian.Triage.skill}"
        assert order.index(by_command["GuardianIssueEvidence"][0]) < order.index(loop_clear[0]) < order.index(by_command["GuardianSkillRead"][0]) < order.index(key)
        assert order.index(key) < order.index(by_command["GuardianRunCapture"][0]) < order.index(
            [k for k, t in doc["tasks"].items() if t["type"] == "title"][0])
        assert "GuardianCaseNote" not in by_command  # the model writes the case note, not the playbook


def test_the_data_exposure_session_follows_the_issues_domain_not_a_fixed_skill():
    doc = _playbook("GuardianTriageDataExposure")
    skill_tasks = [t for t in _tasks(doc, "regular") if _command_of(t) == "GuardianSkillRead"]
    assert _arg(skill_tasks[0], "name") == "${Guardian.Triage.skill}"  # GuardianTriageResult picks it from the List's domain map
    assert _taxonomy()["types"][3]["skill"] == {"detection": "cortex_detection_investigation", "posture": "cortex_posture_misconfiguration"}


def test_the_other_branch_runs_a_full_investigation_like_the_investigate_playbook():
    doc = _playbook("GuardianTriageOther")
    regular = _tasks(doc, "regular")
    assert [_command_of(t) for t in regular] == ["DeleteContext", "GuardianSkillRead", "GuardianReasoningTick", "GuardianRunCapture"]
    assert [t["task"]["name"] for t in regular] == ["Clear the triage session state", "Load the skill", "Run the investigation session",
                                                    "Remember the outcome"]
    clear, load, tick, capture = regular
    assert _arg(clear, "key") == "Guardian.Loop" and _arg(clear, "subplaybook") == "no"
    assert _arg(load, "name") == "${Guardian.Route.skill}" and _arg(load, "summary_only") == "true"
    assert {k: _arg(tick, k) for k in tick["scriptarguments"]} == {
        "prompt": "${inputs.prompt}", "skill": "${Guardian.Route.skill}", "use_prebuilt": "true", "scope_to_incident": "true",
        "assessment_mode": "${Guardian.Route.assessment_mode}", "max_ticks": "${inputs.max_ticks}", "continue_run_totals": "true"}
    # no analyst note task any more: the investigation writes its own case note, and the flow is a straight line
    assert "GuardianCaseNote" not in [_command_of(t) for t in regular]
    order = _flow_order(doc)
    assert [doc["tasks"][k]["task"]["name"] for k in order] == ["", "Clear the triage session state", "Load the skill",
                                                                 "Run the investigation session", "Remember the outcome", "Done"]
    inputs = {i["key"]: i for i in doc["inputs"]}
    assert set(inputs) == {"prompt", "max_ticks"} and inputs["max_ticks"]["value"]["simple"] == ""
    assert "Empty (the default)" in " ".join(inputs["max_ticks"]["description"].split())
    prompt = inputs["prompt"]["value"]["simple"]
    assert "${incident.id}" in prompt and "did not place it in a type" in prompt and "${Guardian.Triage.reason}" in prompt
    assert "DIGEST" not in prompt and "rule_digest" not in prompt  # digest mode is left out
    assert "GuardianTriage" not in prompt


def test_the_parent_hands_the_turn_cap_to_every_branch_including_other():
    doc = _playbook(PARENT)
    branches = _tasks(doc, "playbook")
    assert len(branches) == 10
    assert all(_arg(sub, "max_ticks") == "${inputs.investigate_max_ticks}" for sub in branches)


def test_the_parent_flow_runs_the_preparation_then_triage_then_apply_then_the_branch():
    doc = _playbook(PARENT)
    by_command = {}
    for key, task in doc["tasks"].items():
        if task["type"] == "regular":
            by_command.setdefault(_command_of(task), []).append(key)
    order = _flow_order(doc)

    def at(command, index=0):
        return order.index(by_command[command][index])

    assert at("GuardianKillSwitchCheck", 0) < at("GuardianJobGuardCheck") < at("GuardianIssueRoute") < at("GuardianModelProfileCheck") < at("GuardianIssueEvidence")
    assert at("GuardianIssueEvidence") < at("GuardianPromptBuilder") < at("GuardianToolCatalogBuilder") < at("GuardianSkillRead")
    assert at("GuardianSkillRead") < at("DeleteContext", 0) < at("GuardianReasoningTick") < at("GuardianTriageResult")
    assert at("GuardianTriageResult") < at("DeleteContext", 1) < at("GuardianKillSwitchCheck", 1) < at("GuardianTriageApply")
    branch = [k for k, t in doc["tasks"].items() if t["task"]["name"] == "Which type?"][0]
    assert at("GuardianTriageApply") < order.index(branch)
    deletes = {_arg(doc["tasks"][k], "key") for k in by_command["DeleteContext"]}
    # the triage record of an earlier run goes with the loop state; Guardian.TriageApply stays, so a second apply is a no-op
    assert deletes == {"Guardian.Loop,Guardian.Triage", "Guardian.Preflight.KillSwitch"}
    assert not any("Guardian.TriageApply" in key for key in deletes)
    first_delete = doc["tasks"][by_command["DeleteContext"][0]]
    assert _arg(first_delete, "key") == "Guardian.Loop,Guardian.Triage" and _arg(first_delete, "subplaybook") == "no"
    # the kill switch is checked again right before the apply task, and a halt there skips the apply and every sub-playbook
    second = [k for k, t in doc["tasks"].items() if t["task"]["name"] == "Kill switch on now?"][0]
    assert doc["tasks"][second]["nexttasks"]["#default#"] == by_command["GuardianTriageApply"]
    assert doc["tasks"][doc["tasks"][second]["nexttasks"]["halted"][0]]["type"] == "title"

    tick = doc["tasks"][by_command["GuardianReasoningTick"][0]]
    assert _arg(tick, "assessment_mode") == "triage" and _arg(tick, "skill") == "cortex_triage"
    assert _arg(tick, "max_ticks") == "${inputs.triage_max_ticks}" and _arg(tick, "prompt") == "${inputs.prompt}"
    assert _arg(tick, "use_prebuilt") == "true" and _arg(tick, "scope_to_incident") == "true"
    assert _arg(doc["tasks"][by_command["GuardianSkillRead"][0]], "name") == "cortex_triage"
    assert _arg(doc["tasks"][by_command["GuardianTriageApply"][0]], "apply_changes") == "${inputs.apply_changes}"
    for sub in _tasks(doc, "playbook"):
        assert _arg(sub, "max_ticks") == "${inputs.investigate_max_ticks}"
        assert sub["separatecontext"] is False  # the sub-playbook shares Guardian.Triage, Guardian.Evidence and the prompt


def test_the_parent_inputs_and_prompt():
    doc = _playbook(PARENT)
    inputs = {i["key"]: i["value"]["simple"] for i in doc["inputs"]}
    assert set(inputs) == {"prompt", "apply_changes", "triage_max_ticks", "investigate_max_ticks"}
    assert inputs["apply_changes"] == "true" and inputs["triage_max_ticks"] == "6"  # the triage session is meant to be short
    assert inputs["investigate_max_ticks"] == ""  # empty: the investigation session follows the model size tier and the settings
    prompt = inputs["prompt"]
    for phrase in ("THIS Cortex platform issue", "pinned above", "at most a few lookups", "Do NOT write a case note",
                   "do NOT store a memory row", "EXACTLY the triage block", "`other`", "analysis", "recommendations"):
        assert phrase in prompt, phrase
    assert "${incident.id}" in prompt and "GuardianTriage" not in prompt


def test_the_prompt_tail_says_triage_replaces_the_verdict_block_note_and_memory_row():
    tail = json.loads(_list_data("guardian_prompt_tail"))["tail"]
    assert "starts with `TRIAGE RUN:`" in tail and "replaces the verdict or posture block, the case note and the memory row" in tail
    assert "investigation prompt says" not in tail  # keyed on the pinned paragraph, not on the prompt text
    assert "a focused session after triage), the blocks and steps above all apply" in tail
    # the pinned paragraph the tick adds is the one the tail names
    tick = (SCRIPTS / "GuardianReasoningTick" / "GuardianReasoningTick.py").read_text()
    assert '"\\n\\nTRIAGE RUN: ' in tick


def test_the_new_xql_template_is_registered_and_the_description_lists_it():
    templates = {t["name"]: t for t in json.loads(_list_data("guardian_xql_templates"))["templates"]}
    row = templates["resource_access_activity"]
    assert row["dataset"] == "cloud_audit_logs" and row["params"] == ["resource"] and row["default_hours"] == 24 and row["max_hours"] == 168
    assert 'state_changing_event = "false"' in row["query"] and "{resource_lc}" in row["query"]
    assert 'state_changing_event = "true"' in templates["resource_change_history"]["query"]  # a string on this platform, both quoted
    doc = yaml.safe_load((SCRIPTS / "GuardianXQL" / "GuardianXQL.yml").read_text())
    assert "resource_access_activity" in {a["name"]: a for a in doc["args"]}["template"]["description"]
    assert "context_key" in {a["name"] for a in doc["args"]}


def test_the_evidence_script_documents_append_mode():
    doc = yaml.safe_load((SCRIPTS / "GuardianIssueEvidence" / "GuardianIssueEvidence.yml").read_text())
    args = {a["name"]: a for a in doc["args"]}
    assert "append" in args["mode"]["predefined"] and "paths" in args
    assert "GuardianIssueEvidence" not in _allowed()  # the model cannot rewrite the pinned packet


def test_the_endpoint_hash_lookup_runs_on_the_sha256_input_without_a_regex():
    doc = _playbook("GuardianTriageEndpointThreat")
    text = (PLAYBOOKS / "playbook-GuardianTriageEndpointThreat.yml").read_text()
    assert "operator: match" not in text and "matchRegex" not in text
    prevalence = [(k, t) for k, t in doc["tasks"].items() if t["type"] == "regular" and _command_of(t) == "core-get-hash-analytics-prevalence"]
    assert len(prevalence) == 1
    key, task = prevalence[0]
    assert _arg(task, "sha256") == "${Guardian.Triage.inputs.sha256}"
    assert _guards_of(doc, key) == {"Guardian.Triage.inputs.sha256"}


def test_the_result_documents_the_sha256_input():
    doc = yaml.safe_load((SCRIPTS / "GuardianTriageResult" / "GuardianTriageResult.yml").read_text())
    inputs = [o for o in doc["outputs"] if o["contextPath"] == "Guardian.Triage.inputs"][0]
    assert "sha256" in inputs["description"]


def test_every_continue_on_error_value_is_continue():
    total = 0
    for name in _all_triage_names():
        text = (PLAYBOOKS / "playbook-{}.yml".format(name)).read_text()
        assert 'continueonerrortype: ""' not in text
        total += text.count("continueonerrortype: continue")
    assert total == 113  # every task that continues on error, in all eleven playbooks


def test_the_ten_investigation_sessions_continue_the_run_totals_and_the_other_sessions_do_not():
    for name in _sub_names():
        doc = _playbook(name)
        ticks = [t for t in _tasks(doc, "regular") if _command_of(t) == "GuardianReasoningTick"]
        assert len(ticks) == 1 and _arg(ticks[0], "continue_run_totals") == "true", name
    parent_tick = [t for t in _tasks(_playbook(PARENT), "regular") if _command_of(t) == "GuardianReasoningTick"]
    assert len(parent_tick) == 1 and _arg(parent_tick[0], "continue_run_totals") is None  # the triage session starts the totals
    investigate = yaml.safe_load((PLAYBOOKS / "playbook-GuardianInvestigateIssue.yml").read_text())
    assert all(_arg(t, "continue_run_totals") is None for t in _tasks(investigate, "regular"))


def test_the_tick_declares_continue_run_totals():
    doc = yaml.safe_load((SCRIPTS / "GuardianReasoningTick" / "GuardianReasoningTick.yml").read_text())
    assert "continue_run_totals" in {a["name"] for a in doc["args"]}


def test_the_turn_limit_inputs_say_empty_means_the_investigation_limit():
    parent = {i["key"]: i for i in _playbook(PARENT)["inputs"]}
    text = " ".join(parent["investigate_max_ticks"]["description"].split())
    assert "Empty (the default)" in text and "GuardianInvestigateIssue" in text and "25, 40 or 60" in text and "only lower" in text
    for name in _sub_names():
        inputs = {i["key"]: i for i in _playbook(name)["inputs"]}
        assert "Empty (the default)" in " ".join(inputs["max_ticks"]["description"].split()), name


def test_the_health_note_does_not_quote_the_route_reason():
    doc = _playbook(PARENT)
    notes = [t for t in _tasks(doc, "regular") if _command_of(t) == "GuardianCaseNote"]
    assert len(notes) == 1
    content = _arg(notes[0], "content")
    assert "Guardian.Route.reason" not in content and "handled without a model session" in content and "${Guardian.Route.family}" in content


# --- the summary tasks in the parent, and the investigation rules in every branch ----------------------------------

def test_the_parent_writes_the_triage_summary_after_apply_and_the_conclusion_before_done():
    doc = _playbook(PARENT)
    tasks = doc["tasks"]
    summaries = {_arg(t, "stage"): key for key, t in tasks.items() if t["type"] == "regular" and _command_of(t) == "GuardianIssueSummary"}
    assert set(summaries) == {"triage", "investigation"}
    by_name = {t["task"]["name"]: key for key, t in tasks.items()}
    assert tasks[summaries["triage"]]["task"]["name"] == "Write the triage summary"
    assert tasks[summaries["investigation"]]["task"]["name"] == "Write the investigation conclusion"
    apply_key = [k for k, t in tasks.items() if t["type"] == "regular" and _command_of(t) == "GuardianTriageApply"][0]
    assert tasks[apply_key]["nexttasks"]["#none#"] == [summaries["triage"]]
    assert tasks[summaries["triage"]]["nexttasks"]["#none#"] == [by_name["Which type?"]]
    done = by_name["Done"]
    assert tasks[summaries["investigation"]]["nexttasks"]["#none#"] == [done]
    for branch in _tasks(doc, "playbook"):
        assert branch["nexttasks"]["#none#"] == [summaries["investigation"]], branch["task"]["name"]
    for key in summaries.values():
        task = tasks[key]
        assert _arg(task, "apply_changes") == "${inputs.apply_changes}" and task["continueonerror"] is True
        assert task["separatecontext"] is False and task["task"]["description"]
    # a halted path or the no-model note never passes through them: only the apply task and the branches lead there
    pred = _predecessors(doc)
    assert {p for p, _l in pred[summaries["triage"]]} == {apply_key}
    assert {p for p, _l in pred[summaries["investigation"]]} == {k for k, t in tasks.items() if t["type"] == "playbook"}
    assert {p for p, _l in pred[done]} == {summaries["investigation"], by_name["Note - no model session needed"]}
    for title in [t for t in tasks.values() if t["type"] == "title" and t["task"]["name"].startswith("Halted")]:
        assert not title.get("nexttasks")


def test_every_new_and_moved_task_has_a_view_and_no_two_tasks_share_a_position():
    for name in _all_triage_names():
        doc = _playbook(name)
        positions = [tuple(json.loads(t["view"])["position"].values()) for t in doc["tasks"].values()]
        assert len(positions) == len(set(positions)), name


def _investigate_rules():
    prompt = {i["key"]: i["value"]["simple"] for i in yaml.safe_load((PLAYBOOKS / "playbook-GuardianInvestigateIssue.yml").read_text())["inputs"]}["prompt"]
    text = _flat(prompt)
    start = text.index("Judge by the assessment mode")
    judge = text[start:text.index(" 4) If a memory row")]
    start = text.index("If a memory row")
    memory = text[start:text.index(" 5) DOCUMENT")]
    start = text.index("In `verdict` mode: `Malicious`")
    verdict = text[start:text.index(" End with EXACTLY", start)]
    start = text.index("In `posture` mode: `Confirmed`")
    posture = text[start:text.index(" End with EXACTLY", start)]
    return {"judge": judge, "memory": memory, "verdict": verdict, "posture": posture}


@pytest.mark.parametrize("name", [
    "GuardianTriageIdentityThreat", "GuardianTriageCloudChange", "GuardianTriageEndpointThreat", "GuardianTriageDataExposure",
    "GuardianTriageMisconfiguration", "GuardianTriageVulnerability", "GuardianTriageCodeRisk", "GuardianTriageExcessivePrivilege",
    "GuardianTriageAttackPath", "GuardianTriageOther"])
def test_every_branch_prompt_carries_the_judgment_and_calibration_rules_of_the_investigate_prompt_verbatim(name):
    rules = _investigate_rules()
    assert all(len(rule) > 200 for rule in rules.values())
    prompt = _flat({i["key"]: i["value"]["simple"] for i in _playbook(name)["inputs"]}["prompt"])
    for label, rule in rules.items():
        assert rule in prompt, (name, label)
    for phrase in ("Benign at 70 or more needs evidence that it was expected", "answer Suspicious (confidence 40-70), not Malicious",
                   "A memory row is an earlier conclusion, often Guardian's own", "a resolution as a false positive is evidence",
                   "P1 (fix now: internet-exposed or admin-level in production)"):
        assert phrase in prompt, (name, phrase)
    assert "digest" not in prompt.lower()


def test_the_branch_session_task_is_called_the_investigation_session_everywhere():
    for name in _sub_names():
        doc = _playbook(name)
        names = [t["task"]["name"] for t in _tasks(doc, "regular")]
        assert "Run the investigation session" in names and "Run the focused model session" not in names, name
        assert "focused" not in (PLAYBOOKS / "playbook-{}.yml".format(name)).read_text(), name


def test_the_triage_skill_and_the_tick_ask_for_the_optional_analysis_and_recommendations():
    skill = _skill_body()
    conclude = skill.split("## Conclude", 1)[1]
    assert '"analysis"' in conclude and '"recommendations"' in conclude and "optional" in conclude and "800" in conclude
    schema = (SCRIPTS / "GuardianReasoningTick" / "GuardianReasoningTick.py").read_text()
    assert '"analysis": "optional' in schema and '"recommendations": ["optional' in schema
    doc = yaml.safe_load((SCRIPTS / "GuardianTriageResult" / "GuardianTriageResult.yml").read_text())
    paths = {o["contextPath"] for o in doc["outputs"]}
    assert {"Guardian.Triage.analysis", "Guardian.Triage.recommendations", "Guardian.Triage.issue_id"} <= paths
    index = {e["name"]: e for e in json.loads(_list_data("guardian_skills_index"))}
    assert "analysis and recommendations" in index["cortex_triage"]["description"]
