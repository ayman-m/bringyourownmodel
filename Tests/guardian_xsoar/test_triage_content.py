"""Content checks for the XSOAR 6 edition's deterministic triage: the taxonomy List, the triage skill, the routing
table, the scripts' guards and the triage playbooks. The taxonomy List `guardian_triage_types` is the single source of
truth: the skill text the model reads, the validator's built-in fallback table, the parent playbook's branches and the
sub-playbook files must all agree with it.
"""
import ast
import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "Packs" / "Guardian"
LISTS = PACK / "Lists"
SCRIPTS = PACK / "Scripts"
PLAYBOOKS = PACK / "Playbooks"
PARENT = "GuardianTriageAndInvestigateIncident"

#: The optional lookups of the type playbooks. Every one runs through `GuardianLookup` (never as a `|||` command task and never
#: as a content script task directly): a task for a command no enabled integration implements, or for a script that is not
#: installed, stops the playbook or marks everything after it as not executed, the investigation session included. The
#: command is the task's `command` argument; the argument names are verified against demisto/content integration ymls.
LOOKUP_COMMANDS = {"ip": [{"ip"}], "domain": [{"domain"}], "url": [{"url"}], "file": [{"file"}],
                   "endpoint": [{"hostname"}, {"ip"}], "cve": [{"cve_id"}], "GetUserData": [{"user_name"}],
                   "GetEndpointData": [{"endpoint_hostname"}]}
LOOKUP_SCRIPT = "GuardianLookup"
#: Built-in and content scripts the playbooks may run directly (they exist on every server and do not stop a playbook).
CONTENT_SCRIPTS = {"DeleteContext", "SearchIncidentsV2"}
#: Where each lookup leaves its result in context.
COMMAND_CONTEXT = {
    "ip": ["IP", "DBotScore"], "domain": ["Domain", "DBotScore"], "url": ["URL", "DBotScore"], "file": ["File", "DBotScore"],
    "endpoint": ["Endpoint"], "cve": ["CVE"], "GetUserData": ["UserData"], "GetEndpointData": ["EndpointData"],
    "SearchIncidentsV2": ["foundIncidents"],
}


def _list_data(name):
    return json.loads((LISTS / "list-{}.json".format(name)).read_text())["data"]


def _taxonomy():
    return json.loads(_list_data("guardian_triage_types"))


def _skill_body():
    return _list_data("guardian_skill_xsoar_triage")


def _common_constant(name):
    """A literal constant from the shared helper block, read from the source (no import needed)."""
    tree = ast.parse((SCRIPTS / "GuardianCommon" / "GuardianCommon.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError("{} not found in GuardianCommon".format(name))


def _denied():
    return set(json.loads(_list_data("guardian_tool_denylist"))["denied"])


def _allowed():
    return set(json.loads(_list_data("guardian_tool_allowlist"))["commands"])


# --- the List and the skill ------------------------------------------------------------------------------------------

def test_the_taxonomy_list_parses_with_the_outer_wrapper():
    wrapper = json.loads((LISTS / "list-guardian_triage_types.json").read_text())
    assert set(wrapper) == {"id", "version", "name", "description", "data", "type", "fromVersion"}
    assert wrapper["id"] == wrapper["name"] == "guardian_triage_types" and wrapper["type"] == "json" and wrapper["version"] == -1
    data = json.loads(wrapper["data"])
    assert data["severities"] == ["low", "medium", "high", "critical"] and data["_comment"]


def test_the_six_types_and_other():
    by_name = {t["name"]: t for t in _taxonomy()["types"]}
    assert list(by_name) == ["phishing", "identity_threat", "endpoint_threat", "network_threat", "data_exposure", "vulnerability", "other"]
    assert by_name["data_exposure"]["domains"] == ["detection", "posture"] and by_name["vulnerability"]["domains"] == ["posture"]
    for name in ("phishing", "identity_threat", "endpoint_threat", "network_threat"):
        assert by_name[name]["domains"] == ["detection"]
    assert by_name["other"]["sub_playbook"] == "GuardianTriageOther" and by_name["other"]["skill"] == ""
    for name, row in by_name.items():
        if name != "other":
            assert row["sub_playbook"] == "GuardianTriage" + "".join(p.capitalize() for p in name.split("_"))


def test_every_row_names_a_shipped_enabled_skill():
    index = {e["name"]: e for e in json.loads(_list_data("guardian_skills_index"))}
    for row in _taxonomy()["types"]:
        assert set(row) == {"name", "description", "domains", "sub_playbook", "skill"}
        assert row["description"] and "\n" not in row["description"] and len(row["description"]) <= 120
        if row["name"] != "other":
            assert index[row["skill"]]["enabled"] is True, row["name"]


def test_the_built_in_fallback_table_equals_the_list():
    data = _taxonomy()
    assert _common_constant("GUARDIAN_TRIAGE_DEFAULT_TYPES") == data["types"]
    assert list(_common_constant("GUARDIAN_TRIAGE_SEVERITIES")) == data["severities"]


def test_the_triage_skill_is_indexed_enabled_and_names_exactly_the_lists_types():
    index = {e["name"]: e for e in json.loads(_list_data("guardian_skills_index"))}
    assert index["xsoar_triage"]["enabled"] is True and index["xsoar_triage"]["category"] == "workflows"
    body = _skill_body()
    assert body.startswith("---\nname: xsoar_triage\n")
    section = body.split("## Types", 1)[1].split("\n## ", 1)[0]
    lines = [l for l in section.splitlines() if l.startswith("- `")]
    assert lines == ["- `{}` ({}): {}".format(t["name"], " or ".join(t["domains"]), t["description"]) for t in _taxonomy()["types"]]


def test_the_skill_states_the_block_with_the_validators_entity_lists():
    body = _skill_body()
    block = re.search(r"```json\n(.*?)\n```", body, re.DOTALL).group(1)
    for key in ("severity", "investigation_type", "confidence", "likely_benign", "escalate", "summary", "key_entities", "next_step"):
        assert '"{}"'.format(key) in block, key
    entity_keys = _common_constant("GUARDIAN_TRIAGE_ENTITY_KEYS")
    assert set(re.findall(r'"([a-z]+)": \[\]', block)) == set(entity_keys)
    assert "low|medium|high|critical" in block and "nothing after it" in body
    assert "Happened is not the same as authorised" in body and "GuardianTriage" not in body
    assert "Do not write a case note or a memory row" in body
    assert "`escalate` is `true` only when a person must act within hours" in body
    assert ("attempt that was blocked or failed, with no sign it succeeded (for example a blocked phishing email or a denied "
            "sign-in), does not escalate on its own") in " ".join(body.split())
    # the evidence sections it names are the ones GuardianIncidentEvidence writes
    for section in ("`incident_fields`", "`indicators`", "`related_open`", "`prior_closed`", "`memory`"):
        assert section in body


def test_the_prompt_tail_says_triage_replaces_the_verdict_block_note_and_memory_row():
    tail = json.loads(_list_data("guardian_prompt_tail"))["tail"]
    assert "starts with `TRIAGE RUN:`" in tail and "replaces the verdict block, the case note and the memory row" in tail
    tick = (SCRIPTS / "GuardianReasoningTick" / "GuardianReasoningTick.py").read_text()
    assert '"\\n\\nTRIAGE RUN: ' in tick


# --- the routing table -----------------------------------------------------------------------------------------------

def _routes():
    return json.loads(_list_data("guardian_incident_routes"))


def test_the_routes_list_is_well_formed_and_every_skill_is_shipped():
    data = _routes()
    index = {e["name"] for e in json.loads(_list_data("guardian_skills_index"))}
    allowed_keys = {"type", "source", "category", "type_contains", "name_contains", "label_contains"}
    for row in data["routes"] + [data["default"]]:
        assert row["family"] and row["domain"] in ("detection", "posture") and row["assessment_mode"] in ("verdict", "none")
        if row.get("run_model") is False or row["assessment_mode"] == "none":
            assert row["skill"] == "" and row["evidence_plan"] == []
        else:
            assert row["skill"] in index and row["evidence_plan"]
        assert set(row.get("match") or {}) <= allowed_keys
        for step in row["evidence_plan"]:
            assert step in ("incident", "indicators", "related", "prior_closed", "memory")
    assert data["default"]["domain"] == "detection" and "match" not in data["default"]


def test_guardians_own_incidents_never_get_a_triage_session():
    names = [json.loads(p.read_text())["name"] for p in (PACK / "IncidentTypes").glob("*.json")]
    first = _routes()["routes"][0]
    assert first["run_model"] is False and set(first["match"]["type"]) == set(names)


def test_every_route_family_that_runs_a_model_has_a_type_with_its_domain():
    domains = {d for t in _taxonomy()["types"] if t["name"] != "other" for d in t["domains"]}
    for row in _routes()["routes"]:
        if row.get("run_model") is not False:
            assert row["domain"] in domains, row["id"]


# --- guards on the scripts -------------------------------------------------------------------------------------------

def test_apply_and_result_are_denylisted_and_not_allowlisted():
    for name in ("GuardianTriageApply", "GuardianTriageResult", "GuardianIncidentSummary", "GuardianModelChoice", "GuardianLookup"):
        assert name in _denied() and name not in _allowed()
    for name in ("GuardianIncidentRoute", "GuardianIncidentEvidence", "GuardianRunCapture"):
        assert name not in _allowed()  # harness steps, never model tools
    assert "setIncident" not in _allowed()


@pytest.mark.parametrize("name", ["GuardianIncidentRoute", "GuardianIncidentEvidence", "GuardianRunCapture", "GuardianTriageResult",
                                  "GuardianTriageApply", "GuardianIncidentSummary", "GuardianModelChoice",
                                  "GuardianIncidentDuplicateCheck", "GuardianLookup",
                                  "GuardianHealthCheck"])
def test_the_new_scripts_are_well_formed(name):
    folder = SCRIPTS / name
    doc = yaml.safe_load((folder / (name + ".yml")).read_text())
    assert doc["commonfields"]["id"] == name and doc["name"] == name
    assert doc["marketplaces"] == ["xsoar"] and doc["subtype"] == "python3" and doc["system"] is False
    assert doc["dockerimage"].startswith("demisto/python3:") and doc["fromversion"] == "6.10.0"
    source = (folder / (name + ".py")).read_text()
    assert source.count("# <GUARDIAN_COMMON_INJECT>") == 1 and source.count("# </GUARDIAN_COMMON>") == 1
    assert (folder / (name + "_test.py")).exists()
    for word in ("core-", "XQL", "Cortex platform issue", "marketplacev2"):
        assert word not in source.split("# </GUARDIAN_COMMON_INJECT>")[1], (name, word)


def test_apply_writes_only_severity_and_phase_through_set_incident():
    source = (SCRIPTS / "GuardianTriageApply" / "GuardianTriageApply.py").read_text()
    assert 'GUARDIAN_TRIAGE_APPLY_UPDATE_COMMAND = "setIncident"' in source
    assert source.count("GUARDIAN_TRIAGE_APPLY_UPDATE_COMMAND, update_args") == 1
    assert re.findall(r'update_args = \{(.*?)\}', source) == ['"id": incident_id, "phase": phase']
    assert 'update_args["severity"] = new_severity' in source


def test_the_tick_declares_the_triage_arguments_and_outputs():
    doc = yaml.safe_load((SCRIPTS / "GuardianReasoningTick" / "GuardianReasoningTick.yml").read_text())
    args = {a["name"]: a for a in doc["args"]}
    assert set(args["assessment_mode"]["predefined"]) == {"verdict", "triage"}
    assert args["max_ticks"]["required"] is False and set(args["continue_run_totals"]["predefined"]) == {"true", "false"}
    outputs = {o["contextPath"] for o in doc["outputs"]}
    assert {"Guardian.Loop.conclusion", "Guardian.Loop.triage_block", "Guardian.Loop.assessment_mode"} <= outputs


def test_the_result_yml_documents_every_triage_key_and_input():
    doc = yaml.safe_load((SCRIPTS / "GuardianTriageResult" / "GuardianTriageResult.yml").read_text())
    paths = {o["contextPath"]: o for o in doc["outputs"]}
    contract = {"status", "branch", "investigation_type", "severity", "original_severity", "confidence", "likely_benign", "escalate",
                "summary", "next_step", "domain", "assessment_mode", "sub_playbook", "skill", "reason", "inputs"}
    assert {"Guardian.Triage." + k for k in contract} <= set(paths)
    described = paths["Guardian.Triage.inputs"]["description"]
    for name in ("identity", "ip", "host", "hash", "sha256", "cve", "domain", "url", "email", "rule_id"):
        assert name in described, name


# --- the playbooks ---------------------------------------------------------------------------------------------------

def _playbook(name):
    return yaml.safe_load((PLAYBOOKS / "playbook-{}.yml".format(name)).read_text())


def _sub_names():
    return [t["sub_playbook"] for t in _taxonomy()["types"]]


def _all_triage_names():
    return [PARENT] + _sub_names()


def _tasks(doc, kind=None):
    return [t for t in doc["tasks"].values() if kind is None or t["type"] == kind]


def _arg(task, name):
    return ((task.get("scriptarguments") or {}).get(name) or {}).get("simple")


def _script(task):
    return str((task.get("task") or {}).get("script") or "")


def _command_of(task):
    """The script of a task; for a `GuardianLookup` task the lookup it runs (its `command` argument)."""
    script = _script(task).replace("|||", "")
    return (_arg(task, "command") or "") if script == LOOKUP_SCRIPT else script


def _pack_scripts():
    return {p.name for p in SCRIPTS.iterdir() if p.is_dir()}


def _flow_order(doc):
    """Task keys in a valid execution order (a topological order; every triage playbook is acyclic)."""
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


def _guards_of(doc, key):
    """The input paths a task sits behind: every condition reached on the way back where the path left by `yes`."""
    pred = {}
    for k, task in doc["tasks"].items():
        for label, targets in (task.get("nexttasks") or {}).items():
            for target in targets:
                pred.setdefault(target, []).append((k, label))
    found, seen, stack = set(), set(), [key]
    while stack:
        current = stack.pop()
        for parent, label in pred.get(current, []):
            task = doc["tasks"][parent]
            if task["type"] == "condition" and label == "yes":
                found.add(task["conditions"][0]["condition"][0][0]["left"]["value"]["simple"])
                continue
            if parent not in seen:
                seen.add(parent)
                stack.append(parent)
    return found


def _lookups(doc):
    return [(k, t) for k, t in doc["tasks"].items() if t["type"] == "regular" and _command_of(t) in COMMAND_CONTEXT]


def test_every_triage_playbook_exists_and_is_well_formed():
    for name in _all_triage_names():
        doc = _playbook(name)
        text = (PLAYBOOKS / "playbook-{}.yml".format(name)).read_text()
        assert doc["id"] == doc["name"] == name and doc["version"] == -1
        assert doc["fromversion"] == "6.10.0" and doc["marketplaces"] == ["xsoar"] and "adopted" not in doc
        assert doc["description"] and str(doc["starttaskid"]) in doc["tasks"]
        assert "\t" not in text and "view: |-" in text and 'continueonerrortype: ""' not in text
        ids = set(doc["tasks"])
        for key, task in doc["tasks"].items():
            assert task["id"] == key and task["task"]["id"] == task["taskid"] and task["task"]["description"] is not None
            for targets in (task.get("nexttasks") or {}).values():
                assert set(targets) <= ids, (name, key)
            assert json.loads(task["view"])["position"]["x"] is not None
            if task.get("continueonerror"):
                assert task["continueonerrortype"] == "continue", (name, key)
        assert json.loads(doc["view"])["paper"]["dimensions"]
        assert len({t["taskid"] for t in doc["tasks"].values()}) == len(doc["tasks"])
        _flow_order(doc)


def test_the_parent_has_one_branch_per_type_pointing_at_that_types_sub_playbook():
    doc = _playbook(PARENT)
    branch = [t for t in _tasks(doc, "condition") if t["task"]["name"] == "Which type?"]
    assert len(branch) == 1
    branch = branch[0]
    types = _taxonomy()["types"]
    assert [c["label"] for c in branch["conditions"]] == [t["name"] for t in types]
    for row in types:
        rule = [c for c in branch["conditions"] if c["label"] == row["name"]][0]["condition"][0][0]
        assert rule["operator"] == "isEqualString" and rule["left"]["value"]["simple"] == "Guardian.Triage.branch"
        assert rule["right"]["value"]["simple"] == row["name"]
        target = doc["tasks"][branch["nexttasks"][row["name"]][0]]
        assert target["type"] == "playbook" and target["task"]["playbookName"] == row["sub_playbook"]
    assert [doc["tasks"][t]["task"]["playbookName"] for t in branch["nexttasks"]["#default#"]] == ["GuardianTriageOther"]
    assert sorted(t["task"]["playbookName"] for t in _tasks(doc, "playbook")) == sorted(_sub_names())
    for sub in _tasks(doc, "playbook"):
        assert sub["separatecontext"] is False
        # the investigation model choice folds investigate_max_ticks into the effective limit, so every branch reads one value
        assert _arg(sub, "max_ticks") == "${Guardian.ModelChoiceCurrent.max_ticks}"


def test_every_command_a_triage_playbook_uses_exists_and_is_written_the_right_way():
    scripts = _pack_scripts()
    for name in _all_triage_names():
        for task in _tasks(_playbook(name), "regular"):
            command, script = _command_of(task), _script(task)
            assert not script.startswith("|||") and "skipunavailable" not in task, (name, script)
            assert command not in LOOKUP_COMMANDS or script == LOOKUP_SCRIPT, (name, command)
            assert task["task"]["iscommand"] is False, (name, command)
            if script == LOOKUP_SCRIPT:
                assert command in LOOKUP_COMMANDS and task.get("continueonerror") is True, (name, command)
            else:
                assert script in scripts or script in CONTENT_SCRIPTS, (name, script)


def test_no_type_playbook_runs_a_generic_command_or_a_content_lookup_directly():
    for name in _sub_names():
        text = (PLAYBOOKS / "playbook-{}.yml".format(name)).read_text()
        assert "|||" not in text and "skipunavailable" not in text, name
        for task in _tasks(_playbook(name), "regular"):
            assert _script(task) not in LOOKUP_COMMANDS and _script(task).replace("|||", "") not in LOOKUP_COMMANDS, (name, _script(task))


def test_every_lookup_task_runs_guardian_lookup_with_an_allowed_command_and_the_verified_argument_names():
    for name in _sub_names():
        for key, task in _tasks_with_keys(_playbook(name)):
            if _script(task) != LOOKUP_SCRIPT:
                continue
            command, args = _arg(task, "command"), set((task.get("scriptarguments") or {})) - {"command"}
            assert command in LOOKUP_COMMANDS, (name, key, command)
            assert args in LOOKUP_COMMANDS[command], (name, key, command, args)
            assert task["task"]["iscommand"] is False and task["continueonerror"] is True and "skipunavailable" not in task
            assert "trimevents" not in args  # fails on XSOAR
        for _key, task in _lookups(_playbook(name)):
            if _command_of(task) == "SearchIncidentsV2":
                assert set(task["scriptarguments"]) == {"query", "limit"}


def _tasks_with_keys(doc):
    return [(k, t) for k, t in doc["tasks"].items() if t["type"] == "regular"]


def test_guardian_lookup_is_denylisted_never_allowlisted_and_only_the_type_playbooks_run_it():
    assert LOOKUP_SCRIPT in _denied() and LOOKUP_SCRIPT not in _allowed()
    for name in _all_triage_names():
        runs = [t for t in _tasks(_playbook(name), "regular") if _script(t) == LOOKUP_SCRIPT]
        assert bool(runs) == (name in _sub_names() and name != "GuardianTriageOther"), name


def test_no_triage_playbook_uses_a_write_command():
    policy = {k for k in json.loads(_list_data("guardian_policy")) if not k.startswith("_")}
    denied = _denied()
    for name in _all_triage_names():
        for task in _tasks(_playbook(name), "regular"):
            command, script = _command_of(task), _script(task)
            assert command not in policy and script not in policy, (name, command)
            if script == LOOKUP_SCRIPT:
                assert name in _sub_names() and script in denied, (name, script)
            elif script in denied:
                assert name == PARENT and script in ("GuardianTriageResult", "GuardianTriageApply", "GuardianIncidentSummary",
                                                      "GuardianModelChoice", "GuardianIncidentDuplicateCheck",
                                                      "GuardianReportBuild"), (name, command)
            for blocked in ("setincident", "setlist", "addtolist", "closeinvestigation", "isolate", "quarantine", "block", "delete"):
                assert blocked not in command.lower() or command == "DeleteContext", (name, command)


def test_apply_and_result_are_run_once_and_only_by_the_parent():
    commands = {n: [_command_of(t) for t in _tasks(_playbook(n), "regular")] for n in _all_triage_names()}
    assert commands[PARENT].count("GuardianTriageApply") == 1 and commands[PARENT].count("GuardianTriageResult") == 1
    for name in _sub_names():
        assert "GuardianTriageApply" not in commands[name] and "GuardianTriageResult" not in commands[name]


def test_every_lookup_is_guarded_by_its_input_and_continues_on_error():
    for name in _sub_names():
        if name == "GuardianTriageOther":
            continue
        doc = _playbook(name)
        lookups = _lookups(doc)
        assert lookups, name
        for key, task in lookups:
            assert task["continueonerror"] is True, (name, key)
            refs = {m for v in task["scriptarguments"].values() for m in re.findall(r"Guardian\.Triage\.inputs\.[a-z_0-9]+", v["simple"])}
            guards = _guards_of(doc, key)
            assert refs and refs <= guards, (name, key, refs, guards)
        for task in _tasks(doc, "condition"):
            assert set(task["nexttasks"]) == {"yes", "#default#"}
            rule = task["conditions"][0]
            assert rule["label"] == "yes" and rule["condition"][0][0]["operator"] == "isNotEmpty"


def test_each_sub_playbook_appends_exactly_what_it_fetches_and_clears_only_its_search():
    for name in _sub_names():
        if name == "GuardianTriageOther":
            continue
        doc = _playbook(name)
        tasks = _tasks(doc, "regular")
        appends = [t for t in tasks if _command_of(t) == "GuardianIncidentEvidence"]
        assert len(appends) == 1 and _arg(appends[0], "mode") == "append"
        written = []
        for _k, task in _lookups(doc):
            for path in COMMAND_CONTEXT[_command_of(task)]:
                if path not in written:
                    written.append(path)
        paths = _arg(appends[0], "paths").split(",")
        assert paths == written, (name, paths, written)
        clears = [t for t in tasks if _command_of(t) == "DeleteContext" and _arg(t, "key") != "Guardian.Loop"]
        # shared enrichment keys (IP, Endpoint ...) belong to the incident and are never deleted; only the transient search
        assert [_arg(t, "key") for t in clears] == (["foundIncidents"] if "foundIncidents" in paths else []), name
        order = _flow_order(doc)
        fetches = [k for k, _ in _lookups(doc)]
        append_key = [k for k, t in doc["tasks"].items() if t is appends[0]][0]
        assert order.index(append_key) > max(order.index(k) for k in fetches)
        if clears:
            clear_key = [k for k, t in doc["tasks"].items() if t is clears[0]][0]
            assert order.index(clear_key) < min(order.index(k) for k in fetches)


def test_the_searches_by_entity_only_use_shape_checked_inputs():
    """A search query is built from a triage input inside double quotes: only inputs the validator shape-checks (an IP
    that parses, an email address) may go there, so no value can close the quote."""
    for name in _sub_names():
        for _k, task in _lookups(_playbook(name)):
            if _command_of(task) == "SearchIncidentsV2":
                used = set(re.findall(r"Guardian\.Triage\.inputs\.([a-z_]+)", _arg(task, "query")))
                assert used and used <= {"ip", "email"}, (name, used)
                assert re.fullmatch(r'([a-z]+:"\$\{Guardian\.Triage\.inputs\.[a-z]+\}"( or )?)+', _arg(task, "query"))


def test_plan_enrichment_per_type():
    expected = {
        "GuardianTriagePhishing": {"url", "domain", "file", "SearchIncidentsV2"},
        "GuardianTriageIdentityThreat": {"GetUserData", "ip", "SearchIncidentsV2"},
        "GuardianTriageEndpointThreat": {"endpoint", "GetEndpointData", "file", "ip"},
        "GuardianTriageNetworkThreat": {"ip", "endpoint", "SearchIncidentsV2", "domain", "url"},
        "GuardianTriageDataExposure": {"GetUserData", "endpoint", "domain", "url"},
        "GuardianTriageVulnerability": {"cve", "endpoint", "GetEndpointData"},
    }
    for name, wanted in expected.items():
        assert {_command_of(t) for _k, t in _lookups(_playbook(name))} == wanted, name


def test_every_model_sub_playbook_runs_an_investigation_after_appending_clearing_loop_and_loading_its_skill():
    for name in _sub_names():
        if name == "GuardianTriageOther":
            continue
        doc = _playbook(name)
        by_command = {}
        for k, t in doc["tasks"].items():
            if t["type"] == "regular":
                by_command.setdefault(_command_of(t), []).append(k)
        assert len(by_command["GuardianReasoningTick"]) == 1
        tick = doc["tasks"][by_command["GuardianReasoningTick"][0]]
        assert _arg(tick, "skill") == "${Guardian.Triage.skill}" and _arg(tick, "assessment_mode") == "${Guardian.Triage.assessment_mode}"
        assert _arg(tick, "use_prebuilt") == "true" and _arg(tick, "scope_to_incident") == "true"
        assert _arg(tick, "max_ticks") == "${inputs.max_ticks}" and _arg(tick, "prompt") == "${inputs.prompt}"
        assert _arg(tick, "continue_run_totals") == "true"
        inputs = {i["key"]: i["value"]["simple"] for i in doc["inputs"]}
        assert inputs["max_ticks"] == ""
        prompt = inputs["prompt"]
        for phrase in ("${Guardian.Triage.investigation_type}", "${Guardian.Triage.severity}", "GuardianCaseNote", "op=store",
                       "Do NOT change anything", "no setIncident", "was skipped, not failed", "that is unknown, not clean",
                       "Keep the case note under 2500 characters. Notes over 4000 are rejected"):
            assert phrase in prompt, (name, phrase)
        assert prompt.index("READ THE EVIDENCE PACKET") < prompt.index("DOCUMENT") < prompt.index("REMEMBER") < prompt.index("END with")
        used = sorted(set(re.findall(r"Guardian\.Triage\.inputs\.([a-z_0-9]+)", json.dumps(doc["tasks"]))))
        line = re.search(r"The triage inputs this playbook used:[^\n]*", prompt).group(0)
        assert sorted(re.findall(r"\$\{Guardian\.Triage\.inputs\.([a-z_0-9]+)\}", line)) == used, name
        order = _flow_order(doc)
        loop_clear = [k for k in by_command["DeleteContext"] if _arg(doc["tasks"][k], "key") == "Guardian.Loop"]
        assert len(loop_clear) == 1 and _arg(doc["tasks"][by_command["GuardianSkillRead"][0]], "name") == "${Guardian.Triage.skill}"
        assert (order.index(by_command["GuardianIncidentEvidence"][0]) < order.index(loop_clear[0])
                < order.index(by_command["GuardianSkillRead"][0]) < order.index(by_command["GuardianReasoningTick"][0])
                < order.index(by_command["GuardianRunCapture"][0]))
        assert "GuardianCaseNote" not in by_command


def test_the_case_note_limit_in_the_prompts_matches_the_tool():
    source = (SCRIPTS / "GuardianCaseNote" / "GuardianCaseNote.py").read_text()
    assert re.search(r"^GUARDIAN_CASE_NOTE_MAX_CONTENT_LEN = 4000$", source, re.MULTILINE)


def test_the_other_branch_runs_a_full_investigation_on_the_route_skill_with_no_analyst_only_stop():
    doc = _playbook("GuardianTriageOther")
    order = _flow_order(doc)
    regular = [doc["tasks"][k] for k in order if doc["tasks"][k]["type"] == "regular"]
    assert [_command_of(t) for t in regular] == ["DeleteContext", "GuardianSkillRead", "GuardianReasoningTick", "GuardianRunCapture"]
    assert [t["task"]["name"] for t in regular] == ["Clear the triage session state", "Load the skill", "Run the investigation session",
                                                    "Remember the outcome"]
    clear, load, tick, capture = regular
    assert _arg(clear, "key") == "Guardian.Loop" and _arg(clear, "subplaybook") == "no"
    assert _arg(load, "name") == "${Guardian.Route.skill}" and _arg(load, "summary_only") == "true"
    assert {k: _arg(tick, k) for k in tick["scriptarguments"]} == {
        "prompt": "${inputs.prompt}", "skill": "${Guardian.Route.skill}", "use_prebuilt": "true", "scope_to_incident": "true",
        "assessment_mode": "${Guardian.Route.assessment_mode}", "max_ticks": "${inputs.max_ticks}", "continue_run_totals": "true"}
    assert "GuardianCaseNote" not in [_command_of(t) for t in _tasks(doc, "regular")]  # no analyst-only stop any more
    assert [doc["tasks"][k]["task"]["name"] for k in order] == ["", "Clear the triage session state", "Load the skill",
                                                                 "Run the investigation session", "Remember the outcome", "Done"]
    inputs = {i["key"]: i for i in doc["inputs"]}
    assert set(inputs) == {"prompt", "max_ticks"} and inputs["max_ticks"]["value"]["simple"] == ""
    assert "Empty (the default)" in " ".join(inputs["max_ticks"]["description"].split())
    prompt = inputs["prompt"]["value"]["simple"]
    assert "${incident.id}" in prompt and "did not place it in a type" in prompt and "${Guardian.Triage.reason}" in prompt
    assert "GuardianTriage" not in prompt and "core-" not in prompt
    # the route the Other branch reads never hands the tick an empty skill or the mode `none`: a route that runs a model
    # always names a skill and the verdict mode (Other is reached only when the route runs a model)
    routes = _routes()
    for row in routes["routes"] + [routes["default"]]:
        if row.get("run_model") is not False:
            assert row["skill"] and row["assessment_mode"] == "verdict", row["id"]


def test_the_parent_flow_runs_the_preparation_then_triage_then_apply_then_the_branch():
    doc = _playbook(PARENT)
    by_command = {}
    for key, task in doc["tasks"].items():
        if task["type"] == "regular":
            by_command.setdefault(_command_of(task), []).append(key)
    order = _flow_order(doc)

    def at(command, index=0):
        return order.index(by_command[command][index])

    assert at("GuardianKillSwitchCheck", 0) < at("GuardianJobGuardCheck") < at("GuardianIncidentRoute") < at("GuardianModelChoice")
    assert at("GuardianModelChoice") < at("GuardianModelProfileCheck")
    assert at("GuardianModelProfileCheck") < at("GuardianIncidentEvidence") < at("GuardianPromptBuilder") < at("GuardianToolCatalogBuilder")
    assert at("GuardianToolCatalogBuilder") < at("GuardianSkillRead") < at("DeleteContext", 0) < at("GuardianReasoningTick")
    assert at("GuardianReasoningTick") < at("GuardianTriageResult") < at("DeleteContext", 1) < at("GuardianKillSwitchCheck", 1)
    assert at("GuardianKillSwitchCheck", 1) < at("GuardianTriageApply")
    branch = [k for k, t in doc["tasks"].items() if t["task"]["name"] == "Which type?"][0]
    assert at("GuardianTriageApply") < order.index(branch)
    assert {_arg(doc["tasks"][k], "key") for k in by_command["DeleteContext"]} == {"Guardian.Loop,Guardian.Triage", "Guardian.Preflight.KillSwitch"}
    assert not any("Guardian.TriageApply" in _arg(doc["tasks"][k], "key") for k in by_command["DeleteContext"])
    second = [k for k, t in doc["tasks"].items() if t["task"]["name"] == "Kill switch on now?"][0]
    assert doc["tasks"][second]["nexttasks"]["#default#"] == by_command["GuardianTriageApply"]
    assert doc["tasks"][doc["tasks"][second]["nexttasks"]["halted"][0]]["type"] == "title"
    tick = doc["tasks"][by_command["GuardianReasoningTick"][0]]
    assert _arg(tick, "assessment_mode") == "triage" and _arg(tick, "skill") == "xsoar_triage"
    assert _arg(tick, "max_ticks") == "${inputs.triage_max_ticks}" and _arg(tick, "continue_run_totals") is None
    assert _arg(doc["tasks"][by_command["GuardianSkillRead"][0]], "name") == "xsoar_triage"
    assert _arg(doc["tasks"][by_command["GuardianTriageApply"][0]], "apply_changes") == "${inputs.apply_changes}"
    note = _arg(doc["tasks"][by_command["GuardianCaseNote"][0]], "content")
    assert "${Guardian.Route.family}" in note and "Guardian.Route.reason" not in note


def test_the_parent_inputs_and_prompt():
    inputs = {i["key"]: i for i in _playbook(PARENT)["inputs"]}
    assert set(inputs) == {"prompt", "apply_changes", "triage_max_ticks", "investigate_max_ticks", "check_duplicates", "close_duplicates"}
    assert inputs["check_duplicates"]["value"]["simple"] == "true" and inputs["close_duplicates"]["value"]["simple"] == "false"
    assert inputs["apply_changes"]["value"]["simple"] == "true" and inputs["triage_max_ticks"]["value"]["simple"] == "6"
    assert inputs["investigate_max_ticks"]["value"]["simple"] == ""
    assert "Empty (the default)" in " ".join(inputs["investigate_max_ticks"]["description"].split())
    prompt = inputs["prompt"]["value"]["simple"]
    for phrase in ("THIS XSOAR incident", "pinned above", "at most a few lookups", "Do NOT write a case note",
                   "do NOT store a memory row", "EXACTLY the triage block", "`other`", "${incident.id}", "analysis", "recommendations",
                   "complexity (low, medium or high"):
        assert phrase in prompt, phrase
    assert "GuardianTriage" not in prompt and "core-" not in prompt


# --- triage and investigation in one playbook: summaries, model routing, the investigation rules ---------------------

def _predecessors(doc):
    pred = {}
    for key, task in doc["tasks"].items():
        for label, targets in (task.get("nexttasks") or {}).items():
            for target in targets:
                pred.setdefault(target, []).append((key, label))
    return pred


def _flat(text):
    return " ".join(str(text).split())


def test_the_old_parent_name_is_gone():
    assert not (PLAYBOOKS / "playbook-GuardianTriageIncident.yml").exists()
    for path in list(PLAYBOOKS.glob("*.yml")) + list(LISTS.glob("*.json")) + list(SCRIPTS.glob("*/*.yml")):
        assert "GuardianTriageIncident" not in path.read_text(), path.name


def test_the_parent_writes_the_triage_summary_after_apply_and_the_conclusion_before_done():
    doc = _playbook(PARENT)
    tasks = doc["tasks"]
    summaries = {_arg(t, "stage"): key for key, t in tasks.items() if t["type"] == "regular" and _command_of(t) == "GuardianIncidentSummary"}
    assert set(summaries) == {"triage", "investigation"}
    by_name = {t["task"]["name"]: key for key, t in tasks.items()}
    assert tasks[summaries["triage"]]["task"]["name"] == "Write the triage summary"
    assert tasks[summaries["investigation"]]["task"]["name"] == "Write the investigation conclusion"
    apply_key = [k for k, t in tasks.items() if t["type"] == "regular" and _command_of(t) == "GuardianTriageApply"][0]
    assert tasks[apply_key]["nexttasks"]["#none#"] == [summaries["triage"]]
    chain = ["Choose the investigation model", "Resolve the investigation model profile", "Gather evidence for the investigation model",
             "Build the investigation system prompt", "Build the investigation tool list", "Which type?"]
    assert tasks[summaries["triage"]]["nexttasks"]["#none#"] == [by_name[chain[0]]]
    for here, there in zip(chain, chain[1:]):
        assert tasks[by_name[here]]["nexttasks"]["#none#"] == [by_name[there]], here
    done, report = by_name["Done"], by_name["Build the Guardian report"]
    assert tasks[summaries["investigation"]]["nexttasks"]["#none#"] == [report]
    assert tasks[report]["nexttasks"]["#none#"] == [done]
    for branch in _tasks(doc, "playbook"):
        assert branch["nexttasks"]["#none#"] == [summaries["investigation"]], branch["task"]["name"]
    for key in summaries.values():
        task = tasks[key]
        assert _arg(task, "apply_changes") == "${inputs.apply_changes}" and task["continueonerror"] is True
        assert task["separatecontext"] is False and task["task"]["description"]
    pred = _predecessors(doc)
    assert {p for p, _l in pred[summaries["triage"]]} == {apply_key}
    assert {p for p, _l in pred[summaries["investigation"]]} == {k for k, t in tasks.items() if t["type"] == "playbook"}
    assert {p for p, _l in pred[report]} == {summaries["investigation"]}
    assert {p for p, _l in pred[done]} == {report, by_name["Note - no model session needed"],
                                           by_name["Note - duplicate of an open incident"]}
    for title in [t for t in tasks.values() if t["type"] == "title" and t["task"]["name"].startswith("Halted")]:
        assert not title.get("nexttasks")


def test_the_parent_chooses_the_triage_model_before_resolving_the_profile_and_the_investigation_model_after_the_summary():
    doc = _playbook(PARENT)
    tasks = doc["tasks"]
    by_name = {t["task"]["name"]: key for key, t in tasks.items()}
    choose_triage, resolve = tasks[by_name["Choose the triage model"]], tasks[by_name["Resolve model profile"]]
    assert _command_of(choose_triage) == "GuardianModelChoice" and _arg(choose_triage, "stage") == "triage"
    # the model path goes through the duplicate check first (see the duplicate check tests below), then chooses the model
    assert tasks[by_name["Needs a model session?"]]["nexttasks"]["#default#"] == [by_name["Duplicate check on?"]]
    assert tasks[by_name["Duplicate check on?"]]["nexttasks"]["#default#"] == [by_name["Choose the triage model"]]
    assert tasks[by_name["Duplicate of an open incident?"]]["nexttasks"]["#default#"] == [by_name["Choose the triage model"]]
    assert choose_triage["nexttasks"]["#none#"] == [by_name["Resolve model profile"]]
    assert _arg(resolve, "model") == "${Guardian.ModelChoiceCurrent.model}"
    invest = tasks[by_name["Choose the investigation model"]]
    assert _command_of(invest) == "GuardianModelChoice" and _arg(invest, "stage") == "investigation"
    assert _arg(invest, "investigate_max_ticks") == "${inputs.investigate_max_ticks}"
    second = tasks[by_name["Resolve the investigation model profile"]]
    assert _command_of(second) == "GuardianModelProfileCheck" and _arg(second, "model") == "${Guardian.ModelChoiceCurrent.model}"
    for first, again in (("Build system prompt", "Build the investigation system prompt"), ("Build tool list", "Build the investigation tool list")):
        a, b = tasks[by_name[first]], tasks[by_name[again]]
        assert _command_of(a) == _command_of(b) and a["scriptarguments"] == b["scriptarguments"], again


def test_the_evidence_is_gathered_again_for_the_investigation_model_with_the_same_arguments():
    doc = _playbook(PARENT)
    tasks = doc["tasks"]
    by_name = {t["task"]["name"]: key for key, t in tasks.items()}
    gathers = [k for k, t in tasks.items() if t["type"] == "regular" and _command_of(t) == "GuardianIncidentEvidence"]
    assert sorted(tasks[k]["task"]["name"] for k in gathers) == ["Gather evidence", "Gather evidence for the investigation model"]
    first, again = tasks[by_name["Gather evidence"]], tasks[by_name["Gather evidence for the investigation model"]]
    assert (first.get("scriptarguments") or {}) == (again.get("scriptarguments") or {}) and _arg(again, "mode") is None
    assert tasks[by_name["Resolve the investigation model profile"]]["nexttasks"]["#none#"] == [by_name["Gather evidence for the investigation model"]]
    assert again["continueonerror"] is True and again["continueonerrortype"] == "continue"
    order = _flow_order(doc)
    assert order.index(by_name["Resolve the investigation model profile"]) < order.index(by_name["Gather evidence for the investigation model"])
    assert order.index(by_name["Gather evidence for the investigation model"]) < order.index(by_name["Which type?"])
    # nothing in the parent appends to the packet, so the re-gather loses no enrichment; the branches append afterwards
    assert not [t for t in tasks.values() if t["type"] == "regular" and _command_of(t) == "GuardianIncidentEvidence" and _arg(t, "mode") == "append"]


def test_every_model_routing_task_fails_open():
    doc = _playbook(PARENT)
    new = ["Choose the triage model", "Choose the investigation model", "Resolve the investigation model profile",
           "Gather evidence for the investigation model", "Build the investigation system prompt", "Build the investigation tool list",
           "Write the triage summary", "Write the investigation conclusion"]
    by_name = {t["task"]["name"]: t for t in doc["tasks"].values()}
    for name in new:
        task = by_name[name]
        assert task["continueonerror"] is True and task["continueonerrortype"] == "continue" and task["task"]["description"], name


def test_every_task_has_a_view_and_no_two_tasks_share_a_position():
    for name in _all_triage_names():
        doc = _playbook(name)
        positions = [tuple(json.loads(t["view"])["position"].values()) for t in doc["tasks"].values()]
        assert len(positions) == len(set(positions)), name
        paper = json.loads(doc["view"])["paper"]["dimensions"]
        for x, y in positions:
            assert paper["x"] <= x <= paper["x"] + paper["width"] and paper["y"] <= y <= paper["y"] + paper["height"], (name, x, y)


def _branch_rules(name):
    prompt = {i["key"]: i["value"]["simple"] for i in _playbook(name)["inputs"]}["prompt"]
    text = _flat(prompt)
    start = text.index("2) FOLLOW THE ACTIVE SKILL")
    return text[start:]


def test_every_branch_prompt_carries_the_same_judging_memory_and_calibration_rules():
    rules = _branch_rules("GuardianTriagePhishing")
    assert len(rules) > 2500
    for name in _sub_names():
        assert _branch_rules(name) == rules, name
    for phrase in ("3) Judge the incident as a claim to check", "is a coverage gap, never an empty result",
                   "A memory row is an earlier conclusion, often Guardian's own", "prior_closed; a close as a false positive is evidence",
                   "answer Suspicious with confidence 65 or lower, not Malicious", "Benign at 70 or more needs evidence that it was expected",
                   "are context, not corroboration", "Never write that something was validated, verified or confirmed",
                   "7) DECIDE. Do NOT change anything: no setIncident, no closeInvestigation, no containment", "8) END with EXACTLY the verdict block"):
        assert phrase in rules, phrase
    # the calibration in the branch prompt agrees with the one every system prompt carries
    tail = json.loads(_list_data("guardian_prompt_tail"))["tail"]
    assert "Suspicious with confidence 65 or lower" in tail and "context, not corroboration" in tail
    for name in _sub_names():
        text = _flat({i["key"]: i["value"]["simple"] for i in _playbook(name)["inputs"]}["prompt"])
        assert text.index("READ THE EVIDENCE PACKET") < text.index("Judge the incident") < text.index("If a memory row") \
            < text.index("DOCUMENT") < text.index("REMEMBER") < text.index("DECIDE") < text.index("END with"), name
        assert "digest" not in text.lower() and "posture" not in text.lower(), name


def test_the_branch_session_task_is_called_the_investigation_session_everywhere():
    for name in _sub_names():
        doc = _playbook(name)
        names = [t["task"]["name"] for t in _tasks(doc, "regular")]
        assert "Run the investigation session" in names and "Run the focused model session" not in names, name
        assert "focused" not in (PLAYBOOKS / "playbook-{}.yml".format(name)).read_text(), name
    assert "focused" not in (PLAYBOOKS / "playbook-{}.yml".format(PARENT)).read_text()


def test_every_investigation_session_continues_the_run_totals_and_the_triage_session_does_not():
    for name in _sub_names():
        ticks = [t for t in _tasks(_playbook(name), "regular") if _command_of(t) == "GuardianReasoningTick"]
        assert len(ticks) == 1 and _arg(ticks[0], "continue_run_totals") == "true", name
    parent_tick = [t for t in _tasks(_playbook(PARENT), "regular") if _command_of(t) == "GuardianReasoningTick"]
    assert len(parent_tick) == 1 and _arg(parent_tick[0], "continue_run_totals") is None
    agent_loop = _playbook("GuardianAgentLoop")
    assert all(_arg(t, "continue_run_totals") is None for t in _tasks(agent_loop, "regular"))


def test_the_agent_run_playbook_is_unrouted():
    doc = _playbook("GuardianAgentLoop")
    checks = [t for t in _tasks(doc, "regular") if _command_of(t) == "GuardianModelProfileCheck"]
    assert len(checks) == 1 and _arg(checks[0], "model") is None  # resolved for the configured model, never routed
    assert not [t for t in _tasks(doc, "regular") if _command_of(t) == "GuardianModelChoice"]


def test_the_triage_skill_and_the_tick_ask_for_the_optional_analysis_recommendations_and_complexity():
    skill = _skill_body()
    conclude = skill.split("## Conclude", 1)[1]
    assert '"analysis"' in conclude and '"recommendations"' in conclude and "optional" in conclude and "800" in conclude
    assert '"complexity"' in conclude and "## Complexity" in conclude
    rubric = skill.split("## Complexity", 1)[1]
    for level in ("`low`", "`medium`", "`high`"):
        assert level in rubric
    assert "single-source fact" in rubric and "correlation across a few sources" in rubric and "possible compromise" in rubric
    for name in ("phishing", "identity_threat", "endpoint_threat", "network_threat", "data_exposure", "vulnerability"):
        assert "`{}`".format(name) in skill  # the XSOAR types are kept
    schema = (SCRIPTS / "GuardianReasoningTick" / "GuardianReasoningTick.py").read_text()
    assert '"analysis": "optional' in schema and '"recommendations": ["optional' in schema and '"complexity": "optional' in schema
    doc = yaml.safe_load((SCRIPTS / "GuardianTriageResult" / "GuardianTriageResult.yml").read_text())
    paths = {o["contextPath"] for o in doc["outputs"]}
    assert {"Guardian.Triage.analysis", "Guardian.Triage.recommendations", "Guardian.Triage.complexity"} <= paths
    index = {e["name"]: e for e in json.loads(_list_data("guardian_skills_index"))}
    assert "analysis, recommendations and complexity" in index["xsoar_triage"]["description"]
    for name in ("GUARDIAN_TRIAGE_ANALYSIS_MAX_CHARS", "GUARDIAN_TRIAGE_RECOMMENDATIONS_MAX_ITEMS", "GUARDIAN_TRIAGE_COMPLEXITIES"):
        _common_constant(name)


def test_the_model_choice_is_operator_owned_and_the_routing_list_is_protected():
    assert "GuardianModelChoice" in _denied() and "GuardianModelChoice" not in _allowed()
    assert "GuardianModelChoice" not in _list_data("guardian_policy") and "GuardianModelChoice" not in _list_data("guardian_preapproved")
    denylist = json.loads(_list_data("guardian_tool_denylist"))
    assert "guardian_model_routing" in denylist["protected_lists"]


def test_the_routing_list_ships_empty_so_every_run_behaves_as_before():
    wrapper = json.loads((LISTS / "list-guardian_model_routing.json").read_text())
    assert set(wrapper) == {"id", "version", "name", "description", "data", "type", "fromVersion"}
    assert wrapper["id"] == wrapper["name"] == "guardian_model_routing" and wrapper["type"] == "json" and wrapper["version"] == -1
    data = json.loads(wrapper["data"])
    assert data["triage"] == "" and set(data["complexity"]) == {"low", "medium", "high"}
    assert all(entry.get("model", "") == "" and "max_ticks" not in entry for entry in data["complexity"].values())
    assert "max_ticks" in data["_comment"] and "read-only once installed" in data["_comment"] and "issue" not in data["_comment"]


def test_the_model_choice_and_the_profile_check_document_the_routing_arguments():
    choice = yaml.safe_load((SCRIPTS / "GuardianModelChoice" / "GuardianModelChoice.yml").read_text())
    assert {a["name"] for a in choice["args"]} == {"stage", "investigate_max_ticks"}
    check = yaml.safe_load((SCRIPTS / "GuardianModelProfileCheck" / "GuardianModelProfileCheck.yml").read_text())
    assert [a["name"] for a in check["args"]] == ["read_only", "model"]   # read_only: resolve without saving (the health check)
    paths = {o["contextPath"] for o in check["outputs"]}
    assert {"Guardian.Preflight.ModelProfile.model", "Guardian.Preflight.ModelProfile.routed"} <= paths


def test_the_incident_summary_writes_only_the_details_through_the_shared_rest_helper():
    source = (SCRIPTS / "GuardianIncidentSummary" / "GuardianIncidentSummary.py").read_text().split("# </GUARDIAN_COMMON_INJECT>")[1]
    assert "guardian_set_incident_fields(incident_id, {}, details=build)" in source
    assert source.count("guardian_set_incident_fields(") == 1 and "setIncident" not in source and "core-" not in source
    common = (SCRIPTS / "GuardianCommon" / "GuardianCommon.py").read_text()
    assert 'GUARDIAN_ISSUE_SECTION_MARKER = "--- Guardian (automated) ---"' in common


def test_guardian_strips_its_own_details_section_from_everything_it_reads_back():
    for name, needle in (("GuardianIncidentEvidence", "guardian_strip_issue_section(value)"),
                         ("GuardianReasoningTick", 'guardian_strip_issue_section(inc.get("details") or "")'),
                         ("GuardianToolBridge", "guardian_strip_issue_section_deep(guardian_bridge_extract_contents(entries))"),
                         ("GuardianEvalHarvest", 'guardian_strip_issue_section(incident.get("details") or "")')):
        source = (SCRIPTS / name / (name + ".py")).read_text().split("# </GUARDIAN_COMMON_INJECT>")[1]
        assert needle in source, name


# --- duplicate check ---------------------------------------------------------------------------------------------------------

def test_the_duplicate_check_is_operator_owned_denylisted_and_never_a_tool():
    assert "GuardianIncidentDuplicateCheck" in _denied() and "GuardianIncidentDuplicateCheck" not in _allowed()
    for name in ("guardian_policy", "guardian_preapproved"):
        assert "GuardianIncidentDuplicateCheck" not in _list_data(name), name
    assert not [c for c in _allowed() if "Duplicate" in c]


def test_the_duplicate_check_changes_only_the_incident_it_runs_on_through_one_native_call():
    source = (SCRIPTS / "GuardianIncidentDuplicateCheck" / "GuardianIncidentDuplicateCheck.py").read_text()
    code = source.split("# </GUARDIAN_COMMON_INJECT>")[1]
    assert code.count("guardian_execute(GUARDIAN_DUP_CLOSE_COMMAND, {") == 1
    assert re.findall(r'guardian_execute\(GUARDIAN_DUP_CLOSE_COMMAND, \{\s*(.*?)\}\)', code, re.S) == [
        '"incidentId": original, "linkedIncidentIDs": incident_id, "action": GUARDIAN_DUP_CLOSE_ACTION']
    assert 'GUARDIAN_DUP_CLOSE_COMMAND = "linkIncidents"' in code and 'GUARDIAN_DUP_CLOSE_ACTION = "duplicate"' in code
    assert 'GUARDIAN_DUP_SEARCH_COMMAND = "getIncidents"' in code
    assert "closeInvestigation" not in code and "setIncident" not in code
    assert "return_error" not in code.split("def main():", 1)[1]  # fail open: never an error entry


def test_the_duplicate_check_yml_documents_its_arguments_and_every_output():
    doc = yaml.safe_load((SCRIPTS / "GuardianIncidentDuplicateCheck" / "GuardianIncidentDuplicateCheck.yml").read_text())
    args = {a["name"]: a for a in doc["args"]}
    assert set(args) == {"max_candidates", "close_duplicates"} and not any(a["required"] for a in args.values())
    assert args["close_duplicates"]["predefined"] == ["true", "false"]
    assert {o["contextPath"] for o in doc["outputs"]} == {"Guardian.Duplicate." + k for k in (
        "incident_id", "is_duplicate", "original_id", "matching_open_ids", "open_in_group", "incident_type", "incident_name",
        "fingerprint", "reason", "proposed_exclusion", "proposed_exclusion_text", "closed", "close_error")}


def test_the_duplicate_check_sits_on_the_model_path_only_between_the_route_and_the_model_choice():
    doc = _playbook(PARENT)
    tasks = doc["tasks"]
    by_name = {t["task"]["name"]: key for key, t in tasks.items()}
    gate, check = tasks[by_name["Duplicate check on?"]], tasks[by_name["Check for duplicates"]]
    decide, note = tasks[by_name["Duplicate of an open incident?"]], tasks[by_name["Note - duplicate of an open incident"]]
    # only the model branch of "Needs a model session?" reaches it; the no-model note path is untouched
    needs = tasks[by_name["Needs a model session?"]]
    assert needs["nexttasks"] == {"#default#": [by_name["Duplicate check on?"]], "nomodel": [by_name["Note - no model session needed"]]}
    assert [k for k, t in tasks.items() if by_name["Duplicate check on?"] in sum(t.get("nexttasks", {}).values(), [])] == [by_name["Needs a model session?"]]
    # the gate reads the input and, when it is not "true", skips straight to the model choice
    rule = gate["conditions"][0]["condition"][0][0]
    assert gate["type"] == "condition" and rule["operator"] == "isEqualString" and rule["ignorecase"] is True
    assert rule["left"]["value"]["simple"] == "inputs.check_duplicates" and rule["left"]["iscontext"] is True
    assert rule["right"]["value"]["simple"] == "true"
    assert gate["nexttasks"] == {"#default#": [by_name["Choose the triage model"]], gate["conditions"][0]["label"]: [by_name["Check for duplicates"]]}
    # the check passes the input, continues on error and leads to the decision
    assert _command_of(check) == "GuardianIncidentDuplicateCheck" and _arg(check, "close_duplicates") == "${inputs.close_duplicates}"
    assert check["continueonerror"] is True and check["continueonerrortype"] == "continue" and check["nexttasks"]["#none#"] == [by_name["Duplicate of an open incident?"]]
    # the decision: only an affirmative "true" ends the model path; everything else (no result, "false") continues
    rule = decide["conditions"][0]["condition"][0][0]
    assert rule["left"]["value"]["simple"] == "Guardian.Duplicate.is_duplicate" and rule["right"]["value"]["simple"] == "true"
    assert decide["nexttasks"] == {"#default#": [by_name["Choose the triage model"]], decide["conditions"][0]["label"]: [by_name["Note - duplicate of an open incident"]]}
    # the note says which incident, how many are open, the proposed exclusion, that no model ran, and ends the playbook
    assert _command_of(note) == "GuardianCaseNote" and note["nexttasks"]["#none#"] == [by_name["Done"]]
    assert note["continueonerror"] is True and note["continueonerrortype"] == "continue"
    text = " ".join(_arg(note, "content").split())
    for needle in ("did not run a model session", "${Guardian.Duplicate.original_id}", "${Guardian.Duplicate.open_in_group}",
                   "${Guardian.Duplicate.proposed_exclusion_text}", "nothing was applied"):
        assert needle in text, needle
    assert "${Guardian.Duplicate.reason}" not in text  # the reason repeats what the note already says
    # nothing downstream of the duplicate branch runs a model, applies a triage or writes the investigation conclusion
    order = _flow_order(doc)
    assert order.index(by_name["Duplicate check on?"]) < order.index(by_name["Choose the triage model"])
    for name in ("Duplicate check on?", "Check for duplicates", "Duplicate of an open incident?", "Note - duplicate of an open incident"):
        assert by_name[name] in order and tasks[by_name[name]]["task"]["description"]


def test_the_duplicate_check_inputs_are_described_and_the_new_tasks_keep_existing_views():
    doc = _playbook(PARENT)
    inputs = {i["key"]: i for i in doc["inputs"]}
    for key in ("check_duplicates", "close_duplicates"):
        assert inputs[key]["required"] is False and len(" ".join(inputs[key]["description"].split())) > 80
    positions = {k: json.loads(t["view"])["position"] for k, t in doc["tasks"].items()}
    assert len({(p["x"], p["y"]) for p in positions.values()}) == len(positions)  # no two tasks share a place
    for k in ("43", "44", "45", "46"):  # no new task sits within a card's width and height of another task
        p = positions[k]
        for other, q in positions.items():
            if other != k:
                assert abs(p["x"] - q["x"]) >= 200 or abs(p["y"] - q["y"]) >= 140, (k, other)
    assert positions["6"] == {"x": 450, "y": 920} and positions["7"] == {"x": 450, "y": 1065} and positions["37"] == {"x": 800, "y": 1065}


def test_the_health_check_is_operator_owned_denylisted_and_never_a_tool():
    assert "GuardianHealthCheck" in _denied() and "GuardianHealthCheck" not in _allowed()
    for name in ("guardian_policy", "guardian_preapproved"):
        assert "GuardianHealthCheck" not in _list_data(name), name
    assert not [c for c in _allowed() if "HealthCheck" in c]
    for path in PLAYBOOKS.glob("*.yml"):
        assert "GuardianHealthCheck" not in path.read_text(), path.name   # an operator runs it; no playbook does
