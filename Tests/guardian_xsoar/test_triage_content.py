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
PARENT = "GuardianTriageIncident"

#: Generic reputation and lookup commands every XSOAR 6 server knows by name (each enabled integration that implements
#: one answers it); `|||` runs it across brands. Argument names verified against demisto/content integration ymls.
GENERIC_COMMANDS = {"ip": "ip", "domain": "domain", "url": "url", "file": "file", "endpoint": None, "cve": "cve_id"}
#: Scripts from Cortex XSOAR content (Common Scripts, Aggregated Scripts) and built-ins the playbooks may run.
CONTENT_SCRIPTS = {"DeleteContext", "SearchIncidentsV2", "GetUserData", "GetEndpointData"}
#: Content scripts that may be missing on a server (a pack that is not installed): their tasks skip when unavailable.
OPTIONAL_SCRIPTS = {"GetUserData", "GetEndpointData"}
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
    for name in ("GuardianTriageApply", "GuardianTriageResult"):
        assert name in _denied() and name not in _allowed()
    for name in ("GuardianIncidentRoute", "GuardianIncidentEvidence", "GuardianRunCapture"):
        assert name not in _allowed()  # harness steps, never model tools
    assert "setIncident" not in _allowed()


@pytest.mark.parametrize("name", ["GuardianIncidentRoute", "GuardianIncidentEvidence", "GuardianRunCapture", "GuardianTriageResult",
                                  "GuardianTriageApply"])
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
    return _script(task).replace("|||", "")


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
        if sub["task"]["playbookName"] != "GuardianTriageOther":
            assert _arg(sub, "max_ticks") == "${inputs.investigate_max_ticks}"


def test_every_command_a_triage_playbook_uses_exists_and_is_written_the_right_way():
    scripts = _pack_scripts()
    for name in _all_triage_names():
        for task in _tasks(_playbook(name), "regular"):
            command, script = _command_of(task), _script(task)
            if script.startswith("|||"):
                assert command in GENERIC_COMMANDS and task["task"]["iscommand"] is True, (name, command)
            else:
                assert command in scripts or command in CONTENT_SCRIPTS, (name, command)
                assert task["task"]["iscommand"] is False, (name, command)
            if command in OPTIONAL_SCRIPTS:
                assert task.get("skipunavailable") is True and task.get("continueonerror") is True, (name, command)


def test_the_lookups_use_the_verified_argument_names():
    for name in _sub_names():
        for _key, task in _lookups(_playbook(name)):
            command, args = _command_of(task), set((task.get("scriptarguments") or {}))
            expected = {"ip": [{"ip"}], "domain": [{"domain"}], "url": [{"url"}], "file": [{"file"}],
                        "endpoint": [{"hostname"}, {"ip"}], "cve": [{"cve_id"}], "GetUserData": [{"user_name"}],
                        "GetEndpointData": [{"endpoint_hostname"}], "SearchIncidentsV2": [{"query", "limit"}]}[command]
            assert args in expected, (name, command, args)
            assert "trimevents" not in args  # fails on XSOAR


def test_no_triage_playbook_uses_a_write_command():
    policy = {k for k in json.loads(_list_data("guardian_policy")) if not k.startswith("_")}
    denied = _denied()
    for name in _all_triage_names():
        for task in _tasks(_playbook(name), "regular"):
            command = _command_of(task)
            assert command not in policy, (name, command)
            if command in denied:
                assert name == PARENT and command in ("GuardianTriageResult", "GuardianTriageApply"), (name, command)
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


def test_every_model_sub_playbook_runs_a_focused_session_after_appending_clearing_loop_and_loading_its_skill():
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


def test_the_other_branch_has_no_model_session_and_writes_one_note():
    doc = _playbook("GuardianTriageOther")
    assert [_command_of(t) for t in _tasks(doc, "regular")] == ["GuardianCaseNote"]
    note = _arg(_tasks(doc, "regular")[0], "content")
    assert "needs an analyst" in note and "${Guardian.Triage.reason}" in note and "${Guardian.Triage.summary}" not in note
    assert doc["inputs"] == []


def test_the_parent_flow_runs_the_preparation_then_triage_then_apply_then_the_branch():
    doc = _playbook(PARENT)
    by_command = {}
    for key, task in doc["tasks"].items():
        if task["type"] == "regular":
            by_command.setdefault(_command_of(task), []).append(key)
    order = _flow_order(doc)

    def at(command, index=0):
        return order.index(by_command[command][index])

    assert at("GuardianKillSwitchCheck", 0) < at("GuardianJobGuardCheck") < at("GuardianIncidentRoute") < at("GuardianModelProfileCheck")
    assert at("GuardianModelProfileCheck") < at("GuardianIncidentEvidence") < at("GuardianPromptBuilder") < at("GuardianToolCatalogBuilder")
    assert at("GuardianToolCatalogBuilder") < at("GuardianSkillRead") < at("DeleteContext", 0) < at("GuardianReasoningTick")
    assert at("GuardianReasoningTick") < at("GuardianTriageResult") < at("DeleteContext", 1) < at("GuardianKillSwitchCheck", 1)
    assert at("GuardianKillSwitchCheck", 1) < at("GuardianTriageApply")
    branch = [k for k, t in doc["tasks"].items() if t["task"]["name"] == "Which type?"][0]
    assert at("GuardianTriageApply") < order.index(branch)
    assert {_arg(doc["tasks"][k], "key") for k in by_command["DeleteContext"]} == {"Guardian.Loop,Guardian.Triage", "Guardian.Preflight.KillSwitch"}
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
    assert set(inputs) == {"prompt", "apply_changes", "triage_max_ticks", "investigate_max_ticks"}
    assert inputs["apply_changes"]["value"]["simple"] == "true" and inputs["triage_max_ticks"]["value"]["simple"] == "6"
    assert inputs["investigate_max_ticks"]["value"]["simple"] == ""
    assert "Empty (the default)" in " ".join(inputs["investigate_max_ticks"]["description"].split())
    prompt = inputs["prompt"]["value"]["simple"]
    for phrase in ("THIS XSOAR incident", "pinned above", "at most a few lookups", "Do NOT write a case note",
                   "do NOT store a memory row", "EXACTLY the triage block", "`other`", "${incident.id}"):
        assert phrase in prompt, phrase
    assert "GuardianTriage" not in prompt and "core-" not in prompt
