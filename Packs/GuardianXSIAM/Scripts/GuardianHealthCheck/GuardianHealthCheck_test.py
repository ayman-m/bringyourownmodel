import ast
import copy
import glob
import json
import re
from pathlib import Path

import pytest
import yaml

import GuardianHealthCheck as hc

PACK = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).with_name("GuardianHealthCheck.py")
EDITION = "cortex"
INCIDENT = {"id": "77", "name": "Suspicious sign-in", "type": "Suspicious sign-in"}

# Commands that would change something. The health check must never execute one, whatever the scenario.
WRITE_COMMANDS = {
    "setList", "createList", "addToList", "deleteList", "setIncident", "setPlaybook", "closeInvestigation", "createNewIncident",
    "GuardianToolRegistryRefresh", "GuardianKillSwitchToggle", "GuardianJobsCreate", "GuardianJobsUpdate", "GuardianJobsDelete",
    "GuardianApprovalResolve", "GuardianDeny", "GuardianButtonApprove", "GuardianButtonDeny", "GuardianButtonPause",
    "GuardianButtonResume", "GuardianSkillsCRUD", "GuardianMemory", "GuardianBootstrap", "GuardianSeedContent", "GuardianAuditWrite",
    "GuardianTriageApply", "GuardianIncidentSummary", "GuardianContainmentSimulate", "GuardianProbeModel", "GuardianModelProfileUpdate",
    "demisto-api-put", "core-api-put", "demisto-api-delete", "core-api-delete", "demisto-api-multipart", "core-api-multipart",
}


# --- a fake tenant -------------------------------------------------------------------------------------------------------------

def _shipped_lists():
    lists = {}
    for path in glob.glob(str(PACK / "Lists" / "list-*.json")):
        item = json.load(open(path))
        lists[item["name"]] = item["data"]
    return lists


class Tenant:
    """A tenant that answers every command the health check may run, from the pack's own files. Every call is recorded."""

    def __init__(self):
        self.calls = []
        self.lists = _shipped_lists()
        self.lists["guardian_kill_switch"] = json.dumps({"enabled": False})
        self.lists["guardian_memory"] = "[]"
        self.runtime_list_names = ["guardian_kill_switch", "guardian_memory", "guardian_audit", "guardian_model_profile"]
        self.scripts = list(hc.GUARDIAN_HC_SCRIPTS)
        self.playbooks = list(hc.GUARDIAN_HC_PLAYBOOKS)
        self.fields = list(hc.GUARDIAN_HC_FIELDS)
        self.types = list(hc.GUARDIAN_HC_TYPES)
        self.layouts = list(hc.GUARDIAN_HC_LAYOUTS)
        self.list_names = None
        self.post_errors = {}
        self.get_errors = {}
        self.post_override = {}
        self.get_override = {}
        self.instances = [
            {"name": "lab-model", "brand": "GuardianFoundry", "enabled": "true", "data": [{"name": "model", "value": "gpt-5-mini"}]},
            {"name": "rest", "brand": "Core REST API", "enabled": "true"},
        ]
        self.health = {"lab-model": {"instance": "lab-model", "lastError": ""}}
        self.served_models = {"gpt-5-mini", "gemini-2.5-pro", "gpt-5"}
        self.llm_text = "OK"
        self.llm_reply_model = "gpt-5-mini"
        self.llm_error = None
        self.llm_usage = {"prompt_tokens": 20, "completion_tokens": 2}
        self.llm_calls = []
        self.script_errors = {}
        self.script_contents = {}
        self.profile = {"tier": "large", "tier_source": "catalogue (gpt-5-mini)", "max_input_tokens": 200000, "max_tool_def_tokens": 24000,
                        "model": "gpt-5-mini", "mismatch": False, "warning": None, "warnings": []}
        self.bridge_status = {}
        self.jobs = {name: "disabled" for name in getattr(hc, "GUARDIAN_HC_JOBS", ())}
        self.job_rows = None
        self.xql_error = None
        self.supported = {"lab-model": [{"name": "guardian-llm-chat"}], "xql": [{"name": "xdr-xql-generic-query"}]}

    # -- helpers
    def names(self, command):
        return [c for c, _a in self.calls if c == command]

    def args_of(self, command):
        return [a for c, a in self.calls if c == command]

    def search_response(self):
        configurations = [{"name": n, "display": d, "integrationScript": {"commands": [{"name": "guardian-llm-chat"}]}}
                          for n, d in hc.GUARDIAN_HC_INTEGRATIONS]
        return {"instances": self.instances, "configurations": configurations, "health": self.health}

    def post(self, uri, body):
        if uri in self.post_errors:
            return [{"Type": 4, "Contents": self.post_errors[uri]}]
        if uri in self.post_override:
            return [{"Type": 1, "Contents": {"response": self.post_override[uri]}}]
        if uri == "/settings/integration/search":
            response = self.search_response()
        elif uri == "/automation/search":
            response = {"scripts": [{"id": n, "name": n} for n in self.scripts], "total": len(self.scripts)}
        elif uri == "/playbook/search":
            response = {"playbooks": [{"id": n, "name": n} for n in self.playbooks], "total": len(self.playbooks)}
        elif uri == "/jobs/search":
            rows = self.job_rows if self.job_rows is not None else [{"name": n, "schedulingStatus": s} for n, s in self.jobs.items()]
            response = {"data": rows, "total": len(rows)}
        else:
            raise AssertionError("unexpected post " + uri)
        return [{"Type": 1, "Contents": {"response": response}}]

    def get(self, uri):
        if uri in self.get_errors:
            return [{"Type": 4, "Contents": self.get_errors[uri]}]
        if uri in self.get_override:
            return [{"Type": 1, "Contents": {"response": self.get_override[uri]}}]
        if uri == "/lists/names":
            names = self.list_names if self.list_names is not None else sorted(set(self.lists) | set(self.runtime_list_names))
            response = names
        elif uri == "/incidentfields":
            response = [{"cliName": n, "id": "incident_" + n} for n in self.fields] + [{"cliName": "severity", "id": "incident_severity"}]
        elif uri == "/incidenttypes/export":
            response = [{"id": n, "name": n} for n in self.types] + [{"id": "Phishing", "name": "Phishing"}]
        elif uri == "/layouts":
            response = [{"id": n} for n in self.layouts]
        else:
            raise AssertionError("unexpected get " + uri)
        return [{"Type": 1, "Contents": {"response": response}}]

    def entry(self, contents, context=None):
        out = {"Type": 1, "Contents": contents}
        if context:
            out["EntryContext"] = context
        return [out]

    def __call__(self, command, args):
        self.calls.append((command, args))
        if command in ("demisto-api-post", "core-api-post"):
            return self.post(args["uri"], json.loads(args["body"]) if isinstance(args.get("body"), str) else args.get("body"))
        if command in ("demisto-api-get", "core-api-get"):
            return self.get(args["uri"])
        if command == "getList":
            name = args["listName"]
            if name not in self.lists:
                return [{"Type": 4, "Contents": "Item not found (8)"}]
            return [{"Type": 1, "Contents": self.lists[name]}]
        if command in self.script_errors:
            return [{"Type": 4, "Contents": self.script_errors[command]}]
        if command in self.script_contents:
            return self.entry(self.script_contents[command])
        if command == "guardian-llm-chat":
            self.llm_calls.append(args)
            if self.llm_error:
                return [{"Type": 4, "Contents": self.llm_error}]
            model = args.get("model")
            if model and model not in self.served_models:
                return [{"Type": 4, "Contents": "MODEL_NOT_AVAILABLE: no deployment named {}".format(model)}]
            return self.entry({"model": model or self.llm_reply_model, "choices": [{"message": {"role": "assistant", "content": self.llm_text},
                                                                          "finish_reason": "stop"}], "usage": self.llm_usage,
                               "content_filter": False})
        if command == "GuardianModelProfileCheck":
            return self.entry(self.profile)
        if command == "GuardianKillSwitchCheck":
            return self.entry({"halted": False, "proceed": "true", "reason": "kill switch is off"})
        if command == "GuardianJobGuardCheck":
            return self.entry({"job_name": None, "proceed": "true", "halted": False, "reason": "not started by a scheduled Job"})
        if command == "GuardianToolBridge":
            name = args["tool_name"]
            status = self.bridge_status.get(name)
            if status is None:
                status = "ok" if name == "GuardianSkillRead" else "denied"
            ok = status == "ok"
            return self.entry({"tool_result": {"tool_name": name, "status": status, "ok": ok, "result": {"x": 1} if ok else None,
                                               "error": None if ok else "'{}' is on the bare guardian_tool_denylist".format(name)}})
        if command == "GuardianXQL":
            if args.get("template") == "list":
                return self.entry({"templates": [{"name": "t"}]})
            if self.xql_error:
                return self.entry({"error": self.xql_error})
            return self.entry({"rows": [{"a": 1}], "query_cost": 0.001})
        if command in (hc.GUARDIAN_HC_ROUTE_SCRIPT, hc.GUARDIAN_HC_DUPLICATE_SCRIPT, "GuardianSkillRead", "GuardianPromptBuilder",
                       "GuardianModelChoice"):
            return self.entry({"ok": True})
        raise AssertionError("unexpected command {} {}".format(command, args))


@pytest.fixture
def tenant(monkeypatch):
    t = Tenant()
    monkeypatch.setattr(hc.demisto, "executeCommand", t)
    monkeypatch.setattr(hc.demisto, "error", lambda msg: None)
    monkeypatch.setattr(hc.demisto, "incident", lambda: {})
    monkeypatch.setattr(hc.demisto, "context", lambda: {})
    monkeypatch.setattr(hc.demisto, "getAllSupportedCommands", lambda: t.supported, raising=False)
    return t


def run(args=None):
    results, state = hc.guardian_hc_run_all(args or {})
    return results, state


def by_name(results):
    return {r["name"]: r for r in results}


def statuses(results, status):
    return [r["name"] for r in results if r["status"] == status]


def make_problem_keys_known(results):
    for r in results:
        if r["status"] in ("WARN", "FAIL"):
            assert r["problem"] in hc.GUARDIAN_HC_PROBLEMS, r


# --- the manifest follows the pack ----------------------------------------------------------------------------------------------

def test_the_manifest_names_exactly_what_the_pack_ships():
    # the name the server knows is the yml `name` (the slash-command automations are named guardian-*, in a GuardianXxx folder)
    scripts = sorted(yaml.safe_load(open(f))["name"] for f in glob.glob(str(PACK / "Scripts" / "*" / "*.yml")))
    assert list(hc.GUARDIAN_HC_SCRIPTS) == scripts
    assert {"guardian-approve", "guardian-probe-model", "guardian-killswitch"} <= set(scripts) and "GuardianApprovalResolve" not in scripts
    playbooks = sorted(yaml.safe_load(open(f))["name"] for f in glob.glob(str(PACK / "Playbooks" / "playbook-*.yml")))
    assert list(hc.GUARDIAN_HC_PLAYBOOKS) == playbooks
    kinds = {"json": [], "markdown": []}
    for f in sorted(glob.glob(str(PACK / "Lists" / "list-*.json"))):
        item = json.load(open(f))
        kinds[item["type"]].append(item["name"])
    assert list(hc.GUARDIAN_HC_JSON_LISTS) == kinds["json"] and list(hc.GUARDIAN_HC_MARKDOWN_LISTS) == kinds["markdown"]
    assert list(hc.GUARDIAN_HC_FIELDS) == sorted(json.load(open(f))["cliName"] for f in glob.glob(str(PACK / "IncidentFields" / "*.json")))
    assert list(hc.GUARDIAN_HC_TYPES) == sorted(json.load(open(f))["id"] for f in glob.glob(str(PACK / "IncidentTypes" / "*.json")))
    assert list(hc.GUARDIAN_HC_LAYOUTS) == sorted(json.load(open(f))["id"] for f in glob.glob(str(PACK / "Layouts" / "*.json")))
    integrations = sorted((yaml.safe_load(open(f))["name"], yaml.safe_load(open(f))["display"])
                          for f in glob.glob(str(PACK / "Integrations" / "*" / "*.yml")))
    assert list(hc.GUARDIAN_HC_INTEGRATIONS) == integrations


def test_the_manifest_counts_follow_the_pack_directories():
    assert len(hc.GUARDIAN_HC_SCRIPTS) == len(glob.glob(str(PACK / "Scripts" / "*" / "*.yml")))
    assert len(hc.GUARDIAN_HC_PLAYBOOKS) == len(glob.glob(str(PACK / "Playbooks" / "*.yml")))
    assert len(hc.GUARDIAN_HC_JSON_LISTS) + len(hc.GUARDIAN_HC_MARKDOWN_LISTS) == len(glob.glob(str(PACK / "Lists" / "*.json")))
    assert "GuardianHealthCheck" in hc.GUARDIAN_HC_SCRIPTS


def test_the_health_check_is_operator_owned_denylisted_and_never_a_tool():
    deny = json.loads(json.loads((PACK / "Lists" / "list-guardian_tool_denylist.json").read_text())["data"])
    allow = json.loads(json.loads((PACK / "Lists" / "list-guardian_tool_allowlist.json").read_text())["data"])
    assert "GuardianHealthCheck" in deny["denied"] and "GuardianHealthCheck" not in allow["commands"]
    for name in ("guardian_policy", "guardian_preapproved"):
        assert "GuardianHealthCheck" not in json.loads((PACK / "Lists" / "list-{}.json".format(name)).read_text())["data"]
    # the command the bridge probe asks for is on the shipped denylist, and is not on the allowlist
    assert hc.GUARDIAN_HC_DENY_PROBE in deny["denied"] and hc.GUARDIAN_HC_DENY_PROBE not in allow["commands"]
    assert "GuardianSkillRead" in allow["commands"]


def test_the_yml_documents_the_arguments_and_the_summary():
    doc = yaml.safe_load(SCRIPT.with_suffix(".yml").read_text())
    args = {a["name"]: a for a in doc["args"]}
    assert set(args) == {"test_model", "test_routing", "test_bridge", "include_xql", "max_model_calls", "verbose"}
    assert not any(a["required"] for a in args.values())
    assert args["test_model"]["defaultValue"] == "true" and args["test_routing"]["defaultValue"] == "true"
    assert args["test_bridge"]["defaultValue"] == "true" and args["verbose"]["defaultValue"] == "false"
    assert args["max_model_calls"]["defaultValue"] == "4"
    assert args["include_xql"]["defaultValue"] == "false"
    assert {o["contextPath"] for o in doc["outputs"]} == {"Guardian.HealthCheck." + k for k in (
        "status", "pass", "warn", "fail", "skip", "failed", "warned", "ts", "edition", "seconds", "model_calls", "model_cost_usd")}
    assert doc["marketplaces"] == ["marketplacev2"] and doc["fromversion"] == "6.10.0" and doc["subtype"] == "python3"
    assert doc["dockerimage"].startswith("demisto/python3:") and doc["system"] is False and doc["commonfields"]["id"] == "GuardianHealthCheck"
    source = SCRIPT.read_text()
    assert source.count("# <GUARDIAN_COMMON_INJECT>") == 1 and source.count("# </GUARDIAN_COMMON>") == 1


def test_the_edition_keeps_to_its_own_platform():
    code = own_code()[2]
    for word in ("GUARDIAN_HC_JOBS", "/jobs/search", "GuardianIncident", "marketplaces: [xsoar]"):
        assert word not in code, word
    assert "xdr-xql-generic-query" in code


MANIFEST_NAMES = {"GUARDIAN_HC_SCRIPTS", "GUARDIAN_HC_PLAYBOOKS", "GUARDIAN_HC_JSON_LISTS", "GUARDIAN_HC_MARKDOWN_LISTS", "GUARDIAN_HC_FIELDS",
                  "GUARDIAN_HC_TYPES", "GUARDIAN_HC_LAYOUTS", "GUARDIAN_HC_JOBS", "GUARDIAN_HC_INTEGRATIONS"}


def own_code():
    """The health check's own code: after the shared block, without the manifest (which names every script of the pack)."""
    tree = ast.parse(SCRIPT.read_text().split("# </GUARDIAN_COMMON_INJECT>")[1])
    kept = [node for node in tree.body if not (isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") in MANIFEST_NAMES)]
    return tree, kept, "\n".join(ast.unparse(node) for node in kept)


# --- the never-do list -----------------------------------------------------------------------------------------------------------

def test_the_source_never_names_a_write_command():
    _tree, kept, code = own_code()
    strings = {node.value for part in kept for node in ast.walk(part) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
    for command in WRITE_COMMANDS:
        assert command not in strings, command
    for word in ("setList", "createList", "addToList", "deleteList", "ToolRegistryRefresh", "KillSwitchToggle", "setIncident",
                 "closeInvestigation", "runPlaybook", "ApprovalResolve", "GuardianDeny", "ButtonApprove"):
        assert word not in code, word


def test_the_command_set_is_exactly_the_read_only_one():
    expected = {"getList", "guardian-llm-chat", "GuardianToolBridge", "GuardianModelProfileCheck", "GuardianKillSwitchCheck",
                "GuardianJobGuardCheck", "GuardianSkillRead", "GuardianPromptBuilder", "GuardianModelChoice",
                hc.GUARDIAN_HC_ROUTE_SCRIPT, hc.GUARDIAN_HC_DUPLICATE_SCRIPT, "GuardianXQL"}
    rest = {c for c in hc.GUARDIAN_HC_COMMANDS if c.endswith("-post") or c.endswith("-get")}
    assert hc.GUARDIAN_HC_COMMANDS - rest == expected
    assert rest == {"demisto-api-post", "demisto-api-get", "core-api-post", "core-api-get"}
    assert not hc.GUARDIAN_HC_COMMANDS & WRITE_COMMANDS
    assert hc.GUARDIAN_HC_REST_GET_URIS == {"/lists/names", "/incidentfields", "/incidenttypes/export", "/layouts"}
    assert hc.GUARDIAN_HC_REST_POST_URIS == {"/settings/integration/search", "/automation/search", "/playbook/search"}
    assert all(uri.endswith("/search") for uri in hc.GUARDIAN_HC_REST_POST_URIS)


def test_a_command_or_uri_outside_the_sets_is_refused(tenant):
    for command in ("setList", "GuardianKillSwitchToggle", "GuardianToolRegistryRefresh", "createList"):
        with pytest.raises(ValueError):
            hc.guardian_hc_run(command, {})
    with pytest.raises(ValueError):
        hc.guardian_hc_rest_post("/lists/save", {})
    with pytest.raises(ValueError):
        hc.guardian_hc_rest_get("/users")
    assert tenant.calls == []


@pytest.mark.parametrize("args", [{}, {"verbose": "true"}, {"max_model_calls": "6"}, {"test_bridge": "false", "test_routing": "false"},
                                  {"test_model": "false"}, {"include_xql": "true"}])
@pytest.mark.parametrize("inside", [False, True])
def test_no_scenario_executes_a_write_command(tenant, monkeypatch, args, inside):
    if inside:
        monkeypatch.setattr(hc.demisto, "incident", lambda: dict(INCIDENT))
    tenant.lists["guardian_model_routing"] = json.dumps({"triage": "gemini-2.5-pro", "complexity": {"low": {"model": "gpt-5"}}})
    run(args)
    executed = {c for c, _a in tenant.calls}
    assert not executed & WRITE_COMMANDS
    assert executed <= hc.GUARDIAN_HC_COMMANDS
    for command, call_args in tenant.calls:
        if command.endswith("-post"):
            assert call_args["uri"] in hc.GUARDIAN_HC_REST_POST_URIS
        if command.endswith("-get"):
            assert call_args["uri"] in hc.GUARDIAN_HC_REST_GET_URIS


def test_the_bridge_probes_are_the_only_calls_that_reach_the_gate_and_run_nothing_else(tenant):
    run({})
    probes = tenant.args_of("GuardianToolBridge")
    assert [p["tool_name"] for p in probes] == ["GuardianSkillRead", hc.GUARDIAN_HC_DENY_PROBE]
    assert probes[0]["tool_args"] == {"name": hc.GUARDIAN_HC_TRIAGE_SKILL, "summary_only": "true"}
    assert probes[1]["tool_args"] == hc.GUARDIAN_HC_DENY_PROBE_ARGS
    for probe in probes:
        assert probe["tick_id"] == "healthcheck" and probe["run_id"] == "healthcheck" and probe["tool_call_id"].startswith("healthcheck-")


def test_the_deny_probe_is_harmless_if_the_gate_ever_failed():
    # it reads the routing list, writes its own context key and, through GuardianAuditWrite, one audit row; it changes no
    # incident, no other list and no job
    code = (PACK / "Scripts" / "GuardianModelChoice" / "GuardianModelChoice.py").read_text().split("# </GUARDIAN_COMMON_INJECT>")[1]
    executed = {node.args[0].value for node in ast.walk(ast.parse(code)) if isinstance(node, ast.Call)
                and getattr(node.func, "id", "") == "guardian_execute" and node.args and isinstance(node.args[0], ast.Constant)}
    assert executed == {"getList", "GuardianAuditWrite"}
    for word in ("setList", "createList", "addToList", "setIncident", "closeInvestigation", "executeCommand"):
        assert word not in code, word
    assert hc.GUARDIAN_HC_DENY_PROBE == "GuardianModelChoice"


def test_xql_runs_only_when_asked_and_then_once_with_limit_one_over_one_hour(tenant):
    results, _state = run({})
    assert [a for a in tenant.args_of("GuardianXQL") if a.get("query")] == []
    assert tenant.args_of("GuardianXQL") == [{"template": "list"}]
    assert by_name(results)["XQL query"]["status"] == "SKIP"
    tenant.calls.clear()
    results, _state = run({"include_xql": "true"})
    queries = [a for a in tenant.args_of("GuardianXQL") if a.get("query")]
    assert len(queries) == 1 and queries[0]["hours"] == "1" and queries[0]["query"].endswith("| limit 1")
    assert by_name(results)["XQL query"]["status"] == "PASS"
    assert not [c for c, _a in tenant.calls if c == "xdr-xql-generic-query"]  # only through GuardianXQL


def test_a_failed_xql_query_is_a_warn_not_a_fail(tenant):
    tenant.xql_error = "dataset cloud_audit_logs does not exist"
    row = by_name(run({"include_xql": "true"})[0])["XQL query"]
    assert row["status"] == "WARN" and row["problem"] == "xql_error" and "does not exist" in row["detail"]
    tenant.script_errors["GuardianXQL"] = "GuardianXQL failed unexpectedly: quota exceeded"
    assert by_name(run({"include_xql": "true"})[0])["XQL query"]["status"] == "WARN"



# --- model calls -----------------------------------------------------------------------------------------------------------------

def test_a_healthy_tenant_makes_one_call_for_the_provider_and_none_for_an_empty_routing(tenant):
    run({})
    assert len(tenant.llm_calls) == 1 and "model" not in tenant.llm_calls[0]
    assert tenant.llm_calls[0]["timeout"] == hc.GUARDIAN_HC_MODEL_CALL_TIMEOUT
    assert set(tenant.llm_calls[0]) == {"messages", "timeout"} and tenant.llm_calls[0]["timeout"] == 60
    assert tenant.llm_calls[0]["messages"].startswith("b64:")
    import base64
    assert json.loads(base64.b64decode(tenant.llm_calls[0]["messages"][4:])) == [{"role": "user", "content": hc.GUARDIAN_HC_MODEL_PROMPT}]


def test_one_call_per_distinct_routed_model_and_never_more_than_the_cap(tenant):
    tenant.lists["guardian_model_routing"] = json.dumps({"triage": "gemini-2.5-pro", "complexity": {
        "low": {"model": "gpt-5"}, "medium": {"model": "gemini-2.5-pro"}, "high": {"model": "gpt-5-nano"}}})
    results, state = run({})
    models = [c.get("model") for c in tenant.llm_calls]
    assert models == [None, "gemini-2.5-pro", "gpt-5", "gpt-5-nano"] and state["model_calls"] == 4
    assert by_name(results)["Routed model gpt-5-nano"]["status"] == "FAIL"  # not served by the provider


@pytest.mark.parametrize("cap, expected", [("0", 0), ("1", 1), ("2", 2), ("3", 3), ("4", 4), ("6", 5), ("9", 5), ("-3", 0), ("x", 4)])
def test_the_model_call_cap(tenant, cap, expected):
    # one call for the provider plus four distinct routed models would be five calls
    tenant.lists["guardian_model_routing"] = json.dumps({"triage": "gemini-2.5-pro", "complexity": {
        "low": {"model": "gpt-5"}, "medium": {"model": "gpt-5-mini-x"}, "high": {"model": "gpt-5-nano"}}})
    tenant.served_models |= {"gpt-5-mini-x", "gpt-5-nano"}
    results, _state = run({"max_model_calls": cap})
    assert len(tenant.llm_calls) == expected <= hc.GUARDIAN_HC_MAX_MODEL_CALLS
    skipped = [r for r in results if r["status"] == "SKIP" and "max_model_calls" in r["detail"]]
    assert bool(skipped) == (expected < 5)


def test_the_cap_can_reach_six_and_no_more(tenant):
    tenant.lists["guardian_model_routing"] = json.dumps({"triage": "m1", "complexity": {"low": {"model": "m2"}, "medium": {"model": "m3"},
                                                                                         "high": {"model": "m4"}}})
    tenant.served_models |= {"m1", "m2", "m3", "m4"}
    run({"max_model_calls": "50"})
    assert len(tenant.llm_calls) == 5   # one plus four distinct models: below the cap of six
    assert hc.guardian_hc_new_state({"max_model_calls": "50"})["args"]["max_model_calls"] == 6


def test_test_model_and_test_routing_false_make_no_call(tenant):
    tenant.lists["guardian_model_routing"] = json.dumps({"triage": "gpt-5", "complexity": {}})
    results, _state = run({"test_model": "false", "test_routing": "false"})
    assert tenant.llm_calls == []
    assert by_name(results)["Model answers"]["status"] == "SKIP" and by_name(results)["Routed models"]["status"] == "SKIP"
    tenant.llm_calls.clear()
    run({"test_model": "false"})
    assert [c.get("model") for c in tenant.llm_calls] == ["gpt-5"]


def test_the_configured_model_is_not_called_again_when_it_is_routed(tenant):
    tenant.instances[0]["data"] = [{"name": "model", "value": "gpt-5-mini"}]
    tenant.lists["guardian_model_routing"] = json.dumps({"triage": "gpt-5-mini", "complexity": {}})
    results, _state = run({})
    assert len(tenant.llm_calls) == 1
    assert by_name(results)["Routed models"]["status"] == "PASS"


def test_the_model_answer_reports_latency_tokens_and_cost(tenant):
    results, state = run({})
    row = by_name(results)["Model answers"]
    assert row["status"] == "PASS" and "20 prompt + 2 answer tokens" in row["detail"] and "cost $" in row["detail"]
    price = json.loads(tenant.lists["guardian_pricing"])["gpt-5-mini"]
    assert state["model_cost"] == pytest.approx((20 * price["input_per_1m"] + 2 * price["output_per_1m"]) / 1e6)
    assert by_name(results)["Model cost of this check"]["detail"].startswith("1 call(s), 22 tokens, $")


def test_a_model_with_no_price_says_so(tenant):
    tenant.llm_reply_model = "some-new-model"
    results, state = run({})
    assert "cost unknown" in by_name(results)["Model answers"]["detail"] and state["cost_known"] is False
    assert by_name(results)["Model cost of this check"]["detail"].startswith("1 call(s), 22 tokens, >= $")
    assert "a model is not in guardian_pricing" in hc.guardian_hc_report(results, state)


# --- the report ------------------------------------------------------------------------------------------------------------------

def test_a_healthy_tenant_passes_everything_it_can_check(tenant):
    results, state = run({})
    summary = hc.guardian_hc_summary(results, state)
    assert summary["status"] == "PASS" and summary["fail"] == 0 and summary["warn"] == 0, [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert summary["failed"] == [] and summary["edition"] == EDITION and summary["pass"] > 20
    assert set(by_name(results)) >= {"Automations", "Playbooks", "Lists", "JSON control lists", "Model provider", "Core REST API",
                                     "Model answers", "Kill switch", "Allowed tool passes", "Denylisted script is denied"}
    outside = [r["name"] for r in results if r["status"] == "SKIP"]
    assert any("Route" in n for n in outside) and any("Duplicate check" in n for n in outside)
    make_problem_keys_known(results)


def test_inside_an_item_the_route_and_the_duplicate_check_run(tenant, monkeypatch):
    monkeypatch.setattr(hc.demisto, "incident", lambda: dict(INCIDENT))
    results, _state = run({})
    assert not [r for r in results if r["status"] == "SKIP" and ("Route" in r["name"] or "Duplicate check" in r["name"])]
    assert tenant.names(hc.GUARDIAN_HC_ROUTE_SCRIPT) and tenant.names(hc.GUARDIAN_HC_DUPLICATE_SCRIPT)
    assert tenant.args_of(hc.GUARDIAN_HC_DUPLICATE_SCRIPT) == [{"close_duplicates": "false"}]
    probes = tenant.args_of("GuardianToolBridge")
    assert all(p["run_id"] == "77" for p in probes)


def test_the_report_has_the_sections_in_order_and_a_cause_and_fix_for_every_problem(tenant):
    tenant.scripts.remove("GuardianPing")
    tenant.instances[0]["enabled"] = "false"
    results, state = run({})
    report = hc.guardian_hc_report(results, state)
    heads = re.findall(r"^## (\d+)\. (.+)$", report, re.M)
    assert [h[1] for h in heads] == ["Package content", "Lists valid", "Integrations", "Model", "Core scripts", "Security gate", "Summary"]
    assert [h[0] for h in heads] == [str(i) for i in range(1, 8)]
    assert report.startswith("# Guardian health check") and "**Overall: FAIL**" in report
    problems = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert problems
    assert report.count("    - Likely cause: ") == len(problems) and report.count("    - Fix: ") == len(problems)
    assert "GuardianPing" in report and "To fix, in this order:" in report
    make_problem_keys_known(results)


def test_pass_lines_are_one_line_unless_verbose(tenant):
    results, state = run({})
    results[0]["extra"] = ["a detail line"]
    quiet = hc.guardian_hc_report(results, state)
    assert "a detail line" not in quiet
    state["args"]["verbose"] = True
    assert "    - a detail line" in hc.guardian_hc_report(results, state)
    for line in quiet.splitlines():
        if line.startswith("- PASS"):
            assert "\n" not in line


def test_the_summary_has_the_counts_the_failed_names_the_time_and_the_edition(tenant):
    tenant.scripts.remove("GuardianPing")
    results, state = run({})
    summary = hc.guardian_hc_summary(results, state)
    assert summary["status"] == "FAIL" and "Automations" in summary["failed"]
    assert summary["pass"] + summary["warn"] + summary["fail"] + summary["skip"] == len(results)
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", summary["ts"]) and summary["edition"] == EDITION
    assert summary["seconds"] >= 0 and summary["model_calls"] == 1


# --- 1. package content ----------------------------------------------------------------------------------------------------------

def test_a_missing_automation_is_a_fail_named_in_the_report(tenant):
    tenant.scripts.remove("GuardianToolBridge")
    row = by_name(run({})[0])["Automations"]
    assert row["status"] == "FAIL" and "GuardianToolBridge" in row["detail"] and row["problem"] == "script_missing"


def test_an_extra_guardian_item_is_a_warn_and_a_foreign_one_is_ignored(tenant):
    tenant.scripts += ["GuardianMyOwnThing", "SomethingElse"]
    rows = by_name(run({})[0])
    assert rows["Automations"]["status"] == "PASS"
    assert rows["Automations (extra)"]["status"] == "WARN" and "GuardianMyOwnThing" in rows["Automations (extra)"]["detail"]
    assert "SomethingElse" not in rows["Automations (extra)"]["detail"] and rows["Automations (extra)"]["problem"] == "item_unknown"


def test_missing_playbooks_lists_fields_types_and_layouts(tenant):
    tenant.playbooks.pop()
    del tenant.lists["guardian_policy"]
    tenant.fields.pop()
    tenant.types.pop()
    tenant.layouts.pop()
    rows = by_name(run({})[0])
    assert rows["Playbooks"]["status"] == "FAIL"
    assert rows["Lists"]["status"] == "FAIL" and "guardian_policy" in rows["Lists"]["detail"] and rows["Lists"]["problem"] == "list_missing"
    assert rows["Issue fields"]["status"] == "FAIL" and rows["Issue types"]["status"] == "FAIL"
    assert rows["Layouts"]["status"] == "WARN"


def test_runtime_lists_and_operators_own_skills_are_not_unknown(tenant):
    tenant.list_names = sorted(set(tenant.lists) | {"guardian_audit", "guardian_memory", "guardian_skill_my_own", "guardian_cost_ledger"})
    assert "Lists (extra)" not in by_name(run({})[0])
    tenant.list_names.append("guardian_mystery")
    assert by_name(run({})[0])["Lists (extra)"]["status"] == "WARN"


@pytest.mark.parametrize("uri", ["/automation/search", "/playbook/search"])
def test_a_search_that_cannot_be_asked_is_a_warn_not_a_fail(tenant, uri):
    tenant.post_errors[uri] = "HTTP 500"
    results = run({})[0]
    row = by_name(results)["Automations" if "automation" in uri else "Playbooks"]
    assert row["status"] == "WARN" and row["problem"] == "unverified" and "500" in row["detail"]


def test_an_answer_in_an_unknown_shape_is_a_warn(tenant):
    tenant.post_override["/automation/search"] = {"nothing": 1}
    tenant.get_override["/lists/names"] = {"nothing": 1}
    tenant.get_override["/incidentfields"] = "text"
    results = by_name(run({})[0])
    assert results["Automations"]["status"] == "WARN" and results["Lists"]["status"] == "WARN" and results["Issue fields"]["status"] == "WARN"


def test_the_content_section_makes_one_call_per_kind(tenant):
    run({})
    uris = [a["uri"] for c, a in tenant.calls if c.endswith("-post") or c.endswith("-get")]
    assert sorted(uris) == sorted(["/settings/integration/search", "/automation/search", "/playbook/search", "/lists/names", "/incidentfields",
                                   "/incidenttypes/export", "/layouts"])


def test_jobs_are_not_part_of_the_cortex_check(tenant):
    run({})
    assert "/jobs/search" not in [a["uri"] for c, a in tenant.calls if c.endswith("-post")]
    assert not hasattr(hc, "GUARDIAN_HC_JOBS")



# --- 2. lists valid --------------------------------------------------------------------------------------------------------------

def test_every_shipped_json_list_passes_on_its_own_content(tenant):
    rows = by_name(run({})[0])
    assert rows["JSON control lists"]["status"] == "PASS" and str(len(hc.GUARDIAN_HC_JSON_LISTS)) in rows["JSON control lists"]["detail"]
    for name in ("Settings, policy and approvals", "Allowlist against denylist", "Skills index and routes", "Routing models in the catalogue"):
        assert rows[name]["status"] == "PASS", rows[name]


def test_each_json_list_is_read_once(tenant):
    run({})
    reads = [a["listName"] for c, a in tenant.calls if c == "getList"]
    assert len(reads) == len(set(reads))


def test_a_list_that_is_missing_invalid_or_a_pasted_wrapper_is_a_fail_with_the_right_cause(tenant):
    del tenant.lists["guardian_persona"]
    tenant.lists["guardian_prompt_head"] = "{ this is not json"
    tenant.lists["guardian_pricing"] = json.dumps({"id": "guardian_pricing", "name": "guardian_pricing", "version": -1, "data": "{}", "type": "json"})
    rows = by_name(run({})[0])
    assert (rows["guardian_persona"]["status"], rows["guardian_persona"]["problem"]) == ("FAIL", "list_missing")
    assert (rows["guardian_prompt_head"]["status"], rows["guardian_prompt_head"]["problem"]) == ("FAIL", "list_invalid_json")
    assert (rows["guardian_pricing"]["status"], rows["guardian_pricing"]["problem"]) == ("FAIL", "list_wrapper")
    assert rows["JSON control lists"]["status"] == "PASS" and "; the others follow" in rows["JSON control lists"]["detail"]


def test_a_command_that_is_both_allowed_and_denied_is_a_fail(tenant):
    allow = json.loads(tenant.lists["guardian_tool_allowlist"])
    allow["commands"].append(hc.GUARDIAN_HC_DENY_PROBE)
    tenant.lists["guardian_tool_allowlist"] = json.dumps(allow)
    row = by_name(run({})[0])["Allowlist against denylist"]
    assert row["status"] == "FAIL" and hc.GUARDIAN_HC_DENY_PROBE in row["detail"] and row["problem"] == "list_inconsistent"


def test_required_keys_and_policy_tiers(tenant):
    deny = json.loads(tenant.lists["guardian_tool_denylist"])
    del deny["protected_lists"]
    tenant.lists["guardian_tool_denylist"] = json.dumps(deny)
    policy = json.loads(tenant.lists["guardian_policy"])
    policy["setIncident"] = "maybe"
    tenant.lists["guardian_policy"] = json.dumps(policy)
    row = by_name(run({})[0])["Settings, policy and approvals"]
    assert row["status"] == "FAIL" and "protected_lists" in row["detail"] and "setIncident" in row["detail"]


def test_a_route_naming_a_skill_that_is_not_enabled_and_an_index_entry_without_a_list_are_fails(tenant):
    routes = json.loads(tenant.lists[hc.GUARDIAN_HC_ROUTES_LIST])
    routes["routes"][-1]["skill"] = "no_such_skill"
    tenant.lists[hc.GUARDIAN_HC_ROUTES_LIST] = json.dumps(routes)
    row = by_name(run({})[0])["Skills index and routes"]
    assert row["status"] == "FAIL" and "no_such_skill" in row["detail"]
    tenant.lists[hc.GUARDIAN_HC_ROUTES_LIST] = _shipped_lists()[hc.GUARDIAN_HC_ROUTES_LIST]
    index = json.loads(tenant.lists["guardian_skills_index"])
    name = index[0]["name"]
    tenant.list_names = [n for n in sorted(tenant.lists) if n != "guardian_skill_" + name]
    row = by_name(run({})[0])["Skills index and routes"]
    assert row["status"] == "FAIL" and "guardian_skill_" + name in row["detail"]


def test_a_routed_model_that_is_not_in_the_catalogue_is_a_warn(tenant):
    tenant.lists["guardian_model_routing"] = json.dumps({"triage": "totally-unknown-model", "complexity": {}})
    row = by_name(run({})[0])["Routing models in the catalogue"]
    assert row["status"] == "WARN" and "totally-unknown-model" in row["detail"]
    tenant.lists["guardian_model_routing"] = json.dumps({"triage": "gpt-5", "complexity": {}})
    assert by_name(run({})[0])["Routing models in the catalogue"]["status"] == "PASS"


def test_the_xql_templates_are_checked_for_declared_placeholders(tenant):
    assert by_name(run({})[0])["XQL templates"]["status"] == "PASS"
    templates = json.loads(tenant.lists["guardian_xql_templates"])
    templates["templates"][0]["query"] += " | filter x = \"{undeclared}\""
    tenant.lists["guardian_xql_templates"] = json.dumps(templates)
    row = by_name(run({})[0])["XQL templates"]
    assert row["status"] == "FAIL" and "undeclared" in row["detail"] and row["problem"] == "list_inconsistent"
    del templates["templates"][0]["params"]
    tenant.lists["guardian_xql_templates"] = json.dumps(templates)
    assert "lacks name, params or query" in by_name(run({})[0])["XQL templates"]["detail"]
    tenant.lists["guardian_xql_templates"] = json.dumps({"templates": []})
    assert by_name(run({})[0])["XQL templates"]["status"] == "FAIL"



# --- 3. integrations -------------------------------------------------------------------------------------------------------------

def test_no_provider_is_a_fail_and_two_are_a_warn(tenant):
    tenant.instances[0]["enabled"] = "false"
    row = by_name(run({})[0])["Model provider"]
    assert row["status"] == "FAIL" and row["problem"] == "no_provider" and "lab-model" in row["detail"]
    tenant.instances[0]["enabled"] = "true"
    tenant.instances.append({"name": "second", "brand": "GuardianVertex", "enabled": "true", "data": []})
    row = by_name(run({})[0])["Model provider"]
    assert row["status"] == "WARN" and row["problem"] == "many_providers" and "second" in row["detail"]


def test_the_provider_last_error_is_a_fail_and_an_auth_error_gets_the_auth_cause(tenant):
    tenant.health["lab-model"]["lastError"] = "HTTP 401 Unauthorized: invalid api key"
    row = by_name(run({})[0])["Provider health"]
    assert row["status"] == "FAIL" and "401" in row["detail"] and row["problem"] == "provider_auth"
    tenant.health["lab-model"]["lastError"] = "Could not connect to host"
    assert by_name(run({})[0])["Provider health"]["problem"] == "provider_error"


def test_the_core_rest_api_instance_missing_or_disabled_is_a_fail(tenant):
    tenant.instances[1]["enabled"] = "false"
    row = by_name(run({})[0])["Core REST API"]
    assert row["status"] == "FAIL" and row["problem"] == "no_rest_api" and "disabled" in row["detail"]
    tenant.instances.pop(1)
    row = by_name(run({})[0])["Core REST API"]
    assert row["status"] == "WARN" and row["problem"] == "no_rest_api"


def test_when_the_rest_command_does_not_exist_the_provider_and_rest_checks_fail_with_the_rest_cause(tenant):
    tenant.post_errors["/settings/integration/search"] = "Unsupported Command : demisto-api-post , verify you have proper integration enabled"
    rows = by_name(run({})[0])
    assert rows["Model provider"]["status"] == "FAIL" and rows["Model provider"]["problem"] == "no_rest_api"
    assert rows["Core REST API"]["status"] == "FAIL" and rows["Core REST API"]["problem"] == "no_rest_api"
    assert rows["Provider integrations"]["status"] == "SKIP"


def test_the_pack_integrations_must_be_uploaded(tenant):
    original = tenant.search_response

    def fewer():
        response = original()
        response["configurations"] = response["configurations"][:1]
        return response
    tenant.search_response = fewer
    row = by_name(run({})[0])["Provider integrations"]
    assert row["status"] == "WARN" and "not uploaded" in row["detail"]
    tenant.search_response = lambda: dict(original(), configurations=[])
    assert by_name(run({})[0])["Provider integrations"]["status"] == "FAIL"


def test_the_xql_query_command_is_a_warn_when_absent(tenant):
    assert by_name(run({})[0])["XQL query command"]["status"] == "PASS"
    tenant.supported = {"lab-model": [{"name": "guardian-llm-chat"}]}
    row = by_name(run({})[0])["XQL query command"]
    assert row["status"] == "WARN" and row["problem"] == "xql_unavailable"



# --- 4. model --------------------------------------------------------------------------------------------------------------------

def test_the_model_profile_is_read_only_and_reports_size_budgets_and_turn_limit(tenant):
    row = by_name(run({})[0])["Model profile"]
    assert tenant.args_of("GuardianModelProfileCheck") == [{"read_only": "true"}]
    assert row["status"] == "PASS" and "size large" in row["detail"] and "200000" in row["detail"] and "24000" in row["detail"]
    assert "turn limit 60" in row["detail"]


def test_a_small_size_for_a_catalogue_large_model_is_a_warn(tenant):
    tenant.profile = dict(tenant.profile, tier="small", tier_source="guardian_settings", model="gpt-5")
    row = by_name(run({})[0])["Model profile"]
    assert row["status"] == "WARN" and "large" in row["detail"] and "small" in row["detail"]


def test_a_profile_error_is_a_fail(tenant):
    tenant.script_errors["GuardianModelProfileCheck"] = "GuardianModelProfileCheck failed unexpectedly: boom"
    row = by_name(run({})[0])["Model profile"]
    assert row["status"] == "FAIL" and "boom" in row["detail"]


def test_the_model_answer_paths(tenant):
    tenant.llm_text = "Sure, here you go"
    row = by_name(run({})[0])["Model answers"]
    assert row["status"] == "WARN" and row["problem"] == "model_no_answer"
    tenant.llm_text = "ok"
    assert by_name(run({})[0])["Model answers"]["status"] == "PASS"
    tenant.llm_error = "HTTP 403 Forbidden"
    row = by_name(run({})[0])["Model answers"]
    assert row["status"] == "FAIL" and row["problem"] == "provider_auth"
    tenant.llm_error = "the read operation timed out"
    assert by_name(run({})[0])["Model answers"]["problem"] == "timeout"
    tenant.llm_error = "Failed to pull image demisto/python3"
    assert by_name(run({})[0])["Model answers"]["problem"] == "docker_pull"
    tenant.llm_error = "something odd"
    assert by_name(run({})[0])["Model answers"]["problem"] == "model_error"


def test_routed_model_errors_are_matched_on_the_start_of_the_text(tenant):
    tenant.lists["guardian_model_routing"] = json.dumps({"triage": "gpt-5", "complexity": {"low": {"model": "ghost"}}})
    rows = by_name(run({})[0])
    assert rows["Routed model gpt-5"]["status"] == "PASS"
    assert rows["Routed model ghost"]["status"] == "FAIL" and rows["Routed model ghost"]["problem"] == "model_not_available"
    original = tenant.__call__

    def cohere(command, args):
        if command == "guardian-llm-chat" and args.get("model"):
            return [{"Type": 4, "Contents": "MODEL_SELECTION_UNSUPPORTED: this provider cannot choose a model per call"}]
        return original(command, args)
    tenant_calls = tenant.calls
    hc.demisto.executeCommand = cohere
    rows = by_name(hc.guardian_hc_run_all({})[0])
    assert rows["Routed model gpt-5"]["status"] == "WARN" and rows["Routed model gpt-5"]["problem"] == "model_selection_unsupported"
    assert tenant_calls


# --- 5. core scripts -------------------------------------------------------------------------------------------------------------

def test_every_core_script_is_run_with_its_real_arguments(tenant):
    run({})
    assert tenant.args_of("GuardianKillSwitchCheck") == [{}] and tenant.args_of("GuardianJobGuardCheck") == [{}]
    assert {"name": hc.GUARDIAN_HC_TRIAGE_SKILL, "summary_only": "true"} in tenant.args_of("GuardianSkillRead")
    assert tenant.args_of("GuardianPromptBuilder") == [{"summary_only": "true"}]
    assert tenant.args_of("GuardianModelChoice") == [{"stage": "triage"}]
    names = {c for c, _a in tenant.calls}
    assert "GuardianMemory" not in names and "setList" not in names  # memory is checked by reading its list


def test_script_arguments_exist_in_each_scripts_yml():
    scripts = PACK / "Scripts"
    for name, args in (("GuardianSkillRead", {"name", "summary_only"}), ("GuardianPromptBuilder", {"summary_only"}),
                       ("GuardianModelChoice", {"stage"}), ("GuardianModelProfileCheck", {"read_only"}),
                       ("GuardianKillSwitchCheck", set()), ("GuardianJobGuardCheck", set()),
                       (hc.GUARDIAN_HC_DUPLICATE_SCRIPT, {"close_duplicates"}), (hc.GUARDIAN_HC_ROUTE_SCRIPT, set()),
                       ("GuardianToolBridge", {"tool_name", "tool_args", "tool_call_id", "tick_id", "run_id"}), ("GuardianXQL", {"template", "query", "hours"})):
        declared = {a["name"] for a in yaml.safe_load((scripts / name / (name + ".yml")).read_text()).get("args") or []}
        assert args <= declared, (name, args - declared)


def test_the_kill_switch_on_is_a_warn_and_the_bridge_probes_report_halted(tenant):
    tenant.script_contents["GuardianKillSwitchCheck"] = {"halted": True, "proceed": "false", "reason": "kill switch is ON (maintenance)"}
    tenant.bridge_status = {"GuardianSkillRead": "halted", hc.GUARDIAN_HC_DENY_PROBE: "halted"}
    rows = by_name(run({})[0])
    assert rows["Kill switch"]["status"] == "WARN" and rows["Kill switch"]["problem"] == "kill_switch_on" and "maintenance" in rows["Kill switch"]["detail"]
    assert rows["Allowed tool passes"]["status"] == "WARN" and rows["Allowed tool passes"]["problem"] == "bridge_halted"
    assert rows["Denylisted script is denied"]["problem"] == "bridge_halted"


def test_the_job_guard_halted_is_a_warn(tenant):
    tenant.script_contents["GuardianJobGuardCheck"] = {"halted": True, "proceed": "false", "reason": "Job X is auto-disabled: failures"}
    row = by_name(run({})[0])["Job guard"]
    assert row["status"] == "WARN" and row["problem"] == "job_guard"


@pytest.mark.parametrize("command, name", [("GuardianSkillRead", "Skill read"), ("GuardianPromptBuilder", "Prompt builder"),
                                           ("GuardianModelChoice", "Model choice"), ("GuardianKillSwitchCheck", "Kill switch"),
                                           ("GuardianJobGuardCheck", "Job guard")])
def test_a_script_that_fails_is_a_fail_with_its_error_and_the_report_goes_on(tenant, command, name):
    tenant.script_errors[command] = "GuardianThing failed unexpectedly: kaboom"
    results = run({})[0]
    row = by_name(results)[name]
    assert row["status"] == "FAIL" and "kaboom" in row["detail"]
    assert by_name(results)["Denylisted script is denied"]["status"] in ("PASS", "WARN", "FAIL")  # later sections still ran


def test_a_script_missing_from_the_upload_gets_the_script_cause_and_a_docker_failure_its_own(tenant):
    tenant.script_errors["GuardianPromptBuilder"] = "Script GuardianPromptBuilder was not found in module"
    tenant.script_errors["GuardianModelChoice"] = "Failed to pull image demisto/python3:3.11 : pull access denied"
    rows = by_name(run({})[0])
    assert rows["Prompt builder"]["problem"] == "script_missing" and rows["Model choice"]["problem"] == "docker_pull"


def test_the_memory_check_reads_the_list(tenant):
    assert by_name(run({})[0])["Memory list"]["status"] == "PASS"
    del tenant.lists["guardian_memory"]
    assert by_name(run({})[0])["Memory list"]["detail"].startswith("guardian_memory does not exist yet")
    tenant.lists["guardian_memory"] = "{broken"
    assert by_name(run({})[0])["Memory list"]["status"] == "FAIL"
    tenant.lists["guardian_memory"] = "{}"
    assert by_name(run({})[0])["Memory list"]["problem"] == "list_invalid_json"


def test_the_xql_template_list_is_read_only_and_the_query_is_skipped_by_default(tenant):
    results = run({})[0]
    assert by_name(results)["XQL templates (GuardianXQL template=list)"]["status"] == "PASS"



# --- 6. security gate ------------------------------------------------------------------------------------------------------------

def test_the_gate_passes_when_the_bridge_allows_and_denies_by_its_status(tenant):
    rows = by_name(run({})[0])
    assert rows["Allowed tool passes"]["status"] == "PASS" and "status=ok" in rows["Allowed tool passes"]["detail"]
    assert rows["Denylisted script is denied"]["status"] == "PASS" and "status=denied" in rows["Denylisted script is denied"]["detail"]


def test_an_allowed_tool_that_is_refused_is_a_fail(tenant):
    tenant.bridge_status = {"GuardianSkillRead": "denied"}
    row = by_name(run({})[0])["Allowed tool passes"]
    assert row["status"] == "FAIL" and row["problem"] == "bridge_not_enforcing" and "not enforcing the lists" in row["detail"]


@pytest.mark.parametrize("status", ["ok", "pending_approval", "error", "halted-not"])
def test_a_denylisted_script_that_is_not_denied_is_a_fail(tenant, status):
    tenant.bridge_status = {hc.GUARDIAN_HC_DENY_PROBE: status}
    row = by_name(run({})[0])["Denylisted script is denied"]
    assert row["status"] == "FAIL" and row["problem"] == "bridge_not_enforcing" and "status=" + status in row["detail"]


def test_the_verdict_is_the_bridges_status_never_a_keyword(tenant):
    original = tenant.__call__

    def tricky(command, args):
        if command == "GuardianToolBridge" and args["tool_name"] == "GuardianSkillRead":
            return [{"Type": 1, "Contents": {"tool_result": {"status": "denied", "ok": False, "error": "ok allowed fine"}}}]
        if command == "GuardianToolBridge":
            return [{"Type": 1, "Contents": {"tool_result": {"status": "ok", "ok": True, "result": "denied outright"}}}]
        return original(command, args)
    hc.demisto.executeCommand = tricky
    rows = by_name(hc.guardian_hc_run_all({})[0])
    assert rows["Allowed tool passes"]["status"] == "FAIL" and rows["Denylisted script is denied"]["status"] == "FAIL"


def test_a_bridge_that_returns_nothing_usable_or_fails_is_a_fail(tenant):
    tenant.script_errors["GuardianToolBridge"] = "GuardianToolBridge failed unexpectedly: x"
    rows = by_name(run({})[0])
    assert rows["Allowed tool passes"]["status"] == "FAIL" and rows["Denylisted script is denied"]["status"] == "FAIL"
    del tenant.script_errors["GuardianToolBridge"]
    tenant.script_contents["GuardianToolBridge"] = {"unexpected": 1}
    assert by_name(run({})[0])["Allowed tool passes"]["status"] == "FAIL"


def test_test_bridge_false_skips_the_probes(tenant):
    results, _state = run({"test_bridge": "false"})
    assert tenant.args_of("GuardianToolBridge") == [] and by_name(results)["Tool chokepoint"]["status"] == "SKIP"


# --- the time budget and the older profile check --------------------------------------------------------------------------------

class _Clock:
    def __init__(self, start=1000.0):
        self.now = start

    def time(self):
        return self.now


def test_after_the_time_budget_nothing_more_is_run_and_the_report_still_comes(tenant, monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(hc, "time", clock)
    started = clock.now
    stamps = []
    original = tenant.__call__

    def slow(command, args):
        stamps.append(clock.now)
        clock.now += 60          # every command takes a minute
        return original(command, args)
    monkeypatch.setattr(hc.demisto, "executeCommand", slow)
    results, state = run({})
    assert stamps and max(stamps) <= started + hc.GUARDIAN_HC_BUDGET_SECONDS
    skipped = [r for r in results if r["status"] == "SKIP" and "time budget" in r["detail"]]
    assert len(skipped) >= 10
    report = hc.guardian_hc_report(results, state)
    assert "## 7. Summary" in report and "time budget" in report
    assert hc.guardian_hc_summary(results, state)["skip"] >= len(skipped)


def test_a_model_call_never_runs_past_the_budget(tenant, monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(hc, "time", clock)
    state = hc.guardian_hc_new_state({})
    hc._GUARDIAN_HC_CLOCK["deadline"] = clock.now + 40
    state["lists"] = {}
    call = hc.guardian_hc_model_call(state)
    assert call["ok"] and tenant.llm_calls[-1]["timeout"] == 30     # 40 s left, minus the reserve
    hc._GUARDIAN_HC_CLOCK["deadline"] = clock.now + 5
    with pytest.raises(hc.GuardianHcOutOfTime):
        hc.guardian_hc_model_call(state)
    assert len(tenant.llm_calls) == 1


def test_the_clock_is_set_by_every_run(tenant, monkeypatch):
    clock = _Clock(5000.0)
    monkeypatch.setattr(hc, "time", clock)
    run({})
    assert hc._GUARDIAN_HC_CLOCK["deadline"] == 5000.0 + hc.GUARDIAN_HC_BUDGET_SECONDS


def test_an_older_model_profile_check_that_saved_the_profile_is_a_warn(tenant):
    tenant.profile = dict(tenant.profile, catalog_action="written")
    row = by_name(run({})[0])["Model profile"]
    assert row["status"] == "WARN" and row["problem"] == "profile_check_old" and "saved guardian_model_profile" in row["detail"]
    tenant.profile = dict(tenant.profile, catalog_action="none")
    assert by_name(run({})[0])["Model profile"]["status"] == "PASS"


def test_a_search_that_does_not_return_this_script_is_not_trusted(tenant):
    tenant.scripts = [n for n in tenant.scripts if n != "GuardianHealthCheck"]
    rows = by_name(run({})[0])
    assert rows["Automations"]["status"] == "WARN" and rows["Automations"]["problem"] == "unverified"
    assert "GuardianHealthCheck" in rows["Automations"]["detail"]


def test_empty_playbook_answer_is_trusted_only_when_the_automation_search_proved_itself(tenant):
    tenant.playbooks = []
    assert by_name(run({})[0])["Playbooks"]["status"] == "FAIL"
    tenant.scripts = [n for n in tenant.scripts if n != "GuardianHealthCheck"]
    assert by_name(run({})[0])["Playbooks"]["status"] == "WARN"


def test_a_list_getlist_can_read_is_not_missing_whatever_the_names_call_says(tenant):
    tenant.list_names = [n for n in sorted(tenant.lists) if n not in ("guardian_policy", "guardian_skill_xsoar_triage")]
    tenant.list_names = [n for n in tenant.list_names if n != hc.GUARDIAN_HC_MARKDOWN_LISTS[0]]
    assert by_name(run({})[0])["Lists"]["status"] == "PASS"
    del tenant.lists["guardian_policy"]
    row = by_name(run({})[0])["Lists"]
    assert row["status"] == "FAIL" and "guardian_policy" in row["detail"]


def test_the_slash_command_automations_are_found_by_their_yml_names_whatever_the_case(tenant):
    assert "guardian-approve" in tenant.scripts
    tenant.scripts = [n.upper() if n.startswith("guardian-") else n for n in tenant.scripts]
    rows = by_name(run({})[0])
    assert rows["Automations"]["status"] == "PASS" and "Automations (extra)" not in rows
    tenant.scripts.remove("GUARDIAN-DENY")
    row = by_name(run({})[0])["Automations"]
    assert row["status"] == "FAIL" and "guardian-deny" in row["detail"]


def test_run_time_lists_are_not_unknown(tenant):
    extra = ["guardian_run_dispatch_counts", "guardian_intake_sweep_last_narration", "guardian_audit_shard_2026-10-21", "guardian_seed_snapshots",
             "guardian_cost_ledger", "guardian_dropped_transcript_archive", "guardian_eval_results", "guardian_skill_history_x"]
    tenant.list_names = sorted(set(tenant.lists) | set(extra))
    assert "Lists (extra)" not in by_name(run({})[0])
    assert {"guardian_run_dispatch_counts", "guardian_intake_sweep_last_narration"} <= hc.GUARDIAN_HC_RUNTIME_LISTS


def test_every_run_time_list_the_scripts_create_is_known_to_the_health_check():
    import re
    shipped = {json.load(open(f))["name"] for f in glob.glob(str(PACK / "Lists" / "list-*.json"))}
    created = set()
    for path in glob.glob(str(PACK / "Scripts" / "*" / "*.py")):
        if path.endswith("_test.py"):
            continue
        created |= set(re.findall(r'^\s*[A-Z_]*(?:LIST|REGISTRY|LEDGER)[A-Z_]*\s*=\s*"(guardian_[a-z_0-9]+)"', open(path).read(), re.M))
    unknown = {n for n in created - shipped if n not in hc.GUARDIAN_HC_RUNTIME_LISTS and not n.startswith(hc.GUARDIAN_HC_OPERATOR_LIST_PREFIXES)}
    assert not unknown, unknown


@pytest.mark.parametrize("shape", [{"IncidentTypes": "TYPES"}, {"incidentTypes": "TYPES"}, "TYPES", {"data": "TYPES"}])
def test_the_incident_types_are_read_in_every_shape_the_export_has(tenant, shape):
    rows = [{"id": n, "version": 1} for n in tenant.types] + [{"id": "Phishing", "version": 2}]
    tenant.get_override["/incidenttypes/export"] = json.loads(json.dumps(shape).replace('"TYPES"', json.dumps(rows)))
    row = by_name(run({})[0])["Issue types"]
    assert row["status"] == "PASS", row
    tenant.get_override["/incidenttypes/export"] = json.loads(json.dumps(shape).replace('"TYPES"', json.dumps(rows[1:])))
    assert by_name(run({})[0])["Issue types"]["status"] == "FAIL"


def test_a_dated_model_name_is_priced_as_its_row(tenant):
    tenant.llm_reply_model = "gpt-5-mini-2025-08-07"
    results, state = run({})
    row = by_name(results)["Model answers"]
    assert "cost unknown" not in row["detail"] and "cost $" in row["detail"] and state["cost_known"] is True
    price = json.loads(tenant.lists["guardian_pricing"])["gpt-5-mini"]
    assert state["model_cost"] == pytest.approx((20 * price["input_per_1m"] + 2 * price["output_per_1m"]) / 1e6)
    tenant.llm_reply_model = "gpt-5-mini-2025-08-07"
    state2 = hc.guardian_hc_new_state({})
    assert hc.guardian_hc_price(state2, "gpt-5-nano-2025") is None   # no row for it; gpt-5 must not price gpt-5-nano


# --- isolation -------------------------------------------------------------------------------------------------------------------

def test_an_exception_in_one_check_is_that_checks_fail_and_the_report_goes_on(tenant, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("kaboom in the check")
    monkeypatch.setattr(hc, "guardian_hc_check_search", boom)
    results = run({})[0]
    rows = by_name(results)
    assert rows["Automations"]["status"] == "FAIL" and "kaboom in the check" in rows["Automations"]["detail"] and rows["Automations"]["problem"] == "check_error"
    assert rows["Playbooks"]["status"] == "FAIL"
    assert rows["Model answers"]["status"] == "PASS" and rows["Denylisted script is denied"]["status"] == "PASS"


@pytest.mark.parametrize("section", ["content", "lists", "integrations", "model", "scripts", "bridge"])
def test_an_exception_in_a_whole_section_does_not_end_the_report(tenant, monkeypatch, section):
    def boom(state):
        raise RuntimeError("section blew up")
    monkeypatch.setattr(hc, "guardian_hc_section_" + section, boom)
    results, state = run({})
    assert any("section blew up" in r["detail"] and r["status"] == "FAIL" for r in results)
    report = hc.guardian_hc_report(results, state)
    assert "## " in report and "Summary" in report
    assert len({r["section"] for r in results}) >= 5


def test_a_tenant_where_every_call_raises_still_gives_a_report(tenant, monkeypatch):
    def broken(command, args):
        raise RuntimeError("the server is gone")
    monkeypatch.setattr(hc.demisto, "executeCommand", broken)
    results, state = run({})
    summary = hc.guardian_hc_summary(results, state)
    assert summary["status"] == "FAIL" and summary["fail"] > 5
    assert "Guardian health check" in hc.guardian_hc_report(results, state, summary)


class _Capture:
    def __init__(self, monkeypatch):
        self.results, self.writes, self.errors = [], [], []
        monkeypatch.setattr(hc, "return_results", lambda value: self.results.append(value))
        monkeypatch.setattr(hc.demisto, "setContext", lambda path, value: self.writes.append((path, value)))
        monkeypatch.setattr(hc, "return_error", lambda msg: self.errors.append(msg))


def test_main_returns_one_report_and_the_context_summary(tenant, monkeypatch):
    capture = _Capture(monkeypatch)
    monkeypatch.setattr(hc.demisto, "args", lambda: {})
    hc.main()
    assert capture.errors == [] and len(capture.results) == 1
    result = capture.results[0]
    assert result.outputs_prefix == "Guardian.HealthCheck" and result.outputs_key_field == "ts"
    assert result.readable_output.startswith("# Guardian health check") and result.outputs["status"] == "PASS"
    assert capture.writes and capture.writes[-1][0] == "Guardian.HealthCheck" and capture.writes[-1][1] == result.outputs
    assert set(result.outputs) >= {"status", "pass", "warn", "fail", "skip", "failed", "ts", "edition"}


def test_main_never_raises_even_when_the_run_itself_fails(tenant, monkeypatch):
    capture = _Capture(monkeypatch)
    monkeypatch.setattr(hc.demisto, "args", lambda: {})

    def boom(args):
        raise ValueError("everything failed")
    monkeypatch.setattr(hc, "guardian_hc_run_all", boom)
    hc.main()
    assert capture.errors == [] and len(capture.results) == 1
    assert capture.results[0].outputs["status"] == "FAIL" and "everything failed" in capture.results[0].readable_output


def test_main_survives_a_context_write_that_fails(tenant, monkeypatch):
    capture = _Capture(monkeypatch)
    monkeypatch.setattr(hc.demisto, "args", lambda: {})

    def broken(path, value):
        raise RuntimeError("no context")
    monkeypatch.setattr(hc.demisto, "setContext", broken)
    hc.main()
    assert len(capture.results) == 1 and capture.errors == []


def test_every_known_problem_has_a_cause_and_a_fix_and_the_table_covers_the_brief():
    for key, value in hc.GUARDIAN_HC_PROBLEMS.items():
        assert isinstance(value, tuple) and len(value) == 2 and all(isinstance(part, str) and len(part) > 20 for part in value), key
    assert {"no_rest_api", "no_provider", "provider_auth", "model_not_available", "list_invalid_json", "list_wrapper", "script_missing",
            "kill_switch_on", "docker_pull", "timeout", "bridge_not_enforcing", "xql_unavailable", "xql_error"} <= set(hc.GUARDIAN_HC_PROBLEMS)
    assert 'job_enabled' not in hc.GUARDIAN_HC_PROBLEMS


def test_every_problem_key_the_source_names_is_in_the_table():
    tree = own_code()[0]
    keys = set()

    def strings(node):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                yield node.value
        elif isinstance(node, ast.Subscript):
            yield from strings(node.value)
        else:
            for child in ast.iter_child_nodes(node):
                yield from strings(child)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "guardian_hc_result":
            holders = [node.args[4]] if len(node.args) > 4 else []
            holders += [kw.value for kw in node.keywords if kw.arg == "problem"]
            for holder in holders:
                keys |= set(strings(holder))
        if isinstance(node, ast.Tuple) and len(node.elts) == 3 and isinstance(node.elts[0], ast.Constant) and node.elts[0].value in ("WARN", "FAIL"):
            keys |= set(strings(node.elts[2]))
    assert keys and keys <= set(hc.GUARDIAN_HC_PROBLEMS), keys - set(hc.GUARDIAN_HC_PROBLEMS)
    assert {"no_rest_api", "no_provider", "check_error", "bridge_not_enforcing"} <= keys
