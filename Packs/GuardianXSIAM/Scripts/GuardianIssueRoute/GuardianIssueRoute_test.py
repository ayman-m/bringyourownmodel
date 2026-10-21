import json
from pathlib import Path

import pytest

import GuardianIssueRoute as route

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]
ISSUES = json.loads((HERE / "test_data" / "issues.json").read_text())
SHIPPED_TABLE = json.loads((REPO_ROOT / "Packs" / "GuardianXSIAM" / "Lists" / "list-guardian_issue_routes.json").read_text())["data"]
ALL_SKILLS = {
    "cortex_issue_reference", "cortex_detection_investigation", "cortex_posture_misconfiguration",
    "cortex_identity_risk", "cortex_vulnerability_triage", "cortex_attack_path", "cortex_case_investigation",
    "cortex_data_health",
}


def _route(issue, **kw):
    kw.setdefault("table_contents", SHIPPED_TABLE)
    kw.setdefault("enabled_skills", ALL_SKILLS)
    return route.guardian_route_run(issue, **kw)


@pytest.mark.parametrize(
    "key, family, skill, mode",
    [
        ("detection", "detection", "cortex_detection_investigation", "verdict"),
        ("misconfiguration", "misconfiguration", "cortex_posture_misconfiguration", "posture"),
        ("kubernetes_cis", "kubernetes_cis", "cortex_posture_misconfiguration", "posture"),
        ("identity", "identity", "cortex_identity_risk", "posture"),
        ("vulnerability", "vulnerability", "cortex_vulnerability_triage", "posture"),
        ("code_risk", "code_risk", "cortex_vulnerability_triage", "posture"),
        ("attack_path", "attack_path", "cortex_attack_path", "posture"),
        ("unknown", "unknown", "cortex_issue_reference", "verdict"),
    ],
)
def test_each_family_routes_to_its_skill(key, family, skill, mode):
    result = _route(ISSUES[key])
    assert (result["family"], result["skill"], result["assessment_mode"]) == (family, skill, mode)
    assert result["run_model"] == "true"
    assert "issue" in result["evidence_plan"]


def test_health_runs_no_model_and_loads_no_skill():
    result = _route(ISSUES["health"], skill_override="cortex_issue_reference")
    assert result["family"] == "health"
    assert result["run_model"] == "false"
    assert result["skill"] == ""
    assert result["assessment_mode"] == "none"
    # a route with no model has no skill to miss: the reason must not say an empty skill "is not available"
    assert "not available" not in result["reason"] and "skill ''" not in result["reason"]
    assert result["reason"] == "matched route '{}'".format(result["route_id"])
    assert "not available" not in _route(ISSUES["health"], enabled_skills=set())["reason"]


def test_unknown_issue_uses_the_default_row():
    result = _route(ISSUES["unknown"])
    assert result["route_id"] == "default"
    assert "no route matched" in result["reason"]


def test_signals_carry_the_ids_the_evidence_step_needs():
    result = _route(ISSUES["misconfiguration"])
    assert result["signals"]["rule_id"] == "rule-2"
    assert result["signals"]["asset_ids"] == ["asset-2-1", "asset-2-2"]
    assert result["signals"]["source"] == "cspm_scanner"


def test_source_wins_over_a_shared_category():
    # Both CSPM and Kubernetes policy issues are CONFIGURATION; the scanner decides.
    assert _route(ISSUES["kubernetes_cis"])["family"] == "kubernetes_cis"
    assert _route(ISSUES["misconfiguration"])["family"] == "misconfiguration"


def test_category_alone_is_enough_when_the_source_is_unknown():
    issue = json.loads(json.dumps(ISSUES["identity"]))
    issue["sourceBrand"] = "SOME_NEW_SCANNER"
    assert _route(issue)["family"] == "identity"


def test_field_names_tolerate_case_and_separators():
    issue = {"id": "1", "name": "x", "CustomFields": {"AlertDomain": "DOMAIN_POSTURE", "CategoryName": "Vulnerability"},
             "sourcebrand": "cas_cve_scanner"}
    assert _route(issue)["family"] == "vulnerability"


@pytest.mark.parametrize("bad", [None, "text", [], {"CustomFields": "oops"}, {"CustomFields": None}, {"CustomFields": {"family_tags": 5, "asset_ids": {"a": 1}}}])
def test_malformed_issue_falls_back_without_raising(bad):
    result = route.guardian_route_run(bad, table_contents=SHIPPED_TABLE, enabled_skills=ALL_SKILLS)
    assert result["family"] == "unknown"


def test_missing_list_uses_the_builtin_default():
    result = route.guardian_route_run(ISSUES["misconfiguration"], table_contents="not json", enabled_skills=ALL_SKILLS)
    assert result["family"] == "unknown"
    assert result["skill"] == "cortex_issue_reference"


def test_unavailable_skill_falls_back_and_says_so():
    result = _route(ISSUES["misconfiguration"], enabled_skills={"cortex_issue_reference", "cortex_case_investigation"})
    assert result["family"] == "misconfiguration"
    assert result["skill"] == "cortex_issue_reference"
    assert "not available" in result["reason"]


def test_only_the_old_skill_available_still_gives_a_skill():
    result = _route(ISSUES["detection"], enabled_skills={"cortex_case_investigation"})
    assert result["skill"] == "cortex_case_investigation"


def test_unreadable_skills_index_trusts_the_route():
    result = route.guardian_route_run(ISSUES["identity"], table_contents=SHIPPED_TABLE, enabled_skills=None)
    # enabled_skills=None triggers a real read; with no tenant the read fails and the route is trusted.
    assert result["skill"] == "cortex_identity_risk"


def test_operator_override_wins_and_is_reported():
    result = _route(ISSUES["attack_path"], skill_override="  my_skill ")
    assert result["skill"] == "my_skill"
    assert result["family"] == "attack_path"
    assert "playbook input" in result["reason"]


def test_first_matching_row_wins_and_unknown_keys_never_widen():
    table = json.dumps({"routes": [
        {"id": "a", "family": "misconfiguration", "skill": "s1", "match": {"mystery_key": ["x"]}},
        {"id": "b", "family": "identity", "skill": "s2", "match": {"name_contains": ["storage"]}},
        {"id": "c", "family": "vulnerability", "skill": "s3", "match": {}},
    ], "default": {"id": "d", "family": "unknown", "skill": "s4"}})
    result = route.guardian_route_run(ISSUES["misconfiguration"], table_contents=table, enabled_skills={"s1", "s2", "s3", "s4"})
    assert result["route_id"] == "b"


def test_family_tag_match_and_bad_assessment_mode():
    table = json.dumps({"routes": [
        {"id": "t", "family": "identity", "skill": "s", "assessment_mode": "weird", "match": {"family_tag_contains": ["cspm"]}},
    ]})
    result = route.guardian_route_run(ISSUES["misconfiguration"], table_contents=table, enabled_skills={"s"})
    assert result["route_id"] == "t"
    assert result["assessment_mode"] == "verdict"


def test_shipped_table_rows_are_well_formed():
    rows, default = route.guardian_route_parse_table(SHIPPED_TABLE)
    assert default and default["family"] == "unknown"
    ids = [r["id"] for r in rows]
    assert len(ids) == len(set(ids))
    for row in rows:
        assert row["match"], "a row with no match would catch every issue: " + row["id"]
        assert row["run_model"] is False or row["skill"]
        assert row["assessment_mode"] in route.GUARDIAN_ROUTE_ASSESSMENT_MODES


def test_main_overwrites_the_route_instead_of_appending(monkeypatch):
    written, results = [], []
    monkeypatch.setattr(route.demisto, "args", lambda: {})
    monkeypatch.setattr(route.demisto, "incident", lambda: {"id": "1", "CustomFields": {}})
    monkeypatch.setattr(route, "guardian_route_run", lambda incident, skill_override="": {
        "route_id": "identity", "family": "identity", "skill": "cortex_identity_risk", "assessment_mode": "posture",
        "run_model": "true", "reason": "r"})
    monkeypatch.setattr(route.demisto, "setContext", lambda path, value: written.append((path, value)))
    monkeypatch.setattr(route, "return_results", results.append)
    route.main()
    assert written == [("Guardian.Route", {"route_id": "identity", "family": "identity", "skill": "cortex_identity_risk",
                                           "assessment_mode": "posture", "run_model": "true", "reason": "r"})]
    # the same route is returned as the outputs, keyed by the route row so a re-run merges into one object
    assert results[0].outputs_prefix == "Guardian.Route" and results[0].outputs_key_field == "route_id"
    assert results[0].outputs == written[0][1] and "identity" in results[0].readable_output


# --- data-collection health issues get a model session; other health issues do not ---------------------------------------

def _health_issue(name, **custom):
    fields = {"alert_domain": "DOMAIN_HEALTH", "categoryname": "HEALTH", "family_tags": ["DOM:Health", "DS:ExampleVendor/ExampleProduct"],
              "ruleid": "rule-health", "_vendor": ["ExampleVendor"], "_product": ["ExampleProduct"]}
    fields.update(custom)
    return {"id": "2001", "name": name, "sourceBrand": "CORRELATION", "CustomFields": fields}


@pytest.mark.parametrize("name", [
    "Silent data source (ExampleVendor)", "Yield collapse: modeled events fell to zero", "Events misrouted to unknown",
    "Source stopped sending events", "No events from ExampleProduct in 24 hours", "Ingestion drop on ExampleProduct",
    "Parsing failure rate above threshold", "Modeling rule is not matching", "SILENT DATA SOURCE (EXAMPLEVENDOR)",
])
def test_a_data_collection_health_issue_routes_to_the_data_health_skill_in_posture_mode(name):
    result = _route(_health_issue(name))
    assert result["route_id"] == "data-health" and result["family"] == "data_health"
    assert result["skill"] == "cortex_data_health" and result["run_model"] == "true"
    assert result["assessment_mode"] == "posture"  # a posture block writes no threat verdict; mode `none` would accept either block
    assert result["evidence_plan"] == ["issue", "case", "prior_rules", "memory"]


@pytest.mark.parametrize("name", [
    "Example connector stopped reporting", "Collector certificate expires soon", "Engine disconnected", "License usage above 90 percent", "",
])
def test_any_other_health_issue_keeps_the_no_model_route(name):
    result = _route(_health_issue(name))
    assert result["route_id"] == "health" and result["run_model"] == "false" and result["skill"] == ""


def test_a_name_with_a_health_word_does_not_route_a_non_health_issue_to_the_data_health_skill():
    for domain in ("DOMAIN_SECURITY", "DOMAIN_POSTURE"):
        result = _route(_health_issue("Silent data source: ingestion parsing", alert_domain=domain, categoryname="", family_tags=[]))
        assert result["route_id"] != "data-health" and result["skill"] != "cortex_data_health", domain
    result = _route(dict(ISSUES["detection"], name="Ingestion of a payload from a silent data source"))
    assert result["family"] == "detection" and result["skill"] == "cortex_detection_investigation"


def test_the_data_health_row_comes_first_and_names_a_shipped_enabled_skill():
    rows = json.loads(SHIPPED_TABLE)["routes"]
    assert rows[0]["id"] == "data-health" and rows[0]["match"]["alert_domain"] == ["DOMAIN_HEALTH"]
    assert all(r["run_model"] is False for r in rows[1:4])
    assert [r["family"] for r in rows[1:4]] == ["health"] * 3  # the three no-model rows still follow it


def test_without_the_data_health_skill_the_route_falls_back_and_says_so():
    result = _route(_health_issue("Silent data source (ExampleVendor)"), enabled_skills=ALL_SKILLS - {"cortex_data_health"})
    assert result["route_id"] == "data-health" and result["skill"] == "cortex_issue_reference"
    assert "'cortex_data_health' is not available" in result["reason"]
