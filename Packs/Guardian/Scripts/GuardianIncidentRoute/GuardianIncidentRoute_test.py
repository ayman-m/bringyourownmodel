import json

import pytest

import GuardianIncidentRoute as route

TABLE = {
    "routes": [
        {"id": "phishing", "family": "phishing", "domain": "detection", "skill": "xsoar_case_investigation",
         "evidence_plan": ["incident", "indicators"], "match": {"type_contains": ["phish"]}},
        {"id": "vuln", "family": "vulnerability", "domain": "posture", "skill": "xsoar_case_investigation",
         "evidence_plan": ["incident"], "match": {"type": ["Vulnerability"]}},
        {"id": "edr", "family": "endpoint", "domain": "detection", "skill": "skill_edr",
         "match": {"source": ["Cortex XDR - IR"], "category": ["Malware"]}},
        {"id": "label", "family": "network", "skill": "xsoar_case_investigation", "match": {"label_contains": ["ids"]}},
        {"id": "simulation", "family": "simulation", "assessment_mode": "none", "match": {"type": ["Simulation"]}},
    ],
    "default": {"id": "default", "family": "general", "domain": "detection", "skill": "xsoar_case_investigation",
                "evidence_plan": ["incident"]},
}
ALL_SKILLS = {"xsoar_case_investigation", "skill_edr"}


def _route(incident, **kwargs):
    kwargs.setdefault("table_contents", TABLE)
    kwargs.setdefault("enabled_skills", ALL_SKILLS)
    return route.guardian_route_run(incident, **kwargs)


def test_a_type_substring_match_picks_the_row():
    out = _route({"type": "Phishing - Reported", "name": "Suspicious mail"})
    assert out["family"] == "phishing" and out["domain"] == "detection" and out["route_id"] == "phishing"
    assert out["evidence_plan"] == ["incident", "indicators"] and out["run_model"] == "true" and out["assessment_mode"] == "verdict"
    assert out["reason"] == "matched route 'phishing'"


def test_exact_keys_must_all_match_and_case_is_forgiven():
    incident = {"type": "Malware", "sourceBrand": "Cortex XDR - IR", "CustomFields": {"category": "malware"}}
    assert _route(incident)["family"] == "endpoint"
    incident["sourceBrand"] = "Other EDR"
    assert _route(incident)["family"] == "general"  # one key missing: the row does not match


def test_labels_are_matched_as_type_value_text():
    out = _route({"type": "Unclassified", "labels": [{"type": "Source", "value": "Snort IDS"}]})
    assert out["family"] == "network" and out["domain"] == "detection"  # a row without a domain is a detection


def test_a_posture_row_names_its_domain():
    assert _route({"type": "Vulnerability"})["domain"] == "posture"


def test_no_match_uses_the_default_row():
    out = _route({"type": "Something new"})
    assert out["family"] == "general" and out["route_id"] == "default" and out["reason"] == "no route matched; default route"


def test_a_none_assessment_runs_no_model_and_needs_no_skill():
    out = _route({"type": "Simulation"}, enabled_skills=set())
    assert out["run_model"] == "false" and out["skill"] == "" and "not available" not in out["reason"]


@pytest.mark.parametrize("contents", [None, "", "not json", "[]", 5, {"routes": "x"}, {}])
def test_an_unusable_table_falls_back_to_the_builtin_default(contents):
    out = route.guardian_route_run({"type": "Phishing"}, table_contents=contents, enabled_skills=None)
    assert out["family"] == "general" and out["domain"] == "detection" and out["skill"] == "xsoar_case_investigation"
    assert out["evidence_plan"] == route.GUARDIAN_ROUTE_BUILTIN_DEFAULT["evidence_plan"]


def test_a_table_given_as_json_text_is_read():
    assert _route({"type": "Phishing"}, table_contents=json.dumps(TABLE))["family"] == "phishing"


def test_a_missing_skill_falls_back_to_the_default_rows_and_says_so():
    out = _route({"type": "Malware", "sourceBrand": "Cortex XDR - IR", "category": "Malware"},
                 enabled_skills={"xsoar_case_investigation"})
    assert out["skill"] == "xsoar_case_investigation" and "skill 'skill_edr' is not available" in out["reason"]


def test_an_unreadable_skills_index_trusts_the_routed_skill():
    out = _route({"type": "Malware", "sourceBrand": "Cortex XDR - IR", "category": "Malware"}, enabled_skills=None)
    # enabled_skills=None makes the run read the List; with no List there it trusts the row
    assert out["skill"] in ("skill_edr",)


def test_the_override_wins_but_the_family_is_still_reported():
    out = _route({"type": "Phishing"}, skill_override=" my_skill ")
    assert out["skill"] == "my_skill" and out["family"] == "phishing" and "skill set by the playbook input" in out["reason"]


def test_an_unknown_match_key_never_widens_a_row():
    table = {"routes": [{"id": "x", "family": "x", "match": {"severity": ["high"]}}], "default": TABLE["default"]}
    assert _route({"type": "a", "severity": "high"}, table_contents=table)["family"] == "general"


def test_invalid_rows_are_dropped_and_bad_values_are_normalised():
    rows, default = route.guardian_route_parse_table({"routes": [
        {"family": ""}, "junk", {"family": "Data Exposure", "domain": "cloud", "assessment_mode": "posture", "run_model": "false"}],
        "default": None})
    assert default is None and len(rows) == 1
    row = rows[0]
    assert row["family"] == "data_exposure" and row["domain"] == "detection" and row["assessment_mode"] == "verdict"
    assert row["run_model"] is False and row["match"] == {}


def test_signals_carry_the_rule_and_the_main_entities():
    incident = {"type": "Authentication", "name": "Many failed logins", "sourceBrand": "Okta",
                "CustomFields": {"username": ["jdoe", "jdoe"], "sourceip": "203.0.113.9", "alertname": "Brute force",
                                 "hostname": "bad|host", "emailfrom": "a@b.example", "filehash": "x" * 300}}
    signals = route.guardian_route_signals(incident)
    assert signals["rule_id"] == "Brute force" and signals["source"] == "okta" and signals["type"] == "authentication"
    assert signals["entities"] == ["jdoe", "203.0.113.9", "a@b.example"]  # deduplicated; unsafe and over-long values dropped


def test_the_rule_falls_back_to_the_incident_name_and_entities_are_capped():
    fields = {name: "v-" + name for name in route.GUARDIAN_ROUTE_ENTITY_FIELDS}
    signals = route.guardian_route_signals({"name": "  Alert   name ", "CustomFields": fields})
    assert signals["rule_id"] == "Alert name" and len(signals["entities"]) == route.GUARDIAN_ROUTE_MAX_ENTITIES


@pytest.mark.parametrize("incident", [None, {}, "junk", {"CustomFields": None, "labels": "x"}])
def test_an_odd_incident_still_routes_to_the_default(incident):
    out = _route(incident)
    assert out["family"] == "general" and out["signals"]["entities"] == [] and out["signals"]["labels"] == []


def test_the_shipped_list_parses_and_every_row_has_a_family_domain_and_skill():
    from pathlib import Path
    shipped = json.loads((Path(__file__).resolve().parents[2] / "Lists" / "list-guardian_incident_routes.json").read_text())
    rows, default = route.guardian_route_parse_table(shipped["data"])
    assert rows and default and default["run_model"] is True
    for row in rows + [default]:
        assert row["family"] and row["domain"] in route.GUARDIAN_ROUTE_DOMAINS
        assert row["skill"] or row["run_model"] is False
