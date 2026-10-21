import json

import pytest

import GuardianTriageResult as tri

TABLE = tri.guardian_triage_default_table()
LONG_CONCLUSION = "The unsigned binary on the finance laptop beacons to a newly registered domain every five minutes. " * 2


def _block(**overrides):
    block = {
        "severity": "high",
        "investigation_type": "endpoint_threat",
        "confidence": 82,
        "likely_benign": False,
        "escalate": True,
        "summary": "An unsigned binary on a finance laptop beacons to a newly registered domain.",
        "key_entities": {"identities": [], "ips": [], "hosts": ["host-from-model"], "hashes": [], "domains": [], "urls": [],
                         "emails": []},
        "next_step": "Isolate the laptop and collect the binary.",
    }
    block.update(overrides)
    return block


def _fenced(block):
    return "{}\n```json\n{}\n```".format(LONG_CONCLUSION, json.dumps(block))


POSTURE_ROUTE = {"family": "vulnerability", "domain": "posture", "assessment_mode": "verdict"}
DETECTION_ROUTE = {"family": "endpoint", "domain": "detection", "assessment_mode": "verdict"}
INCIDENT = {"id": "1001", "name": "Example incident", "severity": 3, "CustomFields": {}}


def _run(loop, route=DETECTION_ROUTE, incident=INCIDENT, repair=None):
    return tri.guardian_triage_result_run(incident, route, loop, TABLE, repair=repair or _no_repair)


def _no_repair(conclusion, table, run_id):
    raise AssertionError("the repair call must not be made")


# --- domain and severity -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("route, domain", [
    ({"family": "endpoint"}, "detection"), ({"family": "phishing"}, "detection"), ({"family": "general"}, "detection"),
    ({"family": "vulnerability"}, "posture"), ({"family": "compliance"}, "posture"), ({"family": "Misconfiguration"}, "posture"),
    ({"family": "vulnerability", "domain": "detection"}, "detection"),   # the row's own domain wins
    ({"family": "endpoint", "domain": "POSTURE"}, "posture"),
    ({"family": "endpoint", "domain": "bogus"}, "detection"),             # an unknown domain name is ignored
    ({"family": "health"}, "unknown"), ({"family": "unknown"}, "unknown"), ({"family": ""}, "unknown"), ({"family": None}, "unknown"),
])
def test_domain_comes_from_the_route_row_then_its_family(route, domain):
    assert tri.guardian_triage_domain(route) == domain


def test_domain_of_a_missing_route_is_unknown():
    assert tri.guardian_triage_domain(None) == "unknown"
    assert tri.guardian_triage_domain([]) == "unknown"


@pytest.mark.parametrize("severity, label", [
    (1, "low"), (2, "medium"), (3, "high"), (4, "critical"), (0.5, "informational"), (0, "unknown"), (None, "unknown"),
    ("3", "high"), ("High", "high"), ("SEV_040_HIGH", "high"), ("critical", "critical"), ("bogus", "unknown"), (7, "unknown"), (2.5, "unknown"),
    (True, "unknown"),
])
def test_original_severity_maps_the_numeric_scale(severity, label):
    assert tri.guardian_triage_original_severity({"severity": severity}) == label


# --- shape checks ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("value, ok", [
    ("203.0.113.9", True), ("10.0.0.1", True), ("2001:db8::1", True), (" 8.8.8.8 ", True),
    ("999.1.1.1", False), ("1.2.3", False), ("example.com", False), ("", False), (None, False), (5, False), ("8.8.8.8; drop", False),
])
def test_ip_must_parse(value, ok):
    assert bool(tri.guardian_triage_check_ip(value)) is ok


@pytest.mark.parametrize("value, ok", [
    ("d41d8cd98f00b204e9800998ecf8427e", True),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", True),
    ("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", True),
    ("d41d8cd98f00b204e9800998ecf8427", False), ("z41d8cd98f00b204e9800998ecf8427e", False), ("", False), (None, False),
    ("d41d8cd98f00b204e9800998ecf8427e'", False),
])
def test_hash_is_32_40_or_64_hex(value, ok):
    assert bool(tri.guardian_triage_check_hash(value)) is ok


def test_hash_is_lowercased_and_cve_is_uppercased():
    assert tri.guardian_triage_check_hash("D41D8CD98F00B204E9800998ECF8427E") == "d41d8cd98f00b204e9800998ecf8427e"
    assert tri.guardian_triage_check_cve(" cve-2024-12345 ") == "CVE-2024-12345"
    assert tri.guardian_triage_check_cve("CVE-24-1") == ""


@pytest.mark.parametrize("value", ['a"b', "a'b", "a|b", "a;b", "a`b", "a{b", "a}b", "a\nb", "a\x00b", "a\x7fb", "", "   ", "x" * 513, None, 5, ["a"]])
def test_names_reject_quotes_pipes_semicolons_backticks_braces_control_characters_and_length(value):
    assert tri.guardian_triage_plain_name(value) == ""


@pytest.mark.parametrize("value", ["alice@example.com", "DOMAIN\\svc-deploy", "arn:aws:s3:::my-bucket/key", "web server 01", "x" * 512])
def test_ordinary_names_pass(value):
    assert tri.guardian_triage_plain_name("  " + value + " ") == value


# --- inputs from the incident ---------------------------------------------------------------------------------------

def test_inputs_are_read_from_the_incidents_own_fields_with_normalized_keys():
    incident = {"name": "Example", "CustomFields": {
        "SourceUserName": ["", "alice@example.com", "bob"],
        "sourceip": "203.0.113.9",
        "alertname": "Suspicious beacon",
        "hostname": "web-01",
        "filesha256": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "cve": "CVE-2024-0001",
        "domainname": "update-cdn.example",
        "urls": ["https://update-cdn.example/a"],
        "emailfrom": "Sender@Example.com",
    }}
    inputs = tri.guardian_triage_incident_inputs(incident)
    assert inputs == {"identity": "alice@example.com", "ip": "203.0.113.9", "rule_id": "Suspicious beacon", "host": "web-01",
                      "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "cve": "CVE-2024-0001",
                      "domain": "update-cdn.example", "url": "https://update-cdn.example/a", "email": "sender@example.com"}


def test_identity_priority_and_the_alternate_field_names():
    assert tri.guardian_triage_incident_inputs({"CustomFields": {"accountname": "x@y.z"}})["identity"] == "x@y.z"
    both = {"CustomFields": {"accountname": "second", "username": "first"}}
    assert tri.guardian_triage_incident_inputs(both)["identity"] == "first"
    assert tri.guardian_triage_incident_inputs({"CustomFields": {"src": "10.1.1.1"}})["ip"] == "10.1.1.1"
    assert tri.guardian_triage_incident_inputs({"CustomFields": {"devicename": "lt-7"}})["host"] == "lt-7"


def test_invalid_incident_values_are_dropped_and_a_list_gives_its_first_valid_value():
    incident = {"CustomFields": {"username": ["a|b", "ok-user"], "sourceip": "not-an-ip", "domainname": 'bad"name',
                                 "filesha256": "xyz", "ruleid": "", "emailfrom": "not an email"}}
    inputs = tri.guardian_triage_incident_inputs(incident)
    assert inputs["identity"] == "ok-user"
    assert inputs["ip"] == "" and inputs["domain"] == "" and inputs["hash"] == "" and inputs["rule_id"] == "" and inputs["email"] == ""


def test_the_cve_falls_back_to_the_incident_name():
    assert tri.guardian_triage_incident_inputs({"name": "Package foo has cve-2023-44487", "CustomFields": {}})["cve"] == "CVE-2023-44487"
    assert tri.guardian_triage_incident_inputs({"name": "No id here"})["cve"] == ""


def test_missing_or_odd_incident_gives_empty_strings():
    for incident in (None, {}, {"CustomFields": None}, "junk"):
        inputs = tri.guardian_triage_incident_inputs(incident)
        assert set(inputs) == set(tri.GUARDIAN_TRIAGE_INPUT_NAMES) and set(inputs.values()) == {""}


def test_model_entities_only_fill_empty_slots_and_are_shape_checked():
    incident_inputs = dict.fromkeys(tri.GUARDIAN_TRIAGE_INPUT_NAMES, "")
    incident_inputs["identity"] = "incident-user"
    entities = {"identities": ["model-user"], "ips": ["not-an-ip", "198.51.100.7"], "domains": ['bad"one', "evil.example"],
                "emails": ["a|b"], "hosts": ["host-1"], "hashes": ["zz", "d41d8cd98f00b204e9800998ecf8427e"],
                "urls": ["https://evil.example/x"]}
    inputs, sources = tri.guardian_triage_merge_inputs(incident_inputs, entities)
    assert inputs["identity"] == "incident-user" and sources["identity"] == "incident"  # the incident wins
    assert inputs["ip"] == "198.51.100.7" and sources["ip"] == "model"
    assert inputs["domain"] == "evil.example" and inputs["host"] == "host-1" and inputs["url"] == "https://evil.example/x"
    assert inputs["email"] == "" and sources["email"] == ""
    assert inputs["hash"] == "d41d8cd98f00b204e9800998ecf8427e" and inputs["sha256"] == ""
    assert inputs["rule_id"] == "" and inputs["cve"] == ""


def _incident_inputs_with(identity):
    inputs = dict.fromkeys(tri.GUARDIAN_TRIAGE_INPUT_NAMES, "")
    inputs["identity"] = identity
    return inputs


def test_a_domain_account_identity_is_replaced_by_the_models_upn_for_the_same_account():
    inputs, sources = tri.guardian_triage_merge_inputs(
        _incident_inputs_with("CORP\\Jdoe"), {"identities": ["other@example.test", "JDoe@Example.test"]})
    assert inputs["identity"] == "JDoe@Example.test"
    assert sources["identity"] == "model UPN with the same account name (domain not matched)"


def test_the_upn_whose_domain_contains_the_netbios_domain_is_preferred_and_the_source_says_so():
    entities = {"identities": ["jdoe@other.example.test", "JDoe@Corp.Example.test"]}
    inputs, sources = tri.guardian_triage_merge_inputs(_incident_inputs_with("corp\\jdoe"), entities)
    assert inputs["identity"] == "JDoe@Corp.Example.test"
    assert sources["identity"] == "model UPN with the same account name (domain matched)"


def test_without_a_domain_match_the_first_same_account_upn_is_used_and_the_source_says_it_did_not_match():
    entities = {"identities": ["other@corp.example.test", "jdoe@one.example.test", "jdoe@two.example.test"]}
    inputs, sources = tri.guardian_triage_merge_inputs(_incident_inputs_with("CORP\\jdoe"), entities)
    assert inputs["identity"] == "jdoe@one.example.test"
    assert sources["identity"] == "model UPN with the same account name (domain not matched)"
    assert tri.guardian_triage_matching_upn("CORP\\jdoe", []) == ("", False)
    assert tri.guardian_triage_matching_upn("jdoe@corp.example.test", ["jdoe@corp.example.test"]) == ("", False)


@pytest.mark.parametrize("model_identities", [
    [],
    ["someone-else@example.test"],           # a different account
    ["jdoe"],                                # not a UPN
    ["jdoe2@example.test", "xjdoe@example.test"],  # the local part must equal the account, not contain it
    ["CORP\\jdoe"],                          # not a UPN
    ["jdoe@"], ["@example.test"],            # malformed
    ['jd"oe@example.test'],                  # fails the plain-name check
])
def test_a_domain_account_identity_stays_when_the_model_has_no_matching_upn(model_identities):
    inputs, sources = tri.guardian_triage_merge_inputs(_incident_inputs_with("CORP\\jdoe"), {"identities": model_identities})
    assert inputs["identity"] == "CORP\\jdoe" and sources["identity"] == "incident"


def test_a_upn_straight_from_the_incident_is_used_as_is_and_a_plain_name_is_never_swapped():
    entities = {"identities": ["jdoe@example.test"]}
    inputs, sources = tri.guardian_triage_merge_inputs(_incident_inputs_with("jdoe@corp.example.test"), entities)
    assert inputs["identity"] == "jdoe@corp.example.test" and sources["identity"] == "incident"
    inputs, sources = tri.guardian_triage_merge_inputs(_incident_inputs_with("jdoe"), entities)
    assert inputs["identity"] == "jdoe" and sources["identity"] == "incident"
    # two backslashes, or a backslash and an @, is not a DOMAIN\account
    for odd in ("A\\B\\jdoe", "CORP\\jdoe@x"):
        inputs, _ = tri.guardian_triage_merge_inputs(_incident_inputs_with(odd), entities)
        assert inputs["identity"] == odd


def test_an_empty_incident_identity_still_takes_the_models_first_identity():
    inputs, sources = tri.guardian_triage_merge_inputs(_incident_inputs_with(""), {"identities": ["jdoe@example.test"]})
    assert inputs["identity"] == "jdoe@example.test" and sources["identity"] == "model"


def test_a_long_url_reaches_the_input_slot_whole_and_an_over_long_one_leaves_it_empty():
    url = "https://files.example.test/download/" + "x" * 250 + "?token=abc"
    empty = dict.fromkeys(tri.GUARDIAN_TRIAGE_INPUT_NAMES, "")
    cleaned = tri.guardian_triage_clean_entities({"urls": [url]})
    inputs, sources = tri.guardian_triage_merge_inputs(empty, cleaned)
    assert inputs["url"] == url and sources["url"] == "model"
    # too long for the cap: dropped by the cleaner, so the slot stays empty (a skipped lookup, not a cut-off value)
    cleaned = tri.guardian_triage_clean_entities({"urls": ["https://x.example/" + "q" * 600]})
    inputs, sources = tri.guardian_triage_merge_inputs(empty, cleaned)
    assert inputs["url"] == "" and sources["url"] == ""


# --- the decision ------------------------------------------------------------------------------------------------

def test_a_valid_block_in_the_loop_is_structured():
    record, note, cost = _run({"triage_block": _block(), "conclusion": LONG_CONCLUSION})
    assert record["status"] == "structured" and record["branch"] == "endpoint_threat"
    assert record["investigation_type"] == "endpoint_threat" and record["severity"] == "high"
    assert record["original_severity"] == "high" and record["confidence"] == 82 and record["escalate"] is True
    assert record["domain"] == "detection" and record["assessment_mode"] == "verdict" and record["domain_mismatch"] is False
    assert record["sub_playbook"] == "GuardianTriageEndpointThreat" and record["skill"] == "xsoar_case_investigation"
    assert record["inputs"]["host"] == "host-from-model" and record["input_sources"]["host"] == "model"
    assert note == "" and cost == 0.0


def test_a_block_in_the_conclusion_text_is_structured_even_when_the_loop_has_no_parsed_block():
    record, _n, _c = _run({"conclusion": _fenced(_block(severity="critical"))})
    assert record["status"] == "structured" and record["severity"] == "critical"


def test_an_invalid_parsed_block_in_the_loop_is_not_trusted():
    record, _n, _c = _run({"triage_block": {"severity": "urgent", "investigation_type": "endpoint_threat"}, "conclusion": _fenced(_block())})
    assert record["status"] == "structured" and record["severity"] == "high"  # re-parsed from the text instead


def test_a_missing_block_is_repaired_once():
    calls = []

    def repair(conclusion, table, run_id):
        calls.append((conclusion, run_id))
        return tri.guardian_triage_validate(_block(severity="medium")), "repair call produced a valid block", 0.002

    record, note, cost = _run({"conclusion": LONG_CONCLUSION}, repair=repair)
    assert calls == [(LONG_CONCLUSION, "1001")]
    assert record["status"] == "repaired" and record["severity"] == "medium" and record["branch"] == "endpoint_threat"
    assert "repair call produced a valid block" in record["reason"] and cost == 0.002


def test_a_failed_repair_falls_back_to_other_with_no_severity():
    record, note, _c = _run({"conclusion": LONG_CONCLUSION}, repair=lambda c, t, r: (None, "repair call failed: boom", 0.0))
    assert record["status"] == "fallback" and record["branch"] == "other" and record["investigation_type"] == ""
    assert record["severity"] == "" and record["confidence"] == 0 and record["likely_benign"] is False
    assert record["sub_playbook"] == "GuardianTriageOther" and record["skill"] == ""
    assert "repair call failed: boom" in record["reason"] and "analyst should review" in record["summary"]
    assert record["next_step"] and record["original_severity"] == "high"


@pytest.mark.parametrize("loop", [None, {}, {"conclusion": ""}, {"conclusion": "short"}, {"conclusion": 5}, {"triage_block": None}])
def test_no_usable_conclusion_falls_back_without_a_repair_call(loop):
    record, note, cost = _run(loop)  # _no_repair raises if the repair is attempted
    assert record["status"] == "fallback" and record["branch"] == "other" and note == "" and cost == 0.0
    assert "no usable conclusion" in record["reason"]


def test_a_type_outside_the_routes_domain_goes_to_other_with_a_reason():
    # A scanner finding the model called an identity threat (a detection type) must not run the identity branch.
    record, _n, _c = _run({"triage_block": _block(investigation_type="identity_threat")}, route=POSTURE_ROUTE)
    assert record["status"] == "structured" and record["branch"] == "other" and record["investigation_type"] == "identity_threat"
    assert record["domain_mismatch"] is True and "does not fit this incident's domain (posture)" in record["reason"]
    assert record["sub_playbook"] == "GuardianTriageOther" and record["skill"] == ""
    # and the reverse: a posture type on a detection
    record, _n, _c = _run({"triage_block": _block(investigation_type="vulnerability")}, route=DETECTION_ROUTE)
    assert record["branch"] == "other" and record["domain_mismatch"] is True and record["assessment_mode"] == "verdict"


def test_an_unknown_domain_sends_every_typed_answer_to_other_but_other_is_not_a_mismatch():
    record, _n, _c = _run({"triage_block": _block()}, route={"family": "unknown", "assessment_mode": "verdict"})
    assert record["branch"] == "other" and record["domain"] == "unknown" and record["domain_mismatch"] is True
    record, _n, _c = _run({"triage_block": _block(investigation_type="other")}, route=None)
    assert record["branch"] == "other" and record["domain_mismatch"] is False and record["assessment_mode"] == "verdict"


@pytest.mark.parametrize("route", [DETECTION_ROUTE, POSTURE_ROUTE])
def test_data_exposure_fits_both_domains_and_is_always_a_verdict_session(route):
    record, _n, _c = _run({"triage_block": _block(investigation_type="data_exposure")}, route=route)
    assert record["branch"] == "data_exposure" and record["assessment_mode"] == "verdict"
    assert record["skill"] == "xsoar_case_investigation" and record["sub_playbook"] == "GuardianTriageDataExposure"


def test_every_domain_valid_type_maps_to_its_sub_playbook_and_skill():
    for row in TABLE["types"]:
        if row["name"] == "other":
            continue
        domain = row["domains"][0]
        route = DETECTION_ROUTE if domain == "detection" else POSTURE_ROUTE
        record, _n, _c = _run({"triage_block": _block(investigation_type=row["name"])}, route=route)
        assert record["branch"] == row["name"] and record["sub_playbook"] == row["sub_playbook"]
        expected_skill = row["skill"] if isinstance(row["skill"], str) else row["skill"][domain]
        assert record["skill"] == expected_skill


def test_assessment_mode_is_always_verdict_in_this_edition():
    for route in (POSTURE_ROUTE, DETECTION_ROUTE, {"family": "endpoint", "assessment_mode": "posture"}, None):
        record, _n, _c = _run({"triage_block": _block(investigation_type="other")}, route=route)
        assert record["assessment_mode"] == "verdict"


def test_the_repair_prompt_defines_escalate_like_the_triage_skill():
    prompt = tri.guardian_triage_repair_prompt(TABLE)
    assert '"escalate": true only if it says a person must act within hours' in prompt
    for case in ("active compromise or hostile activity in progress", "an internet-exposed critical weakness in production",
                 "signs that a privileged identity is compromised or misused"):
        assert case in prompt
    assert "a privileged identity at risk" not in prompt
    assert "nor is a configuration weakness on a privileged account: delegatable, admin rights, unused permissions" in prompt
    assert "a posture finding for its owner to fix in the normal course is not an escalation" in prompt
    assert "look at it soon" not in prompt and "{severities}" not in prompt  # formatted, not left as a template


def test_inputs_come_from_the_incident_first_in_the_full_record():
    incident = dict(INCIDENT, CustomFields={"hostname": "host-from-incident", "alertname": "rule-1", "sourceip": "203.0.113.9"})
    record, _n, _c = _run({"triage_block": _block()}, incident=incident)
    assert record["inputs"]["host"] == "host-from-incident" and record["input_sources"]["host"] == "incident"
    assert record["inputs"]["rule_id"] == "rule-1" and record["inputs"]["ip"] == "203.0.113.9"
    assert set(record["inputs"]) == set(tri.GUARDIAN_TRIAGE_INPUT_NAMES) | {"sha256"}
    assert all(isinstance(v, str) for v in record["inputs"].values())


def test_the_record_has_exactly_the_documented_keys():
    record, _n, _c = _run({"triage_block": _block()})
    assert set(record) == {
        "incident_id", "status", "branch", "investigation_type", "severity", "original_severity", "confidence", "likely_benign", "escalate",
        "summary", "next_step", "domain", "assessment_mode", "sub_playbook", "skill", "reason", "inputs", "domain_mismatch",
        "input_sources"}
    json.dumps(record)  # serializable


# --- the repair call ---------------------------------------------------------------------------------------------

def _llm_reply(content, usage=None, model="m1", filtered=False):
    return {"Type": 1, "Contents": {
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}}],
        "usage": usage if usage is not None else {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
        "model": model, "content_filter": filtered}}


def _wire(monkeypatch, replies):
    """`replies` is a list of lists of entries, one per guardian-llm-chat call; the other commands are recorded."""
    seen = {"llm": [], "ledger": [], "audit": []}

    def execute(command, args):
        if command == "guardian-llm-chat":
            seen["llm"].append(dict(args))
            return replies[min(len(seen["llm"]) - 1, len(replies) - 1)]
        if command == "GuardianCostLedger":
            seen["ledger"].append(args)
            return [{"Type": 1, "Contents": {"usd": 0.001}}]
        if command == "GuardianAuditWrite":
            seen["audit"].append(args)
            return [{"Type": 1, "Contents": "ok"}]
        raise AssertionError("unexpected command " + command)

    monkeypatch.setattr(tri.demisto, "executeCommand", execute)
    return seen


def test_repair_sends_the_schema_and_only_the_conclusion_in_json_mode(monkeypatch):
    seen = _wire(monkeypatch, [[_llm_reply(json.dumps(_block(severity="low")))]])
    block, note, cost = tri.guardian_triage_repair(LONG_CONCLUSION, TABLE, "1001")

    assert block["severity"] == "low" and block["investigation_type"] == "endpoint_threat"
    assert "valid block" in note and cost == pytest.approx(0.001)
    assert len(seen["llm"]) == 1
    call = seen["llm"][0]
    assert call["response_format"] == {"type": "json_object"} and call["tool_choice"] == "none" and "tools" not in call
    system, user = call["messages"]
    assert system["role"] == "system" and user == {"role": "user", "content": LONG_CONCLUSION}
    for row in TABLE["types"]:
        assert row["name"] in system["content"]
    for severity in TABLE["severities"]:
        assert severity in system["content"]
    assert seen["ledger"][0]["trigger"] == tri.GUARDIAN_TRIAGE_REPAIR_TRIGGER and seen["ledger"][0]["model"] == "m1"


def test_repair_bounds_the_conclusion_it_sends(monkeypatch):
    seen = _wire(monkeypatch, [[_llm_reply(json.dumps(_block()))]])
    tri.guardian_triage_repair("x" * 50000, TABLE, "1")
    assert len(seen["llm"][0]["messages"][1]["content"]) == tri.GUARDIAN_TRIAGE_REPAIR_MAX_CHARS


def test_repair_retries_once_without_response_format_when_the_provider_errors(monkeypatch):
    seen = _wire(monkeypatch, [[{"Type": 4, "Contents": "response_format is not supported"}], [_llm_reply(json.dumps(_block()))]])
    block, note, _cost = tri.guardian_triage_repair(LONG_CONCLUSION, TABLE, "1")
    assert block is not None and "after a retry without JSON mode" in note
    assert len(seen["llm"]) == 2
    assert "response_format" in seen["llm"][0] and "response_format" not in seen["llm"][1]


def test_repair_gives_up_after_the_retry_fails_too(monkeypatch):
    seen = _wire(monkeypatch, [[{"Type": 4, "Contents": "boom"}]])
    block, note, cost = tri.guardian_triage_repair(LONG_CONCLUSION, TABLE, "1")
    assert block is None and note.startswith("repair call failed: boom") and cost == 0.0
    assert len(seen["llm"]) == 2  # never more than one retry


@pytest.mark.parametrize("content", ["", "not json at all", "{}", json.dumps(_block(severity="urgent")), json.dumps(_block(investigation_type="nope")),
                                     "[1, 2]"])
def test_repair_output_that_is_not_a_valid_block_gives_none(monkeypatch, content):
    _wire(monkeypatch, [[_llm_reply(content)]])
    block, note, _cost = tri.guardian_triage_repair(LONG_CONCLUSION, TABLE, "1")
    assert block is None and "not a valid triage block" in note


def test_repair_accepts_a_fenced_block_in_the_answer(monkeypatch):
    _wire(monkeypatch, [[_llm_reply("Here you go:\n```json\n{}\n```".format(json.dumps(_block())))]])
    assert tri.guardian_triage_repair(LONG_CONCLUSION, TABLE, "1")[0]["severity"] == "high"


def test_repair_treats_a_content_filter_block_as_a_failed_call(monkeypatch):
    _wire(monkeypatch, [[_llm_reply("", filtered=True)]])
    block, note, _cost = tri.guardian_triage_repair(LONG_CONCLUSION, TABLE, "1")
    assert block is None and "content filter" in note


def test_a_dict_without_a_completion_is_a_failed_call(monkeypatch):
    _wire(monkeypatch, [[{"Type": 1, "Contents": "just text"}]])
    assert tri.guardian_triage_repair(LONG_CONCLUSION, TABLE, "1")[0] is None


# --- main --------------------------------------------------------------------------------------------------------

def test_main_writes_the_record_with_setcontext_audits_it_and_reports(monkeypatch):
    seen = _wire(monkeypatch, [[_llm_reply(json.dumps(_block(severity="medium")))]])
    ctx = {"Guardian": {"Route": POSTURE_ROUTE, "Loop": {"conclusion": LONG_CONCLUSION, "triage_block": None}}}
    written, results = {}, []
    monkeypatch.setattr(tri.demisto, "context", lambda: ctx)
    monkeypatch.setattr(tri.demisto, "incident", lambda: INCIDENT)
    monkeypatch.setattr(tri.demisto, "setContext", lambda path, value: written.update({path: value}))
    monkeypatch.setattr(tri, "return_results", lambda r: results.append(r))
    # the taxonomy List is not wired, so the built-in table is used (the default executeCommand stub covers getList)
    original = tri.demisto.executeCommand

    def execute(command, args):
        if command == "getList":
            return [{"Type": 4, "Contents": "Item not found"}]
        return original(command, args)

    monkeypatch.setattr(tri.demisto, "executeCommand", execute)
    tri.main()

    record = written["Guardian.Triage"]
    assert record["status"] == "repaired" and record["severity"] == "medium"
    assert len(results) == 1 and "Guardian triage result" in results[0].readable_output
    assert len(seen["audit"]) == 1
    audit = seen["audit"][0]
    assert audit["action"] == "GuardianTriageResult" and audit["status"] == "ok" and audit["target"] == "1001"
    detail = json.loads(audit["detail"])
    assert detail["triage_status"] == "repaired" and detail["taxonomy"] == "default" and detail["repair_cost_usd"] == 0.001
    # the same record is returned as the task's outputs, keyed by the incident so a re-run merges into one object
    assert results[0].outputs_prefix == "Guardian.Triage" and results[0].outputs_key_field == "incident_id"
    assert results[0].outputs == record and record["incident_id"] == "1001"


def test_main_audits_a_fallback_as_an_error_row(monkeypatch):
    seen = _wire(monkeypatch, [[{"Type": 4, "Contents": "down"}]])
    written = {}
    monkeypatch.setattr(tri.demisto, "context", lambda: {"Guardian": {"Route": POSTURE_ROUTE, "Loop": {"conclusion": LONG_CONCLUSION}}})
    monkeypatch.setattr(tri.demisto, "incident", lambda: INCIDENT)
    monkeypatch.setattr(tri.demisto, "setContext", lambda path, value: written.update({path: value}))
    monkeypatch.setattr(tri, "return_results", lambda r: None)
    original = tri.demisto.executeCommand
    monkeypatch.setattr(tri.demisto, "executeCommand",
                        lambda c, a: [{"Type": 4, "Contents": "nf"}] if c == "getList" else original(c, a))
    tri.main()
    assert written["Guardian.Triage"]["status"] == "fallback"
    assert seen["audit"][0]["status"] == "error"


def test_main_uses_the_newest_loop_when_an_earlier_run_made_it_a_list(monkeypatch):
    _wire(monkeypatch, [[_llm_reply("{}")]])
    written = {}
    loops = [{"conclusion": "old"}, {"triage_block": _block(severity="critical"), "conclusion": LONG_CONCLUSION}]
    monkeypatch.setattr(tri.demisto, "context", lambda: {"Guardian": {"Route": [{"family": "x"}, POSTURE_ROUTE], "Loop": loops}})
    monkeypatch.setattr(tri.demisto, "incident", lambda: INCIDENT)
    monkeypatch.setattr(tri.demisto, "setContext", lambda path, value: written.update({path: value}))
    monkeypatch.setattr(tri, "return_results", lambda r: None)
    original = tri.demisto.executeCommand
    monkeypatch.setattr(tri.demisto, "executeCommand",
                        lambda c, a: [{"Type": 4, "Contents": "nf"}] if c == "getList" else original(c, a))
    tri.main()
    assert written["Guardian.Triage"]["severity"] == "critical" and written["Guardian.Triage"]["domain"] == "posture"


# --- review fixes: the repair call count, sha256, overflow ------------------------------------------------------------

@pytest.mark.parametrize("replies, expected_calls", [
    ([[_llm_reply(json.dumps(_block()))]], 1),                                   # valid answer: one call
    ([[_llm_reply("not json at all")]], 1),                                      # answered but invalid: no second request
    ([[_llm_reply("", filtered=True)]], 1),                                      # filtered completion is not a provider error
    ([[{"Type": 4, "Contents": "json mode rejected"}], [_llm_reply(json.dumps(_block()))]], 2),
    ([[{"Type": 4, "Contents": "boom"}]], 2),                                    # the retry fails too: still two at most
])
def test_repair_makes_one_request_and_a_second_only_after_a_provider_error(monkeypatch, replies, expected_calls):
    seen = _wire(monkeypatch, replies)
    tri.guardian_triage_repair(LONG_CONCLUSION, TABLE, "1")
    assert len(seen["llm"]) == expected_calls
    if expected_calls == 2:
        assert "response_format" in seen["llm"][0] and "response_format" not in seen["llm"][1]
    else:
        assert "response_format" in seen["llm"][0]


def test_sha256_is_the_hash_only_when_it_has_64_hex_characters():
    empty = dict.fromkeys(tri.GUARDIAN_TRIAGE_INPUT_NAMES, "")
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    inputs, sources = tri.guardian_triage_merge_inputs(dict(empty, hash=sha256), {})
    assert inputs["sha256"] == inputs["hash"] == sha256 and sources["sha256"] == "incident"
    for short in ("d41d8cd98f00b204e9800998ecf8427e", "da39a3ee5e6b4b0d3255bfef95601890afd80709"):
        inputs, sources = tri.guardian_triage_merge_inputs(dict(empty, hash=short), {})
        assert inputs["hash"] == short and inputs["sha256"] == "" and sources["sha256"] == ""
    inputs, sources = tri.guardian_triage_merge_inputs(empty, {"hashes": [sha256.upper()]})
    assert inputs["sha256"] == sha256 and sources["sha256"] == "model"
    inputs, _ = tri.guardian_triage_merge_inputs(empty, {})
    assert inputs["sha256"] == ""


@pytest.mark.parametrize("severity", ["inf", "Infinity", "-inf", "nan", "1e999", float("inf"), float("nan")])
def test_an_infinite_or_nan_incident_severity_is_unknown_not_a_crash(severity):
    assert tri.guardian_triage_original_severity({"severity": severity}) == "unknown"


def test_a_bare_json_conclusion_is_structured_and_makes_no_repair_call():
    for conclusion in (json.dumps(_block(severity="high")), "Looks public, so:\n" + json.dumps(_block(severity="high"))):
        record, note, cost = _run({"conclusion": conclusion})
        assert record["status"] == "structured" and record["severity"] == "high" and note == "" and cost == 0.0


def test_a_bare_json_conclusion_that_fails_validation_goes_to_repair():
    calls = []

    def repair(conclusion, table, run_id):
        calls.append(conclusion)
        return None, "repair output was not a valid triage block", 0.0

    record, _note, _cost = _run({"conclusion": json.dumps(_block(investigation_type="made_up")) + " " * 50}, repair=repair)
    assert len(calls) == 1 and record["status"] == "fallback" and record["branch"] == "other"


# --- the optional analysis, recommendations and complexity -----------------------------------------------------------

def test_a_block_without_analysis_or_recommendations_stays_structured_with_empty_values():
    record, _n, _c = _run({"triage_block": _block()})
    assert record["status"] == "structured" and record["analysis"] == "" and record["recommendations"] == []


def test_analysis_and_recommendations_reach_the_record():
    block = tri.guardian_triage_validate(_block(analysis="The sender domain was registered yesterday. " * 3,
                                                recommendations=["Block the sender", "Tell the recipients"]), TABLE)
    record, _n, _c = _run({"triage_block": block})
    assert record["status"] == "structured"
    assert record["analysis"].startswith("The sender domain was registered") and record["recommendations"] == ["Block the sender", "Tell the recipients"]


def test_a_fallback_record_has_empty_analysis_recommendations_and_complexity():
    record, _n, _c = _run({"conclusion": ""})
    assert record["status"] == "fallback" and record["analysis"] == "" and record["recommendations"] == [] and record["complexity"] == ""


def test_complexity_reaches_the_record_and_a_missing_or_invalid_one_is_empty_and_still_structured():
    block = tri.guardian_triage_validate(_block(complexity="high"), TABLE)
    record, _n, _c = _run({"triage_block": block})
    assert record["status"] == "structured" and record["complexity"] == "high"
    for value in (None, "", "extreme", 4):
        block = tri.guardian_triage_validate(_block(complexity=value), TABLE)
        record, _n, _c = _run({"triage_block": block})
        assert record["status"] == "structured" and record["complexity"] == ""


def test_the_repair_prompt_asks_for_the_optional_keys():
    prompt = tri.guardian_triage_repair_prompt(TABLE)
    assert '"analysis"' in prompt and '"recommendations"' in prompt and '"complexity"' in prompt


def test_the_record_has_exactly_the_documented_keys():
    record, _n, _c = _run({"triage_block": _block()})
    assert set(record) == {
        "incident_id", "status", "branch", "investigation_type", "severity", "original_severity", "confidence", "likely_benign",
        "escalate", "summary", "next_step", "analysis", "recommendations", "complexity", "domain", "assessment_mode", "sub_playbook",
        "skill", "reason", "inputs", "domain_mismatch", "input_sources"}
    json.dumps(record)


def test_the_yml_documents_the_optional_keys():
    import pathlib
    import yaml
    doc = yaml.safe_load((pathlib.Path(__file__).parent / "GuardianTriageResult.yml").read_text())
    paths = {o["contextPath"] for o in doc["outputs"]}
    assert {"Guardian.Triage.analysis", "Guardian.Triage.recommendations", "Guardian.Triage.complexity"} <= paths
