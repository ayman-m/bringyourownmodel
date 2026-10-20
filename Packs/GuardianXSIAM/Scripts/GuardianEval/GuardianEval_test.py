import json

import pytest

import GuardianEval as ge


# --- GUARDIAN_EVAL_CASES: case-library integrity (full library) ---------------


def test_case_library_integrity():
    cases = ge.GUARDIAN_EVAL_CASES
    assert 22 <= len(cases) <= 26

    ids = [c["case_id"] for c in cases]
    assert len(ids) == len(set(ids))                       # unique

    tech_re = __import__("re").compile(r"^T\d{4}(\.\d{3})?$")
    valid_verdicts = ("Malicious", "Suspicious", "Benign", "Inconclusive")
    verdict_counts = {v: 0 for v in valid_verdicts}
    for c in cases:
        assert set(c) >= {"case_id", "name", "details", "expected_verdict", "expected_techniques"}
        assert c["expected_verdict"] in valid_verdicts
        verdict_counts[c["expected_verdict"]] += 1
        assert all(tech_re.match(t) for t in c["expected_techniques"])

    assert all(count >= 3 for count in verdict_counts.values()), verdict_counts


# --- guardian_eval_case_by_id --------------------------------------------------


def test_case_by_id_returns_matching_case():
    case = ge.guardian_eval_case_by_id("cred-phish-okta-clone")
    assert case is not None
    assert case["case_id"] == "cred-phish-okta-clone"
    assert case["expected_verdict"] == "Malicious"


def test_case_by_id_returns_none_for_unknown_id():
    assert ge.guardian_eval_case_by_id("no-such-case") is None


# --- harvest candidate #18: runtime case store + guardian_eval_all_cases -------


def _runtime_case(case_id="harvested-100", **overrides):
    case = {
        "case_id": case_id,
        "name": "Harvested incident #100",
        "details": "Real investigation narrative here.",
        "expected_verdict": "Malicious",
        "expected_techniques": ["T1566"],
    }
    case.update(overrides)
    return case


def test_validate_case_shape_accepts_well_formed_case():
    ok, reason = ge._guardian_eval_validate_case_shape(_runtime_case())
    assert ok is True
    assert reason is None


def test_validate_case_shape_accepts_optional_expected_outcome():
    ok, _ = ge._guardian_eval_validate_case_shape(
        _runtime_case(expected_outcome=ge.GUARDIAN_EVAL_OUTCOME_NO_CONCLUSION)
    )
    assert ok is True


def test_validate_case_shape_rejects_non_dict():
    ok, reason = ge._guardian_eval_validate_case_shape("not a dict")
    assert ok is False and "not a dict" in reason


def test_validate_case_shape_rejects_missing_required_key():
    case = _runtime_case()
    del case["details"]
    ok, reason = ge._guardian_eval_validate_case_shape(case)
    assert ok is False and "details" in reason


def test_validate_case_shape_rejects_blank_case_id():
    ok, reason = ge._guardian_eval_validate_case_shape(_runtime_case(case_id="   "))
    assert ok is False and "case_id" in reason


def test_validate_case_shape_rejects_invalid_expected_verdict():
    ok, reason = ge._guardian_eval_validate_case_shape(_runtime_case(expected_verdict="Weaponized"))
    assert ok is False and "expected_verdict" in reason


def test_validate_case_shape_rejects_malformed_technique_id():
    ok, reason = ge._guardian_eval_validate_case_shape(_runtime_case(expected_techniques=["not-a-technique"]))
    assert ok is False and "expected_techniques" in reason


def test_validate_case_shape_rejects_unrecognized_expected_outcome():
    ok, reason = ge._guardian_eval_validate_case_shape(_runtime_case(expected_outcome="bogus"))
    assert ok is False and "expected_outcome" in reason


def test_load_runtime_cases_returns_valid_rows(monkeypatch):
    monkeypatch.setattr(
        ge.demisto, "executeCommand", _multi_command_stub({"getList": _list_contents(json.dumps([_runtime_case()]))})
    )
    cases = ge.guardian_eval_load_runtime_cases()
    assert len(cases) == 1
    assert cases[0]["case_id"] == "harvested-100"


def test_load_runtime_cases_skips_malformed_rows_without_crashing(monkeypatch):
    payload = json.dumps([_runtime_case(case_id="good-1"), {"case_id": "bad-1"}, "not even a dict"])
    monkeypatch.setattr(ge.demisto, "executeCommand", _multi_command_stub({"getList": _list_contents(payload)}))
    errors = []
    monkeypatch.setattr(ge.demisto, "error", lambda msg: errors.append(msg))

    cases = ge.guardian_eval_load_runtime_cases()

    assert [c["case_id"] for c in cases] == ["good-1"]
    assert len(errors) == 2  # one per skipped malformed row


def test_load_runtime_cases_unreadable_list_degrades_to_empty(monkeypatch):
    monkeypatch.setattr(
        ge.demisto, "executeCommand", _multi_command_stub({"getList": _list_contents("Item not found (8)", ok=False)})
    )
    assert ge.guardian_eval_load_runtime_cases() == []


def test_load_runtime_cases_bad_json_degrades_to_empty(monkeypatch):
    monkeypatch.setattr(ge.demisto, "executeCommand", _multi_command_stub({"getList": _list_contents("{not json")}))
    errors = []
    monkeypatch.setattr(ge.demisto, "error", lambda msg: errors.append(msg))
    assert ge.guardian_eval_load_runtime_cases() == []
    assert any("not valid JSON" in e for e in errors)


def test_all_cases_merges_static_and_runtime(monkeypatch):
    monkeypatch.setattr(
        ge.demisto, "executeCommand", _multi_command_stub({"getList": _list_contents(json.dumps([_runtime_case()]))})
    )
    all_cases = ge.guardian_eval_all_cases()
    assert len(all_cases) == len(ge.GUARDIAN_EVAL_CASES) + 1
    assert any(c["case_id"] == "harvested-100" for c in all_cases)


def test_all_cases_static_wins_on_case_id_collision(monkeypatch):
    colliding = _runtime_case(case_id="cred-phish-okta-clone", expected_verdict="Benign")
    monkeypatch.setattr(
        ge.demisto, "executeCommand", _multi_command_stub({"getList": _list_contents(json.dumps([colliding]))})
    )
    all_cases = ge.guardian_eval_all_cases()
    matches = [c for c in all_cases if c["case_id"] == "cred-phish-okta-clone"]
    assert len(matches) == 1  # never duplicated
    assert matches[0]["expected_verdict"] == "Malicious"  # the STATIC case's own value, not the runtime one


def test_case_by_id_finds_a_runtime_only_case(monkeypatch):
    monkeypatch.setattr(
        ge.demisto, "executeCommand", _multi_command_stub({"getList": _list_contents(json.dumps([_runtime_case()]))})
    )
    case = ge.guardian_eval_case_by_id("harvested-100")
    assert case is not None
    assert case["expected_verdict"] == "Malicious"


def test_run_launches_a_runtime_only_case(monkeypatch):
    def handle(command, args):
        if command == "getList":
            return _list_contents(json.dumps([_runtime_case()]))(args)
        if command == "createNewIncident":
            return [{"Type": 1, "Contents": "done"}]
        raise AssertionError("unexpected command {} {}".format(command, args))

    monkeypatch.setattr(ge.demisto, "executeCommand", handle)
    _rest_post_stub(
        monkeypatch,
        {
            "/incidents/search": lambda body: ge.guardian_envelope(True, data={"data": [{"id": "1", "version": 1}]}),
            "/incident/investigate": lambda body: ge.guardian_envelope(True, data={}),
        },
    )

    result = ge.guardian_eval_run(case_ids_filter={"harvested-100"})

    assert result["ok"] is True
    assert len(result["data"]["launched"]) == 1
    assert result["data"]["launched"][0]["case_id"] == "harvested-100"


# --- test fixtures ------------------------------------------------------------


def _multi_command_stub(handlers):
    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command: {} {}".format(command, args))
        return handlers[command](args)

    return fake_execute


def _rest_post_stub(monkeypatch, responses_by_uri):
    def fake(uri, body):
        if uri not in responses_by_uri:
            raise AssertionError("unexpected REST uri: {} {}".format(uri, body))
        return responses_by_uri[uri](body)

    monkeypatch.setattr(ge, "_guardian_rest_post", fake, raising=False)


def _list_contents(payload, ok=True):
    """A getList fake returning `payload` (already JSON-serialized) for
    whatever list name is asked. `ok=False` mirrors a not-found/error entry."""

    def handler(args):
        return [{"Type": 1 if ok else 4, "Contents": payload}]

    return handler


# --- guardian_eval_parse_case_id -------------------------------------------------


def test_parse_case_id_round_trips_with_build_name():
    name = ge.guardian_eval_build_name("cred-phish-okta-clone")
    assert ge.guardian_eval_parse_case_id(name) == "cred-phish-okta-clone"


def test_parse_case_id_returns_none_for_unrelated_name():
    assert ge.guardian_eval_parse_case_id("Some Other Incident") is None
    assert ge.guardian_eval_parse_case_id(None) is None


# --- guardian_eval_launch_case ---------------------------------------------------


def test_launch_case_creates_and_investigates_driver_incident(monkeypatch):
    create_calls = []

    def handle_create(args):
        create_calls.append(dict(args))
        return [{"Type": 1, "Contents": "done"}]

    monkeypatch.setattr(ge.demisto, "executeCommand", _multi_command_stub({"createNewIncident": handle_create}))

    investigate_calls = []

    def handle_search(body):
        return ge.guardian_envelope(True, data={"data": [{"id": "500", "version": 2}]})

    def handle_investigate(body):
        investigate_calls.append(body)
        return ge.guardian_envelope(True, data={"id": body["id"]})

    _rest_post_stub(monkeypatch, {"/incidents/search": handle_search, "/incident/investigate": handle_investigate})

    case = {
        "case_id": "cred-phish-okta-clone",
        "name": "Credential phishing - cloned Okta portal",
        "details": "narrative goes here",
        "expected_verdict": "Malicious",
        "expected_techniques": ["T1566"],
    }
    result = ge.guardian_eval_launch_case(case)
    assert result["ok"] is True
    assert result["data"]["incident_id"] == "500"
    assert result["data"]["case_id"] == "cred-phish-okta-clone"
    assert investigate_calls == [{"id": "500", "version": 2}]
    assert json.loads(create_calls[0]["customFields"]) == {"guardiantriggersource": "eval"}
    assert create_calls[0]["details"] == "narrative goes here"
    assert create_calls[0]["type"] == "Guardian Eval Case"


def test_launch_case_stamps_run_label_when_given(monkeypatch):
    # harvest candidate #11.
    create_calls = []
    monkeypatch.setattr(
        ge.demisto,
        "executeCommand",
        _multi_command_stub({"createNewIncident": lambda args: create_calls.append(dict(args)) or [{"Type": 1, "Contents": "done"}]}),
    )
    _rest_post_stub(
        monkeypatch,
        {
            "/incidents/search": lambda body: ge.guardian_envelope(True, data={"data": [{"id": "500", "version": 2}]}),
            "/incident/investigate": lambda body: ge.guardian_envelope(True, data={}),
        },
    )
    case = {"case_id": "cred-phish-okta-clone", "details": "narrative"}

    result = ge.guardian_eval_launch_case(case, run_label="baseline-cohere-small")

    assert result["ok"] is True
    assert result["data"]["run_label"] == "baseline-cohere-small"
    assert json.loads(create_calls[0]["customFields"]) == {
        "guardiantriggersource": "eval",
        "guardianevalrunlabel": "baseline-cohere-small",
    }


def test_launch_case_omits_run_label_field_when_not_given(monkeypatch):
    create_calls = []
    monkeypatch.setattr(
        ge.demisto,
        "executeCommand",
        _multi_command_stub({"createNewIncident": lambda args: create_calls.append(dict(args)) or [{"Type": 1, "Contents": "done"}]}),
    )
    _rest_post_stub(
        monkeypatch,
        {
            "/incidents/search": lambda body: ge.guardian_envelope(True, data={"data": [{"id": "500", "version": 2}]}),
            "/incident/investigate": lambda body: ge.guardian_envelope(True, data={}),
        },
    )
    case = {"case_id": "cred-phish-okta-clone", "details": "narrative"}

    result = ge.guardian_eval_launch_case(case)

    assert result["data"]["run_label"] is None
    assert "guardianevalrunlabel" not in json.loads(create_calls[0]["customFields"])


# --- guardian_eval_run -----------------------------------------------------------


def test_run_launches_all_cases_by_default(monkeypatch):
    monkeypatch.setattr(
        ge.demisto, "executeCommand", _multi_command_stub({"createNewIncident": lambda args: [{"Type": 1, "Contents": "done"}]})
    )
    counter = {"n": 0}

    def handle_search(body):
        counter["n"] += 1
        return ge.guardian_envelope(True, data={"data": [{"id": str(counter["n"]), "version": 1}]})

    _rest_post_stub(
        monkeypatch, {"/incidents/search": handle_search, "/incident/investigate": lambda body: ge.guardian_envelope(True, data={})}
    )

    result = ge.guardian_eval_run()
    assert result["ok"] is True
    assert len(result["data"]["launched"]) == len(ge.GUARDIAN_EVAL_CASES)


def test_run_restricts_to_case_ids_filter(monkeypatch):
    monkeypatch.setattr(
        ge.demisto, "executeCommand", _multi_command_stub({"createNewIncident": lambda args: [{"Type": 1, "Contents": "done"}]})
    )
    _rest_post_stub(
        monkeypatch,
        {
            "/incidents/search": lambda body: ge.guardian_envelope(True, data={"data": [{"id": "1", "version": 1}]}),
            "/incident/investigate": lambda body: ge.guardian_envelope(True, data={}),
        },
    )

    result = ge.guardian_eval_run(case_ids_filter={"cred-phish-okta-clone"})
    assert result["ok"] is True
    assert len(result["data"]["launched"]) == 1
    assert result["data"]["launched"][0]["case_id"] == "cred-phish-okta-clone"


def test_run_threads_run_label_to_every_launched_case(monkeypatch):
    # harvest candidate #11.
    create_calls = []
    monkeypatch.setattr(
        ge.demisto,
        "executeCommand",
        _multi_command_stub({"createNewIncident": lambda args: create_calls.append(dict(args)) or [{"Type": 1, "Contents": "done"}]}),
    )
    counter = {"n": 0}

    def handle_search(body):
        counter["n"] += 1
        return ge.guardian_envelope(True, data={"data": [{"id": str(counter["n"]), "version": 1}]})

    _rest_post_stub(
        monkeypatch, {"/incidents/search": handle_search, "/incident/investigate": lambda body: ge.guardian_envelope(True, data={})}
    )

    result = ge.guardian_eval_run(case_ids_filter={"cred-phish-okta-clone"}, run_label="candidate-cohere-medium")

    assert result["data"]["launched"][0]["run_label"] == "candidate-cohere-medium"
    assert json.loads(create_calls[0]["customFields"])["guardianevalrunlabel"] == "candidate-cohere-medium"


# --- guardian_eval_distinct_tools -------------------------------------------------


def test_distinct_tools_filters_by_run_id(monkeypatch):
    rows = [
        {"run_id": "42", "action": "ip"},
        {"run_id": "42", "action": "getEntries"},
        {"run_id": "42", "action": "ip"},  # duplicate action -- still one distinct entry
        {"run_id": "99", "action": "domain"},  # different run -- excluded
    ]
    monkeypatch.setattr(ge.demisto, "executeCommand", _multi_command_stub({"getList": _list_contents(json.dumps(rows))}))
    result = ge.guardian_eval_distinct_tools("42")
    assert result["ok"] is True
    assert result["data"]["distinct_tools"] == ["getEntries", "ip"]
    assert result["data"]["tool_call_count"] == 3


def test_distinct_tools_empty_when_audit_list_absent(monkeypatch):
    def handle_get_list(args):
        return [{"Type": 4, "Contents": "Item not found (8)"}]

    monkeypatch.setattr(ge.demisto, "executeCommand", _multi_command_stub({"getList": handle_get_list}))
    result = ge.guardian_eval_distinct_tools("42")
    assert result["ok"] is False


# --- guardian_eval_parse_techniques (reuses guardian_normalize_techniques) ---------


def test_parse_techniques_accepts_list_str_none():
    p = ge.guardian_normalize_techniques
    assert p(["T1566", "t1078.001", "bogus", ""]) == ["T1078", "T1566"]  # collapse+sort+filter
    assert p("T1566, T1114") == ["T1114", "T1566"]
    assert p(None) == []
    assert p("T1566") == ["T1566"]


# --- guardian_eval_load_audit_rows / guardian_eval_latency_seconds -----------------


def test_load_audit_rows_best_effort_empty_on_failure(monkeypatch):
    def handle_get_list(args):
        return [{"Type": 4, "Contents": "Item not found (8)"}]

    monkeypatch.setattr(ge.demisto, "executeCommand", _multi_command_stub({"getList": handle_get_list}))
    assert ge.guardian_eval_load_audit_rows() == []


def test_latency_from_audit_ledger(monkeypatch):
    rows = [
        {"run_id": "42", "ts": "2026-07-15T10:00:00Z"},
        {"run_id": "42", "ts": "2026-07-15T10:02:23Z"},
        {"run_id": "99", "ts": "2026-07-15T09:00:00Z"},
    ]
    monkeypatch.setattr(ge, "guardian_eval_load_audit_rows", lambda: rows)
    assert ge.guardian_eval_latency_seconds("42") == 143.0

    monkeypatch.setattr(ge, "guardian_eval_load_audit_rows", lambda: [{"run_id": "42", "ts": "2026-07-15T10:00:00Z"}])
    assert ge.guardian_eval_latency_seconds("42") is None  # <2 rows


def test_latency_handles_rfc3339nano_and_missing_run(monkeypatch):
    rows = [
        {"run_id": "42", "ts": "2026-07-15T10:00:00.123456789Z"},
        {"run_id": "42", "ts": "2026-07-15T10:00:02.987654321Z"},
    ]
    monkeypatch.setattr(ge, "guardian_eval_load_audit_rows", lambda: rows)
    # Both `ts` values truncate to 6 fractional digits before parsing
    # (.123456 / .987654) -- the 7th+ nanosecond digits are dropped, not
    # rounded, so the exact delta is 2.864198s, not a round 2.0s.
    assert ge.guardian_eval_latency_seconds("42") == pytest.approx(2.864198)
    assert ge.guardian_eval_latency_seconds("no-such-run") is None


# --- guardian_eval_score_one -------------------------------------------------------


def test_score_one_builds_expected_row(monkeypatch):
    monkeypatch.setattr(ge.demisto, "executeCommand", _multi_command_stub({"getList": _list_contents("[]")}))
    incident = {
        "id": "42",
        "name": "Guardian Eval - cred-phish-okta-clone - abc12345",
        "runStatus": "completed",
        "CustomFields": {"guardiantickcount": 2, "guardiancostusd": 0.005856, "guardianverdict": "Benign"},
    }
    result = ge.guardian_eval_score_one(incident)
    assert result["ok"] is True
    row = result["data"]
    assert row["case_id"] == "cred-phish-okta-clone"
    assert row["concluded"] is True
    assert row["failed"] is False
    assert row["tick_count"] == 2
    assert row["cost_usd"] == 0.005856
    assert row["actual_verdict"] == "Benign"
    assert row["actual_techniques"] == []
    assert row["latency_seconds"] is None  # no audit rows for this incident in this test
    assert row["passed"] is True
    assert row["run_label"] is None  # harvest candidate #11 -- absent CustomField
    assert "verdict" not in row
    assert "verdict_reached" not in row


def test_score_one_marks_failed_run_as_not_passed(monkeypatch):
    monkeypatch.setattr(ge.demisto, "executeCommand", _multi_command_stub({"getList": _list_contents("[]")}))
    incident = {"id": "43", "name": "Guardian Eval - cred-phish-okta-clone - xyz98765", "runStatus": "failed", "CustomFields": {}}
    result = ge.guardian_eval_score_one(incident)
    assert result["data"]["concluded"] is False
    assert result["data"]["failed"] is True
    assert result["data"]["passed"] is False
    assert result["data"]["actual_verdict"] is None


def test_score_one_reads_back_run_label_from_custom_field(monkeypatch):
    # harvest candidate #11.
    monkeypatch.setattr(ge.demisto, "executeCommand", _multi_command_stub({"getList": _list_contents("[]")}))
    incident = {
        "id": "44",
        "name": "Guardian Eval - cred-phish-okta-clone - aaaa1111",
        "runStatus": "completed",
        "CustomFields": {"guardianevalrunlabel": "baseline-cohere-small"},
    }
    result = ge.guardian_eval_score_one(incident)
    assert result["data"]["run_label"] == "baseline-cohere-small"


def test_score_row_records_raw_actuals(monkeypatch):
    inc = {
        "id": "42",
        "name": "Guardian Eval - cred-phish-okta-clone - abcd1234",
        "runStatus": "completed",
        "CustomFields": {
            "guardianverdict": "Malicious",
            "guardianattacktechniques": ["T1566"],
            "guardiancostusd": 0.014,
            "guardiantickcount": 6,
        },
    }
    monkeypatch.setattr(ge, "guardian_eval_latency_seconds", lambda i: 143.0)
    row = ge.guardian_eval_score_one(inc)["data"]
    assert row["actual_verdict"] == "Malicious"
    assert row["actual_techniques"] == ["T1566"]
    assert row["latency_seconds"] == 143.0
    assert "verdict_correct" not in row  # accuracy computed at REPORT time, not here


# --- guardian_eval_merge_row --------------------------------------------------------


def test_save_results_dedups_last_wins():
    existing = [{"incident_id": "42", "actual_verdict": None}]
    merged = ge.guardian_eval_merge_row(existing, {"incident_id": "42", "actual_verdict": "Malicious"})
    assert len(merged) == 1 and merged[0]["actual_verdict"] == "Malicious"


def test_merge_row_appends_when_incident_id_not_present():
    existing = [{"incident_id": "1", "actual_verdict": "Benign"}]
    merged = ge.guardian_eval_merge_row(existing, {"incident_id": "2", "actual_verdict": "Malicious"})
    assert len(merged) == 2
    assert [row["incident_id"] for row in merged] == ["1", "2"]


# --- guardian_eval_score: full sweep ----------------------------------------------


def test_score_scans_and_scores_concluded_incidents_only(monkeypatch):
    incidents = [
        {"id": "1", "name": "Guardian Eval - cred-phish-okta-clone - aaaaaaaa", "runStatus": "completed", "CustomFields": {"guardiantickcount": 2}},
        {"id": "2", "name": "Guardian Eval - vuln-scan-known-infra - bbbbbbbb", "runStatus": "running", "CustomFields": {}},
    ]

    def handle(command, args):
        if command == "getList" and args["listName"] == ge.GUARDIAN_EVAL_RESULTS_LIST:
            return [{"Type": 4, "Contents": "Item not found (8)"}]
        if command == "getList" and args["listName"] == ge.GUARDIAN_EVAL_AUDIT_LIST:
            return [{"Type": 1, "Contents": "[]"}]
        if command == "createList":
            handle.saved = json.loads(args["listData"])
            return [{"Type": 1, "Contents": "created"}]
        raise AssertionError("unexpected command {} {}".format(command, args))

    monkeypatch.setattr(ge.demisto, "executeCommand", handle)
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: ge.guardian_envelope(True, data={"data": incidents})})

    result = ge.guardian_eval_score()
    assert result["ok"] is True
    assert len(result["data"]["scored"]) == 1
    assert result["data"]["scored"][0]["incident_id"] == "1"
    assert result["data"]["still_running"] == [{"incident_id": "2", "run_status": "running"}]
    assert handle.saved[0]["incident_id"] == "1"


def test_score_skips_already_scored_incidents_idempotently(monkeypatch):
    existing_rows = [{"incident_id": "1", "case_id": "cred-phish-okta-clone", "actual_verdict": "Benign"}]
    incidents = [{"id": "1", "name": "Guardian Eval - cred-phish-okta-clone - aaaaaaaa", "runStatus": "completed", "CustomFields": {}}]

    def handle(command, args):
        if command == "getList" and args["listName"] == ge.GUARDIAN_EVAL_RESULTS_LIST:
            return [{"Type": 1, "Contents": json.dumps(existing_rows)}]
        if command == "createList":
            raise AssertionError("must not write -- nothing new to score")
        raise AssertionError("unexpected command {} {}".format(command, args))

    monkeypatch.setattr(ge.demisto, "executeCommand", handle)
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: ge.guardian_envelope(True, data={"data": incidents})})

    result = ge.guardian_eval_score()
    assert result["ok"] is True
    assert result["data"]["scored"] == []
    assert result["data"]["already_scored"] == ["1"]


def test_score_rescoring_allowed_when_prior_actual_verdict_is_none(monkeypatch):
    """A row scored while the run had no verdict yet (`actual_verdict is
    None`) must NOT permanently block re-scoring -- the next pass should
    overwrite it in place (via `guardian_eval_merge_row`), never append a
    2nd row for the same incident."""
    existing_rows = [{"incident_id": "1", "case_id": "cred-phish-okta-clone", "actual_verdict": None}]
    incidents = [
        {
            "id": "1",
            "name": "Guardian Eval - cred-phish-okta-clone - aaaaaaaa",
            "runStatus": "completed",
            "CustomFields": {"guardianverdict": "Malicious"},
        }
    ]

    def handle(command, args):
        if command == "getList" and args["listName"] == ge.GUARDIAN_EVAL_RESULTS_LIST:
            return [{"Type": 1, "Contents": json.dumps(existing_rows)}]
        if command == "getList" and args["listName"] == ge.GUARDIAN_EVAL_AUDIT_LIST:
            return [{"Type": 1, "Contents": "[]"}]
        if command == "createList":
            handle.saved = json.loads(args["listData"])
            return [{"Type": 1, "Contents": "created"}]
        raise AssertionError("unexpected command {} {}".format(command, args))

    monkeypatch.setattr(ge.demisto, "executeCommand", handle)
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: ge.guardian_envelope(True, data={"data": incidents})})

    result = ge.guardian_eval_score()
    assert result["ok"] is True
    assert len(result["data"]["scored"]) == 1
    assert result["data"]["already_scored"] == []
    assert len(handle.saved) == 1  # replaced in place, never appended
    assert handle.saved[0]["actual_verdict"] == "Malicious"


def test_score_with_explicit_incident_ids_bypasses_tag_scan(monkeypatch):
    def handle(command, args):
        if command == "getList" and args["listName"] == ge.GUARDIAN_EVAL_RESULTS_LIST:
            return [{"Type": 4, "Contents": "Item not found (8)"}]
        if command == "getList" and args["listName"] == ge.GUARDIAN_EVAL_AUDIT_LIST:
            return [{"Type": 1, "Contents": "[]"}]
        if command == "createList":
            return [{"Type": 1, "Contents": "created"}]
        raise AssertionError("unexpected command {} {}".format(command, args))

    monkeypatch.setattr(ge.demisto, "executeCommand", handle)

    def handle_search(body):
        assert body["filter"]["id"] == ["7"]
        return ge.guardian_envelope(
            True, data={"data": [{"id": "7", "name": "Guardian Eval - cred-phish-okta-clone - aaaaaaaa", "runStatus": "completed", "CustomFields": {}}]}
        )

    _rest_post_stub(monkeypatch, {"/incidents/search": handle_search})

    result = ge.guardian_eval_score(incident_ids_filter=["7"])
    assert result["ok"] is True
    assert len(result["data"]["scored"]) == 1


# --- action=report: math helpers (pinned definitions, task-5 brief) -----------------


def test_percentile_linear_interpolation():
    p = ge._guardian_pct
    assert p([10.0], 90) == 10.0                       # n==1
    assert p([], 50) is None                           # n==0
    assert p([1.0, 2.0, 3.0, 4.0], 50) == 2.5          # linear interp, even n
    assert p([1.0, 2.0, 3.0, 4.0], 90) == 3.7


def test_percentile_sorts_input_defensively():
    # Callers need not pre-sort -- _guardian_pct sorts internally, and does
    # so consistently regardless of the input's own ordering.
    assert ge._guardian_pct([4.0, 1.0, 3.0, 2.0], 50) == 2.5
    assert ge._guardian_pct([4.0, 1.0, 3.0, 2.0], 90) == 3.7


def test_f1_guards_disjoint_and_zero():
    f = ge._guardian_f1
    assert f(0.0, 0.0) == 0.0                           # disjoint non-empty -> no ZeroDivision
    assert f(1.0, 1.0) == 1.0
    assert round(f(0.5, 1.0), 3) == 0.667


def test_wilson_ci_small_n():
    lo, hi = ge._guardian_wilson(8, 10)
    assert 0.0 <= lo < 0.8 < hi <= 1.0


def test_wilson_zero_n_returns_zero_zero():
    assert ge._guardian_wilson(0, 0) == (0.0, 0.0)


def test_wilson_perfect_score_bounds_stay_in_unit_interval():
    lo, hi = ge._guardian_wilson(5, 5)
    assert 0.0 <= lo <= 1.0 and 0.0 <= hi <= 1.0


# --- action=report: verdict normalization / bucketing --------------------------------


def test_verdict_bucket_normalizes_case_and_whitespace():
    b = ge._guardian_eval_verdict_bucket
    assert b("malicious") == "Malicious"
    assert b("  SUSPICIOUS  ") == "Suspicious"
    assert b("Benign") == "Benign"
    assert b("inconclusive") == "Inconclusive"


def test_verdict_bucket_other_for_unrecognized_nonempty_value():
    assert ge._guardian_eval_verdict_bucket("Weaponized") == "Other"


def test_verdict_bucket_none_for_absent_or_empty():
    assert ge._guardian_eval_verdict_bucket(None) == "None"
    assert ge._guardian_eval_verdict_bucket("   ") == "None"
    assert ge._guardian_eval_verdict_bucket("") == "None"


# --- guardian_eval_find_scoreable_incidents pagination ---------------------------------


def test_find_scoreable_incidents_paginates_past_the_page_size(monkeypatch):
    """LIVE-CAUGHT: a single unpaginated size=100 call silently dropped every
    eval incident past the 100th, from both scoring and the launched-count,
    with no error -- the 35-case library at k=3 shots (105 incidents)
    already exceeds it. Mock a >page-size corpus split across pages and
    confirm every record comes back, not just the first page."""
    page_size = ge.GUARDIAN_EVAL_FIND_SCOREABLE_PAGE_SIZE
    all_incidents = [{"id": str(i)} for i in range(page_size + 5)]

    def handler(body):
        page = body["filter"]["page"]
        size = body["filter"]["size"]
        start = page * size
        return ge.guardian_envelope(True, data={"data": all_incidents[start:start + size]})

    _rest_post_stub(monkeypatch, {"/incidents/search": handler})

    result = ge.guardian_eval_find_scoreable_incidents()
    assert result["ok"] is True
    assert [r["id"] for r in result["data"]] == [i["id"] for i in all_incidents]


def test_find_scoreable_incidents_stops_at_the_first_short_page(monkeypatch):
    calls = []

    def handler(body):
        calls.append(body["filter"]["page"])
        return ge.guardian_envelope(True, data={"data": [{"id": "1"}, {"id": "2"}]})

    _rest_post_stub(monkeypatch, {"/incidents/search": handler})

    result = ge.guardian_eval_find_scoreable_incidents()
    assert result["ok"] is True
    assert len(result["data"]) == 2
    assert calls == [0]  # never fetches a second page once one comes back short


def test_find_scoreable_incidents_propagates_a_mid_scan_failure(monkeypatch):
    page_size = ge.GUARDIAN_EVAL_FIND_SCOREABLE_PAGE_SIZE

    def handler(body):
        if body["filter"]["page"] == 0:
            return ge.guardian_envelope(True, data={"data": [{"id": str(i)} for i in range(page_size)]})
        return ge.guardian_envelope(False, error="boom", retryable=True)

    _rest_post_stub(monkeypatch, {"/incidents/search": handler})

    result = ge.guardian_eval_find_scoreable_incidents()
    assert result["ok"] is False
    assert result["error"] == "boom"


# --- action=report: guardian_eval_count_launched --------------------------------------


def test_count_launched_uses_live_eval_tag_scan(monkeypatch):
    incidents = [{"id": "1"}, {"id": "2"}, {"id": "3"}]
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: ge.guardian_envelope(True, data={"data": incidents})})
    assert ge.guardian_eval_count_launched() == 3


def test_count_launched_best_effort_zero_on_scan_failure(monkeypatch):
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: ge.guardian_envelope(False, error="boom")})
    assert ge.guardian_eval_count_launched() == 0


def test_count_launched_filters_by_run_label(monkeypatch):
    # harvest candidate #11.
    incidents = [
        {"id": "1", "CustomFields": {"guardianevalrunlabel": "baseline"}},
        {"id": "2", "CustomFields": {"guardianevalrunlabel": "baseline"}},
        {"id": "3", "CustomFields": {"guardianevalrunlabel": "candidate"}},
        {"id": "4", "CustomFields": {}},
    ]
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: ge.guardian_envelope(True, data={"data": incidents})})

    assert ge.guardian_eval_count_launched(run_label="baseline") == 2
    assert ge.guardian_eval_count_launched(run_label="candidate") == 1
    assert ge.guardian_eval_count_launched(run_label="no-such-label") == 0
    assert ge.guardian_eval_count_launched() == 4  # unscoped -- every launch, unchanged


def test_count_launched_filters_by_case_ids_via_name_convention(monkeypatch):
    """LIVE-CAUGHT: incidents carry no dedicated case_id CustomField --
    only guardian_eval_build_name's `"Guardian Eval - {case_id} - {hex8}"`
    naming convention. count_launched must parse that to scope by
    case_ids, the same way it already scopes by run_label."""
    incidents = [
        {"id": "1", "name": "Guardian Eval - m1 - a1b2c3d4", "CustomFields": {}},
        {"id": "2", "name": "Guardian Eval - m1 - e5f6a7b8", "CustomFields": {}},
        {"id": "3", "name": "Guardian Eval - b1 - 11223344", "CustomFields": {}},
        {"id": "4", "name": "some hand-created incident", "CustomFields": {}},
    ]
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: ge.guardian_envelope(True, data={"data": incidents})})

    assert ge.guardian_eval_count_launched(case_ids={"m1"}) == 2
    assert ge.guardian_eval_count_launched(case_ids={"b1"}) == 1
    assert ge.guardian_eval_count_launched(case_ids={"m1", "b1"}) == 3
    assert ge.guardian_eval_count_launched(case_ids={"no-such-case"}) == 0
    assert ge.guardian_eval_count_launched() == 4  # unscoped -- every launch, unchanged


def test_count_launched_combines_run_label_and_case_ids_as_and(monkeypatch):
    incidents = [
        {"id": "1", "name": "Guardian Eval - m1 - a1b2c3d4", "CustomFields": {"guardianevalrunlabel": "baseline"}},
        {"id": "2", "name": "Guardian Eval - m1 - e5f6a7b8", "CustomFields": {"guardianevalrunlabel": "candidate"}},
        {"id": "3", "name": "Guardian Eval - b1 - 11223344", "CustomFields": {"guardianevalrunlabel": "baseline"}},
    ]
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: ge.guardian_envelope(True, data={"data": incidents})})

    assert ge.guardian_eval_count_launched(run_label="baseline", case_ids={"m1"}) == 1  # only incident 1
    assert ge.guardian_eval_count_launched(run_label="baseline", case_ids={"m1", "b1"}) == 2  # incidents 1 and 3


def test_report_data_scopes_count_launched_to_case_ids_not_the_whole_corpus(monkeypatch):
    """The actual bug: a case_ids-restricted report used to divide its
    case_ids-filtered concluded_count by an UNFILTERED, tenant-wide
    count_launched -- two different populations. Exercise the real (not
    monkeypatched) guardian_eval_count_launched via guardian_eval_report_data
    to prove the fix reaches all the way through."""
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": None, "latency_seconds": None, "tick_count": None},
        {"case_id": "b1", "concluded": True, "actual_verdict": "Benign", "actual_techniques": [],
         "cost_usd": None, "latency_seconds": None, "tick_count": None},
    ]
    cases = (
        {"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},
        {"case_id": "b1", "expected_verdict": "Benign", "expected_techniques": []},
    )
    monkeypatch.setattr(ge, "guardian_eval_load_results", lambda: rows)
    monkeypatch.setattr(ge, "GUARDIAN_EVAL_CASES", tuple(cases))
    incidents = [
        {"id": "1", "name": "Guardian Eval - m1 - a1b2c3d4", "CustomFields": {}},
        {"id": "2", "name": "Guardian Eval - b1 - e5f6a7b8", "CustomFields": {}},
        {"id": "3", "name": "Guardian Eval - other-case - 11223344", "CustomFields": {}},
    ]
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: ge.guardian_envelope(True, data={"data": incidents})})

    data = ge.guardian_eval_report_data(case_ids={"m1"})
    assert data["concluded_count"] == 1
    assert data["count_launched"] == 1  # scoped to case m1's own launch, NOT all 3 incidents
    assert data["concluded_rate"] == 1.0


# --- action=report: guardian_eval_report_data / guardian_eval_report ------------------


def _stub_report(monkeypatch, rows, cases, count_launched=None):
    """Wire the 3 report-time collaborators a report test needs: the scored
    rows, the (possibly overridden) case library, and the live
    guardiantriggersource=eval launched-count -- mirrors the brief's own
    `test_report_binary_accuracy_and_matrix` fixture."""
    monkeypatch.setattr(ge, "guardian_eval_load_results", lambda: rows)
    monkeypatch.setattr(ge, "GUARDIAN_EVAL_CASES", tuple(cases))
    monkeypatch.setattr(
        ge,
        "guardian_eval_count_launched",
        lambda run_label=None, case_ids=None: len(rows) if count_launched is None else count_launched,
    )


def _stub_labeled_report(monkeypatch, rows, cases, count_launched_by_label=None):
    """harvest candidate #11: like `_stub_report`, but `guardian_eval_count_launched`
    is run_label-aware -- `count_launched_by_label` maps a run_label (or
    `None` for the unscoped call) to the count to return; a label not
    present in the map falls back to counting `rows` carrying that label
    (or all `rows` when `run_label` is `None`)."""
    monkeypatch.setattr(ge, "guardian_eval_load_results", lambda: rows)
    monkeypatch.setattr(ge, "GUARDIAN_EVAL_CASES", tuple(cases))
    counts = count_launched_by_label or {}

    def fake_count_launched(run_label=None, case_ids=None):
        if run_label in counts:
            return counts[run_label]
        if run_label is None:
            return len(rows)
        return len([r for r in rows if r.get("run_label") == run_label])

    monkeypatch.setattr(ge, "guardian_eval_count_launched", fake_count_launched)


def test_report_binary_accuracy_and_matrix(monkeypatch):
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious",
         "actual_techniques": ["T1566"], "cost_usd": 0.01, "latency_seconds": 100.0, "tick_count": 5},
        {"case_id": "b1", "concluded": True, "actual_verdict": "Benign",
         "actual_techniques": [], "cost_usd": 0.02, "latency_seconds": 50.0, "tick_count": 3},
        {"case_id": "m2", "concluded": True, "actual_verdict": "Benign",   # a miss
         "actual_techniques": [], "cost_usd": 0.03, "latency_seconds": 80.0, "tick_count": 4},
    ]
    monkeypatch.setattr(ge, "guardian_eval_load_results", lambda: rows)
    monkeypatch.setattr(ge, "guardian_eval_count_launched", lambda run_label=None, case_ids=None: 3)
    monkeypatch.setattr(ge, "GUARDIAN_EVAL_CASES", (
        {"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": ["T1566"]},
        {"case_id": "b1", "expected_verdict": "Benign", "expected_techniques": []},
        {"case_id": "m2", "expected_verdict": "Malicious", "expected_techniques": ["T1078"]}))
    md = ge.guardian_eval_report()
    assert "Binary malicious-detection accuracy" in md
    assert "2/3" in md or "66.7%" in md      # m1 correct, b1 correct, m2 wrong


def test_report_data_full_metrics(monkeypatch):
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious",
         "actual_techniques": ["T1566"], "cost_usd": 0.01, "latency_seconds": 100.0, "tick_count": 5},
        {"case_id": "b1", "concluded": True, "actual_verdict": "Benign",
         "actual_techniques": [], "cost_usd": 0.02, "latency_seconds": 50.0, "tick_count": 3},
        {"case_id": "m2", "concluded": True, "actual_verdict": "Benign",
         "actual_techniques": [], "cost_usd": 0.03, "latency_seconds": 80.0, "tick_count": 4},
    ]
    cases = (
        {"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": ["T1566"]},
        {"case_id": "b1", "expected_verdict": "Benign", "expected_techniques": []},
        {"case_id": "m2", "expected_verdict": "Malicious", "expected_techniques": ["T1078"]},
    )
    _stub_report(monkeypatch, rows, cases, count_launched=3)

    data = ge.guardian_eval_report_data()
    assert data["count_launched"] == 3
    assert data["concluded_count"] == 3
    assert data["concluded_rate"] == 1.0
    assert data["n_v"] == 3
    assert data["verdict_production_rate"] == 1.0
    assert data["binary_correct"] == 2
    assert data["binary_accuracy"] == pytest.approx(2 / 3)
    assert data["majority_baseline"] == pytest.approx(2 / 3)
    assert data["confusion_matrix"]["Malicious"]["Malicious"] == 1
    assert data["confusion_matrix"]["Malicious"]["Benign"] == 1
    assert data["confusion_matrix"]["Benign"]["Benign"] == 1
    assert sum(sum(cols.values()) for cols in data["confusion_matrix"].values()) == 3
    assert data["exact_correct"] == 2
    assert data["exact_accuracy"] == pytest.approx(2 / 3)
    assert data["technique_case_count"] == 2   # m1, m2 -- both |E|>0; b1 excluded (|E|==0)
    assert data["technique_f1_mean"] == pytest.approx(0.5)
    assert data["restraint_total"] == 1
    assert data["restraint_correct"] == 1
    assert data["benign_restraint"] == 1.0
    assert data["cost_usd"]["available"] == 3
    assert data["cost_usd"]["mean"] == pytest.approx(0.02)
    assert data["cost_usd"]["median"] == pytest.approx(0.02)
    assert data["cost_usd"]["max"] == pytest.approx(0.03)
    assert data["cost_usd"]["p90"] is None  # n<10
    assert data["latency_seconds"]["mean"] == pytest.approx(230.0 / 3)
    assert data["tick_count"]["max"] == 5
    # harvest candidate #12: no expected_outcome=no_conclusion cases in this
    # fixture -- the new metric must be a clean, empty no-op.
    assert data["regression_no_conclusion_total"] == 0
    assert data["regression_no_conclusion_correct"] == 0
    assert data["regression_no_conclusion_rate"] is None


def test_report_filters_to_case_ids_arg(monkeypatch):
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": None, "latency_seconds": None, "tick_count": None},
        {"case_id": "b1", "concluded": True, "actual_verdict": "Benign", "actual_techniques": [],
         "cost_usd": None, "latency_seconds": None, "tick_count": None},
    ]
    cases = (
        {"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},
        {"case_id": "b1", "expected_verdict": "Benign", "expected_techniques": []},
    )
    _stub_report(monkeypatch, rows, cases, count_launched=2)

    data = ge.guardian_eval_report_data(case_ids={"m1"})
    assert data["rows_count"] == 1
    assert data["n_v"] == 1
    assert data["rows"][0]["case_id"] == "m1"


def test_report_drops_rows_for_unknown_case_id(monkeypatch):
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": None, "latency_seconds": None, "tick_count": None},
        {"case_id": "retired-case", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": None, "latency_seconds": None, "tick_count": None},
    ]
    cases = ({"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},)
    _stub_report(monkeypatch, rows, cases, count_launched=2)

    data = ge.guardian_eval_report_data()
    assert data["rows_count"] == 1
    assert data["rows"][0]["case_id"] == "m1"


def test_report_excludes_concluded_rows_with_no_verdict_from_n_v(monkeypatch):
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": None, "latency_seconds": None, "tick_count": None},
        {"case_id": "b1", "concluded": True, "actual_verdict": None, "actual_techniques": [],  # verdict not written yet
         "cost_usd": None, "latency_seconds": None, "tick_count": None},
    ]
    cases = (
        {"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},
        {"case_id": "b1", "expected_verdict": "Benign", "expected_techniques": []},
    )
    _stub_report(monkeypatch, rows, cases, count_launched=2)

    data = ge.guardian_eval_report_data()
    assert data["concluded_count"] == 2
    assert data["n_v"] == 1                       # only m1 has a verdict
    assert data["verdict_production_rate"] == pytest.approx(0.5)


def test_report_unrecognized_verdict_buckets_as_other_and_counts_as_a_miss(monkeypatch):
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Weaponized", "actual_techniques": [],
         "cost_usd": None, "latency_seconds": None, "tick_count": None},
    ]
    cases = ({"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},)
    _stub_report(monkeypatch, rows, cases, count_launched=1)

    data = ge.guardian_eval_report_data()
    assert data["n_v"] == 1
    assert data["confusion_matrix"]["Malicious"]["Other"] == 1
    assert data["binary_correct"] == 0     # "Other" != malicious, but expected IS malicious -> mismatch


def test_report_invalid_expected_verdict_is_skipped_not_raised(monkeypatch):
    """A typo'd/miscased `expected_verdict` in the case library must not
    KeyError indexing `confusion_matrix` (its outer keys are only the 4
    valid labels) -- it's recorded (via `demisto.error`) and excluded from
    the matrix/binary/exact tallies, while `n_v` (computed from the actual
    side only) still counts the row and the matrix-total invariant check
    still holds because `invalid_expected_verdict_count` covers it."""
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": None, "latency_seconds": None, "tick_count": None},
        {"case_id": "bad1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": None, "latency_seconds": None, "tick_count": None},
    ]
    cases = (
        {"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},
        {"case_id": "bad1", "expected_verdict": "Malicous", "expected_techniques": []},  # typo -- not a valid label
    )
    _stub_report(monkeypatch, rows, cases, count_launched=2)
    errors = []
    monkeypatch.setattr(ge.demisto, "error", lambda *a: errors.append(" ".join(str(x) for x in a)))

    data = ge.guardian_eval_report_data()  # must not raise

    assert data["n_v"] == 2                # both rows are still concluded-with-verdict
    assert data["binary_correct"] == 1     # only m1 is scoreable; bad1 excluded from the tally
    assert sum(sum(cols.values()) for cols in data["confusion_matrix"].values()) == 1
    assert data["confusion_matrix"]["Malicious"]["Malicious"] == 1
    assert errors and "case_id=bad1" in errors[0]

    md = ge.guardian_eval_render_report(data)  # rendering over this data must also not raise
    assert isinstance(md, str) and md


def test_report_p90_present_when_n_at_least_10(monkeypatch):
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": float(i), "latency_seconds": float(i), "tick_count": i}
        for i in range(1, 11)
    ]
    cases = ({"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},)
    _stub_report(monkeypatch, rows, cases, count_launched=10)

    data = ge.guardian_eval_report_data()
    assert data["cost_usd"]["available"] == 10
    assert data["cost_usd"]["p90"] == ge._guardian_pct([float(i) for i in range(1, 11)], 90)
    md = ge.guardian_eval_render_report(data)
    assert "n/a (n<10)" not in md


def test_report_handles_zero_launched_and_zero_concluded(monkeypatch):
    _stub_report(monkeypatch, [], (), count_launched=0)

    data = ge.guardian_eval_report_data()
    assert data["count_launched"] == 0
    assert data["concluded_count"] == 0
    assert data["concluded_rate"] == 0.0
    assert data["n_v"] == 0
    assert data["verdict_production_rate"] == 0.0
    assert data["binary_accuracy"] == 0.0
    assert data["majority_baseline"] == 0.0
    assert data["technique_f1_mean"] is None
    assert data["benign_restraint"] is None

    md = ge.guardian_eval_render_report(data)
    assert isinstance(md, str) and md  # renders without raising / dividing by zero


def test_report_per_case_table_renders_em_dash_for_null_metrics(monkeypatch):
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": None, "latency_seconds": None, "tick_count": None},
    ]
    cases = ({"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},)
    _stub_report(monkeypatch, rows, cases, count_launched=1)

    md = ge.guardian_eval_report()
    assert "—" in md


# --- harvest candidate #11: run_label grouping / repeat aggregation / compare --------


def test_report_data_rows_param_overrides_load_results(monkeypatch):
    loaded_rows = [{"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
                     "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1}]
    override_rows = [{"case_id": "b1", "concluded": True, "actual_verdict": "Benign", "actual_techniques": [],
                       "cost_usd": 0.02, "latency_seconds": 2.0, "tick_count": 2}]
    cases = (
        {"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},
        {"case_id": "b1", "expected_verdict": "Benign", "expected_techniques": []},
    )
    monkeypatch.setattr(ge, "guardian_eval_load_results", lambda: loaded_rows)
    monkeypatch.setattr(ge, "GUARDIAN_EVAL_CASES", cases)
    monkeypatch.setattr(ge, "guardian_eval_count_launched", lambda run_label=None, case_ids=None: 1)

    data = ge.guardian_eval_report_data(rows=override_rows)

    assert data["rows"] == override_rows  # NOT loaded_rows -- the override won


def test_report_data_by_run_label_filters_rows_and_scopes_denominator(monkeypatch):
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"},
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"},
        {"case_id": "m1", "concluded": True, "actual_verdict": "Benign", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "candidate"},
    ]
    cases = ({"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},)
    _stub_labeled_report(monkeypatch, rows, cases, count_launched_by_label={"baseline": 2, "candidate": 1})

    baseline_data = ge.guardian_eval_report_data_by_run_label("baseline")
    assert baseline_data["rows_count"] == 2
    assert baseline_data["count_launched"] == 2
    assert baseline_data["n_v"] == 2
    assert baseline_data["binary_accuracy"] == 1.0

    candidate_data = ge.guardian_eval_report_data_by_run_label("candidate")
    assert candidate_data["rows_count"] == 1
    assert candidate_data["count_launched"] == 1
    assert candidate_data["binary_accuracy"] == 0.0  # expected Malicious, actual Benign


def test_report_data_by_run_label_empty_group_never_crashes(monkeypatch):
    rows = [{"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
             "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"}]
    cases = ({"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},)
    _stub_labeled_report(monkeypatch, rows, cases)

    data = ge.guardian_eval_report_data_by_run_label("no-such-label")

    assert data["rows_count"] == 0
    assert data["n_v"] == 0
    assert data["binary_accuracy"] == 0.0
    assert data["concluded_rate"] == 0.0


def test_compare_runs_reports_deltas_and_flags_moved_metrics(monkeypatch):
    rows = [
        # baseline: 1/2 correct -> binary_accuracy 0.5
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"},
        {"case_id": "m2", "concluded": True, "actual_verdict": "Benign", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"},
        # candidate: 2/2 correct -> binary_accuracy 1.0 (delta +0.5, clears 0.20 floor)
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "candidate"},
        {"case_id": "m2", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "candidate"},
    ]
    cases = (
        {"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},
        {"case_id": "m2", "expected_verdict": "Malicious", "expected_techniques": []},
    )
    _stub_labeled_report(monkeypatch, rows, cases, count_launched_by_label={"baseline": 2, "candidate": 2})

    data = ge.guardian_eval_compare_runs("baseline", "candidate")

    assert data["baseline_label"] == "baseline"
    assert data["candidate_label"] == "candidate"
    assert data["min_delta"] == ge.GUARDIAN_EVAL_COMPARE_MIN_DELTA
    assert data["either_side_is_anecdotal"] is False  # n_v=2 on both sides

    binary_metric = next(m for m in data["metrics"] if m["key"] == "binary_accuracy")
    assert binary_metric["baseline_value"] == pytest.approx(0.5)
    assert binary_metric["candidate_value"] == pytest.approx(1.0)
    assert binary_metric["delta"] == pytest.approx(0.5)
    assert binary_metric["moved"] is True

    # concluded_rate is 1.0 on both sides -- unmoved.
    concluded_metric = next(m for m in data["metrics"] if m["key"] == "concluded_rate")
    assert concluded_metric["delta"] == pytest.approx(0.0)
    assert concluded_metric["moved"] is False

    assert "rows" not in data["baseline"]  # stripped, mirrors action=report's own convention
    assert "rows" not in data["candidate"]


def test_compare_runs_delta_below_noise_floor_is_not_flagged_moved(monkeypatch):
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"},
        {"case_id": "m2", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"},
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "candidate"},
        {"case_id": "m2", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "candidate"},
    ]
    cases = (
        {"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},
        {"case_id": "m2", "expected_verdict": "Malicious", "expected_techniques": []},
    )
    _stub_labeled_report(monkeypatch, rows, cases, count_launched_by_label={"baseline": 2, "candidate": 2})

    data = ge.guardian_eval_compare_runs("baseline", "candidate")

    binary_metric = next(m for m in data["metrics"] if m["key"] == "binary_accuracy")
    assert binary_metric["delta"] == pytest.approx(0.0)
    assert binary_metric["moved"] is False


def test_compare_runs_flags_anecdotal_when_either_side_has_n_v_le_1(monkeypatch):
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"},
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "candidate"},
        {"case_id": "m2", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "candidate"},
    ]
    cases = (
        {"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},
        {"case_id": "m2", "expected_verdict": "Malicious", "expected_techniques": []},
    )
    _stub_labeled_report(monkeypatch, rows, cases, count_launched_by_label={"baseline": 1, "candidate": 2})

    data = ge.guardian_eval_compare_runs("baseline", "candidate")

    assert data["baseline"]["n_v"] == 1
    assert data["either_side_is_anecdotal"] is True


def test_compare_runs_empty_group_never_crashes(monkeypatch):
    rows = [{"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
             "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"}]
    cases = ({"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},)
    _stub_labeled_report(monkeypatch, rows, cases, count_launched_by_label={"baseline": 1})

    data = ge.guardian_eval_compare_runs("baseline", "no-such-label")

    assert data["candidate"]["n_v"] == 0
    assert data["either_side_is_anecdotal"] is True
    for metric in data["metrics"]:
        assert metric["moved"] in (True, False)  # never raises building the table


def test_compare_runs_missing_metric_value_never_coerces_delta_to_zero(monkeypatch):
    # benign_restraint is None when a side has no |E|==0 cases at all -- must
    # stay None (delta undefined), never silently treated as 0.0.
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": ["T1566"],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"},
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": ["T1566"],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "candidate"},
    ]
    cases = ({"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": ["T1566"]},)
    _stub_labeled_report(monkeypatch, rows, cases, count_launched_by_label={"baseline": 1, "candidate": 1})

    data = ge.guardian_eval_compare_runs("baseline", "candidate")

    restraint_metric = next(m for m in data["metrics"] if m["key"] == "benign_restraint")
    assert restraint_metric["baseline_value"] is None
    assert restraint_metric["candidate_value"] is None
    assert restraint_metric["delta"] is None
    assert restraint_metric["moved"] is False


def test_compare_runs_respects_min_delta_override(monkeypatch):
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"},
        {"case_id": "m2", "concluded": True, "actual_verdict": "Benign", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"},
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "candidate"},
        {"case_id": "m2", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "candidate"},
    ]
    cases = (
        {"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},
        {"case_id": "m2", "expected_verdict": "Malicious", "expected_techniques": []},
    )
    _stub_labeled_report(monkeypatch, rows, cases, count_launched_by_label={"baseline": 2, "candidate": 2})

    # delta is +0.5 -- a tighter 0.60 floor should NOT flag it moved.
    data = ge.guardian_eval_compare_runs("baseline", "candidate", min_delta=0.60)
    assert data["min_delta"] == 0.60
    binary_metric = next(m for m in data["metrics"] if m["key"] == "binary_accuracy")
    assert binary_metric["moved"] is False


def test_render_compare_includes_anecdote_warning_when_flagged(monkeypatch):
    rows = [{"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
             "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"}]
    cases = ({"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},)
    _stub_labeled_report(monkeypatch, rows, cases, count_launched_by_label={"baseline": 1, "candidate": 0})

    md = ge.guardian_eval_compare("baseline", "candidate")

    assert "Guardian Eval Compare: baseline (baseline) vs candidate (candidate)" in md
    assert "WARNING" in md and "anecdote" in md
    assert "| Metric | Baseline | Candidate | Delta | Moved" in md


def test_render_compare_no_warning_when_both_sides_repeat_tested(monkeypatch):
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"},
        {"case_id": "m2", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"},
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "candidate"},
        {"case_id": "m2", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "candidate"},
    ]
    cases = (
        {"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},
        {"case_id": "m2", "expected_verdict": "Malicious", "expected_techniques": []},
    )
    _stub_labeled_report(monkeypatch, rows, cases, count_launched_by_label={"baseline": 2, "candidate": 2})

    md = ge.guardian_eval_compare("baseline", "candidate")
    assert "WARNING" not in md


# --- harvest candidate #12: expected_outcome="no_conclusion" regression cases --------


def test_expects_no_conclusion_true_for_matching_case(monkeypatch):
    monkeypatch.setattr(
        ge, "GUARDIAN_EVAL_CASES", ({"case_id": "nc1", "expected_verdict": "Inconclusive",
                                      "expected_techniques": [], "expected_outcome": "no_conclusion"},)
    )
    assert ge._guardian_eval_expects_no_conclusion("nc1") is True


def test_expects_no_conclusion_false_for_ordinary_case(monkeypatch):
    monkeypatch.setattr(
        ge, "GUARDIAN_EVAL_CASES", ({"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},)
    )
    assert ge._guardian_eval_expects_no_conclusion("m1") is False


def test_expects_no_conclusion_false_for_unknown_case_id(monkeypatch):
    monkeypatch.setattr(ge, "GUARDIAN_EVAL_CASES", ())
    assert ge._guardian_eval_expects_no_conclusion("no-such-case") is False


def test_report_data_no_conclusion_case_correct_when_run_never_concludes(monkeypatch):
    rows = [{"case_id": "nc1", "concluded": False, "actual_verdict": None, "actual_techniques": [],
             "cost_usd": 0.01, "latency_seconds": 10.0, "tick_count": 5}]
    cases = ({"case_id": "nc1", "expected_verdict": "Inconclusive", "expected_techniques": [],
              "expected_outcome": ge.GUARDIAN_EVAL_OUTCOME_NO_CONCLUSION},)
    _stub_report(monkeypatch, rows, cases, count_launched=1)

    data = ge.guardian_eval_report_data()

    assert data["regression_no_conclusion_total"] == 1
    assert data["regression_no_conclusion_correct"] == 1
    assert data["regression_no_conclusion_rate"] == 1.0
    # Never enters the verdict-accuracy pipeline -- it never concluded, so it
    # was never in with_verdict_rows/n_v anyway.
    assert data["n_v"] == 0
    assert data["binary_accuracy"] == 0.0


def test_report_data_no_conclusion_case_incorrect_when_model_concludes_anyway(monkeypatch):
    # The regression scenario this candidate exists to catch: the model
    # SHOULD have held back but produced a confident verdict instead.
    rows = [{"case_id": "nc1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
             "cost_usd": 0.01, "latency_seconds": 10.0, "tick_count": 5}]
    cases = ({"case_id": "nc1", "expected_verdict": "Inconclusive", "expected_techniques": [],
              "expected_outcome": ge.GUARDIAN_EVAL_OUTCOME_NO_CONCLUSION},)
    _stub_report(monkeypatch, rows, cases, count_launched=1)

    data = ge.guardian_eval_report_data()

    assert data["regression_no_conclusion_total"] == 1
    assert data["regression_no_conclusion_correct"] == 0
    assert data["regression_no_conclusion_rate"] == 0.0
    # CRITICAL: even though this row DID conclude with a verdict, it must
    # still be excluded from the ordinary accuracy pipeline -- its
    # expected_verdict="Inconclusive" is a schema placeholder, not a real
    # comparison target, and must never silently pollute the confusion
    # matrix / binary accuracy with a meaningless cell.
    assert data["n_v"] == 0
    assert data["binary_accuracy"] == 0.0
    assert sum(sum(cols.values()) for cols in data["confusion_matrix"].values()) == 0


def test_report_data_no_conclusion_case_never_pollutes_ordinary_accuracy_math(monkeypatch):
    # A no_conclusion case mixed in alongside ordinary cases must leave the
    # ordinary cases' own accuracy numbers byte-for-byte identical to running
    # without it at all.
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": ["T1566"],
         "cost_usd": 0.01, "latency_seconds": 100.0, "tick_count": 5},
        {"case_id": "b1", "concluded": True, "actual_verdict": "Benign", "actual_techniques": [],
         "cost_usd": 0.02, "latency_seconds": 50.0, "tick_count": 3},
        {"case_id": "nc1", "concluded": True, "actual_verdict": "Suspicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 10.0, "tick_count": 5},
    ]
    cases = (
        {"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": ["T1566"]},
        {"case_id": "b1", "expected_verdict": "Benign", "expected_techniques": []},
        {"case_id": "nc1", "expected_verdict": "Inconclusive", "expected_techniques": [],
         "expected_outcome": ge.GUARDIAN_EVAL_OUTCOME_NO_CONCLUSION},
    )
    _stub_report(monkeypatch, rows, cases, count_launched=3)

    data = ge.guardian_eval_report_data()

    assert data["n_v"] == 2  # m1, b1 only -- nc1 excluded
    assert data["binary_correct"] == 2
    assert data["binary_accuracy"] == 1.0
    assert sum(sum(cols.values()) for cols in data["confusion_matrix"].values()) == 2
    assert data["regression_no_conclusion_total"] == 1
    assert data["regression_no_conclusion_correct"] == 0  # nc1 concluded -> incorrect


def test_render_report_no_conclusion_section_na_when_none_scored(monkeypatch):
    _stub_report(monkeypatch, [], (), count_launched=0)
    md = ge.guardian_eval_report()
    assert "Regression: expected no-conclusion cases" in md
    assert "n/a (no expected_outcome=no_conclusion cases scored)" in md


def test_render_report_no_conclusion_section_shows_rate_when_scored(monkeypatch):
    rows = [{"case_id": "nc1", "concluded": False, "actual_verdict": None, "actual_techniques": [],
             "cost_usd": None, "latency_seconds": None, "tick_count": None}]
    cases = ({"case_id": "nc1", "expected_verdict": "Inconclusive", "expected_techniques": [],
              "expected_outcome": ge.GUARDIAN_EVAL_OUTCOME_NO_CONCLUSION},)
    _stub_report(monkeypatch, rows, cases, count_launched=1)

    md = ge.guardian_eval_report()
    assert "1/1" in md and "100.0%" in md


# --- main() ------------------------------------------------------------------------


def test_main_run_action(monkeypatch):
    monkeypatch.setattr(
        ge.demisto, "executeCommand", _multi_command_stub({"createNewIncident": lambda args: [{"Type": 1, "Contents": "done"}]})
    )
    _rest_post_stub(
        monkeypatch,
        {
            "/incidents/search": lambda body: ge.guardian_envelope(True, data={"data": [{"id": "1", "version": 1}]}),
            "/incident/investigate": lambda body: ge.guardian_envelope(True, data={}),
        },
    )
    monkeypatch.setattr(ge.demisto, "args", lambda: {"action": "run"})
    captured = {}
    monkeypatch.setattr(ge, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    ge.main()

    assert "result" in captured
    assert captured["result"].outputs_prefix == "Guardian.Eval.Run"


def test_main_score_action(monkeypatch):
    def handle(command, args):
        if command == "getList" and args["listName"] == ge.GUARDIAN_EVAL_RESULTS_LIST:
            return [{"Type": 4, "Contents": "Item not found (8)"}]
        raise AssertionError("unexpected command {} {}".format(command, args))

    monkeypatch.setattr(ge.demisto, "executeCommand", handle)
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: ge.guardian_envelope(True, data={"data": []})})
    monkeypatch.setattr(ge.demisto, "args", lambda: {"action": "score"})
    captured = {}
    monkeypatch.setattr(ge, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    ge.main()

    assert "result" in captured
    assert captured["result"].outputs_prefix == "Guardian.Eval.Score"


def test_main_report_action(monkeypatch):
    rows = [
        {
            "case_id": "m1",
            "concluded": True,
            "actual_verdict": "Malicious",
            "actual_techniques": [],
            "cost_usd": 0.01,
            "latency_seconds": 10.0,
            "tick_count": 2,
        },
    ]
    cases = ({"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},)
    monkeypatch.setattr(ge, "guardian_eval_load_results", lambda: rows)
    monkeypatch.setattr(ge, "guardian_eval_count_launched", lambda run_label=None, case_ids=None: 1)
    monkeypatch.setattr(ge, "GUARDIAN_EVAL_CASES", cases)
    monkeypatch.setattr(ge.demisto, "args", lambda: {"action": "report"})
    captured = {}
    monkeypatch.setattr(ge, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    ge.main()

    assert "result" in captured
    result = captured["result"]
    assert result.outputs_prefix == "Guardian.Eval.Report"
    assert "Binary malicious-detection accuracy" in result.readable_output
    assert "rows" not in result.outputs  # trimmed from context -- already rendered into the per-case table


def test_yml_documents_every_report_output_key(monkeypatch):
    """`GuardianEval.yml`'s `outputs:` block must document every key
    `main()` writes to `Guardian.Eval.Report.*` for `action=report` -- every
    key of `guardian_eval_report_data()`'s return dict except `rows`, which
    `main()` strips before the `CommandResults` call (see its own comment
    there: already rendered into the per-case markdown table)."""
    import os

    import yaml

    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": None, "latency_seconds": None, "tick_count": None},
    ]
    cases = ({"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},)
    _stub_report(monkeypatch, rows, cases, count_launched=1)
    written_keys = {k for k in ge.guardian_eval_report_data().keys() if k != "rows"}

    yml_path = os.path.join(os.path.dirname(__file__), "GuardianEval.yml")
    with open(yml_path) as f:
        spec = yaml.safe_load(f)
    prefix = "Guardian.Eval.Report."
    documented_keys = {
        o["contextPath"][len(prefix):] for o in spec["outputs"] if o["contextPath"].startswith(prefix)
    }

    assert documented_keys == written_keys


def test_main_run_action_threads_run_label(monkeypatch):
    # harvest candidate #11.
    create_calls = []
    monkeypatch.setattr(
        ge.demisto,
        "executeCommand",
        _multi_command_stub({"createNewIncident": lambda args: create_calls.append(dict(args)) or [{"Type": 1, "Contents": "done"}]}),
    )
    _rest_post_stub(
        monkeypatch,
        {
            "/incidents/search": lambda body: ge.guardian_envelope(True, data={"data": [{"id": "1", "version": 1}]}),
            "/incident/investigate": lambda body: ge.guardian_envelope(True, data={}),
        },
    )
    monkeypatch.setattr(ge.demisto, "args", lambda: {"action": "run", "run_label": "baseline-cohere-small"})
    captured = {}
    monkeypatch.setattr(ge, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    ge.main()

    assert json.loads(create_calls[0]["customFields"])["guardianevalrunlabel"] == "baseline-cohere-small"
    assert captured["result"].outputs["launched"][0]["run_label"] == "baseline-cohere-small"


def test_main_report_action_scopes_to_run_label(monkeypatch):
    # harvest candidate #11: a row NOT carrying the requested label must be
    # excluded from the report entirely when run_label is given.
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"},
        {"case_id": "m1", "concluded": True, "actual_verdict": "Benign", "actual_techniques": [],
         "cost_usd": 0.02, "latency_seconds": 2.0, "tick_count": 2, "run_label": "candidate"},
    ]
    cases = ({"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},)
    _stub_labeled_report(monkeypatch, rows, cases, count_launched_by_label={"baseline": 1})
    monkeypatch.setattr(ge.demisto, "args", lambda: {"action": "report", "run_label": "baseline"})
    captured = {}
    monkeypatch.setattr(ge, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    ge.main()

    assert captured["result"].outputs["rows_count"] == 1
    assert captured["result"].outputs["binary_accuracy"] == 1.0  # only the "baseline" row (correct) counted


def test_main_compare_action_success(monkeypatch):
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"},
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "candidate"},
    ]
    cases = ({"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},)
    _stub_labeled_report(monkeypatch, rows, cases, count_launched_by_label={"baseline": 1, "candidate": 1})
    monkeypatch.setattr(
        ge.demisto, "args", lambda: {"action": "compare", "baseline_label": "baseline", "candidate_label": "candidate"}
    )
    captured = {}
    monkeypatch.setattr(ge, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    ge.main()

    result = captured["result"]
    assert result.outputs_prefix == "Guardian.Eval.Compare"
    assert result.outputs["baseline_label"] == "baseline"
    assert result.outputs["candidate_label"] == "candidate"
    assert "Guardian Eval Compare" in result.readable_output


def test_main_compare_action_min_delta_arg_parsed(monkeypatch):
    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "baseline"},
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": 0.01, "latency_seconds": 1.0, "tick_count": 1, "run_label": "candidate"},
    ]
    cases = ({"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},)
    _stub_labeled_report(monkeypatch, rows, cases, count_launched_by_label={"baseline": 1, "candidate": 1})
    monkeypatch.setattr(
        ge.demisto,
        "args",
        lambda: {"action": "compare", "baseline_label": "baseline", "candidate_label": "candidate", "min_delta": "0.05"},
    )
    captured = {}
    monkeypatch.setattr(ge, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    ge.main()

    assert captured["result"].outputs["min_delta"] == 0.05


def test_main_compare_action_missing_baseline_label_returns_error(monkeypatch):
    monkeypatch.setattr(ge.demisto, "args", lambda: {"action": "compare", "candidate_label": "candidate"})
    errors = []
    monkeypatch.setattr(ge, "return_error", lambda msg: errors.append(msg), raising=False)

    ge.main()

    assert errors
    assert "baseline_label" in errors[0]


def test_main_compare_action_missing_candidate_label_returns_error(monkeypatch):
    monkeypatch.setattr(ge.demisto, "args", lambda: {"action": "compare", "baseline_label": "baseline"})
    errors = []
    monkeypatch.setattr(ge, "return_error", lambda msg: errors.append(msg), raising=False)

    ge.main()

    assert errors
    assert "candidate_label" in errors[0]


def test_yml_documents_every_compare_output_key(monkeypatch):
    """Mirrors `test_yml_documents_every_report_output_key` for
    `action=compare`'s `Guardian.Eval.Compare.*` outputs."""
    import os

    import yaml

    rows = [
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": None, "latency_seconds": None, "tick_count": None, "run_label": "baseline"},
        {"case_id": "m1", "concluded": True, "actual_verdict": "Malicious", "actual_techniques": [],
         "cost_usd": None, "latency_seconds": None, "tick_count": None, "run_label": "candidate"},
    ]
    cases = ({"case_id": "m1", "expected_verdict": "Malicious", "expected_techniques": []},)
    _stub_labeled_report(monkeypatch, rows, cases, count_launched_by_label={"baseline": 1, "candidate": 1})
    written_keys = set(ge.guardian_eval_compare_runs("baseline", "candidate").keys())

    yml_path = os.path.join(os.path.dirname(__file__), "GuardianEval.yml")
    with open(yml_path) as f:
        spec = yaml.safe_load(f)
    prefix = "Guardian.Eval.Compare."
    documented_keys = {
        o["contextPath"][len(prefix):] for o in spec["outputs"] if o["contextPath"].startswith(prefix)
    }

    assert documented_keys == written_keys


def test_main_unknown_action_calls_return_error(monkeypatch):
    monkeypatch.setattr(ge.demisto, "args", lambda: {"action": "bogus"})
    errors = []
    monkeypatch.setattr(ge, "return_error", lambda msg: errors.append(msg), raising=False)

    ge.main()

    assert errors
    assert "unknown action" in errors[0]


def test_main_unexpected_exception_calls_return_error(monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(ge, "guardian_eval_run", boom)
    monkeypatch.setattr(ge.demisto, "args", lambda: {"action": "run"})
    errors = []
    monkeypatch.setattr(ge, "return_error", lambda msg: errors.append(msg), raising=False)

    ge.main()

    assert errors
    assert "kaboom" in errors[0]


def test_launch_case_retries_the_lookup_while_the_search_index_catches_up(monkeypatch):
    """createNewIncident returns before the search index has the incident; a single immediate
    lookup missed it live and left the case created but never started."""
    monkeypatch.setattr(ge.demisto, "executeCommand", _multi_command_stub({"createNewIncident": lambda a: [{"Type": 1, "Contents": "done"}]}))
    monkeypatch.setattr(ge.time, "sleep", lambda s: None)
    lookups = {"n": 0}

    def search(body):
        lookups["n"] += 1
        return ge.guardian_envelope(True, data={"data": [] if lookups["n"] < 3 else [{"id": "77", "version": 2}]})

    _rest_post_stub(monkeypatch, {"/incidents/search": search, "/incident/investigate": lambda b: ge.guardian_envelope(True, data={})})
    case = ge.GUARDIAN_EVAL_CASES[0]
    result = ge.guardian_eval_launch_case(case)
    assert result["ok"] is True and result["data"]["incident_id"] == "77"
    assert lookups["n"] == 3


def test_launch_case_gives_up_after_the_retry_budget(monkeypatch):
    monkeypatch.setattr(ge.demisto, "executeCommand", _multi_command_stub({"createNewIncident": lambda a: [{"Type": 1, "Contents": "done"}]}))
    monkeypatch.setattr(ge.time, "sleep", lambda s: None)
    lookups = {"n": 0}

    def search(body):
        lookups["n"] += 1
        return ge.guardian_envelope(True, data={"data": []})

    _rest_post_stub(monkeypatch, {"/incidents/search": search})
    result = ge.guardian_eval_launch_case(ge.GUARDIAN_EVAL_CASES[0])
    assert result["ok"] is False and "after {} attempts".format(ge.GUARDIAN_EVAL_LOOKUP_ATTEMPTS) in result["error"]
    assert lookups["n"] == ge.GUARDIAN_EVAL_LOOKUP_ATTEMPTS
