import GuardianEvalHarvest as geh


# --- test fixtures ------------------------------------------------------------


def _rest_post_stub(monkeypatch, responses_by_uri):
    def fake(uri, body):
        if uri not in responses_by_uri:
            raise AssertionError("unexpected REST uri: {} {}".format(uri, body))
        return responses_by_uri[uri](body)

    monkeypatch.setattr(geh, "_guardian_rest_post", fake, raising=False)


def _execute_stub(monkeypatch, handlers):
    def fake(command, args, using=None):
        if command not in handlers:
            raise AssertionError("unexpected command: {} {}".format(command, args))
        return handlers[command](args)

    monkeypatch.setattr(geh, "guardian_execute", fake, raising=False)


def _incident(
    incident_id, verdict="Malicious", techniques=None, details="Real investigation narrative.", name=None
):
    return {
        "id": incident_id,
        "name": name or "Test incident {}".format(incident_id),
        "details": details,
        "CustomFields": {
            "guardianverdict": verdict,
            "guardianattacktechniques": techniques if techniques is not None else ["T1110"],
        },
    }


# --- guardian_eval_harvest_find_candidates -------------------------------------


def test_find_candidates_returns_search_results(monkeypatch):
    incidents = [_incident("100"), _incident("101")]
    _rest_post_stub(
        monkeypatch,
        {"/incidents/search": lambda body: geh.guardian_envelope(True, data={"data": incidents})},
    )
    result = geh.guardian_eval_harvest_find_candidates()
    assert result["ok"] is True
    assert result["data"] == incidents


def test_find_candidates_query_shape(monkeypatch):
    """Pins the exclusion criteria -- a regression here would silently
    change which incidents this scheduled job harvests."""
    captured = {}

    def fake(uri, body):
        captured["uri"] = uri
        captured["body"] = body
        return geh.guardian_envelope(True, data={"data": []})

    monkeypatch.setattr(geh, "_guardian_rest_post", fake, raising=False)
    geh.guardian_eval_harvest_find_candidates()

    assert captured["uri"] == "/incidents/search"
    query = captured["body"]["filter"]["query"]
    assert "status:closed" in query
    assert "guardianverdict:*" in query
    assert "-guardiantriggersource:eval" in query
    assert "-guardiantriggersource:simulate" in query
    assert '-guardiantriggersource:"job:intake-sweep"' in query
    assert captured["body"]["filter"]["period"] == {
        "by": "hour",
        "fromValue": geh.GUARDIAN_EVAL_HARVEST_WINDOW_HOURS,
    }


def test_find_candidates_propagates_rest_failure(monkeypatch):
    _rest_post_stub(
        monkeypatch,
        {"/incidents/search": lambda body: geh.guardian_envelope(False, error="connection refused", retryable=True)},
    )
    result = geh.guardian_eval_harvest_find_candidates()
    assert result["ok"] is False
    assert "connection refused" in result["error"]
    assert result["retryable"] is True


def test_find_candidates_tolerates_missing_data_key(monkeypatch):
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: geh.guardian_envelope(True, data={})})
    result = geh.guardian_eval_harvest_find_candidates()
    assert result["ok"] is True
    assert result["data"] == []


# --- guardian_eval_harvest_build_case -------------------------------------------


def test_build_case_success():
    incident = _incident("200", verdict="Malicious", techniques=["T1110", "T1078"], details="A real narrative.")
    case, reason = geh.guardian_eval_harvest_build_case(incident)
    assert reason is None
    assert case["case_id"] == "harvested-200"
    assert case["name"] == "Test incident 200"
    assert case["details"] == "A real narrative."
    assert case["expected_verdict"] == "Malicious"
    assert case["expected_techniques"] == ["T1078", "T1110"]  # normalized + sorted


def test_build_case_uses_fallback_name_when_missing():
    incident = _incident("201")
    incident["name"] = ""  # blank/absent name -- the fixture's own default would otherwise mask this
    case, _ = geh.guardian_eval_harvest_build_case(incident)
    assert case["name"] == "Harvested incident #201"


def test_build_case_rejects_unrecognized_verdict():
    incident = _incident("202", verdict="Weaponized")
    case, reason = geh.guardian_eval_harvest_build_case(incident)
    assert case is None
    assert "guardianverdict" in reason


def test_build_case_rejects_missing_verdict():
    incident = _incident("203", verdict="")
    case, reason = geh.guardian_eval_harvest_build_case(incident)
    assert case is None
    assert "guardianverdict" in reason


def test_build_case_rejects_blank_details():
    incident = _incident("204", details="   ")
    case, reason = geh.guardian_eval_harvest_build_case(incident)
    assert case is None
    assert "blank details" in reason


def test_build_case_scrubs_secrets_from_details():
    incident = _incident("205", details="Investigation notes: api_key=sk-abcdef1234567890 was found in a log.")
    case, _ = geh.guardian_eval_harvest_build_case(incident)
    assert "sk-abcdef1234567890" not in case["details"]
    assert "***" in case["details"]


def test_build_case_truncates_oversized_details():
    incident = _incident("206", details="x" * (geh.GUARDIAN_EVAL_HARVEST_DETAILS_MAX_LEN + 500))
    case, _ = geh.guardian_eval_harvest_build_case(incident)
    assert len(case["details"]) <= geh.GUARDIAN_EVAL_HARVEST_DETAILS_MAX_LEN
    assert case["details"].endswith("…")


def test_build_case_empty_expected_techniques_when_none_recorded():
    incident = _incident("207", techniques=[])
    case, _ = geh.guardian_eval_harvest_build_case(incident)
    assert case["expected_techniques"] == []


# --- guardian_eval_harvest_load_runtime_cases -----------------------------------


def test_load_runtime_cases_returns_parsed_list(monkeypatch):
    cases = [{"case_id": "harvested-1"}]
    _execute_stub(monkeypatch, {"getList": lambda args: {"ok": True, "data": [{"Type": 1, "Contents": __import__("json").dumps(cases)}], "error": None}})
    assert geh.guardian_eval_harvest_load_runtime_cases() == cases


def test_load_runtime_cases_empty_on_unreadable_list(monkeypatch):
    _execute_stub(monkeypatch, {"getList": lambda args: {"ok": False, "data": None, "error": "not found"}})
    assert geh.guardian_eval_harvest_load_runtime_cases() == []


def test_load_runtime_cases_empty_on_bad_json(monkeypatch):
    _execute_stub(monkeypatch, {"getList": lambda args: {"ok": True, "data": [{"Type": 1, "Contents": "{not json"}], "error": None}})
    assert geh.guardian_eval_harvest_load_runtime_cases() == []


def test_load_runtime_cases_empty_when_parsed_content_not_a_list(monkeypatch):
    _execute_stub(monkeypatch, {"getList": lambda args: {"ok": True, "data": [{"Type": 1, "Contents": '{"not": "a list"}'}], "error": None}})
    assert geh.guardian_eval_harvest_load_runtime_cases() == []


# --- guardian_eval_harvest_merge_case -------------------------------------------


def test_merge_case_appends_new_case():
    existing = [{"case_id": "harvested-1"}]
    new_case = {"case_id": "harvested-2"}
    merged, was_new = geh.guardian_eval_harvest_merge_case(existing, new_case)
    assert was_new is True
    assert merged == [{"case_id": "harvested-1"}, {"case_id": "harvested-2"}]
    assert existing == [{"case_id": "harvested-1"}]  # never mutated in place


def test_merge_case_already_present_is_a_no_op():
    existing = [{"case_id": "harvested-1", "expected_verdict": "Malicious"}]
    new_case = {"case_id": "harvested-1", "expected_verdict": "Benign"}  # would-be update, ignored
    merged, was_new = geh.guardian_eval_harvest_merge_case(existing, new_case)
    assert was_new is False
    assert merged is existing  # untouched, not even a copy
    assert merged[0]["expected_verdict"] == "Malicious"  # never re-synced


def test_merge_case_trims_oldest_first_over_cap(monkeypatch):
    monkeypatch.setattr(geh, "GUARDIAN_EVAL_HARVEST_MAX_RUNTIME_CASES", 3)
    existing = [{"case_id": "harvested-{}".format(i)} for i in range(3)]
    merged, was_new = geh.guardian_eval_harvest_merge_case(existing, {"case_id": "harvested-new"})
    assert was_new is True
    assert len(merged) == 3
    assert merged[0]["case_id"] == "harvested-1"  # oldest (harvested-0) trimmed off
    assert merged[-1]["case_id"] == "harvested-new"  # newest always kept


# --- guardian_eval_harvest_run ---------------------------------------------------


def test_run_harvests_each_candidate_and_persists_one_merged_write(monkeypatch):
    incidents = [_incident("500"), _incident("501")]
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: geh.guardian_envelope(True, data={"data": incidents})})
    saved = {}

    def fake_execute(command, args, using=None):
        if command == "getList":
            return {"ok": False, "data": None, "error": "not found"}
        if command == "createList":
            saved["listData"] = args["listData"]
            return {"ok": True, "data": None, "error": None}
        raise AssertionError("unexpected command {} {}".format(command, args))

    monkeypatch.setattr(geh, "guardian_execute", fake_execute, raising=False)

    result = geh.guardian_eval_harvest_run()

    assert result["ok"] is True
    assert [h["incident_id"] for h in result["data"]["harvested"]] == ["500", "501"]
    assert result["data"]["skipped"] == []
    assert result["data"]["errors"] == []
    import json

    persisted = json.loads(saved["listData"])
    assert [c["case_id"] for c in persisted] == ["harvested-500", "harvested-501"]


def test_run_is_best_effort_across_incidents(monkeypatch):
    """One incident being unharvestable must not stop the sweep from
    harvesting the rest."""
    incidents = [_incident("600", verdict="Weaponized"), _incident("601")]
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: geh.guardian_envelope(True, data={"data": incidents})})
    _execute_stub(
        monkeypatch,
        {
            "getList": lambda args: {"ok": False, "data": None, "error": "not found"},
            "createList": lambda args: {"ok": True, "data": None, "error": None},
        },
    )

    result = geh.guardian_eval_harvest_run()

    assert [h["incident_id"] for h in result["data"]["harvested"]] == ["601"]
    assert len(result["data"]["skipped"]) == 1
    assert result["data"]["skipped"][0]["incident_id"] == "600"


def test_run_no_candidates_is_a_clean_no_op_and_never_writes(monkeypatch):
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: geh.guardian_envelope(True, data={"data": []})})
    _execute_stub(monkeypatch, {})  # asserts neither getList nor createList is ever called

    result = geh.guardian_eval_harvest_run()

    assert result["ok"] is True
    assert result["data"] == {"harvested": [], "skipped": [], "errors": []}


def test_run_propagates_scan_failure_without_touching_the_store(monkeypatch):
    _rest_post_stub(
        monkeypatch, {"/incidents/search": lambda body: geh.guardian_envelope(False, error="auth failed", retryable=False)}
    )
    _execute_stub(monkeypatch, {})  # asserts neither getList nor createList is ever called

    result = geh.guardian_eval_harvest_run()

    assert result["ok"] is False
    assert "failed to scan" in result["error"]
    assert result["data"] == {"harvested": [], "skipped": [], "errors": []}


def test_run_already_harvested_incident_is_skipped_never_rewritten(monkeypatch):
    import json

    incident = _incident("700")
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: geh.guardian_envelope(True, data={"data": [incident]})})
    existing = [{"case_id": "harvested-700", "expected_verdict": "Benign"}]  # already there, different verdict
    _execute_stub(
        monkeypatch,
        {"getList": lambda args: {"ok": True, "data": [{"Type": 1, "Contents": json.dumps(existing)}], "error": None}},
    )  # createList NOT wired -- asserts it's never called (nothing new to persist)

    result = geh.guardian_eval_harvest_run()

    assert result["data"]["harvested"] == []
    assert result["data"]["skipped"][0]["reason"] == "already harvested"


def test_run_write_failure_reports_error_and_empties_harvested(monkeypatch):
    incident = _incident("800")
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: geh.guardian_envelope(True, data={"data": [incident]})})
    _execute_stub(
        monkeypatch,
        {
            "getList": lambda args: {"ok": False, "data": None, "error": "not found"},
            "createList": lambda args: {"ok": False, "data": None, "error": "list write conflict"},
        },
    )

    result = geh.guardian_eval_harvest_run()

    assert result["ok"] is False
    assert result["data"]["harvested"] == []  # never actually persisted -- must not claim success
    assert "list write conflict" in result["data"]["errors"][0]["error"]


def test_run_idempotent_across_two_sweeps(monkeypatch):
    import json

    incident = _incident("900")
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: geh.guardian_envelope(True, data={"data": [incident]})})
    store = {"rows": None}

    def fake_execute(command, args, using=None):
        if command == "getList":
            if store["rows"] is None:
                return {"ok": False, "data": None, "error": "not found"}
            return {"ok": True, "data": [{"Type": 1, "Contents": json.dumps(store["rows"])}], "error": None}
        if command == "createList":
            store["rows"] = json.loads(args["listData"])
            return {"ok": True, "data": None, "error": None}
        raise AssertionError("unexpected command {} {}".format(command, args))

    monkeypatch.setattr(geh, "guardian_execute", fake_execute, raising=False)

    first = geh.guardian_eval_harvest_run()
    second = geh.guardian_eval_harvest_run()

    assert [h["case_id"] for h in first["data"]["harvested"]] == ["harvested-900"]
    assert second["data"]["harvested"] == []
    assert second["data"]["skipped"][0]["reason"] == "already harvested"
    assert len(store["rows"]) == 1  # never duplicated


# --- main -----------------------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    monkeypatch.setattr(
        geh,
        "guardian_eval_harvest_run",
        lambda: geh.guardian_envelope(
            True, data={"harvested": [{"incident_id": "1000", "case_id": "harvested-1000"}], "skipped": [], "errors": []}
        ),
    )
    captured = {}
    monkeypatch.setattr(geh, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    geh.main()

    result = captured["result"]
    assert result.outputs_prefix == "Guardian.EvalHarvest"
    assert "1 case(s) harvested" in result.readable_output
    assert result.outputs["harvested"][0]["case_id"] == "harvested-1000"


def test_main_reports_error_when_run_fails(monkeypatch):
    monkeypatch.setattr(
        geh,
        "guardian_eval_harvest_run",
        lambda: geh.guardian_envelope(
            False, data={"harvested": [], "skipped": [], "errors": [{"error": "boom"}]}, error="failed"
        ),
    )
    called = {}
    monkeypatch.setattr(geh, "return_error", lambda msg: called.setdefault("msg", msg))

    geh.main()

    assert "boom" in called["msg"] or "0 case(s) harvested" in called["msg"]


def test_main_unexpected_exception_calls_return_error(monkeypatch):
    monkeypatch.setattr(geh, "guardian_eval_harvest_run", lambda: (_ for _ in ()).throw(RuntimeError("kaboom")))
    called = {}
    monkeypatch.setattr(geh, "return_error", lambda msg: called.setdefault("msg", msg))

    geh.main()

    assert "kaboom" in called["msg"]
