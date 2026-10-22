import GuardianCaseCapture as gcc


# --- test fixtures ------------------------------------------------------------


def _rest_post_stub(monkeypatch, responses_by_uri):
    def fake(uri, body):
        if uri not in responses_by_uri:
            raise AssertionError("unexpected REST uri: {} {}".format(uri, body))
        return responses_by_uri[uri](body)

    monkeypatch.setattr(gcc, "_guardian_rest_post", fake, raising=False)


def _execute_stub(monkeypatch, handlers):
    def fake(command, args, using=None):
        if command not in handlers:
            raise AssertionError("unexpected command: {} {}".format(command, args))
        return handlers[command](args)

    monkeypatch.setattr(gcc, "guardian_execute", fake, raising=False)


def _incident(incident_id, verdict="Malicious", confidence=80, techniques=None, blast_radius=None, closed="2026-08-20T10:00:00Z", name=None):
    return {
        "id": incident_id,
        "name": name or "Test incident {}".format(incident_id),
        "closed": closed,
        "CustomFields": {
            "guardianverdict": verdict,
            "guardianconfidence": confidence,
            "guardianattacktechniques": techniques if techniques is not None else ["T1110"],
            "guardianblastradius": blast_radius or "one host affected",
        },
    }


# --- guardian_case_capture_find_candidates ------------------------------------


def test_find_candidates_returns_search_results(monkeypatch):
    incidents = [_incident("100"), _incident("101")]
    _rest_post_stub(
        monkeypatch,
        {"/incidents/search": lambda body: gcc.guardian_envelope(True, data={"data": incidents})},
    )
    result = gcc.guardian_case_capture_find_candidates()
    assert result["ok"] is True
    assert result["data"] == incidents


def test_find_candidates_query_shape(monkeypatch):
    """Pins the confirmed-live query shape -- a regression here would be a
    silent behavior change to a scheduled job's search, not just a typo."""
    captured = {}

    def fake(uri, body):
        captured["uri"] = uri
        captured["body"] = body
        return gcc.guardian_envelope(True, data={"data": []})

    monkeypatch.setattr(gcc, "_guardian_rest_post", fake, raising=False)
    gcc.guardian_case_capture_find_candidates()

    assert captured["uri"] == "/incidents/search"
    assert captured["body"]["filter"]["query"] == "status:closed and guardianverdict:*"
    assert captured["body"]["filter"]["period"] == {
        "by": "hour",
        "fromValue": gcc.GUARDIAN_CASE_CAPTURE_WINDOW_HOURS,
    }


def test_find_candidates_propagates_rest_failure(monkeypatch):
    _rest_post_stub(
        monkeypatch,
        {"/incidents/search": lambda body: gcc.guardian_envelope(False, error="connection refused", retryable=True)},
    )
    result = gcc.guardian_case_capture_find_candidates()
    assert result["ok"] is False
    assert "connection refused" in result["error"]
    assert result["retryable"] is True


def test_find_candidates_tolerates_missing_data_key(monkeypatch):
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: gcc.guardian_envelope(True, data={})})
    result = gcc.guardian_case_capture_find_candidates()
    assert result["ok"] is True
    assert result["data"] == []


# --- guardian_case_capture_closed_date ----------------------------------------


def test_closed_date_extracts_date_portion():
    assert gcc.guardian_case_capture_closed_date({"closed": "2026-08-20T10:15:00Z"}) == "2026-08-20"


def test_closed_date_falls_back_when_missing_or_malformed():
    assert gcc.guardian_case_capture_closed_date({}) == "unknown-date"
    assert gcc.guardian_case_capture_closed_date({"closed": None}) == "unknown-date"
    assert gcc.guardian_case_capture_closed_date({"closed": "not-a-date"}) == "unknown-date"
    assert gcc.guardian_case_capture_closed_date({"closed": ""}) == "unknown-date"


def test_closed_date_never_uses_todays_date():
    """The whole point of keying on the incident's OWN closed date (not the
    sweep's run date) is idempotency across overlapping windows -- this is
    the one invariant a future refactor could silently break without any
    other test catching it."""
    import datetime

    incident = {"closed": "2020-01-01T00:00:00Z"}
    assert gcc.guardian_case_capture_closed_date(incident) == "2020-01-01"
    assert gcc.guardian_case_capture_closed_date(incident) != datetime.date.today().isoformat()


# --- guardian_case_capture_build_value ----------------------------------------


def test_build_value_includes_all_verdict_fields():
    incident = _incident(
        "205", verdict="Suspicious", confidence=55, techniques=["T1110", "T1078"], blast_radius="two hosts"
    )
    value = gcc.guardian_case_capture_build_value(incident)
    assert "verdict=Suspicious" in value
    assert "confidence=55" in value
    assert "T1110, T1078" in value
    assert "blast_radius=two hosts" in value
    assert "#205" in value


def test_build_value_handles_missing_fields_gracefully():
    incident = {"id": "300", "name": "Bare incident", "CustomFields": {}}
    value = gcc.guardian_case_capture_build_value(incident)
    assert "verdict=unknown" in value
    assert "confidence=unknown" in value
    assert "techniques=none recorded" in value
    assert "blast_radius=none recorded" in value


def test_build_value_caps_length():
    incident = _incident("400", blast_radius="x" * 2000)
    value = gcc.guardian_case_capture_build_value(incident)
    assert len(value) <= gcc.GUARDIAN_CASE_CAPTURE_VALUE_MAX_LEN
    assert value.endswith("…")


# --- guardian_case_capture_run -------------------------------------------------


def test_run_captures_each_candidate_with_correct_key_and_scope(monkeypatch):
    incidents = [_incident("500", closed="2026-08-20T10:00:00Z"), _incident("501", closed="2026-08-21T11:00:00Z")]
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: gcc.guardian_envelope(True, data={"data": incidents})})
    stored = []
    _execute_stub(
        monkeypatch,
        {
            "GuardianMemory": lambda args: stored.append(args) or gcc.guardian_envelope(True, data={"created": True}),
        },
    )

    result = gcc.guardian_case_capture_run()

    assert result["ok"] is True
    assert [c["incident_id"] for c in result["data"]["captured"]] == ["500", "501"]
    assert result["data"]["errors"] == []
    assert len(stored) == 2
    assert stored[0]["op"] == "store"
    assert stored[0]["key"] == "case:500:2026-08-20"
    assert stored[0]["scope"] == "500"
    assert stored[0]["tags"] == gcc.GUARDIAN_CASE_CAPTURE_TAG
    assert stored[1]["key"] == "case:501:2026-08-21"


def test_run_is_best_effort_across_incidents(monkeypatch):
    """One incident's guardian_memory write failing must not stop the sweep
    from capturing the rest."""
    incidents = [_incident("600"), _incident("601")]
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: gcc.guardian_envelope(True, data={"data": incidents})})

    def flaky_store(args):
        if args["scope"] == "600":
            return gcc.guardian_envelope(False, error="list write conflict")
        return gcc.guardian_envelope(True, data={"created": True})

    _execute_stub(monkeypatch, {"GuardianMemory": flaky_store})

    result = gcc.guardian_case_capture_run()

    assert result["ok"] is False  # one error present
    assert [c["incident_id"] for c in result["data"]["captured"]] == ["601"]
    assert len(result["data"]["errors"]) == 1
    assert result["data"]["errors"][0]["incident_id"] == "600"
    assert "list write conflict" in result["data"]["errors"][0]["error"]


def test_run_no_candidates_is_a_clean_no_op(monkeypatch):
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: gcc.guardian_envelope(True, data={"data": []})})
    _execute_stub(monkeypatch, {})  # asserts GuardianMemory is never called

    result = gcc.guardian_case_capture_run()

    assert result["ok"] is True
    assert result["data"] == {"captured": [], "errors": []}


def test_run_propagates_scan_failure_without_calling_guardian_memory(monkeypatch):
    _rest_post_stub(
        monkeypatch,
        {"/incidents/search": lambda body: gcc.guardian_envelope(False, error="auth failed", retryable=False)},
    )
    _execute_stub(monkeypatch, {})  # asserts GuardianMemory is never called

    result = gcc.guardian_case_capture_run()

    assert result["ok"] is False
    assert "failed to scan" in result["error"]
    assert result["data"] == {"captured": [], "errors": []}


def test_run_reprocessing_same_incident_reuses_the_same_key(monkeypatch):
    """The idempotency the module docstring describes: sweeping the SAME
    closed incident twice (e.g. two overlapping windows) must produce the
    identical memory key both times, never a fresh one."""
    incident = _incident("700", closed="2026-08-20T10:00:00Z")
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: gcc.guardian_envelope(True, data={"data": [incident]})})
    stored = []
    _execute_stub(
        monkeypatch,
        {"GuardianMemory": lambda args: stored.append(args) or gcc.guardian_envelope(True, data={"created": False})},
    )

    gcc.guardian_case_capture_run()
    gcc.guardian_case_capture_run()

    assert stored[0]["key"] == stored[1]["key"] == "case:700:2026-08-20"


# --- main -----------------------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    import CommonServerPython as csp

    csp.RESULTS.clear()
    monkeypatch.setattr(
        gcc,
        "guardian_case_capture_run",
        lambda: gcc.guardian_envelope(True, data={"captured": [{"incident_id": "800", "key": "case:800:2026-08-20"}], "errors": []}),
    )

    gcc.main()

    assert len(csp.RESULTS) == 1
    entry = csp.RESULTS[0].to_context()
    # Contents is raw_response (the same data dict as EntryContext here); the
    # human-readable summary line lives in HumanReadable.
    assert "1 case(s) captured" in entry["HumanReadable"]
    assert entry["EntryContext"]["Guardian.CaseCapture"]["captured"][0]["incident_id"] == "800"


def test_main_unexpected_exception_calls_return_error(monkeypatch):
    monkeypatch.setattr(gcc, "guardian_case_capture_run", lambda: (_ for _ in ()).throw(RuntimeError("kaboom")))
    called = {}
    monkeypatch.setattr(gcc, "return_error", lambda msg: called.setdefault("msg", msg))

    gcc.main()

    assert "kaboom" in called["msg"]


def test_run_skips_the_format_violation_placeholder(monkeypatch):
    placeholder = _incident("600", verdict="Inconclusive", confidence=0, blast_radius="[Format violation: no verdict block] The model answered in chat instead.")
    incidents = [placeholder, _incident("601")]
    _rest_post_stub(monkeypatch, {"/incidents/search": lambda body: gcc.guardian_envelope(True, data={"data": incidents})})
    stored = []
    _execute_stub(monkeypatch, {
        "GuardianMemory": lambda args: stored.append(args) or gcc.guardian_envelope(True, data={"created": True}),
    })

    result = gcc.guardian_case_capture_run()

    assert [c["incident_id"] for c in result["data"]["captured"]] == ["601"]
    assert [a["scope"] for a in stored] == ["601"]
