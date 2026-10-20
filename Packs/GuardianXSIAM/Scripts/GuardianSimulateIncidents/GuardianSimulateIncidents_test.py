import json

import pytest

import GuardianSimulateIncidents as gsi


@pytest.fixture(autouse=True)
def _no_sleep_and_record_tags(monkeypatch):
    """The name lookup sleeps between attempts and the tag write is a REST round trip; neither belongs in a unit test."""
    monkeypatch.setattr(gsi.time, "sleep", lambda _s: None)
    tags = []

    def fake_set(incident_id, fields):
        tags.append((incident_id, dict(fields)))
        return gsi.guardian_envelope(True, data={})

    monkeypatch.setattr(gsi, "guardian_set_incident_fields", fake_set, raising=False)
    return tags


# --- test fixtures ------------------------------------------------------------


def _multi_command_stub(handlers):
    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command: {} {}".format(command, args))
        return handlers[command](args)

    return fake_execute


def _rest_post_stub(monkeypatch, module, responses_by_uri):
    """Monkeypatch the module's injected `_guardian_rest_post` to dispatch
    by URI to a {uri: fn(body) -> envelope} map.
    """

    responses_by_uri = {gsi.GUARDIAN_SIMULATE_INSERT_URI: _insert_ok(), **responses_by_uri}

    def fake(uri, body):
        if uri not in responses_by_uri:
            raise AssertionError("unexpected REST uri: {} {}".format(uri, body))
        return responses_by_uri[uri](body)

    monkeypatch.setattr(module, "_guardian_rest_post", fake, raising=False)


def _insert_ok(calls=None):
    """An `insert_parsed_alerts` handler that accepts the alert and records its body."""

    def handler(body):
        if calls is not None:
            calls.append(body["request_data"]["alerts"][0])
        return gsi.guardian_envelope(True, data={"reply": True})

    return handler


def _search_found(incident_id, version=1):
    def handler(body):
        return gsi.guardian_envelope(True, data={"data": [{"id": incident_id, "version": version}]})

    return handler


# --- guardian_simulate_build_payload --------------------------------------------


def test_build_payload_shapes_customfields_and_labels():
    args, name = gsi.guardian_simulate_build_payload("phishing", "Guardian Agent Run", 1)
    assert args["type"] == "Guardian Agent Run"
    assert args["severity"] == "2"
    assert json.loads(args["customFields"]) == {"guardiantriggersource": "simulate"}
    labels = json.loads(args["labels"])
    assert {"type": "guardiantriggersource", "value": "simulate"} in labels
    assert {"type": "GuardianScenario", "value": "phishing"} in labels
    assert name.startswith("Guardian Simulated - phishing #1 - ")


def test_build_payload_names_are_unique_across_calls():
    _, name1 = gsi.guardian_simulate_build_payload("phishing", "Guardian Agent Run", 1)
    _, name2 = gsi.guardian_simulate_build_payload("phishing", "Guardian Agent Run", 1)
    assert name1 != name2


# --- guardian_simulate_create_one -----------------------------------------------


def test_create_one_creates_pending_incident_without_investigating_by_default(monkeypatch, _no_sleep_and_record_tags):
    inserted = []
    _rest_post_stub(
        monkeypatch,
        gsi,
        {gsi.GUARDIAN_SIMULATE_INSERT_URI: _insert_ok(inserted), "/incidents/search": _search_found("100", version=3)},
    )

    result = gsi.guardian_simulate_create_one("phishing", "Guardian Agent Run", 1, investigate_flag=False)
    assert result["ok"] is True
    assert result["data"]["id"] == "100"
    assert result["data"]["investigated"] is False
    assert len(inserted) == 1
    assert inserted[0]["severity"] == "Medium"  # phishing is severity 2
    assert inserted[0]["alert_name"].startswith("Guardian Simulated - phishing #1 - ")
    assert isinstance(inserted[0]["local_port"], int) and isinstance(inserted[0]["remote_port"], int)
    assert _no_sleep_and_record_tags == [("100", {"guardiantriggersource": "simulate"})]


def test_create_one_investigates_when_flag_set(monkeypatch):
    investigate_calls = []

    def handle_investigate(body):
        investigate_calls.append(body)
        return gsi.guardian_envelope(True, data={"id": body["id"]})

    _rest_post_stub(
        monkeypatch,
        gsi,
        {"/incidents/search": _search_found("200", version=5), "/incident/investigate": handle_investigate},
    )

    result = gsi.guardian_simulate_create_one("brute_force", "Guardian Agent Run", 1, investigate_flag=True)
    assert result["ok"] is True
    assert result["data"]["investigated"] is True
    assert investigate_calls == [{"id": "200", "version": 5}]


def test_create_one_reports_investigate_failure_without_losing_the_create(monkeypatch):

    def handle_investigate(body):
        return gsi.guardian_envelope(False, error="version conflict")

    _rest_post_stub(
        monkeypatch,
        gsi,
        {"/incidents/search": _search_found("300"), "/incident/investigate": handle_investigate},
    )

    result = gsi.guardian_simulate_create_one("generic", "Guardian Agent Run", 1, investigate_flag=True)
    assert result["ok"] is True  # the incident WAS created -- not a hard failure
    assert result["data"]["investigated"] is False
    assert "version conflict" in result["data"]["investigate_error"]


def test_create_one_fails_when_the_alert_insert_fails(monkeypatch):
    def handle_insert(body):
        return gsi.guardian_envelope(False, error="Error: bad severity value")

    _rest_post_stub(monkeypatch, gsi, {gsi.GUARDIAN_SIMULATE_INSERT_URI: handle_insert})
    result = gsi.guardian_simulate_create_one("generic", "Guardian Agent Run", 1, investigate_flag=False)
    assert result["ok"] is False
    assert "alert insert failed" in result["error"]
    assert "bad severity value" in result["error"]


def test_create_one_fails_when_the_insert_is_not_acknowledged(monkeypatch):
    def handle_insert(body):
        return gsi.guardian_envelope(True, data={"reply": False})

    _rest_post_stub(monkeypatch, gsi, {gsi.GUARDIAN_SIMULATE_INSERT_URI: handle_insert})
    result = gsi.guardian_simulate_create_one("generic", "Guardian Agent Run", 1, investigate_flag=False)
    assert result["ok"] is False
    assert "not accepted" in result["error"]


def test_name_lookup_retries_until_the_issue_is_ingested(monkeypatch):
    attempts = {"n": 0}

    def handle_search(body):
        attempts["n"] += 1
        rows = [] if attempts["n"] < 3 else [{"id": "77", "version": 1}]
        return gsi.guardian_envelope(True, data={"data": rows})

    _rest_post_stub(monkeypatch, gsi, {"/incidents/search": handle_search})
    result = gsi.guardian_simulate_create_one("generic", "Guardian Agent Run", 1, investigate_flag=False)
    assert result["ok"] is True
    assert result["data"]["id"] == "77"
    assert attempts["n"] == 3


def test_a_failed_tag_write_is_reported_but_does_not_lose_the_create(monkeypatch):
    monkeypatch.setattr(
        gsi, "guardian_set_incident_fields", lambda *_a: gsi.guardian_envelope(False, error="field write refused"), raising=False
    )
    _rest_post_stub(monkeypatch, gsi, {"/incidents/search": _search_found("55")})
    result = gsi.guardian_simulate_create_one("generic", "Guardian Agent Run", 1, investigate_flag=False)
    assert result["ok"] is True
    assert result["data"]["tag_error"] == "field write refused"


def test_create_one_fails_when_name_lookup_finds_nothing(monkeypatch):

    def handle_search(body):
        return gsi.guardian_envelope(True, data={"data": []})

    _rest_post_stub(monkeypatch, gsi, {"/incidents/search": handle_search})
    result = gsi.guardian_simulate_create_one("generic", "Guardian Agent Run", 1, investigate_flag=False)
    assert result["ok"] is False
    assert "not found by name lookup" in result["error"]


# --- guardian_simulate_run: scenario fallback + count clamping ------------------


def test_run_falls_back_to_generic_for_unrecognized_scenario(monkeypatch):
    _rest_post_stub(monkeypatch, gsi, {"/incidents/search": _search_found("1")})

    result = gsi.guardian_simulate_run("totally_unknown_scenario", 1, "Guardian Agent Run", False)
    assert result["ok"] is True
    assert result["data"]["scenario"] == "generic"
    assert "unrecognized scenario" in result["data"]["note"]


def test_run_clamps_count_to_max(monkeypatch):
    create_calls = []
    _rest_post_stub(
        monkeypatch, gsi, {gsi.GUARDIAN_SIMULATE_INSERT_URI: _insert_ok(create_calls), "/incidents/search": _search_found("1")}
    )

    result = gsi.guardian_simulate_run("generic", 999, "Guardian Agent Run", False)
    assert result["ok"] is True
    assert result["data"]["requested_count"] == gsi.GUARDIAN_SIMULATE_MAX_COUNT
    assert len(create_calls) == gsi.GUARDIAN_SIMULATE_MAX_COUNT
    assert "clamped" in result["data"]["note"]


def test_run_creates_requested_count_and_tags_all(monkeypatch, _no_sleep_and_record_tags):
    created_args = []
    counter = {"n": 0}

    def handle_search(body):
        counter["n"] += 1
        return gsi.guardian_envelope(True, data={"data": [{"id": str(counter["n"]), "version": 1}]})

    _rest_post_stub(
        monkeypatch, gsi, {gsi.GUARDIAN_SIMULATE_INSERT_URI: _insert_ok(created_args), "/incidents/search": handle_search}
    )

    result = gsi.guardian_simulate_run("phishing", 3, "Guardian Agent Run", False)
    assert result["ok"] is True
    assert len(result["data"]["created"]) == 3
    assert len(created_args) == 3
    assert [t[1] for t in _no_sleep_and_record_tags] == [{"guardiantriggersource": "simulate"}] * 3


def test_run_is_best_effort_across_incidents(monkeypatch):
    call_count = {"n": 0}

    def handle_insert(body):
        call_count["n"] += 1
        if call_count["n"] == 2:
            return gsi.guardian_envelope(False, error="Error: disk full")
        return gsi.guardian_envelope(True, data={"reply": True})

    _rest_post_stub(monkeypatch, gsi, {gsi.GUARDIAN_SIMULATE_INSERT_URI: handle_insert, "/incidents/search": _search_found("1")})

    result = gsi.guardian_simulate_run("generic", 3, "Guardian Agent Run", False)
    assert result["ok"] is False
    assert len(result["data"]["created"]) == 2
    assert len(result["data"]["errors"]) == 1
    assert result["data"]["errors"][0]["index"] == 2


# --- main() ----------------------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    _rest_post_stub(monkeypatch, gsi, {"/incidents/search": _search_found("42")})
    monkeypatch.setattr(gsi.demisto, "args", lambda: {"scenario": "phishing", "count": "1"})
    captured = {}
    monkeypatch.setattr(gsi, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    gsi.main()

    assert "result" in captured
    assert "1 of 1" in captured["result"].readable_output
    assert captured["result"].outputs_prefix == "Guardian.SimulateIncidents"


def test_main_calls_return_error_on_failure(monkeypatch):
    _rest_post_stub(
        monkeypatch, gsi, {gsi.GUARDIAN_SIMULATE_INSERT_URI: lambda body: gsi.guardian_envelope(False, error="Error: nope")}
    )
    monkeypatch.setattr(gsi.demisto, "args", lambda: {"scenario": "phishing", "count": "1"})
    errors = []
    monkeypatch.setattr(gsi, "return_error", lambda msg: errors.append(msg), raising=False)

    gsi.main()

    assert errors


def test_main_unexpected_exception_calls_return_error(monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(gsi, "guardian_simulate_run", boom)
    monkeypatch.setattr(gsi.demisto, "args", lambda: {})
    errors = []
    monkeypatch.setattr(gsi, "return_error", lambda msg: errors.append(msg), raising=False)

    gsi.main()

    assert errors
    assert "kaboom" in errors[0]
