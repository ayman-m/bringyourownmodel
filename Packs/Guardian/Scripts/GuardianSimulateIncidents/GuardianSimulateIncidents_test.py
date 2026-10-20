import json

import GuardianSimulateIncidents as gsi


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

    def fake(uri, body):
        if uri not in responses_by_uri:
            raise AssertionError("unexpected REST uri: {} {}".format(uri, body))
        return responses_by_uri[uri](body)

    monkeypatch.setattr(module, "_guardian_rest_post", fake, raising=False)


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


def test_create_one_creates_pending_incident_without_investigating_by_default(monkeypatch):
    create_calls = []

    def handle_create(args):
        create_calls.append(dict(args))
        return [{"Type": 1, "Contents": "done"}]

    monkeypatch.setattr(gsi.demisto, "executeCommand", _multi_command_stub({"createNewIncident": handle_create}))
    _rest_post_stub(monkeypatch, gsi, {"/incidents/search": _search_found("100", version=3)})

    result = gsi.guardian_simulate_create_one("phishing", "Guardian Agent Run", 1, investigate_flag=False)
    assert result["ok"] is True
    assert result["data"]["id"] == "100"
    assert result["data"]["investigated"] is False
    assert len(create_calls) == 1
    assert json.loads(create_calls[0]["customFields"]) == {"guardiantriggersource": "simulate"}


def test_create_one_investigates_when_flag_set(monkeypatch):
    monkeypatch.setattr(
        gsi.demisto, "executeCommand", _multi_command_stub({"createNewIncident": lambda args: [{"Type": 1, "Contents": "done"}]})
    )
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
    monkeypatch.setattr(
        gsi.demisto, "executeCommand", _multi_command_stub({"createNewIncident": lambda args: [{"Type": 1, "Contents": "done"}]})
    )

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


def test_create_one_fails_when_createnewincident_fails(monkeypatch):
    def handle_create(args):
        return [{"Type": 4, "Contents": "Error: bad severity value"}]

    monkeypatch.setattr(gsi.demisto, "executeCommand", _multi_command_stub({"createNewIncident": handle_create}))
    result = gsi.guardian_simulate_create_one("generic", "Guardian Agent Run", 1, investigate_flag=False)
    assert result["ok"] is False
    assert "bad severity value" in result["error"]


def test_create_one_fails_when_name_lookup_finds_nothing(monkeypatch):
    monkeypatch.setattr(
        gsi.demisto, "executeCommand", _multi_command_stub({"createNewIncident": lambda args: [{"Type": 1, "Contents": "done"}]})
    )

    def handle_search(body):
        return gsi.guardian_envelope(True, data={"data": []})

    _rest_post_stub(monkeypatch, gsi, {"/incidents/search": handle_search})
    result = gsi.guardian_simulate_create_one("generic", "Guardian Agent Run", 1, investigate_flag=False)
    assert result["ok"] is False
    assert "not found by name lookup" in result["error"]


# --- guardian_simulate_run: scenario fallback + count clamping ------------------


def test_run_falls_back_to_generic_for_unrecognized_scenario(monkeypatch):
    monkeypatch.setattr(
        gsi.demisto, "executeCommand", _multi_command_stub({"createNewIncident": lambda args: [{"Type": 1, "Contents": "done"}]})
    )
    _rest_post_stub(monkeypatch, gsi, {"/incidents/search": _search_found("1")})

    result = gsi.guardian_simulate_run("totally_unknown_scenario", 1, "Guardian Agent Run", False)
    assert result["ok"] is True
    assert result["data"]["scenario"] == "generic"
    assert "unrecognized scenario" in result["data"]["note"]


def test_run_clamps_count_to_max(monkeypatch):
    create_calls = []
    monkeypatch.setattr(
        gsi.demisto,
        "executeCommand",
        _multi_command_stub({"createNewIncident": lambda args: create_calls.append(1) or [{"Type": 1, "Contents": "done"}]}),
    )
    _rest_post_stub(monkeypatch, gsi, {"/incidents/search": _search_found("1")})

    result = gsi.guardian_simulate_run("generic", 999, "Guardian Agent Run", False)
    assert result["ok"] is True
    assert result["data"]["requested_count"] == gsi.GUARDIAN_SIMULATE_MAX_COUNT
    assert len(create_calls) == gsi.GUARDIAN_SIMULATE_MAX_COUNT
    assert "clamped" in result["data"]["note"]


def test_run_creates_requested_count_and_tags_all(monkeypatch):
    created_args = []

    def handle_create(args):
        created_args.append(args)
        return [{"Type": 1, "Contents": "done"}]

    monkeypatch.setattr(gsi.demisto, "executeCommand", _multi_command_stub({"createNewIncident": handle_create}))

    counter = {"n": 0}

    def handle_search(body):
        counter["n"] += 1
        return gsi.guardian_envelope(True, data={"data": [{"id": str(counter["n"]), "version": 1}]})

    _rest_post_stub(monkeypatch, gsi, {"/incidents/search": handle_search})

    result = gsi.guardian_simulate_run("phishing", 3, "Guardian Agent Run", False)
    assert result["ok"] is True
    assert len(result["data"]["created"]) == 3
    assert len(created_args) == 3
    for args in created_args:
        assert json.loads(args["customFields"]) == {"guardiantriggersource": "simulate"}


def test_run_is_best_effort_across_incidents(monkeypatch):
    call_count = {"n": 0}

    def handle_create(args):
        call_count["n"] += 1
        if call_count["n"] == 2:
            return [{"Type": 4, "Contents": "Error: disk full"}]
        return [{"Type": 1, "Contents": "done"}]

    monkeypatch.setattr(gsi.demisto, "executeCommand", _multi_command_stub({"createNewIncident": handle_create}))
    _rest_post_stub(monkeypatch, gsi, {"/incidents/search": _search_found("1")})

    result = gsi.guardian_simulate_run("generic", 3, "Guardian Agent Run", False)
    assert result["ok"] is False
    assert len(result["data"]["created"]) == 2
    assert len(result["data"]["errors"]) == 1
    assert result["data"]["errors"][0]["index"] == 2


# --- main() ----------------------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    monkeypatch.setattr(
        gsi.demisto,
        "executeCommand",
        _multi_command_stub({"createNewIncident": lambda args: [{"Type": 1, "Contents": "done"}]}),
    )
    _rest_post_stub(monkeypatch, gsi, {"/incidents/search": _search_found("42")})
    monkeypatch.setattr(gsi.demisto, "args", lambda: {"scenario": "phishing", "count": "1"})
    captured = {}
    monkeypatch.setattr(gsi, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    gsi.main()

    assert "result" in captured
    assert "1 of 1" in captured["result"].readable_output
    assert captured["result"].outputs_prefix == "Guardian.SimulateIncidents"


def test_main_calls_return_error_on_failure(monkeypatch):
    monkeypatch.setattr(
        gsi.demisto,
        "executeCommand",
        _multi_command_stub({"createNewIncident": lambda args: [{"Type": 4, "Contents": "Error: nope"}]}),
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
