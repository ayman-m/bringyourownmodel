import GuardianDiagnostics as diag


# --- test fixtures -----------------------------------------------------------


def _rest_ok(response_body):
    """A successful demisto-api-post executeCommand entry wrapping
    `response_body` under the Core REST API integration's own envelope.
    """
    return [{"Type": 1, "Contents": {"response": response_body}}]


def _rest_error(message):
    return [{"Type": 4, "Contents": message}]


def _install_commands(monkeypatch, handlers):
    """Wire demisto.executeCommand to `handlers`, a {command_name: callable}
    map keyed by command name, OR a single callable used for every command
    (when a test doesn't care about per-command dispatch).
    """
    if callable(handlers):
        monkeypatch.setattr(diag.demisto, "executeCommand", lambda command, args: handlers(command, args))
        return

    def fake_execute(command, args):
        if command not in handlers:
            raise ValueError("command '{}' was not found in module".format(command))
        return handlers[command](args)

    monkeypatch.setattr(diag.demisto, "executeCommand", fake_execute)


WHOIS_INSTANCE = {"name": "Whois", "brand": "Whois", "enabled": "true", "modified": "2026-01-01T00:00:00Z"}
# NOTE: brand deliberately != name here (confirmed live on XSOAR 6.14.0,
# Task 1.11: demisto.getAllSupportedCommands() keys by configured INSTANCE
# name, not integration brand -- see guardian_diag_command_counts_by_instance's
# docstring). Keeping brand/name distinct in this fixture is what actually
# exercises the name-based join in guardian_diag_instance_row -- a fixture
# where they coincided (as they do for e.g. real "Whois") would pass even
# with the old, wrong brand-keyed join.
UNIT42_INSTANCE = {"name": "Unit 42 Feed", "brand": "Unit42FeedIntegrationBrand", "enabled": "true"}
DISABLED_INSTANCE = {"name": "OldTool", "brand": "OldTool", "enabled": "false"}

SEARCH_RESPONSE = {
    "configurations": [],
    "instances": [WHOIS_INSTANCE, UNIT42_INSTANCE, DISABLED_INSTANCE],
    "health": {
        "Unit 42 Feed": {
            "instance": "Unit 42 Feed",
            "brand": "Unit42FeedIntegrationBrand",
            "lastError": "Script failed to run: Exception: Failed to execute fetch-indicators command.",
            "modified": "2026-07-05T02:04:20Z",
        }
    },
}

#: Keyed by INSTANCE NAME (e.g. "Unit 42 Feed"), never by `brand` -- this is
#: the real, confirmed-live shape `demisto.getAllSupportedCommands()`
#: returns, not the platform's own `{brand: [...]}` naming convention.
ALL_SUPPORTED = {
    "Whois": [{"name": "whois"}],
    "Unit 42 Feed": [{"name": "unit42-get-indicators"}, {"name": "unit42-get-threat-objects"}],
}


def _search_handler(args):
    return _rest_ok(SEARCH_RESPONSE)


def _base_commands(extra=None):
    handlers = {"demisto-api-post": _search_handler}
    if extra:
        handlers.update(extra)
    return handlers


def _install_search(monkeypatch, extra_post_dispatch=None):
    """Dispatch demisto-api-post by target uri: /settings/integration/search
    always returns SEARCH_RESPONSE; any other uri goes through
    `extra_post_dispatch(uri, args)` if given, else a generic ok envelope.
    """

    def handler(command, args):
        uri = args.get("uri", "")
        if uri == "/settings/integration/search":
            return _rest_ok(SEARCH_RESPONSE)
        if extra_post_dispatch:
            return extra_post_dispatch(uri, args)
        return _rest_ok({})

    monkeypatch.setattr(diag.demisto, "executeCommand", handler)
    monkeypatch.setattr(diag.demisto, "getAllSupportedCommands", lambda: ALL_SUPPORTED)


# --- guardian_diag_integration_enabled ---------------------------------------


def test_integration_enabled_handles_string_true():
    assert diag.guardian_diag_integration_enabled({"enabled": "true"}) is True
    assert diag.guardian_diag_integration_enabled({"enabled": "True"}) is True
    assert diag.guardian_diag_integration_enabled({"enabled": "false"}) is False
    assert diag.guardian_diag_integration_enabled({"enabled": True}) is True
    assert diag.guardian_diag_integration_enabled({"enabled": False}) is False
    assert diag.guardian_diag_integration_enabled({}) is False


# --- guardian_diag_health_index ----------------------------------------------


def test_health_index_from_dict_shape():
    index = diag.guardian_diag_health_index(SEARCH_RESPONSE)

    assert "Unit 42 Feed" in index
    assert "malicious_tool" in index["Unit 42 Feed"]["lastError"] or "Exception" in index["Unit 42 Feed"]["lastError"]


def test_health_index_from_list_shape():
    resp = {"health": [{"instance": "X", "lastError": "boom"}]}

    index = diag.guardian_diag_health_index(resp)

    assert index["X"]["lastError"] == "boom"


def test_health_index_tolerates_missing_or_malformed():
    assert diag.guardian_diag_health_index({}) == {}
    assert diag.guardian_diag_health_index(None) == {}
    assert diag.guardian_diag_health_index({"health": "not a dict or list"}) == {}


# --- guardian_diag_find_instance ---------------------------------------------


def test_find_instance_exact_name_match():
    inst, ambiguous = diag.guardian_diag_find_instance(SEARCH_RESPONSE["instances"], "Whois")

    assert inst["name"] == "Whois"
    assert ambiguous == []


def test_find_instance_case_insensitive_name_match():
    inst, ambiguous = diag.guardian_diag_find_instance(SEARCH_RESPONSE["instances"], "whois")

    assert inst["name"] == "Whois"


def test_find_instance_brand_substring_unambiguous():
    inst, ambiguous = diag.guardian_diag_find_instance(SEARCH_RESPONSE["instances"], "unit 42")

    assert inst["name"] == "Unit 42 Feed"


def test_find_instance_substring_matches_multiple_is_ambiguous():
    instances = [{"name": "Splunk_prod", "brand": "SplunkPy"}, {"name": "Splunk_dev", "brand": "SplunkPy"}]

    inst, ambiguous = diag.guardian_diag_find_instance(instances, "splunk")

    assert inst is None
    assert sorted(ambiguous) == ["Splunk_dev", "Splunk_prod"]


def test_find_instance_no_match_returns_none_and_empty():
    inst, ambiguous = diag.guardian_diag_find_instance(SEARCH_RESPONSE["instances"], "totally-unknown")

    assert inst is None
    assert ambiguous == []


# --- guardian_diag_command_counts_by_instance -----------------------------------


def test_command_counts_by_instance():
    counts = diag.guardian_diag_command_counts_by_instance(ALL_SUPPORTED)

    assert counts == {"Whois": 1, "Unit 42 Feed": 2}


def test_command_counts_by_instance_non_dict_input():
    assert diag.guardian_diag_command_counts_by_instance(None) == {}
    assert diag.guardian_diag_command_counts_by_instance("nope") == {}


# --- guardian_diag_is_logical_failure / message ------------------------------


def test_is_logical_failure_detects_err_suffixed_id():
    assert diag.guardian_diag_is_logical_failure({"id": "editJobErr", "error": "bad spec"}) is True


def test_is_logical_failure_detects_success_false():
    assert diag.guardian_diag_is_logical_failure({"success": False, "message": "nope"}) is True


def test_is_logical_failure_false_for_real_success():
    assert diag.guardian_diag_is_logical_failure({"success": True, "message": ""}) is False


def test_is_logical_failure_false_for_non_dict():
    assert diag.guardian_diag_is_logical_failure("not a dict") is False
    assert diag.guardian_diag_is_logical_failure(None) is False


def test_logical_failure_message_prefers_message_field():
    assert diag.guardian_diag_logical_failure_message({"message": "m", "error": "e"}) == "m"
    assert diag.guardian_diag_logical_failure_message({"error": "e"}) == "e"
    assert diag.guardian_diag_logical_failure_message({}) == "operation reported failure with no message"


# --- guardian_diag_test_instance ---------------------------------------------


def test_test_instance_success(monkeypatch):
    _install_commands(monkeypatch, {"demisto-api-post": lambda a: _rest_ok({"success": True, "message": ""})})

    result = diag.guardian_diag_test_instance(WHOIS_INSTANCE)

    assert result["ok"] is True
    assert result["data"]["success"] is True


def test_test_instance_logical_failure_success_false(monkeypatch):
    _install_commands(
        monkeypatch,
        {
            "demisto-api-post": lambda a: _rest_ok(
                {"success": False, "message": "No suitable module for name : X, and brand : Y (46)"}
            )
        },
    )

    result = diag.guardian_diag_test_instance({"name": "X", "brand": "Y"})

    assert result["ok"] is True
    assert result["data"]["success"] is False
    assert "No suitable module" in result["data"]["message"]


def test_test_instance_editjoberr_style_envelope_without_success_key(monkeypatch):
    _install_commands(
        monkeypatch, {"demisto-api-post": lambda a: _rest_ok({"id": "someModuleErr", "error": "bad instance spec"})}
    )

    result = diag.guardian_diag_test_instance(WHOIS_INSTANCE)

    assert result["ok"] is True
    assert result["data"]["success"] is False
    assert "bad instance spec" in result["data"]["message"]


def test_test_instance_call_level_failure_is_not_ok(monkeypatch):
    _install_commands(monkeypatch, {"demisto-api-post": lambda a: _rest_error("Error: connection refused")})

    result = diag.guardian_diag_test_instance(WHOIS_INSTANCE)

    assert result["ok"] is False
    assert result["retryable"] is True


def test_test_instance_scrubs_secrets_in_message(monkeypatch):
    _install_commands(
        monkeypatch,
        {
            "demisto-api-post": lambda a: _rest_ok(
                {"success": False, "message": "auth failed: api_key='sk-liveSecretToken1234567890'"}
            )
        },
    )

    result = diag.guardian_diag_test_instance(WHOIS_INSTANCE)

    assert "sk" "-liveSecretToken1234567890" not in result["data"]["message"]


# --- guardian_diag_shape_fetch_run -------------------------------------------


def test_shape_fetch_run_maps_known_aliases():
    row = {
        "status": "error",
        "lastError": "Failed to execute fetch-indicators command.",
        "lastPullTime": "2026-07-05T02:03:44Z",
        "indicatorsPulled": 0,
    }

    shaped = diag.guardian_diag_shape_fetch_run(row)

    assert shaped["status"] == "error"
    assert "Failed to execute" in shaped["last_error"]
    assert shaped["last_pull_time"] == "2026-07-05T02:03:44Z"
    assert shaped["indicators_pulled"] == 0


def test_shape_fetch_run_empty_error_is_none():
    shaped = diag.guardian_diag_shape_fetch_run({"status": "success", "lastError": ""})

    assert shaped["last_error"] is None


# --- guardian_diag_fetch_history ---------------------------------------------


def test_fetch_history_success(monkeypatch):
    rows = [{"status": "error", "lastError": "boom", "lastPullTime": "t1"}]
    _install_commands(monkeypatch, {"demisto-api-post": lambda a: _rest_ok({"total": 1, "data": rows})})

    result = diag.guardian_diag_fetch_history("Unit 42 Feed", "Unit 42 Feed", 5)

    assert result["available"] is True
    assert result["total"] == 1
    assert result["runs"][0]["status"] == "error"


def test_fetch_history_empty_is_available_with_zero_rows(monkeypatch):
    _install_commands(monkeypatch, {"demisto-api-post": lambda a: _rest_ok({"total": 0, "data": None})})

    result = diag.guardian_diag_fetch_history("Whois", "Whois", 5)

    assert result["available"] is True
    assert result["total"] == 0
    assert result["runs"] == []


def test_fetch_history_rest_failure_is_unavailable_not_a_crash(monkeypatch):
    _install_commands(monkeypatch, {"demisto-api-post": lambda a: _rest_error("Error: 404 Not Found")})

    result = diag.guardian_diag_fetch_history("Brand", "Instance", 5)

    assert result["available"] is False
    assert "note" in result


def test_fetch_history_respects_limit(monkeypatch):
    rows = [{"status": "success", "lastPullTime": str(i)} for i in range(10)]
    _install_commands(monkeypatch, {"demisto-api-post": lambda a: _rest_ok({"total": 10, "data": rows})})

    result = diag.guardian_diag_fetch_history("Brand", "Instance", 3)

    assert len(result["runs"]) == 3


# --- guardian_diag_run (top-level orchestration) -----------------------------


def test_run_summary_lists_enabled_instances_with_health(monkeypatch):
    _install_search(monkeypatch)

    result = diag.guardian_diag_run()

    assert result["ok"] is True
    data = result["data"]
    assert data["target"] is None
    assert data["total_instances"] == 3
    assert data["enabled_count"] == 2  # Whois + Unit 42 Feed, not the disabled OldTool
    assert data["disabled_count"] == 1
    assert data["unhealthy_count"] == 1  # Unit 42 Feed has a lastError
    names = {row["instance_name"] for row in data["instances"]}
    assert names == {"Whois", "Unit 42 Feed"}
    assert data["command_catalog_brands"] == 2
    assert data["command_catalog_total_commands"] == 3


def test_run_named_instance_returns_test_and_fetch_history(monkeypatch):
    def dispatch(uri, args):
        if uri == "/settings/integration/test":
            return _rest_ok({"success": True, "message": ""})
        if uri == "/settings/integration/fetch-history":
            return _rest_ok({"total": 1, "data": [{"status": "error", "lastError": "boom"}]})
        return _rest_ok({})

    _install_search(monkeypatch, dispatch)

    result = diag.guardian_diag_run(name="Unit 42 Feed")

    assert result["ok"] is True
    data = result["data"]
    assert data["target"] == "Unit 42 Feed"
    inst = data["instance"]
    assert inst["instance_name"] == "Unit 42 Feed"
    assert inst["healthy"] is False
    assert inst["test"]["success"] is True
    assert inst["fetch_history"]["available"] is True
    assert inst["fetch_history"]["runs"][0]["status"] == "error"


def test_run_named_instance_not_found_lists_available(monkeypatch):
    _install_search(monkeypatch)

    result = diag.guardian_diag_run(name="NoSuchThing")

    assert result["ok"] is False
    assert "Whois" in result["error"]
    assert "Unit 42 Feed" in result["error"]


def test_run_named_instance_ambiguous_substring(monkeypatch):
    def search_with_two_splunks(command, args):
        resp = dict(SEARCH_RESPONSE)
        resp["instances"] = [
            {"name": "Splunk_prod", "brand": "SplunkPy", "enabled": "true"},
            {"name": "Splunk_dev", "brand": "SplunkPy", "enabled": "true"},
        ]
        return _rest_ok(resp)

    monkeypatch.setattr(diag.demisto, "executeCommand", search_with_two_splunks)
    monkeypatch.setattr(diag.demisto, "getAllSupportedCommands", lambda: {})

    result = diag.guardian_diag_run(name="splunk")

    assert result["ok"] is False
    assert "multiple configured instances" in result["error"]


def test_run_named_instance_unreachable_test_is_envelope_not_crash(monkeypatch):
    def dispatch(uri, args):
        if uri == "/settings/integration/test":
            raise ConnectionError("connection refused")
        if uri == "/settings/integration/fetch-history":
            return _rest_error("Error: not available")
        return _rest_ok({})

    _install_search(monkeypatch, dispatch)

    result = diag.guardian_diag_run(name="Whois")

    assert result["ok"] is True  # the overall tool call never crashes
    inst = result["data"]["instance"]
    assert inst["test"]["success"] is False
    assert inst["test"]["call_failed"] is True
    assert inst["fetch_history"]["available"] is False


def test_run_integration_search_failure_is_hard_error(monkeypatch):
    monkeypatch.setattr(diag.demisto, "executeCommand", lambda c, a: _rest_error("Error: 503 Service Unavailable"))
    monkeypatch.setattr(diag.demisto, "getAllSupportedCommands", lambda: {})

    result = diag.guardian_diag_run()

    assert result["ok"] is False
    assert "integration configuration" in result["error"]


def test_run_get_all_supported_commands_raising_degrades_gracefully(monkeypatch):
    def raising_getall():
        raise RuntimeError("boom")

    monkeypatch.setattr(diag.demisto, "getAllSupportedCommands", raising_getall)
    monkeypatch.setattr(diag.demisto, "executeCommand", lambda c, a: _rest_ok(SEARCH_RESPONSE))
    monkeypatch.setattr(diag.demisto, "error", lambda msg: None)

    result = diag.guardian_diag_run()

    assert result["ok"] is True
    assert result["data"]["command_catalog_brands"] == 0


def test_run_limit_arg_is_clamped(monkeypatch):
    def dispatch(uri, args):
        if uri == "/settings/integration/test":
            return _rest_ok({"success": True, "message": ""})
        if uri == "/settings/integration/fetch-history":
            rows = [{"status": "success", "lastPullTime": str(i)} for i in range(10)]
            return _rest_ok({"total": 10, "data": rows})
        return _rest_ok({})

    _install_search(monkeypatch, dispatch)

    result = diag.guardian_diag_run(name="Whois", limit="not-a-number")

    assert result["ok"] is True
    # falls back to the default limit (5) when unparseable
    assert len(result["data"]["instance"]["fetch_history"]["runs"]) == 5


# --- main() -------------------------------------------------------------------


def test_main_summary_returns_command_results(monkeypatch):
    _install_search(monkeypatch)
    monkeypatch.setattr(diag.demisto, "args", lambda: {})

    captured = {}
    monkeypatch.setattr(diag, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    diag.main()

    result = captured["result"]
    assert result.outputs_prefix == "Guardian.Diagnostics"
    assert result.outputs["enabled_count"] == 2
    assert "Integration Diagnostics Summary" in result.readable_output


def test_main_named_instance_returns_command_results(monkeypatch):
    def dispatch(uri, args):
        if uri == "/settings/integration/test":
            return _rest_ok({"success": True, "message": ""})
        if uri == "/settings/integration/fetch-history":
            return _rest_ok({"total": 0, "data": None})
        return _rest_ok({})

    _install_search(monkeypatch, dispatch)
    monkeypatch.setattr(diag.demisto, "args", lambda: {"name": "Whois"})

    captured = {}
    monkeypatch.setattr(diag, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    diag.main()

    result = captured["result"]
    assert result.outputs["instance"]["instance_name"] == "Whois"
    assert "Whois" in result.readable_output


def test_main_unknown_name_calls_return_error(monkeypatch):
    _install_search(monkeypatch)
    monkeypatch.setattr(diag.demisto, "args", lambda: {"name": "nope"})

    errors = []
    monkeypatch.setattr(diag, "return_error", lambda msg: errors.append(msg), raising=False)

    diag.main()

    assert len(errors) == 1
    assert "no configured integration instance matches" in errors[0]


def test_main_unexpected_exception_is_caught_and_reported(monkeypatch):
    def boom(name=None, limit=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(diag, "guardian_diag_run", boom)
    monkeypatch.setattr(diag.demisto, "args", lambda: {})

    errors = []
    monkeypatch.setattr(diag, "return_error", lambda msg: errors.append(msg), raising=False)

    diag.main()

    assert len(errors) == 1
    assert "unexpectedly" in errors[0]
    assert "boom" in errors[0]
