import GuardianPlaybookMonitor as pbmon


# --- test fixtures -----------------------------------------------------------


def _entry(command, contents, type_=1):
    return {"Type": type_, "Contents": contents}


def _rest_ok(response_body):
    """A successful demisto-api-post/get executeCommand entry wrapping
    `response_body` under the Core REST API integration's own envelope.
    """
    return [_entry(None, {"response": response_body})]


def _rest_error(message):
    return [_entry(None, message, type_=4)]


def _install_commands(monkeypatch, handlers):
    """Wire demisto.executeCommand to `handlers`, a {command_name: callable}
    map. `callable(args) -> list-of-entries` (the raw executeCommand
    return). A command not present in `handlers` raises, mirroring a bad
    command name on the real platform (caught by guardian_execute).
    """

    def fake_execute(command, args):
        if command not in handlers:
            raise ValueError("command '{}' was not found in module".format(command))
        return handlers[command](args)

    monkeypatch.setattr(pbmon.demisto, "executeCommand", fake_execute)


WORKPLAN_SUCCESS = {
    "invPlaybook": {
        "playbookId": "GuardianAgentLoop",
        "name": "GuardianAgentLoop",
        "state": "completed",
        "tasks": {
            "0": {"id": "0", "state": "Completed", "task": {"name": "Start", "type": "start"}},
            "1": {
                "id": "1",
                "state": "Completed",
                "task": {"name": "Run Guardian Reasoning Tick", "type": "regular", "scriptId": "GuardianReasoningTick"},
            },
            "2": {"id": "2", "state": "Completed", "task": {"name": "Done", "type": "title"}},
        },
    }
}

WORKPLAN_FAILED = {
    "invPlaybook": {
        "playbookId": "GuardianAgentLoop",
        "name": "GuardianAgentLoop",
        "state": "failed",
        "tasks": {
            "0": {"id": "0", "state": "Completed", "task": {"name": "Start", "type": "start"}},
            "1": {
                "id": "1",
                "state": "Error",
                "task": {"name": "Run Guardian Reasoning Tick", "type": "regular", "scriptId": "GuardianReasoningTick"},
            },
            "2": {"id": "2", "state": None, "task": {"name": "Done", "type": "title"}},
        },
    }
}

WORKPLAN_NESTED_SUBPLAYBOOK = {
    "invPlaybook": {
        "playbookId": "OuterPB",
        "name": "OuterPB",
        "state": "failed",
        "tasks": {
            "0": {"id": "0", "state": "Completed", "task": {"name": "Start", "type": "start"}},
            "1": {
                "id": "1",
                "state": "Completed",
                "task": {"name": "Sub", "type": "playbook"},
                "subPlaybook": {
                    "tasks": {
                        "0": {"id": "sub-0", "state": "Completed", "task": {"name": "Sub Start"}},
                        "1": {
                            "id": "sub-1",
                            "state": "LoopError",
                            "task": {"name": "Sub Failing Task", "scriptId": "SomeScript"},
                        },
                    }
                },
            },
        },
    }
}

WORKPLAN_NO_PLAYBOOK = {"invPlaybook": None}


def _playbook_search_ok(name="GuardianAgentLoop"):
    def handler(args):
        return _rest_ok({"playbooks": [{"id": name, "name": name}], "total": 1})

    return handler


def _investigation_entries_handler(entries):
    def handler(args):
        return _rest_ok({"entries": entries})

    return handler


# --- guardian_pbmon_rest_get --------------------------------------------------


def test_rest_get_unwraps_response(monkeypatch):
    _install_commands(monkeypatch, {"demisto-api-get": lambda args: _rest_ok({"invPlaybook": None})})

    result = pbmon.guardian_pbmon_rest_get("/investigation/1/workplan")

    assert result["ok"] is True
    assert result["data"] == {"invPlaybook": None}


def test_rest_get_falls_back_to_core_api_get_when_unregistered(monkeypatch):
    def demisto_api_get_missing(args):
        raise ValueError("command 'demisto-api-get' was not found in module")

    _install_commands(
        monkeypatch,
        {
            "demisto-api-get": demisto_api_get_missing,
            "core-api-get": lambda args: _rest_ok({"ok": True}),
        },
    )

    result = pbmon.guardian_pbmon_rest_get("/investigation/1/workplan")

    assert result["ok"] is True
    assert result["data"] == {"ok": True}


def test_rest_get_real_failure_is_not_masked_by_fallback(monkeypatch):
    _install_commands(monkeypatch, {"demisto-api-get": lambda args: _rest_error("Error: 401 Unauthorized")})

    result = pbmon.guardian_pbmon_rest_get("/investigation/1/workplan")

    assert result["ok"] is False
    assert result["is_auth_error"] is True


# --- guardian_pbmon_fetch_workplan -------------------------------------------


def test_fetch_workplan_unknown_incident_is_clean_error(monkeypatch):
    _install_commands(
        monkeypatch,
        {
            "demisto-api-get": lambda args: _rest_error(
                "Error from Core REST API is : ... Body: {\"id\":\"noInv\",\"detail\":\"Could not find investigation\"}"
            )
        },
    )

    result = pbmon.guardian_pbmon_fetch_workplan("999999999")

    assert result["ok"] is False
    assert "no such incident/investigation" in result["error"]
    assert "999999999" in result["error"]


def test_fetch_workplan_other_failure_passes_through(monkeypatch):
    _install_commands(monkeypatch, {"demisto-api-get": lambda args: _rest_error("Error: 503 Service Unavailable")})

    result = pbmon.guardian_pbmon_fetch_workplan("22215")

    assert result["ok"] is False
    assert "no such incident" not in result["error"]
    assert result["retryable"] is True


# --- guardian_pbmon_extract_inv_playbook -------------------------------------


def test_extract_inv_playbook_raw_shape():
    inv = pbmon.guardian_pbmon_extract_inv_playbook(WORKPLAN_SUCCESS)

    assert inv["playbookId"] == "GuardianAgentLoop"


def test_extract_inv_playbook_wrapped_response_shape():
    wrapped = {"response": WORKPLAN_SUCCESS}

    inv = pbmon.guardian_pbmon_extract_inv_playbook(wrapped)

    assert inv["playbookId"] == "GuardianAgentLoop"


def test_extract_inv_playbook_none_when_no_playbook():
    assert pbmon.guardian_pbmon_extract_inv_playbook(WORKPLAN_NO_PLAYBOOK) is None


def test_extract_inv_playbook_non_dict_input():
    assert pbmon.guardian_pbmon_extract_inv_playbook(None) is None
    assert pbmon.guardian_pbmon_extract_inv_playbook("not a dict") is None


# --- guardian_pbmon_walk_tasks ------------------------------------------------


def test_walk_tasks_all_completed_no_failures():
    counts, failed, collected = {}, [], []

    pbmon.guardian_pbmon_walk_tasks(WORKPLAN_SUCCESS["invPlaybook"]["tasks"], counts, failed, collected)

    assert counts == {"completed": 3}
    assert failed == []
    assert len(collected) == 3


def test_walk_tasks_collects_failed_task():
    counts, failed, collected = {}, [], []

    pbmon.guardian_pbmon_walk_tasks(WORKPLAN_FAILED["invPlaybook"]["tasks"], counts, failed, collected)

    assert counts["error"] == 1
    assert counts["completed"] == 1
    assert counts["new"] == 1  # state=None -> "" -> "new" bucket
    assert len(failed) == 1
    assert failed[0]["id"] == "1"
    assert failed[0]["name"] == "Run Guardian Reasoning Tick"
    assert failed[0]["scriptId"] == "GuardianReasoningTick"
    assert failed[0]["state"] == "Error"


def test_walk_tasks_recurses_into_subplaybook():
    counts, failed, collected = {}, [], []

    pbmon.guardian_pbmon_walk_tasks(
        WORKPLAN_NESTED_SUBPLAYBOOK["invPlaybook"]["tasks"], counts, failed, collected
    )

    assert counts["error"] == 1  # the nested LoopError task
    assert len(failed) == 1
    assert failed[0]["id"] == "sub-1"
    assert failed[0]["state"] == "LoopError"
    # the outer + inner start/sub-start tasks plus the failing one
    assert len(collected) == 4


def test_walk_tasks_unknown_state_buckets_to_other():
    tasks = {"0": {"id": "0", "state": "SomeFutureState", "task": {"name": "X"}}}
    counts, failed, collected = {}, [], []

    pbmon.guardian_pbmon_walk_tasks(tasks, counts, failed, collected)

    assert counts == {"other": 1}
    assert failed == []


def test_walk_tasks_non_dict_input_is_noop():
    counts, failed, collected = {}, [], []

    pbmon.guardian_pbmon_walk_tasks(None, counts, failed, collected)
    pbmon.guardian_pbmon_walk_tasks("not a dict", counts, failed, collected)

    assert counts == {}
    assert failed == []
    assert collected == []


# --- guardian_pbmon_enrich_failed_tasks --------------------------------------


def test_enrich_failed_tasks_matches_by_task_id(monkeypatch):
    entries = [
        {"type": 1, "contents": "tick 0 ok", "taskId": "1"},
        {"type": 4, "contents": "Scheduled entry 6@22215 timed out.", "taskId": "1"},
    ]
    _install_commands(
        monkeypatch, {"demisto-api-post": _investigation_entries_handler(entries), "core-api-post": lambda a: []}
    )
    failed = [{"id": "1", "name": "Run Guardian Reasoning Tick", "scriptId": "GuardianReasoningTick", "state": "Error"}]

    pbmon.guardian_pbmon_enrich_failed_tasks("22215", failed)

    assert failed[0]["errorMessage"] == "Scheduled entry 6@22215 timed out."


def test_enrich_failed_tasks_no_match_leaves_no_error_message(monkeypatch):
    entries = [{"type": 4, "contents": "unrelated failure", "taskId": "99"}]
    _install_commands(monkeypatch, {"demisto-api-post": _investigation_entries_handler(entries)})
    failed = [{"id": "1", "name": "X", "scriptId": None, "state": "Error"}]

    pbmon.guardian_pbmon_enrich_failed_tasks("22215", failed)

    assert "errorMessage" not in failed[0]


def test_enrich_failed_tasks_empty_failed_list_is_noop(monkeypatch):
    calls = []
    _install_commands(monkeypatch, {"demisto-api-post": lambda a: calls.append(a) or _rest_ok({"entries": []})})

    pbmon.guardian_pbmon_enrich_failed_tasks("22215", [])

    assert calls == []  # never even attempted the REST read


def test_enrich_failed_tasks_rest_failure_is_graceful(monkeypatch):
    _install_commands(monkeypatch, {"demisto-api-post": lambda a: _rest_error("boom")})
    failed = [{"id": "1", "name": "X", "scriptId": None, "state": "Error"}]

    pbmon.guardian_pbmon_enrich_failed_tasks("22215", failed)

    assert "errorMessage" not in failed[0]


def test_enrich_failed_tasks_redacts_and_scrubs_secrets(monkeypatch):
    entries = [
        {"type": 4, "contents": "auth failed, api_key='sk-liveSecretToken1234567890'", "taskId": "1"},
    ]
    _install_commands(monkeypatch, {"demisto-api-post": _investigation_entries_handler(entries)})
    failed = [{"id": "1", "name": "X", "scriptId": None, "state": "Error"}]

    pbmon.guardian_pbmon_enrich_failed_tasks("22215", failed)

    assert "sk" "-liveSecretToken1234567890" not in failed[0]["errorMessage"]


# --- guardian_pbmon_resolve_playbook_name ------------------------------------


def test_resolve_playbook_name_single_hit(monkeypatch):
    _install_commands(monkeypatch, {"demisto-api-post": _playbook_search_ok("GuardianAgentLoop")})

    name = pbmon.guardian_pbmon_resolve_playbook_name("GuardianAgentLoop", fallback_name="fallback")

    assert name == "GuardianAgentLoop"


def test_resolve_playbook_name_falls_back_on_zero_hits(monkeypatch):
    _install_commands(monkeypatch, {"demisto-api-post": lambda a: _rest_ok({"playbooks": []})})

    name = pbmon.guardian_pbmon_resolve_playbook_name("Unknown", fallback_name="fallback")

    assert name == "fallback"


def test_resolve_playbook_name_falls_back_on_rest_failure(monkeypatch):
    _install_commands(monkeypatch, {"demisto-api-post": lambda a: _rest_error("boom")})

    name = pbmon.guardian_pbmon_resolve_playbook_name("X", fallback_name="fallback")

    assert name == "fallback"


def test_resolve_playbook_name_falsy_id_returns_fallback_without_a_call(monkeypatch):
    calls = []
    _install_commands(monkeypatch, {"demisto-api-post": lambda a: calls.append(a) or _rest_ok({})})

    name = pbmon.guardian_pbmon_resolve_playbook_name(None, fallback_name="fallback")

    assert name == "fallback"
    assert calls == []


# --- guardian_pbmon_run (top-level orchestration) ----------------------------


def test_run_success_path_ran_to_success_true(monkeypatch):
    _install_commands(
        monkeypatch,
        {
            "demisto-api-get": lambda a: _rest_ok(WORKPLAN_SUCCESS),
            "demisto-api-post": _playbook_search_ok("GuardianAgentLoop"),
        },
    )

    result = pbmon.guardian_pbmon_run("22486")

    assert result["ok"] is True
    data = result["data"]
    assert data["has_playbook"] is True
    assert data["overall_state"] == "completed"
    assert data["ran_to_success"] is True
    assert data["failed_tasks"] == []
    assert data["playbook_name"] == "GuardianAgentLoop"
    assert data["task_total"] == 3


def test_run_failed_task_path_surfaces_error(monkeypatch):
    entries = [{"type": 4, "contents": "Scheduled entry 6@22215 timed out.", "taskId": "1"}]

    def post_dispatch(args):
        uri = args.get("uri", "")
        if uri == "/playbook/search":
            return _rest_ok({"playbooks": [{"id": "GuardianAgentLoop", "name": "GuardianAgentLoop"}]})
        return _rest_ok({"entries": entries})

    _install_commands(
        monkeypatch,
        {
            "demisto-api-get": lambda a: _rest_ok(WORKPLAN_FAILED),
            "demisto-api-post": post_dispatch,
        },
    )

    result = pbmon.guardian_pbmon_run("22215")

    assert result["ok"] is True
    data = result["data"]
    assert data["overall_state"] == "failed"
    assert data["ran_to_success"] is False
    assert len(data["failed_tasks"]) == 1
    assert data["failed_tasks"][0]["errorMessage"] == "Scheduled entry 6@22215 timed out."


def test_run_unknown_incident_id_is_clean_error(monkeypatch):
    _install_commands(
        monkeypatch,
        {
            "demisto-api-get": lambda a: _rest_error(
                "Error from Core REST API is : ... {\"id\":\"noInv\",\"detail\":\"Could not find investigation\"}"
            )
        },
    )

    result = pbmon.guardian_pbmon_run("999999999")

    assert result["ok"] is False
    assert "no such incident/investigation" in result["error"]


def test_run_no_playbook_assigned_is_soft_success(monkeypatch):
    _install_commands(monkeypatch, {"demisto-api-get": lambda a: _rest_ok(WORKPLAN_NO_PLAYBOOK)})

    result = pbmon.guardian_pbmon_run("22067")

    assert result["ok"] is True
    assert result["data"]["has_playbook"] is False
    assert "detail" in result["data"]


def test_run_missing_incident_id_is_needs_context_error():
    result = pbmon.guardian_pbmon_run(None)

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_run_blank_incident_id_is_needs_context_error():
    result = pbmon.guardian_pbmon_run("   ")

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_run_accepts_numeric_incident_id(monkeypatch):
    _install_commands(
        monkeypatch,
        {
            "demisto-api-get": lambda a: _rest_ok(WORKPLAN_SUCCESS),
            "demisto-api-post": _playbook_search_ok(),
        },
    )

    result = pbmon.guardian_pbmon_run(22486)

    assert result["ok"] is True
    assert result["data"]["incident_id"] == "22486"


def test_run_task_list_truncated_flag(monkeypatch):
    big_tasks = {
        str(i): {"id": str(i), "state": "Completed", "task": {"name": "T{}".format(i)}}
        for i in range(pbmon.GUARDIAN_PBMON_TASK_CAP + 5)
    }
    workplan = {"invPlaybook": {"playbookId": "Big", "name": "Big", "state": "completed", "tasks": big_tasks}}
    _install_commands(
        monkeypatch,
        {"demisto-api-get": lambda a: _rest_ok(workplan), "demisto-api-post": _playbook_search_ok("Big")},
    )

    result = pbmon.guardian_pbmon_run("1")

    assert result["ok"] is True
    data = result["data"]
    assert data["tasks_truncated"] is True
    assert len(data["tasks"]) == pbmon.GUARDIAN_PBMON_TASK_CAP
    assert data["task_total"] == pbmon.GUARDIAN_PBMON_TASK_CAP + 5


# --- main() -------------------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    _install_commands(
        monkeypatch,
        {"demisto-api-get": lambda a: _rest_ok(WORKPLAN_SUCCESS), "demisto-api-post": _playbook_search_ok()},
    )
    monkeypatch.setattr(pbmon.demisto, "args", lambda: {"incident_id": "22486"})

    captured = {}
    monkeypatch.setattr(pbmon, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    pbmon.main()

    result = captured["result"]
    assert result.outputs_prefix == "Guardian.PlaybookMonitor"
    assert result.outputs["ran_to_success"] is True
    assert "GuardianAgentLoop" in result.readable_output


def test_main_missing_incident_id_calls_return_error(monkeypatch):
    monkeypatch.setattr(pbmon.demisto, "args", lambda: {})

    errors = []
    monkeypatch.setattr(pbmon, "return_error", lambda msg: errors.append(msg), raising=False)

    pbmon.main()

    assert len(errors) == 1
    assert "NEEDS_CONTEXT" in errors[0]


def test_main_unknown_incident_calls_return_error(monkeypatch):
    _install_commands(
        monkeypatch,
        {"demisto-api-get": lambda a: _rest_error('{"id":"noInv","detail":"Could not find investigation"}')},
    )
    monkeypatch.setattr(pbmon.demisto, "args", lambda: {"incident_id": "999999999"})

    errors = []
    monkeypatch.setattr(pbmon, "return_error", lambda msg: errors.append(msg), raising=False)

    pbmon.main()

    assert len(errors) == 1
    assert "no such incident" in errors[0]


def test_main_unexpected_exception_is_caught_and_reported(monkeypatch):
    def boom(incident_id):
        raise RuntimeError("boom")

    monkeypatch.setattr(pbmon, "guardian_pbmon_run", boom)
    monkeypatch.setattr(pbmon.demisto, "args", lambda: {"incident_id": "22486"})

    errors = []
    monkeypatch.setattr(pbmon, "return_error", lambda msg: errors.append(msg), raising=False)

    pbmon.main()

    assert len(errors) == 1
    assert "unexpectedly" in errors[0]
    assert "boom" in errors[0]
