import json

import GuardianJobGuard as jg


# --- test harness --------------------------------------------------------------


def _multi_command_stub(handlers):
    """Fake demisto.executeCommand dispatching by command name to a
    {command_name: fn(args) -> entries} map. Raises on an unhandled command
    so a test can't silently pass over an unexpected call -- mirrors every
    other Guardian *_test.py's identically-named helper.
    """

    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command: {} {}".format(command, args))
        return handlers[command](args)

    return fake_execute


def _get_list_handler(list_name, contents, ok=True):
    def handler(args):
        assert args["listName"] == list_name
        if not ok:
            return [{"Type": 4, "Contents": contents}]
        return [{"Type": 1, "Contents": contents}]

    return handler


def _capturing_set_list(sink):
    def handler(args):
        sink.setdefault("calls", []).append(dict(args))
        return [{"Type": 1, "Contents": "Done: list updated"}]

    return handler


def _capturing_create_list(sink):
    def handler(args):
        sink.setdefault("calls", []).append(dict(args))
        return [{"Type": 1, "Contents": "Done: list created"}]

    return handler


def _get_time_handler(ts="2026-07-06T00:00:00Z"):
    def handler(args):
        return [{"Type": 1, "Contents": ts}]

    return handler


def _api_post_handler(routes):
    """Fake demisto-api-post dispatching by `uri` to a {uri: fn(body_obj) ->
    response_dict} map, wrapping the response the way the real Core REST API
    integration does (`{"response": ...}`)."""

    def handler(args):
        uri = args["uri"]
        body = json.loads(args["body"])
        if uri not in routes:
            raise AssertionError("unexpected demisto-api-post uri: {}".format(uri))
        response = routes[uri](body)
        return [{"Type": 1, "Contents": {"response": response}}]

    return handler


def _install(monkeypatch, handlers, incident=None):
    monkeypatch.setattr(jg.demisto, "executeCommand", _multi_command_stub(handlers))
    monkeypatch.setattr(jg.demisto, "error", lambda msg: None)
    monkeypatch.setattr(jg.demisto, "incident", lambda: incident or {})


# --- guardian_jobguard_load_kill_switch: fail-open matrix -----------------------


def test_kill_switch_enabled_true(monkeypatch):
    _install(monkeypatch, {"getList": _get_list_handler("guardian_kill_switch", '{"enabled": true}')})
    assert jg.guardian_jobguard_load_kill_switch() is True


def test_kill_switch_enabled_false(monkeypatch):
    _install(monkeypatch, {"getList": _get_list_handler("guardian_kill_switch", '{"enabled": false}')})
    assert jg.guardian_jobguard_load_kill_switch() is False


def test_kill_switch_unreadable_fails_open(monkeypatch):
    _install(
        monkeypatch,
        {"getList": _get_list_handler("guardian_kill_switch", "Item not found (8)", ok=False)},
    )
    assert jg.guardian_jobguard_load_kill_switch() is False


def test_kill_switch_malformed_fails_open(monkeypatch):
    _install(monkeypatch, {"getList": _get_list_handler("guardian_kill_switch", "[1,2,3]")})
    assert jg.guardian_jobguard_load_kill_switch() is False


# --- guardian_jobguard_resolve_job_name -----------------------------------------


def test_resolve_job_name_explicit_arg_wins():
    assert jg.guardian_jobguard_resolve_job_name("GuardianIntakeSweep") == "GuardianIntakeSweep"


def test_resolve_job_name_falls_back_to_triggersource(monkeypatch):
    monkeypatch.setattr(
        jg.demisto, "incident", lambda: {"CustomFields": {"guardiantriggersource": "job:intake-sweep"}}
    )
    assert jg.guardian_jobguard_resolve_job_name(None) == "job:intake-sweep"


def test_resolve_job_name_none_when_neither_available(monkeypatch):
    monkeypatch.setattr(jg.demisto, "incident", lambda: {})
    assert jg.guardian_jobguard_resolve_job_name(None) is None
    assert jg.guardian_jobguard_resolve_job_name("   ") is None


# --- guardian_jobguard_check -----------------------------------------------------


def test_check_bails_on_kill_switch(monkeypatch):
    _install(monkeypatch, {"getList": _get_list_handler("guardian_kill_switch", '{"enabled": true}')})
    result = jg.guardian_jobguard_check("GuardianIntakeSweep")
    assert result["proceed"] is False
    assert result["reason"] == "kill_switch_engaged"


def test_check_proceeds_with_no_job_name(monkeypatch):
    _install(monkeypatch, {"getList": _get_list_handler("guardian_kill_switch", '{"enabled": false}')})
    result = jg.guardian_jobguard_check(None)
    assert result["proceed"] is True
    assert result["job_name"] is None


def test_check_proceeds_for_fresh_job_not_in_registry(monkeypatch):
    def get_list(args):
        if args["listName"] == "guardian_kill_switch":
            return [{"Type": 1, "Contents": '{"enabled": false}'}]
        assert args["listName"] == "guardian_jobs_registry"
        return [{"Type": 1, "Contents": "{}"}]

    _install(monkeypatch, {"getList": get_list})
    result = jg.guardian_jobguard_check("GuardianIntakeSweep")
    assert result["proceed"] is True
    assert result["consecutive_failures"] == 0


def test_check_blocks_disabled_job(monkeypatch):
    registry = {"GuardianIntakeSweep": {"consecutive_failures": 10, "enabled": False}}

    def get_list(args):
        if args["listName"] == "guardian_kill_switch":
            return [{"Type": 1, "Contents": '{"enabled": false}'}]
        return [{"Type": 1, "Contents": json.dumps(registry)}]

    _install(monkeypatch, {"getList": get_list})
    result = jg.guardian_jobguard_check("GuardianIntakeSweep")
    assert result["proceed"] is False
    assert result["reason"] == "job_disabled"
    assert result["consecutive_failures"] == 10


def test_check_allows_enabled_job_with_prior_failures(monkeypatch):
    registry = {"GuardianIntakeSweep": {"consecutive_failures": 3, "enabled": True}}

    def get_list(args):
        if args["listName"] == "guardian_kill_switch":
            return [{"Type": 1, "Contents": '{"enabled": false}'}]
        return [{"Type": 1, "Contents": json.dumps(registry)}]

    _install(monkeypatch, {"getList": get_list})
    result = jg.guardian_jobguard_check("GuardianIntakeSweep")
    assert result["proceed"] is True
    assert result["consecutive_failures"] == 3


def test_check_fails_open_on_unreadable_registry(monkeypatch):
    def get_list(args):
        if args["listName"] == "guardian_kill_switch":
            return [{"Type": 1, "Contents": '{"enabled": false}'}]
        return [{"Type": 4, "Contents": "some transient error"}]

    _install(monkeypatch, {"getList": get_list})
    result = jg.guardian_jobguard_check("GuardianIntakeSweep")
    assert result["proceed"] is True
    assert result["reason"] == "registry_unreadable"


# --- guardian_jobguard_report: increment / reset / disable-at-threshold --------


def test_report_success_resets_counter(monkeypatch):
    registry = {"GuardianIntakeSweep": {"consecutive_failures": 4, "enabled": True}}
    set_list_calls = {}

    def get_list(args):
        if args["listName"] == "guardian_kill_switch":
            return [{"Type": 1, "Contents": '{"enabled": false}'}]
        return [{"Type": 1, "Contents": json.dumps(registry)}]

    _install(
        monkeypatch,
        {
            "getList": get_list,
            "setList": _capturing_set_list(set_list_calls),
            "GetTime": _get_time_handler(),
        },
    )
    result = jg.guardian_jobguard_report("GuardianIntakeSweep", "success")
    assert result["consecutive_failures"] == 0
    assert result["enabled"] is True
    assert result["disabled_now"] is False
    saved = json.loads(set_list_calls["calls"][0]["listData"])
    assert saved["GuardianIntakeSweep"]["consecutive_failures"] == 0


def test_report_success_does_not_reenable_a_disabled_job(monkeypatch):
    registry = {"GuardianIntakeSweep": {"consecutive_failures": 10, "enabled": False}}
    set_list_calls = {}

    def get_list(args):
        if args["listName"] == "guardian_kill_switch":
            return [{"Type": 1, "Contents": '{"enabled": false}'}]
        return [{"Type": 1, "Contents": json.dumps(registry)}]

    _install(
        monkeypatch,
        {
            "getList": get_list,
            "setList": _capturing_set_list(set_list_calls),
            "GetTime": _get_time_handler(),
        },
    )
    result = jg.guardian_jobguard_report("GuardianIntakeSweep", "success")
    assert result["consecutive_failures"] == 0
    # still disabled -- a success never flips enabled back to True.
    assert result["enabled"] is False


def test_report_failure_increments_below_threshold(monkeypatch):
    registry = {"GuardianIntakeSweep": {"consecutive_failures": 2, "enabled": True}}
    set_list_calls = {}

    def get_list(args):
        if args["listName"] == "guardian_kill_switch":
            return [{"Type": 1, "Contents": '{"enabled": false}'}]
        if args["listName"] == "guardian_settings":
            return [{"Type": 1, "Contents": '{"job_guard_max_consecutive_failures": 10}'}]
        return [{"Type": 1, "Contents": json.dumps(registry)}]

    _install(
        monkeypatch,
        {
            "getList": get_list,
            "setList": _capturing_set_list(set_list_calls),
            "GetTime": _get_time_handler(),
        },
    )
    result = jg.guardian_jobguard_report("GuardianIntakeSweep", "failure")
    assert result["consecutive_failures"] == 3
    assert result["disabled_now"] is False
    assert result["enabled"] is True


def test_report_failure_at_threshold_disables_job_and_audits(monkeypatch):
    registry = {"GuardianIntakeSweep": {"consecutive_failures": 9, "enabled": True}}
    set_list_calls = {}
    audit_calls = []
    jobs_rest_calls = {"search": [], "post": []}

    def get_list(args):
        if args["listName"] == "guardian_kill_switch":
            return [{"Type": 1, "Contents": '{"enabled": false}'}]
        if args["listName"] == "guardian_settings":
            return [{"Type": 1, "Contents": '{"job_guard_max_consecutive_failures": 10}'}]
        return [{"Type": 1, "Contents": json.dumps(registry)}]

    def handle_audit(args):
        audit_calls.append(args)
        return [{"Type": 1, "Contents": "Guardian audit row written: action=job_disabled status=ok target=x"}]

    def jobs_search(body):
        jobs_rest_calls["search"].append(body)
        return {"data": [{"id": "GuardianIntakeSweep", "version": 5, "name": "GuardianIntakeSweep"}]}

    def jobs_post(body):
        jobs_rest_calls["post"].append(body)
        return {"id": "GuardianIntakeSweep", "version": 6}

    _install(
        monkeypatch,
        {
            "getList": get_list,
            "setList": _capturing_set_list(set_list_calls),
            "GetTime": _get_time_handler(),
            "GuardianAuditWrite": handle_audit,
            "demisto-api-post": _api_post_handler({"/jobs/search": jobs_search, "/jobs": jobs_post}),
        },
    )
    result = jg.guardian_jobguard_report("GuardianIntakeSweep", "failure")
    assert result["consecutive_failures"] == 10
    assert result["disabled_now"] is True
    assert result["enabled"] is False
    assert result["disable_rest_ok"] is True

    saved = json.loads(set_list_calls["calls"][0]["listData"])
    assert saved["GuardianIntakeSweep"]["enabled"] is False
    assert saved["GuardianIntakeSweep"]["disabled_ts"] is not None

    assert len(audit_calls) == 1
    assert audit_calls[0]["action"] == "job_disabled"

    assert jobs_rest_calls["search"][0]["query"] == 'name:"GuardianIntakeSweep"'
    assert jobs_rest_calls["post"][0]["forceDisable"] is True


def test_report_failure_disable_rest_failure_still_flips_local_registry(monkeypatch):
    registry = {"GuardianIntakeSweep": {"consecutive_failures": 9, "enabled": True}}
    set_list_calls = {}

    def get_list(args):
        if args["listName"] == "guardian_kill_switch":
            return [{"Type": 1, "Contents": '{"enabled": false}'}]
        if args["listName"] == "guardian_settings":
            return [{"Type": 1, "Contents": '{"job_guard_max_consecutive_failures": 10}'}]
        return [{"Type": 1, "Contents": json.dumps(registry)}]

    def jobs_search_not_found(args):
        return [{"Type": 1, "Contents": {"response": {"data": []}}}]

    _install(
        monkeypatch,
        {
            "getList": get_list,
            "setList": _capturing_set_list(set_list_calls),
            "GetTime": _get_time_handler(),
            "GuardianAuditWrite": lambda args: [{"Type": 1, "Contents": "Done"}],
            "demisto-api-post": jobs_search_not_found,
        },
    )
    result = jg.guardian_jobguard_report("GuardianIntakeSweep", "failure")
    assert result["disabled_now"] is True
    assert result["disable_rest_ok"] is False
    # the registry flip still happened even though the REST disable failed.
    saved = json.loads(set_list_calls["calls"][0]["listData"])
    assert saved["GuardianIntakeSweep"]["enabled"] is False


def test_report_bails_on_kill_switch_without_mutating_registry(monkeypatch):
    def get_list(args):
        assert args["listName"] == "guardian_kill_switch"
        return [{"Type": 1, "Contents": '{"enabled": true}'}]

    def boom_set_list(args):
        raise AssertionError("setList must not be called while the kill switch is engaged")

    _install(monkeypatch, {"getList": get_list, "setList": boom_set_list})
    result = jg.guardian_jobguard_report("GuardianIntakeSweep", "failure")
    assert result["proceed"] is False
    assert result["reason"] == "kill_switch_engaged"


def test_report_requires_job_name():
    result = jg.guardian_jobguard_report(None, "failure")
    assert "error" in result


def test_report_requires_valid_outcome():
    result = jg.guardian_jobguard_report("GuardianIntakeSweep", "maybe")
    assert "error" in result


# --- guardian_jobguard_disable_job_rest -----------------------------------------


def test_disable_job_rest_not_found(monkeypatch):
    _install(
        monkeypatch,
        {"demisto-api-post": _api_post_handler({"/jobs/search": lambda body: {"data": []}})},
    )
    result = jg.guardian_jobguard_disable_job_rest("NoSuchJob")
    assert result["ok"] is False
    assert "no scheduled Job found" in result["error"]


def test_disable_job_rest_server_rejects_spec(monkeypatch):
    _install(
        monkeypatch,
        {
            "demisto-api-post": _api_post_handler(
                {
                    "/jobs/search": lambda body: {"data": [{"id": "X", "name": "X"}]},
                    "/jobs": lambda body: {"id": "editJobErr", "error": "bad cron"},
                }
            )
        },
    )
    result = jg.guardian_jobguard_disable_job_rest("X")
    assert result["ok"] is False
    assert "server rejected" in result["error"]


def test_disable_job_rest_success(monkeypatch):
    _install(
        monkeypatch,
        {
            "demisto-api-post": _api_post_handler(
                {
                    "/jobs/search": lambda body: {"data": [{"id": "X", "name": "X", "version": 3}]},
                    "/jobs": lambda body: {"id": "X", "version": 4},
                }
            )
        },
    )
    result = jg.guardian_jobguard_disable_job_rest("X")
    assert result["ok"] is True
    assert result["data"]["job_id"] == "X"


# --- guardian_jobguard_run / main() dispatch ------------------------------------


def test_run_defaults_to_check_action(monkeypatch):
    _install(monkeypatch, {"getList": _get_list_handler("guardian_kill_switch", '{"enabled": false}')})
    result = jg.guardian_jobguard_run({"job_name": None})
    assert result["proceed"] is True


def test_run_rejects_bad_action():
    result = jg.guardian_jobguard_run({"action": "banana"})
    assert "error" in result


def test_main_check_success(monkeypatch):
    jg.RESULTS.clear()
    _install(monkeypatch, {"getList": _get_list_handler("guardian_kill_switch", '{"enabled": false}')})
    monkeypatch.setattr(jg.demisto, "args", lambda: {"action": "check", "job_name": "GuardianIntakeSweep"})
    jg.main()
    assert len(jg.RESULTS) == 1
    cr = jg.RESULTS[0]
    assert cr.outputs["proceed"] is True


def test_main_report_missing_outcome_return_error(monkeypatch):
    jg.RESULTS.clear()
    monkeypatch.setattr(jg.demisto, "args", lambda: {"action": "report", "job_name": "GuardianIntakeSweep"})
    import pytest

    with pytest.raises(SystemExit) as exc_info:
        jg.main()
    assert "outcome" in str(exc_info.value)


def test_main_unexpected_exception_return_error(monkeypatch):
    jg.RESULTS.clear()

    def boom(args):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(jg, "guardian_jobguard_run", boom)
    monkeypatch.setattr(jg.demisto, "args", lambda: {"action": "check", "job_name": "X"})
    import pytest

    with pytest.raises(SystemExit) as exc_info:
        jg.main()
    assert "unexpectedly" in str(exc_info.value)
