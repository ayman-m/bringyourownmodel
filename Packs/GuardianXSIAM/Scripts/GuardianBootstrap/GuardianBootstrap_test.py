import json

import GuardianBootstrap as gb


# --- test fixtures ------------------------------------------------------------


def _multi_command_stub(handlers):
    """Fake demisto.executeCommand dispatching by command name to a
    {command_name: fn(args) -> entries} map. Raises if an unhandled command
    is invoked, so a test can't silently pass over an unexpected call --
    mirrors GuardianAuditWrite_test.py's identically-named helper.
    """

    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command: {} {}".format(command, args))
        return handlers[command](args)

    return fake_execute


def _not_found_get_list(args):
    """Fake getList response for a genuinely-missing List -- the exact
    "item not found" shape confirmed live against the lab tenant during Task 1.4's
    build (`!getList listName=<missing>` -> `"Item not found (8) on list
    [...]"`)."""
    return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(args.get("listName"))}]


def _existing_get_list(contents):
    """Fake getList response for a List that already exists, with `contents`
    as its raw `Contents` string (or None/other type, for edge cases)."""

    def handler(args):
        return [{"Type": 1, "Contents": contents}]

    return handler


def _get_list_error(message):
    """Fake getList response for a failure that is NOT the "item not found"
    shape (e.g. a transient/connectivity error) -- must never be treated as
    "safe to createList"."""

    def handler(args):
        return [{"Type": 4, "Contents": message}]

    return handler


def _capturing_create_list_handler(sink, ok=True):
    def handler(args):
        sink.setdefault("calls", []).append(dict(args))
        if ok:
            return [{"Type": 1, "Contents": "Done: list {} was created".format(args["listName"])}]
        return [{"Type": 4, "Contents": "createList failed: disk full"}]

    return handler


# --- GUARDIAN_BOOTSTRAP_TARGETS -----------------------------------------------


def test_bootstrap_targets_cover_exactly_the_ten_runtime_mutable_lists():
    names = [name for name, _ in gb.GUARDIAN_BOOTSTRAP_TARGETS]
    assert names == [
        "guardian_kill_switch",
        "guardian_audit",
        "guardian_cost_ledger",
        "guardian_memory",
        "guardian_approvals_ledger",
        "guardian_jobs_registry",
        "guardian_seed_version",
        "guardian_skills_crud_index",
        "guardian_model_calibration",
        "guardian_model_profile",
    ]


def test_bootstrap_target_defaults_match_spec():
    defaults = dict(gb.GUARDIAN_BOOTSTRAP_TARGETS)
    assert defaults["guardian_kill_switch"] == {"enabled": False}
    assert defaults["guardian_audit"] == []
    # Task 1.7: `guardian_cost_ledger`'s real shape is an incremental rollup
    # OBJECT, not an append-only row array -- see GuardianBootstrap.py's
    # GUARDIAN_BOOTSTRAP_TARGETS comment and GuardianCostLedger.py's module
    # docstring for why.
    assert defaults["guardian_cost_ledger"] == {}
    assert defaults["guardian_memory"] == []
    assert defaults["guardian_approvals_ledger"] == []
    assert defaults["guardian_jobs_registry"] == {}
    assert defaults["guardian_seed_version"] == {"version": "0.0.1"}
    # Task 3.3: GuardianSkillsCRUD's own mutable registry -- see
    # GuardianBootstrap.py's module docstring "Task 3.3 hit the SAME wall"
    # section for why this can't simply be guardian_skills_index itself.
    assert defaults["guardian_skills_crud_index"] == []
    # Live-caught 2026-08-25: GuardianProbeModel's diagnostic calibration history -- see
    # GuardianBootstrap.py's GUARDIAN_BOOTSTRAP_TARGETS comment and GuardianProbeModel.py's own
    # write-site comment for why this is DIAGNOSTIC ONLY, never wired into agent behavior.
    assert defaults["guardian_model_calibration"] == {}


# --- guardian_bootstrap_ensure_list: creates-when-absent ----------------------


def test_ensure_list_creates_when_not_found(monkeypatch):
    create_sink = {}
    handlers = {
        "getList": _not_found_get_list,
        "createList": _capturing_create_list_handler(create_sink),
    }
    monkeypatch.setattr(gb.demisto, "executeCommand", _multi_command_stub(handlers))

    result = gb.guardian_bootstrap_ensure_list("guardian_kill_switch", {"enabled": False})

    assert result["ok"] is True
    assert result["data"] == {"list_name": "guardian_kill_switch", "action": "created"}
    assert len(create_sink["calls"]) == 1
    call = create_sink["calls"][0]
    assert call["listName"] == "guardian_kill_switch"
    assert json.loads(call["listData"]) == {"enabled": False}


def test_ensure_list_creates_when_contents_blank_string(monkeypatch):
    create_sink = {}
    handlers = {
        "getList": _existing_get_list(""),
        "createList": _capturing_create_list_handler(create_sink),
    }
    monkeypatch.setattr(gb.demisto, "executeCommand", _multi_command_stub(handlers))

    result = gb.guardian_bootstrap_ensure_list("guardian_audit", [])

    assert result["ok"] is True
    assert result["data"]["action"] == "created"
    assert len(create_sink["calls"]) == 1
    assert json.loads(create_sink["calls"][0]["listData"]) == []


def test_ensure_list_creates_when_contents_whitespace_only(monkeypatch):
    create_sink = {}
    handlers = {
        "getList": _existing_get_list("   \n  "),
        "createList": _capturing_create_list_handler(create_sink),
    }
    monkeypatch.setattr(gb.demisto, "executeCommand", _multi_command_stub(handlers))

    result = gb.guardian_bootstrap_ensure_list("guardian_cost_ledger", [])

    assert result["ok"] is True
    assert result["data"]["action"] == "created"
    assert len(create_sink["calls"]) == 1


def test_ensure_list_creates_when_contents_is_missing_entirely(monkeypatch):
    """getList succeeds but the entry carries no "Contents" key at all --
    treated the same as blank, not as a hard failure."""
    create_sink = {}

    def handle_get_list(args):
        return [{"Type": 1}]

    handlers = {
        "getList": handle_get_list,
        "createList": _capturing_create_list_handler(create_sink),
    }
    monkeypatch.setattr(gb.demisto, "executeCommand", _multi_command_stub(handlers))

    result = gb.guardian_bootstrap_ensure_list("guardian_memory", [])

    assert result["ok"] is True
    assert result["data"]["action"] == "created"
    assert len(create_sink["calls"]) == 1


# --- guardian_bootstrap_ensure_list: skips-when-present -----------------------


def test_ensure_list_skips_when_already_present_matching_default(monkeypatch):
    create_sink = {}
    handlers = {
        "getList": _existing_get_list("[]"),
        "createList": _capturing_create_list_handler(create_sink),
    }
    monkeypatch.setattr(gb.demisto, "executeCommand", _multi_command_stub(handlers))

    result = gb.guardian_bootstrap_ensure_list("guardian_audit", [])

    assert result["ok"] is True
    assert result["data"] == {"list_name": "guardian_audit", "action": "already_present"}
    assert create_sink == {}  # createList never called


def test_ensure_list_skips_when_already_present_with_real_accumulated_state(monkeypatch):
    """The whole point of the idempotency guard: a List that already holds
    real accumulated rows must never be touched, no matter how it differs
    from the default -- createList is create-OR-OVERWRITE and calling it
    here would silently destroy that state."""
    create_sink = {}
    existing_rows = json.dumps([{"ts": "2026-01-01T00:00:00Z", "action": "ip"}])
    handlers = {
        "getList": _existing_get_list(existing_rows),
        "createList": _capturing_create_list_handler(create_sink),
    }
    monkeypatch.setattr(gb.demisto, "executeCommand", _multi_command_stub(handlers))

    result = gb.guardian_bootstrap_ensure_list("guardian_audit", [])

    assert result["ok"] is True
    assert result["data"]["action"] == "already_present"
    assert create_sink == {}


def test_ensure_list_skips_when_contents_is_non_string_non_empty(monkeypatch):
    """A server that hands back already-parsed (non-string) Contents -- a
    non-empty dict/list is still "present with content", not "empty"."""
    create_sink = {}
    handlers = {
        "getList": _existing_get_list({"enabled": True}),
        "createList": _capturing_create_list_handler(create_sink),
    }
    monkeypatch.setattr(gb.demisto, "executeCommand", _multi_command_stub(handlers))

    result = gb.guardian_bootstrap_ensure_list("guardian_kill_switch", {"enabled": False})

    assert result["ok"] is True
    assert result["data"]["action"] == "already_present"
    assert create_sink == {}


# --- guardian_bootstrap_ensure_list: error handling ---------------------------


def test_ensure_list_reports_error_on_non_not_found_get_list_failure(monkeypatch):
    """A genuinely different getList failure (e.g. transient/connectivity)
    must NOT be treated as "safe to createList" -- only the exact
    "item not found" signal does that."""
    create_sink = {}
    handlers = {
        "getList": _get_list_error("Error: connection reset by peer"),
        "createList": _capturing_create_list_handler(create_sink),
    }
    monkeypatch.setattr(gb.demisto, "executeCommand", _multi_command_stub(handlers))

    result = gb.guardian_bootstrap_ensure_list("guardian_jobs_registry", {})

    assert result["ok"] is False
    assert result["data"]["action"] == "error"
    assert "connection reset" in result["error"]
    assert create_sink == {}  # never called


def test_ensure_list_reports_error_when_create_list_fails(monkeypatch):
    create_sink = {}
    handlers = {
        "getList": _not_found_get_list,
        "createList": _capturing_create_list_handler(create_sink, ok=False),
    }
    monkeypatch.setattr(gb.demisto, "executeCommand", _multi_command_stub(handlers))

    result = gb.guardian_bootstrap_ensure_list("guardian_seed_version", {"version": "0.0.1"})

    assert result["ok"] is False
    assert result["data"]["action"] == "error"
    assert "disk full" in result["error"]
    assert len(create_sink["calls"]) == 1  # createList WAS attempted


# --- guardian_bootstrap_run: full sweep ---------------------------------------


def test_bootstrap_run_all_absent_creates_every_target_with_correct_default(monkeypatch):
    create_sink = {}
    handlers = {
        "getList": _not_found_get_list,
        "createList": _capturing_create_list_handler(create_sink),
    }
    monkeypatch.setattr(gb.demisto, "executeCommand", _multi_command_stub(handlers))

    result = gb.guardian_bootstrap_run()

    assert result["ok"] is True
    assert result["data"]["errors"] == []
    assert result["data"]["already_present"] == []
    assert set(result["data"]["created"]) == {name for name, _ in gb.GUARDIAN_BOOTSTRAP_TARGETS}

    calls_by_name = {call["listName"]: json.loads(call["listData"]) for call in create_sink["calls"]}
    assert calls_by_name == {
        "guardian_kill_switch": {"enabled": False},
        "guardian_audit": [],
        "guardian_cost_ledger": {},
        "guardian_memory": [],
        "guardian_approvals_ledger": [],
        "guardian_jobs_registry": {},
        "guardian_seed_version": {"version": "0.0.1"},
        "guardian_skills_crud_index": [],
        "guardian_model_calibration": {},
        "guardian_model_profile": {},
    }


def test_bootstrap_run_all_present_creates_nothing(monkeypatch):
    create_sink = {}

    def handle_get_list(args):
        # Every List already has SOME content -- doesn't need to match the
        # real default, just needs to be non-blank.
        return [{"Type": 1, "Contents": "{}"}]

    handlers = {
        "getList": handle_get_list,
        "createList": _capturing_create_list_handler(create_sink),
    }
    monkeypatch.setattr(gb.demisto, "executeCommand", _multi_command_stub(handlers))

    result = gb.guardian_bootstrap_run()

    assert result["ok"] is True
    assert result["data"]["created"] == []
    assert set(result["data"]["already_present"]) == {name for name, _ in gb.GUARDIAN_BOOTSTRAP_TARGETS}
    assert result["data"]["errors"] == []
    assert create_sink == {}


def test_bootstrap_run_is_best_effort_across_targets(monkeypatch):
    """One target's getList/createList failure must not stop the sweep over
    the remaining targets -- every target gets attempted regardless."""
    create_sink = {}

    def handle_get_list(args):
        name = args["listName"]
        if name == "guardian_memory":
            return [{"Type": 4, "Contents": "Error: connection reset by peer"}]
        if name == "guardian_jobs_registry":
            return [{"Type": 1, "Contents": '{"already": "here"}'}]
        return _not_found_get_list(args)

    handlers = {
        "getList": handle_get_list,
        "createList": _capturing_create_list_handler(create_sink),
    }
    monkeypatch.setattr(gb.demisto, "executeCommand", _multi_command_stub(handlers))

    result = gb.guardian_bootstrap_run()

    assert result["ok"] is False  # at least one error -> overall not ok
    assert result["data"]["already_present"] == ["guardian_jobs_registry"]
    assert result["data"]["errors"] == [
        {"list_name": "guardian_memory", "error": result["data"]["errors"][0]["error"]}
    ]
    assert "connection reset" in result["data"]["errors"][0]["error"]
    # every OTHER target (7 of 9) still got created despite the one failure
    assert set(result["data"]["created"]) == {
        "guardian_kill_switch",
        "guardian_audit",
        "guardian_cost_ledger",
        "guardian_approvals_ledger",
        "guardian_seed_version",
        "guardian_skills_crud_index",
        "guardian_model_calibration",
        "guardian_model_profile",
    }
    created_names = {call["listName"] for call in create_sink["calls"]}
    assert created_names == set(result["data"]["created"])


# --- main() --------------------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    handlers = {
        "getList": _not_found_get_list,
        "createList": _capturing_create_list_handler({}),
    }
    monkeypatch.setattr(gb.demisto, "executeCommand", _multi_command_stub(handlers))
    captured = {}
    monkeypatch.setattr(gb, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    gb.main()

    assert "result" in captured
    assert "10 created, 0 already present, 0 error(s)" in captured["result"].readable_output
    assert set(captured["result"].outputs["created"]) == {name for name, _ in gb.GUARDIAN_BOOTSTRAP_TARGETS}
    assert captured["result"].outputs["errors"] == []
    assert captured["result"].outputs_prefix == "Guardian.Bootstrap"


def test_main_calls_return_error_on_partial_failure(monkeypatch):
    handlers = {
        "getList": _get_list_error("Error: connection reset by peer"),
        "createList": _capturing_create_list_handler({}),
    }
    monkeypatch.setattr(gb.demisto, "executeCommand", _multi_command_stub(handlers))
    errors = []
    monkeypatch.setattr(gb, "return_error", lambda msg: errors.append(msg), raising=False)
    results = []
    monkeypatch.setattr(gb, "return_results", lambda cr: results.append(cr), raising=False)

    gb.main()

    assert errors
    assert "one or more target Lists failed to bootstrap" in errors[0]
    assert not results  # return_results must NOT also fire on the failure path


def test_main_unexpected_exception_calls_return_error(monkeypatch):
    """Belt-and-suspenders: guardian_bootstrap_run() itself should never
    raise (guardian_execute swallows every executeCommand exception into an
    envelope), but main() is the automation's only entry point and must
    never surface an unhandled traceback if it somehow does."""

    def boom():
        raise RuntimeError("kaboom")

    monkeypatch.setattr(gb, "guardian_bootstrap_run", boom)
    errors = []
    monkeypatch.setattr(gb, "return_error", lambda msg: errors.append(msg), raising=False)

    gb.main()

    assert errors
    assert "kaboom" in errors[0]
