import json

import GuardianAuditWrite as gaw


# --- test fixtures ------------------------------------------------------------


def _get_time_stub(iso_value="2026-07-04T12:00:00.000Z", ok=True):
    """Fake demisto.executeCommand answering GetTime (and nothing else)."""

    def fake_execute(command, args):
        assert command == "GetTime"
        assert args == {"dateFormat": "ISO"}
        if ok:
            return [{"Type": 1, "Contents": iso_value}]
        return [{"Type": 4, "Contents": "GetTime is disabled"}]

    return fake_execute


def _multi_command_stub(handlers):
    """Fake demisto.executeCommand dispatching by command name to a
    {command_name: fn(args) -> entries} map. Raises if an unhandled command
    is invoked, so a test can't silently pass over an unexpected call.
    """

    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command: {} {}".format(command, args))
        return handlers[command](args)

    return fake_execute


def _list_handler(rows, list_name="guardian_audit"):
    def handle_get_list(args):
        assert args["listName"] == list_name
        return [{"Type": 1, "Contents": json.dumps(rows)}]

    return handle_get_list


def _capturing_set_list_handler(sink):
    def handle_set_list(args):
        sink["listName"] = args["listName"]
        sink["listData"] = json.loads(args["listData"])
        return [{"Type": 1, "Contents": "Done: list {} was updated".format(args["listName"])}]

    return handle_set_list


def _capturing_add_entries_handler(sink):
    def handle_add_entries(args):
        sink["calls"] = sink.get("calls", 0) + 1
        sink["last_args"] = args
        return [{"Type": 1, "Contents": "done"}]

    return handle_add_entries


def _install_happy_path(monkeypatch, existing_rows=None, get_time_value="2026-07-04T12:00:00.000Z"):
    """Wires GetTime, getList (returning `existing_rows`), setList, and
    addEntries all as success stubs, capturing the setList/addEntries calls
    for assertions. Returns the (set_list_sink, add_entries_sink) dicts.

    Defaults `demisto.incident()` to a real incident (an id present) --
    most tests here are exercising substrate behavior (List/War Room note),
    not the no-incident skip path, so they need the War Room note substrate
    to actually run. Tests for the no-incident skip path (indicator-triggered
    calls) override this back to `{}` explicitly.
    """
    existing_rows = existing_rows if existing_rows is not None else []
    set_list_sink = {}
    add_entries_sink = {}

    handlers = {
        "GetTime": lambda args: [{"Type": 1, "Contents": get_time_value}],
        "getList": _list_handler(existing_rows),
        "setList": _capturing_set_list_handler(set_list_sink),
        "addEntries": _capturing_add_entries_handler(add_entries_sink),
    }
    monkeypatch.setattr(gaw.demisto, "executeCommand", _multi_command_stub(handlers))
    monkeypatch.setattr(gaw.demisto, "context", lambda: {})
    monkeypatch.setattr(gaw.demisto, "setContext", lambda path, value: {"status": True})
    monkeypatch.setattr(gaw.demisto, "incident", lambda: {"id": "test-incident-1"})
    return set_list_sink, add_entries_sink


# --- guardian_audit_get_server_time -------------------------------------------


def test_get_server_time_uses_get_time_iso(monkeypatch):
    monkeypatch.setattr(gaw.demisto, "executeCommand", _get_time_stub("2026-07-04T11:37:17.394Z"))

    ts, warning = gaw.guardian_audit_get_server_time()

    assert ts == "2026-07-04T11:37:17.394Z"
    assert warning is None


def test_get_server_time_falls_back_to_incident_modified_when_get_time_fails(monkeypatch):
    monkeypatch.setattr(gaw.demisto, "executeCommand", _get_time_stub(ok=False))
    monkeypatch.setattr(gaw.demisto, "incident", lambda: {"modified": "2026-07-04T09:00:00Z"})

    ts, warning = gaw.guardian_audit_get_server_time()

    assert ts == "2026-07-04T09:00:00Z"
    assert warning is not None
    assert "degraded" in warning


def test_get_server_time_returns_none_and_warns_when_nothing_available(monkeypatch):
    monkeypatch.setattr(gaw.demisto, "executeCommand", _get_time_stub(ok=False))
    monkeypatch.setattr(gaw.demisto, "incident", lambda: {})

    ts, warning = gaw.guardian_audit_get_server_time()

    assert ts is None
    assert "never fabricated" in warning


def test_get_server_time_treats_go_zero_value_incident_modified_as_unavailable(monkeypatch):
    """The Go zero-value `dueDate`-style timestamp can also show up on
    `modified` for a never-touched incident record -- must not be used as a
    real fallback timestamp."""
    monkeypatch.setattr(gaw.demisto, "executeCommand", _get_time_stub(ok=False))
    monkeypatch.setattr(gaw.demisto, "incident", lambda: {"modified": "0001-01-01T00:00:00Z"})

    ts, warning = gaw.guardian_audit_get_server_time()

    assert ts is None
    assert "never fabricated" in warning


# --- guardian_audit_parse_detail / guardian_audit_parse_duration_ms -----------


def test_parse_detail_parses_json_object_string():
    assert gaw.guardian_audit_parse_detail('{"a": 1}') == {"a": 1}


def test_parse_detail_keeps_non_json_as_plain_text():
    assert gaw.guardian_audit_parse_detail("just some notes") == "just some notes"


def test_parse_detail_none_and_empty_string():
    assert gaw.guardian_audit_parse_detail(None) is None
    assert gaw.guardian_audit_parse_detail("") is None
    assert gaw.guardian_audit_parse_detail("   ") is None


def test_parse_detail_passes_through_non_string():
    assert gaw.guardian_audit_parse_detail({"already": "structured"}) == {"already": "structured"}


def test_parse_duration_ms_integer_and_float():
    assert gaw.guardian_audit_parse_duration_ms("120") == 120
    assert gaw.guardian_audit_parse_duration_ms("120.5") == 120.5
    assert gaw.guardian_audit_parse_duration_ms(120) == 120


def test_parse_duration_ms_unparseable_or_missing_is_none():
    assert gaw.guardian_audit_parse_duration_ms(None) is None
    assert gaw.guardian_audit_parse_duration_ms("") is None
    assert gaw.guardian_audit_parse_duration_ms("not-a-number") is None


# --- guardian_audit_build_row ("row shape") -----------------------------------


def test_build_row_shape_has_exactly_the_nine_fields():
    row = gaw.guardian_audit_build_row(
        action="ip",
        target="1.2.3.4",
        status="ok",
        duration_ms="42",
        actor="agent",
        tick_id="tick-1",
        run_id="123",
        detail='{"note": "fine"}',
        ts="2026-07-04T12:00:00Z",
    )

    assert set(row.keys()) == {
        "ts", "actor", "action", "target", "status", "duration_ms", "tick_id", "run_id", "detail",
    }
    assert row == {
        "ts": "2026-07-04T12:00:00Z",
        "actor": "agent",
        "action": "ip",
        "target": "1.2.3.4",
        "status": "ok",
        "duration_ms": 42,
        "tick_id": "tick-1",
        "run_id": "123",
        "detail": {"note": "fine"},
    }


def test_build_row_defaults_actor_when_falsy():
    row = gaw.guardian_audit_build_row(
        action="ip", target=None, status="ok", duration_ms=None, actor=None,
        tick_id=None, run_id=None, detail=None, ts="2026-07-04T12:00:00Z",
    )
    assert row["actor"] == "agent"


# --- redaction at capture ------------------------------------------------------


def test_write_redacts_secret_in_detail_before_anything_is_persisted(monkeypatch):
    """The core capture-time-redaction lesson: a secret embedded in `detail`
    must be masked in the row that is buffered, listed, AND noted -- never
    just scrubbed post-hoc on read."""
    set_list_sink, add_entries_sink = _install_happy_path(monkeypatch)

    result = gaw.guardian_audit_write(
        action="ip",
        target="1.2.3.4",
        status="ok",
        detail=json.dumps({"api_key": "sk-super-secret", "note": "safe to keep"}),
    )

    assert result["ok"] is True
    row = result["data"]["row"]
    assert row["detail"]["api_key"] == "***"
    assert row["detail"]["note"] == "safe to keep"

    # The List write persisted the REDACTED row, not the raw secret.
    persisted_row = set_list_sink["listData"][-1]
    assert persisted_row["detail"]["api_key"] == "***"

    # The War Room note body also carries the redacted value, never the raw
    # secret -- capture-time redaction, not a substrate-specific scrub.
    note_body = add_entries_sink["last_args"]["entries"][0]["Contents"]
    assert "sk-super-secret" not in note_body
    assert "***" in note_body


def test_write_redacts_nested_secret_in_detail(monkeypatch):
    """Non-recursion lesson: a secret nested two levels deep in `detail`
    must still be caught (guardian_redact recurses; a shallow/top-level-only
    scrub would miss this)."""
    set_list_sink, _ = _install_happy_path(monkeypatch)

    result = gaw.guardian_audit_write(
        action="setIncident",
        status="ok",
        detail=json.dumps({"payload": {"auth": {"token": "abc123"}}}),
    )

    row = result["data"]["row"]
    assert row["detail"]["payload"]["auth"]["token"] == "***"
    assert set_list_sink["listData"][-1]["detail"]["payload"]["auth"]["token"] == "***"


# --- append-not-overwrite -------------------------------------------------------


def test_write_appends_to_existing_rows_without_dropping_them(monkeypatch):
    existing = [
        {"ts": "2026-07-01T00:00:00Z", "actor": "agent", "action": "whois", "target": "x", "status": "ok",
         "duration_ms": None, "tick_id": None, "run_id": None, "detail": None},
        {"ts": "2026-07-02T00:00:00Z", "actor": "agent", "action": "url", "target": "y", "status": "ok",
         "duration_ms": None, "tick_id": None, "run_id": None, "detail": None},
    ]
    set_list_sink, _ = _install_happy_path(monkeypatch, existing_rows=existing)

    result = gaw.guardian_audit_write(action="ip", target="1.2.3.4", status="ok")

    assert result["ok"] is True
    saved = set_list_sink["listData"]
    assert len(saved) == 3
    assert saved[0]["action"] == "whois"
    assert saved[1]["action"] == "url"
    assert saved[2]["action"] == "ip"
    assert result["data"]["list_row_count"] == 3


def test_write_does_not_overwrite_when_list_was_already_populated_by_another_call(monkeypatch):
    """Simulates two sequential calls in the same test run -- the second
    call's read-append-write must still see the first call's row (this is
    NOT a concurrency test -- it's confirming the read-modify-write path
    itself doesn't clobber, independent of the documented cross-incident
    race caveat)."""
    rows = []

    def handle_get_list(args):
        return [{"Type": 1, "Contents": json.dumps(rows)}]

    def handle_set_list(args):
        rows[:] = json.loads(args["listData"])
        return [{"Type": 1, "Contents": "Done"}]

    handlers = {
        "GetTime": lambda args: [{"Type": 1, "Contents": "2026-07-04T12:00:00Z"}],
        "getList": handle_get_list,
        "setList": handle_set_list,
        "addEntries": lambda args: [{"Type": 1, "Contents": "done"}],
    }
    monkeypatch.setattr(gaw.demisto, "executeCommand", _multi_command_stub(handlers))
    monkeypatch.setattr(gaw.demisto, "context", lambda: {})
    monkeypatch.setattr(gaw.demisto, "setContext", lambda path, value: {"status": True})
    monkeypatch.setattr(gaw.demisto, "incident", lambda: {})

    gaw.guardian_audit_write(action="ip", status="ok")
    gaw.guardian_audit_write(action="whois", status="ok")

    assert [r["action"] for r in rows] == ["ip", "whois"]


# --- exactly-one-row-per-call ---------------------------------------------------


def test_write_appends_exactly_one_row_and_writes_exactly_one_entry(monkeypatch):
    set_list_sink, add_entries_sink = _install_happy_path(monkeypatch, existing_rows=[{"action": "prior"}])

    gaw.guardian_audit_write(action="ip", status="ok")

    assert len(set_list_sink["listData"]) == 2  # the one prior row + exactly one new row
    assert add_entries_sink["calls"] == 1  # exactly one War Room note


def test_write_buffers_exactly_one_row_into_incident_context(monkeypatch):
    _install_happy_path(monkeypatch)
    written = {}

    def fake_set_context(path, value):
        written[path] = value
        return {"status": True}

    monkeypatch.setattr(gaw.demisto, "setContext", fake_set_context)
    monkeypatch.setattr(gaw.demisto, "context", lambda: {})

    gaw.guardian_audit_write(action="ip", status="ok")

    assert len(written["Guardian.AuditBuffer"]) == 1
    assert written["Guardian.AuditBuffer"][0]["action"] == "ip"


def test_write_appends_to_existing_context_buffer_without_dropping_prior_rows(monkeypatch):
    _install_happy_path(monkeypatch)
    existing_buffer = [{"action": "whois", "status": "ok"}]
    monkeypatch.setattr(gaw.demisto, "context", lambda: {"Guardian": {"AuditBuffer": existing_buffer}})
    written = {}
    monkeypatch.setattr(gaw.demisto, "setContext", lambda path, value: written.setdefault(path, value))

    gaw.guardian_audit_write(action="ip", status="ok")

    buffer = written["Guardian.AuditBuffer"]
    assert len(buffer) == 2
    assert buffer[0]["action"] == "whois"
    assert buffer[1]["action"] == "ip"


# --- War Room note tagging -----------------------------------------------------


def test_write_tags_the_note_with_action_and_generic_audit_tag(monkeypatch):
    """Confirmed live (see guardian_audit_write_entry's docstring): Tags/Note
    must be set as PER-ENTRY fields inside `entries`, not as top-level
    `addEntries` command args (those are silently accepted but ignored)."""
    _, add_entries_sink = _install_happy_path(monkeypatch)

    gaw.guardian_audit_write(action="ip", status="ok")

    entry = add_entries_sink["last_args"]["entries"][0]
    assert "guardian-audit" in entry["Tags"]
    assert "guardian-audit:ip" in entry["Tags"]
    assert entry["Note"] is True
    assert "tags" not in add_entries_sink["last_args"]
    assert "note" not in add_entries_sink["last_args"]


# --- validation / NEEDS_CONTEXT paths -------------------------------------------


def test_write_rejects_missing_action(monkeypatch):
    _install_happy_path(monkeypatch)

    result = gaw.guardian_audit_write(action=None, status="ok")

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_write_rejects_invalid_status(monkeypatch):
    _install_happy_path(monkeypatch)

    result = gaw.guardian_audit_write(action="ip", status="totally-not-a-status")

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]
    assert "status" in result["error"]


def test_write_accepts_halted_status(monkeypatch):
    """"halted" was added for Task 1.3 (GuardianToolBridge) -- the
    kill-switch-active outcome, a tool call that never reached the
    denylist/policy/execute steps at all."""
    _install_happy_path(monkeypatch)

    result = gaw.guardian_audit_write(action="ip", status="halted")

    assert result["ok"] is True
    assert result["data"]["row"]["status"] == "halted"


def test_write_defaults_run_id_to_current_incident_id(monkeypatch):
    _install_happy_path(monkeypatch)
    monkeypatch.setattr(gaw.demisto, "incident", lambda: {"id": "999"})

    result = gaw.guardian_audit_write(action="ip", status="ok")

    assert result["data"]["row"]["run_id"] == "999"


def test_write_prefers_explicit_run_id_over_incident_id(monkeypatch):
    _install_happy_path(monkeypatch)
    monkeypatch.setattr(gaw.demisto, "incident", lambda: {"id": "999"})

    result = gaw.guardian_audit_write(action="ip", status="ok", run_id="explicit-run")

    assert result["data"]["row"]["run_id"] == "explicit-run"


# --- no-incident context (indicator-triggered calls) -------------------------
#
# Guardian's own SOC Agent indicator governance buttons (e.g. Apply Policy)
# call this script directly from an indicator action button -- there is no
# incident/investigation behind that execution at all, and `addEntries`
# always fails there ("Item not found"; confirmed live). The War Room note
# substrate is skipped -- not attempted-and-failed -- in that case, so a
# clean policy apply doesn't carry a permanent, unactionable "Warning".
#
# IMPORTANT (confirmed live, not assumed -- a first attempt at this fix got
# this wrong): `demisto.incident()` does NOT return `{}`/no-id for these
# calls. It returns a fully-populated, real-looking dict -- id,
# investigationId, the works -- for every script execution, incident-bound
# or not. The actual tell is `name == "Do Not Use Me"` (the server's own
# hardcoded placeholder for a synthetic execution context), with every
# lifecycle timestamp left at the Go zero-value. The `{}` shape below is
# still worth covering (a defensive `demisto.incident() or {}` fallback), but
# it is NOT what the platform actually sends here -- see the
# `_DO_NOT_USE_ME_INCIDENT` fixture for the real shape.


_DO_NOT_USE_ME_INCIDENT = {
    "id": "9bb15437-8467-48fc-82d0-82ae50c596e2",
    "investigationId": "9bb15437-8467-48fc-82d0-82ae50c596e2",
    "name": "Do Not Use Me",
    "isPlayground": False,
    "isDebug": False,
    "created": "0001-01-01T00:00:00Z",
    "closed": "0001-01-01T00:00:00Z",
    "modified": "0001-01-01T00:00:00Z",
}


def test_write_skips_war_room_note_for_the_do_not_use_me_placeholder_incident(monkeypatch):
    """The real, live-observed shape: an indicator action button click
    (Apply Policy, etc.) gives `demisto.incident()` a real `id` bound to the
    server's "Do Not Use Me" placeholder, not an empty dict."""
    set_list_sink, add_entries_sink = _install_happy_path(monkeypatch)
    monkeypatch.setattr(gaw.demisto, "incident", lambda: dict(_DO_NOT_USE_ME_INCIDENT))

    result = gaw.guardian_audit_write(action="guardian-soc-agent-apply-tool-policy", status="ok")

    assert result["ok"] is True
    assert "calls" not in add_entries_sink  # addEntries was never invoked
    assert result["data"]["war_room_note_skipped"] == "no incident/investigation context"
    # The row is still durably captured in the List substrate -- nothing lost.
    assert set_list_sink["listData"][-1]["action"] == "guardian-soc-agent-apply-tool-policy"


def test_write_skips_war_room_note_when_no_incident_context(monkeypatch):
    """Defensive coverage for the `demisto.incident() or {}` fallback --
    not the shape actually observed live (see the placeholder test above),
    but still a case the guard must handle."""
    set_list_sink, add_entries_sink = _install_happy_path(monkeypatch)
    monkeypatch.setattr(gaw.demisto, "incident", lambda: {})

    result = gaw.guardian_audit_write(action="guardian-soc-agent-apply-tool-policy", status="ok")

    assert result["ok"] is True
    assert "calls" not in add_entries_sink  # addEntries was never invoked
    assert result["data"]["war_room_note_skipped"] == "no incident/investigation context"
    # The row is still durably captured in the List substrate -- nothing lost.
    assert set_list_sink["listData"][-1]["action"] == "guardian-soc-agent-apply-tool-policy"


def test_write_skips_war_room_note_even_with_an_explicit_run_id(monkeypatch):
    """An explicit `run_id` is row metadata only -- it does not change WHERE
    `addEntries` posts to (the current investigation). Passing one must not
    be mistaken for "there is an incident to write into"."""
    _, add_entries_sink = _install_happy_path(monkeypatch)
    monkeypatch.setattr(gaw.demisto, "incident", lambda: dict(_DO_NOT_USE_ME_INCIDENT))

    result = gaw.guardian_audit_write(action="ip", status="ok", run_id="some-other-incident")

    assert result["ok"] is True
    assert "calls" not in add_entries_sink
    assert result["data"]["row"]["run_id"] == "some-other-incident"


# --- resilience: List failure must not block the War Room note ---------------


def test_write_still_writes_war_room_note_when_list_read_fails(monkeypatch):
    """A genuine (non-"item not found") List failure -- e.g. a transient
    server error -- must not block the War Room note, and must NOT trigger
    the missing-List bootstrap path (that's a distinct, narrower signal;
    see the bootstrap-specific tests below)."""
    add_entries_sink = {}
    errors = []

    handlers = {
        "GetTime": lambda args: [{"Type": 1, "Contents": "2026-07-04T12:00:00Z"}],
        "getList": lambda args: [{"Type": 4, "Contents": "internal server error (500)"}],
        "addEntries": _capturing_add_entries_handler(add_entries_sink),
    }
    monkeypatch.setattr(gaw.demisto, "executeCommand", _multi_command_stub(handlers))
    monkeypatch.setattr(gaw.demisto, "context", lambda: {})
    monkeypatch.setattr(gaw.demisto, "setContext", lambda path, value: {"status": True})
    monkeypatch.setattr(gaw.demisto, "incident", lambda: {"id": "test-incident-1"})
    monkeypatch.setattr(gaw.demisto, "error", lambda *a: errors.append(" ".join(str(x) for x in a)))

    result = gaw.guardian_audit_write(action="ip", status="ok")

    assert result["ok"] is True  # overall call still succeeds
    assert result["data"]["list_warning"] is not None
    assert errors and "internal server error" in errors[0]
    assert add_entries_sink["calls"] == 1  # the note still went out


# --- defensive self-bootstrap on a missing List (RUNTIME-MUTABLE LISTS ARE
# RUNTIME-CREATED, NEVER PACK-SEEDED: `guardian_audit` is no longer
# pack-delivered as of Task 1.4b, so it may still be missing on a box where
# GuardianBootstrap hasn't run yet -- this script's own fallback must create
# it here, exactly once) -----------------------------------------------------


def test_load_list_bootstraps_via_create_list_when_missing(monkeypatch):
    create_calls = []

    def handle_get_list(args):
        return [{"Type": 4, "Contents": "Item not found (8) on list [guardian_audit]"}]

    def handle_create_list(args):
        create_calls.append(args)
        return [{"Type": 1, "Contents": "Done: list {} was updated".format(args["listName"])}]

    monkeypatch.setattr(
        gaw.demisto,
        "executeCommand",
        _multi_command_stub({"getList": handle_get_list, "createList": handle_create_list}),
    )

    result = gaw.guardian_audit_load_list()

    assert result["ok"] is True
    assert result["data"] == []
    assert len(create_calls) == 1
    assert create_calls[0] == {"listName": "guardian_audit", "listData": "[]"}


def test_load_list_does_not_bootstrap_on_a_different_getlist_failure(monkeypatch):
    """createList must NEVER be called speculatively -- only on the specific
    "item not found" signal -- since createList is create-OR-OVERWRITE and
    would silently destroy real rows if called on any other kind of
    (possibly transient) getList failure."""

    def handle_get_list(args):
        return [{"Type": 4, "Contents": "rate limit exceeded (429)"}]

    monkeypatch.setattr(
        gaw.demisto,
        "executeCommand",
        _multi_command_stub({"getList": handle_get_list}),  # no createList handler -- must not be called
    )

    result = gaw.guardian_audit_load_list()

    assert result["ok"] is False
    assert "rate limit" in result["error"]


def test_write_end_to_end_bootstraps_list_then_appends_row(monkeypatch):
    """Simulates a genuinely fresh box: the List doesn't exist yet, gets
    bootstrapped via createList, and the very same call's row still lands
    via setList right after."""
    set_list_sink = {}
    add_entries_sink = {}
    state = {"exists": False, "rows": []}

    def handle_get_list(args):
        if not state["exists"]:
            return [{"Type": 4, "Contents": "Item not found (8) on list [guardian_audit]"}]
        return [{"Type": 1, "Contents": json.dumps(state["rows"])}]

    def handle_create_list(args):
        state["exists"] = True
        state["rows"] = json.loads(args["listData"])
        return [{"Type": 1, "Contents": "Done"}]

    def handle_set_list(args):
        set_list_sink["listData"] = json.loads(args["listData"])
        state["rows"] = set_list_sink["listData"]
        return [{"Type": 1, "Contents": "Done"}]

    handlers = {
        "GetTime": lambda args: [{"Type": 1, "Contents": "2026-07-04T12:00:00Z"}],
        "getList": handle_get_list,
        "createList": handle_create_list,
        "setList": handle_set_list,
        "addEntries": _capturing_add_entries_handler(add_entries_sink),
    }
    monkeypatch.setattr(gaw.demisto, "executeCommand", _multi_command_stub(handlers))
    monkeypatch.setattr(gaw.demisto, "context", lambda: {})
    monkeypatch.setattr(gaw.demisto, "setContext", lambda path, value: {"status": True})
    monkeypatch.setattr(gaw.demisto, "incident", lambda: {})

    result = gaw.guardian_audit_write(action="ip", status="ok")

    assert result["ok"] is True
    assert result["data"]["list_warning"] is None
    assert set_list_sink["listData"] == [result["data"]["row"]]


def test_write_fails_overall_when_war_room_note_write_fails(monkeypatch):
    set_list_sink, _ = _install_happy_path(monkeypatch)
    monkeypatch.setattr(
        gaw.demisto,
        "executeCommand",
        _multi_command_stub(
            {
                "GetTime": lambda args: [{"Type": 1, "Contents": "2026-07-04T12:00:00Z"}],
                "getList": _list_handler([]),
                "setList": _capturing_set_list_handler(set_list_sink),
                "addEntries": lambda args: [{"Type": 4, "Contents": "boom"}],
            }
        ),
    )

    result = gaw.guardian_audit_write(action="ip", status="ok")

    assert result["ok"] is False
    assert "War Room" in result["error"]


# --- main() --------------------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    _install_happy_path(monkeypatch)
    monkeypatch.setattr(
        gaw.demisto,
        "args",
        lambda: {"action": "ip", "target": "1.2.3.4", "status": "ok"},
    )
    captured = {}
    monkeypatch.setattr(gaw, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    gaw.main()

    assert "result" in captured
    assert captured["result"].outputs["action"] == "ip"


def test_main_calls_return_error_on_failure(monkeypatch):
    _install_happy_path(monkeypatch)
    monkeypatch.setattr(gaw.demisto, "args", lambda: {"action": None, "status": "ok"})
    errors = []
    monkeypatch.setattr(gaw, "return_error", lambda msg: errors.append(msg), raising=False)

    gaw.main()

    assert errors
    assert "NEEDS_CONTEXT" in errors[0]
