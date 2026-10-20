import json

import GuardianHousekeeping as hk


# --- test harness ----------------------------------------------------------------


def _multi_command_stub(handlers):
    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command: {} {}".format(command, args))
        return handlers[command](args)

    return fake_execute


def _get_list_router(lists):
    """`lists`: {list_name: contents_string_or_value}. Missing keys ->
    "item not found" error entry."""

    def handler(args):
        name = args["listName"]
        if name not in lists:
            return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(name)}]
        return [{"Type": 1, "Contents": lists[name]}]

    return handler


def _capturing_set_list(sink):
    def handler(args):
        sink.setdefault("calls", []).append(dict(args))
        return [{"Type": 1, "Contents": "Done: list updated"}]

    return handler


def _capturing_create_list(sink, ok=True):
    def handler(args):
        sink.setdefault("calls", []).append(dict(args))
        if ok:
            return [{"Type": 1, "Contents": "Done: list created"}]
        return [{"Type": 4, "Contents": "disk full"}]

    return handler


def _get_time_handler(ts="2026-07-06T12:00:00.000Z"):
    def handler(args):
        return [{"Type": 1, "Contents": ts}]

    return handler


def _api_post_router(routes):
    """`routes`: {uri: fn(body_obj) -> response_value}. Wraps like the real
    Core REST API integration (`{"response": ...}`)."""

    def handler(args):
        uri = args["uri"]
        body = json.loads(args["body"])
        for prefix, fn in routes.items():
            if uri == prefix or (callable(prefix) and prefix(uri)):
                return [{"Type": 1, "Contents": {"response": fn(uri, body)}}]
        raise AssertionError("unrouted demisto-api-post uri: {}".format(uri))

    return handler


def _install(monkeypatch, handlers):
    monkeypatch.setattr(hk.demisto, "executeCommand", _multi_command_stub(handlers))
    monkeypatch.setattr(hk.demisto, "error", lambda msg: None)


#: Sentinel telling `_entry_execute_sync_router` to simulate a FAILED remote
#: probe (a `Type==4` inner entry) for that investigationId, instead of a
#: successful JSON payload.
_PROBE_ERROR = object()


def _entry_execute_sync_router(probe_map):
    """Fake `demisto-api-post` handler for `/entry/execute/sync` calls that
    distinguishes a `probe_key=` remote self-invocation (see
    `guardian_hk_read_incident_context`'s docstring -- the REAL mechanism,
    not a `${...}` DT-query) from a real remote action (`Set`/
    `GuardianReasoningTick`/`GuardianAuditWrite`), which always gets a
    generic success response. `probe_map`: ``{investigationId: value}``
    (or `_PROBE_ERROR` for that id to simulate a failed remote probe).
    Mirrors the RAW REST shape `/entry/execute/sync` actually returns
    (lowercase `contents`/`type` keys, confirmed live -- distinct from the
    CAPITALIZED `Contents`/`Type` shape `demisto.executeCommand` hands back
    to Python code, which is what wraps this as the OUTER entry).
    """

    def handler(args):
        assert args["uri"] == "/entry/execute/sync"
        body = json.loads(args["body"])
        inv_id = body["investigationId"]
        data = body["data"]
        if "probe_key=" in data:
            if inv_id not in probe_map:
                raise AssertionError("no probe response configured for investigationId {}".format(inv_id))
            value = probe_map[inv_id]
            if value is _PROBE_ERROR:
                inner = [{"type": 4, "contents": "boom"}]
            else:
                inner = [{"type": 1, "contents": json.dumps(value)}]
        else:
            inner = [{"type": 1, "contents": "ok"}]
        return [{"Type": 1, "Contents": {"response": inner}}]

    return handler


# --- guardian_hk_parse_iso / minutes_since ---------------------------------------


def test_parse_iso_z_suffix():
    dt = hk.guardian_hk_parse_iso("2026-07-06T12:00:00.000Z")
    assert dt is not None
    assert dt.year == 2026 and dt.month == 7 and dt.day == 6


def test_parse_iso_rejects_go_zero_value():
    assert hk.guardian_hk_parse_iso("0001-01-01T00:00:00Z") is None


def test_parse_iso_rejects_blank_and_none():
    assert hk.guardian_hk_parse_iso("") is None
    assert hk.guardian_hk_parse_iso("   ") is None
    assert hk.guardian_hk_parse_iso(None) is None


def test_parse_iso_rejects_garbage():
    assert hk.guardian_hk_parse_iso("not-a-date") is None


def test_minutes_since_normal():
    minutes = hk.guardian_hk_minutes_since("2026-07-06T11:00:00.000Z", "2026-07-06T12:00:00.000Z")
    assert abs(minutes - 60.0) < 0.01


def test_minutes_since_unparseable_returns_none():
    assert hk.guardian_hk_minutes_since("garbage", "2026-07-06T12:00:00.000Z") is None
    assert hk.guardian_hk_minutes_since("2026-07-06T11:00:00.000Z", None) is None


# --- guardian_hk_load_settings ----------------------------------------------------


def test_load_settings_defaults_when_missing(monkeypatch):
    _install(monkeypatch, {"getList": _get_list_router({})})
    settings = hk.guardian_hk_load_settings()
    assert settings["approval_sla_minutes"] == 60
    assert settings["audit_retention_days"] == 30
    assert settings["stalled_run_minutes"] == 15
    assert settings["watchdog_policy"] == {"pending": "rearm", "awaiting_analyst": "rearm", "running": "reap"}


def test_load_settings_honors_overrides(monkeypatch):
    _install(
        monkeypatch,
        {
            "getList": _get_list_router(
                {
                    "guardian_settings": json.dumps(
                        {
                            "approval_sla_minutes": 30,
                            "audit_retention_days": 7,
                            "stalled_run_minutes": 5,
                            "watchdog_policy": {"running": "rearm"},
                        }
                    )
                }
            )
        },
    )
    settings = hk.guardian_hk_load_settings()
    assert settings["approval_sla_minutes"] == 30
    assert settings["audit_retention_days"] == 7
    assert settings["stalled_run_minutes"] == 5
    assert settings["watchdog_policy"]["running"] == "rearm"
    assert settings["watchdog_policy"]["pending"] == "rearm"  # untouched default


def test_load_settings_ignores_invalid_policy_value(monkeypatch):
    _install(
        monkeypatch,
        {"getList": _get_list_router({"guardian_settings": json.dumps({"watchdog_policy": {"running": "banana"}})})},
    )
    settings = hk.guardian_hk_load_settings()
    assert settings["watchdog_policy"]["running"] == "reap"  # falls back to default


def test_load_settings_ignores_non_positive_numbers(monkeypatch):
    _install(
        monkeypatch,
        {"getList": _get_list_router({"guardian_settings": json.dumps({"approval_sla_minutes": -5, "audit_retention_days": 0})})},
    )
    settings = hk.guardian_hk_load_settings()
    assert settings["approval_sla_minutes"] == 60
    assert settings["audit_retention_days"] == 30


# --- guardian_hk_reap_stale_approvals ---------------------------------------------


def test_reap_stale_approvals_expires_old_pending(monkeypatch):
    ledger = [
        {"approval_id": "a1", "status": "pending", "created_ts": "2026-07-06T10:00:00.000Z"},
        {"approval_id": "a2", "status": "pending", "created_ts": "2026-07-06T11:58:00.000Z"},
        {"approval_id": "a3", "status": "approved", "created_ts": "2026-07-06T09:00:00.000Z"},
        {"approval_id": "a4", "status": "pending", "created_ts": None},
    ]
    set_calls = {}
    _install(
        monkeypatch,
        {
            "getList": _get_list_router({"guardian_approvals_ledger": json.dumps(ledger)}),
            "setList": _capturing_set_list(set_calls),
        },
    )
    result = hk.guardian_hk_reap_stale_approvals("2026-07-06T12:00:00.000Z", 60)
    assert result["ok"] is True
    assert result["expired_count"] == 1
    assert result["expired_ids"] == ["a1"]
    saved = json.loads(set_calls["calls"][0]["listData"])
    by_id = {row["approval_id"]: row for row in saved}
    assert by_id["a1"]["status"] == "expired"
    assert by_id["a1"]["reason"].startswith("sla_expired")
    assert by_id["a2"]["status"] == "pending"  # too fresh
    assert by_id["a3"]["status"] == "approved"  # not pending
    assert by_id["a4"]["status"] == "pending"  # unparseable created_ts -- untouched


def test_reap_stale_approvals_no_op_when_nothing_stale(monkeypatch):
    ledger = [{"approval_id": "a1", "status": "pending", "created_ts": "2026-07-06T11:59:00.000Z"}]

    def boom_set_list(args):
        raise AssertionError("setList must not be called when nothing changed")

    _install(monkeypatch, {"getList": _get_list_router({"guardian_approvals_ledger": json.dumps(ledger)}), "setList": boom_set_list})
    result = hk.guardian_hk_reap_stale_approvals("2026-07-06T12:00:00.000Z", 60)
    assert result["ok"] is True
    assert result["expired_count"] == 0


def test_reap_stale_approvals_unreadable_list(monkeypatch):
    _install(monkeypatch, {"getList": _get_list_router({})})
    result = hk.guardian_hk_reap_stale_approvals("2026-07-06T12:00:00.000Z", 60)
    assert result["ok"] is False
    assert "unreadable" in result["error"]


# --- guardian_hk_release_approval -------------------------------------------------


def test_release_approval_marks_expired(monkeypatch):
    ledger = [{"approval_id": "a1", "status": "pending"}]
    set_calls = {}
    _install(
        monkeypatch,
        {"getList": _get_list_router({"guardian_approvals_ledger": json.dumps(ledger)}), "setList": _capturing_set_list(set_calls)},
    )
    result = hk.guardian_hk_release_approval("a1", "2026-07-06T12:00:00.000Z")
    assert result == {"ok": True, "released": True}
    saved = json.loads(set_calls["calls"][0]["listData"])
    assert saved[0]["status"] == "expired"
    assert saved[0]["reason"] == "stalled-watchdog-reap"


def test_release_approval_no_op_when_already_resolved(monkeypatch):
    ledger = [{"approval_id": "a1", "status": "approved"}]

    def boom_set_list(args):
        raise AssertionError("must not write when nothing to release")

    _install(monkeypatch, {"getList": _get_list_router({"guardian_approvals_ledger": json.dumps(ledger)}), "setList": boom_set_list})
    result = hk.guardian_hk_release_approval("a1", "2026-07-06T12:00:00.000Z")
    assert result == {"ok": True, "released": False}


def test_release_approval_no_op_when_missing(monkeypatch):
    _install(monkeypatch, {"getList": _get_list_router({"guardian_approvals_ledger": "[]"})})
    result = hk.guardian_hk_release_approval("missing", "2026-07-06T12:00:00.000Z")
    assert result == {"ok": True, "released": False}


def test_release_approval_none_id_no_op():
    assert hk.guardian_hk_release_approval(None, "2026-07-06T12:00:00.000Z") == {"ok": True, "released": False}


# --- guardian_hk_reap_expired_memory -----------------------------------------------


def test_reap_expired_memory_drops_only_expired_ttl_rows(monkeypatch):
    memory = [
        {"key": "m1", "updated_at": "2026-07-06T10:00:00.000Z", "ttl_seconds": 60},  # 2h old, 60s ttl -> expired
        {"key": "m2", "updated_at": "2026-07-06T11:59:30.000Z", "ttl_seconds": 3600},  # fresh, 1h ttl -> kept
        {"key": "m3", "updated_at": "2026-07-06T09:00:00.000Z", "ttl_seconds": None},  # permanent -> kept
        {"key": "m4", "updated_at": None, "ttl_seconds": 60},  # unparseable age -> kept (conservative)
    ]
    set_calls = {}
    _install(
        monkeypatch,
        {"getList": _get_list_router({"guardian_memory": json.dumps(memory)}), "setList": _capturing_set_list(set_calls)},
    )
    result = hk.guardian_hk_reap_expired_memory("2026-07-06T12:00:00.000Z")
    assert result["ok"] is True
    assert result["reaped_count"] == 1
    assert result["reaped_keys"] == ["m1"]
    saved = json.loads(set_calls["calls"][0]["listData"])
    kept_keys = {row["key"] for row in saved}
    assert kept_keys == {"m2", "m3", "m4"}


def test_reap_expired_memory_no_op_when_empty(monkeypatch):
    _install(monkeypatch, {"getList": _get_list_router({"guardian_memory": "[]"})})
    result = hk.guardian_hk_reap_expired_memory("2026-07-06T12:00:00.000Z")
    assert result == {"ok": True, "reaped_count": 0, "reaped_keys": []}


# --- guardian_hk_rotate_audit -----------------------------------------------------


def test_rotate_audit_shards_old_rows_and_trims_live_list(monkeypatch):
    rows = [
        {"ts": "2026-05-01T00:00:00.000Z", "action": "old1"},
        {"ts": "2026-05-01T01:00:00.000Z", "action": "old2"},
        {"ts": "2026-07-06T11:00:00.000Z", "action": "recent"},
        {"ts": None, "action": "no-ts"},
    ]
    set_calls = {}
    create_calls = {}

    _install(
        monkeypatch,
        {
            "getList": _get_list_router({"guardian_audit": json.dumps(rows)}),
            "setList": _capturing_set_list(set_calls),
            "createList": _capturing_create_list(create_calls),
        },
    )
    result = hk.guardian_hk_rotate_audit("2026-07-06T12:00:00.000Z", 30)
    assert result["ok"] is True
    assert result["rotated_count"] == 2
    assert result["shards_touched"] == ["guardian_audit_shard_2026-05-01"]

    # the shard was created (didn't exist) with the two old rows
    shard_call = create_calls["calls"][0]
    assert shard_call["listName"] == "guardian_audit_shard_2026-05-01"
    shard_rows = json.loads(shard_call["listData"])
    assert [r["action"] for r in shard_rows] == ["old1", "old2"]

    # the live list keeps everything else
    live_calls = [c for c in set_calls.get("calls", []) if c["listName"] == "guardian_audit"]
    kept = json.loads(live_calls[0]["listData"])
    assert {r["action"] for r in kept} == {"recent", "no-ts"}


def test_rotate_audit_appends_to_existing_shard(monkeypatch):
    rows = [{"ts": "2026-05-01T00:00:00.000Z", "action": "old-new"}]
    existing_shard = [{"ts": "2026-05-01T00:00:00.000Z", "action": "old-existing"}]
    set_calls = {}

    def get_list(args):
        if args["listName"] == "guardian_audit":
            return [{"Type": 1, "Contents": json.dumps(rows)}]
        if args["listName"] == "guardian_audit_shard_2026-05-01":
            return [{"Type": 1, "Contents": json.dumps(existing_shard)}]
        raise AssertionError("unexpected getList: {}".format(args))

    _install(monkeypatch, {"getList": get_list, "setList": _capturing_set_list(set_calls)})
    result = hk.guardian_hk_rotate_audit("2026-07-06T12:00:00.000Z", 30)
    assert result["ok"] is True
    shard_calls = [c for c in set_calls["calls"] if c["listName"] == "guardian_audit_shard_2026-05-01"]
    merged = json.loads(shard_calls[0]["listData"])
    assert {r["action"] for r in merged} == {"old-existing", "old-new"}


def test_rotate_audit_no_op_when_nothing_old(monkeypatch):
    rows = [{"ts": "2026-07-06T11:00:00.000Z", "action": "recent"}]

    def boom_set_list(args):
        raise AssertionError("must not write when nothing to rotate")

    _install(monkeypatch, {"getList": _get_list_router({"guardian_audit": json.dumps(rows)}), "setList": boom_set_list})
    result = hk.guardian_hk_rotate_audit("2026-07-06T12:00:00.000Z", 30)
    assert result == {"ok": True, "rotated_count": 0, "shards_touched": []}


def test_rotate_audit_refuses_on_unparseable_now(monkeypatch):
    _install(monkeypatch, {"getList": _get_list_router({"guardian_audit": "[]"})})
    result = hk.guardian_hk_rotate_audit("not-a-date", 30)
    assert result["ok"] is False
    assert "refusing to rotate" in result["error"]


def test_rotate_audit_shard_write_failure_keeps_rows_in_live_list(monkeypatch):
    rows = [{"ts": "2026-05-01T00:00:00.000Z", "action": "old1"}]

    def get_list(args):
        if args["listName"] == "guardian_audit":
            return [{"Type": 1, "Contents": json.dumps(rows)}]
        return [{"Type": 4, "Contents": "some transient shard read error"}]

    set_calls = {}
    _install(monkeypatch, {"getList": get_list, "setList": _capturing_set_list(set_calls)})
    result = hk.guardian_hk_rotate_audit("2026-07-06T12:00:00.000Z", 30)
    assert result["ok"] is False
    assert result["rotated_count"] == 0
    # the live list write, if any, must still contain the row (never lost)
    live_calls = [c for c in set_calls.get("calls", []) if c["listName"] == "guardian_audit"]
    if live_calls:
        kept = json.loads(live_calls[-1]["listData"])
        assert any(r["action"] == "old1" for r in kept)


# --- guardian_hk_consolidate_ledgers -----------------------------------------------


def test_consolidate_ledgers_recovers_missing_buffered_row(monkeypatch):
    shared_rows = [{"ts": "t1", "action": "a", "run_id": "100", "tick_id": 1}]
    buffer_100 = [
        {"ts": "t1", "action": "a", "run_id": "100", "tick_id": 1},  # already present -- skip
        {"ts": "t2", "action": "b", "run_id": "100", "tick_id": 2},  # missing -- recover
    ]
    set_calls = {}

    _install(
        monkeypatch,
        {
            "getList": _get_list_router({"guardian_audit": json.dumps(shared_rows)}),
            "setList": _capturing_set_list(set_calls),
            "demisto-api-post": _entry_execute_sync_router({"100": buffer_100}),
        },
    )
    result = hk.guardian_hk_consolidate_ledgers([{"id": "100", "investigation_id": "100"}])
    assert result["ok"] is True
    assert result["recovered_count"] == 1
    saved = json.loads(set_calls["calls"][0]["listData"])
    assert len(saved) == 2
    assert any(r["action"] == "b" for r in saved)


def test_consolidate_ledgers_no_op_when_all_present(monkeypatch):
    shared_rows = [{"ts": "t1", "action": "a", "run_id": "100"}]
    buffer_100 = [{"ts": "t1", "action": "a", "run_id": "100"}]

    def boom_set_list(args):
        raise AssertionError("must not write when nothing new")

    _install(
        monkeypatch,
        {
            "getList": _get_list_router({"guardian_audit": json.dumps(shared_rows)}),
            "setList": boom_set_list,
            "demisto-api-post": _entry_execute_sync_router({"100": buffer_100}),
        },
    )
    result = hk.guardian_hk_consolidate_ledgers([{"id": "100", "investigation_id": "100"}])
    assert result["ok"] is True
    assert result["recovered_count"] == 0


def test_consolidate_ledgers_records_read_error_without_crashing(monkeypatch):
    _install(
        monkeypatch,
        {"getList": _get_list_router({"guardian_audit": "[]"}), "demisto-api-post": _entry_execute_sync_router({"999": _PROBE_ERROR})},
    )
    result = hk.guardian_hk_consolidate_ledgers([{"id": "999", "investigation_id": "999"}])
    assert result["ok"] is True
    assert result["recovered_count"] == 0
    assert result["read_errors"][0]["incident_id"] == "999"


def test_consolidate_ledgers_skips_uninvestigated_incident(monkeypatch):
    # An un-investigated incident (empty investigation_id) has no buffer to
    # consolidate and is skipped silently (never probed, not an error).
    def boom(args):
        raise AssertionError("must not probe an un-investigated incident")

    _install(monkeypatch, {"getList": _get_list_router({"guardian_audit": "[]"}), "demisto-api-post": boom})
    result = hk.guardian_hk_consolidate_ledgers([{"id": "50", "investigation_id": ""}])
    assert result["ok"] is True
    assert result["recovered_count"] == 0
    assert result["read_errors"] == []


# --- guardian_hk_probe_context / guardian_hk_read_incident_context (the real,
# non-${...}, remote-context-read mechanism) --------------------------------------


def test_probe_context_reads_own_context(monkeypatch):
    monkeypatch.setattr(hk.demisto, "context", lambda: {"Guardian": {"Loop": {"status": "running"}}})
    assert hk.guardian_hk_probe_context("Loop") == {"status": "running"}


def test_probe_context_missing_key_returns_none(monkeypatch):
    monkeypatch.setattr(hk.demisto, "context", lambda: {})
    assert hk.guardian_hk_probe_context("Loop") is None


def test_read_incident_context_success(monkeypatch):
    calls = []

    def api_post(args):
        calls.append(args)
        return _entry_execute_sync_router({"55": {"status": "running"}})(args)

    _install(monkeypatch, {"demisto-api-post": api_post})
    result = hk.guardian_hk_read_incident_context("55", "Loop")
    assert result["ok"] is True
    assert result["data"] == {"status": "running"}
    body = json.loads(calls[0]["body"])
    assert body["investigationId"] == "55"
    assert body["data"] == "!GuardianHousekeeping probe_key=Loop"


def test_read_incident_context_remote_error(monkeypatch):
    _install(monkeypatch, {"demisto-api-post": _entry_execute_sync_router({"56": _PROBE_ERROR})})
    result = hk.guardian_hk_read_incident_context("56", "Loop")
    assert result["ok"] is False
    assert "failed" in result["error"]


def test_read_incident_context_no_loop_state_yet(monkeypatch):
    """A brand-new incident whose tick 0 hasn't run yet has no Guardian.Loop
    key at all -- guardian_ctx_read's own default (None) round-trips
    through json.dumps/json.loads as a clean `null`, not an error."""
    _install(monkeypatch, {"demisto-api-post": _entry_execute_sync_router({"57": None})})
    result = hk.guardian_hk_read_incident_context("57", "Loop")
    assert result["ok"] is True
    assert result["data"] is None


# --- guardian_hk_classify_stall ----------------------------------------------------


def test_classify_stall_no_loop_state():
    assert hk.guardian_hk_classify_stall(None) == (False, None)
    assert hk.guardian_hk_classify_stall({}) == (False, None)


def test_classify_stall_terminal_status_not_a_candidate():
    assert hk.guardian_hk_classify_stall({"status": "done"}) == (False, None)
    assert hk.guardian_hk_classify_stall({"status": "error"}) == (False, None)
    assert hk.guardian_hk_classify_stall({"status": "stopped"}) == (False, None)


def test_classify_stall_pending():
    is_candidate, sub_state = hk.guardian_hk_classify_stall({"status": "running", "pending": {"approval_id": "a1"}})
    assert is_candidate is True
    assert sub_state == "pending"


def test_classify_stall_awaiting_analyst():
    is_candidate, sub_state = hk.guardian_hk_classify_stall(
        {"status": "running", "pending": None, "awaiting_analyst": {"question": "q"}}
    )
    assert is_candidate is True
    assert sub_state == "awaiting_analyst"


def test_classify_stall_bare_running():
    is_candidate, sub_state = hk.guardian_hk_classify_stall({"status": "running", "pending": None, "awaiting_analyst": None})
    assert is_candidate is True
    assert sub_state == "running"


def test_classify_stall_pending_takes_precedence_over_awaiting():
    is_candidate, sub_state = hk.guardian_hk_classify_stall(
        {"status": "running", "pending": {"approval_id": "a1"}, "awaiting_analyst": {"question": "q"}}
    )
    assert sub_state == "pending"


# --- guardian_hk_rearm_incident / guardian_hk_reap_incident ------------------------


def test_rearm_incident_success(monkeypatch):
    calls = []

    def api_post(args):
        calls.append(args)
        return [{"Type": 1, "Contents": {"response": [{"Type": 1, "Contents": "ok"}]}}]

    _install(monkeypatch, {"demisto-api-post": api_post})
    result = hk.guardian_hk_rearm_incident("42")
    assert result["ok"] is True
    assert result["note_posted"] is True
    assert calls[0]["uri"] == "/entry/execute/sync"
    body0 = json.loads(calls[0]["body"])
    assert body0["investigationId"] == "42"
    assert body0["data"] == "!GuardianReasoningTick"


def test_rearm_incident_tick_failure(monkeypatch):
    def api_post(args):
        return [{"Type": 4, "Contents": "boom"}]

    _install(monkeypatch, {"demisto-api-post": api_post})
    result = hk.guardian_hk_rearm_incident("42")
    assert result["ok"] is False
    assert "re-arm tick invocation failed" in result["error"]


def test_reap_incident_success(monkeypatch):
    calls = []

    def api_post(args):
        calls.append(args["uri"])
        body = json.loads(args["body"])
        calls.append(body.get("data"))
        return [{"Type": 1, "Contents": {"response": "ok"}}]

    _install(monkeypatch, {"demisto-api-post": api_post})
    result = hk.guardian_hk_reap_incident("42", "running")
    assert result["ok"] is True
    assert result["state_mutated"] is True
    assert any("Guardian.Loop.status value=stopped" in str(c) for c in calls)
    assert any("Guardian.Loop.stall_reason" in str(c) for c in calls)


def test_reap_incident_partial_failure(monkeypatch):
    call_count = {"n": 0}

    def api_post(args):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return [{"Type": 1, "Contents": {"response": "ok"}}]
        return [{"Type": 4, "Contents": "boom"}]

    _install(monkeypatch, {"demisto-api-post": api_post})
    result = hk.guardian_hk_reap_incident("42", "running")
    assert result["ok"] is False
    assert result["state_mutated"] is False


# --- guardian_hk_run_watchdog (end to end fixtures) --------------------------------


def test_run_watchdog_rearms_pending_stall(monkeypatch):
    incidents = [{"id": "1", "modified": "2026-07-06T11:00:00.000Z", "investigation_id": "1"}]  # 60m stale

    _install(
        monkeypatch,
        {"demisto-api-post": _entry_execute_sync_router({"1": {"status": "running", "pending": {"approval_id": "a1"}}})},
    )
    result = hk.guardian_hk_run_watchdog(incidents, "2026-07-06T12:00:00.000Z", 15, hk.GUARDIAN_HK_DEFAULT_WATCHDOG_POLICY)
    assert result["ok"] is True
    assert len(result["rearmed"]) == 1
    assert result["rearmed"][0]["incident_id"] == "1"
    assert result["rearmed"][0]["sub_state"] == "pending"


def test_run_watchdog_reaps_bare_running_stall_and_releases_pending(monkeypatch):
    incidents = [{"id": "2", "modified": "2026-07-06T11:00:00.000Z", "investigation_id": "2"}]
    ledger = [{"approval_id": "a9", "status": "pending"}]
    set_calls = {}

    # sub_state "pending" here (Loop.pending set) -- exercised with the
    # policy override below forcing "pending" -> "reap" so the release-path
    # (Loop.pending.approval_id -> guardian_approvals_ledger release) fires.
    _install(
        monkeypatch,
        {
            "demisto-api-post": _entry_execute_sync_router({"2": {"status": "running", "pending": {"approval_id": "a9"}}}),
            "getList": _get_list_router({"guardian_approvals_ledger": json.dumps(ledger)}),
            "setList": _capturing_set_list(set_calls),
        },
    )
    policy = {"pending": "reap", "awaiting_analyst": "rearm", "running": "reap"}
    result = hk.guardian_hk_run_watchdog(incidents, "2026-07-06T12:00:00.000Z", 15, policy)
    assert result["ok"] is True
    assert len(result["reaped"]) == 1
    assert result["reaped"][0]["approval_released"] is True
    saved = json.loads(set_calls["calls"][0]["listData"])
    assert saved[0]["status"] == "expired"


def test_run_watchdog_skips_incident_not_stale_enough(monkeypatch):
    incidents = [{"id": "3", "modified": "2026-07-06T11:50:00.000Z", "investigation_id": "3"}]  # only 10m stale

    def boom(args):
        raise AssertionError("must not read context for a fresh incident")

    _install(monkeypatch, {"demisto-api-post": boom})
    result = hk.guardian_hk_run_watchdog(incidents, "2026-07-06T12:00:00.000Z", 15, hk.GUARDIAN_HK_DEFAULT_WATCHDOG_POLICY)
    assert result == {"ok": True, "rearmed": [], "reaped": [], "skipped": [], "errors": []}


def test_run_watchdog_skips_incident_with_unknown_age(monkeypatch):
    incidents = [{"id": "4", "modified": None, "investigation_id": "4"}]

    def boom(args):
        raise AssertionError("must not read context when age is unknown")

    _install(monkeypatch, {"demisto-api-post": boom})
    result = hk.guardian_hk_run_watchdog(incidents, "2026-07-06T12:00:00.000Z", 15, hk.GUARDIAN_HK_DEFAULT_WATCHDOG_POLICY)
    assert result["rearmed"] == [] and result["reaped"] == []


def test_run_watchdog_skips_uninvestigated_incident_silently(monkeypatch):
    # status:0/Pending -> empty investigation_id -> never started ticking ->
    # not a stall candidate, and NOT an error (nothing there to watch).
    incidents = [
        {"id": "8", "modified": "2026-07-06T11:00:00.000Z", "investigation_id": ""},
        {"id": "9", "modified": "2026-07-06T11:00:00.000Z", "investigation_id": None},
    ]

    def boom(args):
        raise AssertionError("must not probe an un-investigated incident")

    _install(monkeypatch, {"demisto-api-post": boom})
    result = hk.guardian_hk_run_watchdog(incidents, "2026-07-06T12:00:00.000Z", 15, hk.GUARDIAN_HK_DEFAULT_WATCHDOG_POLICY)
    assert result == {"ok": True, "rearmed": [], "reaped": [], "skipped": [], "errors": []}


def test_search_active_runs_excludes_pending_and_sorts_newest_first(monkeypatch):
    """The watchdog reads ONE 200-row page. Pending incidents must be left out
    by the query itself, or a fetch integration filing alerts as this type
    fills the page and hides the real runs (seen live: 18 of 24 missed)."""
    bodies = []

    def api_post(args):
        assert args["uri"] == "/incidents/search"
        bodies.append(json.loads(args["body"]))
        return [{"Type": 1, "Contents": {"response": {"data": [
            {"id": "7", "name": "run", "modified": "2026-07-06T11:00:00Z", "status": 1, "investigationId": "7"},
        ]}}}]

    _install(monkeypatch, {"demisto-api-post": api_post})
    result = hk.guardian_hk_search_active_agent_run_incidents()

    assert result["ok"] is True
    assert [inc["id"] for inc in result["data"]] == ["7"]
    flt = bodies[0]["filter"]
    assert flt["query"] == 'type:"Guardian Agent Run" and -status:closed and -status:Pending'
    assert flt["sort"] == [{"field": "modified", "asc": False}]
    assert flt["size"] == 200 and flt["page"] == 0


def test_run_watchdog_skips_terminal_incident(monkeypatch):
    incidents = [{"id": "5", "modified": "2026-07-06T11:00:00.000Z", "investigation_id": "5"}]

    _install(monkeypatch, {"demisto-api-post": _entry_execute_sync_router({"5": {"status": "done"}})})
    result = hk.guardian_hk_run_watchdog(incidents, "2026-07-06T12:00:00.000Z", 15, hk.GUARDIAN_HK_DEFAULT_WATCHDOG_POLICY)
    assert result == {"ok": True, "rearmed": [], "reaped": [], "skipped": [], "errors": []}


def test_run_watchdog_records_unrecognized_policy_as_skipped_not_reaped(monkeypatch):
    incidents = [{"id": "6", "modified": "2026-07-06T11:00:00.000Z", "investigation_id": "6"}]

    _install(
        monkeypatch,
        {"demisto-api-post": _entry_execute_sync_router({"6": {"status": "running", "pending": {"approval_id": "a1"}}})},
    )
    bad_policy = {"pending": "banana", "awaiting_analyst": "rearm", "running": "reap"}
    result = hk.guardian_hk_run_watchdog(incidents, "2026-07-06T12:00:00.000Z", 15, bad_policy)
    assert result["rearmed"] == []
    assert result["reaped"] == []
    assert len(result["skipped"]) == 1
    assert result["skipped"][0]["incident_id"] == "6"


def test_run_watchdog_records_context_read_error(monkeypatch):
    incidents = [{"id": "7", "modified": "2026-07-06T11:00:00.000Z", "investigation_id": "7"}]

    _install(monkeypatch, {"demisto-api-post": _entry_execute_sync_router({"7": _PROBE_ERROR})})
    result = hk.guardian_hk_run_watchdog(incidents, "2026-07-06T12:00:00.000Z", 15, hk.GUARDIAN_HK_DEFAULT_WATCHDOG_POLICY)
    assert result["ok"] is False
    assert result["errors"][0]["incident_id"] == "7"


# --- guardian_housekeeping_run / main() (full orchestration smoke) ----------------


def test_housekeeping_run_skips_entirely_when_clock_unavailable(monkeypatch):
    def get_time_fail(args):
        return [{"Type": 4, "Contents": "GetTime disabled"}]

    _install(monkeypatch, {"GetTime": get_time_fail})
    summary = hk.guardian_housekeeping_run()
    assert summary["skipped_entirely"] is True
    assert summary["ts"] is None


def test_housekeeping_run_full_sweep_with_everything_mocked(monkeypatch):
    audit_rows = []
    approvals = []
    memory = []

    def api_post(args):
        uri = args["uri"]
        if uri == "/incidents/search":
            return [{"Type": 1, "Contents": {"response": {"data": []}}}]
        raise AssertionError(uri)

    handlers = {
        "GetTime": _get_time_handler(),
        "getList": _get_list_router(
            {
                "guardian_audit": json.dumps(audit_rows),
                "guardian_approvals_ledger": json.dumps(approvals),
                "guardian_memory": json.dumps(memory),
                "guardian_settings": "{}",
            }
        ),
        "demisto-api-post": api_post,
        "GuardianAuditWrite": lambda args: [{"Type": 1, "Contents": "Guardian audit row written"}],
    }
    _install(monkeypatch, handlers)
    summary = hk.guardian_housekeeping_run()
    assert summary["skipped_entirely"] is False
    ops = summary["ops"]
    assert ops["consolidate_ledgers"]["ok"] is True
    assert ops["rotate_audit"]["ok"] is True
    assert ops["reap_approvals"]["ok"] is True
    assert ops["reap_memory"]["ok"] is True
    assert ops["watchdog"]["ok"] is True


def test_main_smoke(monkeypatch):
    hk.RESULTS.clear()

    def api_post(args):
        return [{"Type": 1, "Contents": {"response": {"data": []}}}]

    _install(
        monkeypatch,
        {
            "GetTime": _get_time_handler(),
            "getList": _get_list_router({"guardian_audit": "[]", "guardian_approvals_ledger": "[]", "guardian_memory": "[]", "guardian_settings": "{}"}),
            "demisto-api-post": api_post,
            "GuardianAuditWrite": lambda args: [{"Type": 1, "Contents": "Guardian audit row written"}],
        },
    )
    hk.main()
    assert len(hk.RESULTS) == 1
    cr = hk.RESULTS[0]
    assert "GuardianHousekeeping sweep" in cr.readable_output


def test_main_probe_mode_returns_raw_json_and_skips_sweep(monkeypatch):
    hk.RESULTS.clear()
    monkeypatch.setattr(hk.demisto, "args", lambda: {"probe_key": "Loop"})
    monkeypatch.setattr(hk.demisto, "context", lambda: {"Guardian": {"Loop": {"status": "running", "tick": 3}}})

    def boom_get_time(args):
        raise AssertionError("probe mode must never run the sweep (no GetTime call)")

    _install(monkeypatch, {"GetTime": boom_get_time})
    hk.main()
    assert len(hk.RESULTS) == 1
    assert json.loads(hk.RESULTS[0].readable_output) == {"status": "running", "tick": 3}


def test_main_unexpected_exception_return_error(monkeypatch):
    hk.RESULTS.clear()

    def boom():
        raise RuntimeError("kaboom")

    monkeypatch.setattr(hk, "guardian_housekeeping_run", boom)
    import pytest

    with pytest.raises(SystemExit) as exc_info:
        hk.main()
    assert "unexpectedly" in str(exc_info.value)
