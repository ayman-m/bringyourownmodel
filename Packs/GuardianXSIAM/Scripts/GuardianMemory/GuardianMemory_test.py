import json

import pytest

import GuardianMemory as gm


# --- test fixtures -----------------------------------------------------------


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


def _get_list_handler(rows_holder, list_name="guardian_memory"):
    def handle_get_list(args):
        assert args["listName"] == list_name
        return [{"Type": 1, "Contents": json.dumps(rows_holder["rows"])}]

    return handle_get_list


def _set_list_handler(rows_holder, list_name="guardian_memory"):
    def handle_set_list(args):
        assert args["listName"] == list_name
        rows_holder["rows"] = json.loads(args["listData"])
        rows_holder["saved"] = True
        return [{"Type": 1, "Contents": "Done: list {} was updated".format(args["listName"])}]

    return handle_set_list


def _install(monkeypatch, rows=None, now="2026-07-06T12:00:00.000Z"):
    """Wires GetTime/getList/setList as success stubs over an in-memory
    `rows_holder`, and a bare `incident()`. Returns the rows_holder dict
    (`{"rows": [...], "saved": bool}`) for post-call assertions.
    """
    rows_holder = {"rows": rows if rows is not None else [], "saved": False}
    handlers = {
        "GetTime": lambda args: [{"Type": 1, "Contents": now}],
        "getList": _get_list_handler(rows_holder),
        "setList": _set_list_handler(rows_holder),
    }
    monkeypatch.setattr(gm.demisto, "executeCommand", _multi_command_stub(handlers))
    monkeypatch.setattr(gm.demisto, "incident", lambda: {})
    return rows_holder


def _row(key, value, updated_at="2026-07-06T12:00:00.000Z", created_at=None, scope=None, tags=None, ttl=None,
         hits=0):
    return {
        "key": key,
        "value": value,
        "scope": scope,
        "tags": tags or [],
        "ttl": ttl,
        "created_at": created_at or updated_at,
        "updated_at": updated_at,
        "hits": hits,
    }


# --- server time / iso parsing ------------------------------------------------


def test_get_server_time_uses_get_time_iso(monkeypatch):
    monkeypatch.setattr(
        gm.demisto, "executeCommand", lambda cmd, args: [{"Type": 1, "Contents": "2026-07-06T11:00:00.000Z"}]
    )

    ts, warning = gm.guardian_memory_get_server_time()

    assert ts == "2026-07-06T11:00:00.000Z"
    assert warning is None


def test_get_server_time_falls_back_to_incident_modified(monkeypatch):
    monkeypatch.setattr(
        gm.demisto, "executeCommand", lambda cmd, args: [{"Type": 4, "Contents": "GetTime disabled"}]
    )
    monkeypatch.setattr(gm.demisto, "incident", lambda: {"modified": "2026-07-06T09:00:00Z"})

    ts, warning = gm.guardian_memory_get_server_time()

    assert ts == "2026-07-06T09:00:00Z"
    assert "degraded" in warning


def test_get_server_time_none_when_wholly_unavailable(monkeypatch):
    monkeypatch.setattr(gm.demisto, "executeCommand", lambda cmd, args: [{"Type": 4, "Contents": "boom"}])
    monkeypatch.setattr(gm.demisto, "incident", lambda: {})

    ts, warning = gm.guardian_memory_get_server_time()

    assert ts is None
    assert "never fabricated" in warning


def test_parse_iso_rejects_go_zero_value_and_blank():
    assert gm.guardian_memory_parse_iso("0001-01-01T00:00:00Z") is None
    assert gm.guardian_memory_parse_iso("") is None
    assert gm.guardian_memory_parse_iso(None) is None


def test_parse_iso_accepts_trailing_z():
    parsed = gm.guardian_memory_parse_iso("2026-07-06T12:00:00.000Z")
    assert parsed is not None
    assert parsed.year == 2026


def test_seconds_since_unparseable_is_none():
    assert gm.guardian_memory_seconds_since("not-a-date", "2026-07-06T12:00:00Z") is None
    assert gm.guardian_memory_seconds_since("2026-07-06T12:00:00Z", "not-a-date") is None


def test_seconds_since_computes_elapsed():
    elapsed = gm.guardian_memory_seconds_since("2026-07-06T11:00:00Z", "2026-07-06T12:00:00Z")
    assert elapsed == pytest.approx(3600.0)


# --- parsing helpers: ttl / tags / limit ---------------------------------------


def test_parse_ttl_none_or_empty_is_permanent():
    assert gm.guardian_memory_parse_ttl(None) == (None, None)
    assert gm.guardian_memory_parse_ttl("") == (None, None)


def test_parse_ttl_non_positive_is_permanent():
    assert gm.guardian_memory_parse_ttl(0) == (None, None)
    assert gm.guardian_memory_parse_ttl("-5") == (None, None)


def test_parse_ttl_positive_numeric_string():
    seconds, error = gm.guardian_memory_parse_ttl("3600")
    assert seconds == 3600
    assert error is None


def test_parse_ttl_garbage_is_an_error():
    seconds, error = gm.guardian_memory_parse_ttl("not-a-number")
    assert seconds is None
    assert "NEEDS_CONTEXT" in error


def test_parse_tags_json_array_string():
    assert gm.guardian_memory_parse_tags('["ioc", "network"]') == ["ioc", "network"]


def test_parse_tags_comma_separated_string():
    assert gm.guardian_memory_parse_tags("ioc, network,  ") == ["ioc", "network"]


def test_parse_tags_empty_and_none():
    assert gm.guardian_memory_parse_tags(None) == []
    assert gm.guardian_memory_parse_tags("") == []


def test_parse_tags_already_a_list():
    assert gm.guardian_memory_parse_tags(["ioc", " network "]) == ["ioc", "network"]


def test_parse_limit_default_and_clamp():
    assert gm.guardian_memory_parse_limit(None) == gm.GUARDIAN_MEMORY_DEFAULT_SEARCH_LIMIT
    assert gm.guardian_memory_parse_limit("not-a-number") == gm.GUARDIAN_MEMORY_DEFAULT_SEARCH_LIMIT
    assert gm.guardian_memory_parse_limit("5") == 5
    assert gm.guardian_memory_parse_limit("9999") == gm.GUARDIAN_MEMORY_MAX_SEARCH_LIMIT
    assert gm.guardian_memory_parse_limit("0") == 1


# --- redaction at capture ------------------------------------------------------


def test_redact_value_masks_secret_in_json_object_string():
    redacted = gm.guardian_memory_redact_value(json.dumps({"api_key": "sk-super-secret", "note": "safe"}))
    assert redacted["api_key"] == "***"
    assert redacted["note"] == "safe"


def test_redact_value_masks_secret_embedded_in_free_text():
    redacted = gm.guardian_memory_redact_value("connect using token=sk-abc123456789 for the jump box")
    assert "sk-abc123456789" not in redacted
    assert "***" in redacted


def test_redact_value_leaves_plain_safe_text_unchanged():
    text = "agents beacon to 8.8.8.8 on port 443"
    assert gm.guardian_memory_redact_value(text) == text


def test_redact_value_keeps_identifiers_but_still_masks_secrets():
    redacted = gm.guardian_memory_redact_value(
        "asset 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 "
        "rule 3f2b8c1e-9a4d-4e6f-8b7a-1c2d3e4f5a6b status STATUS_250_RESOLVED_FIXED "
        "key sk-abcdefghijklmnopqrstuvwxyz123456 md5 d41d8cd98f00b204e9800998ecf8427e"
    )
    assert "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" in redacted
    assert "3f2b8c1e-9a4d-4e6f-8b7a-1c2d3e4f5a6b" in redacted
    assert "STATUS_250_RESOLVED_FIXED" in redacted
    assert "abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "d41d8cd98f00b204e9800998ecf8427e" not in redacted


# --- store: create / upsert ----------------------------------------------------


def test_store_creates_new_row(monkeypatch):
    rows_holder = _install(monkeypatch)

    result = gm.guardian_memory_store(key="pattern:test", value="agents beacon to 8.8.8.8 on port 443", ttl=3600)

    assert result["ok"] is True
    row = result["data"]["row"]
    assert row["key"] == "pattern:test"
    assert row["value"] == "agents beacon to 8.8.8.8 on port 443"
    assert row["ttl"] == 3600
    assert row["created_at"] == row["updated_at"] == "2026-07-06T12:00:00.000Z"
    assert row["hits"] == 0
    assert result["data"]["created"] is True
    assert rows_holder["rows"] == [row]


def test_store_redacts_secret_before_persisting(monkeypatch):
    rows_holder = _install(monkeypatch)

    gm.guardian_memory_store(key="tech_stack:vpn", value=json.dumps({"api_key": "sk-hidden", "vendor": "acme"}))

    persisted = rows_holder["rows"][0]["value"]
    assert persisted["api_key"] == "***"
    assert persisted["vendor"] == "acme"


def test_store_upserts_existing_key_updates_value_and_updated_at(monkeypatch):
    existing = _row("case:1:2026-07-01", "first note", updated_at="2026-07-01T00:00:00Z", hits=3)
    rows_holder = _install(monkeypatch, rows=[existing], now="2026-07-06T12:00:00.000Z")

    result = gm.guardian_memory_store(key="case:1:2026-07-01", value="refined note")

    assert result["ok"] is True
    assert result["data"]["created"] is False
    row = result["data"]["row"]
    assert row["value"] == "refined note"
    assert row["updated_at"] == "2026-07-06T12:00:00.000Z"
    assert row["created_at"] == "2026-07-01T00:00:00Z"  # never touched on update
    assert row["hits"] == 3  # store never resets hits
    assert len(rows_holder["rows"]) == 1  # upsert, not a second row


def test_store_preserves_scope_tags_ttl_when_omitted_on_update(monkeypatch):
    existing = _row("k", "v", scope="org-a", tags=["ioc"], ttl=600)
    rows_holder = _install(monkeypatch, rows=[existing])

    gm.guardian_memory_store(key="k", value="new value")

    row = rows_holder["rows"][0]
    assert row["scope"] == "org-a"
    assert row["tags"] == ["ioc"]
    assert row["ttl"] == 600


def test_store_overwrites_scope_tags_ttl_when_given_on_update(monkeypatch):
    existing = _row("k", "v", scope="org-a", tags=["ioc"], ttl=600)
    rows_holder = _install(monkeypatch, rows=[existing])

    gm.guardian_memory_store(key="k", value="new value", scope="org-b", tags="network", ttl=120)

    row = rows_holder["rows"][0]
    assert row["scope"] == "org-b"
    assert row["tags"] == ["network"]
    assert row["ttl"] == 120


def test_store_rejects_missing_key(monkeypatch):
    _install(monkeypatch)
    result = gm.guardian_memory_store(key=None, value="x")
    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_store_rejects_missing_value(monkeypatch):
    _install(monkeypatch)
    result = gm.guardian_memory_store(key="k", value="")
    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_store_rejects_invalid_ttl(monkeypatch):
    _install(monkeypatch)
    result = gm.guardian_memory_store(key="k", value="v", ttl="not-a-number")
    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]
    assert "ttl" in result["error"]


def test_store_bootstraps_list_when_missing(monkeypatch):
    create_calls = []

    def handle_get_list(args):
        return [{"Type": 4, "Contents": "Item not found (8) on list [guardian_memory]"}]

    def handle_create_list(args):
        create_calls.append(args)
        return [{"Type": 1, "Contents": "Done"}]

    saved = {}

    def handle_set_list(args):
        saved["listData"] = json.loads(args["listData"])
        return [{"Type": 1, "Contents": "Done"}]

    handlers = {
        "GetTime": lambda args: [{"Type": 1, "Contents": "2026-07-06T12:00:00Z"}],
        "getList": handle_get_list,
        "createList": handle_create_list,
        "setList": handle_set_list,
    }
    monkeypatch.setattr(gm.demisto, "executeCommand", _multi_command_stub(handlers))
    monkeypatch.setattr(gm.demisto, "incident", lambda: {})

    result = gm.guardian_memory_store(key="k", value="v")

    assert result["ok"] is True
    assert len(create_calls) == 1
    assert create_calls[0] == {"listName": "guardian_memory", "listData": "[]"}
    assert saved["listData"][0]["key"] == "k"


# --- search: keyword matching, exclusion --------------------------------------


def test_search_excludes_non_matching_rows(monkeypatch):
    rows = [_row("a", "agents beacon to 8.8.8.8"), _row("b", "totally unrelated finding")]
    _install(monkeypatch, rows=rows)

    result = gm.guardian_memory_search(query="beacon")

    assert result["ok"] is True
    keys = [r["key"] for r in result["data"]["results"]]
    assert keys == ["a"]


def test_search_rejects_missing_query(monkeypatch):
    _install(monkeypatch)
    result = gm.guardian_memory_search(query="")
    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_search_over_empty_list_is_graceful(monkeypatch):
    _install(monkeypatch, rows=[])

    result = gm.guardian_memory_search(query="anything")

    assert result["ok"] is True
    assert result["data"]["results"] == []
    assert result["data"]["count"] == 0


def test_search_over_missing_list_bootstraps_gracefully(monkeypatch):
    create_calls = []

    def handle_get_list(args):
        return [{"Type": 4, "Contents": "Item not found (8) on list [guardian_memory]"}]

    def handle_create_list(args):
        create_calls.append(args)
        return [{"Type": 1, "Contents": "Done"}]

    handlers = {
        "GetTime": lambda args: [{"Type": 1, "Contents": "2026-07-06T12:00:00Z"}],
        "getList": handle_get_list,
        "createList": handle_create_list,
    }
    monkeypatch.setattr(gm.demisto, "executeCommand", _multi_command_stub(handlers))
    monkeypatch.setattr(gm.demisto, "incident", lambda: {})

    result = gm.guardian_memory_search(query="anything")

    assert result["ok"] is True
    assert result["data"]["count"] == 0
    assert len(create_calls) == 1


def test_search_and_store_support_namespaced_keys(monkeypatch):
    rows_holder = _install(monkeypatch)
    gm.guardian_memory_store(key="tech_stack:siem", value="org uses Splunk ES for SIEM")

    result = gm.guardian_memory_search(query="splunk")

    assert result["data"]["count"] == 1
    assert result["data"]["results"][0]["key"] == "tech_stack:siem"
    assert rows_holder["saved"] is True


# --- search: ranking (recency + hit boost) -------------------------------------


def test_search_ranks_more_recent_row_first(monkeypatch):
    rows = [
        _row("old", "beacon activity noted", updated_at="2026-06-01T00:00:00Z"),
        _row("new", "beacon activity noted", updated_at="2026-07-06T11:00:00Z"),
    ]
    _install(monkeypatch, rows=rows, now="2026-07-06T12:00:00Z")

    result = gm.guardian_memory_search(query="beacon")

    keys = [r["key"] for r in result["data"]["results"]]
    assert keys == ["new", "old"]


def test_search_ranks_more_hits_higher_when_recency_tied(monkeypatch):
    same_ts = "2026-07-06T11:00:00Z"
    rows = [
        _row("cold", "beacon activity", updated_at=same_ts, hits=0),
        _row("hot", "beacon activity", updated_at=same_ts, hits=8),
    ]
    _install(monkeypatch, rows=rows, now="2026-07-06T12:00:00Z")

    result = gm.guardian_memory_search(query="beacon")

    keys = [r["key"] for r in result["data"]["results"]]
    assert keys == ["hot", "cold"]


def test_keyword_score_none_when_no_token_matches():
    assert gm.guardian_memory_keyword_score(["zzz"], "zzz", "beacon activity") is None


def test_keyword_score_partial_vs_full_token_match():
    haystack = "agents beacon to 8.8.8.8 on port 443"
    partial = gm.guardian_memory_keyword_score(["beacon", "nomatch"], "beacon nomatch", haystack)
    full = gm.guardian_memory_keyword_score(["beacon"], "beacon", haystack)
    assert partial == pytest.approx(0.5 * gm.GUARDIAN_MEMORY_KEYWORD_WEIGHT)
    assert full == pytest.approx(1.0 * gm.GUARDIAN_MEMORY_KEYWORD_WEIGHT + gm.GUARDIAN_MEMORY_PHRASE_BONUS)


def test_recency_score_decays_with_age():
    row_fresh = _row("k", "v", updated_at="2026-07-06T12:00:00Z")
    row_old = _row("k", "v", updated_at="2026-06-01T12:00:00Z")
    now = "2026-07-06T12:00:00Z"
    assert gm.guardian_memory_recency_score(row_fresh, now) == pytest.approx(gm.GUARDIAN_MEMORY_RECENCY_WEIGHT)
    assert gm.guardian_memory_recency_score(row_old, now) < gm.guardian_memory_recency_score(row_fresh, now)


def test_recency_score_unparseable_is_zero():
    row = _row("k", "v", updated_at="not-a-date")
    assert gm.guardian_memory_recency_score(row, "2026-07-06T12:00:00Z") == 0.0


def test_hit_score_capped():
    row_many_hits = {"hits": 9999}
    row_no_hits = {"hits": 0}
    assert gm.guardian_memory_hit_score(row_many_hits) == pytest.approx(
        gm.GUARDIAN_MEMORY_HIT_CAP * gm.GUARDIAN_MEMORY_HIT_WEIGHT
    )
    assert gm.guardian_memory_hit_score(row_no_hits) == 0.0


# --- search: hit-count increment + persistence ---------------------------------


def test_search_increments_hits_on_returned_rows_and_persists(monkeypatch):
    rows = [_row("a", "beacon activity", hits=2)]
    rows_holder = _install(monkeypatch, rows=rows)

    result = gm.guardian_memory_search(query="beacon")

    assert result["data"]["results"][0]["hits"] == 3
    assert rows_holder["rows"][0]["hits"] == 3
    assert rows_holder["saved"] is True


def test_search_does_not_persist_when_nothing_reaped_or_matched(monkeypatch):
    rows = [_row("a", "totally unrelated")]
    rows_holder = _install(monkeypatch, rows=rows)

    gm.guardian_memory_search(query="beacon")

    assert rows_holder["saved"] is False


# --- search: reap-on-read -------------------------------------------------------


def test_search_reap_drops_expired_row_even_if_it_would_match(monkeypatch):
    expired = _row("stale", "beacon activity", updated_at="2026-07-06T10:00:00Z", ttl=60)
    rows_holder = _install(monkeypatch, rows=[expired], now="2026-07-06T12:00:00Z")

    result = gm.guardian_memory_search(query="beacon")

    assert result["data"]["results"] == []
    assert result["data"]["reaped_count"] == 1
    assert rows_holder["rows"] == []  # persisted without the expired row


def test_search_reap_persists_even_when_query_matches_nothing(monkeypatch):
    expired = _row("stale", "old note", updated_at="2026-07-06T10:00:00Z", ttl=60)
    live = _row("fresh", "another note", updated_at="2026-07-06T11:59:00Z")
    rows_holder = _install(monkeypatch, rows=[expired, live], now="2026-07-06T12:00:00Z")

    result = gm.guardian_memory_search(query="zzz-no-match")

    assert result["data"]["results"] == []
    assert result["data"]["reaped_count"] == 1
    assert [r["key"] for r in rows_holder["rows"]] == ["fresh"]


def test_search_never_reaps_permanent_row_even_when_very_old(monkeypatch):
    permanent = _row("perm", "beacon activity", updated_at="2020-01-01T00:00:00Z", ttl=None)
    _install(monkeypatch, rows=[permanent], now="2026-07-06T12:00:00Z")

    result = gm.guardian_memory_search(query="beacon")

    assert result["data"]["reaped_count"] == 0
    assert [r["key"] for r in result["data"]["results"]] == ["perm"]


def test_is_expired_permanent_row_is_never_expired():
    assert gm.guardian_memory_is_expired(_row("k", "v", ttl=None), "2099-01-01T00:00:00Z") is False
    assert gm.guardian_memory_is_expired(_row("k", "v", ttl=0), "2099-01-01T00:00:00Z") is False


def test_is_expired_unparseable_age_is_conservative():
    row = _row("k", "v", updated_at="not-a-date", ttl=60)
    assert gm.guardian_memory_is_expired(row, "2026-07-06T12:00:00Z") is False


def test_search_skips_reap_when_server_time_unobtainable(monkeypatch):
    """If GetTime AND incident.modified are both unavailable, reap-on-read is
    skipped conservatively (never guess an age) -- but the search itself still
    runs (recency just contributes 0 for every row)."""
    expired_looking = _row("stale", "beacon activity", updated_at="2020-01-01T00:00:00Z", ttl=60)
    rows_holder = {"rows": [expired_looking], "saved": False}
    handlers = {
        "GetTime": lambda args: [{"Type": 4, "Contents": "disabled"}],
        "getList": _get_list_handler(rows_holder),
        "setList": _set_list_handler(rows_holder),
    }
    monkeypatch.setattr(gm.demisto, "executeCommand", _multi_command_stub(handlers))
    monkeypatch.setattr(gm.demisto, "incident", lambda: {})

    result = gm.guardian_memory_search(query="beacon")

    assert result["data"]["reaped_count"] == 0
    assert len(result["data"]["results"]) == 1
    assert result["data"]["ts_warning"] is not None


# --- search: scope / tags filters -----------------------------------------------


def test_search_filters_by_scope(monkeypatch):
    rows = [_row("a", "beacon activity", scope="org-a"), _row("b", "beacon activity", scope="org-b")]
    _install(monkeypatch, rows=rows)

    result = gm.guardian_memory_search(query="beacon", scope="org-a")

    assert [r["key"] for r in result["data"]["results"]] == ["a"]


def test_search_filters_by_tags_any_overlap(monkeypatch):
    rows = [
        _row("a", "beacon activity", tags=["ioc"]),
        _row("b", "beacon activity", tags=["network"]),
        _row("c", "beacon activity", tags=[]),
    ]
    _install(monkeypatch, rows=rows)

    result = gm.guardian_memory_search(query="beacon", tags="ioc,other")

    assert [r["key"] for r in result["data"]["results"]] == ["a"]


# --- top-level dispatch / main() ------------------------------------------------


def test_dispatch_rejects_unknown_op(monkeypatch):
    _install(monkeypatch)
    result = gm.guardian_memory({"op": "delete"})
    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_main_store_success(monkeypatch):
    _install(monkeypatch)
    monkeypatch.setattr(gm.demisto, "args", lambda: {"op": "store", "key": "k", "value": "v"})
    captured = {}
    monkeypatch.setattr(gm, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    gm.main()

    assert "result" in captured
    assert captured["result"].outputs["op"] == "store"
    assert captured["result"].outputs["key"] == "k"


def test_main_search_success(monkeypatch):
    rows = [_row("a", "beacon activity")]
    _install(monkeypatch, rows=rows)
    monkeypatch.setattr(gm.demisto, "args", lambda: {"op": "search", "query": "beacon"})
    captured = {}
    monkeypatch.setattr(gm, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    gm.main()

    assert captured["result"].outputs["op"] == "search"
    assert captured["result"].outputs["count"] == 1


def test_main_calls_return_error_on_bad_op(monkeypatch):
    _install(monkeypatch)
    monkeypatch.setattr(gm.demisto, "args", lambda: {"op": "nope"})
    errors = []
    monkeypatch.setattr(gm, "return_error", lambda msg: errors.append(msg), raising=False)

    gm.main()

    assert errors
    assert "NEEDS_CONTEXT" in errors[0]


def test_main_calls_return_error_on_missing_required_arg(monkeypatch):
    _install(monkeypatch)
    monkeypatch.setattr(gm.demisto, "args", lambda: {"op": "store", "key": None, "value": None})
    errors = []
    monkeypatch.setattr(gm, "return_error", lambda msg: errors.append(msg), raising=False)

    gm.main()

    assert errors
    assert "NEEDS_CONTEXT" in errors[0]
