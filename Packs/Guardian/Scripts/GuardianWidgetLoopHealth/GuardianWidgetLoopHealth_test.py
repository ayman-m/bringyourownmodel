import json

import GuardianWidgetLoopHealth as gwlh


# --- fixtures / test harness --------------------------------------------------


def _entries(contents):
    return [{"Type": 1, "Contents": contents}]


def _not_found(list_name):
    return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(list_name)}]


NOW = "2026-07-05T12:00:00Z"


# --- guardian_widget_loophealth_classify ----------------------------------------


def test_classify_bare_running():
    assert gwlh.guardian_widget_loophealth_classify({"status": "running"}) == "running"


def test_classify_pending_is_awaiting():
    assert gwlh.guardian_widget_loophealth_classify({"status": "running", "pending": {"approval_id": "x"}}) == "awaiting"


def test_classify_awaiting_analyst_is_awaiting():
    assert (
        gwlh.guardian_widget_loophealth_classify({"status": "running", "awaiting_analyst": {"question": "q"}})
        == "awaiting"
    )


def test_classify_terminal_statuses():
    assert gwlh.guardian_widget_loophealth_classify({"status": "done"}) == "done"
    assert gwlh.guardian_widget_loophealth_classify({"status": "stopped"}) == "stopped"


def test_classify_empty_is_not_started():
    assert gwlh.guardian_widget_loophealth_classify(None) == "not_started"
    assert gwlh.guardian_widget_loophealth_classify({}) == "not_started"


def test_classify_unrecognized_status_is_unknown():
    assert gwlh.guardian_widget_loophealth_classify({"status": "weird"}) == "unknown"
    assert gwlh.guardian_widget_loophealth_classify({"other_key": 1}) == "unknown"


# --- time helpers ------------------------------------------------------------------


def test_parse_iso_and_minutes_since():
    assert gwlh._guardian_widget_loophealth_parse_iso("0001-01-01T00:00:00Z") is None
    assert gwlh._guardian_widget_loophealth_parse_iso("not-a-date") is None
    assert gwlh.guardian_widget_loophealth_minutes_since("2026-07-05T11:00:00Z", NOW) == 60.0
    assert gwlh.guardian_widget_loophealth_minutes_since("garbage", NOW) is None


# --- settings / kill switch --------------------------------------------------------


def test_load_settings_default_when_missing(monkeypatch):
    monkeypatch.setattr(gwlh.demisto, "executeCommand", lambda c, a: _not_found(gwlh.GUARDIAN_SETTINGS_LIST_NAME))
    assert gwlh.guardian_widget_loophealth_load_settings() == gwlh.GUARDIAN_LOOP_HEALTH_DEFAULT_STALLED_MINUTES


def test_load_settings_custom_value(monkeypatch):
    monkeypatch.setattr(
        gwlh.demisto, "executeCommand", lambda c, a: _entries(json.dumps({"stalled_run_minutes": 45}))
    )
    assert gwlh.guardian_widget_loophealth_load_settings() == 45


def test_load_settings_malformed_falls_back(monkeypatch):
    monkeypatch.setattr(
        gwlh.demisto, "executeCommand", lambda c, a: _entries(json.dumps({"stalled_run_minutes": -5}))
    )
    assert gwlh.guardian_widget_loophealth_load_settings() == gwlh.GUARDIAN_LOOP_HEALTH_DEFAULT_STALLED_MINUTES


def test_load_kill_switch_missing_is_default_off(monkeypatch):
    monkeypatch.setattr(gwlh.demisto, "executeCommand", lambda c, a: _not_found(gwlh.GUARDIAN_KILL_SWITCH_LIST_NAME))
    state = gwlh.guardian_widget_loophealth_load_kill_switch()
    assert state["enabled"] is False
    assert gwlh.guardian_widget_loophealth_format_kill_switch(state) == "OFF"


def test_load_kill_switch_on_with_full_state(monkeypatch):
    payload = {"enabled": True, "reason": "incident spike", "toggled_by": "operator", "ts": "2026-07-05T09:00:00Z"}
    monkeypatch.setattr(gwlh.demisto, "executeCommand", lambda c, a: _entries(json.dumps(payload)))
    state = gwlh.guardian_widget_loophealth_load_kill_switch()
    displayed = gwlh.guardian_widget_loophealth_format_kill_switch(state)
    assert displayed == "ON by operator at 2026-07-05T09:00:00Z (reason: incident spike)"


def test_format_kill_switch_off():
    assert gwlh.guardian_widget_loophealth_format_kill_switch({"enabled": False}) == "OFF"


# --- guardian_widget_loophealth_run (injected fakes) --------------------------------


FAKE_INCIDENTS = [
    {"id": "1", "modified": "2026-07-05T11:00:00Z", "investigation_id": "inv1", "tick_count": 5},  # stale -> stalled
    {"id": "2", "modified": "2026-07-05T11:55:00Z", "investigation_id": "inv2", "tick_count": 3},  # fresh running
    {"id": "3", "modified": "2026-07-05T10:00:00Z", "investigation_id": None, "tick_count": None},  # not_started
    {"id": "4", "modified": "2026-07-05T11:59:00Z", "investigation_id": "inv4", "tick_count": 10},  # done
    {"id": "5", "modified": "2026-07-05T11:59:00Z", "investigation_id": "inv5", "tick_count": None},  # awaiting
]

FAKE_LOOP_BY_ID = {
    "1": {"status": "running"},
    "2": {"status": "running"},
    "4": {"status": "done"},
    "5": {"status": "running", "pending": {"approval_id": "z"}},
}


def _fake_search_ok():
    return gwlh.guardian_envelope(True, data=list(FAKE_INCIDENTS))


def _fake_probe(incident_id):
    loop_ctx = FAKE_LOOP_BY_ID.get(incident_id)
    return gwlh.guardian_envelope(True, data=loop_ctx)


def _fake_settings():
    return 15


def _fake_kill_switch():
    return {"enabled": True, "reason": "test", "toggled_by": "operator", "ts": "2026-07-05T09:00:00Z"}


def _fake_server_time():
    return NOW, None


def test_run_computes_buckets_avg_ticks_and_stalled():
    result = gwlh.guardian_widget_loophealth_run(
        search_fn=_fake_search_ok,
        probe_fn=_fake_probe,
        settings_fn=_fake_settings,
        kill_switch_fn=_fake_kill_switch,
        server_time_fn=_fake_server_time,
    )
    assert result["ok"] is True
    data = result["data"]
    assert data["bucket_counts"]["running"] == 2
    assert data["bucket_counts"]["awaiting"] == 1
    assert data["bucket_counts"]["done"] == 1
    assert data["bucket_counts"]["stopped"] == 0
    assert data["bucket_counts"]["not_started"] == 1
    assert data["bucket_counts"]["unknown"] == 0
    assert data["bucket_counts"]["unprobed"] == 0
    assert data["bucket_counts"]["probe_error"] == 0
    assert data["avg_ticks"] == 6.0  # (5+3+10)/3
    assert data["stalled_count"] == 1  # only incident 1 (60min > 15min threshold)
    assert "ON" in data["kill_switch_display"]


def test_run_empty_incidents_is_graceful():
    result = gwlh.guardian_widget_loophealth_run(
        search_fn=lambda: gwlh.guardian_envelope(True, data=[]),
        probe_fn=_fake_probe,
        settings_fn=_fake_settings,
        kill_switch_fn=lambda: {"enabled": False},
        server_time_fn=_fake_server_time,
    )
    assert result["ok"] is True
    data = result["data"]
    assert all(count == 0 for count in data["bucket_counts"].values())
    assert data["avg_ticks"] is None
    assert data["stalled_count"] == 0
    assert data["kill_switch_display"] == "OFF"


def test_run_search_failure_propagates():
    result = gwlh.guardian_widget_loophealth_run(
        search_fn=lambda: gwlh.guardian_envelope(False, error="boom"),
        probe_fn=_fake_probe,
        settings_fn=_fake_settings,
        kill_switch_fn=_fake_kill_switch,
        server_time_fn=_fake_server_time,
    )
    assert result["ok"] is False
    assert "boom" in result["error"]


def test_run_respects_max_probed_cap(monkeypatch):
    monkeypatch.setattr(gwlh, "GUARDIAN_LOOP_HEALTH_MAX_PROBED", 1)
    incidents = [
        {"id": "1", "modified": "2026-07-05T11:59:00Z", "investigation_id": "inv1", "tick_count": 1},
        {"id": "2", "modified": "2026-07-05T11:58:00Z", "investigation_id": "inv2", "tick_count": 2},
    ]
    result = gwlh.guardian_widget_loophealth_run(
        search_fn=lambda: gwlh.guardian_envelope(True, data=incidents),
        probe_fn=lambda incident_id: gwlh.guardian_envelope(True, data={"status": "running"}),
        settings_fn=_fake_settings,
        kill_switch_fn=lambda: {"enabled": False},
        server_time_fn=_fake_server_time,
    )
    data = result["data"]
    assert data["bucket_counts"]["running"] == 1
    assert data["bucket_counts"]["unprobed"] == 1


def test_run_probe_error_is_counted_not_fatal():
    def probe_error(incident_id):
        return gwlh.guardian_envelope(False, error="REST hiccup")

    result = gwlh.guardian_widget_loophealth_run(
        search_fn=_fake_search_ok,
        probe_fn=probe_error,
        settings_fn=_fake_settings,
        kill_switch_fn=lambda: {"enabled": False},
        server_time_fn=_fake_server_time,
    )
    assert result["ok"] is True
    # every one of the 4 investigated incidents (1,2,4,5) fails to probe
    assert result["data"]["bucket_counts"]["probe_error"] == 4
    assert result["data"]["bucket_counts"]["not_started"] == 1


def test_run_adds_the_exact_not_started_count():
    """The page leaves Pending incidents out; their exact count comes from
    not_started_fn, on top of any page row that has no investigation."""
    result = gwlh.guardian_widget_loophealth_run(
        search_fn=_fake_search_ok,
        probe_fn=_fake_probe,
        settings_fn=_fake_settings,
        kill_switch_fn=_fake_kill_switch,
        server_time_fn=_fake_server_time,
        not_started_fn=lambda: gwlh.guardian_envelope(True, data=43486),
    )
    assert result["data"]["bucket_counts"]["not_started"] == 1 + 43486
    assert result["data"]["bucket_counts"]["running"] == 2  # real runs still probed


def test_run_not_started_count_failure_is_a_warning():
    result = gwlh.guardian_widget_loophealth_run(
        search_fn=_fake_search_ok,
        probe_fn=_fake_probe,
        settings_fn=_fake_settings,
        kill_switch_fn=_fake_kill_switch,
        server_time_fn=_fake_server_time,
        not_started_fn=lambda: gwlh.guardian_envelope(False, error="REST hiccup"),
    )
    assert result["ok"] is True
    assert result["data"]["bucket_counts"]["not_started"] == 1
    assert any("not-started count failed" in w for w in result["data"]["warnings"])


# --- guardian_widget_loophealth_build ------------------------------------------------


def test_build_always_shows_every_bucket():
    state = {
        "bucket_counts": {bucket: 0 for bucket in gwlh.GUARDIAN_LOOP_HEALTH_BUCKET_ORDER},
        "avg_ticks": None,
        "stalled_count": 0,
        "kill_switch_display": "OFF",
    }
    widget = gwlh.guardian_widget_loophealth_build(state)
    displayed = json.loads(widget.to_display())
    assert displayed["total"] == len(gwlh.GUARDIAN_LOOP_HEALTH_BUCKET_ORDER) + 3  # + avg_ticks/stalled/kill_switch
    metrics = [row["Metric"] for row in displayed["data"]]
    assert set(gwlh.GUARDIAN_LOOP_HEALTH_BUCKET_ORDER).issubset(set(metrics))
    assert "avg_ticks" in metrics
    assert "stalled_runs" in metrics
    assert "kill_switch" in metrics
    avg_row = next(row for row in displayed["data"] if row["Metric"] == "avg_ticks")
    assert avg_row["Value"] == "n/a"


# --- REST plumbing (search_incidents / probe_loop) ------------------------------------


def test_search_incidents_projects_and_sorts(monkeypatch):
    def fake_execute(command, args):
        assert command == "demisto-api-post"
        body = json.loads(args["body"])
        assert body["filter"]["query"] == 'type:"Guardian Agent Run" and -status:closed and -status:Pending'
        assert body["filter"]["sort"] == [{"field": "modified", "asc": False}]
        return _entries(
            {
                "response": {
                    "data": [
                        {
                            "id": "1",
                            "modified": "2026-07-05T11:00:00Z",
                            "investigationId": "inv1",
                            "CustomFields": {"guardiantickcount": 5},
                        },
                        {
                            "id": "2",
                            "modified": "2026-07-05T11:55:00Z",
                            "investigationId": "",
                            "CustomFields": {},
                        },
                    ]
                }
            }
        )

    monkeypatch.setattr(gwlh.demisto, "executeCommand", fake_execute)
    result = gwlh.guardian_widget_loophealth_search_incidents()
    assert result["ok"] is True
    ids_in_order = [inc["id"] for inc in result["data"]]
    assert ids_in_order == ["2", "1"]  # sorted most-recently-modified first
    assert result["data"][1]["tick_count"] == 5
    assert result["data"][0]["investigation_id"] == ""


def test_count_not_started_reads_the_exact_total(monkeypatch):
    def fake_execute(command, args):
        body = json.loads(args["body"])
        assert body["filter"]["query"] == 'type:"Guardian Agent Run" and status:Pending'
        assert body["filter"]["size"] == 1
        return _entries({"response": {"total": 43486, "data": [{"id": "17"}]}})

    monkeypatch.setattr(gwlh.demisto, "executeCommand", fake_execute)
    result = gwlh.guardian_widget_loophealth_count_not_started()
    assert result == gwlh.guardian_envelope(True, data=43486)


def test_count_not_started_rejects_a_missing_total(monkeypatch):
    monkeypatch.setattr(gwlh.demisto, "executeCommand", lambda command, args: _entries({"response": {"data": []}}))
    assert gwlh.guardian_widget_loophealth_count_not_started()["ok"] is False


def test_probe_loop_parses_remote_entries(monkeypatch):
    def fake_execute(command, args):
        assert command == "demisto-api-post"
        body = json.loads(args["body"])
        assert body["investigationId"] == "42"
        assert body["data"] == "!GuardianHousekeeping probe_key=Loop"
        return _entries({"response": [{"type": 1, "contents": json.dumps({"status": "running"})}]})

    monkeypatch.setattr(gwlh.demisto, "executeCommand", fake_execute)
    result = gwlh.guardian_widget_loophealth_probe_loop("42")
    assert result["ok"] is True
    assert result["data"] == {"status": "running"}


def test_probe_loop_remote_error_entry(monkeypatch):
    def fake_execute(command, args):
        return _entries({"response": [{"type": gwlh.GUARDIAN_ERROR_ENTRY_TYPE, "contents": "boom"}]})

    monkeypatch.setattr(gwlh.demisto, "executeCommand", fake_execute)
    result = gwlh.guardian_widget_loophealth_probe_loop("42")
    assert result["ok"] is False


def test_probe_loop_no_loop_state_yet(monkeypatch):
    def fake_execute(command, args):
        return _entries({"response": [{"type": 1, "contents": None}]})

    monkeypatch.setattr(gwlh.demisto, "executeCommand", fake_execute)
    result = gwlh.guardian_widget_loophealth_probe_loop("42")
    assert result["ok"] is True
    assert result["data"] is None


# --- main() end-to-end ---------------------------------------------------------------


def test_main_end_to_end(monkeypatch):
    def fake_execute(command, args):
        if command == "getList" and args["listName"] == gwlh.GUARDIAN_SETTINGS_LIST_NAME:
            return _entries(json.dumps({"stalled_run_minutes": 15}))
        if command == "getList" and args["listName"] == gwlh.GUARDIAN_KILL_SWITCH_LIST_NAME:
            return _entries(json.dumps({"enabled": False}))
        if command == "GetTime":
            return _entries(NOW)
        if command == "demisto-api-post":
            body = json.loads(args["body"])
            if args["uri"] == "/incidents/search":
                return _entries(
                    {
                        "response": {
                            "data": [
                                {
                                    "id": "1",
                                    "modified": "2026-07-05T11:59:00Z",
                                    "investigationId": "inv1",
                                    "CustomFields": {"guardiantickcount": 2},
                                }
                            ]
                        }
                    }
                )
            if args["uri"] == "/entry/execute/sync":
                assert body["investigationId"] == "1"
                return _entries({"response": [{"type": 1, "contents": json.dumps({"status": "running"})}]})
        raise AssertionError("unexpected command {} {}".format(command, args))

    monkeypatch.setattr(gwlh.demisto, "executeCommand", fake_execute)
    gwlh.RESULTS.clear()
    gwlh.main()
    assert len(gwlh.RESULTS) == 1
    displayed = json.loads(gwlh.RESULTS[0])
    metrics = {row["Metric"]: row["Value"] for row in displayed["data"]}
    assert metrics["running"] == 1
    assert metrics["kill_switch"] == "OFF"
