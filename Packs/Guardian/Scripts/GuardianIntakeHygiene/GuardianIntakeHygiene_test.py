import GuardianIntakeHygiene as gih


# --- test harness -------------------------------------------------------------


def _get_list_handler(contents, ok=True):
    """Fake `getList` returning `contents` as the Contents string (or the raw
    value directly), or an error entry when `ok` is False."""

    def handler(args):
        assert args["listName"] == "guardian_kill_switch"
        if not ok:
            return [{"Type": 4, "Contents": contents}]
        return [{"Type": 1, "Contents": contents}]

    return handler


def _install(monkeypatch, get_list_handler):
    def fake_execute(command, args):
        if command == "getList":
            return get_list_handler(args)
        raise AssertionError("unexpected command dispatched: {} {}".format(command, args))

    monkeypatch.setattr(gih.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(gih.demisto, "error", lambda msg: None)
    monkeypatch.setattr(gih.demisto, "info", lambda msg: None)


# --- guardian_intake_load_kill_switch: fail-open matrix ------------------------


def test_load_kill_switch_enabled_true(monkeypatch):
    _install(monkeypatch, _get_list_handler('{"enabled": true}'))
    enabled, note = gih.guardian_intake_load_kill_switch()
    assert enabled is True
    assert note is None


def test_load_kill_switch_enabled_false(monkeypatch):
    _install(monkeypatch, _get_list_handler('{"enabled": false}'))
    enabled, note = gih.guardian_intake_load_kill_switch()
    assert enabled is False
    assert note is None


def test_load_kill_switch_unreadable_fails_open(monkeypatch):
    _install(monkeypatch, _get_list_handler("Item not found (8) on list [guardian_kill_switch]", ok=False))
    enabled, note = gih.guardian_intake_load_kill_switch()
    assert enabled is False
    assert "fails OPEN" in note


def test_load_kill_switch_empty_string_fails_open(monkeypatch):
    _install(monkeypatch, _get_list_handler("   "))
    enabled, note = gih.guardian_intake_load_kill_switch()
    assert enabled is False
    assert "empty" in note


def test_load_kill_switch_bad_json_fails_open(monkeypatch):
    _install(monkeypatch, _get_list_handler("{not json"))
    enabled, note = gih.guardian_intake_load_kill_switch()
    assert enabled is False
    assert "not valid JSON" in note


def test_load_kill_switch_wrong_shape_fails_open(monkeypatch):
    _install(monkeypatch, _get_list_handler("[1, 2, 3]"))
    enabled, note = gih.guardian_intake_load_kill_switch()
    assert enabled is False
    assert "unexpected shape" in note


def test_load_kill_switch_missing_enabled_key_keeps(monkeypatch):
    # A dict without an `enabled` key -> not enabled (keep). enabled is True
    # only on an affirmative `enabled: true`.
    _install(monkeypatch, _get_list_handler('{"reason": "x"}'))
    enabled, note = gih.guardian_intake_load_kill_switch()
    assert enabled is False
    assert note is None


# --- guardian_intake_has_open_queue_work (harvest candidate #16) ---------------


def _rest_post_stub(monkeypatch, response=None, ok=True, error="connection refused"):
    captured = {}

    def fake(uri, body_obj):
        captured["uri"] = uri
        captured["body"] = body_obj
        if not ok:
            return {"ok": False, "error": error, "retryable": True, "is_auth_error": False, "data": None}
        return {"ok": True, "data": response, "error": None, "retryable": False, "is_auth_error": False}

    monkeypatch.setattr(gih, "_guardian_rest_post", fake)
    return captured


def test_has_open_queue_work_true_when_records_present(monkeypatch):
    _rest_post_stub(monkeypatch, response={"data": [{"id": "42"}], "total": 1})
    has_work, note = gih.guardian_intake_has_open_queue_work()
    assert has_work is True
    assert note is None


def test_has_open_queue_work_false_when_no_records(monkeypatch):
    _rest_post_stub(monkeypatch, response={"data": [], "total": 0})
    has_work, note = gih.guardian_intake_has_open_queue_work()
    assert has_work is False
    assert "nothing for this sweep to triage" in note


def test_has_open_queue_work_query_shape_excludes_guardian_meta_types(monkeypatch):
    """Pins the confirmed-live query shape -- a regression here would be a
    silent behavior change to a scheduled job's pre-model gate."""
    captured = _rest_post_stub(monkeypatch, response={"data": [], "total": 0})
    gih.guardian_intake_has_open_queue_work()

    assert captured["uri"] == "/incidents/search"
    query = captured["body"]["filter"]["query"]
    assert "-status:closed" in query
    assert '-type:"Guardian Agent Run"' in query
    assert '-type:"Guardian Eval Case"' in query
    assert captured["body"]["filter"]["size"] == 1  # existence only, never a full page


def test_has_open_queue_work_fails_open_on_rest_failure(monkeypatch):
    _rest_post_stub(monkeypatch, ok=False, error="auth failed")
    has_work, note = gih.guardian_intake_has_open_queue_work()
    assert has_work is True
    assert "auth failed" in note and "fails OPEN" in note


def test_has_open_queue_work_fails_open_on_unexpected_response_shape(monkeypatch):
    _rest_post_stub(monkeypatch, response={"unexpected": "shape"})
    has_work, note = gih.guardian_intake_has_open_queue_work()
    assert has_work is True
    assert "unexpected response shape" in note and "fails OPEN" in note


# --- guardian_intake_decision (pure) ------------------------------------------


def test_decision_drops_agent_run_when_switch_on():
    keep, note = gih.guardian_intake_decision({"type": "Guardian Agent Run"}, True)
    assert keep is False
    assert "dropping" in note


def test_decision_keeps_agent_run_when_switch_off():
    keep, note = gih.guardian_intake_decision({"type": "Guardian Agent Run"}, False)
    assert keep is True
    assert "kept" in note


def test_decision_keeps_non_agent_incident_even_when_switch_on():
    # Defense in depth: this gate only guards agent-run intake.
    keep, note = gih.guardian_intake_decision({"type": "Phishing"}, True)
    assert keep is True
    assert "not" in note


def test_decision_treats_missing_type_as_in_scope():
    # No type -> the rule matched it, respect the rule; still only dropped
    # when the switch is on.
    keep_on, _ = gih.guardian_intake_decision({}, True)
    keep_off, _ = gih.guardian_intake_decision({}, False)
    assert keep_on is False
    assert keep_off is True


# --- guardian_intake_decision: harvest candidate #16 (is_sweep_run / has_open_queue_work) ---


def test_decision_drops_sweep_run_with_no_open_queue_work():
    keep, note = gih.guardian_intake_decision(
        {"type": "Guardian Agent Run"}, False, is_sweep_run=True, has_open_queue_work=False
    )
    assert keep is False
    assert "dropping this sweep's incident" in note


def test_decision_keeps_sweep_run_with_open_queue_work():
    keep, note = gih.guardian_intake_decision(
        {"type": "Guardian Agent Run"}, False, is_sweep_run=True, has_open_queue_work=True
    )
    assert keep is True


def test_decision_defaults_never_drop_for_open_queue_work_alone():
    # is_sweep_run defaults False -- has_open_queue_work=False by itself must
    # never drop a non-sweep call (every pre-#16 caller passes only 2 args).
    keep, note = gih.guardian_intake_decision({"type": "Guardian Agent Run"}, False)
    assert keep is True
    assert "dropping this sweep" not in note


def test_decision_non_sweep_run_ignores_has_open_queue_work():
    # is_sweep_run=False -- has_open_queue_work is irrelevant even if explicitly False.
    keep, note = gih.guardian_intake_decision(
        {"type": "Guardian Agent Run"}, False, is_sweep_run=False, has_open_queue_work=False
    )
    assert keep is True


def test_decision_kill_switch_still_wins_over_sweep_queue_check():
    # The switch is checked FIRST -- a switch-enabled sweep run still drops
    # for the switch reason, not the queue-emptiness reason.
    keep, note = gih.guardian_intake_decision(
        {"type": "Guardian Agent Run"}, True, is_sweep_run=True, has_open_queue_work=True
    )
    assert keep is False
    assert "guardian_kill_switch.enabled=true" in note


# --- guardian_intake_hygiene_run (end to end, mocked) -------------------------


def test_run_drops_when_switch_on(monkeypatch):
    _install(monkeypatch, _get_list_handler('{"enabled": true}'))
    monkeypatch.setattr(gih.demisto, "incident", lambda: {"type": "Guardian Agent Run"})
    keep, note = gih.guardian_intake_hygiene_run()
    assert keep is False
    assert "dropping" in note


def test_run_keeps_when_switch_off(monkeypatch):
    _install(monkeypatch, _get_list_handler('{"enabled": false}'))
    monkeypatch.setattr(gih.demisto, "incident", lambda: {"type": "Guardian Agent Run"})
    keep, note = gih.guardian_intake_hygiene_run()
    assert keep is True


def test_run_keeps_when_switch_absent_fail_open(monkeypatch):
    _install(monkeypatch, _get_list_handler("Item not found (8)", ok=False))
    monkeypatch.setattr(gih.demisto, "incident", lambda: {"type": "Guardian Agent Run"})
    keep, note = gih.guardian_intake_hygiene_run()
    assert keep is True
    assert "fails OPEN" in note


def test_run_prepends_load_note_when_degraded(monkeypatch):
    _install(monkeypatch, _get_list_handler("{bad", ok=True))
    monkeypatch.setattr(gih.demisto, "incident", lambda: {"type": "Guardian Agent Run"})
    keep, note = gih.guardian_intake_hygiene_run()
    assert keep is True
    assert "not valid JSON" in note and "kept" in note


# --- guardian_intake_hygiene_run: harvest candidate #16 wiring -----------------


def _sweep_incident(trigger_source="job:intake-sweep"):
    return {"type": "Guardian Agent Run", "CustomFields": {"guardiantriggersource": trigger_source}}


def test_run_checks_open_queue_work_only_for_sweep_trigger_source(monkeypatch):
    _install(monkeypatch, _get_list_handler('{"enabled": false}'))
    monkeypatch.setattr(gih.demisto, "incident", lambda: _sweep_incident())
    calls = []
    monkeypatch.setattr(
        gih, "guardian_intake_has_open_queue_work", lambda: (calls.append(1), (True, None))[1]
    )

    gih.guardian_intake_hygiene_run()

    assert len(calls) == 1


def test_run_never_checks_open_queue_work_for_non_sweep_trigger_source(monkeypatch):
    _install(monkeypatch, _get_list_handler('{"enabled": false}'))
    monkeypatch.setattr(gih.demisto, "incident", lambda: {"type": "Guardian Agent Run"})  # no CustomFields at all
    calls = []
    monkeypatch.setattr(
        gih, "guardian_intake_has_open_queue_work", lambda: (calls.append(1), (False, "should never run"))[1]
    )

    keep, note = gih.guardian_intake_hygiene_run()

    assert calls == []  # the REST-backed check is never even invoked
    assert keep is True
    assert "should never run" not in note


def test_run_never_checks_open_queue_work_when_kill_switch_already_enabled(monkeypatch):
    # The switch already decides "drop" -- paying for the REST call would be pure waste.
    _install(monkeypatch, _get_list_handler('{"enabled": true}'))
    monkeypatch.setattr(gih.demisto, "incident", lambda: _sweep_incident())
    calls = []
    monkeypatch.setattr(
        gih, "guardian_intake_has_open_queue_work", lambda: (calls.append(1), (True, None))[1]
    )

    keep, note = gih.guardian_intake_hygiene_run()

    assert calls == []
    assert keep is False
    assert "guardian_kill_switch.enabled=true" in note


def test_run_drops_sweep_incident_when_queue_check_says_no_open_work(monkeypatch):
    _install(monkeypatch, _get_list_handler('{"enabled": false}'))
    monkeypatch.setattr(gih.demisto, "incident", lambda: _sweep_incident())
    monkeypatch.setattr(
        gih, "guardian_intake_has_open_queue_work", lambda: (False, "no open non-Guardian-meta incidents found")
    )

    keep, note = gih.guardian_intake_hygiene_run()

    assert keep is False
    assert "no open non-Guardian-meta incidents found" in note
    assert "dropping this sweep's incident" in note


def test_run_keeps_sweep_incident_when_queue_check_says_open_work_exists(monkeypatch):
    _install(monkeypatch, _get_list_handler('{"enabled": false}'))
    monkeypatch.setattr(gih.demisto, "incident", lambda: _sweep_incident())
    monkeypatch.setattr(gih, "guardian_intake_has_open_queue_work", lambda: (True, None))

    keep, note = gih.guardian_intake_hygiene_run()

    assert keep is True


# --- current-incident shape tolerance -----------------------------------------


def test_current_incident_falls_back_to_incidents_list(monkeypatch):
    monkeypatch.setattr(gih.demisto, "incident", lambda: {})
    monkeypatch.setattr(gih.demisto, "incidents", lambda: [{"type": "Guardian Agent Run", "id": "9"}])
    inc = gih.guardian_intake_current_incident()
    assert inc.get("id") == "9"


def test_current_incident_empty_when_neither_available(monkeypatch):
    monkeypatch.setattr(gih.demisto, "incident", lambda: {})
    monkeypatch.setattr(gih.demisto, "incidents", lambda: [])
    assert gih.guardian_intake_current_incident() == {}


# --- main() returns a bare boolean (the pre-process drop/keep signal) ---------


def test_main_returns_false_to_drop(monkeypatch):
    gih.RESULTS.clear()
    _install(monkeypatch, _get_list_handler('{"enabled": true}'))
    monkeypatch.setattr(gih.demisto, "incident", lambda: {"type": "Guardian Agent Run"})
    gih.main()
    assert gih.RESULTS == [False]


def test_main_returns_true_to_keep(monkeypatch):
    gih.RESULTS.clear()
    _install(monkeypatch, _get_list_handler('{"enabled": false}'))
    monkeypatch.setattr(gih.demisto, "incident", lambda: {"type": "Guardian Agent Run"})
    gih.main()
    assert gih.RESULTS == [True]


def test_main_fails_open_on_exception(monkeypatch):
    gih.RESULTS.clear()

    def boom(command, args):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(gih.demisto, "executeCommand", boom)
    monkeypatch.setattr(gih.demisto, "incident", lambda: {"type": "Guardian Agent Run"})
    monkeypatch.setattr(gih.demisto, "error", lambda msg: None)
    monkeypatch.setattr(gih.demisto, "info", lambda msg: None)
    # guardian_execute catches the raise and returns an unreadable envelope
    # (fail-open) rather than propagating -- so this keeps, not drops.
    gih.main()
    assert gih.RESULTS == [True]
