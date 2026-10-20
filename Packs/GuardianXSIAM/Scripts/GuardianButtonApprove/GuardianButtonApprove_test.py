import json

import pytest

import GuardianButtonApprove as button

OK = [{"Type": 1, "Contents": "Done", "HumanReadable": "Done"}]
HOSTILE = "<script>alert(1)</script>"

LEDGER = [
    {"approval_id": "appr-1", "incident_id": "22486", "run_id": "22486", "status": "pending", "risk_tier": "soft"},
    {"approval_id": "appr-other", "incident_id": "99999", "run_id": "99999", "status": "pending", "risk_tier": "soft"},
    {"approval_id": "appr-noinc", "status": "pending"},
]


def _install(monkeypatch, responses=None, incident_id="22486", ledger=None):
    """Stub demisto: record every executeCommand call and answer from `responses` (command -> entries)."""
    calls = []
    responses = responses or {}

    def fake_execute(command, args):
        calls.append((command, args))
        if command == "getList":
            if ledger is False:
                return [{"Type": 4, "Contents": "Item not found (8)"}]
            return [{"Type": 1, "Contents": json.dumps(LEDGER if ledger is None else ledger)}]
        return responses.get(command, OK)

    monkeypatch.setattr(button.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(button.demisto, "incident", lambda: {"id": incident_id} if incident_id else {})
    return calls


def _run_main(monkeypatch, args):
    import CommonServerPython as csp

    csp.RESULTS.clear()
    monkeypatch.setattr(button.demisto, "args", lambda: args)
    return csp


def _commands(calls):
    return [call for call in calls if call[0] != "getList"]


def test_approve_calls_only_guardian_approve_with_the_id_and_a_layout_actor(monkeypatch):
    calls = _install(monkeypatch)
    ok, text = button.guardian_button_approve("  appr-1  ")
    assert ok is True and "appr-1" in text and "next reasoning tick" in text
    assert _commands(calls) == [("guardian-approve", {"approval_id": "appr-1", "actor": "analyst (layout button)"})]
    assert "confirm" not in _commands(calls)[0][1]  # never supplies CONFIRM: that is the credential button's job


def test_approve_requires_an_id(monkeypatch):
    calls = _install(monkeypatch)
    for bad in (None, "", "   ", 5):
        ok, text = button.guardian_button_approve(bad)
        assert ok is False and "approval_id is required" in text
    assert calls == []


def test_approve_refuses_an_approval_that_belongs_to_another_incident(monkeypatch):
    calls = _install(monkeypatch)
    ok, text = button.guardian_button_approve("appr-other")
    assert ok is False and "belongs to incident 99999" in text
    assert _commands(calls) == []  # nothing was resolved


def test_approve_matches_on_run_id_too_and_lets_unknown_or_unscoped_rows_through(monkeypatch):
    ledger = [{"approval_id": "r1", "run_id": "22486"}, {"approval_id": "n1"}]
    for approval_id in ("r1", "n1", "not-in-ledger"):
        calls = _install(monkeypatch, ledger=ledger)
        assert button.guardian_button_approve(approval_id)[0] is True
        assert [c[0] for c in _commands(calls)] == ["guardian-approve"]


def test_approve_still_works_when_the_ledger_is_unreadable_or_no_incident_is_known(monkeypatch):
    _install(monkeypatch, ledger=False)
    assert button.guardian_button_approve("appr-1")[0] is True
    _install(monkeypatch, incident_id="")
    assert button.guardian_button_approve("appr-other")[0] is True


def test_approve_surfaces_the_command_error(monkeypatch):
    _install(monkeypatch, {"guardian-approve": [{"Type": 4, "Contents": "already resolved"}]})
    ok, text = button.guardian_button_approve("appr-1")
    assert ok is False and "already resolved" in text


def test_approve_points_credential_requests_at_the_credential_button(monkeypatch):
    _install(monkeypatch, {"guardian-approve": [{"Type": 4, "Contents": "approval_id 'appr-1' is credential-tier -- approving it requires confirm=CONFIRM"}]})
    ok, text = button.guardian_button_approve("appr-1")
    assert ok is False and "Approve (credential tier)" in text and "CONFIRM" in text


def test_approve_does_not_raise_when_the_command_raises(monkeypatch):
    def boom(command, args):
        raise RuntimeError("no such command")

    monkeypatch.setattr(button.demisto, "executeCommand", boom)
    monkeypatch.setattr(button.demisto, "incident", lambda: {"id": "1"})
    ok, text = button.guardian_button_approve("appr-1")
    assert ok is False and "no such command" in text


def test_approve_caps_the_id_length(monkeypatch):
    calls = _install(monkeypatch)
    button.guardian_button_approve("x" * 1000)
    assert len(_commands(calls)[0][1]["approval_id"]) == button.GUARDIAN_BUTTON_MAX_ID_CHARS


def test_main_success_returns_a_short_message(monkeypatch):
    _install(monkeypatch)
    csp = _run_main(monkeypatch, {"approval_id": "appr-1"})
    button.main()
    assert len(csp.RESULTS) == 1 and "approved" in csp.RESULTS[0].readable_output


def test_main_failure_is_an_error_not_a_success(monkeypatch):
    _install(monkeypatch)
    _run_main(monkeypatch, {"approval_id": "appr-other"})
    with pytest.raises(SystemExit) as exc_info:
        button.main()
    assert "belongs to incident" in str(exc_info.value)


def test_hostile_id_is_forwarded_as_plain_text_and_never_rendered(monkeypatch):
    calls = _install(monkeypatch)
    button.guardian_button_approve(HOSTILE)
    assert _commands(calls)[0][1]["approval_id"] == HOSTILE  # the command validates it; the button result is plain text
