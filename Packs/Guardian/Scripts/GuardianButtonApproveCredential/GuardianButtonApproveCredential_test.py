import json

import pytest

import GuardianButtonApproveCredential as button

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


def test_credential_approve_requires_the_exact_confirm_word(monkeypatch):
    calls = _install(monkeypatch)
    for bad in (None, "", "confirm", "Confirm", " CONFIRM", "yes"):
        ok, text = button.guardian_button_approve_credential("appr-1", bad)
        assert ok is False and "Type CONFIRM exactly" in text
    assert _commands(calls) == []


def test_credential_approve_passes_confirm_through_and_audits_the_actor(monkeypatch):
    calls = _install(monkeypatch)
    ok, text = button.guardian_button_approve_credential("appr-1", "CONFIRM")
    assert ok is True and "credential tier" in text
    assert _commands(calls) == [
        ("guardian-approve", {"approval_id": "appr-1", "confirm": "CONFIRM", "actor": "analyst (layout button)"})
    ]


def test_credential_approve_requires_an_id_and_the_right_incident(monkeypatch):
    calls = _install(monkeypatch)
    assert button.guardian_button_approve_credential("", "CONFIRM")[0] is False
    ok, text = button.guardian_button_approve_credential("appr-other", "CONFIRM")
    assert ok is False and "belongs to incident 99999" in text
    assert _commands(calls) == []


def test_credential_approve_surfaces_the_command_error(monkeypatch):
    _install(monkeypatch, {"guardian-approve": [{"Type": 4, "Contents": "already resolved"}]})
    ok, text = button.guardian_button_approve_credential("appr-1", "CONFIRM")
    assert ok is False and "already resolved" in text


def test_main_success_and_failure(monkeypatch):
    _install(monkeypatch)
    csp = _run_main(monkeypatch, {"approval_id": "appr-1", "confirm": "CONFIRM"})
    button.main()
    assert "approved" in csp.RESULTS[0].readable_output
    _run_main(monkeypatch, {"approval_id": "appr-1", "confirm": "nope"})
    with pytest.raises(SystemExit) as exc_info:
        button.main()
    assert "Type CONFIRM exactly" in str(exc_info.value)
