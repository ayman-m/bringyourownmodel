import json

import pytest

import GuardianButtonDeny as button

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


def test_deny_calls_only_guardian_deny_with_the_reason(monkeypatch):
    calls = _install(monkeypatch)
    ok, text = button.guardian_button_deny("appr-1", "  not during the maintenance window ")
    assert ok is True and "denied" in text and "Nothing runs" in text
    assert _commands(calls) == [
        ("guardian-deny", {"approval_id": "appr-1", "reason": "not during the maintenance window", "actor": "analyst (layout button)"})
    ]


def test_deny_requires_both_an_id_and_a_reason(monkeypatch):
    calls = _install(monkeypatch)
    assert "approval_id is required" in button.guardian_button_deny("", "why")[1]
    assert "reason is required" in button.guardian_button_deny("appr-1", "  ")[1]
    assert button.guardian_button_deny("appr-1", None)[0] is False
    assert calls == []


def test_deny_refuses_another_incidents_approval(monkeypatch):
    calls = _install(monkeypatch)
    ok, text = button.guardian_button_deny("appr-other", "no")
    assert ok is False and "belongs to incident 99999" in text and _commands(calls) == []


def test_deny_surfaces_the_command_error_and_caps_the_reason(monkeypatch):
    _install(monkeypatch, {"guardian-deny": [{"Type": 4, "Contents": "not found"}]})
    assert button.guardian_button_deny("appr-1", "no") == (False, "not found")
    calls = _install(monkeypatch)
    button.guardian_button_deny("appr-1", "r" * 9000)
    assert len(_commands(calls)[0][1]["reason"]) == button.GUARDIAN_BUTTON_MAX_TEXT_CHARS


def test_main_success_and_failure(monkeypatch):
    _install(monkeypatch)
    csp = _run_main(monkeypatch, {"approval_id": "appr-1", "reason": "no"})
    button.main()
    assert "denied" in csp.RESULTS[0].readable_output
    _run_main(monkeypatch, {"approval_id": "appr-1", "reason": ""})
    with pytest.raises(SystemExit):
        button.main()
