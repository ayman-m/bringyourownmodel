import json
from pathlib import Path

import GuardianSocAgentCreateInvestigation as create


REPO_ROOT = Path(__file__).resolve().parents[4]


def test_default_type_matches_a_real_shipped_incident_type():
    """DEFAULT_TYPE previously named an incident type ("Guardian Investigation")
    that was never actually shipped anywhere in the pack -- every real
    createNewIncident call with it either failed outright or silently fell
    back to an unbound default, never starting an investigation. Reads the
    REAL IncidentTypes/ directory from disk so a future edit can't silently
    reintroduce a type that doesn't exist."""
    incident_types_dir = REPO_ROOT / "Packs" / "Guardian" / "IncidentTypes"
    shipped_names = set()
    for path in incident_types_dir.glob("incidenttype-*.json"):
        shipped_names.add(json.loads(path.read_text())["name"])
    assert create.DEFAULT_TYPE in shipped_names


def test_requires_analyst_name_and_details():
    ok, result = create.guardian_soc_agent_create_investigation("", "details")
    assert ok is False
    assert "required" in result["error"]


def test_creates_investigation_and_audits_without_logging_details(monkeypatch):
    calls = []

    def fake_execute(command, args):
        calls.append((command, args))
        if command == "createNewIncident":
            return [{"Type": 1, "Contents": {"id": "123"}}]
        if command == "GuardianAuditWrite":
            return [{"Type": 1, "Contents": "Done"}]
        raise AssertionError(command)

    monkeypatch.setattr(create.demisto, "executeCommand", fake_execute)
    ok, result = create.guardian_soc_agent_create_investigation("Follow up", "sensitive operator details", "3")
    assert ok is True
    assert result["incident_id"] == "123"
    assert calls[0][1]["type"] == create.DEFAULT_TYPE
    assert calls[1][1]["detail"] == {"incident_type": create.DEFAULT_TYPE, "severity": 3}


def test_rejects_invalid_severity():
    ok, result = create.guardian_soc_agent_create_investigation("Follow up", "details", "9")
    assert ok is False
    assert "severity" in result["error"]
