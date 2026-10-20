import json

import GuardianSocAgentCreateInvestigation as create


def _install(monkeypatch, search_rows, insert_reply=None, calls=None, insert_error=False):
    """Fake executeCommand: core-api-post for the insert and the search, GuardianAuditWrite for the audit."""
    calls = calls if calls is not None else []
    monkeypatch.setattr(create.time, "sleep", lambda _s: None)

    def fake_execute(command, args):
        calls.append((command, args))
        if command == "core-api-post":
            if args["uri"] == create.INSERT_URI:
                if insert_error:
                    return [{"Type": 4, "Contents": "boom"}]
                return [{"Type": 1, "Contents": {"response": insert_reply if insert_reply is not None else {"reply": True}}}]
            if args["uri"] == create.SEARCH_URI:
                return [{"Type": 1, "Contents": {"response": {"data": search_rows}}}]
        if command == "GuardianAuditWrite":
            return [{"Type": 1, "Contents": "Done"}]
        raise AssertionError(command)

    monkeypatch.setattr(create.demisto, "executeCommand", fake_execute)
    return calls


def _row(issue_id="191300"):
    return {"id": issue_id, "name": "Follow up", "created": "2999-01-01T00:00:00Z"}


def test_requires_analyst_name_and_details():
    ok, result = create.guardian_soc_agent_create_investigation("", "details")
    assert ok is False
    assert "required" in result["error"]


def test_rejects_invalid_severity():
    ok, result = create.guardian_soc_agent_create_investigation("Follow up", "details", "9")
    assert ok is False
    assert "severity" in result["error"]


def test_inserts_an_alert_finds_the_issue_and_audits_without_logging_details(monkeypatch):
    calls = _install(monkeypatch, [_row("191300")])
    ok, result = create.guardian_soc_agent_create_investigation("Follow up", "sensitive operator details", "3")
    assert ok is True
    assert result["incident_id"] == "191300"
    insert = json.loads(calls[0][1]["body"])["request_data"]["alerts"][0]
    assert calls[0][1]["uri"] == create.INSERT_URI
    assert insert["alert_name"] == "Follow up"
    assert insert["severity"] == "High"
    assert all(isinstance(insert[k], int) and 0 < insert[k] <= 65535 for k in ("local_port", "remote_port"))
    audit = [args for command, args in calls if command == "GuardianAuditWrite"][0]
    assert "sensitive operator details" not in json.dumps(audit)
    assert audit["target"] == "191300"


def test_severity_maps_to_the_four_alert_levels(monkeypatch):
    seen = {}
    for given, expected in (("0", "Low"), ("1", "Low"), ("2", "Medium"), ("4", "Critical")):
        calls = _install(monkeypatch, [_row()])
        create.guardian_soc_agent_create_investigation("Follow up", "details", given)
        seen[given] = json.loads(calls[0][1]["body"])["request_data"]["alerts"][0]["severity"]
        assert seen[given] == expected


def test_a_rejected_insert_is_a_failure(monkeypatch):
    _install(monkeypatch, [], insert_error=True)
    ok, result = create.guardian_soc_agent_create_investigation("Follow up", "details", "1")
    assert ok is False
    assert "alert insert failed" in result["error"]


def test_an_insert_without_reply_true_is_a_failure(monkeypatch):
    _install(monkeypatch, [], insert_reply={"reply": False})
    ok, result = create.guardian_soc_agent_create_investigation("Follow up", "details", "1")
    assert ok is False
    assert "not accepted" in result["error"]


def test_an_issue_that_is_not_visible_yet_is_still_a_success_without_an_id(monkeypatch):
    calls = _install(monkeypatch, [])
    ok, result = create.guardian_soc_agent_create_investigation("Follow up", "details", "1")
    assert ok is True
    assert result["incident_id"] is None
    assert len([c for c in calls if c[1].get("uri") == create.SEARCH_URI]) == create.LOOKUP_ATTEMPTS


def test_an_older_issue_with_the_same_name_is_not_picked_up(monkeypatch):
    _install(monkeypatch, [{"id": "100", "name": "Follow up", "created": "2020-01-01T00:00:00Z"}])
    ok, result = create.guardian_soc_agent_create_investigation("Follow up", "details", "1")
    assert ok is True
    assert result["incident_id"] is None
