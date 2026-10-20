import json

import GuardianSocAgentValidateToolPolicy as policy


def _install(monkeypatch, lists):
    def fake_execute(command, args):
        assert command == "getList"
        if args["listName"] not in lists:
            return [{"Type": 4, "Contents": "Item not found"}]
        return [{"Type": 1, "Contents": json.dumps(lists[args["listName"]])}]

    monkeypatch.setattr(policy.demisto, "executeCommand", fake_execute)


def test_validates_a_clean_runtime_policy(monkeypatch):
    _install(monkeypatch, {
        "guardian_tool_allowlist_runtime": {"commands": ["ip", "domain"]},
        "guardian_tool_available": {"refreshed_at": "2026-08-19T00:00:00Z", "commands": [{"name": "ip"}, {"name": "domain"}]},
    })
    report = policy.guardian_soc_agent_validate_policy()
    assert report["valid"] is True
    assert report["source"] == "guardian_tool_allowlist_runtime"


def test_reports_duplicates_and_commands_missing_from_snapshot(monkeypatch):
    _install(monkeypatch, {
        "guardian_tool_allowlist_runtime": {"commands": ["ip", "ip", "not-live", 7]},
        "guardian_tool_available": {"commands": [{"name": "ip"}]},
    })
    report = policy.guardian_soc_agent_validate_policy()
    assert report["valid"] is False
    assert report["duplicates"] == ["ip"]
    assert report["unavailable"] == ["not-live"]
    assert report["invalid"] == ["7"]


def test_uses_pack_baseline_only_before_runtime_list_exists(monkeypatch):
    _install(monkeypatch, {
        "guardian_tool_allowlist": {"commands": ["ip"]},
        "guardian_tool_available": {"commands": [{"name": "ip"}]},
    })
    report = policy.guardian_soc_agent_validate_policy()
    assert report["valid"] is True
    assert report["source"] == "guardian_tool_allowlist"


# --- main() message shape ----------------------------------------------------


# Note: no manual '"Validate Tools" ...' prefix in any of these -- the layout
# UI itself wraps the toast with the button's own label (confirmed live via
# POST /indicator/execute/{id}); restating it here would double the sentence.


def test_main_valid_policy_is_a_short_plain_confirmation(monkeypatch):
    policy.RESULTS.clear()
    _install(monkeypatch, {
        "guardian_tool_allowlist_runtime": {"commands": ["ip", "domain"]},
        "guardian_tool_available": {"refreshed_at": "now", "commands": [{"name": "ip"}, {"name": "domain"}]},
    })
    policy.main()
    assert len(policy.RESULTS) == 1
    out = policy.RESULTS[0].readable_output
    assert out  # non-empty: empty triggers XSOAR's own outputs-table fallback
    assert not out.startswith('"')
    assert "###" not in out and "**" not in out


def test_main_invalid_policy_fails_with_a_plain_actionable_reason(monkeypatch):
    import pytest

    _install(monkeypatch, {
        "guardian_tool_allowlist_runtime": {"commands": ["ip", "ip", "not-live"]},
        "guardian_tool_available": {"commands": [{"name": "ip"}]},
    })
    with pytest.raises(SystemExit) as exc_info:
        policy.main()
    message = str(exc_info.value)
    assert message.startswith("Policy needs review: ")
    assert "not-live" in message
    assert "ip" in message
    assert "###" not in message and "**" not in message  # plain text, not markdown


def test_main_load_error_is_a_real_failure_not_a_review_finding(monkeypatch):
    import pytest

    _install(monkeypatch, {})  # neither allowlist exists
    with pytest.raises(SystemExit) as exc_info:
        policy.main()
    assert not str(exc_info.value).startswith('"')
