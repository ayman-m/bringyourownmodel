import json

import GuardianSocAgentApplyToolPolicy as apply


def _install(monkeypatch, policy_text, available, runtime_exists=True):
    writes, audits = [], []

    def fake_execute(command, args):
        if command == "findIndicators":
            return [{"Type": 1, "Contents": [{"CustomFields": {"socagenttoolpolicy": policy_text}}]}]
        if command == "getList":
            name = args["listName"]
            if name == "guardian_tool_available":
                return [{"Type": 1, "Contents": json.dumps({"commands": [{"name": name} for name in available]})}]
            if name == "guardian_tool_allowlist_runtime" and runtime_exists:
                return [{"Type": 1, "Contents": json.dumps({"commands": ["old"]})}]
            return [{"Type": 4, "Contents": "Item not found"}]
        if command == "setList":
            writes.append(json.loads(args["listData"]))
            return [{"Type": 1, "Contents": "Done"}]
        if command == "GuardianAuditWrite":
            audits.append(args)
            return [{"Type": 1, "Contents": "Done"}]
        raise AssertionError("unexpected command {}".format(command))

    monkeypatch.setattr(apply.demisto, "executeCommand", fake_execute)
    return writes, audits


def test_applies_only_a_valid_available_policy(monkeypatch):
    writes, audits = _install(monkeypatch, '{"commands": ["ip", "domain"]}', ["ip", "domain"])
    ok, result = apply.guardian_soc_agent_apply_tool_policy("approved after review")
    assert ok is True
    assert writes == [{"commands": ["ip", "domain"]}]
    assert audits[0]["detail"]["reason"] == "approved after review"
    assert result["audited"] is True


def test_rejects_unavailable_policy_without_writing(monkeypatch):
    writes, _audits = _install(monkeypatch, '{"commands": ["not-live"]}', ["ip"])
    ok, result = apply.guardian_soc_agent_apply_tool_policy("reviewed")
    assert ok is False
    assert result["unavailable"] == ["not-live"]
    assert writes == []


def test_requires_reason_and_runtime_allowlist(monkeypatch):
    writes, _audits = _install(monkeypatch, '{"commands": ["ip"]}', ["ip"], runtime_exists=False)
    ok, result = apply.guardian_soc_agent_apply_tool_policy("")
    assert ok is False
    assert "reason" in result["error"]
    ok, result = apply.guardian_soc_agent_apply_tool_policy("reviewed")
    assert ok is False
    assert "refresh available tools" in result["error"]
    assert writes == []


# --- main() message shape ----------------------------------------------------


# Note: no manual '"Apply Policy" ...' text in any of these -- the layout UI
# itself wraps the toast with the button's own label (confirmed live via
# POST /indicator/execute/{id}); restating it here would double the sentence.


def test_main_success_is_a_short_plain_confirmation(monkeypatch):
    apply.RESULTS.clear()
    _install(monkeypatch, '{"commands": ["ip", "domain"]}', ["ip", "domain"])
    monkeypatch.setattr(apply.demisto, "args", lambda: {"reason": "approved after review"})
    apply.main()
    assert len(apply.RESULTS) == 1
    out = apply.RESULTS[0].readable_output
    assert out == "Applied 2 command(s)."  # non-empty: empty triggers the outputs-table fallback


def test_main_failure_matches_the_operators_own_example(monkeypatch):
    import pytest

    _install(monkeypatch, "", ["ip"])  # empty policy field -- the reported example
    monkeypatch.setattr(apply.demisto, "args", lambda: {"reason": "approved after review"})
    with pytest.raises(SystemExit) as exc_info:
        apply.main()
    assert str(exc_info.value) == (
        "Guardian Approved Tool Policy is empty; save JSON in the indicator field first"
    )


def test_main_success_with_failed_audit_still_reports_success_plus_a_warning(monkeypatch):
    apply.RESULTS.clear()
    _install(monkeypatch, '{"commands": ["ip"]}', ["ip"])
    real_execute = apply.demisto.executeCommand

    def wrapped(command, args):
        if command == "GuardianAuditWrite":
            return [{"Type": 4, "Contents": "audit list unwritable"}]
        return real_execute(command, args)

    monkeypatch.setattr(apply.demisto, "executeCommand", wrapped)
    monkeypatch.setattr(apply.demisto, "args", lambda: {"reason": "approved after review"})
    apply.main()
    assert apply.RESULTS[0].readable_output.startswith("Applied 1 command(s). Warning: audit log write failed")
