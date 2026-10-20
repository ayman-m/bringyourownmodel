import json

import GuardianSocAgentExportConfiguration as export


def _install(monkeypatch, lists):
    def fake_execute(command, args):
        assert command == "getList"
        if args["listName"] not in lists:
            return [{"Type": 4, "Contents": "Item not found"}]
        return [{"Type": 1, "Contents": json.dumps(lists[args["listName"]])}]

    monkeypatch.setattr(export.demisto, "executeCommand", fake_execute)


def test_snapshot_contains_only_metadata_and_not_persona_text(monkeypatch):
    _install(monkeypatch, {
        "guardian_tool_allowlist_runtime": {"commands": ["ip"]},
        "guardian_tool_available": {"refreshed_at": "2026-08-19", "commands": [{"name": "ip"}]},
        "guardian_persona": {"persona": "Never render this wording"},
        "guardian_kill_switch": {"enabled": False, "ts": "2026-08-19"},
    })
    report = export.guardian_soc_agent_export_configuration()
    rendered = export.guardian_soc_agent_export_render(report)
    assert report["persona_configured"] is True
    assert report["allowed_command_count"] == 1
    assert "Never render this wording" not in rendered
    assert report["persona_fingerprint"]


def test_snapshot_falls_back_to_baseline_and_reports_missing_lists(monkeypatch):
    _install(monkeypatch, {"guardian_tool_allowlist": {"commands": ["ip"]}})
    report = export.guardian_soc_agent_export_configuration()
    assert report["allowlist_source"] == "guardian_tool_allowlist"
    assert "available_tools" in report["errors"]
