import json

import GuardianSocAgentReadiness as readiness

if not hasattr(readiness.demisto, "getAllSupportedCommands"):
    readiness.demisto.getAllSupportedCommands = lambda: {}


def _install(monkeypatch, lists):
    def fake_execute(command, args):
        assert command == "getList"
        if args["listName"] not in lists:
            return [{"Type": 4, "Contents": "Item not found"}]
        return [{"Type": 1, "Contents": json.dumps(lists[args["listName"]])}]

    monkeypatch.setattr(readiness.demisto, "executeCommand", fake_execute)


def test_ready_when_policy_discovery_and_provider_command_are_present(monkeypatch):
    _install(monkeypatch, {
        "guardian_kill_switch": {"enabled": False},
        "guardian_tool_allowlist_runtime": {"commands": ["ip"]},
        "guardian_tool_available": {"refreshed_at": "now", "commands": [{"name": "ip"}]},
    })
    report = readiness.guardian_soc_agent_readiness(lambda: {"Guardian Vertex": [{"name": "guardian-llm-chat"}]})
    assert report["status"] == "Ready"


def test_paused_state_is_reported_without_becoming_a_failure(monkeypatch):
    _install(monkeypatch, {
        "guardian_kill_switch": {"enabled": True, "reason": "maintenance"},
        "guardian_tool_allowlist_runtime": {"commands": ["ip"]},
        "guardian_tool_available": {"commands": [{"name": "ip"}]},
    })
    report = readiness.guardian_soc_agent_readiness(lambda: {"Guardian Vertex": [{"name": "guardian-llm-chat"}]})
    assert report["status"] == "Paused"
    assert "maintenance" in readiness.guardian_soc_agent_readiness_render(report)


def test_missing_provider_command_is_degraded(monkeypatch):
    _install(monkeypatch, {
        "guardian_tool_allowlist_runtime": {"commands": ["ip"]},
        "guardian_tool_available": {"commands": [{"name": "ip"}]},
    })
    report = readiness.guardian_soc_agent_readiness(lambda: {"Other": [{"name": "ip"}]})
    assert report["status"] == "Degraded"


# --- main(): always the full report -- panel-only script, see module docstring
# and the button's own separate GuardianSocAgentReadinessCheck script -------


def test_main_always_returns_the_full_report(monkeypatch):
    readiness.RESULTS.clear()
    _install(monkeypatch, {
        "guardian_kill_switch": {"enabled": True, "reason": "maintenance"},
        "guardian_tool_allowlist_runtime": {"commands": ["ip"]},
        "guardian_tool_available": {"commands": [{"name": "ip"}]},
    })
    monkeypatch.setattr(readiness.demisto, "args", lambda: {})
    monkeypatch.setattr(readiness.demisto, "getAllSupportedCommands", lambda: {"Guardian Vertex": [{"name": "guardian-llm-chat"}]})
    readiness.main()
    assert len(readiness.RESULTS) == 1
    entry = readiness.RESULTS[0]
    assert entry["Type"] == 1 and entry["ContentsFormat"] == "html"
    assert "maintenance" in entry["Contents"] and "PAUSED" in entry["Contents"]
    assert entry["EntryContext"]["Guardian.SocAgent.Readiness"]["status"] == "Paused"  # same context output as before


def test_main_unexpected_exception_carries_no_manual_prefix(monkeypatch):
    import pytest

    monkeypatch.setattr(readiness.demisto, "args", lambda: {})

    def boom():
        raise RuntimeError("kaboom")

    monkeypatch.setattr(readiness, "guardian_soc_agent_readiness", boom)
    with pytest.raises(SystemExit) as exc_info:
        readiness.main()
    assert str(exc_info.value) == "kaboom"  # the panel query never renders an "<button>" wrapper anyway


# --- HTML rendering ----------------------------------------------------------------------

HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(2)>"


def _no_tags(markup):
    for forbidden in ("<script", "<img", "<iframe", "<style", "onerror=alert(2)>"):
        assert forbidden not in markup


def _report(status, *findings, selected=1):
    return {"status": status, "findings": list(findings), "selected_count": selected}


def test_html_ready_report_has_overall_badge_and_a_row_per_check():
    report = _report(
        "Ready",
        {"check": "Kill switch", "state": "Running", "detail": "No operator reason recorded"},
        {"check": "Provider command", "state": "Ready", "detail": "guardian-llm-chat is in configured command surface"},
    )
    html = readiness.guardian_soc_agent_readiness_render_html(report)
    assert "Agent readiness" in html and "background:#1f8a5b" in html and ">READY<" in html  # green overall badge
    assert html.count("background:#1f8a5b") == 3  # overall, Running (healthy) and Ready all green
    assert html.count("<tr>") == 3 and "Kill switch" in html and "Provider command" in html
    assert "<b>Checks</b> 2" in html and "<b>Allowed commands</b> 1" in html
    _no_tags(html)


def test_html_degraded_and_paused_states_get_a_next_step():
    report = _report(
        "Degraded",
        {"check": "Kill switch", "state": "Paused", "detail": "maintenance"},
        {"check": "Tool discovery", "state": "Needs refresh", "detail": "Item not found"},
        {"check": "Provider command", "state": "Degraded", "detail": "guardian-llm-chat is not in configured command surface"},
    )
    html = readiness.guardian_soc_agent_readiness_render_html(report)
    assert "background:#c0392b" in html  # red overall badge
    assert "Click Resume Agent" in html and "Click Refresh Tools" in html and "Enable exactly one Guardian model integration" in html
    assert "&lt;br&gt;" not in html and "<br>" in html  # the line break between detail and hint is real markup


def test_html_escapes_hostile_check_state_detail_and_status():
    report = _report(HOSTILE, {"check": HOSTILE, "state": HOSTILE, "detail": HOSTILE + " password=hunter2"})
    html = readiness.guardian_soc_agent_readiness_render_html(report)
    _no_tags(html)
    assert "hunter2" not in html and "&lt;script&gt;" in html


def test_html_with_no_findings_has_an_empty_state():
    html = readiness.guardian_soc_agent_readiness_render_html({})
    assert "No checks ran" in html


def test_html_matches_a_real_report(monkeypatch):
    _install(monkeypatch, {
        "guardian_kill_switch": {"enabled": True, "reason": "maintenance"},
        "guardian_tool_allowlist_runtime": {"commands": ["ip"]},
        "guardian_tool_available": {"commands": [{"name": "ip"}]},
    })
    report = readiness.guardian_soc_agent_readiness(lambda: {"Guardian Vertex": [{"name": "guardian-llm-chat"}]})
    html = readiness.guardian_soc_agent_readiness_render_html(report)
    assert "PAUSED" in html and "maintenance" in html and "Runtime allowlist" in html


def test_main_falls_back_to_the_markdown_result_with_the_same_context_when_html_raises(monkeypatch):
    readiness.RESULTS.clear()
    _install(monkeypatch, {
        "guardian_kill_switch": {"enabled": False},
        "guardian_tool_allowlist_runtime": {"commands": ["ip"]},
        "guardian_tool_available": {"commands": [{"name": "ip"}]},
    })
    monkeypatch.setattr(readiness.demisto, "args", lambda: {})
    monkeypatch.setattr(readiness.demisto, "getAllSupportedCommands", lambda: {"Guardian Vertex": [{"name": "guardian-llm-chat"}]})

    def boom(*args, **kwargs):
        raise RuntimeError("html broke")

    monkeypatch.setattr(readiness, "guardian_soc_agent_readiness_render_html", boom)
    readiness.main()
    assert len(readiness.RESULTS) == 1
    assert "Guardian Agent Readiness" in readiness.RESULTS[0].readable_output
    assert readiness.RESULTS[0].outputs["status"] == "Ready"
