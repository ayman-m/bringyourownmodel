import json

import GuardianLayoutSocAgentTools as layout


def _install(monkeypatch, lists):
    def fake_execute(command, args):
        assert command == "getList"
        name = args["listName"]
        if name not in lists:
            return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(name)}]
        return [{"Type": 1, "Contents": json.dumps(lists[name])}]

    monkeypatch.setattr(layout.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(layout.demisto, "error", lambda _message: None)
    monkeypatch.setattr(layout.demisto, "info", lambda _message: None)


def test_dynamic_section_renders_effective_selection_and_sources(monkeypatch):
    _install(
        monkeypatch,
        {
            "guardian_tool_allowlist_runtime": {"commands": ["ip", "splunk-search", "not-live"]},
            "guardian_tool_available": {
                "refreshed_at": "2026-08-18T00:00:00Z",
                "total_instances": 2,
                "commands": [
                    {"name": "ip", "instances": ["IPInfo"]},
                    {"name": "splunk-search", "instances": ["Splunk"]},
                ],
            },
        },
    )

    text = layout.guardian_soc_agent_tools_run()

    assert "runtime operator selection" in text
    assert "`ip` | Available | `IPInfo`" in text
    assert "`not-live` | **Not on latest snapshot**" in text
    assert "Available commands by configured instance" in text
    assert "Settings → Advanced → Lists" in text


def test_dynamic_section_uses_baseline_before_runtime_list_exists(monkeypatch):
    _install(
        monkeypatch,
        {
            "guardian_tool_allowlist": {"commands": ["ip"]},
            "guardian_tool_available": {"commands": [{"name": "ip", "instances": ["IPInfo"]}]},
        },
    )

    text = layout.guardian_soc_agent_tools_run()

    assert "pack baseline fallback" in text
    assert "guardian_tool_allowlist`" in text


def test_dynamic_section_explains_how_to_refresh_when_snapshot_is_absent(monkeypatch):
    _install(monkeypatch, {"guardian_tool_allowlist_runtime": {"commands": ["ip"]}})

    text = layout.guardian_soc_agent_tools_run()

    assert "No valid snapshot yet" in text
    assert "GuardianToolRegistryRefresh" in text


# --- HTML rendering and main() -----------------------------------------------------------

HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(2)>"


def _no_tags(markup):
    for forbidden in ("<script", "<img", "<iframe", "<style", "onerror=alert(2)>"):
        assert forbidden not in markup


LISTS = {
    "guardian_tool_allowlist_runtime": {"commands": ["ip", "splunk-search", "not-live"]},
    "guardian_tool_available": {
        "refreshed_at": "2026-08-18T00:00:00Z",
        "total_instances": 2,
        "commands": [
            {"name": "ip", "instances": ["IPInfo"]},
            {"name": "splunk-search", "instances": ["Splunk", "SplunkBackup"]},
        ],
    },
}


def _load(monkeypatch, lists):
    _install(monkeypatch, lists)
    return layout.guardian_soc_agent_tools_load()


def test_html_shows_header_allowed_table_availability_and_instances(monkeypatch):
    allowlist, snapshot = _load(monkeypatch, LISTS)
    html = layout.guardian_soc_agent_render_html(allowlist, snapshot)
    assert "Tool registry" in html and "3 allowed" in html and "runtime selection" in html
    assert "<b>Available commands</b> 2" in html and "<b>Instances</b> 2" in html and "2026-08-18 00:00:00" in html
    assert "<table" in html and "Allowed command" in html
    assert "not on latest snapshot" in html and "available" in html
    assert ">ip</code>" in html
    assert "IPInfo" in html and "SplunkBackup" in html and "Available commands by configured instance" in html
    assert "Settings &gt; Advanced &gt; Lists" in html
    _no_tags(html)


def test_html_baseline_fallback_is_flagged(monkeypatch):
    allowlist, snapshot = _load(
        monkeypatch,
        {"guardian_tool_allowlist": {"commands": ["ip"]}, "guardian_tool_available": {"commands": [{"name": "ip", "instances": ["IPInfo"]}]}},
    )
    html = layout.guardian_soc_agent_render_html(allowlist, snapshot)
    assert "pack baseline" in html and "Click Refresh Tools once" in html


def test_html_without_snapshot_tells_the_operator_what_to_click(monkeypatch):
    allowlist, snapshot = _load(monkeypatch, {"guardian_tool_allowlist_runtime": {"commands": ["ip"]}})
    html = layout.guardian_soc_agent_render_html(allowlist, snapshot)
    assert "No tool snapshot yet" in html and "Refresh Tools button" in html


def test_html_unreadable_allowlist_and_bad_snapshot_are_cards_not_errors(monkeypatch):
    allowlist, snapshot = _load(monkeypatch, {"guardian_tool_available": {"commands": "nope"}})
    html = layout.guardian_soc_agent_render_html(allowlist, snapshot)
    assert "Allowed tools unavailable" in html or "Available tools unavailable" in html


def test_html_empty_allowlist_has_a_hint(monkeypatch):
    allowlist, snapshot = _load(
        monkeypatch,
        {"guardian_tool_allowlist_runtime": {"commands": []}, "guardian_tool_available": {"commands": [{"name": "ip", "instances": ["A"]}]}},
    )
    assert "No commands are allowed" in layout.guardian_soc_agent_render_html(allowlist, snapshot)


def test_html_escapes_hostile_command_instance_and_error_text(monkeypatch):
    lists = {
        "guardian_tool_allowlist_runtime": {"commands": [HOSTILE]},
        "guardian_tool_available": {"refreshed_at": HOSTILE, "total_instances": HOSTILE, "commands": [{"name": HOSTILE, "instances": [HOSTILE]}]},
    }
    html = layout.guardian_soc_agent_render_html(*_load(monkeypatch, lists))
    _no_tags(html)
    assert "&lt;script&gt;" in html
    broken = layout.guardian_soc_agent_render_html(
        {"ok": False, "error": HOSTILE}, {"ok": False, "error": HOSTILE}
    )
    _no_tags(broken)


def test_html_caps_commands_per_instance(monkeypatch):
    monkeypatch.setattr(layout, "GUARDIAN_TOOLS_HTML_MAX_COMMANDS_PER_INSTANCE", 2)
    lists = {
        "guardian_tool_allowlist_runtime": {"commands": []},
        "guardian_tool_available": {"commands": [{"name": "c{}".format(i), "instances": ["A"]} for i in range(5)]},
    }
    html = layout.guardian_soc_agent_render_html(*_load(monkeypatch, lists))
    assert "(+3 more)" in html


def test_main_returns_html_and_reads_each_list_once(monkeypatch):
    _install(monkeypatch, LISTS)
    reads = []
    original = layout.demisto.executeCommand
    monkeypatch.setattr(layout.demisto, "executeCommand", lambda c, a: reads.append(a["listName"]) or original(c, a))

    import CommonServerPython as csp

    csp.RESULTS.clear()
    layout.main()
    assert len(csp.RESULTS) == 1
    entry = csp.RESULTS[0]
    assert entry["Type"] == 1 and entry["ContentsFormat"] == "html" and "Tool registry" in entry["Contents"]
    assert sorted(reads) == ["guardian_tool_allowlist_runtime", "guardian_tool_available"]


def test_main_falls_back_to_markdown_when_the_html_builder_raises(monkeypatch):
    _install(monkeypatch, LISTS)

    def boom(*args, **kwargs):
        raise RuntimeError("html broke")

    monkeypatch.setattr(layout, "guardian_soc_agent_render_html", boom)

    import CommonServerPython as csp

    csp.RESULTS.clear()
    layout.main()
    assert len(csp.RESULTS) == 1
    assert "runtime operator selection" in csp.RESULTS[0].readable_output
