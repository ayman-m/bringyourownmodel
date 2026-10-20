import json

import GuardianLayoutSocAgentMemory as layout


def _install(monkeypatch, contents=None, error=None):
    def fake_execute(command, args):
        assert command == "getList"
        assert args == {"listName": layout.GUARDIAN_MEMORY_LIST_NAME}
        if error:
            return [{"Type": 4, "Contents": error}]
        return [{"Type": 1, "Contents": json.dumps(contents)}]

    monkeypatch.setattr(layout.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(layout.demisto, "error", lambda _message: None)
    monkeypatch.setattr(layout.demisto, "info", lambda _message: None)


def test_memory_section_renders_bounded_metadata_without_values(monkeypatch):
    _install(
        monkeypatch,
        [
            {
                "key": "tech_stack:siem",
                "value": "Splunk is the SIEM; token=super-secret-value",
                "scope": "global",
                "tags": ["vendor", "logging"],
                "ttl": 3600,
                "updated_at": "2026-08-18T01:00:00Z",
                "hits": 4,
            }
        ],
    )

    text = layout.guardian_soc_agent_memory_run()

    assert "1 memory row(s)" in text
    assert "tech_stack:siem" in text
    assert "3600s" in text
    assert "super-secret-value" not in text
    assert "Stored values are intentionally not rendered" in text


def test_memory_section_handles_a_missing_runtime_list_without_creating_it(monkeypatch):
    _install(monkeypatch, error="Item not found (8) on list [guardian_memory]")

    text = layout.guardian_soc_agent_memory_run()

    assert "has not been initialized" in text
    assert "never creates it" in text


def test_memory_section_sorts_and_caps_rows(monkeypatch):
    rows = [
        {"key": "k{:02d}".format(index), "updated_at": "2026-08-18T00:{:02d}:00Z".format(index), "ttl": None}
        for index in range(30)
    ]
    _install(monkeypatch, rows)

    text = layout.guardian_soc_agent_memory_run()

    assert "Showing the 25 most recently updated" in text
    assert "`k29`" in text
    assert "`k00`" not in text


def test_memory_section_treats_nonpositive_ttl_as_permanent():
    assert layout.guardian_soc_memory_ttl({"ttl": 0}) == ("Permanent", False)
    assert layout.guardian_soc_memory_ttl({"ttl_seconds": 12}) == ("12s", True)


def test_memory_section_handles_unreadable_list(monkeypatch):
    _install(monkeypatch, error="connection refused")

    text = layout.guardian_soc_agent_memory_run()

    assert "Could not read" in text
    assert "connection refused" in text


# --- HTML rendering and main() -----------------------------------------------------------

HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(2)>"


def _no_tags(markup):
    for forbidden in ("<script", "<img", "<iframe", "<style", "onerror=alert(2)>"):
        assert forbidden not in markup


ROW = {
    "key": "tech_stack:siem",
    "value": "Splunk is the SIEM; token=super-secret-value",
    "scope": "global",
    "tags": ["vendor", "logging"],
    "ttl": 3600,
    "updated_at": "2026-08-18T01:00:00Z",
    "hits": 4,
}


def _ok(rows):
    return layout.guardian_envelope(True, data={"state": "ready", "rows": rows})


def test_html_shows_header_counts_badges_and_metadata_but_never_values():
    html = layout.guardian_soc_memory_render_html(_ok([ROW, dict(ROW, key="b", ttl=None)]))
    assert "SOC Agent memory" in html and "1 permanent" in html and "1 time-bound" in html
    assert "<b>Rows</b> 2" in html and "shared by every Guardian run" in html
    assert "<table" in html and "tech_stack:siem" in html and "global" in html and "vendor" in html and "logging" in html
    assert "3600s" in html and "2026-08-18 01:00:00" in html
    assert "super-secret-value" not in html and "Splunk is the SIEM" not in html
    assert "Metadata only" in html
    _no_tags(html)


def test_html_escapes_hostile_key_scope_tags_and_ttl_text():
    row = {"key": HOSTILE, "scope": HOSTILE, "tags": [HOSTILE, {"a": HOSTILE}], "ttl": HOSTILE, "updated_at": HOSTILE, "hits": HOSTILE}
    html = layout.guardian_soc_memory_render_html(_ok([row]))
    _no_tags(html)
    assert "&lt;script&gt;" in html
    _no_tags(layout.guardian_soc_memory_render_html(layout.guardian_envelope(False, error=HOSTILE)))


def test_html_redacts_secrets_in_visible_metadata():
    html = layout.guardian_soc_memory_render_html(_ok([dict(ROW, key="k password=hunter2", tags=["api_key=sk-abcdefghij123456"])]))
    assert "hunter2" not in html and "sk-abcdefghij123456" not in html


def test_html_empty_states_say_what_happens_next():
    html = layout.guardian_soc_memory_render_html(layout.guardian_envelope(True, data={"state": "not_initialized", "rows": []}))
    assert "Memory is not initialized" in html and "never creates it" in html
    html = layout.guardian_soc_memory_render_html(_ok([]))
    assert "No stored memories" in html and "across runs" in html
    html = layout.guardian_soc_memory_render_html(layout.guardian_envelope(False, error="connection refused"))
    assert "Memory unavailable" in html and "connection refused" in html


def test_html_sorts_caps_and_reports_skipped_rows():
    rows = [{"key": "k{:02d}".format(i), "updated_at": "2026-08-18T00:{:02d}:00Z".format(i), "ttl": None} for i in range(30)]
    html = layout.guardian_soc_memory_render_html(_ok(rows + ["junk"]))
    assert "Showing the 25 most recently updated" in html and "1 malformed row(s) omitted" in html
    assert ">k29</code>" in html and ">k00</code>" not in html


def test_main_returns_html(monkeypatch):
    _install(monkeypatch, [ROW])

    import CommonServerPython as csp

    csp.RESULTS.clear()
    layout.main()
    assert len(csp.RESULTS) == 1
    entry = csp.RESULTS[0]
    assert entry["Type"] == 1 and entry["ContentsFormat"] == "html" and "tech_stack:siem" in entry["Contents"]


def test_main_falls_back_to_markdown_when_the_html_builder_raises(monkeypatch):
    _install(monkeypatch, [ROW])

    def boom(*args, **kwargs):
        raise RuntimeError("html broke")

    monkeypatch.setattr(layout, "guardian_soc_memory_render_html", boom)

    import CommonServerPython as csp

    csp.RESULTS.clear()
    layout.main()
    assert len(csp.RESULTS) == 1
    assert "1 memory row(s)" in csp.RESULTS[0].readable_output
