import json

import GuardianLayoutSocAgentPersona as layout


def _install(monkeypatch, contents=None, error=None):
    def fake_execute(command, args):
        assert command == "getList"
        assert args == {"listName": layout.GUARDIAN_PERSONA_LIST_NAME}
        if error:
            return [{"Type": 4, "Contents": error}]
        return [{"Type": 1, "Contents": json.dumps(contents)}]

    monkeypatch.setattr(layout.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(layout.demisto, "error", lambda _message: None)
    monkeypatch.setattr(layout.demisto, "info", lambda _message: None)


def test_persona_section_renders_the_active_persona(monkeypatch):
    _install(monkeypatch, {"persona": "Be a terse SOC analyst."})

    text = layout.guardian_soc_agent_persona_run()

    assert "SOC Agent Persona" in text
    assert "Be a terse SOC analyst." in text
    assert "GuardianPromptBuilder" in text
    assert "```text" in text


def test_persona_section_handles_an_empty_persona(monkeypatch):
    _install(monkeypatch, {"persona": "  "})

    text = layout.guardian_soc_agent_persona_run()

    assert "does not currently include" in text


def test_persona_section_handles_read_errors_without_raising(monkeypatch):
    _install(monkeypatch, error="Item not found (8) on list [guardian_persona]")

    text = layout.guardian_soc_agent_persona_run()

    assert "Could not read" in text
    assert "guardian_persona" in text


def test_persona_section_caps_and_fences_untrusted_markdown(monkeypatch):
    _install(monkeypatch, {"persona": "```" + ("x" * 7000)})

    text = layout.guardian_soc_agent_persona_run()

    assert "Display is capped" in text
    assert "```" not in text.replace("```text", "").replace("\n```", "")


# --- HTML rendering and main() -----------------------------------------------------------

HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(2)>"


def _no_tags(markup):
    for forbidden in ("<script", "<img", "<iframe", "<style", "onerror=alert(2)>"):
        assert forbidden not in markup


def _ok(persona):
    return layout.guardian_envelope(True, data={"persona": persona})


def test_html_shows_the_persona_with_line_breaks_and_a_note():
    html = layout.guardian_soc_persona_render_html(_ok("Be a terse SOC analyst.\nCite evidence."))
    assert "SOC Agent persona" in html and "read on every tick" in html
    assert "Be a terse SOC analyst.<br>Cite evidence." in html
    assert "<b>Characters</b> 38" in html and "guardian_persona" in html
    assert "cannot override Guardian" in html
    _no_tags(html)


def test_html_escapes_a_hostile_persona_and_error():
    _no_tags(layout.guardian_soc_persona_render_html(_ok(HOSTILE + "\n```code```")))
    html = layout.guardian_soc_persona_render_html(layout.guardian_envelope(False, error=HOSTILE + " token=abc123def456"))
    _no_tags(html)
    assert "Persona unavailable" in html and "abc123def456" not in html


def test_html_scrubs_secrets_and_caps_length():
    html = layout.guardian_soc_persona_render_html(_ok("password=hunter2 " + "x" * 7000))
    assert "hunter2" not in html and "Display is capped" in html and html.count("x") < 7000


def test_html_empty_persona_says_what_happens_next():
    html = layout.guardian_soc_persona_render_html(_ok("  "))
    assert "No operator persona is set" in html and "leaves its persona block out" in html


def test_main_returns_html(monkeypatch):
    _install(monkeypatch, {"persona": "Be a terse SOC analyst."})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    layout.main()
    assert len(csp.RESULTS) == 1
    entry = csp.RESULTS[0]
    assert entry["Type"] == 1 and entry["ContentsFormat"] == "html" and "Be a terse SOC analyst." in entry["Contents"]


def test_main_falls_back_to_markdown_when_the_html_builder_raises(monkeypatch):
    _install(monkeypatch, {"persona": "Be a terse SOC analyst."})

    def boom(*args, **kwargs):
        raise RuntimeError("html broke")

    monkeypatch.setattr(layout, "guardian_soc_persona_render_html", boom)

    import CommonServerPython as csp

    csp.RESULTS.clear()
    layout.main()
    assert len(csp.RESULTS) == 1
    assert "```text" in csp.RESULTS[0].readable_output
