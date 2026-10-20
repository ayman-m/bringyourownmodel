import json

import GuardianLayoutTrace as glt


# --- fixtures -----------------------------------------------------------------


def _tool_call(call_id, name, arguments):
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments}}


def _tool_message(call_id, content_obj):
    return {"role": "tool", "tool_call_id": call_id, "content": json.dumps(content_obj)}


SAMPLE_LOOP = {
    "status": "done",
    "tick": 2,
    "cost_usd": 0.024606,
    "cost_tokens_total": 148998,
    "messages": [
        {"role": "system", "content": "You are the Guardian Agent."},
        {"role": "user", "content": "<untrusted-case-data>\nInvestigate.\n</untrusted-case-data>"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [_tool_call("call_0", "GuardianSkillRead", json.dumps({"name": "xsoar_case_triage"}))],
        },
        _tool_message("call_0", {"ok": True, "status": "ok", "error": None, "result": {"body": "..."}}),
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [_tool_call("call_0", "SearchIncidentsV2", json.dumps({"status": ["1"]}))],
        },
        _tool_message("call_0", {"ok": False, "status": "error", "error": "boom", "result": None}),
        {"role": "assistant", "content": "I found nothing urgent to triage.", "tool_calls": []},
    ],
}


# --- guardian_trace_format_args -------------------------------------------------


def test_format_args_dict_json_string():
    rendered = glt.guardian_trace_format_args(json.dumps({"name": "xsoar_case_triage"}))
    assert rendered == "name=xsoar_case_triage"


def test_format_args_multiple_keys():
    rendered = glt.guardian_trace_format_args(json.dumps({"status": ["1"], "limit": "10"}))
    assert "status=" in rendered and "limit=10" in rendered


def test_format_args_none():
    assert glt.guardian_trace_format_args(None) == ""


def test_format_args_malformed_json_falls_back_to_raw_text():
    rendered = glt.guardian_trace_format_args("not json{{{")
    assert rendered == "not json{{{"


def test_format_args_caps_length():
    long_value = "x" * 500
    rendered = glt.guardian_trace_format_args(json.dumps({"k": long_value}))
    assert len(rendered) <= glt.GUARDIAN_TRACE_MAX_ARGS_CHARS
    assert rendered.endswith("…")


# --- guardian_trace_summarize_tool_result --------------------------------------


def test_summarize_tool_result_ok():
    summary = glt.guardian_trace_summarize_tool_result(json.dumps({"ok": True, "status": "ok"}))
    assert summary == "**ok**"


def test_summarize_tool_result_error_includes_message():
    summary = glt.guardian_trace_summarize_tool_result(json.dumps({"ok": False, "status": "error", "error": "boom"}))
    assert summary == "**error** — boom"


def test_summarize_tool_result_none_content():
    assert glt.guardian_trace_summarize_tool_result(None) == "(no result)"


def test_summarize_tool_result_malformed_json_falls_back_to_raw_preview():
    summary = glt.guardian_trace_summarize_tool_result("not valid json")
    assert summary == "not valid json"


def test_summarize_tool_result_caps_error_length():
    long_error = "e" * 500
    summary = glt.guardian_trace_summarize_tool_result(json.dumps({"ok": False, "error": long_error}))
    assert len(summary) < 500
    assert summary.endswith("…")


# --- guardian_trace_format_tool_call -------------------------------------------


def test_format_tool_call_happy_path():
    tool_call = _tool_call("call_0", "ip", json.dumps({"ip": "8.8.8.8"}))
    replies = {"call_0": json.dumps({"ok": True, "status": "ok"})}
    line = glt.guardian_trace_format_tool_call(tool_call, replies)
    assert line == "- `ip(ip=8.8.8.8)` → **ok**"


def test_format_tool_call_malformed_no_function():
    line = glt.guardian_trace_format_tool_call({"id": "call_0"}, {})
    assert line == "- `(malformed tool call)`"


def test_format_tool_call_not_a_dict():
    line = glt.guardian_trace_format_tool_call("not a dict", {})
    assert line == "- `(malformed tool call)`"


def test_format_tool_call_no_matching_reply():
    tool_call = _tool_call("call_0", "ip", json.dumps({"ip": "8.8.8.8"}))
    line = glt.guardian_trace_format_tool_call(tool_call, {})
    assert "(no result)" in line


# --- guardian_trace_build_header ------------------------------------------------


def test_build_header_full():
    header = glt.guardian_trace_build_header(SAMPLE_LOOP, "Benign")
    assert "**Status:** done" in header
    assert "**Tick:** 2" in header
    assert "**Cost:** $0.0246 (148998 tokens)" in header
    assert "**Verdict:** Benign" in header


def test_build_header_no_verdict_yet():
    header = glt.guardian_trace_build_header({}, None)
    assert "**Verdict:** _pending_" in header


def test_build_header_cost_without_tokens():
    header = glt.guardian_trace_build_header({"cost_usd": 1.5}, None)
    assert "**Cost:** $1.5000" in header


# --- guardian_trace_render (full render / empty-incident gracefulness) --------


def test_render_empty_incident_and_loop_is_graceful():
    markdown = glt.guardian_trace_render({}, {})
    assert "Guardian Reasoning Trace" in markdown
    assert "No reasoning trace yet" in markdown
    assert "_pending_" in markdown


def test_render_none_incident_and_loop_never_crashes():
    markdown = glt.guardian_trace_render(None, None)
    assert "No reasoning trace yet" in markdown


def test_render_loop_present_but_messages_missing():
    markdown = glt.guardian_trace_render({}, {"status": "running", "tick": 0})
    assert "**Status:** running" in markdown
    assert "No reasoning trace yet" in markdown


def test_render_full_transcript_shows_turns_and_tool_outcomes():
    incident = {"CustomFields": {"guardianverdict": None}}
    markdown = glt.guardian_trace_render(incident, SAMPLE_LOOP)
    assert "**Turn 1**" in markdown
    assert "GuardianSkillRead" in markdown
    assert "**ok**" in markdown
    assert "**Turn 2**" in markdown
    assert "**error** — boom" in markdown
    assert "**Turn 3**" in markdown
    assert "I found nothing urgent to triage." in markdown


def test_render_includes_verdict_from_custom_fields():
    incident = {"CustomFields": {"guardianverdict": "Malicious"}}
    markdown = glt.guardian_trace_render(incident, SAMPLE_LOOP)
    assert "**Verdict:** Malicious" in markdown


def test_render_skips_system_and_user_messages_as_turns():
    markdown = glt.guardian_trace_render({}, SAMPLE_LOOP)
    assert "**Turn 1**" in markdown
    # exactly 3 assistant turns in the fixture -- no phantom Turn 4.
    assert "**Turn 4**" not in markdown


def test_render_caps_turns_to_most_recent_n(monkeypatch):
    monkeypatch.setattr(glt, "GUARDIAN_TRACE_MAX_TURNS", 2)
    markdown = glt.guardian_trace_render({}, SAMPLE_LOOP)
    assert "1 earlier turn(s) not shown" in markdown
    assert "**Turn 1**" not in markdown
    assert "**Turn 3**" in markdown


def test_render_never_crashes_on_malformed_messages_entries():
    loop = {"status": "running", "messages": ["not a dict", {"role": "assistant", "content": "ok"}, 42]}
    markdown = glt.guardian_trace_render({}, loop)
    assert "**Turn 1**" in markdown


def test_render_no_assistant_turns_but_messages_present():
    loop = {"status": "running", "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "u"}]}
    markdown = glt.guardian_trace_render({}, loop)
    assert "No assistant turns recorded yet" in markdown


# --- HTML rendering ----------------------------------------------------------------------


HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(2)>"


def _no_tags(markup):
    for forbidden in ("<script", "<img", "<iframe", "<style", "onerror=alert(2)>"):
        assert forbidden not in markup


def test_result_parts_ok_error_and_odd_shapes():
    assert glt.guardian_trace_result_parts(json.dumps({"ok": True, "status": "ok"})) == ("ok", "")
    assert glt.guardian_trace_result_parts(json.dumps({"ok": False, "status": "error", "error": "boom"})) == ("error", "boom")
    assert glt.guardian_trace_result_parts(json.dumps({"ok": False})) == ("error", "")
    assert glt.guardian_trace_result_parts(None) == ("no result", "")
    assert glt.guardian_trace_result_parts("not json") == ("result", "not json")
    label, detail = glt.guardian_trace_result_parts(json.dumps({"status": "error", "error": "e" * 900}))
    assert len(detail) <= glt.GUARDIAN_TRACE_MAX_RESULT_CHARS
    assert "hunter2" not in glt.guardian_trace_result_parts(json.dumps({"error": "password=hunter2"}))[1]


def test_html_render_full_transcript_has_header_timeline_and_outcome_badges():
    incident = {"CustomFields": {"guardianverdict": "Benign"}}
    html = glt.guardian_trace_render_html(incident, SAMPLE_LOOP)
    assert "Reasoning trace" in html and "DONE" in html
    assert "<b>Tick</b> 2" in html and "$0.0246 (148,998 tokens)" in html and "<b>Verdict</b> Benign" in html
    assert "Turn 1 - 1 tool call(s)" in html and "Turn 2 - 1 tool call(s)" in html and "Turn 3 - conclusion" in html
    assert "GuardianSkillRead" in html and "name=xsoar_case_triage" in html
    assert "#1f8a5b" in html and "#c0392b" in html and "boom" in html  # ok badge, error badge and message
    assert "I found nothing urgent to triage." in html
    _no_tags(html)


def test_html_render_no_verdict_yet_says_pending():
    assert "<b>Verdict</b> pending" in glt.guardian_trace_render_html({}, {})


def test_html_render_empty_states_say_what_happens_next():
    html = glt.guardian_trace_render_html(None, None)
    assert "No reasoning trace yet" in html and "first model call" in html
    html = glt.guardian_trace_render_html({}, {"status": "running", "messages": [{"role": "system", "content": "s"}]})
    assert "No assistant turns recorded yet" in html


def test_html_render_escapes_hostile_reasoning_args_results_and_verdict():
    loop = {
        "status": HOSTILE,
        "tick": HOSTILE,
        "cost_usd": 0.1,
        "messages": [
            {"role": "assistant", "content": HOSTILE, "tool_calls": [_tool_call("c1", HOSTILE, json.dumps({"k": HOSTILE}))]},
            _tool_message("c1", {"ok": False, "status": HOSTILE, "error": HOSTILE}),
        ],
    }
    html = glt.guardian_trace_render_html({"CustomFields": {"guardianverdict": HOSTILE}}, loop)
    _no_tags(html)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_html_render_scrubs_secrets_in_args_and_reasoning():
    loop = {
        "messages": [
            {"role": "assistant", "content": "using password=hunter2", "tool_calls": [_tool_call("c", "x", json.dumps({"q": "api_key=sk-abcdefghij123456"}))]}
        ]
    }
    html = glt.guardian_trace_render_html({}, loop)
    assert "hunter2" not in html and "sk-abcdefghij123456" not in html


def test_html_render_caps_turns_and_notes_it(monkeypatch):
    monkeypatch.setattr(glt, "GUARDIAN_TRACE_MAX_TURNS", 2)
    html = glt.guardian_trace_render_html({}, SAMPLE_LOOP)
    assert "1 earlier turn(s) not shown" in html and "Turn 1 -" not in html and "Turn 3 -" in html


def test_html_render_survives_malformed_entries():
    loop = {
        "status": "running",
        "messages": [
            "junk",
            {"role": "assistant", "content": None, "tool_calls": [{"id": "x"}, "bad"]},
            {"role": "assistant", "content": None},
            42,
        ],
    }
    html = glt.guardian_trace_render_html({}, loop)
    assert "(malformed tool call)" in html and "no reasoning text and no tool calls" in html


def test_assistant_turns_group_replies_with_the_turn_they_follow():
    turns = glt.guardian_trace_assistant_turns(SAMPLE_LOOP["messages"])
    assert [turn[0] for turn in turns] == [1, 2, 3]
    assert "call_0" in turns[0][2] and turns[2][2] == {}


# --- main(): entry-point smoke tests --------------------------------------------


def test_main_empty_playground_context_is_graceful(monkeypatch):
    monkeypatch.setattr(glt.demisto, "incident", lambda: {})
    monkeypatch.setattr(glt.demisto, "context", lambda: {})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    glt.main()

    assert len(csp.RESULTS) == 1
    entry = csp.RESULTS[0]
    assert entry["Type"] == 1 and entry["ContentsFormat"] == "html"
    assert "No reasoning trace yet" in entry["Contents"]


def test_main_real_incident_returns_the_html_timeline(monkeypatch):
    monkeypatch.setattr(glt.demisto, "incident", lambda: {"id": "22486", "CustomFields": {}})
    monkeypatch.setattr(glt.demisto, "context", lambda: {"Guardian": {"Loop": SAMPLE_LOOP}})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    glt.main()

    assert len(csp.RESULTS) == 1
    entry = csp.RESULTS[0]
    assert entry["ContentsFormat"] == "html"
    assert "Turn 1" in entry["Contents"] and "DONE" in entry["Contents"]


def test_main_falls_back_to_markdown_when_the_html_builder_raises(monkeypatch):
    monkeypatch.setattr(glt.demisto, "incident", lambda: {"id": "22486", "CustomFields": {}})
    monkeypatch.setattr(glt.demisto, "context", lambda: {"Guardian": {"Loop": SAMPLE_LOOP}})

    def boom(*args, **kwargs):
        raise RuntimeError("html broke")

    monkeypatch.setattr(glt, "guardian_trace_render_html", boom)

    import CommonServerPython as csp

    csp.RESULTS.clear()
    glt.main()

    assert len(csp.RESULTS) == 1
    readable = csp.RESULTS[0].readable_output
    assert "**Turn 1**" in readable and "**Status:** done" in readable


# --- the verdict falls back to the one the loop recorded when the issue field is empty -----------------------


def test_trace_falls_back_to_the_loop_verdict_when_the_field_is_empty():
    loop = dict(SAMPLE_LOOP, verdict={"verdict": "Suspicious", "confidence": 65, "techniques": ["T1059"]})
    incident = {"CustomFields": {}}
    assert "**Verdict:** Suspicious (65)" in glt.guardian_trace_render(incident, loop)
    assert "<b>Verdict</b> Suspicious (65)" in glt.guardian_trace_render_html(incident, loop)
    assert "_pending_" not in glt.guardian_trace_render({"CustomFields": {"guardianverdict": ""}}, loop)


def test_trace_prefers_the_issue_field_over_the_loop_verdict():
    loop = dict(SAMPLE_LOOP, verdict={"verdict": "Suspicious", "confidence": 65, "techniques": []})
    incident = {"CustomFields": {"guardianverdict": "Malicious"}}
    markdown = glt.guardian_trace_render(incident, loop)
    assert "**Verdict:** Malicious" in markdown and "Suspicious" not in markdown


def test_trace_still_says_pending_without_a_field_or_a_loop_verdict():
    assert "_pending_" in glt.guardian_trace_render({"CustomFields": {}}, SAMPLE_LOOP)
    assert "pending" in glt.guardian_trace_render_html({"CustomFields": {}}, dict(SAMPLE_LOOP, verdict="junk"))
    assert glt.guardian_trace_verdict({}, {"verdict": {"verdict": "Benign"}}) == "Benign"
