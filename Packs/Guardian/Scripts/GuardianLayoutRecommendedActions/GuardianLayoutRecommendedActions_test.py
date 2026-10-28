import json

import pytest

import GuardianLayoutRecommendedActions as gra


# --- fixtures / test harness --------------------------------------------------


def _entries(contents):
    return [{"Type": 1, "Contents": contents}]


def _not_found(list_name):
    return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(list_name)}]


SAMPLE_LOOP = {
    "status": "done",
    "tick": 6,
    "messages": [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "task"},
        {"role": "assistant", "content": None, "tool_calls": [{"id": "c0", "function": {"name": "ip", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "c0", "content": json.dumps({"ok": True})},
        {"role": "assistant", "content": "Recommend closing as False Positive; no active impact found.", "tool_calls": []},
    ],
}

SAMPLE_LEDGER_ROWS = [
    {
        "approval_id": "approval-a",
        "kind": "tool",
        "tool_name": "closeInvestigation",
        "risk_tier": "destructive",
        "status": "pending",
        "created_ts": "2026-07-04T13:10:53.786Z",
        "incident_id": "22486",
        "run_id": "22486",
    },
    {
        "approval_id": "approval-b",
        "kind": "tool",
        "tool_name": "setIncident",
        "risk_tier": "soft",
        "status": "pending",
        "created_ts": "2026-07-04T13:11:00.000Z",
        "incident_id": "22486",
        "run_id": "22486",
    },
    {
        "approval_id": "approval-c",
        "kind": "tool",
        "tool_name": "demisto-api-delete",
        "risk_tier": "soft",
        "status": "denied",
        "created_ts": "2026-07-04T13:07:18.528Z",
        "incident_id": "22486",
        "run_id": "22486",
    },
    {
        "approval_id": "approval-d",
        "kind": "tool",
        "tool_name": "closeInvestigation",
        "risk_tier": "destructive",
        "status": "pending",
        "created_ts": "2026-07-04T13:12:00.000Z",
        "incident_id": "99999",
        "run_id": "99999",
    },
]


def _install(monkeypatch, rows=None, list_missing=False):
    rows = SAMPLE_LEDGER_ROWS if rows is None else rows

    def fake_execute(command, args):
        assert command == "getList"
        if list_missing:
            return _not_found(gra.GUARDIAN_APPROVALS_LEDGER_LIST_NAME)
        return _entries(json.dumps(rows))

    monkeypatch.setattr(gra.demisto, "executeCommand", fake_execute)


# --- guardian_recommended_final_conclusion --------------------------------------


def test_final_conclusion_picks_last_assistant_message_with_content():
    conclusion = gra.guardian_recommended_final_conclusion(SAMPLE_LOOP)
    assert conclusion == "Recommend closing as False Positive; no active impact found."


def test_final_conclusion_no_messages():
    assert gra.guardian_recommended_final_conclusion({}) is None


def test_final_conclusion_messages_not_a_list():
    assert gra.guardian_recommended_final_conclusion({"messages": "not a list"}) is None


def test_final_conclusion_only_tool_call_turns_no_content():
    loop = {"messages": [{"role": "assistant", "content": None, "tool_calls": [{"id": "c0"}]}]}
    assert gra.guardian_recommended_final_conclusion(loop) is None


def test_final_conclusion_caps_length():
    long_text = "x" * 5000
    loop = {"messages": [{"role": "assistant", "content": long_text}]}
    conclusion = gra.guardian_recommended_final_conclusion(loop)
    assert len(conclusion) <= gra.GUARDIAN_RECOMMENDED_MAX_CONCLUSION_CHARS
    assert conclusion.endswith("…")


# --- guardian_recommended_pending_rows ------------------------------------------


def test_pending_rows_filters_by_status_and_incident_id():
    rows = gra.guardian_recommended_pending_rows(SAMPLE_LEDGER_ROWS, "22486")
    assert len(rows) == 2
    assert all(r["status"] == "pending" for r in rows)
    assert all(str(r["incident_id"]) == "22486" for r in rows)


def test_pending_rows_sorted_oldest_first():
    rows = gra.guardian_recommended_pending_rows(SAMPLE_LEDGER_ROWS, "22486")
    assert rows[0]["tool_name"] == "closeInvestigation"
    assert rows[0]["created_ts"] == "2026-07-04T13:10:53.786Z"


def test_pending_rows_no_match_returns_empty():
    assert gra.guardian_recommended_pending_rows(SAMPLE_LEDGER_ROWS, "no-such-incident") == []


def test_pending_rows_never_crashes_on_malformed_entries():
    rows = gra.guardian_recommended_pending_rows(["not a dict", None, SAMPLE_LEDGER_ROWS[0]], "22486")
    assert len(rows) == 1


def test_pending_rows_matches_run_id_fallback_when_incident_id_absent():
    row = {"approval_id": "x", "kind": "tool", "tool_name": "setIncident", "status": "pending", "run_id": "555"}
    rows = gra.guardian_recommended_pending_rows([row], "555")
    assert len(rows) == 1


def test_denied_and_approved_rows_never_show_as_pending():
    """The staleness fix this task made: a resolved row (approved OR
    denied) must never render as "still awaiting approval"."""
    rows = [
        {"approval_id": "x", "kind": "tool", "tool_name": "setIncident", "status": "approved", "incident_id": "1"},
        {"approval_id": "y", "kind": "tool", "tool_name": "setIncident", "status": "denied", "incident_id": "1"},
        {"approval_id": "z", "kind": "tool", "tool_name": "setIncident", "status": "expired", "incident_id": "1"},
    ]
    assert gra.guardian_recommended_pending_rows(rows, "1") == []


# --- guardian_recommended_describe_action ---------------------------------------


def test_describe_action_tool_kind_is_the_tool_name():
    assert gra.guardian_recommended_describe_action({"kind": "tool", "tool_name": "setIncident"}) == "setIncident"


def test_describe_action_plan_kind_shows_step_count():
    row = {"kind": "plan", "steps": [{"tool_name": "a"}, {"tool_name": "b"}]}
    assert gra.guardian_recommended_describe_action(row) == "plan (2 step(s))"


def test_describe_action_defaults_kind_to_tool():
    assert gra.guardian_recommended_describe_action({"tool_name": "setIncident"}) == "setIncident"


# --- guardian_recommended_build_pending_section ---------------------------------


def test_build_pending_section_includes_table_and_resolve_instructions():
    rows = gra.guardian_recommended_pending_rows(SAMPLE_LEDGER_ROWS, "22486")
    section = gra.guardian_recommended_build_pending_section(rows)
    assert "Awaiting human approval (2)" in section
    assert "approval-a" in section
    assert "approval-b" in section
    assert "closeInvestigation" in section
    assert "setIncident" in section
    assert "destructive" in section
    assert "!guardian-approve approval_id=<id>" in section
    assert "!guardian-deny approval_id=<id>" in section
    assert "confirm=CONFIRM" in section


def test_build_pending_section_caps_rows(monkeypatch):
    monkeypatch.setattr(gra, "GUARDIAN_RECOMMENDED_MAX_PENDING_ROWS", 1)
    rows = gra.guardian_recommended_pending_rows(SAMPLE_LEDGER_ROWS, "22486")
    section = gra.guardian_recommended_build_pending_section(rows)
    assert "1 earlier pending row(s) not shown" in section


def test_build_pending_section_renders_plan_rows():
    rows = [
        {
            "approval_id": "plan-1",
            "kind": "plan",
            "risk_tier": "credential",
            "status": "pending",
            "created_ts": "2026-07-05T00:00:00Z",
            "steps": [{"tool_name": "a"}, {"tool_name": "b"}, {"tool_name": "c"}],
        }
    ]
    section = gra.guardian_recommended_build_pending_section(rows)
    assert "plan (3 step(s))" in section
    assert "credential" in section


# --- guardian_recommended_render (full render / graceful empty) ----------------


def test_render_no_incident_is_graceful():
    markdown = gra.guardian_recommended_render({}, {})
    assert "Guardian Recommended Actions" in markdown
    assert "No incident context available" in markdown
    assert "No recommendations yet" in markdown


def test_render_none_incident_and_loop_never_crashes():
    markdown = gra.guardian_recommended_render(None, None)
    assert "Guardian Recommended Actions" in markdown


def test_render_states_the_source_used():
    markdown = gra.guardian_recommended_render({}, {})
    assert "Source:" in markdown
    assert "guardian_approvals_ledger" in markdown
    assert "!guardian-approve" in markdown


def test_render_full_with_pending_and_conclusion(monkeypatch):
    _install(monkeypatch)
    incident = {"id": "22486"}
    markdown = gra.guardian_recommended_render(
        incident, SAMPLE_LOOP, pending_load_fn=gra.guardian_recommended_load_pending_approvals
    )
    assert "Awaiting human approval (2)" in markdown
    assert "closeInvestigation" in markdown
    assert "Recommend closing as False Positive" in markdown
    # a pending row belonging to a DIFFERENT incident must not leak in
    assert markdown.count("closeInvestigation") == 1


def test_render_no_pending_rows_but_has_conclusion(monkeypatch):
    _install(monkeypatch, rows=[])
    incident = {"id": "22486"}
    markdown = gra.guardian_recommended_render(
        incident, SAMPLE_LOOP, pending_load_fn=gra.guardian_recommended_load_pending_approvals
    )
    assert "No tool calls are currently awaiting approval" in markdown
    assert "Recommend closing as False Positive" in markdown


def test_render_list_missing_is_graceful(monkeypatch):
    _install(monkeypatch, list_missing=True)
    incident = {"id": "22486"}
    markdown = gra.guardian_recommended_render(
        incident, SAMPLE_LOOP, pending_load_fn=gra.guardian_recommended_load_pending_approvals
    )
    assert "No tool calls are currently awaiting approval" in markdown


def test_render_unreadable_list_surfaces_warning_not_crash():
    def broken_load():
        return gra.guardian_envelope(False, error="boom")

    incident = {"id": "22486"}
    markdown = gra.guardian_recommended_render(incident, SAMPLE_LOOP, pending_load_fn=broken_load)
    assert "Could not read the `guardian_approvals_ledger` List" in markdown
    assert "boom" in markdown


def test_render_no_conclusion_run_in_progress(monkeypatch):
    _install(monkeypatch, rows=[])
    incident = {"id": "22486"}
    loop = {"status": "running", "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]}
    markdown = gra.guardian_recommended_render(incident, loop, pending_load_fn=gra.guardian_recommended_load_pending_approvals)
    assert "No final conclusion recorded yet" in markdown


def test_render_no_messages_at_all(monkeypatch):
    _install(monkeypatch, rows=[])
    incident = {"id": "22486"}
    markdown = gra.guardian_recommended_render(incident, {}, pending_load_fn=gra.guardian_recommended_load_pending_approvals)
    assert "No recommendations yet" in markdown


# --- guardian_recommended_load_pending_approvals --------------------------------


def test_load_pending_approvals_missing_list_is_empty(monkeypatch):
    _install(monkeypatch, list_missing=True)
    result = gra.guardian_recommended_load_pending_approvals()
    assert result["ok"] is True
    assert result["data"] == []


def test_load_pending_approvals_malformed_json_is_error(monkeypatch):
    def fake_execute(command, args):
        return _entries("not valid json{{{")

    monkeypatch.setattr(gra.demisto, "executeCommand", fake_execute)
    result = gra.guardian_recommended_load_pending_approvals()
    assert result["ok"] is False


# --- HTML rendering ----------------------------------------------------------------------


HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(2)>"
NOW = gra.guardian_ts_parse("2026-07-04T13:30:00Z")  # 20 minutes after the first sample row


def _ok_load(rows=None):
    return gra.guardian_envelope(True, data=SAMPLE_LEDGER_ROWS if rows is None else rows)


def _no_tags(markup):
    for forbidden in ("<script", "<img", "<iframe", "<style", "onerror=alert(2)>"):
        assert forbidden not in markup


def test_html_render_with_pending_rows_shows_table_badges_sla_and_resolve_instructions():
    html = gra.guardian_recommended_render_html({"id": "22486"}, SAMPLE_LOOP, _ok_load(), sla_minutes=60, now=NOW)
    assert "<table" in html and "Approval ID" in html and "Risk tier" in html and "SLA" in html
    assert "approval-a" in html and "approval-b" in html and "approval-d" not in html  # other incident
    assert "closeInvestigation" in html and "setIncident" in html
    assert "40m left" in html  # approval-a: requested 13:10:53, SLA 60 min, now 13:30
    assert "!guardian-approve approval_id=approval-a" in html and "!guardian-deny approval_id=approval-b" in html
    assert "Approve (credential tier)" not in html  # no credential row
    assert "2 awaiting approval" in html
    assert "Recommend closing as False Positive" in html and "Agent&#x27;s conclusion" in html
    _no_tags(html)


def test_html_render_credential_row_points_at_the_credential_button_and_confirm_word():
    rows = [dict(SAMPLE_LEDGER_ROWS[0], approval_id="cred-1", risk_tier="credential")]
    html = gra.guardian_recommended_render_html({"id": "22486"}, SAMPLE_LOOP, _ok_load(rows), sla_minutes=60, now=NOW)
    assert "Approve (credential tier)" in html and "CONFIRM" in html
    assert "!guardian-approve approval_id=cred-1 confirm=CONFIRM" in html


def test_html_render_expired_sla_is_flagged():
    late = gra.guardian_ts_parse("2026-07-04T15:00:00Z")
    html = gra.guardian_recommended_render_html({"id": "22486"}, SAMPLE_LOOP, _ok_load(), sla_minutes=60, now=late)
    assert "expired" in html and "housekeeping sweep" in html


def test_html_render_sla_unknown_shows_a_dash():
    label, kind, expired = gra.guardian_recommended_sla(SAMPLE_LEDGER_ROWS[0], None, NOW)
    assert (label, kind, expired) == ("-", "muted", False)
    assert gra.guardian_recommended_sla({"created_ts": "garbage"}, 60, NOW)[0] == "-"


def test_sla_label_goes_amber_when_less_than_a_quarter_is_left():
    row = {"created_ts": "2026-07-04T13:00:00Z"}
    soon = gra.guardian_ts_parse("2026-07-04T13:50:00Z")
    assert gra.guardian_recommended_sla(row, 60, soon) == ("10m left", "warn", False)
    assert gra.guardian_recommended_sla(row, 60, NOW) == ("30m left", "ok", False)


def test_html_render_escapes_hostile_model_output_tool_names_args_and_ids():
    rows = [
        {
            "approval_id": HOSTILE,
            "kind": "tool",
            "tool_name": HOSTILE,
            "tool_args_redacted": {"note": HOSTILE},
            "risk_tier": HOSTILE,
            "status": "pending",
            "created_ts": HOSTILE,
            "incident_id": "1",
        }
    ]
    loop = {"status": HOSTILE, "tick": HOSTILE, "messages": [{"role": "assistant", "content": HOSTILE + "\nsecond line"}]}
    html = gra.guardian_recommended_render_html({"id": "1"}, loop, _ok_load(rows), sla_minutes=60, now=NOW)
    _no_tags(html)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<br>second line" in html  # conclusion keeps its line breaks, escaped


def test_html_render_ledger_error_is_escaped_and_scrubbed():
    html = gra.guardian_recommended_render_html(
        {"id": "1"}, {}, gra.guardian_envelope(False, error=HOSTILE + " password=hunter2"), sla_minutes=None
    )
    _no_tags(html)
    assert "hunter2" not in html and "Pending approvals unavailable" in html


def test_html_render_empty_states_give_a_next_step():
    html = gra.guardian_recommended_render_html({"id": "1"}, {}, _ok_load([]), sla_minutes=60)
    assert "No actions are waiting for approval" in html and "appears here with Approve and Deny" in html
    assert "No recommendations yet" in html and "after its first model turn" in html
    html = gra.guardian_recommended_render_html(
        {"id": "1"}, {"status": "running", "messages": [{"role": "user", "content": "task"}]}, _ok_load([]), sla_minutes=60
    )
    assert "No final conclusion yet" in html and "still in progress" in html
    html = gra.guardian_recommended_render_html({}, {}, None)
    assert "No incident context" in html


def test_html_render_never_crashes_on_none_inputs():
    html = gra.guardian_recommended_render_html(None, None, None)
    assert "Recommended actions" in html


def test_args_summary_uses_the_redacted_copy_and_never_the_raw_args():
    row = {"kind": "tool", "tool_args": {"password": "hunter2", "host": "h1"}, "tool_args_redacted": {"password": "***", "host": "h1"}}
    summary = gra.guardian_recommended_args_summary(row)
    assert summary == "password=***, host=h1" and "hunter2" not in summary


def test_args_summary_redacts_an_older_row_that_has_no_redacted_copy():
    row = {"kind": "tool", "tool_args": {"api_key": "sk-abc123", "host": "h1"}}
    summary = gra.guardian_recommended_args_summary(row)
    assert "sk-abc123" not in summary and "host=h1" in summary


def test_args_summary_truncates_and_handles_plans():
    long_row = {"kind": "tool", "tool_args_redacted": {"q": "x" * 500}}
    assert len(gra.guardian_recommended_args_summary(long_row)) <= gra.GUARDIAN_RECOMMENDED_MAX_ARGS_CHARS
    plan = {"kind": "plan", "steps": [{"tool_name": "a"}, {"tool_name": "b"}, "junk"]}
    assert gra.guardian_recommended_args_summary(plan) == "a, b"
    assert gra.guardian_recommended_args_summary({"kind": "tool"}) == ""


def test_html_pending_caps_rows_and_commands(monkeypatch):
    monkeypatch.setattr(gra, "GUARDIAN_RECOMMENDED_MAX_PENDING_ROWS", 12)
    rows = [
        {"approval_id": "id-{:02d}".format(i), "kind": "tool", "tool_name": "setIncident", "risk_tier": "soft", "status": "pending",
         "created_ts": "2026-07-04T13:10:53Z", "incident_id": "1"}
        for i in range(15)
    ]
    html = gra.guardian_recommended_build_pending_html(rows, 60, NOW)
    assert "3 earlier pending row(s) not shown" in html
    assert "+2 more" in html  # 12 shown, 10 command lines


def test_load_sla_minutes(monkeypatch):
    def execute(settings):
        monkeypatch.setattr(gra.demisto, "executeCommand", lambda command, args: settings)

    execute(_entries(json.dumps({"approval_sla_minutes": 45})))
    assert gra.guardian_recommended_load_sla_minutes() == 45
    execute(_entries(json.dumps({"approval_sla_minutes": "soon"})))
    assert gra.guardian_recommended_load_sla_minutes() is None
    execute(_entries(json.dumps({"approval_sla_minutes": 0})))
    assert gra.guardian_recommended_load_sla_minutes() is None
    execute(_entries("not json"))
    assert gra.guardian_recommended_load_sla_minutes() is None
    execute(_not_found("guardian_settings"))
    assert gra.guardian_recommended_load_sla_minutes() is None


# --- main(): entry-point smoke tests ---------------------------------------------


def _run_main(monkeypatch, incident, loop, rows=None, list_missing=False, settings=None):
    """Run main() with every external read stubbed; return csp.RESULTS."""
    calls = []

    def fake_execute(command, args):
        assert command == "getList"
        calls.append(args["listName"])
        if args["listName"] == gra.GUARDIAN_SETTINGS_LIST_NAME:
            return _entries(json.dumps(settings if settings is not None else {"approval_sla_minutes": 60}))
        if list_missing:
            return _not_found(gra.GUARDIAN_APPROVALS_LEDGER_LIST_NAME)
        return _entries(json.dumps(SAMPLE_LEDGER_ROWS if rows is None else rows))

    monkeypatch.setattr(gra.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(gra.demisto, "incident", lambda: incident)
    monkeypatch.setattr(gra.demisto, "context", lambda: {"Guardian": {"Loop": loop}} if loop else {})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    gra.main()
    return csp.RESULTS, calls


def test_main_empty_playground_context_is_graceful(monkeypatch):
    results, calls = _run_main(monkeypatch, {}, {})
    assert len(results) == 1 and calls == []  # no incident: nothing is read
    entry = results[0]
    assert entry["Type"] == 1 and entry["ContentsFormat"] == "html"
    assert "No recommendations yet" in entry["Contents"] and "No incident context" in entry["Contents"]


def test_main_real_incident_returns_html_with_pending_and_conclusion(monkeypatch):
    results, calls = _run_main(monkeypatch, {"id": "22486"}, SAMPLE_LOOP)
    assert len(results) == 1
    entry = results[0]
    assert entry["ContentsFormat"] == "html"
    assert "2 awaiting approval" in entry["Contents"]
    assert "Recommend closing as False Positive" in entry["Contents"]
    assert sorted(calls) == ["guardian_approvals_ledger", "guardian_settings"]  # each List read once
    _no_tags(entry["Contents"])


def test_main_falls_back_to_markdown_without_rereading_when_the_html_builder_raises(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("html broke")

    monkeypatch.setattr(gra, "guardian_recommended_render_html", boom)
    results, calls = _run_main(monkeypatch, {"id": "22486"}, SAMPLE_LOOP)
    assert len(results) == 1
    readable = results[0].readable_output  # CommandResults, as before the redesign
    assert "Awaiting human approval (2)" in readable and "Recommend closing as False Positive" in readable
    assert calls.count("guardian_approvals_ledger") == 1  # the fallback reuses the first read


# --- the agent's conclusion as a verdict block ----------------------------------------------------------------------------

VERDICT = {"verdict": "Malicious", "confidence": 92, "techniques": ["T1204.002", "T1059.001", "T1071.001"],
           "summary": "Confirmed malicious downloader execution on WS-0421 with active C2 <b>quarantine</b> failed."}


def _loop_with(conclusion):
    return {"status": "done", "tick": 7, "messages": [{"role": "user", "content": "task"},
                                                      {"role": "assistant", "content": conclusion}]}


def _conclusion_html(conclusion):
    return str(gra.guardian_recommended_render_html({"id": "5"}, _loop_with(conclusion), _ok_load([]), sla_minutes=60, now=NOW))


def test_a_bare_json_verdict_block_is_a_pill_a_confidence_technique_chips_and_the_summary():
    html = _conclusion_html(json.dumps(VERDICT, indent=2))
    assert "MALICIOUS" in html and "background:#c0392b" in html and "Confidence&nbsp;<b>92%</b>" in html
    for technique in VERDICT["techniques"]:
        assert "<code" in html and technique in html
    assert "Confirmed malicious downloader execution on WS-0421" in html
    assert "&quot;verdict&quot;" not in html and "&quot;confidence&quot;" not in html and "{" not in html.split("Conclusion")[1]
    assert "Agent&#x27;s verdict" in html or "Agent's verdict" in html


def test_a_fenced_verdict_block_is_read_the_same_way():
    for fence in ("```json\n{}\n```", "```\n{}\n```", "```JSON\n{}```"):
        html = _conclusion_html(fence.format(json.dumps(VERDICT)))
        assert "MALICIOUS" in html and "T1204.002" in html and "```" not in html


@pytest.mark.parametrize("verdict, color", [("Malicious", "#c0392b"), ("suspicious", "#b36b00"), ("BENIGN", "#1f8a5b"),
                                           ("Inconclusive", "#667085")])
def test_the_pill_colour_follows_the_verdict(verdict, color):
    html = _conclusion_html(json.dumps({"verdict": verdict, "confidence": 50, "summary": "x"}))
    assert "background:{}".format(color) in html and verdict.upper() in html


def test_the_model_text_of_a_verdict_block_is_escaped():
    html = _conclusion_html(json.dumps({"verdict": "Malicious", "summary": "<script>alert(1)</script>",
                                        "techniques": ["T1059<img>", "T1059"]}))
    assert "<script>" not in html and "&lt;script&gt;" in html and "<img" not in html and "T1059" in html


def test_a_verdict_block_without_confidence_techniques_or_summary_still_renders():
    html = _conclusion_html(json.dumps({"verdict": "Benign"}))
    assert "BENIGN" in html and "Confidence" not in html and "<code" not in html


def test_confidence_is_clamped_and_techniques_are_deduplicated_and_validated():
    block = gra.guardian_recommended_verdict_block(json.dumps({
        "verdict": "suspicious", "confidence": 250, "techniques": ["T1059", "t1059", "TA0001", "T1059.001", 5, None, "x"]}))
    assert block == {"verdict": "Suspicious", "confidence": 100, "techniques": ["T1059", "T1059.001"], "summary": ""}
    assert gra.guardian_recommended_verdict_block('{"verdict": "Benign", "confidence": "high"}')["confidence"] is None
    assert gra.guardian_recommended_verdict_block('{"verdict": "Benign", "confidence": true}')["confidence"] is None
    many = gra.guardian_recommended_verdict_block(json.dumps({"verdict": "Benign", "techniques": ["T%04d" % i for i in range(40)]}))
    assert len(many["techniques"]) == 12


@pytest.mark.parametrize("text", [
    "Recommend closing as a false positive.",                                         # prose
    "Findings first.\n```json\n" + json.dumps(VERDICT) + "\n```",                       # prose around the block
    json.dumps(VERDICT) + "\nand more text",                                           # text after the block
    '{"verdict": "Maybe", "confidence": 3}',                                           # not a verdict
    '{"verdict": 5}', '{"summary": "no verdict"}', '[{"verdict": "Malicious"}]', '{"verdict": "Malicious"',    # not a block
    "", None, 7])
def test_anything_else_keeps_the_text_block(text):
    assert gra.guardian_recommended_verdict_block(text) is None
    if isinstance(text, str) and text.strip():
        html = _conclusion_html(text)
        assert "Agent&#x27;s conclusion" in html or "Agent's conclusion" in html


def test_the_verdict_block_does_not_change_the_other_sections():
    html = str(gra.guardian_recommended_render_html({"id": "22486"}, _loop_with(json.dumps(VERDICT)),
                                                    _ok_load(SAMPLE_LEDGER_ROWS), sla_minutes=60, now=NOW))
    assert "closeInvestigation" in html and "Awaiting your decision" in html and "2 awaiting approval" in html
