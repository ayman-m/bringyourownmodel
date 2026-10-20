import json

import GuardianLayoutToolLedger as gll


# --- fixtures / test harness --------------------------------------------------


def _entries(contents):
    return [{"Type": 1, "Contents": contents}]


def _not_found(list_name):
    return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(list_name)}]


SAMPLE_ROWS = [
    {
        "ts": "2026-07-05T12:50:10.229Z",
        "actor": "agent",
        "action": "GuardianSkillRead",
        "target": '{"name": "xsoar_case_triage"}',
        "status": "ok",
        "duration_ms": 184,
        "tick_id": "0",
        "run_id": "22486",
        "detail": {"args_warning": None},
    },
    {
        "ts": "2026-07-05T12:50:32.076Z",
        "actor": "agent",
        "action": "SearchIncidentsV2",
        "target": '{"level": ["4", "3"]}',
        "status": "error",
        "duration_ms": 432,
        "tick_id": "1",
        "run_id": "22486",
        "detail": {"args_warning": None},
    },
    {
        "ts": "2026-07-04T13:10:53.786Z",
        "actor": "agent",
        "action": "closeInvestigation",
        "target": None,
        "status": "pending_approval",
        "duration_ms": None,
        "tick_id": "5",
        "run_id": "00000000-0000-4000-8000-000000000000",
        "detail": {"args_warning": None, "kill_switch_note": None},
    },
    {
        "ts": "2026-07-04T13:07:18.528Z",
        "actor": "agent",
        "action": "demisto-api-delete",
        "target": None,
        "status": "denied",
        "duration_ms": None,
        "tick_id": None,
        "run_id": "22486",
        "detail": {"kill_switch_note": "kill switch active"},
    },
]


def _install(monkeypatch, rows=None, list_missing=False, incident_id="22486"):
    rows = SAMPLE_ROWS if rows is None else rows

    def fake_execute(command, args):
        assert command == "getList"
        assert args["listName"] == gll.GUARDIAN_AUDIT_LIST_NAME
        if list_missing:
            return _not_found(gll.GUARDIAN_AUDIT_LIST_NAME)
        return _entries(json.dumps(rows))

    monkeypatch.setattr(gll.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(gll.demisto, "incident", lambda: {"id": incident_id} if incident_id else {})


# --- guardian_ledger_escape_cell ------------------------------------------------


def test_escape_cell_none_is_blank():
    assert gll.guardian_ledger_escape_cell(None) == ""


def test_escape_cell_escapes_pipes_and_newlines():
    rendered = gll.guardian_ledger_escape_cell("a|b\nc")
    assert "\n" not in rendered
    assert rendered == "a\\|b c"


def test_escape_cell_truncates_long_values():
    rendered = gll.guardian_ledger_escape_cell("x" * 500, max_len=50)
    assert len(rendered) == 50
    assert rendered.endswith("…")


def test_escape_cell_stringifies_dicts():
    rendered = gll.guardian_ledger_escape_cell({"a": 1})
    assert "a" in rendered


# --- guardian_ledger_status_cell -------------------------------------------------


def test_status_cell_emphasizes_pending_denied_error():
    assert gll.guardian_ledger_status_cell("pending_approval") == "**PENDING_APPROVAL**"
    assert gll.guardian_ledger_status_cell("denied") == "**DENIED**"
    assert gll.guardian_ledger_status_cell("error") == "**ERROR**"


def test_status_cell_plain_ok():
    assert gll.guardian_ledger_status_cell("ok") == "ok"


def test_status_cell_missing_status():
    assert gll.guardian_ledger_status_cell(None) == "unknown"


# --- guardian_ledger_note_for_row ------------------------------------------------


def test_note_for_row_picks_first_non_null_hint():
    row = {"detail": {"args_warning": None, "kill_switch_note": "blocked", "truncation_note": None}}
    assert gll.guardian_ledger_note_for_row(row) == "blocked"


def test_note_for_row_no_detail():
    assert gll.guardian_ledger_note_for_row({}) == ""


def test_note_for_row_malformed_detail_never_crashes():
    assert gll.guardian_ledger_note_for_row({"detail": "not a dict"}) == ""


# --- guardian_ledger_load_rows ---------------------------------------------------


def test_load_rows_happy_path(monkeypatch):
    _install(monkeypatch)
    result = gll.guardian_ledger_load_rows()
    assert result["ok"] is True
    assert len(result["data"]) == 4


def test_load_rows_missing_list_is_empty_not_error(monkeypatch):
    _install(monkeypatch, list_missing=True)
    result = gll.guardian_ledger_load_rows()
    assert result["ok"] is True
    assert result["data"] == []


def test_load_rows_malformed_json_string_is_error(monkeypatch):
    def fake_execute(command, args):
        return _entries("not valid json{{{")

    monkeypatch.setattr(gll.demisto, "executeCommand", fake_execute)
    result = gll.guardian_ledger_load_rows()
    assert result["ok"] is False


def test_load_rows_non_array_payload_is_error(monkeypatch):
    def fake_execute(command, args):
        return _entries(json.dumps({"not": "an array"}))

    monkeypatch.setattr(gll.demisto, "executeCommand", fake_execute)
    result = gll.guardian_ledger_load_rows()
    assert result["ok"] is False


def test_load_rows_no_contents_at_all_is_empty(monkeypatch):
    def fake_execute(command, args):
        return [{"Type": 1}]

    monkeypatch.setattr(gll.demisto, "executeCommand", fake_execute)
    result = gll.guardian_ledger_load_rows()
    assert result["ok"] is True
    assert result["data"] == []


# --- guardian_ledger_build_table -------------------------------------------------


def test_build_table_has_header_and_one_row_per_entry():
    rows = [SAMPLE_ROWS[0]]
    table = gll.guardian_ledger_build_table(rows)
    lines = table.splitlines()
    assert lines[0].startswith("| Tick |")
    assert len(lines) == 3  # header + separator + 1 row


def test_build_table_skips_non_dict_rows():
    table = gll.guardian_ledger_build_table(["not a dict", SAMPLE_ROWS[0]])
    assert len(table.splitlines()) == 3


# --- guardian_ledger_render (full render / graceful empty) ----------------------


def test_render_no_incident_id_is_graceful():
    markdown = gll.guardian_ledger_render(None)
    assert "Guardian Tool-Call Ledger" in markdown
    assert "No incident context available" in markdown


def test_render_list_missing_is_graceful(monkeypatch):
    _install(monkeypatch, list_missing=True)
    markdown = gll.guardian_ledger_render("22486", load_rows_fn=gll.guardian_ledger_load_rows)
    assert "No tool calls recorded yet" in markdown


def test_render_unreadable_list_surfaces_warning_not_crash(monkeypatch):
    def broken_load():
        return gll.guardian_envelope(False, error="boom")

    markdown = gll.guardian_ledger_render("22486", load_rows_fn=broken_load)
    assert "Could not read the `guardian_audit` List" in markdown
    assert "boom" in markdown


def test_render_filters_by_run_id_and_distinguishes_statuses(monkeypatch):
    _install(monkeypatch)
    markdown = gll.guardian_ledger_render("22486", load_rows_fn=gll.guardian_ledger_load_rows)
    # 3 of the 4 sample rows belong to incident 22486 (one is a different run_id)
    assert "**3 tool call(s):**" in markdown
    assert "GuardianSkillRead" in markdown
    assert "**ERROR**" in markdown
    assert "**DENIED**" in markdown
    # the pending_approval row belongs to a DIFFERENT run_id -- must not leak in
    assert "closeInvestigation" not in markdown
    assert "**PENDING_APPROVAL**" not in markdown


def test_render_no_rows_for_this_incident(monkeypatch):
    _install(monkeypatch, incident_id="99999999")
    markdown = gll.guardian_ledger_render("99999999", load_rows_fn=gll.guardian_ledger_load_rows)
    assert "No tool calls recorded yet for this incident (run_id=`99999999`)" in markdown


def test_render_caps_rows_to_most_recent_n(monkeypatch):
    many_rows = [
        {
            "ts": "2026-07-05T12:00:{:02d}.000Z".format(i),
            "action": "a{}".format(i),
            "status": "ok",
            "target": None,
            "duration_ms": 1,
            "tick_id": i,
            "run_id": "22486",
            "detail": None,
        }
        for i in range(5)
    ]
    monkeypatch.setattr(gll, "GUARDIAN_LEDGER_MAX_ROWS", 2)
    _install(monkeypatch, rows=many_rows)
    markdown = gll.guardian_ledger_render("22486", load_rows_fn=gll.guardian_ledger_load_rows)
    assert "3 earlier row(s) not shown" in markdown
    assert "a4" in markdown  # most recent kept
    assert "a0" not in markdown  # oldest dropped


# --- HTML rendering ----------------------------------------------------------------------


HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(2)>"


def _ok(rows=None):
    return gll.guardian_envelope(True, data=SAMPLE_ROWS if rows is None else rows)


def _no_tags(markup):
    for forbidden in ("<script", "<img", "<iframe", "<style", "onerror=alert(2)>"):
        assert forbidden not in markup


def test_html_render_shows_header_counts_table_and_status_badges():
    html = gll.guardian_ledger_render_html("22486", _ok())
    assert "Tool-call ledger" in html and "<table" in html
    assert "3 calls" not in html and "<b>Calls</b> 3" in html  # 3 rows belong to run 22486
    assert "1 ok" in html and "1 error" in html and "1 denied" in html
    assert "GuardianSkillRead" in html and "SearchIncidentsV2" in html and "demisto-api-delete" in html
    assert "closeInvestigation" not in html  # another run's row
    assert "#1f8a5b" in html and "#c0392b" in html  # green ok, red error/denied
    assert "184 ms" in html and "2026-07-05 12:50:10" in html
    _no_tags(html)


def test_html_render_rows_are_chronological():
    html = gll.guardian_ledger_render_html("22486", _ok())
    assert html.index("demisto-api-delete") < html.index("GuardianSkillRead") < html.index("SearchIncidentsV2")


def test_html_render_hostile_values_are_escaped_everywhere():
    rows = [
        {
            "ts": HOSTILE,
            "action": HOSTILE,
            "target": HOSTILE,
            "status": HOSTILE,
            "duration_ms": HOSTILE,
            "tick_id": HOSTILE,
            "run_id": "7",
            "detail": {"kill_switch_note": HOSTILE},
        }
    ]
    html = gll.guardian_ledger_render_html("7", _ok(rows))
    _no_tags(html)
    assert "&lt;script&gt;" in html


def test_html_render_target_is_scrubbed_and_truncated():
    rows = [dict(SAMPLE_ROWS[0], target="password=hunter2 " + "x" * 400)]
    html = gll.guardian_ledger_render_html("22486", _ok(rows))
    assert "hunter2" not in html and "…" in html


def test_html_render_marks_auto_approved_rows():
    rows = [dict(SAMPLE_ROWS[0], detail={"auto_approved": True})]
    assert "auto-approved" in gll.guardian_ledger_render_html("22486", _ok(rows))


def test_html_render_empty_states_say_what_happens_next():
    html = gll.guardian_ledger_render_html("22486", _ok([]))
    assert "No tool calls recorded yet" in html and "listed here as it happens" in html
    html = gll.guardian_ledger_render_html(None, None)
    assert "No incident context" in html
    html = gll.guardian_ledger_render_html("22486", gll.guardian_envelope(False, error=HOSTILE + " api_key=abc"))
    _no_tags(html)
    assert "Ledger unavailable" in html


def test_html_render_caps_rows(monkeypatch):
    monkeypatch.setattr(gll, "GUARDIAN_LEDGER_MAX_ROWS", 2)
    many = [
        {"ts": "2026-07-05T12:0{}:00Z".format(i), "action": "a{}".format(i), "status": "ok", "run_id": "1"} for i in range(5)
    ]
    html = gll.guardian_ledger_render_html("1", _ok(many))
    assert "3 earlier row(s) not shown" in html and "a4" in html and "a0" not in html


def test_duration_text():
    assert gll.guardian_ledger_duration_text(184) == "184 ms"
    assert gll.guardian_ledger_duration_text(1800) == "1.8 s"
    assert gll.guardian_ledger_duration_text(None) == "-" and gll.guardian_ledger_duration_text(True) == "-"


def test_run_rows_filters_and_sorts():
    rows = gll.guardian_ledger_run_rows(SAMPLE_ROWS + ["junk", None], "22486")
    assert [r["action"] for r in rows] == ["demisto-api-delete", "GuardianSkillRead", "SearchIncidentsV2"]


# --- main(): entry-point smoke tests ---------------------------------------------


def test_main_no_incident_is_graceful(monkeypatch):
    monkeypatch.setattr(gll.demisto, "incident", lambda: {})

    import CommonServerPython as csp

    csp.RESULTS.clear()
    gll.main()

    assert len(csp.RESULTS) == 1
    entry = csp.RESULTS[0]
    assert entry["ContentsFormat"] == "html" and entry["Type"] == 1
    assert "No incident context" in entry["Contents"]


def test_main_real_incident_returns_the_html_table(monkeypatch):
    _install(monkeypatch)

    import CommonServerPython as csp

    csp.RESULTS.clear()
    gll.main()

    assert len(csp.RESULTS) == 1
    entry = csp.RESULTS[0]
    assert entry["ContentsFormat"] == "html"
    assert "Tool-call ledger" in entry["Contents"] and "GuardianSkillRead" in entry["Contents"]


def test_main_falls_back_to_markdown_without_rereading_when_the_html_builder_raises(monkeypatch):
    reads = []
    _install(monkeypatch)
    original = gll.demisto.executeCommand
    monkeypatch.setattr(gll.demisto, "executeCommand", lambda c, a: reads.append(c) or original(c, a))

    def boom(*args, **kwargs):
        raise RuntimeError("html broke")

    monkeypatch.setattr(gll, "guardian_ledger_render_html", boom)

    import CommonServerPython as csp

    csp.RESULTS.clear()
    gll.main()

    assert len(csp.RESULTS) == 1
    readable = csp.RESULTS[0].readable_output
    assert "Guardian Tool-Call Ledger" in readable and "GuardianSkillRead" in readable
    assert reads == ["getList"]  # one read, shared by the failed HTML build and the fallback
