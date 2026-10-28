import json
import re

import pytest

import GuardianLayoutAssessment as gla

INCIDENT = {"id": "4217", "name": "Repeated failed sign-ins for jdoe-example", "type": "Guardian Agent Run", "severity": 3, "owner": ""}

TRIAGE = {
    "status": "structured", "branch": "identity", "investigation_type": "credential_abuse", "severity": "low",
    "original_severity": "high", "confidence": 90, "likely_benign": True, "escalate": False, "complexity": "medium",
    "summary": "Twelve failed sign-ins from 203.0.113.50 followed by one success from the user's usual network.",
    "analysis": "The failures stop after the user reset the password.\nNo sign of lateral movement.",
    "recommendations": ["Confirm the password reset with the user", "Review sign-ins from 198.51.100.7"],
    "next_step": "Close the incident after the user confirms.",
    "inputs": {"identity": "jdoe-example", "ip": "203.0.113.50", "host": "", "domain": "example.com", "email": "jdoe@example.com"},
}
APPLY = {"status": "applied", "severity_before": "high", "severity_after": "low", "phase": "Guardian triage: identity",
         "reason": "severity: lowered from high to low (structured result, confidence 90); phase: Guardian triage: identity"}
VERDICT_FENCE = '```json\n{"verdict": "Suspicious", "confidence": 70, "techniques": ["T1110"], "summary": "Brute force then success."}\n```'
CONCLUSION = (
    "## Findings\n\nThe account **jdoe-example** saw 12 failures from `203.0.113.50`.\n\n"
    "- password was reset at 09:14\n- no further failures\n\n1. confirm with the user\n2. close\n\n"
    "Checked guardian_approvals_ledger and cost_usd for *other* runs.\n" + VERDICT_FENCE
)
LOOP = {
    "status": "done", "tick": 7, "cost_tokens_total": 123456, "cost_usd": 0.0421,
    "verdict": {"verdict": "Suspicious", "confidence": 70, "techniques": ["T1110", "T1078"], "summary": "Brute force then success."},
    "messages": [
        {"role": "user", "content": "task"},
        {"role": "assistant", "content": "interim thought"},
        {"role": "assistant", "content": CONCLUSION},
        {"role": "assistant", "content": ""},
    ],
}


def _install(monkeypatch, incident=INCIDENT, guardian=None, rows=None, ledger=None, args=None):
    """Patch everything the script reads. `rows` is the ledger content; `ledger` overrides the whole executeCommand reply."""
    context = {"Guardian": guardian} if guardian is not None else {}
    monkeypatch.setattr(gla.demisto, "incident", lambda: incident)
    monkeypatch.setattr(gla.demisto, "context", lambda: context)
    monkeypatch.setattr(gla.demisto, "args", lambda: args or {})
    monkeypatch.setattr(gla.demisto, "debug", lambda *_: None)
    monkeypatch.setattr(gla.demisto, "error", lambda *_: None)
    reply = ledger if ledger is not None else [{"Type": 1, "Contents": json.dumps(rows or [])}]
    calls = []

    def fake_execute(command, command_args):
        calls.append((command, command_args))
        return reply

    monkeypatch.setattr(gla.demisto, "executeCommand", fake_execute)
    return calls


def _html(monkeypatch, guardian, **kwargs):
    _install(monkeypatch, guardian=guardian, **kwargs)
    entry = gla.build_entry(gla.demisto.incident(), gla.demisto.context())
    assert entry["ContentsFormat"] == "html"
    return entry["Contents"]


FULL = {"Triage": TRIAGE, "TriageApply": APPLY, "Loop": LOOP}


def test_full_triage_and_applied_lowering(monkeypatch):
    calls = _install(monkeypatch, guardian=FULL, rows=[
        {"status": "pending", "incident_id": "4217"}, {"status": "pending", "run_id": "4217"},
        {"status": "denied", "incident_id": "4217"}, {"status": "pending", "incident_id": "9999"}])
    entry = gla.build_entry(gla.demisto.incident(), gla.demisto.context())
    assert set(entry) == {"Type", "ContentsFormat", "Contents"} and entry["Type"] == 1 and entry["ContentsFormat"] == "html"
    page = entry["Contents"]
    assert calls == [("getList", {"listName": "guardian_approvals_ledger"})]
    for expected in ("Suspicious", "70%", "credential_abuse", "medium", "Lowered by Guardian triage", ">High<", ">Low<",
                     "lowered from high to low", "Twelve failed sign-ins", "No sign of lateral movement",
                     "Confirm the password reset with the user", "Close the incident after the user confirms.",
                     "T1110", "T1078", "<b>jdoe-example</b>", "<b>203.0.113.50</b>", "<b>example.com</b>",
                     "2 actions are waiting for approval", "Ticks 7", "Tokens 123,456", "Cost $0.0421", "Run", "done"):
        assert expected in page, expected
    assert "<h" not in page.replace("<hr", "")  # headings are styled divs
    assert "<b>Host</b>" not in page and ">Host " not in page  # empty inputs are skipped
    assert "Escalate" not in page
    for banned in ("<script", "<style", "<details", "http://", "https://", "src=", "href="):
        assert banned not in page, banned


def test_escalate_badge_and_single_pending(monkeypatch):
    triage = dict(TRIAGE, escalate=True)
    page = _html(monkeypatch, {"Triage": triage, "TriageApply": APPLY, "Loop": LOOP}, rows=[{"status": "pending", "incident_id": "4217"}])
    assert ">Escalate<" in page
    assert "1 action is waiting for approval" in page


def test_no_pending_actions(monkeypatch):
    assert "No actions are waiting for approval" in _html(monkeypatch, FULL, rows=[])


def test_apply_skipped_because_of_owner(monkeypatch):
    apply_record = {"status": "skipped", "severity_before": "high", "severity_after": "high", "phase": "", "reason": "the incident already has an owner"}
    page = _html(monkeypatch, {"Triage": TRIAGE, "TriageApply": apply_record, "Loop": LOOP})
    assert "Unchanged: the incident already has an owner" in page
    assert ">High<" in page and "Lowered" not in page and gla.ARROW not in page


def test_apply_raised_dry_run_and_error(monkeypatch):
    raised = dict(APPLY, severity_before="low", severity_after="critical", reason="raised from low to critical")
    page = _html(monkeypatch, {"Triage": TRIAGE, "TriageApply": raised})
    assert "Raised by Guardian triage" in page and ">Critical<" in page and gla.ARROW in page
    dry = dict(APPLY, status="dry_run")
    assert "Dry run, nothing written: would be lowered by Guardian triage" in _html(monkeypatch, {"Triage": TRIAGE, "TriageApply": dry})
    same = dict(APPLY, status="dry_run", severity_after="high", reason="severity: the severity is already high")
    assert "Dry run, unchanged: severity: the severity is already high" in _html(monkeypatch, {"Triage": TRIAGE, "TriageApply": same})
    error = dict(APPLY, status="error", severity_after="high", reason="setIncident failed: timed out")
    assert "Not changed (error): setIncident failed: timed out" in _html(monkeypatch, {"Triage": TRIAGE, "TriageApply": error})


def test_applied_without_a_severity_change_for_a_repaired_result(monkeypatch):
    apply_record = dict(APPLY, severity_after="high", reason="severity: a repaired result never changes the severity")
    page = _html(monkeypatch, {"Triage": dict(TRIAGE, status="repaired"), "TriageApply": apply_record})
    assert "Unchanged: severity: a repaired result never changes the severity" in page
    assert "Lowered" not in page and "Raised" not in page


def test_no_triage_apply_record_shows_the_current_severity(monkeypatch):
    page = _html(monkeypatch, {"Triage": TRIAGE, "Loop": LOOP})
    assert "Severity was not changed by Guardian in this run." in page and ">High<" in page


@pytest.mark.parametrize("number, name", [(0, "Unknown"), (0.5, "Informational"), (1, "Low"), (2, "Medium"), (3, "High"), (4, "Critical")])
def test_incident_severity_numbers(monkeypatch, number, name):
    _install(monkeypatch, incident=dict(INCIDENT, severity=number), guardian={"Triage": TRIAGE})
    page = gla.build_entry(gla.demisto.incident(), gla.demisto.context())["Contents"]
    assert ">{}<".format(name) in page


def test_agent_loop_path_without_triage(monkeypatch):
    page = _html(monkeypatch, {"Loop": LOOP})
    assert "Suspicious" in page and "70%" in page and "Brute force then success." in page  # summary from the verdict
    assert "account <b>jdoe-example</b> saw" in page  # the conclusion is rendered
    assert "T1110" in page and "Analysis" not in page and "Recommended actions" not in page and "Key entities" not in page
    assert "Severity was not changed by Guardian in this run." in page


def test_loop_without_a_conclusion_yet(monkeypatch):
    page = _html(monkeypatch, {"Loop": {"status": "running", "tick": 1}})
    assert "No conclusion yet" in page and "running" in page


def test_no_guardian_data_shows_one_short_line(monkeypatch):
    calls = _install(monkeypatch, guardian=None)
    entry = gla.build_entry(gla.demisto.incident(), gla.demisto.context())
    assert "Guardian has not assessed this incident yet." in entry["Contents"] and entry["ContentsFormat"] == "html"
    assert len(entry["Contents"]) < 200 and calls == []
    _install(monkeypatch, incident={}, guardian={})
    assert "has not assessed" in gla.build_entry({}, {})["Contents"]


def test_list_shaped_context_uses_the_last_dict(monkeypatch):
    guardian = {"Triage": [dict(TRIAGE, summary="Old summary"), TRIAGE], "TriageApply": [{"status": "skipped", "reason": "old"}, APPLY],
                "Loop": [{"status": "old"}, LOOP]}
    page = _html(monkeypatch, guardian)
    assert "Twelve failed sign-ins" in page and "Old summary" not in page and "Lowered by Guardian triage" in page
    assert gla._dict([1, {"a": 1}, "x"]) == {"a": 1} and gla._dict("text") == {} and gla._dict(None) == {}


def test_markdown_conversion():
    out = gla.markdown_to_html("# One\n## Two\n### Three\n\nA **bold** and *slanted* and _also_ with `x*y*z`.\nsecond line\n\n- a\n- b\n* c\n\n1. first\n2. second")
    assert out.count("font-weight:700") == 3 and ">One<" in out and ">Three<" in out
    assert "<b>bold</b>" in out and "<i>slanted</i>" in out and "<i>also</i>" in out
    assert ">x*y*z</code>" in out  # code is left alone
    assert "A <b>bold</b>" in out and "<br>second line" in out
    assert out.count("<ul") == 1 and out.count("<li>") == 5 and "<li>c</li>" in out
    assert out.count("<ol") == 1 and "<li>second</li>" in out and out.count("<p ") == 1
    plain = gla.markdown_to_html("see guardian_approvals_ledger and cost_usd, 2 * 3 * 4, and snake_case_name")
    assert "<i>" not in plain


def test_verdict_fence_is_dropped_and_other_fences_are_kept(monkeypatch):
    text = ("Before.\n" + VERDICT_FENCE + "\nMiddle.\n```\n{\"severity\": \"low\", \"investigation_type\": \"x\"}\n```\n"
            "```python\nprint('<hi>')\n```\n```\n{\"note\": \"plain object\"}\n```\nAfter.")
    out = gla.markdown_to_html(text)
    assert "Suspicious" not in out and "severity" not in out and "Brute force" not in out
    assert out.count("<pre") == 2 and "print(&#x27;&lt;hi&gt;&#x27;)" in out and "&quot;note&quot;: &quot;plain object&quot;" in out
    assert "Before." in out and "Middle." in out and "After." in out
    assert "```" not in out
    assert "<pre" not in gla.markdown_to_html('```json\n{"investigation_type": "phishing"}\n```')
    assert "<pre" in gla.markdown_to_html("```json\n{not json\n```")


def test_a_bare_verdict_object_is_dropped_too():
    out = gla.markdown_to_html('Done.\n\n{"verdict": "Benign", "confidence": 90, "summary": "x"}\n')
    assert "Done." in out and "verdict" not in out
    assert "verdict" not in gla.markdown_to_html('{"verdict": "Benign"}')
    assert "{not a verdict}" in gla.markdown_to_html("{not a verdict}")


def test_unclosed_fence_does_not_swallow_a_verdict_fence_before_it():
    out = gla.markdown_to_html(VERDICT_FENCE + "\nThen ```\nunfinished")
    assert "Suspicious" not in out and "unfinished" in out and "<pre" in out


def test_conclusion_is_escaped(monkeypatch):
    loop = {"status": "done", "messages": [{"role": "assistant", "content": "<script>alert(1)</script> **x**\n- <img src=x onerror=alert(2)>\n```\n<script>bad()</script>\n```"}]}
    page = _html(monkeypatch, {"Loop": loop})
    assert "<script" not in page and "<img" not in page and "&lt;img src=x onerror=alert(2)&gt;" in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt; <b>x</b>" in page
    assert "&lt;script&gt;bad()&lt;/script&gt;" in page


def test_every_value_is_escaped(monkeypatch):
    evil = "<b onmouseover=x>&\"'"
    triage = dict(TRIAGE, summary=evil, analysis=evil, next_step=evil, investigation_type=evil, complexity=evil,
                  recommendations=[evil], inputs={"ip": evil, "identity": evil})
    guardian = {"Triage": triage, "TriageApply": dict(APPLY, reason=evil), "Loop": dict(LOOP, status=evil, verdict={"verdict": "Benign", "techniques": [evil]})}
    page = _html(monkeypatch, guardian, incident=dict(INCIDENT, name=evil, type=evil, owner=evil))
    assert "<b onmouseover" not in page and "&lt;b onmouseover=x&gt;" in page


def test_long_conclusion_is_truncated(monkeypatch):
    loop = {"status": "done", "messages": [{"role": "assistant", "content": "word " * 5000}]}
    page = _html(monkeypatch, {"Loop": loop})
    assert "Truncated: the conclusion was cut at 6000 characters." in page and page.count("word") <= 1200 + 1
    monkeypatch.setattr(gla.demisto, "context", lambda: {"Guardian": {"Loop": loop}})
    assert "cut at 6000 characters" in gla.build_entry(INCIDENT, gla.demisto.context(), "markdown")["Contents"]


def test_markdown_format_returns_the_same_content(monkeypatch):
    _install(monkeypatch, guardian=FULL, rows=[{"status": "pending", "incident_id": "4217"}])
    entry = gla.build_entry(gla.demisto.incident(), gla.demisto.context(), "markdown")
    assert set(entry) == {"Type", "ContentsFormat", "Contents"} and entry["ContentsFormat"] == "markdown"
    text = entry["Contents"]
    for expected in ("Suspicious", "70%", "Lowered by Guardian triage", "Twelve failed sign-ins", "1. Confirm the password reset",
                     "**Next step:** Close the incident after the user confirms.", "IP: 203.0.113.50", "T1110, T1078",
                     "**Conclusion:**", "The account **jdoe-example** saw 12 failures", "- password was reset at 09:14",
                     "1 action is waiting for approval", "Ticks 7", "Cost $0.0421"):
        assert expected in text, expected
    assert "<" not in text.replace("<br>", "") and "verdict" not in text and "```" not in text


def test_markdown_escapes_markup_in_the_conclusion(monkeypatch):
    loop = {"status": "done", "messages": [{"role": "assistant", "content": "<script>alert(1)</script> & done"}]}
    _install(monkeypatch, guardian={"Loop": loop})
    text = gla.build_entry(INCIDENT, gla.demisto.context(), "markdown")["Contents"]
    assert "<script" not in text and "&lt;script&gt;alert(1)&lt;/script&gt; &amp; done" in text


def test_main_uses_the_format_argument(monkeypatch):
    results = []
    _install(monkeypatch, guardian=FULL, args={"format": "markdown"})
    monkeypatch.setattr(gla.demisto, "results", results.append)
    gla.main()
    assert results[0]["ContentsFormat"] == "markdown"
    _install(monkeypatch, guardian=FULL, args={})
    gla.main()
    assert results[1]["ContentsFormat"] == "html"


def test_html_builder_failure_falls_back_to_markdown(monkeypatch):
    _install(monkeypatch, guardian=FULL)
    errors = []
    monkeypatch.setattr(gla.demisto, "error", errors.append)
    monkeypatch.setattr(gla, "render_html", lambda model: 1 / 0)
    entry = gla.build_entry(gla.demisto.incident(), gla.demisto.context())
    assert entry["ContentsFormat"] == "markdown" and "Guardian assessment" in entry["Contents"] and "Twelve failed sign-ins" in entry["Contents"]
    assert len(errors) == 1 and "HTML build failed" in errors[0]


def test_unreadable_approvals_list_leaves_the_line_out(monkeypatch):
    for reply in ([{"Type": 4, "Contents": "Error 500 from the server"}], [{"Type": 1, "Contents": "not json"}], [{"Type": 1, "Contents": '{"a": 1}'}]):
        page = _html(monkeypatch, FULL, ledger=reply)
        assert "Pending approvals" not in page and "waiting for approval" not in page and "Twelve failed sign-ins" in page
    _install(monkeypatch, guardian=FULL)

    def boom(command, args):
        raise RuntimeError("down")

    monkeypatch.setattr(gla.demisto, "executeCommand", boom)
    entry = gla.build_entry(gla.demisto.incident(), gla.demisto.context())
    assert "Pending approvals" not in entry["Contents"]
    assert "Pending approvals" not in gla.build_entry(gla.demisto.incident(), gla.demisto.context(), "markdown")["Contents"]


def test_missing_ledger_list_means_no_pending_actions(monkeypatch):
    page = _html(monkeypatch, FULL, ledger=[{"Type": 4, "Contents": "Item not found (8) on list [guardian_approvals_ledger]"}])
    assert "No actions are waiting for approval" in page


def test_no_incident_id_skips_the_ledger_read(monkeypatch):
    calls = _install(monkeypatch, incident={}, guardian=FULL)
    page = gla.build_entry({}, gla.demisto.context())["Contents"]
    assert calls == [] and "Pending approvals" not in page and "Lowered by Guardian triage" in page


def test_likely_benign_triage_without_a_verdict(monkeypatch):
    page = _html(monkeypatch, {"Triage": TRIAGE})
    assert ">Likely benign<" in page and "90%" in page
    assert ">Likely benign<" not in _html(monkeypatch, {"Triage": dict(TRIAGE, likely_benign=False)})


def test_markdown_neutralises_links_images_and_stray_fences_in_model_text(monkeypatch):
    conclusion = ("See [the report](https://evil.example/x) and ![pixel](https://evil.example/p.png).\n"
                  "[ref]: https://evil.example/ref\n\n"
                  "```\nrun this ```` then ``` and stop\n```\n"
                  "after the block")
    triage = dict(TRIAGE, summary="Open [here](https://evil.example/s) now", next_step="![x](https://evil.example/n.png)")
    loop = {"status": "done", "messages": [{"role": "assistant", "content": conclusion}]}
    _install(monkeypatch, guardian={"Triage": triage, "Loop": loop})
    text = gla.build_entry(INCIDENT, gla.demisto.context(), "markdown")["Contents"]
    assert re.search(r"(?<!\\)[\[\]]", text) is None  # every bracket is escaped, so no link, image or reference exists
    assert "\\[the report\\](https://evil.example/x)" in text  # the words stay readable, they just are not a link
    assert "\\[ref\\]: https://evil.example/ref" in text
    # stray fences in the model text cannot unbalance the blocks: the fence lines come in pairs and nothing else has ```
    lines = text.splitlines()
    fences = [line for line in lines if set(line) == {"`"}]
    assert len(fences) % 2 == 0 and all(len(line) >= 3 for line in fences)
    assert not any("```" in line for line in lines if line not in fences)
    assert "after the block" in text
    # the HTML card does not turn the text into a link either
    page = _html(monkeypatch, {"Triage": triage, "Loop": loop})
    assert "<a " not in page and "<img" not in page
