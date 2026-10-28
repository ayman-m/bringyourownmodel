import copy
import json
import re
import unittest

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
    assert "Unchanged by Guardian triage" in page and "a repaired result never changes" not in page
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


# --- the report renderer (ported from the approved prototype) -------------------------------------------------------

SAMPLE = json.loads(r"""
{
"v": 1,
"headline": "Phishing macro on WS-0142 led to credential theft, lateral movement to FS-01 and 412 MB exfiltrated over C2.",
"verdict": "malicious",
"confidence": 92,
"severity": {"from": "medium", "to": "critical", "reason": "Confirmed LSASS access, SMB lateral movement to a file server and 412 MB sent to a C2 address."},
"entities": [
{"id": "e1", "type": "email", "value": "billing@invoices.example.net", "rep": "malicious", "role": "attacker", "ref": ["t1"]},
{"id": "e2", "type": "user", "value": "jdoe@example.com", "rep": "benign", "role": "victim", "ref": ["t1", "t2"]},
{"id": "e3", "type": "host", "value": "WS-0142", "rep": "unknown", "role": "victim", "ref": ["t2"]},
{"id": "e4", "type": "file", "value": "invoice.docm", "rep": "malicious", "role": "tool", "ref": ["t1", "t5"]},
{"id": "e5", "type": "process", "value": "WINWORD.EXE", "rep": "benign", "role": "tool", "ref": ["t2"]},
{"id": "e6", "type": "process", "value": "powershell.exe", "rep": "malicious", "role": "tool", "ref": ["t2"]},
{"id": "e7", "type": "domain", "value": "cdn.example.org", "rep": "malicious", "role": "infra", "ref": ["t4", "t10"]},
{"id": "e8", "type": "ip", "value": "203.0.113.50", "rep": "malicious", "role": "infra", "ref": ["t3", "t10"]},
{"id": "e9", "type": "process", "value": "rundll32.exe", "rep": "malicious", "role": "tool", "ref": ["t2"]},
{"id": "e10", "type": "domain", "value": "update-check.example.org", "rep": "malicious", "role": "infra", "ref": ["t4", "t10"]},
{"id": "e11", "type": "ip", "value": "198.51.100.23", "rep": "malicious", "role": "infra", "ref": ["t3", "t9", "t10"]},
{"id": "e12", "type": "process", "value": "lsass.exe", "rep": "benign", "role": "asset", "ref": ["t6"]},
{"id": "e13", "type": "host", "value": "FS-01", "rep": "unknown", "role": "victim", "ref": ["t7"]},
{"id": "e14", "type": "user", "value": "svc-backup", "rep": "suspicious", "role": "victim", "ref": ["t7"]},
{"id": "e15", "type": "file", "value": "bk-0912.7z", "rep": "suspicious", "role": "tool", "ref": ["t8"]},
{"id": "e16", "type": "hash", "value": "9b2c4e71d0a85f3366c1e07ab94d5e2f1c8a7b03d6e94f2a5c1b80e3d7f6a492", "rep": "malicious", "role": "tool", "ref": ["t5"]}
],
"edges": [
{"from": "e2", "to": "e3", "rel": "logged_on", "ref": ["t2"]},
{"from": "e1", "to": "e4", "rel": "sent", "ref": ["t1"]},
{"from": "e3", "to": "e5", "rel": "ran", "ref": ["t2"]},
{"from": "e5", "to": "e4", "rel": "accessed", "ref": ["t2"]},
{"from": "e5", "to": "e6", "rel": "spawned", "ref": ["t2"]},
{"from": "e6", "to": "e7", "rel": "downloaded", "ref": ["t3", "t4"]},
{"from": "e7", "to": "e8", "rel": "resolved", "ref": ["t4"]},
{"from": "e6", "to": "e9", "rel": "spawned", "ref": ["t2"]},
{"from": "e9", "to": "e10", "rel": "resolved", "ref": ["t4"]},
{"from": "e10", "to": "e11", "rel": "resolved", "ref": ["t4"]},
{"from": "e9", "to": "e11", "rel": "connected", "ref": ["t3"]},
{"from": "e6", "to": "e12", "rel": "accessed", "ref": ["t6"]},
{"from": "e14", "to": "e13", "rel": "authenticated", "ref": ["t7"]},
{"from": "e3", "to": "e13", "rel": "connected", "ref": ["t7"]},
{"from": "e13", "to": "e15", "rel": "wrote", "ref": ["t8"]},
{"from": "e15", "to": "e11", "rel": "sent", "ref": ["t9"]}
],
"attack": [
{"tactic": "Initial Access", "tech": "T1566.001", "name": "Spearphishing Attachment", "time": "2026-10-27T21:14:08Z", "evidence": "invoice.docm from billing@invoices.example.net delivered to jdoe@example.com", "ents": ["e1", "e2", "e4"], "ref": ["t1"]},
{"tactic": "Execution", "tech": "T1059.001", "name": "PowerShell", "time": "2026-10-27T21:31:55Z", "evidence": "WINWORD.EXE spawned powershell.exe -nop -w hidden -enc with an encoded stager", "ents": ["e5", "e6"], "ref": ["t2"]},
{"tactic": "Command and Control", "tech": "T1105", "name": "Ingress Tool Transfer", "time": "2026-10-27T21:32:07Z", "evidence": "powershell.exe downloaded a.ps1 from cdn.example.org (203.0.113.50)", "ents": ["e6", "e7", "e8"], "ref": ["t3", "t4"]},
{"tactic": "Defense Evasion", "tech": "T1218.011", "name": "Rundll32", "time": "2026-10-27T21:33:40Z", "evidence": "rundll32.exe loaded upd.dll from the user Temp folder", "ents": ["e9", "e16"], "ref": ["t2", "t5"]},
{"tactic": "Command and Control", "tech": "T1071.001", "name": "Web Protocols", "time": "2026-10-27T21:34:12Z", "evidence": "HTTPS beacon about every 60s to update-check.example.org (198.51.100.23:443)", "ents": ["e9", "e10", "e11"], "ref": ["t3", "t4"]},
{"tactic": "Credential Access", "tech": "T1003.001", "name": "LSASS Memory", "time": "2026-10-27T22:02:19Z", "evidence": "powershell.exe opened lsass.exe with PROCESS_VM_READ", "ents": ["e6", "e12"], "ref": ["t6"]},
{"tactic": "Lateral Movement", "tech": "T1021.002", "name": "SMB/Windows Admin Shares", "time": "2026-10-27T22:41:03Z", "evidence": "svc-backup authenticated to FS-01 over SMB from WS-0142; PSEXESVC installed", "ents": ["e14", "e13", "e3"], "ref": ["t7"]},
{"tactic": "Collection", "tech": "T1560.001", "name": "Archive via Utility", "time": "2026-10-27T23:18:44Z", "evidence": "7z.exe built bk-0912.7z (412 MB) from the finance share on FS-01", "ents": ["e13", "e15"], "ref": ["t8"]},
{"tactic": "Exfiltration", "tech": "T1041", "name": "Exfiltration Over C2 Channel", "time": "2026-10-28T00:06:21Z", "evidence": "bk-0912.7z (412 MB) sent to 198.51.100.23 over the existing C2 session", "ents": ["e15", "e11"], "ref": ["t9"]}
],
"timeline": [
{"t": "2026-10-27T21:14:08Z", "event": "Email with invoice.docm delivered to jdoe@example.com", "src": "mail-gw", "ents": ["e1", "e2", "e4"], "tech": "T1566.001", "ref": ["t1"]},
{"t": "2026-10-27T21:31:42Z", "event": "jdoe opens invoice.docm on WS-0142 and enables the macro", "src": "edr", "ents": ["e2", "e3", "e4", "e5"], "ref": ["t2"]},
{"t": "2026-10-27T21:31:55Z", "event": "WINWORD.EXE spawns powershell.exe -enc (encoded stager)", "src": "edr", "ents": ["e5", "e6"], "tech": "T1059.001", "ref": ["t2"]},
{"t": "2026-10-27T21:32:07Z", "event": "powershell.exe resolves cdn.example.org and downloads a.ps1 from 203.0.113.50", "src": "dns", "ents": ["e6", "e7", "e8"], "tech": "T1105", "ref": ["t3", "t4"]},
{"t": "2026-10-27T21:33:40Z", "event": "a.ps1 drops upd.dll; rundll32.exe loads it", "src": "edr", "ents": ["e9", "e16"], "tech": "T1218.011", "ref": ["t2", "t5"]},
{"t": "2026-10-27T21:34:12Z", "event": "First beacon to update-check.example.org (198.51.100.23:443)", "src": "firewall", "ents": ["e9", "e10", "e11"], "tech": "T1071.001", "ref": ["t3", "t4"]},
{"t": "2026-10-27T22:02:19Z", "event": "powershell.exe opens a handle on lsass.exe with PROCESS_VM_READ", "src": "edr", "ents": ["e6", "e12"], "tech": "T1003.001", "ref": ["t6"]},
{"t": "2026-10-27T22:41:03Z", "event": "svc-backup logs on to FS-01 over SMB (type 3) from WS-0142", "src": "auth", "ents": ["e14", "e13", "e3"], "tech": "T1021.002", "ref": ["t7"]},
{"t": "2026-10-27T22:41:30Z", "event": "PSEXESVC service starts on FS-01 and spawns cmd.exe", "src": "edr", "ents": ["e13"], "tech": "T1021.002", "ref": ["t7"]},
{"t": "2026-10-27T23:18:44Z", "event": "7z.exe creates bk-0912.7z (412 MB) from the finance share", "src": "edr", "ents": ["e13", "e15"], "tech": "T1560.001", "ref": ["t8"]},
{"t": "2026-10-28T00:06:21Z", "event": "bk-0912.7z leaves FS-01 for 198.51.100.23 over the C2 session", "src": "netflow", "ents": ["e15", "e11"], "tech": "T1041", "ref": ["t9"]},
{"t": "2026-10-28T00:07:02Z", "event": "EDR alert Suspicious PowerShell raised for WS-0142", "src": "edr", "ents": ["e3"], "ref": ["t2"]},
{"t": "2026-10-28T00:31:50Z", "event": "Threat intel marks 198.51.100.23 and cdn.example.org as known C2 and staging", "src": "ti", "ents": ["e7", "e11"], "ref": ["t10"]},
{"t": "2026-10-28T00:44:09Z", "event": "C2 session from FS-01 still open at the last check", "src": "netflow", "ents": ["e13", "e11"], "ref": ["t9"]}
],
"tree": [
{"id": "n1", "parent": null, "ent": "e5", "name": "WINWORD.EXE", "cmd": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" \"C:\\Users\\jdoe\\Downloads\\invoice.docm\"", "pid": "5120", "ref": ["t2"]},
{"id": "n2", "parent": "n1", "ent": "e6", "name": "powershell.exe", "cmd": "powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA==", "pid": "6644", "flag": "malicious", "tech": "T1059.001", "ref": ["t2"]},
{"id": "n3", "parent": "n2", "ent": "e9", "name": "rundll32.exe", "cmd": "rundll32.exe C:\\Users\\jdoe\\AppData\\Local\\Temp\\upd.dll,Start", "pid": "7032", "flag": "malicious", "tech": "T1218.011", "ref": ["t2"]},
{"id": "n4", "parent": "n2", "name": "nltest.exe", "cmd": "nltest.exe /dclist:example.com", "pid": "7410", "flag": "suspicious", "ref": ["t2"]},
{"id": "n5", "parent": null, "ent": null, "name": "services.exe", "pid": "712", "ref": ["t7"]},
{"id": "n6", "parent": "n5", "name": "PSEXESVC.exe", "cmd": "C:\\Windows\\PSEXESVC.exe", "pid": "3380", "flag": "malicious", "tech": "T1021.002", "ref": ["t7"]},
{"id": "n7", "parent": "n6", "name": "cmd.exe", "cmd": "cmd.exe /c 7z.exe a -mhe=on C:\\ProgramData\\bk-0912.7z D:\\Finance\\*", "pid": "4216", "flag": "suspicious", "ref": ["t8"]},
{"id": "n8", "parent": "n7", "name": "7z.exe", "cmd": "7z.exe a -mhe=on C:\\ProgramData\\bk-0912.7z D:\\Finance\\*", "pid": "4288", "flag": "malicious", "tech": "T1560.001", "ref": ["t8"]},
{"id": "n9", "parent": "n7", "name": "rundll32.exe", "cmd": "rundll32.exe C:\\ProgramData\\upd.dll,Send", "pid": "4390", "flag": "malicious", "tech": "T1041", "ref": ["t9"]}
],
"findings": [
{"text": "The macro in invoice.docm ran an encoded PowerShell stager that fetched a.ps1 from cdn.example.org (203.0.113.50), which threat intel lists as staging infrastructure.", "ref": ["t2", "t4", "t10"]},
{"text": "rundll32.exe loaded upd.dll and beacons about every 60 seconds to update-check.example.org (198.51.100.23:443).", "ref": ["t3", "t5"]},
{"text": "powershell.exe read LSASS memory on WS-0142; the svc-backup account was then used from that host to log on to FS-01 over SMB.", "ref": ["t6", "t7"]},
{"text": "A 412 MB 7z archive of the finance share was created on FS-01 and sent to 198.51.100.23 over the same C2 channel.", "ref": ["t8", "t9"]},
{"text": "No other hosts in the subnet show the same beacon pattern, so the intrusion is probably limited to these two hosts."}
],
"actions": [
{"p": 1, "action": "Isolate WS-0142 and FS-01 from the network", "owner": "guardian", "approval": true, "cmd": "!core-isolate-endpoint endpoint_id=WS-0142"},
{"p": 1, "action": "Block 198.51.100.23 and 203.0.113.50 at the perimeter", "owner": "guardian", "approval": true, "cmd": "!pan-os-register-ip-tag tag=guardian-block ip=198.51.100.23,203.0.113.50"},
{"p": 1, "action": "Disable svc-backup and reset the password of jdoe", "owner": "analyst", "approval": true, "cmd": "!ad-disable-account username=svc-backup"},
{"p": 2, "action": "Purge the phishing email from every mailbox", "owner": "guardian", "approval": true, "cmd": "!ews-delete-items item-ids=<ids from search>"},
{"p": 3, "action": "Hunt the upd.dll hash and a.ps1 across the fleet", "owner": "analyst", "approval": false, "cmd": "!core-xql-generic-query query=\"dataset=xdr_data | filter action_file_sha256 = '9b2c4e71...'\""}
],
"gaps": [
"The contents of bk-0912.7z are unknown: the EDR returned no file listing, so the data loss is not yet scoped.",
"Delivery of the phishing email to other recipients was not checked; the mail gateway query returned only jdoe."
],
"refs": {
"t1": {"tool": "gmail-get-message", "summary": "From billing@invoices.example.net to jdoe@example.com with attachment invoice.docm"},
"t2": {"tool": "core-get-process-tree", "summary": "WINWORD.EXE > powershell.exe -enc > rundll32.exe on WS-0142"},
"t3": {"tool": "core-network-events", "summary": "Outbound 443 to 203.0.113.50 and 198.51.100.23 from WS-0142"},
"t4": {"tool": "core-xql-generic-query", "summary": "DNS lookups for cdn.example.org and update-check.example.org"},
"t5": {"tool": "core-get-file-details", "summary": "upd.dll sha256 9b2c4e71..., written to Temp by powershell.exe"},
"t6": {"tool": "core-get-memory-access", "summary": "powershell.exe opened lsass.exe PROCESS_VM_READ"},
"t7": {"tool": "ad-get-logon-events", "summary": "4624 type 3 for svc-backup on FS-01 from WS-0142"},
"t8": {"tool": "core-get-file-events", "summary": "7z.exe created C:\\ProgramData\\bk-0912.7z (412 MB)"},
"t9": {"tool": "netflow-query", "summary": "412 MB from FS-01 to 198.51.100.23:443 between 00:06 and 00:19"},
"t10": {"tool": "threat-intel-lookup", "summary": "198.51.100.23, 203.0.113.50 and both domains match known C2 and staging lists"}
}
}
""")
META = {
 "model": "example-model-35b",
 "turns": 14,
 "tokens": 61230,
 "cost": 0.1832,
 "run_id": "GR-4821-7f3a2c",
 "incident": {
  "id": "4821",
  "name": "Suspicious PowerShell on WS-0142",
  "type": "Guardian Alert",
  "owner": "unassigned"
 }
}

XSS = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "' onmouseover='x", "</td></tr></table><b>"]


def assert_safe(tc, out):
    tc.assertNotIn("<script", out.lower())
    tc.assertNotRegex(out, r"<img[^>]+onerror", "raw onerror attribute")
    tc.assertNotIn("<img", out.lower())
    # every tag in the output must come from the renderer's own whitelist
    for tag in re.findall(r"</?([a-zA-Z0-9]+)", out):
        tc.assertIn(tag.lower(), gla.ALLOWED_TAGS)
    for tag in re.findall(r"<[a-zA-Z][^>]*>", out):
        if re.search(r"\son[a-z]+\s*=", tag):
            tc.fail("event attribute in %s" % tag)


class Robust(unittest.TestCase):
    def test_sample_renders(self):
        out = gla.render_report(SAMPLE, META)
        self.assertIsInstance(out, str)
        assert_safe(self, out)
        self.assertIn("Phishing macro", out)

    def test_garbage_never_raises(self):
        garbage = [None, 5, "x", [], {}, {"entities": "x"}, {"entities": [1, None, "a", {}]},
                   {"edges": {"a": 1}, "attack": [None], "timeline": "t", "tree": [{"id": 5}], "refs": [1, 2]},
                   {"confidence": "92", "verdict": 7}, {"confidence": 150, "headline": ["x"]},
                   {"confidence": True}, {"severity": "high"}, {"actions": [{"p": "x", "approval": "no"}]},
                   {"findings": [{"text": None, "ref": "t1"}]}, {"gaps": [1, None, {"a": 1}]}]
        for g in garbage:
            for m in (META, None, "x", {}, {"incident": "x", "tokens": "abc", "cost": object()}):
                out = gla.render_report(g, m)
                self.assertTrue(out is None or isinstance(out, str))

    def test_empty_returns_none(self):
        self.assertIsNone(gla.render_report({}, META))
        self.assertIsNone(gla.render_report(None, META))
        self.assertIsNone(gla.render_report({"entities": "x"}, META))

    def test_confidence_coercion(self):
        out = gla.render_report({"headline": "h", "verdict": "malicious", "confidence": "92"}, {})
        self.assertIn("92%", out)
        out = gla.render_report({"headline": "h", "confidence": 150}, {})
        self.assertIn("100%", out)
        out = gla.render_report({"headline": "h", "confidence": "abc"}, {})
        self.assertNotIn("abc", out)

    def test_xss_everywhere(self):
        for payload in XSS:
            r = copy.deepcopy(SAMPLE)
            r["headline"] = payload
            r["severity"]["reason"] = payload
            for k in ("entities", "edges", "attack", "timeline", "tree", "findings", "actions"):
                for item in r[k]:
                    for f, v in list(item.items()):
                        if isinstance(v, str) and f not in ("id", "from", "to", "parent", "ent", "p", "rel", "type", "rep",
                                                           "role", "owner", "flag", "tactic"):
                            item[f] = payload
                    if "tactic" in item:
                        item["tactic"] = payload
            r["gaps"] = [payload]
            r["refs"] = {k: {"tool": payload, "summary": payload} for k in r["refs"]}
            m = copy.deepcopy(META)
            for k in ("model", "run_id"):
                m[k] = payload
            m["incident"] = {k: payload for k in m["incident"]}
            out = gla.render_report(r, m)
            self.assertIsNotNone(out)
            assert_safe(self, out)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", out) if payload.startswith("<script") else None

    def test_hostile_ids_and_enums(self):
        r = copy.deepcopy(SAMPLE)
        r["entities"][0]["id"] = '"><script>'
        r["entities"][1]["type"] = '"><script>'
        r["entities"][2]["rep"] = 'red;background:url(x)'
        r["verdict"] = '"><script>'
        r["severity"] = {"from": "<b>", "to": "<i>"}
        out = gla.render_report(r, META)
        assert_safe(self, out)
        self.assertNotIn("url(x)", out)

    def test_unknown_edges_and_refs_dropped(self):
        r = copy.deepcopy(SAMPLE)
        r["edges"] += [{"from": "e1", "to": "zz", "rel": "ran", "ref": ["t1"]}, {"from": "e1", "to": "e1", "rel": "ran"}]
        r["findings"][0]["ref"] = ["t99"]
        c = gla._Ctx(r, META)
        self.assertEqual(len(c.get("edges")), 16)
        self.assertEqual(c.get("findings")[0]["ref"], [])
        out = gla.render_report(r, META)
        self.assertIn("unverified", out)

    def test_caps(self):
        r = copy.deepcopy(SAMPLE)
        r["entities"] = [{"id": "e%d" % i, "type": "host", "value": "h%d" % i, "ref": ["t1"]} for i in range(60)]
        r["edges"] = [{"from": "e%d" % i, "to": "e%d" % (i + 1), "rel": "ran", "ref": ["t1"]} for i in range(59)]
        r["attack"] = r["attack"] * 4
        r["timeline"] = r["timeline"] * 4
        r["tree"] = [{"id": "n%d" % i, "parent": "n%d" % (i - 1) if i else None, "name": "p%d" % i} for i in range(80)]
        r["findings"] = r["findings"] * 5
        r["actions"] = r["actions"] * 5
        r["gaps"] = r["gaps"] * 5
        c = gla._Ctx(r, META)
        self.assertLessEqual(len(c.get("entities")), 20)
        self.assertLessEqual(len(c.get("edges")), 30)
        self.assertLessEqual(len(c.get("attack")), 15)
        self.assertLessEqual(len(c.get("timeline")), 25)
        self.assertLessEqual(len(c.get("tree")), 30)
        self.assertLessEqual(len(c.get("findings")), 10)
        self.assertLessEqual(len(c.get("actions")), 8)
        self.assertLessEqual(len(c.get("gaps")), 5)
        out = gla.render_report(r, META)
        self.assertIsInstance(out, str)

    def test_tree_cycles(self):
        r = {"tree": [{"id": "a", "parent": "b", "name": "A"}, {"id": "b", "parent": "a", "name": "B"},
                      {"id": "c", "parent": "c", "name": "C"}, {"id": "d", "parent": "zz", "name": "D"}]}
        out = gla.render_report(r, {})
        for n in "ABCD":
            self.assertIn(">%s<" % n, out)

    def test_cyclic_edges(self):
        r = copy.deepcopy(SAMPLE)
        r["edges"] += [{"from": "e11", "to": "e9", "rel": "sent"}, {"from": "e8", "to": "e7", "rel": "sent"},
                       {"from": "e4", "to": "e1", "rel": "sent"}]
        out = gla.render_report(r, META)
        self.assertIsInstance(out, str)


class Graph(unittest.TestCase):
    def check_rows(self, report):
        c = gla._Ctx(report, META)
        graph = gla._graph(c)
        rows, width = graph["rows"], graph["width"]
        self.assertTrue(rows)
        # rowspans: every column position is covered exactly once per row
        nrows = len(rows)
        occupancy = [[0] * width for _ in range(nrows)]
        for r, row in enumerate(rows):
            for cell in row:
                for dr in range(cell["rs"]):
                    for dc in range(cell["cs"]):
                        occupancy[r + dr][cell["x"] + dc] += 1
        for line in occupancy:
            self.assertEqual(line, [1] * width)
        return c, rows

    def test_sample_widths(self):
        c, rows = self.check_rows(SAMPLE)
        out = gla.render_report(SAMPLE, META)
        for e in c.get("entities"):
            self.assertIn(gla._hx(e["value"][:10]), out)

    def test_every_entity_visible(self):
        c = gla._Ctx(SAMPLE, META)
        html_ = gla._sec_graph(c)
        for e in c.get("entities"):
            self.assertIn(gla._hx(gla._shorten(e["value"], e["type"])), html_)

    def test_duplicate_marker(self):
        html_ = gla._sec_graph(gla._Ctx(SAMPLE, META))
        self.assertGreaterEqual(html_.count("&#8634;"), 2)

    def test_random_graphs(self):
        import random
        rnd = random.Random(7)
        types = ["user", "host", "process", "file", "ip", "domain", "email", "hash", "cloud", "other", "url"]
        for _ in range(60):
            n = rnd.randint(2, 20)
            ents = [{"id": "e%d" % i, "type": rnd.choice(types), "value": "v%d" % i, "ref": ["t1"]} for i in range(n)]
            edges = [{"from": "e%d" % rnd.randrange(n), "to": "e%d" % rnd.randrange(n), "rel": "ran"}
                     for _ in range(rnd.randint(0, 30))]
            rep = {"entities": ents, "edges": edges, "refs": {"t1": {"tool": "x", "summary": "y"}}}
            c = gla._Ctx(rep, META)
            if c.get("edges"):
                self.check_rows(rep)
            html_ = gla._sec_graph(c)
            for e in c.get("entities"):
                if html_:
                    self.assertIn(gla._hx(e["value"]), html_)

    def test_row_cap(self):
        ents = [{"id": "e%d" % i, "type": "user", "value": "u%d" % i} for i in range(20)]
        ents += [{"id": "h%d" % i, "type": "host", "value": "hh%d" % i} for i in range(1)]
        edges = [{"from": "e%d" % i, "to": "h0", "rel": "ran"} for i in range(20)]
        out = gla.render_report({"entities": ents, "edges": edges}, {})
        self.assertIsInstance(out, str)


class Time(unittest.TestCase):
    def test_date_once_per_day(self):
        out = gla._sec_timeline(gla._Ctx(SAMPLE, META))
        self.assertEqual(out.count("2026-10-27"), 1)
        self.assertEqual(out.count("2026-10-28"), 1)


class Tactics(unittest.TestCase):
    def test_slots(self):
        for name, slot in (("Initial Access", 2), ("initial-access", 2), ("TA0001", 2), ("C2", 11), ("Command and Control", 11),
                           ("lateral movement", 9), ("Exfil", 12), ("bogus", None), (None, None), (5, None)):
            self.assertEqual(gla._tactic_slot(name), slot, name)


# --- the report page ---------------------------------------------------------------------------------------------------

RUN = dict(LOOP, run_id="4217")
RECORD = {"v": 1, "run_id": "4217", "tick": 7, "model": "model-x", "calls": 3, "errors": [], "report": SAMPLE, "refs": SAMPLE["refs"]}
WITH_REPORT = {"Triage": TRIAGE, "TriageApply": APPLY, "Loop": RUN, "Report": RECORD}


def _entry(monkeypatch, guardian, output_format="html", part="all", **kwargs):
    """The whole page by default: the tests of one part say so."""
    _install(monkeypatch, guardian=guardian, **kwargs)
    return gla.build_entry(gla.demisto.incident(), gla.demisto.context(), output_format, part)


def _is_report(page):
    return "CAUSALITY CHAIN" in page and "Kill chain".upper() in page


def _is_card(page):
    return "Twelve failed sign-ins" in page and "CAUSALITY CHAIN" not in page


def test_a_report_of_this_run_is_the_page(monkeypatch):
    entry = _entry(monkeypatch, WITH_REPORT)
    page = entry["Contents"]
    assert entry["ContentsFormat"] == "html" and entry["Type"] == 1
    assert _is_report(page) and "Phishing macro" in page and "powershell.exe" in page
    assert_safe(unittest.TestCase(), page)


def test_the_header_is_the_runs_own_not_the_reports(monkeypatch):
    # the report says malicious, 92%, medium to critical; the run says Suspicious, 70%, high lowered to low
    page = _entry(monkeypatch, WITH_REPORT)["Contents"]
    header = page[:page.index("KILL CHAIN")]
    assert "SUSPICIOUS" in header and ">70%<" in header and "MALICIOUS" not in header and ">92%<" not in header
    assert ">HIGH<" in header and ">LOW<" in header and "CRITICAL" not in header
    assert "Lowered by Guardian triage" in header and "lowered from high to low" not in header
    assert "#4217" in header and "Repeated failed sign-ins for jdoe-example" in header
    assert "123,456" in header and "$0.0421" in header and "Investigation turns" in header
    footer = page[page.rindex("model"):]
    assert "model-x" in footer and "run 4217" in footer


def test_the_header_of_an_unchanged_severity_is_one_badge(monkeypatch):
    guardian = dict(WITH_REPORT, TriageApply={})
    header = _entry(monkeypatch, guardian)["Contents"].split("KILL CHAIN")[0]
    assert header.count("&#9656;") == 0 and ">HIGH<" in header and "Not changed by Guardian" in header


def test_a_report_of_an_earlier_run_never_shows(monkeypatch):
    for record in (dict(RECORD, run_id="4000"), dict(RECORD, run_id=""), {k: v for k, v in RECORD.items() if k != "run_id"},
                   dict(RECORD, tick=3)):
        assert _is_card(_entry(monkeypatch, dict(WITH_REPORT, Report=record))["Contents"]), record.get("run_id")
    assert _is_card(_entry(monkeypatch, dict(WITH_REPORT, Loop=dict(LOOP)))["Contents"])           # the run state has no run id
    assert _is_card(_entry(monkeypatch, dict(WITH_REPORT, Loop=dict(RUN, run_id="9999")))["Contents"])


def test_a_rerun_with_the_same_run_id_and_tick_but_another_fingerprint_shows_the_card(monkeypatch):
    record = dict(RECORD, fingerprint="aaa")
    same = dict(WITH_REPORT, Report=record, Loop=dict(RUN, last_assistant_fingerprint="aaa"))
    assert _is_report(_entry(monkeypatch, same)["Contents"])
    other = dict(WITH_REPORT, Report=record, Loop=dict(RUN, last_assistant_fingerprint="bbb"))
    assert _is_card(_entry(monkeypatch, other)["Contents"])
    for loop_fingerprint in (None, ""):        # a side without a fingerprint is judged by run id and tick alone
        unmarked = dict(WITH_REPORT, Report=record, Loop=dict(RUN, last_assistant_fingerprint=loop_fingerprint))
        assert _is_report(_entry(monkeypatch, unmarked)["Contents"])


def test_a_report_without_a_tick_is_judged_by_the_run_id_alone(monkeypatch):
    record = {k: v for k, v in RECORD.items() if k != "tick"}
    assert _is_report(_entry(monkeypatch, dict(WITH_REPORT, Report=record))["Contents"])


def test_a_failed_report_step_shows_the_card_unchanged(monkeypatch):
    failed = {"v": 1, "run_id": "4217", "tick": 7, "report": None, "refs": {}, "errors": ["core: no usable JSON"]}
    with_failure = _entry(monkeypatch, dict(WITH_REPORT, Report=failed))["Contents"]
    without = _entry(monkeypatch, {"Triage": TRIAGE, "TriageApply": APPLY, "Loop": RUN})["Contents"]
    assert with_failure == without and _is_card(with_failure)
    for record in ({}, [], "x", {"report": {}}, {"report": "x", "run_id": "4217"}):
        assert _is_card(_entry(monkeypatch, dict(WITH_REPORT, Report=record))["Contents"])


def test_a_report_the_renderer_cannot_draw_shows_the_card(monkeypatch):
    record = dict(RECORD, report={"entities": "x", "headline": ""}, refs={})
    guardian = dict(WITH_REPORT, Report=record, Loop=dict(RUN, verdict=None), Triage={"summary": "Twelve failed sign-ins."})
    assert gla.render_report({"entities": "x"}, {}) is None
    page = _entry(monkeypatch, guardian)["Contents"]
    assert "CAUSALITY CHAIN" not in page and "Twelve failed sign-ins" in page


def test_an_error_while_drawing_the_report_shows_the_card(monkeypatch):
    def boom(*_args):
        raise RuntimeError("renderer broke")

    monkeypatch.setattr(gla, "render_report", boom)
    assert _is_card(_entry(monkeypatch, WITH_REPORT)["Contents"])


def test_markdown_format_is_the_card_even_with_a_report(monkeypatch):
    entry = _entry(monkeypatch, WITH_REPORT, "markdown")
    assert entry["ContentsFormat"] == "markdown" and entry["Contents"].startswith("### Guardian assessment")
    assert "Phishing macro" not in entry["Contents"]


def test_the_report_page_adds_no_context_list_or_incident_write(monkeypatch):
    calls = _install(monkeypatch, guardian=WITH_REPORT)
    gla.build_entry(gla.demisto.incident(), gla.demisto.context())
    assert all(command == "getList" for command, _ in calls)


def test_more_than_sixty_references_are_all_kept():
    refs = {"t%d" % i: {"tool": "tool%d" % i, "summary": "s"} for i in range(1, 121)}
    report = {"headline": "h", "findings": [{"text": "late fact", "ref": ["t120"]}], "refs": refs}
    out = gla.render_report(report, {})
    assert "t120 tool120" in out and "unverified" not in out


def _tree_rows(markup):
    """For each row of the causality chain: (text of the prefix cell's lines, name)."""
    section = markup[markup.index("CAUSALITY CHAIN"):]
    cells = re.findall(r'<table cellspacing="0" style="width:100%"><tr><td valign="top" style="width:1px;[^"]*">(.*?)</td>'
                       r'<td valign="top" style="[^"]*">(.*?)</td></tr></table>', section)
    rows = []
    for prefix, name in cells:
        text = re.sub(r"<[^>]+>", "", prefix.replace("<br>", "\n")).replace("&nbsp;", " ").replace("\xa0", " ")
        rows.append((text.split("\n"), re.sub(r"<[^>]+>", "", name.split("</b>")[0] + "</b>").replace("&nbsp;", " ").strip()))
    return rows


TREE = [
    {"id": "n1", "parent": None, "name": "root.exe", "cmd": "root.exe --start"},
    {"id": "n2", "parent": "n1", "name": "a.exe", "cmd": "a.exe -x"},
    {"id": "n3", "parent": "n2", "name": "c.exe"},
    {"id": "n4", "parent": "n2", "name": "d.exe", "cmd": "d.exe -y"},
    {"id": "n5", "parent": "n1", "name": "e.exe"},
    {"id": "n6", "parent": "n5", "name": "f.exe", "cmd": "f.exe -z"},
    {"id": "n7", "parent": "n6", "name": "g.exe"},
]


def test_each_child_row_is_one_step_further_in_and_the_guides_line_up():
    rows = _tree_rows(gla.render_report({"tree": TREE}, {}))
    assert [name for _prefix, name in rows] == ["root.exe", "a.exe", "c.exe", "d.exe", "e.exe", "f.exe", "g.exe"]
    first_lines = [prefix[0] for prefix, _name in rows]
    assert first_lines == ["", "├─ ", "│  ├─ ", "│  └─ ", "└─ ",
                           "   └─ ", "      └─ "]
    depth = [0, 1, 2, 2, 1, 2, 3]
    for first, level in zip(first_lines, depth):
        assert len(first) == 3 * level                                  # the name starts one step (3 columns) per level in
    # a branch mark sits under the first column of its parent's name: parent's name column = 3 * (child depth - 1)
    for first, level in zip(first_lines, depth):
        if level:
            assert first[3 * (level - 1)] in "├└" and first[3 * (level - 1) + 1] == "─"
    # the second line of a row (its command) starts under its name, and a pipe continues the node's own branch
    seconds = {name: prefix[1] for prefix, name in rows if len(prefix) > 1}
    assert seconds == {"root.exe": "", "a.exe": "│  ", "d.exe": "│  " + "   ", "f.exe": "   " + "   "}
    for name, line in seconds.items():
        level = depth[[n for _p, n in rows].index(name)]
        assert len(line) == 3 * level


def test_the_tree_is_one_small_table_per_node_so_no_column_is_shared():
    out = gla.render_report({"tree": TREE}, {})
    assert out.count('<td valign="top" style="width:1px;') == len(TREE)


def test_a_tree_row_names_its_command_and_reference_and_flags_a_bad_process():
    out = gla.render_report({"tree": [{"id": "n1", "name": "ps.exe", "flag": "malicious", "pid": 12, "tech": "T1059.001",
                                      "cmd": "ps.exe -enc AAA", "ref": ["t1"]}], "refs": {"t1": {"tool": "x", "summary": "y"}}}, {})
    assert gla._tint("red") in out and "[12]" in out and "T1059.001" in out and "ps.exe -enc AAA" in out and "\u2713 1 ref" in out


def test_the_layout_script_stays_self_contained():
    source = open(gla.__file__).read()
    assert "GUARDIAN_COMMON" not in source and "guardian_execute" not in source
    assert set(re.findall(r"^(?:import|from) (\w+)", source, re.M)) == {"html", "json", "math", "re", "demistomock", "CommonServerPython"}


# --- the premium page: layout rules, the map, the severity line ------------------------------------------------------------

def _render(report, meta=None):
    out = gla.render_report(report, META if meta is None else meta)
    assert out is not None
    return out


def test_fills_are_only_ever_on_spans_and_every_colour_comes_from_the_palette():
    out = _render(SAMPLE)
    for tag in ("td", "div", "table", "tr", "details", "summary", "b"):
        for match in re.findall(r"<{}\b[^>]*>".format(tag), out):
            assert "background" not in match, match
    assert 'background' in out and "<span" in out
    solids = {value[0].lower() for value in gla.PAL.values()}
    for color in re.findall(r"#[0-9a-fA-F]{6}\b", out):
        assert color.lower() in solids, color
    allowed = {value[1] for value in gla.PAL.values()} | {value[2] for value in gla.PAL.values()} | {gla.LINE, "rgba(255,255,255,.3)"}
    for color in re.findall(r"rgba\([^)]*\)", out):
        assert color in allowed, color


def test_every_filled_element_also_has_a_border_or_a_text_colour_of_its_own():
    out = _render(SAMPLE)
    for style in re.findall(r'<span style="([^"]*background[^"]*)"', out):
        assert "border" in style or "color:" in style, style


def test_no_light_hex_fill_and_no_inline_font_family_but_monospace():
    out = _render(SAMPLE)
    assert not re.search(r"background:#", out.replace("background:#e5484d", "").replace("background:#f76b15", "").replace(
        "background:#2f80ed", "").replace("background:#2f9e63", "").replace("background:#d18b00", "").replace("background:#7f8791", "")
        .replace("background:#8e5bd9", "").replace("background:#14a39a", ""))
    assert set(re.findall(r"font-family:([a-z]+)", out)) == {"monospace"}


def test_section_cards_are_rounded_have_an_uppercase_title_and_a_count_badge():
    out = _render(SAMPLE)
    for title, count in (("KILL CHAIN", "8 of 14 tactics"), ("ATTACK CHAIN", "9 steps"), ("RELATIONSHIP MAP", "16 entities"),
                         ("CAUSALITY CHAIN", "9 processes"), ("TIMELINE", "14 events"), ("FINDINGS", ">5<"),
                         ("RECOMMENDED ACTIONS", ">5<"), ("GAPS", ">2<")):
        assert title in out and count in out, title
    assert out.count("border-radius:8px;font-size:13px") >= 8


def test_the_kill_chain_is_fourteen_equal_cells_with_solid_active_and_tinted_inactive_tactics():
    out = _render(SAMPLE)
    chain = out[out.index("KILL CHAIN"):out.index("ATTACK CHAIN")]
    assert chain.count('style="width:7.14%') == 14
    active = [m for m in re.findall(r'<span style="([^"]*)">', chain) if "background:#f76b15;color:#fff" in m]
    assert len(active) == 8
    assert chain.count("background:{};color:{};border-radius:7px".format(gla._tint("grey"), gla.GREY)) == 6


def test_attack_cards_share_the_full_row():
    for count, per in ((1, 1), (2, 2), (3, 3), (4, 4), (5, 4), (9, 4)):
        report = {"attack": [{"tactic": "Execution", "name": "n%d" % i, "ref": ["t1"]} for i in range(count)],
                  "refs": {"t1": {"tool": "x", "summary": "y"}}}
        chain = gla._sec_attack(gla._Ctx(report, {}))
        widths = [float(w) for w in re.findall(r'<td valign="top" style="width:([\d.]+)%;border:1px solid', chain)]
        assert len(widths) == count and len(set(widths)) == 1
        arrows = 2.6 * (per - 1)
        assert abs(widths[0] * per + arrows - 100.0) < 0.1, (count, widths)


def _graph_report(entities, edges):
    return {"entities": [dict(e, ref=["t1"]) for e in entities], "edges": [dict(e, ref=["t1"]) for e in edges],
            "refs": {"t1": {"tool": "x", "summary": "y"}}}


ENTS = [{"id": "e1", "type": "user", "value": "jdoe"}, {"id": "e2", "type": "process", "value": "a.exe"},
        {"id": "e3", "type": "host", "value": "WS-1"}, {"id": "e4", "type": "ip", "value": "203.0.113.9"}]


def test_a_column_nobody_is_in_is_not_drawn():
    report = _graph_report(ENTS[:2], [{"from": "e1", "to": "e2", "rel": "ran"}])
    graph = gla._graph(gla._Ctx(report, {}))
    assert graph["cols"] == ["Identity", "Process / File"] and graph["width"] == 3
    page = gla._sec_graph(gla._Ctx(report, {}))
    for dropped in ("HOST", "INDICATOR", "EXTERNAL", "NOT LINKED"):
        assert ">{}<".format(dropped) not in page, dropped
    assert ">IDENTITY<" in page and ">PROCESS / FILE<" in page


def test_an_edge_over_a_dropped_column_spans_it():
    report = _graph_report([ENTS[0], ENTS[3]], [{"from": "e1", "to": "e4", "rel": "connected"}])
    graph = gla._graph(gla._Ctx(report, {}))
    assert graph["cols"] == ["Identity", "External"] and graph["width"] == 3
    conn = [cell for row in graph["rows"] for cell in row if cell["kind"] == "conn"]
    assert len(conn) == 1 and conn[0]["cs"] == 1


def test_entities_with_no_relationship_get_their_own_dashed_column_on_the_right():
    report = _graph_report(ENTS, [{"from": "e1", "to": "e2", "rel": "ran"}])
    c = gla._Ctx(report, {})
    graph = gla._graph(c)
    assert graph["cols"] == ["Identity", "Process / File", "Not linked"] and graph["width"] == 5
    assert [e["value"] for e in graph["unlinked"]] == ["WS-1", "203.0.113.9"]
    cells = [(r, cell) for r, row in enumerate(graph["rows"]) for cell in row if cell["kind"] == "unlinked"]
    assert [(r, cell["x"]) for r, cell in cells] == [(0, 4), (1, 4)]
    page = gla._sec_graph(c)
    assert ">NOT LINKED<" in page and page.count("dashed") >= 4
    for value in ("WS-1", "203.0.113.9"):
        assert value in page
    # the linked entities' nodes are solid, not dashed
    assert page.count("border:1px solid") >= 2


def test_more_unlinked_entities_than_rows_add_rows_and_still_tile_the_grid():
    ents = ENTS[:2] + [{"id": "u%d" % i, "type": "domain", "value": "d%d.example" % i} for i in range(6)]
    c = gla._Ctx(_graph_report(ents, [{"from": "e1", "to": "e2", "rel": "ran"}]), {})
    graph = gla._graph(c)
    assert len(graph["rows"]) == 6 and len(graph["unlinked"]) == 6
    occupancy = [[0] * graph["width"] for _ in graph["rows"]]
    for r, row in enumerate(graph["rows"]):
        for cell in row:
            for dr in range(cell["rs"]):
                for dc in range(cell["cs"]):
                    occupancy[r + dr][cell["x"] + dc] += 1
    assert all(line == [1] * graph["width"] for line in occupancy)


def test_with_no_relationship_at_all_the_entities_are_a_dashed_group_and_the_page_says_so():
    c = gla._Ctx(_graph_report(ENTS, []), {})
    graph = gla._graph(c)
    assert graph["rows"] == [] and len(graph["unlinked"]) == 4
    page = gla._sec_graph(c)
    assert "No relationships were reported." in page and page.count("dashed") >= 8
    for e in ENTS:
        assert e["value"] in page


def test_a_node_has_a_type_tag_a_coloured_edge_and_the_reputation_word():
    c = gla._Ctx(_graph_report([dict(ENTS[1], rep="malicious", role="tool"), dict(ENTS[0], role="victim")], []), {})
    page = gla._sec_graph(c)
    assert "PROC" in page and "USER" in page and "malicious" in page and "victim" in page
    assert "border-left:4px dashed {}".format(gla._col("red")) in page and "border-left:4px dashed {}".format(gla._col("blue")) in page


def _header(monkeypatch, apply_record, severity=3):
    guardian = {"Triage": TRIAGE, "TriageApply": apply_record, "Loop": RUN, "Report": RECORD}
    _install(monkeypatch, guardian=guardian, incident=dict(INCIDENT, severity=severity))
    page = gla.build_entry(gla.demisto.incident(), gla.demisto.context())["Contents"]
    return page[:page.index("KILL CHAIN")]


def test_an_unchanged_severity_reads_as_one_pill_and_unchanged_by_triage(monkeypatch):
    unchanged = dict(APPLY, severity_before="high", severity_after="high",
                     reason="severity: the severity is already high; phase: Guardian triage: endpoint_threat")
    header = _header(monkeypatch, unchanged)
    assert ">HIGH<" in header and header.count("&#9656;") == 0 and "Unchanged by Guardian triage" in header
    assert "severity: the severity is already high" not in header and "phase:" not in header


def test_a_raised_severity_reads_from_to_and_raised_by_triage(monkeypatch):
    header = _header(monkeypatch, dict(APPLY, severity_before="medium", severity_after="high", reason="long reason text"))
    assert ">MEDIUM<" in header and ">HIGH<" in header and header.count("&#9656;") == 1
    assert "Raised by Guardian triage" in header and "long reason text" not in header


def test_the_severity_text_of_the_card_still_says_why_when_triage_skipped_the_incident(monkeypatch):
    skipped = {"status": "skipped", "severity_before": "high", "severity_after": "high", "reason": "the incident already has an owner"}
    assert gla._severity_change({"severity": 3}, skipped)[2] == "Unchanged: the incident already has an owner"
    assert gla._severity_change({"severity": 3}, None)[2] == "Severity was not changed by Guardian in this run."
    applied = gla._severity_change({"severity": 3}, {"status": "applied", "severity_before": "high", "severity_after": "high",
                                                      "reason": "severity: the severity is already high; phase: x"})
    assert applied == ("high", None, "Unchanged by Guardian triage")


def test_the_hero_header_has_the_big_confidence_the_bar_key_indicators_and_the_run_stats():
    out = _render(SAMPLE, dict(META, tool_calls=6, turns=7, tokens=61230, cost=0.1832))
    hero = out[:out.index("KILL CHAIN")]
    assert "font-size:26px" in hero and "92%" in hero and "font-size:18px" in hero
    assert "border-left:6px solid {}".format(gla._col("red")) in hero
    assert "KEY INDICATORS" in hero and "invoice.docm" in hero and "powershell.exe" in hero
    for label, value in (("Tool calls", ">6<"), ("Investigation turns", ">7<"), ("Tokens", "61,230"), ("Cost", "$0.1832")):
        assert label in hero and value in hero
    assert re.search(r"\d+/\d+ referenced", hero)
    assert "turns 14" not in out


def test_the_footer_has_the_model_the_run_and_the_reference_pill():
    out = _render(SAMPLE)
    footer = out[out.rindex('<div style="font-size:11px;line-height:2.1'):]
    assert "model example-model-35b" in footer and "run GR-4821-7f3a2c" in footer and "unverified" in footer
    clean = _render({"headline": "h", "findings": [{"text": "t", "ref": ["t1"]}], "refs": {"t1": {"tool": "x", "summary": "y"}}})
    assert "every item has a reference" in clean[clean.rindex("line-height:2.1"):]


def test_a_finding_shows_its_references_on_the_same_row():
    report = {"findings": [{"text": "first", "ref": ["t1", "t2"]}, {"text": "second", "ref": []}],
              "refs": {"t1": {"tool": "getEntries", "summary": ""}, "t2": {"tool": "domain", "summary": ""}}}
    section = gla._sec_findings(gla._Ctx(report, {}))
    rows = re.findall(r"<tr>.*?</tr>", section)
    assert len(rows) == 2 and "first" in rows[0] and "t1 getEntries" in rows[0] and "t2 domain" in rows[0]
    assert "second" in rows[1] and "unverified" in rows[1]


def test_the_timeline_keeps_the_tags_next_to_the_text_in_percentage_columns():
    section = gla._sec_timeline(gla._Ctx(SAMPLE, META))
    rows = re.findall(r"<tr><td valign=\"top\" style=\"width:9%.*?</tr>", section)
    assert len(rows) == 14
    widths = [int(w) for w in re.findall(r"width:(\d+)%", rows[0])]
    assert widths == [9, 3, 78, 10]
    assert "powershell" in rows[2] and re.search(r"powershell[^<]*(&nbsp;)+<span", rows[2])


def test_actions_are_in_percentage_columns_with_solid_priority_and_tint_approval_pills():
    section = gla._sec_actions(gla._Ctx(SAMPLE, META))
    assert re.findall(r'<td style="[^"]*?width:(\d+)%', section.split("</tr>")[0]) == ["7", "41", "10", "14", "28"]
    assert "background:{};color:#fff".format(gla._col("red")) in section
    assert "needs approval" in section and "automatic" in section
    assert "background:{};color:{}".format(gla._tint("amber"), gla._col("amber")) in section


def test_a_malicious_process_is_a_red_tint_chip_in_the_tree():
    section = gla._sec_tree(gla._Ctx({"tree": [{"id": "n1", "name": "bad.exe", "flag": "malicious"},
                                               {"id": "n2", "parent": "n1", "name": "ok.exe"}]}, {}))
    assert "background:{};border:1px solid {}".format(gla._tint("red"), gla._line("red")) in section
    assert section.count(gla._tint("red")) == 1


# --- the three parts: the incident page limits one dynamic section, so the page is three sections ------------------------

def _words(length, seed=0):
    base = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa quebec romeo".split()
    out, i = "", seed
    while len(out) < length:
        out += base[i % len(base)] + " "
        i += 1
    return out[:length].strip()


def _capped_report():
    """Every list at its cap and every string at its length limit: the largest report the page has to draw."""
    types = ["user", "host", "process", "file", "ip", "domain", "url", "email", "hash", "cloud"]
    caps = gla.CAPS
    entities = [{"id": "e%d" % i, "type": types[i % 10], "value": ("v%d-" % i) + _words(120).replace(" ", "-")[:116],
                 "rep": ["malicious", "suspicious", "benign", "unknown"][i % 4], "role": ["victim", "attacker", "infra", "asset"][i % 4],
                 "ref": ["t1", "t2", "t3"]} for i in range(caps["entities"])]
    edges = [{"from": "e%d" % (i % 19), "to": "e%d" % (i % 19 + 1), "rel": gla.RELS[i % 12], "ref": ["t1", "t2"]}
             for i in range(caps["edges"])]
    attack = [{"tactic": gla.TACTIC_FULL[i % 14], "tech": "T1%03d.001" % i, "name": _words(60, i), "time": "2026-10-27T21:%02d:08Z" % i,
               "evidence": _words(160, i), "ents": ["e%d" % j for j in range(6)], "ref": ["t1", "t2", "t3"]} for i in range(caps["attack"])]
    timeline = [{"t": "2026-10-27T21:%02d:08Z" % i, "event": _words(160, i), "src": _words(24, i), "ents": ["e1"],
                 "tech": "T1%03d" % i, "ref": ["t1", "t2"]} for i in range(caps["timeline"])]
    tree = [{"id": "n%d" % i, "parent": "n%d" % (i - 1) if i else None, "ent": "e1", "name": _words(60, i), "cmd": _words(160, i),
             "pid": "1234567890", "flag": ["malicious", "suspicious", ""][i % 3], "tech": "T1059.001", "ref": ["t1", "t2"]}
            for i in range(caps["tree"])]
    findings = [{"text": _words(200, i), "ref": ["t%d" % (j + 1) for j in range(8)]} for i in range(caps["findings"])]
    actions = [{"p": 1 + i % 3, "action": _words(160, i), "owner": ["guardian", "analyst"][i % 2], "approval": i % 2 == 0,
                "cmd": _words(200, i).replace(" ", "-")} for i in range(caps["actions"])]
    gaps = [_words(200, i) for i in range(caps["gaps"])]
    refs = dict(("t%d" % (i + 1), {"tool": _words(40, i), "summary": _words(200, i)}) for i in range(60))
    return {"v": 1, "headline": _words(140), "verdict": "malicious", "confidence": 92,
            "severity": {"from": "medium", "to": "high", "reason": _words(160)}, "entities": entities, "edges": edges,
            "attack": attack, "timeline": timeline, "tree": tree, "findings": findings, "actions": actions, "gaps": gaps, "refs": refs}


CAPPED_META = {"model": _words(60), "turns": 14, "tokens": 368320, "cost": 0.0642, "run_id": _words(40).replace(" ", "-"),
               "tool_calls": 6, "generated": "2026-10-28 07:15Z",
               "incident": {"id": "55503", "name": _words(80), "type": _words(80), "owner": _words(80)}}


def test_the_synthetic_report_really_is_at_every_cap():
    report = _capped_report()
    for key, cap in gla.CAPS.items():
        assert len(report[key]) == cap, key
    c = gla._Ctx(report, CAPPED_META)
    for key, cap in gla.CAPS.items():
        assert len(c.all(key)) == cap, key


@pytest.mark.parametrize("part", ["overview", "story", "findings"])
def test_every_part_of_the_largest_report_stays_under_the_size_limit(part):
    out = gla.render_report(_capped_report(), CAPPED_META, part)
    assert out is not None and len(out.encode("utf-8")) <= gla.MAX_PART_BYTES == 30000


@pytest.mark.parametrize("report", [_capped_report(), SAMPLE])
def test_every_part_of_every_report_is_under_the_limit_even_with_text_that_escapes_to_more_bytes(report):
    noisy = json.loads(json.dumps(report).replace("alpha", "a&b<c>").replace("echo", "e&c'h"))
    for part in ("overview", "story", "findings"):
        for r in (report, noisy):
            assert len(gla.render_report(r, CAPPED_META, part).encode("utf-8")) <= gla.MAX_PART_BYTES, part


def test_the_whole_page_is_not_cut_and_says_nothing_is_missing():
    out = gla.render_report(_capped_report(), CAPPED_META, "all")
    assert len(out.encode("utf-8")) > 3 * gla.MAX_PART_BYTES and "more not shown" not in out
    assert out.count("<table") > 60 and "CAUSALITY CHAIN" in out and "GAPS" in out and "KILL CHAIN" in out


def test_an_oversize_part_loses_rows_from_the_end_of_its_biggest_section_and_says_how_many():
    report = _capped_report()
    out = gla.render_report(report, CAPPED_META, "story")
    notes = re.findall(r"(\d+) more not shown, see the full report with !GuardianLayoutAssessment part=all", out)
    assert notes and all(int(n) >= 1 for n in notes)
    kept_tree = len(re.findall(r'<td valign="top" style="width:1px;', out))
    kept_events = len(re.findall(r'<tr><td valign="top" style="width:9%', out))
    assert 0 < kept_tree < 30 and 0 < kept_events < 25
    # the rows that remain are the first ones: a row is only ever taken off the end
    assert report["tree"][0]["name"][:19] in out
    assert re.findall(r"(\d\d):\d\d:08", out)[:1] == ["21"] and "21:%02d:08" % (kept_events - 1) in out
    assert "21:%02d:08" % kept_events not in out and "21:24:08" not in out
    # the count in each badge is still the whole list
    assert ">30 processes<" in out and ">25 events<" in out and ">20 entities<" in out


def test_a_part_that_fits_is_not_touched():
    out = gla.render_report(SAMPLE, META, "findings")
    assert "more not shown" not in out and len(out.encode("utf-8")) < gla.MAX_PART_BYTES


def test_trimming_never_takes_the_last_row_and_never_loops_forever():
    report = {"entities": [{"id": "e1", "type": "host", "value": "x" * 120, "ref": ["t1"]}], "edges": [],
              "timeline": [{"t": "2026-10-27T21:14:08Z", "event": "y" * 160, "ref": ["t1"]}],
              "refs": {"t1": {"tool": "a", "summary": "b"}}}
    c = gla._Ctx(report, {})
    assert not c.can_trim("timeline") and not c.can_trim("graph")
    old = gla.MAX_PART_BYTES
    try:
        gla.MAX_PART_BYTES = 100
        out = gla.render_report(report, {}, "story")
    finally:
        gla.MAX_PART_BYTES = old
    assert out is not None and "y" * 160 in out


def test_the_default_part_is_overview(monkeypatch):
    assert gla.DEFAULT_PART == "overview" and gla.PARTS == ("overview", "story", "findings", "all")
    _install(monkeypatch, guardian=WITH_REPORT)
    default = gla.build_entry(gla.demisto.incident(), gla.demisto.context())["Contents"]
    overview = gla.build_entry(gla.demisto.incident(), gla.demisto.context(), "html", "overview")["Contents"]
    assert default == overview
    for title in ("GUARDIAN ASSESSMENT", "KILL CHAIN", "ATTACK CHAIN"):
        assert title in default
    for title in ("RELATIONSHIP MAP", "CAUSALITY CHAIN", "TIMELINE", "FINDINGS", "RECOMMENDED ACTIONS", "GAPS"):
        assert title not in default


def test_an_unknown_part_is_the_overview(monkeypatch):
    _install(monkeypatch, guardian=WITH_REPORT)
    default = gla.build_entry(gla.demisto.incident(), gla.demisto.context())["Contents"]
    for odd in ("", "bogus", None, "STORY ", 5):
        assert gla.build_entry(gla.demisto.incident(), gla.demisto.context(), "html", odd)["Contents"] == default


def test_main_reads_the_part_argument_and_defaults_to_the_overview(monkeypatch):
    results = []
    _install(monkeypatch, guardian=WITH_REPORT)
    monkeypatch.setattr(gla, "return_results", results.append)
    for args in ({}, {"part": "story"}, {"part": " FINDINGS "}, {"part": "all"}):
        monkeypatch.setattr(gla.demisto, "args", lambda args=args: args)
        gla.main()
    default, story, findings, everything = [r["Contents"] for r in results]
    assert "ATTACK CHAIN" in default and "TIMELINE" not in default
    assert "TIMELINE" in story and "FINDINGS" not in story and "ATTACK CHAIN" not in story
    assert "FINDINGS" in findings and "RECOMMENDED ACTIONS" in findings and "GAPS" in findings and "TIMELINE" not in findings
    assert "ATTACK CHAIN" in everything and "TIMELINE" in everything and "GAPS" in everything


def test_the_three_parts_hold_the_sections_the_layout_promises(monkeypatch):
    out = {}
    for part in ("overview", "story", "findings"):
        out[part] = _entry(monkeypatch, WITH_REPORT, part=part)["Contents"]
    assert [t in out["overview"] for t in ("GUARDIAN ASSESSMENT", "KILL CHAIN", "ATTACK CHAIN")] == [True] * 3
    assert [t in out["story"] for t in ("RELATIONSHIP MAP", "CAUSALITY CHAIN", "TIMELINE")] == [True] * 3
    assert [t in out["findings"] for t in ("FINDINGS", "RECOMMENDED ACTIONS", "GAPS")] == [True] * 3
    assert "every item" in out["findings"] or "unverified" in out["findings"]          # the footer is in the last part
    assert "run 4217" not in out["overview"] and "run 4217" not in out["story"] and "run 4217" in out["findings"]


def test_the_no_report_states_render_once_in_the_overview_and_the_other_parts_point_to_it(monkeypatch):
    states = {
        "no report": {"Triage": TRIAGE, "TriageApply": APPLY, "Loop": RUN},
        "stale": dict(WITH_REPORT, Report=dict(RECORD, run_id="1")),
        "failed": dict(WITH_REPORT, Report={"v": 1, "run_id": "4217", "tick": 7, "report": None, "errors": ["x"]}),
        "undrawable": dict(WITH_REPORT, Report=dict(RECORD, report={"entities": "x"}, refs={}), Loop=dict(RUN, verdict=None)),
    }
    for name, guardian in states.items():
        overview = _entry(monkeypatch, guardian, part="overview")["Contents"]
        assert "Twelve failed sign-ins" in overview, name                       # today's card
        for part in ("story", "findings"):
            entry = _entry(monkeypatch, guardian, part=part)
            assert entry["Type"] == 1 and entry["ContentsFormat"] == "html"
            assert entry["Contents"] == '<div style="opacity:.7;font-size:12px">See the assessment above.</div>', (name, part)


def test_no_assessment_yet_says_so_once(monkeypatch):
    _install(monkeypatch, guardian={}, incident={"id": "1"})
    for part in ("story", "findings"):
        entry = gla.build_entry(gla.demisto.incident(), gla.demisto.context(), "html", part)
        assert "See the assessment above." in entry["Contents"] and "has not assessed" not in entry["Contents"]
    assert "has not assessed" in gla.build_entry(gla.demisto.incident(), gla.demisto.context(), "html", "overview")["Contents"]


def test_a_part_with_nothing_to_draw_says_so(monkeypatch):
    report = {"headline": "only a headline", "refs": {}}
    record = dict(RECORD, report=report, refs={})
    entry = _entry(monkeypatch, dict(WITH_REPORT, Report=record), part="story")
    assert "Nothing to show here for this report." in entry["Contents"]
    assert "only a headline" in _entry(monkeypatch, dict(WITH_REPORT, Report=record), part="overview")["Contents"]


def test_markdown_follows_the_same_split(monkeypatch):
    overview = _entry(monkeypatch, WITH_REPORT, "markdown", part="overview")
    assert overview["ContentsFormat"] == "markdown" and overview["Contents"].startswith("### Guardian assessment")
    for part in ("story", "findings"):
        entry = _entry(monkeypatch, WITH_REPORT, "markdown", part=part)
        assert entry["ContentsFormat"] == "markdown" and entry["Contents"] == "See the assessment above."
    assert _entry(monkeypatch, WITH_REPORT, "markdown", part="all")["Contents"] == overview["Contents"]


def test_an_error_in_a_later_part_shows_the_note_not_an_error(monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("renderer broke")

    monkeypatch.setattr(gla, "render_report", boom)
    for part in ("story", "findings"):
        assert "See the assessment above." in _entry(monkeypatch, WITH_REPORT, part=part)["Contents"]


def test_the_header_values_are_the_runs_own_in_every_part_that_has_a_header(monkeypatch):
    overview = _entry(monkeypatch, WITH_REPORT, part="overview")["Contents"]
    assert "SUSPICIOUS" in overview and ">70%<" in overview and "MALICIOUS" not in overview
