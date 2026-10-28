"""GuardianLayoutAssessment -- the assessment page for the Guardian tab of GuardianAgentRunLayout.

Two pages, one script. When `Guardian.Report` (GuardianReportBuild) holds a report of the current run, the page is the
rich report: header, kill chain, attack chain, relationship map, process tree, timeline, findings, recommended actions and
gaps, each item marked verified or unverified. Otherwise (no report, a report of an earlier run, a failed report step, a
report that cannot be drawn) it is the assessment card: the verdict, confidence, investigation type and complexity, the
severity before and after with the reason, the summary, analysis, recommended actions and next step, the key entities, the
ATT&CK techniques, the agent's conclusion (Markdown rendered as HTML), the actions waiting for approval, and the ticks,
tokens and cost.

The header of the report page is never taken from the report: the verdict, confidence and severity are the run's own
(`Guardian.Loop.verdict`, the incident, `Guardian.TriageApply`), exactly as the card shows them.

Display only: it never writes context, a List or an incident field, and never calls GuardianToolBridge. It is
self-contained on purpose (`demistomock`, `CommonServerPython` and the standard library only, no shared Guardian
block), so an operator can paste it into the automation editor by hand.

Data, every key optional (a context value may be a dict or a list of dicts; the last dict is used): `Guardian.Report`
(GuardianReportBuild), `Guardian.Triage` (GuardianTriageResult), `Guardian.TriageApply` (GuardianTriageApply),
`Guardian.Loop` (`verdict`, `status`, `tick`, `run_id`, `last_assistant_fingerprint`, `cost_*`, `messages`), `demisto.incident()`, and the pending rows of
the `guardian_approvals_ledger` List (left out when the List cannot be read). A report is shown only while its `run_id`
(and its `tick` and `fingerprint`, when it has them) equals the run state's, so the report of an earlier run on the same incident never shows.

Output: one HTML note entry with inline styles only (no script, style block, external resource or event handler; every
value escaped; the report page is laid out with tables in percentage widths, and every fill (an rgba tint, or a solid colour
with white text) is on an inline-block span, with a border or text colour of its own so it reads without the fill; the card uses solid
white-on-colour badges, inherited text colour and rgba borders so it reads on light and dark themes). `format=markdown`
returns the card as a Markdown note, and so does a failure while building the HTML.
"""

import html
import json
import math
import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

LEDGER_LIST = "guardian_approvals_ledger"
MAX_CONCLUSION_CHARS = 6000
ARROW, DASH = "\u2192", "\u2014"

SEVERITY_COLORS = {
    "critical": "#a4161a", "high": "#c2410c", "medium": "#a16207", "low": "#1d6fa5",
    "informational": "#4b6a88", "unknown": "#6b7280",
}
SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")
SEVERITY_BY_NUMBER = {0.5: "informational", 1: "low", 2: "medium", 3: "high", 4: "critical"}
VERDICT_COLORS = {"Malicious": "#c62828", "Suspicious": "#b45309", "Benign": "#2e7d32", "Inconclusive": "#5f6b7a"}
ENTITY_LABELS = (
    ("identity", "Identity"), ("ip", "IP"), ("host", "Host"), ("hash", "Hash"), ("sha256", "SHA256"),
    ("cve", "CVE"), ("domain", "Domain"), ("url", "URL"), ("email", "Email"), ("rule_id", "Rule"),
)
#: A fenced JSON object with one of these keys is the verdict or triage block, which the card already shows.
BLOCK_KEYS = ("verdict", "severity", "investigation_type")


# Reading the data

def _dict(value):
    """The dict itself, or the last dict of a list (appended context); ``{}`` otherwise."""
    if isinstance(value, list):
        value = next((item for item in reversed(value) if isinstance(item, dict)), {})
    return value if isinstance(value, dict) else {}


def _s(value):
    return "" if value is None or isinstance(value, (dict, list)) else str(value).strip()


def _number(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and not isinstance(value, bool) else None


def _severity(value):
    """Severity name for a numeric or text severity; ``unknown`` for anything else."""
    text = _s(value).lower()
    if text in SEVERITY_COLORS:
        return text
    return SEVERITY_BY_NUMBER.get(_number(value), "unknown")


def _conclusion(loop):
    messages = loop.get("messages")
    for message in reversed(messages if isinstance(messages, list) else []):
        if isinstance(message, dict) and message.get("role") == "assistant":
            content = message.get("content")
            if isinstance(content, str) and content.strip():
                return content
    return ""


def _pending_count(incident_id):
    """Pending approvals for this incident, 0 when the List does not exist yet, ``None`` when it cannot be read."""
    if not incident_id:
        return None
    try:
        entries = demisto.executeCommand("getList", {"listName": LEDGER_LIST}) or []
        errors = [str(e.get("Contents")).lower() for e in entries if isinstance(e, dict) and e.get("Type") == 4]
        if errors:
            return 0 if any("item not found" in text for text in errors) else None
        values = [e.get("Contents") for e in entries if isinstance(e, dict) and e.get("Contents") is not None]
        rows = values[-1] if values else []
        rows = json.loads(rows) if isinstance(rows, str) and rows.strip() else rows
        if rows in ("", None):
            return 0
        if not isinstance(rows, list):
            return None
        wanted = str(incident_id)
        return sum(
            1 for row in rows
            if isinstance(row, dict) and row.get("status") == "pending"
            and wanted in (str(row.get("incident_id")), str(row.get("run_id")))
        )
    except Exception as exc:  # the line is optional: leave it out, never fail the card
        demisto.debug("GuardianLayoutAssessment: approvals ledger not read: {}".format(exc))
        return None


def _severity_parts(incident, apply_record):
    """``(before, after, head, reason)``: the severity badges to show (`after` is ``None`` when Guardian did not change the
    severity), a short phrase saying what Guardian did, and the reason it gave when that adds something."""
    if not apply_record:
        return _severity(incident.get("severity")), None, "Not changed by Guardian", ""
    status = _s(apply_record.get("status")).lower()
    before = _severity(apply_record.get("severity_before"))
    after = _severity(apply_record.get("severity_after")) if _s(apply_record.get("severity_after")) else before
    reason = _s(apply_record.get("reason"))
    order, delta = SEVERITY_ORDER, 0
    if before in order and after in order:
        delta = (order.index(after) > order.index(before)) - (order.index(after) < order.index(before))
    word = {1: "raised", -1: "lowered"}.get(delta)
    if status in ("applied", "dry_run") and word:
        head = "{} by Guardian triage".format(word.capitalize()) if status == "applied" \
            else "Dry run, nothing written: would be {} by Guardian triage".format(word)
        return before, after, head, reason
    if status == "dry_run":
        return before, None, "Dry run, unchanged", reason
    if status == "error":
        return before, None, "Not changed (error)", reason
    if status == "applied":
        # triage ran and left the severity alone: its reason only repeats that, and talks about the phase it wrote
        return before, None, "Unchanged by Guardian triage", ""
    return before, None, "Unchanged", reason


def _severity_change(incident, apply_record):
    """``(before, after, text)``: the severity badges to show and one line saying what Guardian did and why."""
    if not apply_record:
        return _severity(incident.get("severity")), None, "Severity was not changed by Guardian in this run."
    before, after, head, reason = _severity_parts(incident, apply_record)
    return before, after, head + ((" " + DASH + " " if after else ": ") + reason if reason else "")


def _collect(incident, context):
    """Everything the card shows, read once, as plain values (nothing escaped yet)."""
    guardian = _dict(_dict(context).get("Guardian"))
    triage, apply_record, loop = _dict(guardian.get("Triage")), _dict(guardian.get("TriageApply")), _dict(guardian.get("Loop"))
    verdict = _dict(loop.get("verdict"))
    techniques = verdict.get("techniques")
    techniques = [techniques] if isinstance(techniques, str) else techniques if isinstance(techniques, list) else []
    name = _s(verdict.get("verdict")).title()
    if name:
        name = name if name in VERDICT_COLORS else "Inconclusive"
    elif triage.get("likely_benign") is True:
        name = "Likely benign"
    confidence = _number(verdict.get("confidence") if name else triage.get("confidence"))
    if confidence is None:
        confidence = _number(triage.get("confidence"))
    inputs = _dict(triage.get("inputs"))
    recommendations = triage.get("recommendations")
    before, after, severity_text = _severity_change(incident, apply_record)
    severity_head = _severity_parts(incident, apply_record)[2]
    model = {
        "incident": incident, "triage": triage, "verdict": name,
        "confidence": None if confidence is None else int(confidence),
        "kind": _s(triage.get("investigation_type")) or _s(triage.get("branch")), "complexity": _s(triage.get("complexity")),
        "escalate": triage.get("escalate") is True, "run_status": _s(loop.get("status")),
        "severity_before": before, "severity_after": after, "severity_text": severity_text, "severity_head": severity_head,
        "summary": _s(triage.get("summary")) or _s(verdict.get("summary")), "analysis": _s(triage.get("analysis")),
        "recommendations": [_s(r) for r in recommendations if _s(r)] if isinstance(recommendations, list) else [],
        "next_step": _s(triage.get("next_step")),
        "entities": [(label, _s(inputs.get(key))) for key, label in ENTITY_LABELS if _s(inputs.get(key))],
        "techniques": [_s(t) for t in techniques if _s(t)], "conclusion": _conclusion(loop),
        "loop": loop, "report": _dict(guardian.get("Report")),
        "pending": None, "ticks": _number(loop.get("tick")), "tokens": _number(loop.get("cost_tokens_total")), "cost": _number(loop.get("cost_usd")),
        "has_data": bool(triage or apply_record or verdict or loop.get("status") or _conclusion(loop)),
    }
    if model["has_data"]:
        model["pending"] = _pending_count(incident.get("id"))
    return model


# Markdown to HTML (the text is escaped before anything is converted)

def _esc(value):
    return html.escape(str(value), quote=True)


def _inline(text):
    """Escape one line, then turn `code`, **bold** and *italic* / _italic_ into tags. Code is not touched by the others."""
    pieces = re.split(r"(`[^`\n]+`)", _esc(text))
    for index, piece in enumerate(pieces):
        if index % 2:
            pieces[index] = '<code style="background:rgba(128,128,128,.2);border-radius:3px;padding:0 4px">{}</code>'.format(piece[1:-1])
            continue
        piece = re.sub(r"\*\*(?=\S)(.+?)(?<=\S)\*\*", r"<b>\1</b>", piece)
        piece = re.sub(r"(?<![\w*])\*(?=[^\s*])(.+?)(?<=[^\s*])\*(?![\w*])", r"<i>\1</i>", piece)
        pieces[index] = re.sub(r"(?<![\w_])_(?=[^\s_])(.+?)(?<=[^\s_])_(?![\w_])", r"<i>\1</i>", piece)
    return "".join(pieces)


def _blocks(text):
    """HTML for text outside code fences: headings, bullet and numbered lists, paragraphs, line breaks."""
    out, paragraph, items, list_tag = [], [], [], ""

    def flush():
        nonlocal paragraph, items, list_tag
        if paragraph:
            out.append('<p style="margin:6px 0">{}</p>'.format("<br>".join(paragraph)))
        if items:
            out.append('<{0} style="margin:6px 0;padding-left:22px">{1}</{0}>'.format(list_tag, "".join("<li>{}</li>".format(i) for i in items)))
        paragraph, items, list_tag = [], [], ""

    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.strip()
        heading = re.match(r"(#{1,3})\s+(.+)$", line)
        bullet, number = re.match(r"[-*]\s+(.+)$", line), re.match(r"\d+[.)]\s+(.+)$", line)
        if heading:
            flush()
            size = {1: 15, 2: 14, 3: 13}[len(heading.group(1))]
            out.append('<div style="font-weight:700;font-size:{}px;margin:10px 0 4px 0">{}</div>'.format(size, _inline(heading.group(2))))
        elif bullet or number:
            tag = "ul" if bullet else "ol"
            if paragraph or (items and tag != list_tag):
                flush()
            list_tag = tag
            items.append(_inline((bullet or number).group(1)))
        elif line:
            if items:
                flush()
            paragraph.append(_inline(line))
        else:
            flush()
    flush()
    return "".join(out)


def _is_block(text):
    """Whether `text` is one JSON object carrying a verdict or triage key."""
    try:
        block = json.loads(text) if text.strip().startswith("{") else None
    except ValueError:
        return False
    return isinstance(block, dict) and any(key in block for key in BLOCK_KEYS)


def _chunks(text):
    """Split raw text into ``("text", s)`` and ``("code", s)`` pieces, drop the fenced verdict or triage block, and cap the
    length. Returns ``(pieces, truncated)``. The decision to drop a fence is made on the raw JSON, before any escaping."""
    pieces, position, used, truncated = [], 0, 0, False
    for match in re.finditer(r"```[ \t]*[\w+-]*[ \t]*\n?(.*?)(?:```|\Z)", text, re.S):
        pieces += [("text", text[position:match.start()]), ("code", match.group(1).strip("\n"))]
        position = match.end()
    pieces.append(("text", text[position:]))
    kept = []
    for kind, body in pieces:
        if kind == "code" and _is_block(body):
            continue
        if kind == "text":  # a bare verdict object on its own paragraph is dropped too
            body = "\n\n".join(part for part in re.split(r"\n\s*\n", body) if not _is_block(part))
        if not body.strip():
            continue
        if used + len(body) > MAX_CONCLUSION_CHARS:
            body, truncated = body[:MAX_CONCLUSION_CHARS - used], True
        used += len(body)
        kept.append((kind, body))
        if truncated:
            break
    return kept, truncated


def markdown_to_html(text):
    pieces, truncated = _chunks(text)
    parts = [
        _blocks(body) if kind == "text" else
        '<pre style="margin:6px 0;padding:8px 10px;border:1px solid rgba(128,128,128,.35);border-radius:4px;'
        'background:rgba(128,128,128,.12);white-space:pre-wrap;font-size:12px">{}</pre>'.format(_esc(body))
        for kind, body in pieces
    ]
    if truncated:
        parts.append('<div style="opacity:.7;font-size:12px">Truncated: the conclusion was cut at {} characters.</div>'.format(MAX_CONCLUSION_CHARS))
    return "".join(parts)


# The card

def _badge(label, color):
    return ('<span style="display:inline-block;background:{};color:#fff;border-radius:10px;padding:1px 9px;margin:0 6px 3px 0;'
            'font-size:12px;font-weight:600">{}</span>').format(color, _esc(label))


def _chip(label, value):
    return ('<span style="display:inline-block;border:1px solid rgba(128,128,128,.5);border-radius:4px;padding:1px 7px;'
            'margin:0 6px 4px 0;font-size:12px">{}<b>{}</b></span>').format(
                '<span style="opacity:.7">{} </span>'.format(_esc(label)) if label else "", _esc(value))


def _section(title, body):
    return ('<div style="margin-top:10px;padding-top:8px;border-top:1px solid rgba(128,128,128,.3)">'
            '<div style="font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;opacity:.7;margin-bottom:3px">{}</div>'
            '{}</div>').format(_esc(title), body)


def render_html(m):
    badges = ""
    if m["verdict"]:
        badges += _badge(m["verdict"], VERDICT_COLORS.get(m["verdict"], "#2e7d32" if m["verdict"] == "Likely benign" else "#5f6b7a"))
    if m["escalate"]:
        badges += _badge("Escalate", "#c62828")
    chips = "".join(_chip(label, value) for label, value in (
        ("Confidence", None if m["confidence"] is None else "{}%".format(m["confidence"])), ("Investigation", m["kind"]),
        ("Complexity", m["complexity"]), ("Triage", _s(m["triage"].get("status"))), ("Run", m["run_status"])) if value)
    incident = m["incident"]
    facts = " &middot; ".join("<b>{}</b> {}".format(_esc(label), _esc(value)) for label, value in (
        ("Incident", "#{} {}".format(incident.get("id"), _s(incident.get("name"))).strip() if incident.get("id") else ""),
        ("Type", _s(incident.get("type"))), ("Owner", _s(incident.get("owner")))) if value)
    parts = ['<div style="font-size:13px;line-height:1.5"><div style="font-size:15px;font-weight:700;margin-bottom:4px">Guardian assessment</div>'
             '<div>{}{}</div>{}'.format(badges, chips, '<div style="opacity:.85;margin-top:2px">{}</div>'.format(facts) if facts else "")]
    arrow = " {} ".format(ARROW).join(_badge(s.capitalize(), SEVERITY_COLORS[s]) for s in (m["severity_before"], m["severity_after"]) if s)
    parts.append(_section("Severity", '<div>{}<span>{}</span></div>'.format(arrow, _esc(m["severity_text"]))))
    for title, key in (("Summary", "summary"), ("Analysis", "analysis")):
        if m[key]:
            parts.append(_section(title, '<div style="white-space:pre-wrap">{}</div>'.format(_esc(m[key]))))
    if m["recommendations"]:
        parts.append(_section("Recommended actions", '<ol style="margin:0;padding-left:22px">{}</ol>'.format(
            "".join("<li>{}</li>".format(_esc(r)) for r in m["recommendations"]))))
    if m["next_step"]:
        parts.append(_section("Next step", '<div style="border-left:4px solid #1d6fa5;background:rgba(29,111,165,.12);padding:6px 10px;'
                              'border-radius:0 4px 4px 0">{}</div>'.format(_esc(m["next_step"]))))
    if m["entities"]:
        parts.append(_section("Key entities", "".join(_chip(label, value) for label, value in m["entities"])))
    if m["techniques"]:
        parts.append(_section("ATT&CK techniques", "".join(_chip("", t) for t in m["techniques"])))
    if m["conclusion"]:
        parts.append(_section("Conclusion", markdown_to_html(m["conclusion"])))
    elif m["has_data"]:
        parts.append(_section("Conclusion", '<div style="opacity:.7">No conclusion yet. The agent writes it when it stops calling tools.</div>'))
    if m["pending"] is not None:
        parts.append(_section("Pending approvals", "<div><b>{}</b></div>".format(_esc(_pending_text(m["pending"])))))
    if _footer(m):
        parts.append('<div style="opacity:.7;font-size:12px;margin-top:10px">{}</div>'.format(_esc(_footer(m))))
    return "".join(parts) + "</div>"


def _pending_text(count):
    if not count:
        return "No actions are waiting for approval"
    return "{} {} waiting for approval {} use Approve or Deny".format(count, "action is" if count == 1 else "actions are", DASH)


def _footer(m):
    bits = ["Ticks {:d}".format(int(m["ticks"])) if m["ticks"] is not None else "",
            "Tokens {:,d}".format(int(m["tokens"])) if m["tokens"] else "",
            "Cost ${:.4f}".format(m["cost"]) if m["cost"] and m["cost"] > 0 else ""]
    return " | ".join(bit for bit in bits if bit)


def render_markdown(m):
    def md(value):
        """Escape one value for Markdown: HTML is escaped, and the brackets are backslash-escaped so that no link, image
        or reference definition can be built from model text (the card never makes a clickable link out of it)."""
        return html.escape(str(value), quote=False).replace("[", "\\[").replace("]", "\\]")

    def fenced(body):
        """A code block whose fence is longer than any run of backticks inside it, so the text cannot close it early."""
        longest = max((len(run) for run in re.findall(r"`+", body)), default=0)
        fence = "`" * max(3, longest + 1)
        return "{}\n{}\n{}".format(fence, body, fence)

    head = [m["verdict"], "" if m["confidence"] is None else "{}%".format(m["confidence"]), m["kind"], m["complexity"],
            "Escalate" if m["escalate"] else "", "Run " + m["run_status"] if m["run_status"] else ""]
    incident = m["incident"]
    lines = ["### Guardian assessment", " | ".join(md(v) for v in head if v)]
    if incident.get("id"):
        lines.append(md("Incident #{} {}".format(incident.get("id"), _s(incident.get("name"))).strip()))
    arrow = " {} ".format(ARROW).join(s.capitalize() for s in (m["severity_before"], m["severity_after"]) if s)
    lines.append("**Severity:** {}. {}".format(arrow, md(m["severity_text"])))
    for title, key in (("Summary", "summary"), ("Analysis", "analysis"), ("Next step", "next_step")):
        if m[key]:
            lines += ["", "**{}:** {}".format(title, md(m[key]))]
    if m["recommendations"]:
        lines += ["", "**Recommended actions:**"] + ["{}. {}".format(i, md(r)) for i, r in enumerate(m["recommendations"], 1)]
    if m["entities"]:
        lines += ["", "**Key entities:** " + ", ".join(md("{}: {}".format(label, value)) for label, value in m["entities"])]
    if m["techniques"]:
        lines += ["", "**ATT&CK techniques:** " + ", ".join(md(t) for t in m["techniques"])]
    if m["conclusion"]:
        pieces, truncated = _chunks(m["conclusion"])
        lines += ["", "**Conclusion:**", ""] + [md(b) if k == "text" else fenced(b) for k, b in pieces]
        if truncated:
            lines.append("_Truncated: the conclusion was cut at {} characters._".format(MAX_CONCLUSION_CHARS))
    if m["pending"] is not None:
        lines += ["", "**Pending approvals:** " + _pending_text(m["pending"])]
    if _footer(m):
        lines += ["", "_{}_".format(_footer(m))]
    return "\n".join(lines)


# The report page (Guardian.Report)
#
# Built from tables, because the incident page's HTML filter keeps layout only from tables, `color` and `border`. A fill is
# put on an inline-block SPAN only (an rgba tint, or a solid colour with white text): that is what the filter was measured to
# keep. A fill on a td or a div is never relied on, so every filled element also has a border or a text colour of its own and
# stays readable without it. Column widths are percentages, so the page fills a wide section and a narrow one alike. Every
# string comes from the model and is escaped; colours and styles come only from the lookups below, never from the report.

GREY = "#7f8791"
_HEX = {"red": "#e5484d", "orange": "#f76b15", "amber": "#d18b00", "green": "#2f9e63", "blue": "#2f80ed",
        "violet": "#8e5bd9", "teal": "#14a39a", "grey": GREY}


def _rgba(color, alpha):
    return "rgba({},{},{},{})".format(int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16), alpha)


#: name -> (solid colour, tint for a fill, line for a border)
PAL = dict((name, (hex_, _rgba(hex_, ".14"), _rgba(hex_, ".5"))) for name, hex_ in _HEX.items())
LINE = "rgba(127,127,127,.35)"
LINE2 = GREY
MONO = "font-family:monospace"
ALLOWED_TAGS = frozenset(("div", "span", "table", "tr", "td", "b", "br", "details", "summary"))

VERDICT_COLOR = {"malicious": "red", "suspicious": "orange", "benign": "green", "inconclusive": "grey"}
SEV_COLOR = {"critical": "red", "high": "orange", "medium": "amber", "low": "blue", "informational": "grey"}
REP_COLOR = {"malicious": "red", "suspicious": "orange", "benign": "green", "unknown": "grey"}
FLAG_COLOR = {"malicious": "red", "suspicious": "orange"}
PRIO_COLOR = {1: "red", 2: "orange", 3: "blue"}
ETYPES = ("user", "host", "process", "file", "ip", "domain", "url", "email", "hash", "cloud", "other")
ETAG = {"user": "USER", "host": "HOST", "process": "PROC", "file": "FILE", "ip": "IP", "domain": "DOMAIN", "url": "URL",
        "email": "EMAIL", "hash": "HASH", "cloud": "CLOUD", "other": "OTHER"}
#: The colour of an entity type, for the tag and the left edge of its node (a malicious or suspicious one is red or orange).
TYPE_COLOR = {"user": "blue", "email": "blue", "host": "teal", "cloud": "teal", "process": "violet", "file": "violet",
              "ip": "amber", "domain": "grey", "url": "grey", "hash": "grey", "other": "grey"}
ROLES = ("victim", "attacker", "infra", "asset", "tool", "other")
RELS = ("logged_on", "ran", "spawned", "wrote", "connected", "resolved", "downloaded", "sent", "received",
        "authenticated", "accessed", "other")
REL_LABEL = {"logged_on": "logon", "ran": "ran", "spawned": "spawn", "wrote": "wrote", "connected": "conn",
             "resolved": "dns", "downloaded": "fetch", "sent": "sent", "received": "recv",
             "authenticated": "auth", "accessed": "access", "other": "rel"}
REL_PASSIVE = {"logged_on": "logon from", "ran": "run by", "spawned": "spawned by", "wrote": "written by",
               "connected": "connected from", "resolved": "resolved by", "downloaded": "downloaded by",
               "sent": "sent by", "received": "received by", "authenticated": "authenticated by",
               "accessed": "accessed by", "other": "linked from"}
SEVERITIES = ("informational", "low", "medium", "high", "critical")

TACTICS = ("Recon", "Resource Dev", "Initial Access", "Execution", "Persistence", "Priv Esc", "Defense Evasion",
           "Cred Access", "Discovery", "Lateral Mvmt", "Collection", "C2", "Exfil", "Impact")
TACTIC_FULL = ("Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
               "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
               "Collection", "Command and Control", "Exfiltration", "Impact")
_TACTIC_ALIAS = {
    "reconnaissance": 0, "recon": 0, "ta0043": 0, "resourcedevelopment": 1, "resourcedev": 1, "ta0042": 1,
    "initialaccess": 2, "ta0001": 2, "execution": 3, "ta0002": 3, "persistence": 4, "ta0003": 4,
    "privilegeescalation": 5, "privesc": 5, "ta0004": 5, "defenseevasion": 6, "defenceevasion": 6, "ta0005": 6,
    "credentialaccess": 7, "credaccess": 7, "ta0006": 7, "discovery": 8, "ta0007": 8, "lateralmovement": 9,
    "lateralmvmt": 9, "ta0008": 9, "collection": 10, "ta0009": 10, "commandandcontrol": 11, "commandcontrol": 11,
    "c2": 11, "ta0011": 11, "exfiltration": 12, "exfil": 12, "ta0010": 12, "impact": 13, "ta0040": 13,
}

CAPS = {"entities": 20, "edges": 30, "attack": 15, "timeline": 25, "tree": 30, "findings": 10, "actions": 8, "gaps": 5}
GRAPH_COLS = ("Identity", "Host", "Process / File", "Indicator", "External")
UNLINKED_COL = "Not linked"
TYPE_COL = {"user": 0, "email": 0, "host": 1, "cloud": 1, "process": 2, "file": 2, "domain": 3, "url": 3, "hash": 3,
            "other": 3, "ip": 4}
MAX_GRAPH_ROWS = 40
MAX_REFS = 200
MAX_KEY_INDICATORS = 6
MAX_ATTACK_PER_ROW = 4
MAX_FINDING_REFS = 3
MAX_CARD_ENTITIES = 4

_ID = re.compile(r"^[A-Za-z0-9_.\-]{1,12}$")
_TIME = re.compile(r"^\s*(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})(?::(\d{2}))?")
#: A vertical gap between two cards. The height is a line height, which the filter keeps, not a height on a div.
_GAP = '<div style="font-size:1px;line-height:12px">&nbsp;</div>'


# -- small helpers --------------------------------------------------------------------------------------------------

def _hx(value):
    return html.escape("" if value is None else str(value), quote=True)


def _clip(value, limit):
    """Plain one-line text cut to `limit` characters (raw: escape afterwards, never before cutting)."""
    if value is None or isinstance(value, (dict, list, tuple, set, bool)):
        return ""
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[:max(limit - 1, 0)] + "…"


def _t(value, limit):
    return _hx(_clip(value, limit))


def _num(value):
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number == number and abs(number) != float("inf") else None


def _enum(value, allowed, default):
    text = value.strip().lower() if isinstance(value, str) else ""
    return text if text in allowed else default


def _items(value, cap):
    return [item for item in value if isinstance(item, dict)][:cap] if isinstance(value, list) else []


def _ids(value, known, cap):
    out = []
    for item in value if isinstance(value, list) else []:
        if isinstance(item, str) and item in known and item not in out:
            out.append(item)
    return out[:cap]


def _tactic_slot(name):
    if not isinstance(name, str):
        return None
    return _TACTIC_ALIAS.get(re.sub(r"[^a-z0-9]", "", name.lower()))


def _tkey(value):
    match = _TIME.match(value) if isinstance(value, str) else None
    return (match.group(1), match.group(2) + ":" + (match.group(3) or "00")) if match else None


def _shorten(value, etype):
    if etype == "hash" and len(value) > 24:
        return value[:10] + "…" + value[-6:]
    return value


def _col(name):
    return PAL.get(name, PAL["grey"])[0]


def _tint(name):
    return PAL.get(name, PAL["grey"])[1]


def _line(name):
    return PAL.get(name, PAL["grey"])[2]


def _pill(text, color, solid=False, size=12):
    """A rounded label. Solid: the accent with white text (the same look as the DONE badge). Otherwise a tint with a text
    colour and a border of its own."""
    if solid:
        return ('<span style="display:inline-block;background:{c};color:#fff;border:1px solid {c};border-radius:10px;'
                'padding:1px 11px;font-size:{s}px;font-weight:700">{x}</span>').format(
                    c=_col(color), s=size, x=_hx(text))
    return ('<span style="display:inline-block;background:{t};color:{c};border:1px solid {l};border-radius:10px;'
            'padding:0 9px;font-size:{s}px;font-weight:700">{x}</span>').format(
                t=_tint(color), c=_col(color), l=_line(color), s=size, x=_hx(text))


def _rchip(text, color=None, wrap=False, size=11):
    """A small rounded tag in monospace (an id, a technique, a command, an IOC). A coloured one is a tint with a border and
    a text colour; the neutral one is only a hairline border, so a page full of them stays light."""
    if not color or color == "grey":
        return '<span style="border:1px solid {};border-radius:4px;padding:0 6px;font-size:{}px;{}{}">{}</span>'.format(
            LINE, size, MONO, ";word-break:break-all" if wrap else "", _hx(text))
    return ('<span style="display:inline-block;background:{t};color:{c};border:1px solid {l};border-radius:4px;padding:0 6px;'
            'font-size:{s}px;{m}{w}">{x}</span>').format(
                t=_tint(color), c=_col(color), l=_line(color), s=size, m=MONO, w=";word-break:break-all" if wrap else "",
                x=_hx(text))


def _mono(text, size=12, color=None, bold=False):
    return '<span style="{m};font-size:{s}px{c}{b}">{x}</span>'.format(
        m=MONO, s=size, c=";color:" + color if color else "", b=";font-weight:700" if bold else "", x=_hx(text))


def _circle(text, color, size=22):
    """A solid round number or mark."""
    return ('<span style="display:inline-block;width:{s}px;height:{s}px;line-height:{s}px;text-align:center;'
            'border-radius:{r}px;background:{c};color:#fff;font-size:11px;font-weight:700">{x}</span>').format(
                s=size, r=size // 2, c=_col(color), x=_hx(text))


def _refmark(ref_ids):
    """The verified mark of an item: a green tint pill with the number of references, or an amber one saying none. It
    repeats on every row, so it has no border: its text colour keeps it readable without the fill."""
    ok = bool(ref_ids)
    return ('<span style="display:inline-block;background:{t};color:{c};border-radius:10px;padding:0 9px;font-size:11px;'
            'font-weight:700">{x}</span>').format(
                t=_tint("green" if ok else "amber"), c=_col("green" if ok else "amber"),
                x=("✓ {} ref{}".format(len(ref_ids), "" if len(ref_ids) == 1 else "s")) if ok else "⚠ unverified")


def _counter(text):
    return ('<span style="display:inline-block;background:{t};color:{c};border-radius:9px;padding:0 9px;font-size:11px;'
            'font-weight:700;line-height:1.6">{x}</span>').format(t=_tint("grey"), c=GREY, x=_hx(text))


def _box(title, body, details=False, count=None, accent=None):
    """A section card: hairline border, rounded corners, an uppercase title and a count badge (both in the page's own
    font). `accent` adds a heavier left edge."""
    label = _hx(title.upper()) + ("&nbsp;&nbsp;" + _counter(count) if count else "")
    head = "font-size:11px;font-weight:700;color:{}".format(GREY)
    border = "border:1px solid {};".format(LINE)
    if accent:
        border += "border-left:5px solid {};".format(_col(accent))
    if details:
        inner = '<details open><summary style="{}">{}</summary><div style="padding-top:12px">{}</div></details>'.format(
            head, label, body)
    else:
        inner = '<div style="{};padding-bottom:12px">{}</div>{}'.format(head, label, body)
    return ('<table cellspacing="0" style="width:100%;{}border-radius:8px;font-size:13px"><tr>'
            '<td style="padding:14px 18px 16px 18px">{}</td></tr></table>').format(border, inner)


def _note(name, exc):
    return '<div style="font-size:12px;color:{};padding:2px 0">Section {} skipped ({}).</div>'.format(
        GREY, _hx(name), _hx(type(exc).__name__))


def _table(rows, extra=""):
    return '<table cellspacing="0" style="width:100%;{}">{}</table>'.format(extra, "".join(rows))


def _label(text):
    """A small grey caption above a value."""
    return '<div style="font-size:10px;font-weight:700;color:{};padding-bottom:2px">{}</div>'.format(GREY, _hx(text.upper()))


# -- normalising the model's report ---------------------------------------------------------------------------------

class _Ctx(object):
    """Validated, capped, reference-checked view of the report. Each list is built on first use."""

    def __init__(self, report, meta):
        self.r = report if isinstance(report, dict) else {}
        self.meta = meta if isinstance(meta, dict) else {}
        self.refs = {}
        refs = self.r.get("refs")
        for key, val in (list(refs.items())[:MAX_REFS] if isinstance(refs, dict) else []):
            if isinstance(key, str) and _ID.match(key) and isinstance(val, dict):
                self.refs[key] = (_clip(val.get("tool"), 40), _clip(val.get("summary"), 200))
        self._cache = {}
        self.keep = {}

    def all(self, name):
        """The validated list, never shortened."""
        if name not in self._cache:
            self._cache[name] = getattr(self, "_n_" + name)()
        return self._cache[name]

    def get(self, name):
        """The list as the page shows it: `all`, less the rows `trim` took off its end."""
        items = self.all(name)
        keep = self.keep.get(name)
        return items if keep is None else items[:keep]

    def _total(self, name):
        return len(self.all("entities" if name == "graph" else name))

    def can_trim(self, name):
        return self.keep.get(name, self._total(name)) > 1

    def trim(self, name):
        """Take a quarter (at least one row) off the end of a list; `graph` is the entity count of the relationship map."""
        now = self.keep.get(name, self._total(name))
        self.keep[name] = max(1, now - max(1, now // 4))

    def more(self, name):
        """The muted line saying how many rows were left out of the section, or an empty string."""
        hidden = self._total(name) - self.keep.get(name, self._total(name))
        if hidden <= 0:
            return ""
        return '<div style="font-size:11px;color:{};padding-top:8px">{}</div>'.format(GREY, _hx(MORE_NOTE.format(hidden)))

    def ent_map(self):
        return dict((e["id"], e) for e in self.get("entities"))

    def _refs(self, item):
        value = item.get("ref")
        return [r for r in dict.fromkeys(x for x in value if isinstance(x, str)) if r in self.refs][:8] \
            if isinstance(value, list) else []

    def _n_entities(self):
        out, seen = [], set()
        for it in _items(self.r.get("entities"), 60):
            eid, value = it.get("id"), _clip(it.get("value"), 120)
            if not (isinstance(eid, str) and _ID.match(eid)) or eid in seen or not value:
                continue
            seen.add(eid)
            out.append({"id": eid, "type": _enum(it.get("type"), ETYPES, "other"), "value": value,
                        "rep": _enum(it.get("rep"), REP_COLOR, "unknown"), "role": _enum(it.get("role"), ROLES, "other"),
                        "ref": self._refs(it)})
        return out[:CAPS["entities"]]

    def _n_edges(self):
        known, out, seen = set(e["id"] for e in self.get("entities")), [], set()
        for it in _items(self.r.get("edges"), 100):
            a, b = it.get("from"), it.get("to")
            rel = _enum(it.get("rel"), RELS, "other")
            if not (isinstance(a, str) and isinstance(b, str) and a in known and b in known and a != b) \
                    or (a, b, rel) in seen:
                continue
            seen.add((a, b, rel))
            out.append({"from": a, "to": b, "rel": rel, "time": _clip(it.get("time"), 30), "ref": self._refs(it)})
        return out[:CAPS["edges"]]

    def _ents_of(self, it):
        return _ids(it.get("ents"), set(e["id"] for e in self.get("entities")), 6)

    def _n_attack(self):
        out = []
        for it in _items(self.r.get("attack"), 40):
            tactic = _clip(it.get("tactic"), 40)
            slot = _tactic_slot(tactic)
            out.append({"tactic": TACTIC_FULL[slot] if slot is not None else tactic, "slot": slot,
                        "tech": _clip(it.get("tech"), 16), "name": _clip(it.get("name"), 60),
                        "time": _clip(it.get("time"), 30), "evidence": _clip(it.get("evidence"), 160),
                        "ents": self._ents_of(it), "ref": self._refs(it)})
        out = out[:CAPS["attack"]]
        if out and all(_tkey(a["time"]) for a in out):
            out.sort(key=lambda a: _tkey(a["time"]))
        return out

    def _n_timeline(self):
        out = []
        for it in _items(self.r.get("timeline"), 60):
            event = _clip(it.get("event"), 160)
            if event:
                out.append({"t": _clip(it.get("t"), 30), "event": event, "src": _clip(it.get("src"), 24),
                            "ents": self._ents_of(it), "tech": _clip(it.get("tech"), 16), "ref": self._refs(it)})
        out = out[:CAPS["timeline"]]
        if out and all(_tkey(x["t"]) for x in out):
            out.sort(key=lambda x: _tkey(x["t"]))
        return out

    def _n_tree(self):
        out, seen = [], set()
        ents = self.ent_map()
        for it in _items(self.r.get("tree"), 60):
            nid = it.get("id")
            if not (isinstance(nid, str) and _ID.match(nid)) or nid in seen:
                continue
            seen.add(nid)
            ent = it.get("ent") if isinstance(it.get("ent"), str) and it.get("ent") in ents else None
            name = _clip(it.get("name"), 60) or (ents[ent]["value"] if ent else "")
            if not name:
                continue
            parent = it.get("parent")
            out.append({"id": nid, "parent": parent if isinstance(parent, str) else None, "ent": ent, "name": name,
                        "cmd": _clip(it.get("cmd"), 160), "pid": _clip(it.get("pid"), 10),
                        "flag": _enum(it.get("flag"), FLAG_COLOR, ""), "tech": _clip(it.get("tech"), 16),
                        "ref": self._refs(it)})
        return out[:CAPS["tree"]]

    def _n_findings(self):
        return [{"text": _clip(it.get("text"), 200), "ref": self._refs(it)}
                for it in _items(self.r.get("findings"), 30) if _clip(it.get("text"), 200)][:CAPS["findings"]]

    def _n_actions(self):
        out = []
        for it in _items(self.r.get("actions"), 30):
            action = _clip(it.get("action"), 160)
            p = _num(it.get("p"))
            if action:
                out.append({"p": min(3, max(1, int(p))) if p is not None else 3, "action": action,
                            "owner": _enum(it.get("owner"), ("guardian", "analyst"), "analyst"),
                            "approval": it.get("approval") not in (False, "false", "no", 0),
                            "cmd": _clip(it.get("cmd"), 200)})
        out = out[:CAPS["actions"]]
        out.sort(key=lambda a: a["p"])
        return out

    def _n_gaps(self):
        gaps = self.r.get("gaps")
        return [_clip(g, 200) for g in (gaps if isinstance(gaps, list) else []) if _clip(g, 200)][:CAPS["gaps"]]

    def referenced(self):
        """``(items with a reference, items)`` over the sections that carry references."""
        with_ref = total = 0
        for name in ("entities", "edges", "attack", "timeline", "tree", "findings"):
            try:
                items = self.all(name)
            except Exception:
                continue
            total += len(items)
            with_ref += sum(1 for item in items if item["ref"])
        return with_ref, total

    def unverified(self):
        total = 0
        for name in ("entities", "edges", "attack", "timeline", "tree", "findings"):
            try:
                total += sum(1 for item in self.all(name) if not item["ref"])
            except Exception:
                pass
        return total


# -- A. header ------------------------------------------------------------------------------------------------------

def _tag(text, color):
    """A tiny uppercase type tag: a tint behind coloured bold text."""
    return ('<span style="background:{};color:{};border-radius:4px;padding:0 5px;font-size:9px;font-weight:700">{}</span>'
            ).format(_tint(color), _col(color), _hx(text))


def _bar(percent, color):
    """A confidence bar: a track (tint) and a fill (solid), both spans; the track has its own border."""
    fill = ('<span style="display:inline-block;width:{}%;height:6px;background:{};border-radius:4px;font-size:1px;'
            'line-height:6px">&nbsp;</span>').format(percent, _col(color)) if percent else ""
    return ('<span style="display:inline-block;width:92%;height:6px;background:{};border:1px solid {};border-radius:5px;'
            'font-size:1px;line-height:6px;text-align:left">{}</span>').format(_tint(color), _line(color), fill)


def _key_indicators(c):
    """The malicious and suspicious entities, worst first, as chips with a type tag."""
    ents = [e for e in c.get("entities") if e["rep"] in ("malicious", "suspicious")]
    ents.sort(key=lambda e: 0 if e["rep"] == "malicious" else 1)
    chips = []
    for e in ents[:MAX_KEY_INDICATORS]:
        color = REP_COLOR[e["rep"]]
        chips.append('<span style="display:inline-block;background:{t};border:1px solid {l};border-radius:6px;padding:0 8px;'
                     'font-size:12px;line-height:1.6">{tag}&nbsp;{val}</span>'.format(
                         t=_tint(color), l=_line(color), tag=_tag(ETAG[e["type"]], color),
                         val=_mono(_clip(_shorten(e["value"], e["type"]), 40), 12, _col(color), True)))
    return chips


def _stat_rows(c):
    m = c.meta
    rows = []
    for label, value in (("Tool calls", _num(m.get("tool_calls"))), ("Investigation turns", _num(m.get("turns"))),
                         ("Tokens", _num(m.get("tokens"))), ("Cost", _num(m.get("cost")))):
        if value is None:
            continue
        shown = "${:.4f}".format(value) if label == "Cost" else "{:,d}".format(int(value))
        rows.append((label, shown))
    with_ref, total = c.referenced()
    if total:
        rows.append(("References", "{}/{} referenced".format(with_ref, total)))
    return rows


def _sec_header(c):
    r = c.r
    headline = _clip(r.get("headline"), 140)
    verdict = _enum(r.get("verdict"), VERDICT_COLOR, "")
    conf = _num(r.get("confidence"))
    conf = None if conf is None else int(min(100, max(0, conf)))
    sev = r.get("severity") if isinstance(r.get("severity"), dict) else {}
    sfrom, sto = _enum(sev.get("from"), SEVERITIES, ""), _enum(sev.get("to"), SEVERITIES, "")
    reason = _clip(sev.get("reason"), 160)
    if not (headline or verdict or conf is not None or sfrom or sto):
        return ""
    color = VERDICT_COLOR.get(verdict, "blue")
    cells = []
    if verdict:
        cells.append('<td valign="top" style="width:22%;padding:0 12px 4px 0">{}{}</td>'.format(
            _label("Verdict"), _pill(verdict.upper(), color, solid=True, size=15)))
    if conf is not None:
        cells.append('<td valign="top" style="width:30%;padding:0 12px 4px 0">{}<span style="font-size:26px;font-weight:700;'
                     'line-height:1.1;color:{}">{}%</span><div style="padding-top:6px;line-height:8px">{}</div></td>'.format(
                         _label("Confidence"), _col(color), conf, _bar(conf, color)))
    if sfrom or sto:
        pills = " <span style=\"color:{}\">&#9656;</span> ".format(GREY).join(
            _pill(s.upper(), SEV_COLOR[s], solid=True, size=13) for s in (sfrom, sto) if s)
        cells.append('<td valign="top" style="padding:0 0 4px 0">{}{}{}</td>'.format(
            _label("Severity"), pills,
            '<div style="font-size:12px;color:{};padding-top:4px">{}</div>'.format(GREY, _hx(reason)) if reason else ""))
    left = ['<div style="font-size:11px;font-weight:700;color:{};padding-bottom:10px">GUARDIAN ASSESSMENT</div>'.format(GREY)]
    if cells:
        left.append(_table(['<tr>{}</tr>'.format("".join(cells))]))
    if headline:
        left.append('<div style="font-size:18px;font-weight:700;line-height:1.35;padding-top:12px">{}</div>'.format(_hx(headline)))
    inc = c.meta.get("incident") if isinstance(c.meta.get("incident"), dict) else {}
    bits = []
    if _clip(inc.get("id"), 20):
        bits.append("Incident " + _mono("#" + _clip(inc.get("id"), 20), 12))
    for key in ("name", "type", "owner"):
        if _clip(inc.get(key), 80):
            bits.append(_t(inc.get(key), 80))
    if bits:
        left.append('<div style="font-size:12px;color:{};padding-top:4px">{}</div>'.format(GREY, " &middot; ".join(bits)))
    chips = _key_indicators(c)
    if chips:
        left.append('<div style="padding-top:12px">{}<div style="line-height:2.1">{}</div></div>'.format(
            _label("Key indicators"), " ".join(chips)))
    stats = _stat_rows(c)
    if stats:
        rows = ['<tr><td style="font-size:11px;color:{};padding:4px 0;border-bottom:1px solid {}">{}</td>'
                '<td style="font-size:12px;font-weight:700;text-align:right;padding:4px 0;border-bottom:1px solid {}">{}</td></tr>'
                .format(GREY, LINE, _hx(label), LINE, _hx(value)) for label, value in stats]
        body = ('<table cellspacing="0" style="width:100%"><tr><td valign="top" style="width:70%;padding:0 20px 0 0">{}</td>'
                '<td valign="top" style="width:30%;border-left:1px solid {};padding:0 0 0 20px">{}{}</td></tr></table>').format(
                    "".join(left), LINE, _label("Run"), _table(rows))
    else:
        body = "".join(left)
    return ('<table cellspacing="0" style="width:100%;border:1px solid {l};border-left:6px solid {c};border-radius:8px">'
            '<tr><td style="padding:18px 22px 20px 22px">{b}</td></tr></table>').format(l=LINE, c=_col(color), b=body)


# -- B. kill chain strip --------------------------------------------------------------------------------------------

def _sec_killchain(c):
    attack = c.all("attack")
    if not attack:
        return ""
    counts = [0] * 14
    for a in attack:
        if a["slot"] is not None:
            counts[a["slot"]] += 1
    cells = []
    for i, label in enumerate(TACTICS):
        if counts[i]:
            body = ('<span style="display:inline-block;width:90%;background:{o};color:#fff;border-radius:7px;'
                    'padding:6px 0 5px 0;font-size:11px;font-weight:700;line-height:1.3;text-align:center">{lab}<br>'
                    '<span style="display:inline-block;background:rgba(255,255,255,.3);border-radius:8px;padding:0 8px;'
                    'font-size:11px">{n}</span></span>').format(o=_col("orange"), lab=_hx(label), n=counts[i])
        else:
            body = ('<span style="display:inline-block;width:90%;background:{t};color:{g};border-radius:7px;'
                    'padding:6px 0 5px 0;font-size:11px;line-height:1.3;text-align:center">{lab}<br>&nbsp;</span>').format(
                        t=_tint("grey"), g=GREY, lab=_hx(label))
        cells.append('<td style="width:7.14%;text-align:center;padding:0">{}</td>'.format(body))
    seen = sum(1 for n in counts if n)
    return _box("Kill chain", _table(['<tr>' + "".join(cells) + '</tr>']), count="{} of 14 tactics".format(seen))


# -- C. attack chain ------------------------------------------------------------------------------------------------

def _card(c, step, a, ents, width):
    time = _tkey(a["time"])
    shown = [e for e in a["ents"] if e in ents]
    chips = " ".join(_rchip(_clip(ents[e]["value"], 28), None, True) for e in shown[:MAX_CARD_ENTITIES])
    if len(shown) > MAX_CARD_ENTITIES:
        chips += " " + _rchip("+{}".format(len(shown) - MAX_CARD_ENTITIES), None)
    head = (_rchip(a["tech"], "orange", size=11) + " " if a["tech"] else "") + '<b style="font-size:13px">{}</b>'.format(_hx(a["name"]))
    stamp = (_mono("{} {}Z".format(time[0][5:], time[1][:5]), 11, GREY) + " ") if time else ""
    return ('<td valign="top" style="width:{w:.2f}%;border:1px solid {l};border-top:3px solid {o};border-radius:8px;'
            'padding:11px 13px 12px 13px;font-size:12px;line-height:1.45">'
            '<div>{n}&nbsp;&nbsp;<b style="color:{o};font-size:13px">{tac}</b></div>'
            '<div style="padding-top:7px">{head}</div>'
            '<div style="padding-top:4px;color:{g}">{ev}</div>'
            '<div style="padding-top:7px;line-height:1.9">{stamp}{refs}</div>'
            '{chips}</td>').format(
                w=width, l=LINE, o=_col("orange"), g=GREY, n=_circle("{:02d}".format(step), "orange"), tac=_hx(a["tactic"]),
                head=head, ev=_hx(a["evidence"]), stamp=stamp, refs=_refmark(a["ref"]),
                chips='<div style="padding-top:3px;line-height:2.1">{}</div>'.format(chips) if chips else "")


def _sec_attack(c):
    attack = c.get("attack")
    if not attack:
        return ""
    ents, rows = c.ent_map(), []
    per = max(1, min(len(attack), MAX_ATTACK_PER_ROW))
    gap = 2.6
    width = (100.0 - gap * (per - 1)) / per
    arrow = ('<td style="width:{}%;text-align:center;padding:0"><span style="display:inline-block;width:22px;height:22px;'
             'line-height:22px;text-align:center;border-radius:11px;background:{};color:{};font-size:12px">&#9656;</span></td>'
             ).format(gap, _tint("grey"), GREY)
    for start in range(0, len(attack), per):
        group = attack[start:start + per]
        cells = []
        for j in range(per):
            if j:
                cells.append(arrow if j < len(group) else '<td style="width:{}%">&nbsp;</td>'.format(gap))
            cells.append(_card(c, start + j + 1, group[j], ents, width) if j < len(group)
                         else '<td style="width:{:.2f}%">&nbsp;</td>'.format(width))
        rows.append('<tr>{}</tr>'.format("".join(cells)))
        if start + per < len(attack):
            rows.append('<tr><td colspan="{}" style="font-size:1px;line-height:12px">&nbsp;</td></tr>'.format(2 * per - 1))
    total = len(c.all("attack"))
    return _box("Attack chain", _table(rows) + c.more("attack"), count="{} step{}".format(total, "" if total == 1 else "s"))


# -- D. relationship map --------------------------------------------------------------------------------------------

def _graph(c):
    """Layered left-to-right layout on an occupancy grid: one node column per entity column that has a node, a connector
    column between two node columns, and, when there are entities with no relationship, one more node column of their own
    on the right. A column nobody is in is not drawn.

    Returns {"rows": [[anchor, ...], ...], "cols": [name, ...], "width": grid columns, "unlinked": [entity, ...],
    "dropped": n}. An anchor is a dict with x (grid column), cs, rs and kind: node / unlinked / conn / empty. Covered grid
    cells are not emitted, so the anchors of all rows tile the grid exactly once. With no relationship at all `rows` is
    empty and `unlinked` holds every entity."""
    ents = c.ent_map()
    order = [e["id"] for e in c.get("entities")][:c.keep.get("graph")]
    col = dict((i, TYPE_COL.get(ents[i]["type"], 3)) for i in order)
    fwd, has_in, notes, linked = {}, set(), {}, set()
    for e in c.get("edges"):
        a, b = e["from"], e["to"]
        if a not in col or b not in col:
            continue
        linked.update((a, b))
        if col[a] == col[b]:  # same column: kept as a note on the target node
            notes.setdefault(b, []).append("{} {}".format(REL_PASSIVE[e["rel"]], _clip(ents[a]["value"], 24)))
            continue
        src, dst, rev = (a, b, False) if col[a] < col[b] else (b, a, True)
        slot = fwd.setdefault(src, {})
        if dst in slot:
            slot[dst]["rels"].append((e["rel"], rev))
            slot[dst]["ok"] = slot[dst]["ok"] and bool(e["ref"])
        else:
            slot[dst] = {"rels": [(e["rel"], rev)], "ok": bool(e["ref"])}
        has_in.add(dst)
    roots = [i for i in order if i in linked and i not in has_in]
    placed = set()

    def build(nid):
        placed.add(nid)
        node = {"id": nid, "dup": False, "kids": [], "span": 1}
        for dst, link in fwd.get(nid, {}).items():
            kid = {"id": dst, "dup": True, "kids": [], "span": 1} if dst in placed else build(dst)
            node["kids"].append((kid, link))
        node["span"] = max(1, sum(k["span"] for k, _ in node["kids"]))
        return node

    trees, total, dropped = [], 0, 0
    for rid in roots:
        if rid in placed:
            continue
        tree = build(rid)
        if total + tree["span"] > MAX_GRAPH_ROWS:
            dropped += 1
            continue
        total += tree["span"]
        trees.append(tree)
    unlinked = [ents[i] for i in order if i not in linked]
    if not trees:
        return {"rows": [], "cols": [], "width": 0, "unlinked": unlinked, "dropped": dropped}

    def walk(node):
        yield node["id"]
        for kid, _link in node["kids"]:
            for nid in walk(kid):
                yield nid

    used = sorted(set(col[nid] for tree in trees for nid in walk(tree)))
    pos = dict((x, n) for n, x in enumerate(used))
    names = [GRAPH_COLS[x] for x in used] + ([UNLINKED_COL] if unlinked else [])
    width = 2 * len(names) - 1
    nrows = max(total, len(unlinked))
    grid = [[None] * width for _ in range(nrows)]
    covered = object()

    def put(r, x, cell):
        for dr in range(cell["rs"]):
            for dc in range(cell["cs"]):
                if grid[r + dr][x + dc] is not None:
                    raise ValueError("grid overlap")
                grid[r + dr][x + dc] = covered
        grid[r][x] = cell
        cell["x"] = x

    def place(node, r, level):
        put(r, 2 * level, {"kind": "node", "node": node, "rs": node["span"], "cs": 1, "notes": notes.get(node["id"], [])})
        row = r
        for kid, link in node["kids"]:
            kl = pos[col[kid["id"]]]
            put(row, 2 * level + 1, {"kind": "conn", "link": link, "rs": kid["span"], "cs": 2 * (kl - level) - 1})
            place(kid, row, kl)
            row += kid["span"]

    r = 0
    for tree in trees:
        place(tree, r, pos[col[tree["id"]]])
        r += tree["span"]
    for index, ent in enumerate(unlinked):
        put(index, width - 1, {"kind": "unlinked", "ent": ent, "rs": 1, "cs": 1})
    rows = []
    for ri in range(nrows):
        cells, x = [], 0
        while x < width:
            cell = grid[ri][x]
            if cell is covered:
                x += 1
            elif cell is None:
                run = 1
                while x + run < width and grid[ri][x + run] is None:
                    run += 1
                cells.append({"kind": "empty", "x": x, "cs": run, "rs": 1})
                x += run
            else:
                cells.append(cell)
                x += cell["cs"]
        rows.append(cells)
    return {"rows": rows, "cols": names, "width": width, "unlinked": unlinked, "dropped": dropped}


def _graph_rows(c):
    return _graph(c)["rows"]


def _node_html(c, ent, dup, notes, dashed=False):
    """One entity: a rounded box with an edge in its colour (red or orange for a malicious or suspicious one, else the
    colour of its type), a tiny type tag, the role and reputation, and the value in monospace."""
    bad = ent["rep"] in ("malicious", "suspicious")
    tcol = TYPE_COLOR.get(ent["type"], "grey")
    edge = REP_COLOR[ent["rep"]] if bad else tcol
    words = [ent["role"]] if ent["role"] in ("victim", "attacker") else []
    if bad:
        words.append(ent["rep"])
    head = '<div style="line-height:1.7">{}{}{}{}</div>'.format(
        _tag(ETAG[ent["type"]], tcol),
        ' <span style="font-size:10px;font-weight:700;color:{}">{}</span>'.format(_col(edge), _hx(" · ".join(words))) if words else "",
        ' <span style="font-size:11px;color:{}">&#8634;</span>'.format(GREY) if dup else "",
        "" if ent["ref"] else ' <span style="font-size:11px;color:{}">&#9888;</span>'.format(_col("amber")))
    value = '<div style="{};font-size:12px;word-break:break-all{}">{}</div>'.format(
        MONO, ";color:{};font-weight:700".format(_col(edge)) if bad else "", _hx(_shorten(ent["value"], ent["type"])))
    extra = "".join('<div style="font-size:10px;color:{};line-height:1.3;word-break:break-word">&#9666; {}</div>'.format(
        GREY, _hx(n)) for n in notes[:2]) if not dup else ""
    style = "dashed" if dashed else "solid"
    return ('<div style="border:1px {st} {line};border-left:4px {st} {e};border-radius:7px;padding:4px 8px 5px 8px">{h}{v}{x}'
            '</div>').format(st=style, line=LINE2 if dashed else _line(edge) if bad else LINE, e=_col(edge), h=head, v=value, x=extra)


def _conn_html(link):
    rels = list(dict.fromkeys(link["rels"]))
    rev = all(r for _, r in rels)
    label = "/".join(("◂" if r and not rev else "") + REL_LABEL[k] for k, r in rels)
    mark = '<span style="color:{}">&#9888;</span> '.format(_col("amber")) if not link["ok"] else ""
    line = '<td style="font-size:1px;line-height:1px;padding:0;border:1px solid {};border-width:1px 0 0 0">&nbsp;</td>'.format(LINE2)
    head = '<td style="width:9px;padding:0;font-size:11px;line-height:3px;color:{}">&#9666;</td>'.format(GREY)
    tail = '<td style="width:9px;padding:0;font-size:11px;line-height:3px;color:{};text-align:right">&#9656;</td>'.format(GREY)
    cells = (head + line) if rev else (line + tail)
    pill = '<span style="border:1px solid {};border-radius:8px;padding:0 7px;font-size:10px;{}">{}{}</span>'.format(
        LINE, MONO, mark, _hx(label))
    return ('<table cellspacing="0" style="width:100%"><tr><td colspan="2" style="text-align:center;padding-bottom:5px">{}</td>'
            '</tr><tr>{}</tr></table>').format(pill, cells)


def _sec_graph(c):
    ents = c.ent_map()
    if not c.get("edges") and not ents:
        return ""
    g = _graph(c)
    if not g["rows"]:
        per = 4
        cells = ['<td valign="top" style="width:{:.2f}%;padding:0 8px 8px 0">{}</td>'.format(
            100.0 / per, _node_html(c, e, False, [], True)) for e in g["unlinked"]]
        while len(cells) % per:
            cells.append('<td style="width:{:.2f}%">&nbsp;</td>'.format(100.0 / per))
        body = _table(['<tr>{}</tr>'.format("".join(cells[i:i + per])) for i in range(0, len(cells), per)])
        body = '<div style="font-size:11px;color:{};padding-bottom:8px">No relationships were reported.</div>'.format(GREY) + body
        return _box("Relationship map", body + c.more("graph"), count="{} entit{}".format(len(ents), "y" if len(ents) == 1 else "ies"))
    ncols = len(g["cols"])
    link_w = 7.0 if ncols <= 4 else 5.5
    node_w = (100.0 - link_w * (ncols - 1)) / ncols
    widths = [("{:.2f}%".format(node_w) if i % 2 == 0 else "{:.2f}%".format(link_w)) for i in range(g["width"])]
    head = ['<td style="width:{};font-size:11px;font-weight:700;color:{};padding:0 0 6px 0">{}</td>'.format(
        widths[i], GREY, _hx(g["cols"][i // 2].upper()) if i % 2 == 0 else "&nbsp;") for i in range(g["width"])]
    rows = ['<tr>' + "".join(head) + '</tr>']
    for row in g["rows"]:
        tds = []
        for cell in row:
            span = ' colspan="{}"'.format(cell["cs"]) if cell["cs"] > 1 else ""
            span += ' rowspan="{}"'.format(cell["rs"]) if cell["rs"] > 1 else ""
            if cell["kind"] == "node":
                n = cell["node"]
                tds.append('<td{} style="padding:4px 0">{}</td>'.format(span, _node_html(c, ents[n["id"]], n["dup"], cell["notes"])))
            elif cell["kind"] == "unlinked":
                tds.append('<td{} style="padding:4px 0">{}</td>'.format(span, _node_html(c, cell["ent"], False, [], True)))
            elif cell["kind"] == "conn":
                tds.append('<td{} style="padding:0 4px">{}</td>'.format(span, _conn_html(cell["link"])))
            else:
                tds.append('<td{}>&nbsp;</td>'.format(span))
        rows.append('<tr>' + "".join(tds) + '</tr>')
    body = _table(rows)
    if g["dropped"]:
        body += '<div style="padding-top:6px;font-size:11px;color:{}">{} more graph branches not shown.</div>'.format(GREY, g["dropped"])
    return _box("Relationship map", body + c.more("graph"), count="{} entit{}".format(len(ents), "y" if len(ents) == 1 else "ies"))


# -- E. causality chain ---------------------------------------------------------------------------------------------

def _sec_tree(c):
    """The process tree, one small table per row: a prefix cell (the guides) and a name cell, so every row's name starts
    exactly where its prefix ends. A child's prefix is one step (three characters) longer than its parent's, and its branch
    mark sits under the first character of the parent's name. A malicious or suspicious process is a tinted chip."""
    nodes = c.get("tree")
    if not nodes:
        return ""
    by_id = dict((n["id"], n) for n in nodes)
    kids = {}
    for n in nodes:
        parent = n["parent"] if n["parent"] in by_id and n["parent"] != n["id"] else None
        kids.setdefault(parent, []).append(n)
    rows, seen = [], set()
    pipe, gap = "│\u00a0\u00a0", "\u00a0\u00a0\u00a0"  # no-break spaces, as characters: three bytes shorter than the entity each

    def emit(n, guides, last, top):
        seen.add(n["id"])
        base = "".join(pipe if g else gap for g in guides)
        first = base + ("" if top else ("└─\u00a0" if last else "├─\u00a0"))
        child_guides = guides if top else guides + [not last]
        children = [k for k in kids.get(n["id"], []) if k["id"] not in seen]
        cont = "".join(pipe if g else gap for g in child_guides)
        color = FLAG_COLOR.get(n["flag"])
        name = '<b style="{};font-size:12px{}">{}</b>'.format(MONO, ";color:" + _col(color) if color else "", _hx(n["name"]))
        if color:
            name = ('<span style="display:inline-block;background:{};border:1px solid {};border-radius:5px;padding:0 7px;'
                    'line-height:1.6">{}</span>').format(_tint(color), _line(color), name)
        line1 = name + (" " + _mono("[" + n["pid"] + "]", 11, GREY) if n["pid"] else "")
        if n["tech"]:
            line1 += " " + _rchip(n["tech"], "orange")
        line1 += " " + _refmark(n["ref"])
        line2 = ""
        if n["cmd"]:
            line2 = '<br><span style="{};font-size:11px;color:{};word-break:break-all">{}</span>'.format(
                MONO, GREY, _hx(_clip(n["cmd"], 130)))
        prefix = '<span style="{};font-size:12px;color:{}">{}{}</span>'.format(
            MONO, GREY, first, "<br>" + cont if line2 else "")
        rows.append('<table cellspacing="0" style="width:100%"><tr><td valign="top" style="width:1px;line-height:1.7;'
                    'padding:0 0 3px 0">{}</td><td valign="top" style="line-height:1.7;padding:0 0 3px 0">{}{}</td></tr></table>'
                    .format(prefix, line1, line2))
        for i, k in enumerate(children):
            if k["id"] not in seen:
                emit(k, child_guides, i == len(children) - 1, False)

    for root in kids.get(None, []):
        if root["id"] not in seen:
            emit(root, [], True, True)
    for n in nodes:  # a parent cycle never reaches a root: show the rest as roots
        if n["id"] not in seen:
            emit(n, [], True, True)
    total = len(c.all("tree"))
    return _box("Causality chain", "".join(rows) + c.more("tree"), details=True,
                count="{} process{}".format(total, "" if total == 1 else "es"))


# -- F. timeline ----------------------------------------------------------------------------------------------------

def _sec_timeline(c):
    rows = c.get("timeline")
    if not rows:
        return ""
    out, day = [], None
    for x in rows:
        key = _tkey(x["t"])
        if key and key[0] != day:
            day = key[0]
            out.append('<tr><td colspan="5" style="padding:8px 0 4px 0;font-size:12px;font-weight:700">{}</td></tr>'.format(
                _mono(day + " UTC", 12, None, True)))
        verified = bool(x["ref"])
        dot = '<span style="color:{}">{}</span>'.format(_col("orange" if x["tech"] else "blue") if verified else _col("amber"),
                                                       "\u25cf" if verified else "\u25cb")
        shown = key[1] if key else _clip(x["t"], 20)
        tags = " ".join(t for t in (_rchip(x["src"], None) if x["src"] else "", _rchip(x["tech"], "orange") if x["tech"] else "") if t)
        out.append(
            '<tr><td valign="top" style="width:9%;padding:4px 6px 4px 0;line-height:1.9">{t}</td>'
            '<td valign="top" style="width:3%;text-align:center;border:1px solid {l};border-top:0;border-bottom:0;border-right:0;'
            'padding:3px 0 4px 0;font-size:14px;line-height:1.5">{dot}</td><td valign="top" style="width:78%;padding:3px 10px;font-size:12px;line-height:1.9">'
            '{ev}&nbsp;&nbsp;{tags}</td>'
            '<td valign="top" style="width:10%;padding:3px 0;text-align:right;line-height:1.9">{ref}</td></tr>'.format(
                t=_mono(shown, 12, GREY), l=LINE, dot=dot, ev=_hx(x["event"]), tags=tags, ref=_refmark(x["ref"])))
    total = len(c.all("timeline"))
    return _box("Timeline", _table(out) + c.more("timeline"), details=True, count="{} event{}".format(total, "" if total == 1 else "s"))


# -- G. findings ----------------------------------------------------------------------------------------------------

def _sec_findings(c):
    rows = c.get("findings")
    if not rows:
        return ""
    out = []
    for i, f in enumerate(rows, 1):
        edge = "border-bottom:1px solid {};".format(LINE) if i < len(rows) else ""
        chips = " ".join(_rchip("{} {}".format(r, _clip(c.refs[r][0], 28)), "green") for r in f["ref"][:MAX_FINDING_REFS]) \
            + (" " + _rchip("+{}".format(len(f["ref"]) - MAX_FINDING_REFS), "green") if len(f["ref"]) > MAX_FINDING_REFS else "") \
            if f["ref"] else _pill("⚠ unverified", "amber", size=11)
        out.append('<tr><td valign="top" style="width:3%;padding:8px 0;{e}">{n}</td>'
                   '<td valign="top" style="width:67%;padding:8px 12px 8px 0;line-height:1.5;{e}">{t}</td>'
                   '<td valign="top" style="width:30%;padding:7px 0;text-align:right;line-height:2;{e}">{c}</td></tr>'.format(
                       e=edge, n=_circle(str(i), "blue"), t=_hx(f["text"]), c=chips))
    return _box("Findings", _table(out) + c.more("findings"), details=True, count=str(len(c.all("findings"))))


# -- H. actions, I. gaps --------------------------------------------------------------------------------------------

def _sec_actions(c):
    rows = c.get("actions")
    if not rows:
        return ""
    th = 'font-size:10px;font-weight:700;color:{};padding:0 8px 6px 0;border-bottom:1px solid {}'.format(GREY, LINE)
    out = ['<tr><td style="{w}width:7%">P</td><td style="{w}width:41%">ACTION</td><td style="{w}width:10%">OWNER</td>'
           '<td style="{w}width:14%">APPROVAL</td><td style="{w}width:28%">COMMAND</td></tr>'.format(w=th)]
    for i, a in enumerate(rows, 1):
        edge = "border-bottom:1px solid {};".format(LINE) if i < len(rows) else ""
        out.append(
            '<tr><td valign="top" style="width:7%;padding:8px 8px 8px 0;{e}">{p}</td><td valign="top" style="width:41%;'
            'padding:8px 12px 8px 0;line-height:1.45;{e}">{a}</td><td valign="top" style="width:10%;padding:8px 8px 8px 0;'
            'font-size:12px;{e}">{o}</td><td valign="top" style="width:14%;padding:7px 8px 7px 0;{e}">{ap}</td>'
            '<td valign="top" style="width:28%;padding:7px 0;line-height:1.9;{e}">{cmd}</td></tr>'.format(
                e=edge, p=_pill("P{}".format(a["p"]), PRIO_COLOR[a["p"]], solid=True, size=11), a=_hx(a["action"]),
                o=_hx(a["owner"]),
                ap=_pill("needs approval", "amber", size=11) if a["approval"] else _pill("automatic", "green", size=11),
                cmd=_rchip(a["cmd"], None, True) if a["cmd"] else ""))
    return _box("Recommended actions", _table(out) + c.more("actions"), count=str(len(c.all("actions"))))


def _sec_gaps(c):
    gaps = c.get("gaps")
    if not gaps:
        return ""
    rows = ['<tr><td valign="top" style="width:2%;color:{};padding:3px 0;font-weight:700">&#9656;</td>'
            '<td valign="top" style="padding:3px 0;line-height:1.5">{}</td></tr>'.format(_col("amber"), _hx(g)) for g in gaps]
    return _box("Gaps", _table(rows) + c.more("gaps"), count=str(len(c.all("gaps"))), accent="amber")


# -- J. footer ------------------------------------------------------------------------------------------------------

def _sec_footer(c):
    m = c.meta
    chips = []
    if _clip(m.get("model"), 60):
        chips.append(_rchip("model " + _clip(m.get("model"), 60), None))
    if _clip(m.get("run_id"), 40):
        chips.append(_rchip("run " + _clip(m.get("run_id"), 40), None))
    if _clip(m.get("generated"), 30):
        chips.append(_rchip("built " + _clip(m.get("generated"), 30), None))
    n = c.unverified()
    chips.append(_pill("⚠ {} unverified item{}".format(n, "" if n == 1 else "s"), "amber", size=11) if n
                 else _pill("✓ every item has a reference", "green", size=11))
    return '<div style="font-size:11px;line-height:2.1;padding:2px 2px">{}</div>'.format(" ".join(chips))


#: The sections of each part of the page. The incident page limits how much one dynamic section may return, so the page is
#: three sections (the layout has one per part), each far below that limit.
PART_SECTIONS = {
    "overview": (("Guardian assessment", _sec_header), ("Kill chain", _sec_killchain), ("Attack chain", _sec_attack)),
    "story": (("Relationship map", _sec_graph), ("Causality chain", _sec_tree), ("Timeline", _sec_timeline)),
    "findings": (("Findings", _sec_findings), ("Recommended actions", _sec_actions), ("Gaps", _sec_gaps)),
}
PARTS = ("overview", "story", "findings", "all")
DEFAULT_PART = "overview"
SECTIONS = PART_SECTIONS["overview"] + PART_SECTIONS["story"] + PART_SECTIONS["findings"]
#: The list a section can be shortened by, when its part is over the size limit.
TRIM_KEYS = {"Attack chain": "attack", "Relationship map": "graph", "Causality chain": "tree", "Timeline": "timeline",
             "Findings": "findings", "Recommended actions": "actions", "Gaps": "gaps"}
MAX_PART_BYTES = 30000
MORE_NOTE = "{} more not shown, see the full report with !GuardianLayoutAssessment part=all"
SEE_ABOVE = "See the assessment above."
NOTHING_HERE = "Nothing to show here for this report."


def _wrap(parts):
    return '<div style="font-size:13px;line-height:1.45">{}</div>'.format(_GAP.join(parts))


def _size(parts):
    return len(_wrap(parts).encode("utf-8"))


def render_report(report: dict, meta: dict = None, part: str = "all") -> str:
    """HTML for one part of the report (`overview`, `story`, `findings`) or all of it, or None when there is nothing to draw
    in it (the caller shows the old card or a note). A part over `MAX_PART_BYTES` is shortened: rows are dropped from the end
    of its biggest section until it fits, and the section says how many are not shown. `all` is never shortened."""
    try:
        if not isinstance(report, dict):
            return None
        c = _Ctx(report, meta)
        sections = SECTIONS if part == "all" else PART_SECTIONS.get(part, ())
        rendered, drawn = [], 0
        for name, fn in sections:
            try:
                out = fn(c)
                drawn += 1 if out else 0
            except Exception as exc:  # one broken section must not take the page down
                out = _note(name, exc)
            rendered.append([name, fn, out])
        if not drawn:
            return None
        footer = ""
        if part in ("findings", "all"):
            try:
                footer = _sec_footer(c)
            except Exception as exc:
                footer = _note("Footer", exc)

        def parts():
            return [out for _n, _f, out in rendered if out] + ([footer] if footer else [])

        while part != "all" and _size(parts()) > MAX_PART_BYTES:
            candidates = [item for item in rendered if item[2] and item[0] in TRIM_KEYS and c.can_trim(TRIM_KEYS[item[0]])]
            if not candidates:
                break
            item = max(candidates, key=lambda i: len(i[2]))
            c.trim(TRIM_KEYS[item[0]])
            try:
                item[2] = item[1](c)
            except Exception as exc:
                item[2] = _note(item[0], exc)
        return _wrap(parts())
    except Exception:
        return None


def _report_for_run(m):
    """The report record when it belongs to this run: same `run_id` as `Guardian.Loop` and, when both have one, the same
    tick. ``None`` otherwise (no report, a failed step, a report of an earlier run)."""
    record, loop = m["report"], m["loop"]
    report = record.get("report")
    if not isinstance(report, dict) or not report:
        return None
    run_id = _s(loop.get("run_id"))
    if not run_id or _s(record.get("run_id")) != run_id:
        return None
    tick, now = _number(record.get("tick")), _number(loop.get("tick"))
    if tick is not None and now is not None and tick != now:
        return None
    # the run id is the incident id and the tick restarts at 0 on a re-run: the last assistant fingerprint tells the runs apart
    mark, current = _s(record.get("fingerprint")), _s(loop.get("last_assistant_fingerprint"))
    if mark and current and mark != current:
        return None
    return record


def _report_parts(m):
    """``(report, meta)`` ready to draw for this run, or ``None`` when there is no report of this run or nothing in it can be
    drawn. The header values are the run's own, never the report's."""
    record = _report_for_run(m)
    if record is None:
        return None
    incident, loop = m["incident"], m["loop"]
    report = {k: v for k, v in record["report"].items() if k not in ("verdict", "confidence", "severity", "refs")}
    refs = record.get("refs")
    report["refs"] = refs if isinstance(refs, dict) else {}
    if render_report(report, {}) is None:
        return None
    verdict = {"Likely benign": "benign"}.get(m["verdict"], m["verdict"].lower())
    if verdict:
        report["verdict"] = verdict
    if m["confidence"] is not None:
        report["confidence"] = m["confidence"]
    report["severity"] = {"from": m["severity_before"], "to": m["severity_after"] or "", "reason": m["severity_head"]}
    activity = _dict(loop.get("activity"))
    meta = {
        "model": _s(record.get("model")), "turns": loop.get("tick"), "tokens": loop.get("cost_tokens_total"),
        "cost": loop.get("cost_usd"), "run_id": _s(loop.get("run_id")), "tool_calls": activity.get("calls"),
        "generated": _s(record.get("generated_at"))[:16].replace("T", " ") + ("Z" if _s(record.get("generated_at")) else ""),
        "incident": {"id": _s(incident.get("id")), "name": _s(incident.get("name")), "type": _s(incident.get("type")),
                     "owner": _s(incident.get("owner"))},
    }
    return report, meta


def _report_page(m, part="all"):
    """One part of the report page for the run, or ``None`` when there is no report of this run or it cannot be drawn."""
    ready = _report_parts(m)
    return None if ready is None else render_report(ready[0], ready[1], part)


def _entry(kind, contents):
    return {"Type": entryTypes["note"], "ContentsFormat": formats[kind], "Contents": contents}


def _part_note(kind, text):
    return _entry("markdown", text) if kind == "markdown" else \
        _entry("html", '<div style="opacity:.7;font-size:12px">{}</div>'.format(_esc(text)))


def build_entry(incident, context, output_format="html", part=DEFAULT_PART):
    """The entry for one part of the page. The incident page limits what one dynamic section may return, so the layout has
    three sections, each asking for a part: `overview` (the default, what a section with no arguments gets), `story` and
    `findings`. `all` is everything, for a War Room command. The states with no report of this run (and the card that
    shows them) are in `overview`; the other parts then say to see it."""
    part = part if part in PARTS else DEFAULT_PART
    model = _collect(incident, context)
    later = part in ("story", "findings")
    if not model["has_data"]:
        if later:
            return _part_note(output_format, SEE_ABOVE)
        message = "Guardian has not assessed this incident yet."
        return _entry("markdown", message) if output_format == "markdown" else \
            _entry("html", '<div style="opacity:.75;font-size:13px">{}</div>'.format(message))
    if output_format == "markdown":
        return _part_note("markdown", SEE_ABOVE) if later else _entry("markdown", render_markdown(model))
    try:
        try:
            if later:
                ready = _report_parts(model)
                if ready is None:
                    return _part_note("html", SEE_ABOVE)
                page = render_report(ready[0], ready[1], part)
                return _entry("html", page) if page else _part_note("html", NOTHING_HERE)
            page = _report_page(model, part)
        except Exception as exc:  # the report is the richer page; the card is the fallback
            demisto.error("GuardianLayoutAssessment: report page failed, using the card: {}".format(exc))
            if later:
                return _part_note("html", SEE_ABOVE)
            page = None
        return _entry("html", page or render_html(model))
    except Exception as exc:  # a display script must not break the layout: show the Markdown instead
        demisto.error("GuardianLayoutAssessment: HTML build failed, using Markdown: {}".format(exc))
    return _part_note("markdown", SEE_ABOVE) if later else _entry("markdown", render_markdown(model))


def main():
    try:
        args = demisto.args() or {}
        output_format = str(args.get("format") or "html").strip().lower()
        part = str(args.get("part") or DEFAULT_PART).strip().lower()
        incident = _dict(demisto.incident())
        return_results(build_entry(incident, demisto.context() or {}, output_format, part))
    except Exception as exc:
        return_error("GuardianLayoutAssessment failed unexpectedly: {}".format(exc))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
