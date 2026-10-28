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
value escaped; the report page is built from tables, and colour comes from `color` and `border`; the card uses solid
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


def _severity_change(incident, apply_record):
    """``(before, after, text)``: the severity badges to show and one line saying what Guardian did and why."""
    if not apply_record:
        return _severity(incident.get("severity")), None, "Severity was not changed by Guardian in this run."
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
        return before, after, head + (" " + DASH + " " + reason if reason else "")
    head = {"dry_run": "Dry run, unchanged", "error": "Not changed (error)"}.get(status, "Unchanged")
    return before, None, head + (": " + reason if reason else "")


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
    model = {
        "incident": incident, "triage": triage, "verdict": name,
        "confidence": None if confidence is None else int(confidence),
        "kind": _s(triage.get("investigation_type")) or _s(triage.get("branch")), "complexity": _s(triage.get("complexity")),
        "escalate": triage.get("escalate") is True, "run_status": _s(loop.get("status")),
        "severity_before": before, "severity_after": after, "severity_text": severity_text,
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
# Built from tables, because the incident page's HTML filter keeps layout only from tables, `color` and `border`. Every string
# comes from the model and is escaped; colours and styles come only from the lookups below, never from the report.

GREY = "#7f8791"
PAL = {
    "red": ("#e5484d", "rgba(229,72,77,.14)"), "orange": ("#f76b15", "rgba(247,107,21,.14)"),
    "amber": ("#d18b00", "rgba(209,139,0,.14)"), "green": ("#2f9e63", "rgba(47,158,99,.14)"),
    "blue": ("#2f80ed", "rgba(47,128,237,.14)"), "grey": (GREY, "rgba(127,135,145,.14)"),
}
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
TYPE_COL = {"user": 0, "email": 0, "host": 1, "cloud": 1, "process": 2, "file": 2, "domain": 3, "url": 3, "hash": 3,
            "other": 3, "ip": 4}
MAX_GRAPH_ROWS = 40
MAX_REFS = 200

_ID = re.compile(r"^[A-Za-z0-9_.\-]{1,12}$")
_TIME = re.compile(r"^\s*(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})(?::(\d{2}))?")
_GAP = '<div style="height:10px;font-size:1px">&nbsp;</div>'


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


def _pill(text, color):
    return ('<span style="color:{c};border:1px solid {c};background:{t};padding:1px 8px;font-size:12px;'
            'font-weight:700">{x}</span>').format(c=_col(color), t=_tint(color), x=_hx(text))


def _rchip(text, color=None, wrap=False):
    c = _col(color) if color else LINE2
    return '<span style="{}border:1px solid {};padding:0 5px;font-size:11px;{}{}">{}</span>'.format(
        "color:{};".format(c) if color else "", c, MONO, ";word-break:break-all" if wrap else "", _hx(text))


def _mono(text, size=12, color=None, bold=False):
    return '<span style="{m};font-size:{s}px{c}{b}">{x}</span>'.format(
        m=MONO, s=size, c=";color:" + color if color else "", b=";font-weight:700" if bold else "", x=_hx(text))


def _refmark(ref_ids):
    if ref_ids:
        return '<span style="color:{};font-size:11px">✓&nbsp;{}&nbsp;ref{}</span>'.format(
            _col("green"), len(ref_ids), "" if len(ref_ids) == 1 else "s")
    return '<span style="color:{};font-size:11px;font-weight:700">⚠&nbsp;unverified</span>'.format(_col("amber"))


def _box(title, body, details=False, count=None, accent=None):
    label = _hx(title.upper()) + (" " + _mono(str(count), 11, GREY) if count else "")
    head = 'font-size:11px;font-weight:700;color:{}'.format(GREY)
    border = "border:1px solid {};".format(LINE) if not accent else "border:1px solid {c};border-left:4px solid {c};".format(
        c=_col(accent))
    if details:
        inner = '<details open><summary style="{}">{}</summary><div style="padding-top:8px">{}</div></details>'.format(
            head, label, body)
    else:
        inner = '<div style="{};padding-bottom:8px">{}</div>{}'.format(head, label, body)
    return ('<table cellspacing="0" style="width:100%;{}font-size:13px"><tr>'
            '<td style="padding:10px 12px">{}</td></tr></table>').format(border, inner)


def _note(name, exc):
    return '<div style="font-size:12px;color:{};padding:2px 0">Section {} skipped ({}).</div>'.format(
        GREY, _hx(name), _hx(type(exc).__name__))


def _table(rows, extra=""):
    return '<table cellspacing="0" style="width:100%;{}">{}</table>'.format(extra, "".join(rows))


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

    def get(self, name):
        if name not in self._cache:
            self._cache[name] = getattr(self, "_n_" + name)()
        return self._cache[name]

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

    def unverified(self):
        total = 0
        for name in ("entities", "edges", "attack", "timeline", "tree", "findings"):
            try:
                total += sum(1 for item in self.get(name) if not item["ref"])
            except Exception:
                pass
        return total


# -- A. header ------------------------------------------------------------------------------------------------------

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
        cells.append('<td valign="top" style="width:20%;padding:0 12px 8px 0">{}</td>'.format(_pill(verdict.upper(), color)))
    if conf is not None:
        meter = []
        if conf:
            meter.append('<td style="width:{}%;height:6px;font-size:1px;border:1px solid {c};border-bottom:3px solid {c};'
                         'background:{t}">&nbsp;</td>'.format(conf, c=_col(color), t=_tint(color)))
        if conf < 100:
            meter.append('<td style="width:{}%;height:6px;font-size:1px;border:1px solid {}">&nbsp;</td>'.format(
                100 - conf, LINE))
        cells.append('<td valign="top" style="width:30%;padding:0 16px 8px 0"><div style="font-size:11px;color:{}">CONFIDENCE '
                     '<b style="color:{};font-size:13px">{}%</b></div>{}</td>'.format(
                         GREY, _col(color), conf, _table(['<tr>' + "".join(meter) + '</tr>'], "margin-top:3px")))
    if sfrom or sto:
        pills = " &#9656; ".join(_pill(s.upper(), SEV_COLOR[s]) for s in (sfrom, sto) if s)
        cells.append('<td valign="top" style="padding:0 0 8px 0"><div style="font-size:11px;color:{}">SEVERITY</div>{}{}</td>'.format(
            GREY, pills, '<div style="font-size:12px;padding-top:3px">{}</div>'.format(_hx(reason)) if reason else ""))
    rows = ['<tr>{}</tr>'.format("".join(cells))] if cells else []
    if headline:
        rows.append('<tr><td colspan="3" style="font-size:17px;font-weight:700;line-height:1.3;padding:2px 0 4px 0">{}</td>'
                    '</tr>'.format(_hx(headline)))
    inc = c.meta.get("incident") if isinstance(c.meta.get("incident"), dict) else {}
    bits = []
    if _clip(inc.get("id"), 20):
        bits.append("Incident " + _mono("#" + _clip(inc.get("id"), 20), 12))
    for key in ("name", "type", "owner"):
        if _clip(inc.get(key), 80):
            bits.append(_t(inc.get(key), 80))
    if bits:
        rows.append('<tr><td colspan="3" style="font-size:12px;color:{}">{}</td></tr>'.format(GREY, " &middot; ".join(bits)))
    return _box("Guardian assessment", _table(rows), accent=color)


# -- B. kill chain strip --------------------------------------------------------------------------------------------

def _sec_killchain(c):
    attack = c.get("attack")
    if not attack:
        return ""
    counts = [0] * 14
    for a in attack:
        if a["slot"] is not None:
            counts[a["slot"]] += 1
    cells = []
    for i, label in enumerate(TACTICS):
        w = "width:7.1%;text-align:center;padding:5px 1px;font-size:10px;line-height:1.25;word-break:break-word;"
        if counts[i]:
            cells.append('<td style="{}border:1px solid {c};border-top:4px solid {c};font-weight:700">{}<br>'
                         '<span style="color:{c}">{}</span></td>'.format(w, _hx(label), counts[i], c=_col("orange")))
        else:
            cells.append('<td style="{}border:1px solid {};color:{}">{}<br>&nbsp;</td>'.format(w, LINE, GREY, _hx(label)))
    seen = sum(1 for n in counts if n)
    return _box("Kill chain", _table(['<tr>' + "".join(cells) + '</tr>']), count="{} of 14 tactics".format(seen))


# -- C. attack chain ------------------------------------------------------------------------------------------------

def _card(c, step, a, ents):
    time = _tkey(a["time"])
    chips = [ents[e]["value"] for e in a["ents"] if e in ents]
    chips_html = " ".join(_rchip(_clip(v, 24), None, len(v) > 18) for v in chips[:3])
    if len(chips) > 3:
        chips_html += " " + _mono("+{}".format(len(chips) - 3), 11, GREY)
    tech = (_mono(a["tech"], 12, bold=True) + " " if a["tech"] else "") + _hx(a["name"])
    return ('<td valign="top" style="width:23%;border:1px solid {l};border-top:3px solid {o};padding:7px 9px;font-size:12px;line-height:1.4">'
            '<div>{n} <b style="color:{o}">{tac}</b></div><div style="padding-top:2px">{tech}</div>'
            '<div style="padding-top:3px;color:{g}">{ev}</div>'
            '<div style="padding-top:4px;font-size:11px">{time}{refs}</div>'
            '<div style="padding-top:4px;line-height:1.7">{chips}</div></td>').format(
                l=LINE, o=_col("orange"), g=GREY, n=_mono("{:02d}".format(step), 12, GREY, True), tac=_hx(a["tactic"]),
                tech=tech, ev=_hx(a["evidence"]),
                time=(_mono("{} {}Z".format(time[0][5:], time[1][:5]), 11, GREY) + " &nbsp; ") if time else "",
                refs=_refmark(a["ref"]), chips=chips_html)


def _sec_attack(c):
    attack = c.get("attack")
    if not attack:
        return ""
    ents, rows = c.ent_map(), []
    blank = '<td style="width:23%">&nbsp;</td>'
    arrow = '<td style="width:2.6%;text-align:center;font-size:14px;color:{}">&#9656;</td>'.format(GREY)
    for start in range(0, len(attack), 4):
        group = attack[start:start + 4]
        cells = []
        for j in range(4):
            if j:
                cells.append(arrow if j < len(group) else '<td style="width:2.6%">&nbsp;</td>')
            cells.append(_card(c, start + j + 1, group[j], ents) if j < len(group) else blank)
        rows.append('<tr>{}</tr>'.format("".join(cells)))
        if start + 4 < len(attack):
            rows.append('<tr><td colspan="7" style="height:8px;font-size:1px;line-height:8px">&nbsp;</td></tr>')
    return _box("Attack chain", _table(rows), count="{} steps".format(len(attack)))


# -- D. relationship map --------------------------------------------------------------------------------------------

def _graph(c):
    """Layered left-to-right layout on a 9-column occupancy grid (5 node columns, 4 connector columns).

    Returns {"rows": [[anchor, ...], ...], "unlinked": [entity, ...], "dropped": n}. An anchor is a dict with x (grid
    column), cs, rs and kind: node / conn / empty. Covered grid cells are not emitted, so the anchors of all rows
    tile the grid exactly once."""
    ents = c.ent_map()
    order = [e["id"] for e in c.get("entities")]
    col = dict((i, TYPE_COL.get(ents[i]["type"], 3)) for i in order)
    fwd, has_in, notes, linked = {}, set(), {}, set()
    for e in c.get("edges"):
        a, b = e["from"], e["to"]
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
    grid = [[None] * 9 for _ in range(total)]
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
            kl = col[kid["id"]]
            put(row, 2 * level + 1, {"kind": "conn", "link": link, "rs": kid["span"], "cs": 2 * (kl - level) - 1})
            place(kid, row, kl)
            row += kid["span"]

    r = 0
    for tree in trees:
        place(tree, r, col[tree["id"]])
        r += tree["span"]
    rows = []
    for ri in range(total):
        cells, x = [], 0
        while x < 9:
            cell = grid[ri][x]
            if cell is covered:
                x += 1
            elif cell is None:
                run = 1
                while x + run < 9 and grid[ri][x + run] is None:
                    run += 1
                cells.append({"kind": "empty", "x": x, "cs": run, "rs": 1})
                x += run
            else:
                cells.append(cell)
                x += cell["cs"]
        rows.append(cells)
    return {"rows": rows, "unlinked": [ents[i] for i in order if i not in linked], "dropped": dropped}


def _graph_rows(c):
    return _graph(c)["rows"]


def _node_html(c, ent, dup, notes):
    color = REP_COLOR.get(ent["rep"], "grey")
    tag = [_hx(ETAG[ent["type"]])]
    if ent["role"] in ("victim", "attacker"):
        tag.append(_hx(ent["role"]))
    if ent["rep"] in ("malicious", "suspicious"):
        tag.append('<span style="color:{}">{}</span>'.format(_col(color), ent["rep"]))
    head = '<div style="font-size:10px;font-weight:700;color:{};line-height:1.3">{}{}{}</div>'.format(
        GREY, " &middot; ".join(tag), " <span style=\"color:{}\">&#8634;</span>".format(GREY) if dup else "",
        "" if ent["ref"] else ' <span style="color:{};font-size:11px">&#9888;</span>'.format(_col("amber")))
    value = '<div style="{};font-size:11px;word-break:break-all;line-height:1.3{}">{}</div>'.format(
        MONO, ";color:{};font-weight:700".format(_col(color)) if ent["rep"] in ("malicious", "suspicious") else "",
        _hx(_shorten(ent["value"], ent["type"])))
    extra = "".join('<div style="font-size:10px;color:{};line-height:1.3;word-break:break-word">&#9666; {}</div>'.format(
        GREY, _hx(n)) for n in notes[:2]) if not dup else ""
    return '<div style="border:1px solid {c};border-left:3px solid {c};padding:3px 4px">{}{}{}</div>'.format(
        head, value, extra, c=_col(color))


def _conn_html(link):
    rels = list(dict.fromkeys(link["rels"]))
    rev = all(r for _, r in rels)
    label = "/".join(("\u25c2" if r and not rev else "") + REL_LABEL[k] for k, r in rels)
    mark = '<span style="color:{};font-weight:700">&#9888;</span> '.format(_col("amber")) if not link["ok"] else ""
    line = '<td style="height:0;font-size:1px;line-height:1px;padding:0;border:1px solid {};border-width:1px 0 0 0">&nbsp;</td>'.format(LINE2)
    head = '<td style="width:9px;padding:0;font-size:11px;line-height:3px;height:3px;color:{}">&#9666;</td>'.format(GREY)
    tail = '<td style="width:9px;padding:0;font-size:11px;line-height:3px;height:3px;color:{};text-align:right">&#9656;</td>'.format(GREY)
    cells = (head + line) if rev else (line + tail)
    return ('<table cellspacing="0" style="width:100%"><tr><td colspan="2" style="text-align:center;font-size:10px;'
            'line-height:1.2;padding-bottom:4px;word-break:break-all;{m};color:{g}">{mark}{label}</td></tr>'
            '<tr>{cells}</tr></table>').format(m=MONO, g=GREY, mark=mark, label=_hx(label), cells=cells)


def _sec_graph(c):
    ents = c.ent_map()
    if not c.get("edges") and not ents:
        return ""
    g = _graph(c)
    widths = []
    for i in range(9):
        widths.append("14%" if i % 2 == 0 else "7.5%")
    head = ['<td style="width:{};font-size:11px;font-weight:700;color:{};padding:0 0 2px 0">{}</td>'.format(
        widths[i], GREY, _hx(GRAPH_COLS[i // 2]) if i % 2 == 0 else "&nbsp;") for i in range(9)]
    rows = ['<tr>' + "".join(head) + '</tr>']
    for row in g["rows"]:
        tds = []
        for cell in row:
            span = ' colspan="{}"'.format(cell["cs"]) if cell["cs"] > 1 else ""
            span += ' rowspan="{}"'.format(cell["rs"]) if cell["rs"] > 1 else ""
            if cell["kind"] == "node":
                n = cell["node"]
                tds.append('<td{} style="padding:3px 0">{}</td>'.format(
                    span, _node_html(c, ents[n["id"]], n["dup"], cell["notes"])))
            elif cell["kind"] == "conn":
                tds.append('<td{} style="padding:0 3px">{}</td>'.format(span, _conn_html(cell["link"])))
            else:
                tds.append('<td{}>&nbsp;</td>'.format(span))
        rows.append('<tr>' + "".join(tds) + '</tr>')
    body = _table(rows)
    if g["unlinked"]:
        chips = " ".join(
            '<span style="color:{c};border:1px solid {c};padding:0 5px;font-size:11px;{m}">{t} {v}</span>'.format(
                c=_col(REP_COLOR.get(e["rep"], "grey")), m=MONO, t=_hx(ETAG[e["type"]]),
                v=_hx(_clip(_shorten(e["value"], e["type"]), 40))) for e in g["unlinked"])
        body += '<div style="padding-top:8px;font-size:11px;color:{};line-height:1.9">Not linked&nbsp;&nbsp;{}</div>'.format(GREY, chips)
    if g["dropped"]:
        body += '<div style="padding-top:4px;font-size:11px;color:{}">{} more graph branches not shown.</div>'.format(GREY, g["dropped"])
    return _box("Relationship map", body, count="{} entities".format(len(ents)))


# -- E. causality chain ---------------------------------------------------------------------------------------------

def _sec_tree(c):
    """The process tree, one small table per row: a prefix cell (the guides) and a name cell, so every row's name starts
    exactly where its prefix ends. A child's prefix is one step (three characters) longer than its parent's, and its branch
    mark sits under the first character of the parent's name."""
    nodes = c.get("tree")
    if not nodes:
        return ""
    by_id = dict((n["id"], n) for n in nodes)
    kids = {}
    for n in nodes:
        parent = n["parent"] if n["parent"] in by_id and n["parent"] != n["id"] else None
        kids.setdefault(parent, []).append(n)
    rows, seen = [], set()
    pipe, gap = "\u2502&nbsp;&nbsp;", "&nbsp;&nbsp;&nbsp;"

    def emit(n, guides, last, top):
        seen.add(n["id"])
        base = "".join(pipe if g else gap for g in guides)
        first = base + ("" if top else ("\u2514\u2500&nbsp;" if last else "\u251c\u2500&nbsp;"))
        child_guides = guides if top else guides + [not last]
        children = [k for k in kids.get(n["id"], []) if k["id"] not in seen]
        cont = "".join(pipe if g else gap for g in child_guides)
        color = FLAG_COLOR.get(n["flag"])
        name = '<b style="{};font-size:12px{}">{}{}</b>'.format(
            MONO, ";color:" + _col(color) if color else "", "\u25cf&nbsp;" if color else "", _hx(n["name"]))
        line1 = name + (" " + _mono("[" + n["pid"] + "]", 11, GREY) if n["pid"] else "")
        if n["tech"]:
            line1 += " " + _rchip(n["tech"])
        line1 += " " + _refmark(n["ref"])
        line2 = ""
        if n["cmd"]:
            line2 = '<br><span style="{};font-size:11px;color:{};word-break:break-all">{}</span>'.format(
                MONO, GREY, _hx(_clip(n["cmd"], 130)))
        prefix = '<span style="{};font-size:12px;color:{}">{}{}</span>'.format(
            MONO, GREY, first, "<br>" + cont if line2 else "")
        rows.append('<table cellspacing="0" style="width:100%"><tr><td valign="top" style="width:1px;line-height:1.35;'
                    'padding:0 0 3px 0">{}</td><td valign="top" style="line-height:1.35;padding:0 0 3px 0">{}{}</td></tr></table>'
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
    return _box("Causality chain", "".join(rows), details=True, count="{} processes".format(len(nodes)))


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
            out.append('<tr><td colspan="6" style="padding:6px 0 3px 0;font-size:12px;font-weight:700">{}</td></tr>'.format(
                _mono(day + " UTC", 12, None, True)))
        verified = bool(x["ref"])
        dot = '<span style="color:{}">{}</span>'.format(
            _col("orange" if x["tech"] else "blue") if verified else _col("amber"), "●" if verified else "○")
        shown = key[1] if key else _clip(x["t"], 20)
        out.append(
            '<tr><td valign="top" style="width:62px;padding:3px 6px 3px 0">{t}</td>'
            '<td valign="top" style="width:22px;text-align:center;border:1px solid {l};border-top:0;border-bottom:0;border-right:0;'
            'padding:3px 0">{dot}</td><td valign="top" style="padding:3px 8px;font-size:12px;line-height:1.4">{ev}</td>'
            '<td valign="top" style="width:70px;padding:3px 4px">{src}</td>'
            '<td valign="top" style="width:76px;padding:3px 4px">{tech}</td>'
            '<td valign="top" style="width:84px;padding:3px 0">{ref}</td></tr>'.format(
                t=_mono(shown, 12, GREY), l=LINE2, dot=dot, ev=_hx(x["event"]),
                src=_rchip(x["src"], "grey") if x["src"] else "", tech=_rchip(x["tech"]) if x["tech"] else "",
                ref=_refmark(x["ref"])))
    return _box("Timeline", _table(out), details=True, count="{} events".format(len(rows)))


# -- G. findings ----------------------------------------------------------------------------------------------------

def _sec_findings(c):
    rows = c.get("findings")
    if not rows:
        return ""
    out = []
    for i, f in enumerate(rows, 1):
        chips = " ".join(_rchip("{} {}".format(r, _clip(c.refs[r][0], 28)), "green") for r in f["ref"]) if f["ref"] else \
            '<span style="color:{};font-weight:700;font-size:12px">⚠&nbsp;unverified</span>'.format(_col("amber"))
        out.append('<tr><td valign="top" style="width:22px;padding:4px 0">{}</td><td valign="top" style="padding:4px 0;line-height:1.45">'
                   '{}<div style="padding-top:3px;line-height:1.8">{}</div></td></tr>'.format(
                       _mono(str(i), 12, GREY, True), _hx(f["text"]), chips))
    return _box("Findings", _table(out), details=True, count=str(len(rows)))


# -- H. actions, I. gaps --------------------------------------------------------------------------------------------

def _sec_actions(c):
    rows = c.get("actions")
    if not rows:
        return ""
    th = 'font-size:11px;font-weight:700;color:{};padding:0 6px 4px 0'.format(GREY)
    out = ['<tr><td style="{w}width:34px">P</td><td style="{w}">ACTION</td><td style="{w}width:72px">OWNER</td>'
           '<td style="{w}width:88px">APPROVAL</td><td style="{w}width:30%">COMMAND</td></tr>'.format(w=th)]
    for a in rows:
        out.append(
            '<tr><td valign="top" style="width:34px;padding:5px 6px 5px 0">{p}</td><td valign="top" style="'
            'padding:5px 8px 5px 0;line-height:1.4">{a}</td><td valign="top" style="width:72px;padding:5px 6px 5px 0;'
            'font-size:12px">{o}</td><td valign="top" style="width:88px;padding:5px 6px 5px 0;font-size:12px">{ap}</td>'
            '<td valign="top" style="width:30%;padding:5px 0;word-break:break-all">{cmd}</td></tr>'.format(
                p=_pill("P{}".format(a["p"]), PRIO_COLOR[a["p"]]), a=_hx(a["action"]), o=_hx(a["owner"]),
                ap=('<span style="color:{};font-weight:700">needs&nbsp;approval</span>'.format(_col("amber")) if a["approval"]
                    else '<span style="color:{}">automatic</span>'.format(GREY)),
                cmd=_mono(a["cmd"], 11, GREY) if a["cmd"] else ""))
    return _box("Recommended actions", _table(out), count=str(len(rows)))


def _sec_gaps(c):
    gaps = c.get("gaps")
    if not gaps:
        return ""
    rows = ['<tr><td valign="top" style="width:18px;color:{};padding:2px 0">&#9656;</td>'
            '<td valign="top" style="padding:2px 0;line-height:1.45">{}</td></tr>'.format(_col("amber"), _hx(g)) for g in gaps]
    return _box("Gaps", _table(rows))


# -- J. footer ------------------------------------------------------------------------------------------------------

def _sec_footer(c):
    m = c.meta
    bits = []
    if _clip(m.get("model"), 60):
        bits.append("model " + _mono(_clip(m.get("model"), 60), 11))
    turns, tokens, cost = _num(m.get("turns")), _num(m.get("tokens")), _num(m.get("cost"))
    if turns is not None:
        bits.append("turns {:d}".format(int(turns)))
    if tokens is not None:
        bits.append("tokens {:,d}".format(int(tokens)))
    if cost is not None:
        bits.append("cost ${:.4f}".format(cost))
    if _clip(m.get("run_id"), 40):
        bits.append("run " + _mono(_clip(m.get("run_id"), 40), 11))
    n = c.unverified()
    bits.append('<span style="color:{};font-weight:700">{}</span>'.format(
        _col("amber"), "⚠ {} unverified item{}".format(n, "" if n == 1 else "s")) if n
        else '<span style="color:{}">✓ every item has a reference</span>'.format(_col("green")))
    return '<div style="font-size:11px;color:{};padding:2px 2px">{}</div>'.format(GREY, " &nbsp;|&nbsp; ".join(bits))


SECTIONS = (("Guardian assessment", _sec_header), ("Kill chain", _sec_killchain), ("Attack chain", _sec_attack),
            ("Relationship map", _sec_graph), ("Causality chain", _sec_tree), ("Timeline", _sec_timeline),
            ("Findings", _sec_findings), ("Recommended actions", _sec_actions), ("Gaps", _sec_gaps))


def render_report(report: dict, meta: dict = None) -> str:
    """HTML for the report, or None when there is nothing to draw (the caller shows the old card)."""
    try:
        if not isinstance(report, dict):
            return None
        c = _Ctx(report, meta)
        parts, drawn = [], 0
        for name, fn in SECTIONS:
            try:
                out = fn(c)
                drawn += 1 if out else 0
            except Exception as exc:  # one broken section must not take the page down
                out = _note(name, exc)
            if out:
                parts.append(out)
        if not drawn:
            return None
        try:
            parts.append(_sec_footer(c))
        except Exception as exc:
            parts.append(_note("Footer", exc))
        return '<div style="font-size:13px;line-height:1.45">{}</div>'.format(_GAP.join(parts))
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


def _report_page(m):
    """The report page for the run, or ``None`` when there is no report of this run or it cannot be drawn."""
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
    report["severity"] = {"from": m["severity_before"], "to": m["severity_after"] or "", "reason": m["severity_text"]}
    meta = {
        "model": _s(record.get("model")), "turns": loop.get("tick"), "tokens": loop.get("cost_tokens_total"),
        "cost": loop.get("cost_usd"), "run_id": _s(loop.get("run_id")),
        "incident": {"id": _s(incident.get("id")), "name": _s(incident.get("name")), "type": _s(incident.get("type")),
                     "owner": _s(incident.get("owner"))},
    }
    return render_report(report, meta)


def _entry(kind, contents):
    return {"Type": entryTypes["note"], "ContentsFormat": formats[kind], "Contents": contents}


def build_entry(incident, context, output_format="html"):
    model = _collect(incident, context)
    if not model["has_data"]:
        message = "Guardian has not assessed this incident yet."
        return _entry("markdown", message) if output_format == "markdown" else \
            _entry("html", '<div style="opacity:.75;font-size:13px">{}</div>'.format(message))
    if output_format != "markdown":
        try:
            try:
                page = _report_page(model)
            except Exception as exc:  # the report is the richer page; the card is the fallback
                demisto.error("GuardianLayoutAssessment: report page failed, using the card: {}".format(exc))
                page = None
            return _entry("html", page or render_html(model))
        except Exception as exc:  # a display script must not break the layout: show the Markdown instead
            demisto.error("GuardianLayoutAssessment: HTML build failed, using Markdown: {}".format(exc))
    return _entry("markdown", render_markdown(model))


def main():
    try:
        output_format = str((demisto.args() or {}).get("format") or "html").strip().lower()
        incident = _dict(demisto.incident())
        return_results(build_entry(incident, demisto.context() or {}, output_format))
    except Exception as exc:
        return_error("GuardianLayoutAssessment failed unexpectedly: {}".format(exc))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
