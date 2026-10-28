"""GuardianLayoutAssessment -- the assessment card for the Guardian tab of GuardianAgentRunLayout.

One readable card with the verdict, confidence, investigation type and complexity, the severity before and after
with the reason, the summary, analysis, recommended actions and next step, the key entities, the ATT&CK techniques,
the agent's conclusion (Markdown rendered as HTML), the actions waiting for approval, and the ticks, tokens and cost.

Display only: it never writes context, a List or an issue field, and never calls GuardianToolBridge. It is
self-contained on purpose (`demistomock`, `CommonServerPython` and the standard library only, no shared Guardian
block), so an operator can paste it into the automation editor by hand.

Data, every key optional (a context value may be a dict or a list of dicts; the last dict is used): `Guardian.Triage`
(GuardianTriageResult), `Guardian.TriageApply` (GuardianTriageApply), `Guardian.Loop` (`verdict`, `status`, `tick`,
`cost_*`, `messages`), `demisto.incident()` (the issue), and the pending rows of the `guardian_approvals_ledger` List (left out
when the List cannot be read).

Output: one HTML note entry with inline styles only (no script, style block, external resource or details element; every
value escaped; solid white-on-colour badges, inherited text colour and rgba borders so it reads on light and dark
themes). `format=markdown` returns the same content as a Markdown note, and so does a failure while building the HTML.
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
    for part, name in (("critical", "critical"), ("high", "high"), ("medium", "medium"), ("low", "low"),
                       ("info", "informational")):  # a platform label such as SEV_040_HIGH
        if part in text:
            return name
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
        ("Issue", "#{} {}".format(incident.get("id"), _s(incident.get("name"))).strip() if incident.get("id") else ""),
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
        lines.append(md("Issue #{} {}".format(incident.get("id"), _s(incident.get("name"))).strip()))
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


def _entry(kind, contents):
    return {"Type": entryTypes["note"], "ContentsFormat": formats[kind], "Contents": contents}


def build_entry(incident, context, output_format="html"):
    model = _collect(incident, context)
    if not model["has_data"]:
        message = "Guardian has not assessed this issue yet."
        return _entry("markdown", message) if output_format == "markdown" else \
            _entry("html", '<div style="opacity:.75;font-size:13px">{}</div>'.format(message))
    if output_format != "markdown":
        try:
            return _entry("html", render_html(model))
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
