import re
from datetime import datetime, timezone

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

GUARDIAN_CONTAIN_MAX_LEN = 256
GUARDIAN_CONTAIN_ENDPOINT_MAX_LEN = 128
_GUARDIAN_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
#: Inline markdown/HTML structural characters. Backslash-escaped so an attacker-influenceable value
#: cannot render as a link/image/emphasis/code/heading/blockquote/table/HTML. XSOAR 6 renders the
#: note entry as markdown regardless of CommandResults(content_format="text"), so escaping (not the
#: entry format) is the load-bearing control. Backslash is escaped first so it is not double-escaped.
_GUARDIAN_MD_ESCAPE_RE = re.compile(r"([\\`*_\[\]()#!<>|~])")


def guardian_contain_sanitize(value, max_len):
    """Render a model-authored (untrusted, attacker-influenceable) string safe for a War Room note +
    context output: coerce to str, replace control chars/newlines with a space, collapse whitespace,
    hard-cap length, then neutralize inline markdown/HTML by backslash-escaping structural characters.
    The result is single-line AND cannot form a link/image/emphasis/fake block, so it cannot break out
    of its slot or forge an entry/approval line however it is later rendered (text or markdown)."""
    text = "" if value is None else str(value)
    text = _GUARDIAN_CONTROL_CHARS_RE.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()
    truncated = len(text) > max_len
    if truncated:
        text = text[:max_len]
    text = _GUARDIAN_MD_ESCAPE_RE.sub(r"\\\1", text)  # neutralize inline markdown AFTER the cap
    if truncated:
        text += "…truncated"  # markdown-inert marker, appended after escaping so it stays literal
    return text


def guardian_containment_simulate(args):
    """DUMMY simulated endpoint isolation -- inert. Emits exactly ONE plain-text entry describing what
    a REAL isolation WOULD do, with every model-supplied value sanitized. Performs NO EDR/containment
    effect and NO control-plane mutation; its only write is the namespaced Guardian.SimulatedContainment
    context of this single entry. Never raises."""
    endpoint_id = guardian_contain_sanitize(args.get("endpoint_id"), GUARDIAN_CONTAIN_ENDPOINT_MAX_LEN)
    reason = guardian_contain_sanitize(args.get("reason"), GUARDIAN_CONTAIN_MAX_LEN)
    ts = datetime.now(timezone.utc).isoformat()
    outputs = {"endpoint_id": endpoint_id, "reason": reason, "action": "simulate-isolate",
               "simulated": True, "ts": ts}
    if not endpoint_id:
        outputs["error"] = "missing endpoint_id"
        note = ("SIMULATED CONTAINMENT — ERROR: no endpoint_id supplied. NO real action taken (dummy).\n"
                "[untrusted, model-supplied] reason: {}".format(reason or "(none)"))
    else:
        note = ("SIMULATED CONTAINMENT — would isolate endpoint; NO real action taken (dummy).\n"
                "[untrusted, model-supplied]\n  endpoint_id: {}\n  reason: {}".format(
                    endpoint_id, reason or "(none)"))
    return CommandResults(
        readable_output=note,
        content_format="text",  # plain text, never markdown (defense-in-depth; sanitize is the primary control)
        outputs_prefix="Guardian.SimulatedContainment",
        outputs=outputs,
    )


def main():
    try:
        return_results(guardian_containment_simulate(demisto.args()))
    except Exception as ex:
        return_error("Failed to execute GuardianContainmentSimulate. Error: {}".format(str(ex)))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
