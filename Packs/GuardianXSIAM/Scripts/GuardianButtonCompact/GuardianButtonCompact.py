"""Guardian Agent Run layout button: compact the agent's transcript now.

Calls the existing `guardian-compact` command with its defaults (keep the 10 newest messages), which
summarizes the older ones into a checkpoint. It makes one billed model call and returns an error
when there is no active loop or the transcript is already short.

Operator-only: listed in the code-level GUARDIAN_OPERATOR_ONLY_COMMANDS sets of GuardianToolBridge
and GuardianToolCatalogBuilder, so the model can neither see nor call it.
"""

import json

import demistomock as demisto
from CommonServerPython import *  # noqa: F401

#: Recorded as the resolver / toggler, so the audit trail shows the action came from the layout.
GUARDIAN_BUTTON_ACTOR = "analyst (layout button)"

#: The runtime approvals ledger (read only here, to check which incident a request belongs to).
GUARDIAN_APPROVALS_LEDGER_LIST_NAME = "guardian_approvals_ledger"

#: Longest id / text a button forwards.
GUARDIAN_BUTTON_MAX_ID_CHARS = 128
GUARDIAN_BUTTON_MAX_TEXT_CHARS = 4000


def _guardian_button_errors(entries):
    """Join the text of every error entry (``Type == 4``) of an ``executeCommand`` result."""
    return "; ".join(
        str(entry.get("Contents") or "error")
        for entry in entries or []
        if isinstance(entry, dict) and entry.get("Type") == 4
    )


def _guardian_button_text(value, max_len):
    """A trimmed, length-capped string argument (``""`` for anything that is not text)."""
    return value.strip()[:max_len] if isinstance(value, str) else ""


def _guardian_button_run(command, args):
    """Run an operator command. Returns ``(ok, entries_or_error_text)``; never raises."""
    try:
        entries = demisto.executeCommand(command, args)
    except Exception as exc:
        return False, "{} raised: {}".format(command, exc)
    error = _guardian_button_errors(entries)
    if error:
        return False, error
    return True, entries


def guardian_button_compact():
    """Compact this incident's transcript now. Returns ``(ok, text)``."""
    ok, result = _guardian_button_run("guardian-compact", {})
    if not ok:
        return False, result
    notes = []
    for entry in result or []:
        if isinstance(entry, dict) and entry.get("Type") != 4:
            text = entry.get("HumanReadable") or (entry.get("Contents") if isinstance(entry.get("Contents"), str) else "")
            if text:
                notes.append(str(text).strip())
    return True, "\n\n".join(notes) or "Transcript compacted."


def main():
    args = demisto.args()
    try:
        ok, text = guardian_button_compact()
    except Exception as exc:
        return_error("GuardianButtonCompact failed unexpectedly: {}".format(exc))
        return
    if not ok:
        return_error(text)
        return
    return_results(CommandResults(readable_output=text))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
