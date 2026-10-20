"""Guardian Agent Run layout button: pause ALL Guardian runs (kill switch on).

The kill switch is global: it halts every agent run within one poll cycle, not only the incident
this button was clicked on. There is no per-run pause. The reason (mandatory) is recorded by the
audited `guardian-killswitch` command, the only component that writes the protected switch.

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


def guardian_button_pause(reason):
    """Turn the global kill switch on. Returns ``(ok, text)``."""
    reason = _guardian_button_text(reason, GUARDIAN_BUTTON_MAX_TEXT_CHARS)
    if not reason:
        return False, "A reason is required before pausing the agent."
    ok, result = _guardian_button_run("guardian-killswitch", {"state": "on", "reason": reason, "actor": GUARDIAN_BUTTON_ACTOR})
    if not ok:
        return False, result
    return True, "All Guardian runs are paused (kill switch on) and halt within one poll cycle. Use Resume all runs to continue."


def main():
    args = demisto.args()
    try:
        ok, text = guardian_button_pause(args.get("reason"))
    except Exception as exc:
        return_error("GuardianButtonPause failed unexpectedly: {}".format(exc))
        return
    if not ok:
        return_error(text)
        return
    return_results(CommandResults(readable_output=text))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
