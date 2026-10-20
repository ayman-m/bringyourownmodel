"""Guardian Agent Run layout button: reply to the agent.

Asks for a message (mandatory) and queues it through the existing `guardian-chat` command, which
adds it to the agent's transcript as "[Analyst]: ..." on its next tick. It also answers a question
the agent paused on. If the loop has already finished, `guardian-chat` re-opens it and its note
(returned here) says to re-run the GuardianAgentLoop playbook to resume ticking.

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


def guardian_button_reply(message):
    """Queue an analyst message for the agent on this incident. Returns ``(ok, text)``."""
    message = _guardian_button_text(message, GUARDIAN_BUTTON_MAX_TEXT_CHARS)
    if not message:
        return False, "A message is required."
    ok, result = _guardian_button_run("guardian-chat", {"message": message})
    if not ok:
        return False, result
    notes = []
    for entry in result or []:
        if isinstance(entry, dict) and entry.get("Type") != 4:
            text = entry.get("HumanReadable") or (entry.get("Contents") if isinstance(entry.get("Contents"), str) else "")
            if text:
                notes.append(str(text).strip())
    return True, "\n\n".join(notes) or "Message queued for the agent."


def main():
    args = demisto.args()
    try:
        ok, text = guardian_button_reply(args.get("message"))
    except Exception as exc:
        return_error("GuardianButtonReply failed unexpectedly: {}".format(exc))
        return
    if not ok:
        return_error(text)
        return
    return_results(CommandResults(readable_output=text))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
