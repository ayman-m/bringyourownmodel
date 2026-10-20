"""Guardian Agent Run layout button: deny a pending action.

Asks for the approval id and a reason (both mandatory), and calls the operator-only
`guardian-deny` command. Nothing runs; the next reasoning tick tells the model the action was
denied and why.

Operator-only: not on the agent's allowlist or policy, and listed in the code-level
GUARDIAN_OPERATOR_ONLY_COMMANDS sets of GuardianToolBridge and GuardianToolCatalogBuilder.
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


def _guardian_button_current_incident_id():
    try:
        incident = demisto.incident() or {}
    except Exception:
        return ""
    value = incident.get("id") if isinstance(incident, dict) else None
    return str(value) if value not in (None, "") else ""


def _guardian_button_ledger_row(approval_id):
    """The ledger row for ``approval_id``, or ``None`` when the ledger cannot be read or has no such
    row (the approve/deny command then reports its own error)."""
    try:
        entries = demisto.executeCommand("getList", {"listName": GUARDIAN_APPROVALS_LEDGER_LIST_NAME})
    except Exception:
        return None
    if _guardian_button_errors(entries):
        return None
    contents = None
    for entry in entries or []:
        if isinstance(entry, dict) and entry.get("Contents") is not None:
            contents = entry["Contents"]
    if isinstance(contents, str):
        try:
            contents = json.loads(contents)
        except ValueError:
            return None
    if not isinstance(contents, list):
        return None
    for row in contents:
        if isinstance(row, dict) and row.get("approval_id") == approval_id:
            return row
    return None


def guardian_button_scope_error(approval_id):
    """An error text when the request belongs to a different incident than the one this button was
    clicked on (so a mistyped id cannot resolve another incident's request); ``None`` when it matches,
    when the incident or the request cannot be determined, or when the request has no incident."""
    current = _guardian_button_current_incident_id()
    row = _guardian_button_ledger_row(approval_id)
    if not current or row is None:
        return None
    owners = {str(row.get(key)) for key in ("incident_id", "run_id") if row.get(key) not in (None, "")}
    if owners and current not in owners:
        return "Approval {} belongs to incident {}, not this one. Open that incident to resolve it.".format(
            approval_id, ", ".join(sorted(owners))
        )
    return None


def guardian_button_deny(approval_id, reason):
    """Deny a pending request on this incident. Returns ``(ok, text)``."""
    approval_id = _guardian_button_text(approval_id, GUARDIAN_BUTTON_MAX_ID_CHARS)
    reason = _guardian_button_text(reason, GUARDIAN_BUTTON_MAX_TEXT_CHARS)
    if not approval_id:
        return False, "approval_id is required: copy it from the Approval ID column of the Recommended Actions table."
    if not reason:
        return False, "A reason is required: it is passed back to the agent so it can change course."
    scope_error = guardian_button_scope_error(approval_id)
    if scope_error:
        return False, scope_error
    ok, result = _guardian_button_run(
        "guardian-deny", {"approval_id": approval_id, "reason": reason, "actor": GUARDIAN_BUTTON_ACTOR}
    )
    if not ok:
        return False, result
    return True, "Approval {} denied. Nothing runs; the agent is told why on its next reasoning tick.".format(approval_id)


def main():
    args = demisto.args()
    try:
        ok, text = guardian_button_deny(args.get("approval_id"), args.get("reason"))
    except Exception as exc:
        return_error("GuardianButtonDeny failed unexpectedly: {}".format(exc))
        return
    if not ok:
        return_error(text)
        return
    return_results(CommandResults(readable_output=text))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
