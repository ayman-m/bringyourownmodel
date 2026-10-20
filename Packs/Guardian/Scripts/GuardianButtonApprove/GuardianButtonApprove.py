"""Guardian Agent Run layout button: approve a pending action.

Asks for one mandatory argument, the approval id shown in the Recommended Actions table, and
calls the operator-only `guardian-approve` command. The agent then runs the action once on its
next reasoning tick. A credential-tier request needs the separate "Approve (credential tier)"
button (GuardianButtonApproveCredential), which also asks for the word CONFIRM.

Operator-only: not on the agent's allowlist or policy, and listed in the code-level
GUARDIAN_OPERATOR_ONLY_COMMANDS sets of GuardianToolBridge and GuardianToolCatalogBuilder, so
the model can neither see nor call it.
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


def guardian_button_approve(approval_id):
    """Approve a pending request on this incident. Returns ``(ok, text)``."""
    approval_id = _guardian_button_text(approval_id, GUARDIAN_BUTTON_MAX_ID_CHARS)
    if not approval_id:
        return False, "approval_id is required: copy it from the Approval ID column of the Recommended Actions table."
    scope_error = guardian_button_scope_error(approval_id)
    if scope_error:
        return False, scope_error
    ok, result = _guardian_button_run("guardian-approve", {"approval_id": approval_id, "actor": GUARDIAN_BUTTON_ACTOR})
    if not ok:
        if "credential-tier" in result:
            return False, (
                "Approval {} is a credential-tier request. Use the Approve (credential tier) button, "
                "which also asks you to type CONFIRM.".format(approval_id)
            )
        return False, result
    return True, "Approval {} approved. The agent runs it once on its next reasoning tick.".format(approval_id)


def main():
    args = demisto.args()
    try:
        ok, text = guardian_button_approve(args.get("approval_id"))
    except Exception as exc:
        return_error("GuardianButtonApprove failed unexpectedly: {}".format(exc))
        return
    if not ok:
        return_error(text)
        return
    return_results(CommandResults(readable_output=text))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
