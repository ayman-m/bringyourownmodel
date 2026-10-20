"""Create a deliberate Guardian follow-up investigation from the SOC Agent UI."""

import demistomock as demisto
from CommonServerPython import *  # noqa: F401


#: Must match an incident type shipped in this pack (see IncidentTypes/). The type's
#: own playbook binding (GuardianAgentLoop) is what starts Guardian investigating the
#: incident this script creates; a type without that binding would create an incident
#: that is never investigated.
DEFAULT_TYPE = "Guardian Agent Run"


def _errors(entries):
    return "; ".join(str(entry.get("Contents") or "error") for entry in entries or [] if isinstance(entry, dict) and entry.get("Type") == 4)


def _last_contents(entries):
    rows = [entry.get("Contents") for entry in entries or [] if isinstance(entry, dict) and entry.get("Contents") is not None]
    return rows[-1] if rows else None


def _incident_id(contents):
    if isinstance(contents, dict):
        return contents.get("id") or contents.get("ID") or contents.get("incidentId")
    if isinstance(contents, list):
        for row in contents:
            result = _incident_id(row)
            if result:
                return result
    return None


def guardian_soc_agent_create_investigation(name, details, severity=None):
    name = name.strip() if isinstance(name, str) else ""
    details = details.strip() if isinstance(details, str) else ""
    if not name or not details:
        return False, {"error": "name and details are required to create an investigation"}
    try:
        severity_value = int(severity) if severity not in (None, "") else 1
    except (TypeError, ValueError):
        return False, {"error": "severity must be an integer from 0 through 4"}
    if severity_value not in range(5):
        return False, {"error": "severity must be an integer from 0 through 4"}
    args = {"name": name, "details": details, "type": DEFAULT_TYPE, "severity": severity_value}
    try:
        entries = demisto.executeCommand("createNewIncident", args)
    except Exception as exc:
        return False, {"error": "createNewIncident raised: {}".format(exc)}
    error = _errors(entries)
    if error:
        return False, {"error": "createNewIncident failed: {}".format(error)}
    incident_id = _incident_id(_last_contents(entries))
    audit_payload = {"action": "guardian-soc-agent-create-investigation", "target": str(incident_id or "new-guardian-investigation"), "status": "ok", "actor": "operator", "detail": {"incident_type": DEFAULT_TYPE, "severity": severity_value}}
    try:
        audit_entries = demisto.executeCommand("GuardianAuditWrite", audit_payload)
        audit_error = _errors(audit_entries)
    except Exception as exc:
        audit_error = str(exc)
    return True, {"incident_id": incident_id, "incident_type": DEFAULT_TYPE, "severity": severity_value, "audited": not bool(audit_error), "audit_error": audit_error or None}


def main():
    args = demisto.args()
    try:
        ok, result = guardian_soc_agent_create_investigation(args.get("name"), args.get("details"), args.get("severity"))
        if not ok:
            return_error(result["error"])
            return
        lines = ["Created Guardian follow-up investigation.", "- Type: `{}`".format(result["incident_type"]), "- Severity: `{}`".format(result["severity"])]
        if result["incident_id"]:
            lines.append("- ID: `{}`".format(result["incident_id"]))
        if not result["audited"]:
            lines.append("- WARNING: creation succeeded but audit write failed: {}".format(result["audit_error"]))
        return_results(CommandResults(readable_output="\n".join(lines), outputs_prefix="Guardian.SocAgent.FollowUp", outputs=result, raw_response=result))
    except Exception as exc:
        return_error("GuardianSocAgentCreateInvestigation failed unexpectedly: {}".format(exc))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
