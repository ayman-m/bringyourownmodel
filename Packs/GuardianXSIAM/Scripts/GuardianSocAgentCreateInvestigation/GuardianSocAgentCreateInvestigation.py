"""Create a deliberate Guardian follow-up investigation from the SOC Agent UI.

Cortex XSIAM has no issue-creation command: ``createNewIncident`` and ``POST /incident`` succeed and create nothing.
An issue is created by inserting an alert, so this script posts one to ``/public_api/v1/alerts/insert_parsed_alerts``
through the Core REST API integration (``core-api-post``), which uses the tenant's own identity and needs no stored
API key. The insert replies only ``{"reply": true}``, so the new issue's id is looked up by name afterwards.
"""

import json
import time

import demistomock as demisto
from CommonServerPython import *  # noqa: F401


INSERT_URI = "/public_api/v1/alerts/insert_parsed_alerts"
SEARCH_URI = "/incidents/search"
#: Alerts carry a vendor/product pair; the pair also lets an analyst filter these issues out of the queue.
ALERT_VENDOR = "Guardian"
ALERT_PRODUCT = "Guardian SOC Agent"
#: The alert API insists on a source and destination address and port (ports must be 1-65535); a follow-up has no
#: network event, so these are placeholders from the RFC 5737 documentation range.
PLACEHOLDER_LOCAL_IP = "203.0.113.10"
PLACEHOLDER_REMOTE_IP = "203.0.113.50"
PLACEHOLDER_LOCAL_PORT = 49152
PLACEHOLDER_REMOTE_PORT = 443
ERROR_LIMIT = 300
#: Ingestion took about 20 seconds when measured, so six looks at ten second gaps is a generous bound.
LOOKUP_ATTEMPTS = 6
LOOKUP_GAP_SECONDS = 10
#: Guardian severity 0-4 -> the alert API's four levels.
SEVERITY_NAMES = {0: "Low", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def _errors(entries):
    return "; ".join(str(entry.get("Contents") or "error") for entry in entries or [] if isinstance(entry, dict) and entry.get("Type") == 4)


def _last_contents(entries):
    rows = [entry.get("Contents") for entry in entries or [] if isinstance(entry, dict) and entry.get("Contents") is not None]
    return rows[-1] if rows else None


def _api_post(uri, body):
    """POST through the Core REST API integration; returns (parsed response or None, error text)."""
    try:
        entries = demisto.executeCommand("core-api-post", {"uri": uri, "body": json.dumps(body)})
    except Exception as exc:
        return None, "core-api-post raised: {}".format(exc)
    error = _errors(entries)
    if error:
        return None, error
    contents = _last_contents(entries)
    response = contents.get("response") if isinstance(contents, dict) else None
    if response is None:
        return None, "core-api-post returned no response body"
    return response, ""


def _find_issue_id(name, not_before_ms):
    """Poll the issue search for the issue the insert produced; returns its id or None."""
    query = 'name:"{}"'.format(name.replace('"', ""))
    for attempt in range(LOOKUP_ATTEMPTS):
        if attempt:
            time.sleep(LOOKUP_GAP_SECONDS)
        response, error = _api_post(SEARCH_URI, {"filter": {"query": query, "size": 5, "sort": [{"field": "id", "asc": False}]}})
        if error or not isinstance(response, dict):
            continue
        for row in response.get("data") or []:
            if isinstance(row, dict) and row.get("id") and _created_ms(row) >= not_before_ms:
                return str(row["id"])
    return None


def _created_ms(row):
    created = row.get("created") or ""
    try:
        return int(arg_to_datetime(created).timestamp() * 1000)
    except Exception:
        return 0


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
    started_ms = int(time.time() * 1000)
    alert = {
        "vendor": ALERT_VENDOR,
        "product": ALERT_PRODUCT,
        "local_ip": PLACEHOLDER_LOCAL_IP,
        "local_port": PLACEHOLDER_LOCAL_PORT,
        "remote_ip": PLACEHOLDER_REMOTE_IP,
        "remote_port": PLACEHOLDER_REMOTE_PORT,
        "event_timestamp": started_ms,
        "severity": SEVERITY_NAMES[severity_value],
        "alert_name": name,
        "alert_description": details,
    }
    response, error = _api_post(INSERT_URI, {"request_data": {"alerts": [alert]}})
    if error:
        return False, {"error": "alert insert failed: {}".format(error[:ERROR_LIMIT])}
    if not (isinstance(response, dict) and response.get("reply") is True):
        return False, {"error": "alert insert was not accepted: {}".format(str(response)[:200])}
    incident_id = _find_issue_id(name, started_ms - 5000)
    audit_payload = {"action": "guardian-soc-agent-create-investigation", "target": str(incident_id or "pending-issue"), "status": "ok", "actor": "operator", "detail": {"alert_name": name, "severity": severity_value, "issue_found": bool(incident_id)}}
    try:
        audit_entries = demisto.executeCommand("GuardianAuditWrite", audit_payload)
        audit_error = _errors(audit_entries)
    except Exception as exc:
        audit_error = str(exc)
    return True, {"incident_id": incident_id, "severity": severity_value, "audited": not bool(audit_error), "audit_error": audit_error or None}


def main():
    args = demisto.args()
    try:
        ok, result = guardian_soc_agent_create_investigation(args.get("name"), args.get("details"), args.get("severity"))
        if not ok:
            return_error(result["error"])
            return
        lines = ["Created Guardian follow-up issue.", "- Severity: `{}`".format(result["severity"])]
        if result["incident_id"]:
            lines.append("- ID: `{}`".format(result["incident_id"]))
        else:
            lines.append("- ID: not visible yet; the issue is created and appears in the queue shortly")
        if not result["audited"]:
            lines.append("- WARNING: creation succeeded but audit write failed: {}".format(result["audit_error"]))
        return_results(CommandResults(readable_output="\n".join(lines), outputs_prefix="Guardian.SocAgent.FollowUp", outputs=result, raw_response=result))
    except Exception as exc:
        return_error("GuardianSocAgentCreateInvestigation failed unexpectedly: {}".format(exc))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
