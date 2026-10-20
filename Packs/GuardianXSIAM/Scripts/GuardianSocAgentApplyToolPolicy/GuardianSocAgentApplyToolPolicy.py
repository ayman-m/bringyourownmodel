"""Apply an approved SOC Agent tool policy after strict validation.

The policy is edited in the SOC Agent indicator's `socagenttoolpolicy` field
as JSON (`{"commands": ["ip", "domain"]}`). This action validates it against
the latest discovered command snapshot before replacing the runtime allowlist.
It is operator-only and deliberately absent from Guardian's LLM tool catalog.
"""

import json

import demistomock as demisto
from CommonServerPython import *  # noqa: F401


SOC_AGENT_VALUE = "guardian:primary"
SOC_AGENT_TYPE = "SOC Agent"
POLICY_FIELD = "socagenttoolpolicy"
RUNTIME_ALLOWLIST = "guardian_tool_allowlist_runtime"
AVAILABLE_TOOLS = "guardian_tool_available"


def _errors(entries):
    return "; ".join(str(row.get("Contents") or "error") for row in entries or [] if isinstance(row, dict) and row.get("Type") == 4)


def _last_contents(entries):
    values = [row.get("Contents") for row in entries or [] if isinstance(row, dict) and row.get("Contents") is not None]
    return values[-1] if values else None


def _execute(command, args):
    try:
        entries = demisto.executeCommand(command, args)
    except Exception as exc:
        return False, "{} raised: {}".format(command, exc), []
    error = _errors(entries)
    return (not error), error, entries


def _get_json_list(name):
    ok, error, entries = _execute("getList", {"listName": name})
    if not ok:
        return False, error
    contents = _last_contents(entries)
    try:
        data = json.loads(contents) if isinstance(contents, str) else contents
    except ValueError as exc:
        return False, "{} is not valid JSON: {}".format(name, exc)
    return (True, data) if isinstance(data, dict) else (False, "{} must contain a JSON object".format(name))


def _indicator_rows(contents):
    if isinstance(contents, str):
        try:
            contents = json.loads(contents)
        except ValueError:
            return []
    if isinstance(contents, list):
        return [row for row in contents if isinstance(row, dict)]
    if isinstance(contents, dict):
        for key in ("data", "iocObjects", "indicators"):
            if isinstance(contents.get(key), list):
                return [row for row in contents[key] if isinstance(row, dict)]
        return [contents]
    return []


def _load_approved_policy():
    ok, error, entries = _execute("findIndicators", {"query": 'value:"{}" and type:"{}"'.format(SOC_AGENT_VALUE, SOC_AGENT_TYPE), "size": 1})
    if not ok:
        return False, "could not read SOC Agent indicator: {}".format(error)
    rows = _indicator_rows(_last_contents(entries))
    if not rows:
        return False, "SOC Agent indicator {} was not found".format(SOC_AGENT_VALUE)
    fields = rows[0].get("CustomFields") or rows[0].get("customFields") or {}
    if not isinstance(fields, dict):
        return False, "SOC Agent indicator has no readable custom fields"
    policy = fields.get(POLICY_FIELD)
    if not isinstance(policy, str) or not policy.strip():
        return False, "Guardian Approved Tool Policy is empty; save JSON in the indicator field first"
    try:
        payload = json.loads(policy)
    except ValueError as exc:
        return False, "Guardian Approved Tool Policy is not valid JSON: {}".format(exc)
    if not isinstance(payload, dict) or not isinstance(payload.get("commands"), list):
        return False, "Guardian Approved Tool Policy must be an object with a commands array"
    commands, seen = [], set()
    for value in payload["commands"]:
        if not isinstance(value, str) or not value.strip():
            return False, "Guardian Approved Tool Policy contains a blank or non-text command"
        name = value.strip()
        if name in seen:
            return False, "Guardian Approved Tool Policy contains duplicate command '{}'".format(name)
        seen.add(name)
        commands.append(name)
    if not commands:
        return False, "Guardian Approved Tool Policy commands array must not be empty"
    return True, commands


def guardian_soc_agent_apply_tool_policy(reason):
    reason = reason.strip() if isinstance(reason, str) else ""
    if not reason:
        return False, {"error": "reason is required before applying a shared tool policy"}
    ok, approved = _load_approved_policy()
    if not ok:
        return False, {"error": approved}
    ok, snapshot = _get_json_list(AVAILABLE_TOOLS)
    if not ok:
        return False, {"error": "refresh available tools before applying policy: {}".format(snapshot)}
    rows = snapshot.get("commands")
    if not isinstance(rows, list):
        return False, {"error": "availability snapshot must contain a commands array"}
    available = {row.get("name").strip() for row in rows if isinstance(row, dict) and isinstance(row.get("name"), str) and row["name"].strip()}
    unavailable = [name for name in approved if name not in available]
    if unavailable:
        return False, {"error": "policy contains commands absent from the latest snapshot", "unavailable": unavailable}
    runtime_ok, runtime = _get_json_list(RUNTIME_ALLOWLIST)
    if not runtime_ok:
        return False, {"error": "runtime allowlist is unavailable; refresh available tools first: {}".format(runtime)}
    write_ok, write_error, _entries = _execute("setList", {"listName": RUNTIME_ALLOWLIST, "listData": json.dumps({"commands": approved})})
    if not write_ok:
        return False, {"error": "failed to update runtime allowlist: {}".format(write_error)}
    audit_ok, audit_error, _audit_entries = _execute("GuardianAuditWrite", {
        "action": "guardian-soc-agent-apply-tool-policy", "target": RUNTIME_ALLOWLIST, "status": "ok",
        "actor": "operator", "detail": {"reason": reason, "command_count": len(approved), "snapshot_refreshed_at": snapshot.get("refreshed_at")},
    })
    return True, {"applied": approved, "command_count": len(approved), "reason": reason, "audited": audit_ok, "audit_error": audit_error or None}


def main():
    # Indicator-layout action button: Cortex platform wraps the result with the
    # button's own label ('"Apply Policy" completed successfully. <this
    # text>' / '"Apply Policy" failed. <this text>'), so no manual
    # "<name> failed." prefix is added here. readable_output must be short
    # but non-empty on success: if it is empty or omitted, CommandResults
    # renders a markdown table from `outputs` instead.
    try:
        ok, result = guardian_soc_agent_apply_tool_policy(demisto.args().get("reason"))
    except Exception as exc:
        return_error(str(exc))
        return
    if not ok:
        return_error(result["error"])
        return
    readable = "Applied {} command(s).".format(result["command_count"])
    if not result["audited"]:
        # The policy write itself succeeded (the primary effect the button
        # promises), so the result stays a success. The audit failure is still
        # surfaced, since an incomplete audit trail needs operator attention.
        readable += " Warning: audit log write failed: {}".format(result["audit_error"])
    return_results(CommandResults(readable_output=readable, outputs_prefix="Guardian.SocAgent.ToolPolicyApply", outputs=result, raw_response=result))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
