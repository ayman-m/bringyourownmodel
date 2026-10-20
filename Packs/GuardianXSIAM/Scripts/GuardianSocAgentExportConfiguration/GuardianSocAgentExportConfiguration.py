"""Produce a redacted Guardian SOC Agent configuration snapshot.

The action only reads the control-plane Lists. It intentionally exports hashes,
counts, timestamps, and state—not persona text, credentials, memory values, or
raw list payloads. The result is suitable for a War Room review record.
"""

import hashlib
import json

import demistomock as demisto
from CommonServerPython import *  # noqa: F401


LISTS = {
    "runtime_allowlist": "guardian_tool_allowlist_runtime",
    "baseline_allowlist": "guardian_tool_allowlist",
    "available_tools": "guardian_tool_available",
    "persona": "guardian_persona",
    "kill_switch": "guardian_kill_switch",
}


def _error(entries):
    return "; ".join(str(entry.get("Contents") or "error") for entry in entries or [] if isinstance(entry, dict) and entry.get("Type") == 4)


def _last_contents(entries):
    data = [entry.get("Contents") for entry in entries or [] if isinstance(entry, dict) and entry.get("Contents") is not None]
    return data[-1] if data else None


def _read_list(name):
    try:
        entries = demisto.executeCommand("getList", {"listName": name})
    except Exception as exc:
        return False, "getList {} raised: {}".format(name, exc)
    error = _error(entries)
    if error:
        return False, error
    contents = _last_contents(entries)
    try:
        value = json.loads(contents) if isinstance(contents, str) else contents
    except ValueError as exc:
        return False, "invalid JSON: {}".format(exc)
    return (True, value) if isinstance(value, dict) else (False, "must contain a JSON object")


def _fingerprint(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def guardian_soc_agent_export_configuration():
    values = {}
    errors = {}
    for key, name in LISTS.items():
        ok, value = _read_list(name)
        if ok:
            values[key] = value
        else:
            errors[key] = str(value)

    allowlist = values.get("runtime_allowlist") or values.get("baseline_allowlist") or {}
    allowed = allowlist.get("commands") if isinstance(allowlist.get("commands"), list) else []
    snapshot = values.get("available_tools") or {}
    rows = snapshot.get("commands") if isinstance(snapshot.get("commands"), list) else []
    persona = values.get("persona") or {}
    persona_value = persona.get("persona") if isinstance(persona.get("persona"), str) else ""
    switch = values.get("kill_switch") or {}
    return {
        "allowlist_source": LISTS["runtime_allowlist"] if "runtime_allowlist" in values else LISTS["baseline_allowlist"],
        "allowed_command_count": len([item for item in allowed if isinstance(item, str) and item.strip()]),
        "allowlist_fingerprint": _fingerprint(allowlist) if allowlist else None,
        "available_command_count": len(rows),
        "availability_refreshed_at": snapshot.get("refreshed_at"),
        "availability_fingerprint": _fingerprint(snapshot) if snapshot else None,
        "persona_configured": bool(persona_value.strip()),
        "persona_fingerprint": _fingerprint({"persona": persona_value}) if persona_value else None,
        "agent_halted": bool(switch.get("enabled")),
        "kill_switch_timestamp": switch.get("ts"),
        "errors": errors,
    }


def guardian_soc_agent_export_render(report):
    lines = ["### Guardian SOC Agent — Redacted Configuration Snapshot", "", "| Setting | Value |", "|---|---|"]
    lines.extend([
        "| Effective allowlist | `{}` |".format(report["allowlist_source"]),
        "| Allowed command count | {} |".format(report["allowed_command_count"]),
        "| Allowlist fingerprint | `{}` |".format(report["allowlist_fingerprint"] or "not available"),
        "| Available command count | {} |".format(report["available_command_count"]),
        "| Availability refreshed | {} |".format(report["availability_refreshed_at"] or "not available"),
        "| Availability fingerprint | `{}` |".format(report["availability_fingerprint"] or "not available"),
        "| Persona configured | {} |".format(report["persona_configured"]),
        "| Persona fingerprint | `{}` |".format(report["persona_fingerprint"] or "not available"),
        "| Agent halted | {} |".format(report["agent_halted"]),
        "| Kill-switch timestamp | {} |".format(report["kill_switch_timestamp"] or "not available"),
    ])
    if report["errors"]:
        lines.extend(["", "#### Unavailable inputs"])
        lines.extend("- `{}`: {}".format(name, error) for name, error in sorted(report["errors"].items()))
    lines.extend(["", "No secrets, raw persona text, or memory values are included in this snapshot."])
    return "\n".join(lines)


def main():
    try:
        report = guardian_soc_agent_export_configuration()
        return_results(CommandResults(readable_output=guardian_soc_agent_export_render(report), outputs_prefix="Guardian.SocAgent.ConfigurationSnapshot", outputs=report, raw_response=report))
    except Exception as exc:
        return_error("GuardianSocAgentExportConfiguration failed unexpectedly: {}".format(exc))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
