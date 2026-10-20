"""Validate the effective Guardian SOC Agent tool policy without changing it.

This is an indicator-layout action button, not an LLM tool. It compares the
runtime allowlist (or the pack baseline before first refresh) to the saved
availability snapshot. It never refreshes discovery and never writes a List.
"""

import json

import demistomock as demisto
from CommonServerPython import *  # noqa: F401


RUNTIME_ALLOWLIST = "guardian_tool_allowlist_runtime"
BASELINE_ALLOWLIST = "guardian_tool_allowlist"
AVAILABLE_TOOLS = "guardian_tool_available"


def _error_text(entries):
    return "; ".join(str(entry.get("Contents") or entry.get("HumanReadable") or "error") for entry in entries or [] if isinstance(entry, dict) and entry.get("Type") == 4)


def _last_contents(entries):
    values = [entry.get("Contents") for entry in entries or [] if isinstance(entry, dict) and entry.get("Contents") is not None]
    return values[-1] if values else None


def _get_json_list(name):
    try:
        entries = demisto.executeCommand("getList", {"listName": name})
    except Exception as exc:
        return False, "getList {} raised: {}".format(name, exc)
    errors = _error_text(entries)
    if errors:
        return False, errors
    contents = _last_contents(entries)
    try:
        data = json.loads(contents) if isinstance(contents, str) else contents
    except ValueError as exc:
        return False, "{} is not valid JSON: {}".format(name, exc)
    if not isinstance(data, dict):
        return False, "{} must contain a JSON object".format(name)
    return True, data


def _is_not_found(error):
    return "item not found" in str(error).lower()


def _command_names(payload, list_name):
    values = payload.get("commands") if isinstance(payload, dict) else None
    if not isinstance(values, list):
        return [], [], ["{} must contain a commands array".format(list_name)]
    names, duplicates, invalid = [], [], []
    seen = set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            invalid.append(repr(value))
            continue
        name = value.strip()
        if name in seen:
            duplicates.append(name)
            continue
        seen.add(name)
        names.append(name)
    return names, duplicates, invalid


def guardian_soc_agent_validate_policy():
    """Return a structured, read-only policy-validation report."""
    ok, allowlist = _get_json_list(RUNTIME_ALLOWLIST)
    source = RUNTIME_ALLOWLIST
    if not ok and _is_not_found(allowlist):
        ok, allowlist = _get_json_list(BASELINE_ALLOWLIST)
        source = BASELINE_ALLOWLIST
    if not ok:
        return {"valid": False, "source": source, "error": "could not load allowlist: {}".format(allowlist)}

    selected, duplicates, invalid = _command_names(allowlist, source)
    snapshot_ok, snapshot = _get_json_list(AVAILABLE_TOOLS)
    if not snapshot_ok:
        return {
            "valid": False, "source": source, "allowed": selected, "duplicates": duplicates, "invalid": invalid,
            "error": "could not load availability snapshot: {}".format(snapshot),
        }
    rows = snapshot.get("commands")
    if not isinstance(rows, list):
        return {"valid": False, "source": source, "allowed": selected, "error": "availability snapshot must contain a commands array"}
    available = {row.get("name").strip() for row in rows if isinstance(row, dict) and isinstance(row.get("name"), str) and row["name"].strip()}
    unavailable = [name for name in selected if name not in available]
    return {
        "valid": not duplicates and not invalid and not unavailable,
        "source": source,
        "allowed": selected,
        "available_count": len(available),
        "unavailable": unavailable,
        "duplicates": duplicates,
        "invalid": invalid,
        "refreshed_at": snapshot.get("refreshed_at"),
    }


def _short_invalid_reason(report):
    """One plain-text line naming what's wrong -- report[...] is guaranteed
    to carry unavailable/duplicates/invalid once report.get('error') is None
    (every early-exit shape in guardian_soc_agent_validate_policy that lacks
    those keys also carries 'error', and is caught before this is called)."""
    parts = []
    if report["unavailable"]:
        parts.append("{} unavailable ({})".format(len(report["unavailable"]), ", ".join(report["unavailable"])))
    if report["duplicates"]:
        parts.append("{} duplicate ({})".format(len(report["duplicates"]), ", ".join(report["duplicates"])))
    if report["invalid"]:
        parts.append("{} invalid entr{}".format(len(report["invalid"]), "y" if len(report["invalid"]) == 1 else "ies"))
    return "; ".join(parts) or "policy needs review"


def main():
    # This is an indicator-layout action button. Cortex platform itself wraps the
    # result with the button's OWN label from the layout -- '"Validate
    # Tools" completed successfully. <this readable_output>' on success,
    # '"Validate Tools" failed. <this text>' on return_error. So there is no
    # manual "<name> failed." prefix here (it would repeat the label), and
    # readable_output must be short but NON-EMPTY on success: if it is empty
    # or omitted, CommandResults renders a markdown table from `outputs`
    # instead, which is the long report this button exists to avoid.
    try:
        report = guardian_soc_agent_validate_policy()
    except Exception as exc:
        return_error(str(exc))
        return
    if report.get("error"):
        return_error(report["error"])
        return
    if not report["valid"]:
        # Not a script error -- the check ran fine and found a real problem.
        # Reported as a failure anyway: this IS the actionable thing the
        # button exists to surface, and burying it under a bare success
        # would defeat the button's purpose.
        return_error("Policy needs review: {}.".format(_short_invalid_reason(report)))
        return
    readable = "Policy is valid -- {} command(s) from `{}`.".format(len(report["allowed"]), report["source"])
    return_results(CommandResults(readable_output=readable, outputs_prefix="Guardian.SocAgent.ToolPolicy", outputs=report, raw_response=report))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
