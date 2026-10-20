"""Indicator-layout wrapper for Guardian's established operator kill switch.

The existing `guardian-killswitch` automation remains the only component that
writes the protected runtime List and audit record. This tagged wrapper merely
maps the unambiguous UI choices `pause` and `resume` to its `on`/`off` API.
"""

import demistomock as demisto
from CommonServerPython import *  # noqa: F401


STATE_MAP = {"pause": "on", "resume": "off"}


def _errors(entries):
    return "; ".join(str(entry.get("Contents") or "error") for entry in entries or [] if isinstance(entry, dict) and entry.get("Type") == 4)


def guardian_soc_agent_set_state(state, reason):
    choice = state.strip().lower() if isinstance(state, str) else ""
    reason = reason.strip() if isinstance(reason, str) else ""
    if choice not in STATE_MAP:
        return False, {"error": "state is required and must be pause or resume"}
    if not reason:
        return False, {"error": "reason is required before changing agent state"}
    try:
        entries = demisto.executeCommand("guardian-killswitch", {"state": STATE_MAP[choice], "reason": reason})
    except Exception as exc:
        return False, {"error": "guardian-killswitch raised: {}".format(exc)}
    error = _errors(entries)
    if error:
        return False, {"error": "guardian-killswitch failed: {}".format(error)}
    return True, {"state": "Paused" if choice == "pause" else "Ready", "reason": reason, "kill_switch_state": STATE_MAP[choice]}


def main():
    # Indicator-layout action button: Cortex platform wraps the result with the
    # clicked button's own label from the layout ('"Pause Agent" failed.
    # <this text>' or '"Resume Agent" failed. <this text>'), even though both
    # buttons share this one script. A manual prefix would repeat the label,
    # so none is added.
    args = demisto.args()
    choice = str(args.get("state") or "").strip().lower()
    try:
        ok, result = guardian_soc_agent_set_state(args.get("state"), args.get("reason"))
    except Exception as exc:
        return_error(str(exc))
        return
    if not ok:
        return_error(result["error"])
        return
    readable = "Agent paused." if choice == "pause" else "Agent resumed."
    return_results(CommandResults(readable_output=readable, outputs_prefix="Guardian.SocAgent.State", outputs=result, raw_response=result))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
