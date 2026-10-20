"""Button-only readiness trigger for the Guardian SOC Agent layout.

This script exists as a separate automation because indicator-layout action
buttons do not send the layout item's configured `args` when they run a
script, so a per-invocation mode flag on GuardianSocAgentReadiness could not
tell a button click from a panel query. A distinct script id is the
mechanism that does.

It re-runs GuardianSocAgentReadiness via executeCommand (XSOAR 6 scripts
cannot import one another's Python) so a manual click causes a fresh
evaluation, and returns a short, non-empty confirmation. It does not return
the status word itself, which would mean parsing the other script's rendered
markdown or its EntryContext shape; the layout's persistent "Agent Readiness"
panel, one section below this button, already shows the live status.
"""

import demistomock as demisto
from CommonServerPython import *  # noqa: F401


def _errors(entries):
    return "; ".join(str(row.get("Contents") or "error") for row in entries or [] if isinstance(row, dict) and row.get("Type") == 4)


def main():
    try:
        entries = demisto.executeCommand("GuardianSocAgentReadiness", {})
    except Exception as exc:
        return_error(str(exc))
        return
    error = _errors(entries)
    if error:
        return_error(error)
        return
    # Indicator-layout action button: XSOAR wraps this with the button's own
    # label ('"Agent Readiness" completed successfully. <this text>'), so no
    # manual prefix is added here. readable_output must stay short but
    # non-empty: if it is empty or omitted, CommandResults renders a markdown
    # table from `outputs` instead, which is the long report this button
    # avoids.
    return_results(CommandResults(readable_output="See the Agent Readiness panel below for the current status."))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
