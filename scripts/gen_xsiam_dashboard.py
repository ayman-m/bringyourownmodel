#!/usr/bin/env python3
"""Generate the "Guardian Performance" Cortex platform dashboard (Dashboards & Reports -> Import).

Every widget is a Custom XQL query over the `issues` dataset: the loop writes its verdict, confidence, cost,
tick count, model and tool activity onto the issue's custom fields, and the platform exposes them as
`xdm.issue.custom_fields`. Nothing here reads a Guardian list, so no Guardian automation has to run to draw it.

    python3 scripts/gen_xsiam_dashboard.py            # writes Packs/GuardianXSIAM/XSIAMDashboards/dashboard-GuardianPerformance.json
    python3 scripts/gen_xsiam_dashboard.py --print    # prints each widget's XQL (for testing through the API)
"""
import json
import sys
import uuid
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "Packs" / "GuardianXSIAM" / "XSIAMDashboards" / "dashboard-GuardianPerformance.json"
DASH_ID = "6f1c2d0a9b7e4c3d8a5e1f0b2c4d6e81"
DAY, WEEK = 86400000, 604800000

#: One row per Guardian run: only issues the loop has written a verdict to.
BASE = (
    "dataset = issues\n"
    "| alter verdict = xdm.issue.custom_fields -> guardianverdict,\n"
    "        confidence = to_integer(xdm.issue.custom_fields -> guardianconfidence),\n"
    "        cost = to_float(xdm.issue.custom_fields -> guardiancostusd),\n"
    "        ticks = to_integer(xdm.issue.custom_fields -> guardiantickcount),\n"
    "        calls = to_integer(xdm.issue.custom_fields -> guardiantoolcalls),\n"
    "        fails = to_integer(xdm.issue.custom_fields -> guardiantoolfailures),\n"
    "        approvals = to_integer(xdm.issue.custom_fields -> guardianapprovalsrequested),\n"
    "        model = xdm.issue.custom_fields -> guardianmodel,\n"
    "        gate = xdm.issue.custom_fields -> guardiangateaction,\n"
    "        tools = xdm.issue.custom_fields -> guardiantoolsused\n"
    "| filter verdict != null and verdict != \"\""
)


def cmds(**kv):
    return [{"command": {"op": "=", "name": k, "value": v}} for k, v in kv.items()]


def graph(kind, header, x=None, y=None, **extra):
    parts = ["type = %s" % kind]
    c = {}
    for k, v in extra.items():
        parts.append("%s = %s" % (k, v)); c[k] = v if not v.startswith("`") else v.strip("`")
    parts.append('header = "%s"' % header); c["header"] = '"%s"' % header
    if x:
        parts.append("xaxis = %s" % x); c["xaxis"] = x
    if y:
        parts.append("yaxis = %s" % y); c["yaxis"] = y
    return "| view graph " + " ".join(parts), {"type": kind, "commands": cmds(**c)}


#: One 0/1 column per verdict, so a chart can stack the verdicts without a second grouping column.
VERDICT_COLUMNS = (
    "| alter is_malicious = if(verdict = \"Malicious\", 1, 0), is_suspicious = if(verdict = \"Suspicious\", 1, 0),\n"
    "        is_benign = if(verdict = \"Benign\", 1, 0), is_inconclusive = if(verdict = \"Inconclusive\", 1, 0)\n"
)

W = []  # (key, title, description, phrase, viewOptions, width, height, timeframe, table)


def widget(title, description, body, kind, header=None, x=None, y=None, width=33.3, height=300, tf=WEEK, **extra):
    key = "xql_%d" % (1791300000000 + len(W))
    if kind == "table":
        phrase, view = BASE + "\n" + body, {"type": "table", "commands": []}
    else:
        tail, view = graph(kind, header or title, x, y, **extra)
        phrase = BASE + "\n" + body + "\n" + tail
    W.append(dict(key=key, title=title, description=description, phrase=phrase, view=view, width=width, height=height, tf=tf))


# --- row 1: headline numbers --------------------------------------------------------------------------------
widget("Guardian runs", "Runs that ended with a recorded verdict.", "| comp count() as runs", "single",
       y="runs", width=20, height=150, subtype="standard")
widget("Average confidence", "Average confidence the model reported.",
       "| comp avg(confidence) as avg_confidence\n| alter avg_confidence = round(avg_confidence)", "single",
       y="avg_confidence", width=20, height=150, subtype="standard")
widget("Total cost (USD)", "Model spend recorded on the runs.",
       "| comp sum(cost) as total_cost\n| alter total_cost = divide(round(multiply(total_cost, 10000)), 10000)", "single",
       y="total_cost", width=20, height=150, subtype="standard")
widget("Average ticks per run", "Reasoning turns a run took to conclude.",
       "| comp avg(ticks) as avg_ticks\n| alter avg_ticks = divide(round(multiply(avg_ticks, 10)), 10)", "single",
       y="avg_ticks", width=20, height=150, subtype="standard")
widget("Tool failure rate (%)", "Tool calls that errored, were denied or were blocked, as a share of all tool calls.",
       "| comp sum(calls) as all_calls, sum(fails) as failed\n| alter failure_rate = if(all_calls > 0, round(divide(multiply(failed, 100), all_calls)), 0)",
       "single", y="failure_rate", width=20, height=150, subtype="standard")

# --- row 2: verdicts ----------------------------------------------------------------------------------------
widget("Verdicts", "How the runs concluded.", "| comp count() as runs by verdict", "pie", x="verdict", y="runs", width=33.3, height=320)
widget("Runs per day by verdict", "Daily run count, split by verdict.",
       VERDICT_COLUMNS + "| bin _time span = 1d\n| comp sum(is_malicious) as malicious, sum(is_suspicious) as suspicious, sum(is_benign) as benign, sum(is_inconclusive) as inconclusive by _time\n| sort asc _time",
       "column", x="_time", y="malicious,suspicious,benign,inconclusive", width=33.4, height=320, subtype="stacked")
widget("Average confidence by verdict", "Confidence the model reported for each verdict.",
       "| comp avg(confidence) as avg_confidence by verdict\n| alter avg_confidence = round(avg_confidence)", "column",
       x="verdict", y="avg_confidence", width=33.3, height=320, subtype="grouped")

# --- row 3: cost and effort ---------------------------------------------------------------------------------
widget("Cost per day (USD)", "Daily spend.",
       "| bin _time span = 1d\n| comp sum(cost) as daily_cost by _time\n| sort asc _time", "line",
       x="_time", y="daily_cost", width=33.3, height=320)
widget("Cost by model (USD)", "Total spend per model.",
       "| alter model = if(model = null or model = \"\", \"unknown\", model)\n| comp sum(cost) as total_cost by model\n| sort desc total_cost",
       "column", x="model", y="total_cost", width=33.4, height=320, subtype="grouped")
widget("Ticks per run", "How many runs took each number of ticks.",
       "| comp count() as runs by ticks\n| sort asc ticks", "column", x="ticks", y="runs", width=33.3, height=320, subtype="grouped")

# --- row 4: actions -----------------------------------------------------------------------------------------
widget("Tools the agent used", "Tool calls by tool name (runs recorded since the activity fields were added).",
       "| filter tools != null and tools != \"\"\n| alter tool = split(tools, \",\")\n| arrayexpand tool\n| comp count() as uses by tool\n| sort desc uses\n| limit 15",
       "column", x="tool", y="uses", width=50, height=340, subtype="grouped", layout="horizontal")
widget("Tool calls and failures per day", "Tool calls, and how many of them failed, per day.",
       "| filter calls != null\n| bin _time span = 1d\n| comp sum(calls) as tool_calls, sum(fails) as failures, sum(approvals) as approvals by _time\n| sort asc _time",
       "line", x="_time", y="tool_calls,failures,approvals", width=50, height=340)

# --- row 5: calibration, techniques -------------------------------------------------------------------------
widget("Calibration gate", "Runs the conclusion check nudged, or whose verdict it downgraded.",
       "| alter gate = if(gate = null or gate = \"\", \"passed\", gate)\n| comp count() as runs by gate", "pie",
       x="gate", y="runs", width=33.3, height=320)
widget("Verdicts by alert type", "The ten alert types with most runs, split by verdict.",
       VERDICT_COLUMNS + "| alter alert = xdm.issue.name\n| comp count() as runs, sum(is_malicious) as malicious, sum(is_suspicious) as suspicious, sum(is_benign) as benign, sum(is_inconclusive) as inconclusive by alert\n| sort desc runs\n| limit 10",
       "column", x="alert", y="malicious,suspicious,benign,inconclusive", width=33.4, height=320, subtype="stacked", layout="horizontal")
widget("Performance by model", "One line per model: runs, confidence, effort, cost and tool failures.",
       "| alter model = if(model = null or model = \"\", \"unknown\", model)\n| comp count() as runs, avg(confidence) as avg_confidence, avg(ticks) as avg_ticks, sum(cost) as total_cost, sum(calls) as tool_calls, sum(fails) as tool_failures by model\n| alter avg_confidence = round(avg_confidence), avg_ticks = divide(round(multiply(avg_ticks, 10)), 10)\n| sort desc runs",
       "table", width=33.3, height=320)

# --- row 6: the runs ----------------------------------------------------------------------------------------
widget("Recent Guardian runs", "Latest runs with what each concluded and what it did.",
       "| alter blast = xdm.issue.custom_fields -> guardianblastradius\n| fields _time, xdm.issue.id as issue_id, xdm.issue.name as alert, verdict, confidence, ticks, cost, calls, fails, approvals, gate, model, blast\n| sort desc _time\n| limit 100",
       "table", width=100, height=520, tf=WEEK)


def build():
    rows, i = [], 0
    layout_rows = [[0, 1, 2, 3, 4], [5, 6, 7], [8, 9, 10], [11, 12], [13, 14, 15], [16]]
    for n, idxs in enumerate(layout_rows):
        items = []
        for k in idxs:
            w = W[k]
            data = {"type": "Custom XQL", "width": w["width"], "height": w["height"], "phrase": w["phrase"],
                    "time_frame": {"relativeTime": w["tf"]}, "viewOptions": w["view"]}
            if w["view"]["type"] == "table":
                data["gridRawStorageInfo"] = {"sort": None, "coldefs": {}, "columnWidth": None,
                                              "rowHeight": '{"rowHeight":"regular","gridRowsHeight":"medium-row"}'}
            items.append({"key": w["key"], "data": data})
        rows.append({"id": "row-%d" % (1000 + n), "data": items})
    widgets = []
    for w in W:
        d = {"phrase": w["phrase"], "time_frame": {"relativeTime": w["tf"]}, "viewOptions": w["view"]}
        if w["view"]["type"] == "table":
            d["gridRawStorageInfo"] = {"sort": None, "coldefs": {}, "columnWidth": None,
                                       "rowHeight": '{"rowHeight":"regular","gridRowsHeight":"medium-row"}'}
        widgets.append({"widget_key": w["key"], "title": w["title"], "creation_time": int(w["key"][4:]),
                        "description": w["description"], "data": d})
    return {
        "dashboards_data": [{
            "id": DASH_ID, "name": "Guardian Performance",
            "description": "What the Guardian agent concluded, how confident it was, what it cost, which model ran and which tools it used.",
            "status": "ENABLED", "layout": rows, "default_dashboard_id": 1, "global_id": DASH_ID,
        }],
        "widgets_data": widgets, "fromVersion": "6.10.0", "supportedModules": ["xsiam"],
    }


if __name__ == "__main__":
    if "--print" in sys.argv:
        for k, w in enumerate(W):
            print("### %d %s\n%s\n" % (k, w["title"], w["phrase"].replace("\n", " ")))
    else:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(build(), indent=2) + "\n")
        print("wrote", OUT, len(W), "widgets")
