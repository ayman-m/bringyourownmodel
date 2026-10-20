#!/usr/bin/env python3
"""Guardian static/script smoke suite. Runs categories of war-room commands
against the admin Playground and records structured PASS/FAIL/INFO results.

Usage: smoke_suite.py <category|all>
Categories: config health model commands security memory widgets catalog prompt
Results are appended to scripts/results.json (gitignored) (one object per test).
"""
import json, os, re, sys, time
sys.path.insert(0, os.path.dirname(__file__))
from smoke_harness import execute

RESULTS_PATH = os.path.join(os.path.dirname(__file__), "results.json")

def load_results():
    if os.path.exists(RESULTS_PATH):
        try:
            return json.load(open(RESULTS_PATH))
        except Exception:
            return {}
    return {}

def save_results(r):
    json.dump(r, open(RESULTS_PATH, "w"), indent=2)

# ---- test spec ----
# each: (name, cmd, dict(contains=[...any-of...], all=[...], error_ok=False, timeout=180))
CATEGORIES = {
    "config": [
        ("list:kill_switch", "!getList listName=guardian_kill_switch", dict(contains=["loaded", "kill_switch"])),
        ("list:settings",    "!getList listName=guardian_settings",    dict(contains=["loaded"])),
        ("list:policy",      "!getList listName=guardian_policy",      dict(contains=["loaded"])),
        ("list:persona",     "!getList listName=guardian_persona",     dict(contains=["loaded"])),
        ("list:allowlist",   "!getList listName=guardian_tool_allowlist", dict(contains=["loaded", "commands"])),
        ("list:denylist",    "!getList listName=guardian_tool_denylist",  dict(contains=["loaded"])),
        ("list:pricing",     "!getList listName=guardian_pricing",     dict(contains=["loaded"])),
        ("list:model_catalog", "!getList listName=guardian_model_catalog", dict(contains=["loaded"])),
        ("list:preapproved", "!getList listName=guardian_preapproved", dict(contains=["loaded"])),
        ("list:skills_index","!getList listName=guardian_skills_index",dict(contains=["loaded"])),
    ],
    "health": [
        ("GuardianPing", "!GuardianPing", dict(contains=["pong"])),
        ("GuardianDiagnostics", "!GuardianDiagnostics", dict(contains=["integration", "enabled", "guardian", "diagnos"], any=True, timeout=120)),
    ],
    "model": [
        ("guardian-model", "!guardian-model", dict(contains=["model", "vertex", "gemini"], any=True)),
        ("guardian-probe-model", "!guardian-probe-model", dict(contains=["token", "window", "model", "probe", "gemini"], any=True, timeout=240)),
    ],
    "commands": [
        ("guardian-help", "!guardian-help", dict(contains=["guardian-", "command"], any=True)),
        ("guardian-tools", "!guardian-tools", dict(contains=["tool", "allow"], any=True)),
        ("guardian-cost", "!guardian-cost", dict(contains=["cost", "usd", "spend", "ledger"], any=True)),
    ],
    # Security tests assert the bridge's own `status=` verdict, never a keyword: an any-of
    # keyword match once passed a DENIED positive control because "ok" is a substring of
    # "ok=False" and "allow" of "allowlist".
    "security": [
        # POSITIVE: GuardianSkillRead, because every allowlist Guardian can run with includes it
        # (skills cannot load without it) -- getList is absent from narrowed runtime allowlists.
        ("bridge:allow(GuardianSkillRead)", "!GuardianToolBridge tool_name=GuardianSkillRead tool_args=`{\"name\":\"xsoar_case_triage\"}`",
            dict(expect_status=["ok"], timeout=120)),
        # NEGATIVE 1: generic REST read verb (worst-case) NOT on allowlist -> DENIED
        ("bridge:deny(demisto-api-get)", "!GuardianToolBridge tool_name=demisto-api-get tool_args=`{\"uri\":\"/user\"}`",
            dict(expect_status=["denied"], timeout=120)),
        # NEGATIVE 2: off-catalogue nonexistent tool -> DENIED
        ("bridge:deny(fake-tool)", "!GuardianToolBridge tool_name=totally-not-a-real-tool tool_args=`{}`",
            dict(expect_status=["denied"], timeout=90)),
        # NEGATIVE 3: state-changing command -> BLOCKED: denied outright, or parked for a human
        # (a policy-classified command). Either way it never executes; a parked probe is denied
        # straight away so it cannot sit in the approvals queue waiting to be approved by mistake.
        ("bridge:blocked(setList)", "!GuardianToolBridge tool_name=setList tool_args=`{\"listName\":\"__guardian_deny_probe__\",\"listData\":\"x\"}`",
            dict(expect_status=["denied", "pending_approval"], deny_if_parked=True, timeout=90)),
    ],
    "memory": [
        ("memory:store", "!GuardianMemory op=store key=smoke_probe_note value=`smoke-test 2026-07-14 harness note` scope=global tags=smoke",
            dict(contains=["stored", "ok", "memory", "smoke_probe_note"], any=True, timeout=120)),
        ("memory:search", "!GuardianMemory op=search query=smoke limit=5",
            dict(contains=["smoke", "memory", "result"], any=True, timeout=120)),
        ("kb:search", "!GuardianKBSearch query=`phishing investigation` limit=3",
            dict(contains=["phishing", "technique", "kb", "T1", "investigat"], any=True, timeout=120)),
    ],
    "widgets": [
        ("widget:Cost", "!GuardianWidgetCost", dict(contains=["data", "group", "gemini", "usd", "line"], any=True, timeout=90)),
        ("widget:ToolLedger", "!GuardianWidgetToolLedger", dict(contains=["data", "group", "ok", "denied", "error"], any=True, timeout=90)),
        ("widget:LoopHealth", "!GuardianWidgetLoopHealth", dict(contains=["metric", "value", "data", "health", "tick"], any=True, timeout=90)),
        ("widget:EventFeed", "!GuardianWidgetEventFeed", dict(contains=["data", "time", "action", "status", "feed"], any=True, timeout=90)),
        ("widget:ApprovalsQueue", "!GuardianWidgetApprovalsQueue", dict(contains=["data", "approval", "queue", "pending"], any=True, timeout=90)),
    ],
    "catalog": [
        ("GuardianToolCatalogBuilder", "!GuardianToolCatalogBuilder", dict(contains=["tool", "catalog", "command", "function"], any=True, timeout=300)),
    ],
    "prompt": [
        ("GuardianPromptBuilder", "!GuardianPromptBuilder", dict(contains=["you are", "guardian", "policy", "tool", "soc"], any=True, timeout=120)),
    ],
}


def assert_test(res, spec):
    if spec.get("expect_status"):
        m = re.search(r"\bstatus=(\w+)", res.get("text") or "")
        got = m.group(1) if m else None
        if got in spec["expect_status"]:
            return "PASS", f"status={got}"
        return "FAIL", f"status={got or 'missing'}, expected one of {spec['expect_status']}"
    text = (res.get("text") or "").lower()
    contains = [c.lower() for c in spec.get("contains", [])]
    any_mode = spec.get("any", False)
    error_ok = spec.get("error_ok", False)
    # error handling
    if res.get("error") and not error_ok:
        return "FAIL", "type-4 error entry"
    if res.get("raw_status") != 200 and not error_ok:
        return "FAIL", f"http {res.get('raw_status')}"
    if not contains:
        return ("PASS", "ok") if res.get("ok") else ("FAIL", "not ok")
    hits = [c for c in contains if c in text]
    if any_mode:
        if hits:
            return "PASS", f"matched {hits[:3]}"
        return "FAIL", f"none of {contains} in output"
    else:
        missing = [c for c in contains if c not in text]
        if not missing:
            return "PASS", "all markers present"
        return "FAIL", f"missing {missing}"


def run_category(cat):
    tests = CATEGORIES[cat]
    results = load_results()
    catres = []
    print(f"\n{'='*72}\nCATEGORY: {cat}  ({len(tests)} tests)\n{'='*72}")
    for name, cmd, spec in tests:
        t0 = time.time()
        res = execute(cmd, timeout=spec.get("timeout", 180))
        verdict, why = assert_test(res, spec)
        dt = time.time() - t0
        snippet = (res.get("text") or "")[:400].replace("\n", " ⏎ ")
        print(f"[{verdict}] {name}  ({dt:.1f}s, status={res.get('raw_status')}, err={res.get('error')}) -- {why}")
        print(f"        > {snippet[:360]}")
        parked = re.search(r"approval_id=([0-9a-f]+)", res.get("text") or "")
        if spec.get("deny_if_parked") and parked:
            c = execute(f'!guardian-deny approval_id={parked.group(1)} reason="smoke-test probe cleanup - never meant to execute"', timeout=120)
            print(f"        cleanup: parked approval {parked.group(1)} -> {' '.join((c.get('text') or '').split())[:80]}")
        catres.append({"name": name, "cmd": cmd, "verdict": verdict, "why": why,
                        "status": res.get("raw_status"), "error_entry": res.get("error"),
                        "seconds": round(dt, 1), "output": (res.get("text") or "")[:1500]})
    results[cat] = catres
    save_results(results)
    npass = sum(1 for r in catres if r["verdict"] == "PASS")
    print(f"\n  {cat}: {npass}/{len(catres)} PASS")
    return catres


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    cats = list(CATEGORIES) if which == "all" else [which]
    grand = 0; grandn = 0
    for c in cats:
        cr = run_category(c)
        grand += sum(1 for r in cr if r["verdict"] == "PASS"); grandn += len(cr)
    print(f"\n########## TOTAL: {grand}/{grandn} PASS ##########")
