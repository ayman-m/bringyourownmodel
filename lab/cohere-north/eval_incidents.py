#!/usr/bin/env python3
"""Run the Guardian agent (small model) across N existing Splunk-Finding incidents via the playground
reset+multitick harness, capturing each investigation's tool use, verdict, tick count, and errors.
Results -> /tmp/eval_results.json (written incrementally)."""
import json
import os
import re
import ssl
import time
import urllib.request

BASE = os.environ["DEMISTO_BASE_URL"].rstrip("/")
KEY = os.environ["DEMISTO_API_KEY"]
PG = __import__("os").environ.get("GUARDIAN_PLAYGROUND", "")
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
N_INCIDENTS = int(os.environ.get("N_INCIDENTS", "20"))
MAX_TICKS = int(os.environ.get("MAX_TICKS", "4"))
OUT = "/tmp/eval_results.json"


def call(path, body, timeout=180):
    req = urllib.request.Request(f"{BASE}{path}", data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": KEY, "Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


def execute(cmd, timeout=180):
    d = call("/entry/execute/sync", {"investigationId": PG, "data": cmd}, timeout=timeout)
    ents = d if isinstance(d, list) else [d]
    out = []
    for e in ents:
        c = e.get("contents")
        out.append({"type": e.get("type"), "contents": c if isinstance(c, str) else json.dumps(c) if c else ""})
    return out


def pick_incidents(n):
    d = call("/incidents/search", {"filter": {"type": ["Splunk Finding"], "page": 0, "size": 200,
                                              "sort": [{"field": "created", "asc": False}]}})
    seen, picked = set(), []
    for i in d.get("data", []):
        name = i.get("name") or ""
        scenario = name.split(":")[0].strip()  # dedupe by scenario so we get variety
        keyed = (scenario, i.get("severity"))
        if keyed in seen:
            continue
        seen.add(keyed)
        picked.append({"id": i.get("id"), "name": name, "severity": i.get("severity")})
        if len(picked) >= n:
            break
    # top up if not enough variety
    if len(picked) < n:
        for i in d.get("data", []):
            row = {"id": i.get("id"), "name": i.get("name"), "severity": i.get("severity")}
            if row["id"] not in [p["id"] for p in picked]:
                picked.append(row)
            if len(picked) >= n:
                break
    return picked


TOOLS_RE = re.compile(r"model called \d+ tool\(s\): ([^.(]+)")
CONCLUDE_RE = re.compile(r"concluded at tick (\d+)")


def investigate(inc):
    execute("!DeleteContext key=Guardian", timeout=60)
    prompt = (f"Investigate Splunk Finding incident {inc['id']} ({inc['name']}). Use getIncidents "
              f"id={inc['id']} to pull its details and War Room, assess whether it is a true or false "
              f"positive, and give a one-line verdict plus one recommended action. Conclude when confident.")
    cmd = f'!GuardianReasoningTick prompt="{prompt}"'
    trace, tools_used, concluded_tick, verdict, error = [], [], None, None, None
    for t in range(MAX_TICKS):
        try:
            ents = execute(cmd, timeout=185)
        except Exception as e:
            error = f"tick {t}: {type(e).__name__}: {e}"
            break
        text = " ".join(e["contents"] for e in ents)
        trace.append(text[:1200])
        for e in ents:
            if e["type"] == 4:
                error = e["contents"][:300]
        tools_used += [x.strip() for x in TOOLS_RE.findall(text)]
        m = CONCLUDE_RE.search(text)
        if m:
            concluded_tick = int(m.group(1))
            # verdict = text after "concluded at tick N):"
            parts = text.split("):", 1)
            verdict = (parts[1].strip() if len(parts) > 1 else text)[:800]
            break
        if "loop already" in text:
            break
    return {"incident": inc, "concluded_tick": concluded_tick, "tools_used": tools_used,
            "verdict": verdict, "error": error, "trace": trace}


def main():
    incidents = pick_incidents(N_INCIDENTS)
    print(f"selected {len(incidents)} incidents")
    results = []
    for idx, inc in enumerate(incidents, 1):
        t0 = time.monotonic()
        r = investigate(inc)
        r["seconds"] = round(time.monotonic() - t0, 1)
        results.append(r)
        with open(OUT, "w") as f:
            json.dump(results, f, indent=1)
        v = (r["verdict"] or r["error"] or "(no conclusion)")[:70].replace("\n", " ")
        print(f"[{idx}/{len(incidents)}] inc {inc['id']} '{inc['name'][:32]}' "
              f"tick={r['concluded_tick']} tools={r['tools_used']} :: {v}")
    print(f"\nDONE -> {OUT}")


if __name__ == "__main__":
    main()
