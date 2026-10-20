#!/usr/bin/env python3
"""Guardian smoke-test harness core: run war-room commands via /entry/execute/sync
against the admin Playground on the target tenant, returning structured entries.
Type 4 == error entry.

GUARDIAN_PLAYGROUND must name the Playground investigation id for the API-key
user on THIS tenant. It is deliberately required rather than defaulted: a
hard-coded fallback id belongs to whichever tenant it was captured on, and on
any other server it fails every check against a foreign/absent investigation
with a misleading error instead of a clear misconfiguration message.
"""
import json, os, time, urllib3, requests
urllib3.disable_warnings()

BASE = os.environ["DEMISTO_BASE_URL"]
KEY = os.environ.get("DEMISTO_API_KEY") or os.environ["XSOAR6_API_KEY"]
PLAYGROUND = os.environ.get("GUARDIAN_PLAYGROUND")
if not PLAYGROUND:
    raise SystemExit(
        "GUARDIAN_PLAYGROUND is not set. Set it to the Playground investigation id "
        "for the API-key user on this tenant, e.g.:\n"
        '  export GUARDIAN_PLAYGROUND="$(curl -sk -H "Authorization: $DEMISTO_API_KEY" '
        "\"$DEMISTO_BASE_URL/investigations/search\" -d '{\"filter\":{\"type\":[9]}}' "
        '-H \'Content-Type: application/json\' | python3 -c \'import json,sys; '
        "print(json.load(sys.stdin)[\"data\"][0][\"id\"])')\""
    )

S = requests.Session(); S.verify = False
S.headers.update({"Authorization": KEY, "Content-Type": "application/json", "Accept": "application/json"})


def _norm(entry):
    """Normalize an entry dict (endpoint may return Capitalized or lower keys)."""
    def g(*keys, default=None):
        for k in keys:
            if k in entry:
                return entry[k]
        return default
    return {
        "type": g("Type", "type"),
        "contents": g("Contents", "contents"),
        "hr": g("HumanReadable", "humanReadable", "ReadableContents", "readableContents"),
        "brand": g("Brand", "brand"),
        "id": g("ID", "id"),
        "context": g("EntryContext", "entryContext"),
    }


def execute(cmd, investigation_id=None, timeout=180):
    """Run a war-room command string like '!GuardianPing' and return dict:
    {ok, error, entries:[norm...], text, raw_status}."""
    inv = investigation_id or PLAYGROUND
    body = {"investigationId": inv, "data": cmd}
    try:
        r = S.post(BASE + "/entry/execute/sync", json=body, timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": True, "entries": [], "text": f"REQUEST-EXCEPTION: {e}", "raw_status": None}
    status = r.status_code
    try:
        data = r.json()
    except Exception:
        return {"ok": False, "error": True, "entries": [], "text": f"NON-JSON status={status}: {r.text[:300]}", "raw_status": status}
    if isinstance(data, dict):
        # error envelope sometimes {"error": "..."}
        if "error" in data and not data.get("entries"):
            return {"ok": False, "error": True, "entries": [], "text": f"ERR-ENVELOPE: {json.dumps(data)[:400]}", "raw_status": status}
        data = data.get("entries") or [data]
    entries = [_norm(e) for e in data] if isinstance(data, list) else []
    has_err = any(e["type"] == 4 for e in entries)
    texts = []
    for e in entries:
        c = e["hr"] or e["contents"]
        if isinstance(c, (dict, list)):
            c = json.dumps(c)[:2000]
        texts.append(str(c))
    return {"ok": (status == 200 and not has_err), "error": has_err, "entries": entries,
            "text": "\n".join(t for t in texts if t and t != "None"), "raw_status": status}


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "!GuardianPing"
    res = execute(cmd)
    print("STATUS:", res["raw_status"], "| ok:", res["ok"], "| error-entry:", res["error"], "| entries:", len(res["entries"]))
    print("--- text ---")
    print(res["text"][:2500])
