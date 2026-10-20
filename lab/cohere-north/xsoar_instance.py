#!/usr/bin/env python3
"""Create/enable the Guardian Cohere lab instance on xsoar6 (-> lab middleware) and disable
Guardian Vertex, so guardian-llm-chat routes to the lab model. Stdlib-only (urllib)."""
import json
import os
import ssl
import sys
import urllib.request

BASE = os.environ["DEMISTO_BASE_URL"].rstrip("/")
KEY = os.environ["DEMISTO_API_KEY"]
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

# desired values; booleans (type 8) must be real bools to match the server's data shape
VALUES = {
    "endpoint_url": os.environ.get("NORTH_MOCK_URL", "http://<gpu-host>:8000"),
    "agent_id": "lab-agent-0001",
    "session_id": "",
    "bearer_token": "lab-secret-token",
    "conversation_mode": "stateless",   # per-incident isolation for the multi-incident run
    "tool_format": "openai",
    "model": "qwen2.5:7b-lab",
    "request_timeout": "300",
    "insecure": True,
    "proxy": False,
}
INSTANCE_NAME = "GuardianCohereLab"


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{BASE}{path}", data=data, method=method, headers={
        "Authorization": KEY, "Content-Type": "application/json", "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=60) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code} on {method} {path}: {e.read().decode()[:500]}", file=sys.stderr)
        raise


def main():
    search = call("POST", "/settings/integration/search", {"size": 500})
    cohere = next((c for c in search.get("configurations", []) if c.get("id") == "GuardianCohere"), None)
    if not cohere:
        sys.exit("GuardianCohere configuration not found (deploy the pack first).")

    # a data entry is the param definition + value/hasvalue
    data = []
    for p in cohere.get("configuration", []):
        name = p["name"]
        val = VALUES.get(name, p.get("defaultValue", ""))
        entry = dict(p)
        entry["value"] = val
        entry["hasvalue"] = val not in (None, "", False) or isinstance(val, bool)
        data.append(entry)

    existing = next((i for i in search.get("instances", []) if i.get("name") == INSTANCE_NAME), None)
    payload = {
        "brand": "GuardianCohere",
        "name": INSTANCE_NAME,
        "enabled": "true",
        "engine": "",
        "engineGroup": "",
        "propagationLabels": ["all"],
        "isIntegrationScript": True,
        "configuration": cohere,
        "data": data,
        "version": existing.get("version", -1) if existing else -1,
    }
    if existing:
        payload["id"] = existing["id"]

    res = call("PUT", "/settings/integration", payload)
    print("instance:", res.get("name"), "| id:", res.get("id"), "| enabled:", res.get("enabled"))

    # disable enabled Guardian Vertex instances so routing goes to the lab
    for i in call("POST", "/settings/integration/search", {"size": 500}).get("instances", []):
        if i.get("brand") == "GuardianVertex" and (i.get("enabled") in (True, "true")):
            i2 = dict(i)
            i2["enabled"] = "false"
            try:
                call("PUT", "/settings/integration", i2)
                print("disabled Guardian Vertex:", i.get("name"))
            except Exception as e:
                print("WARN could not disable Vertex", i.get("name"), ":", e)


if __name__ == "__main__":
    main()
