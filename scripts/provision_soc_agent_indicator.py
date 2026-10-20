#!/usr/bin/env python3
"""Provision Guardian's SOC Agent indicator control plane on an XSOAR 6 tenant.

The normal pack-zip deployment path marks content as system-owned on an XSOAR
development tenant. This installer uses three explicit, paced phases so it can
deliver the complete indicator control plane without exceeding the project's
per-run write budget. The foundation phase uploads the display scripts and all
SOC Agent indicator fields. The controls phase uploads the action scripts,
layout, and indicator type, then creates the single ``guardian:primary``
record if it does not already exist.

Run without arguments to validate and show the exact write plan. Use
``--apply --phase foundation``, ``--apply --phase controls``, then
``--apply --phase finalize`` only against the intended tenant. All API calls
are serialised and paced at 1.5 seconds; no phase exceeds ten writes.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FOUNDATION_SCRIPT_IDS = (
    "GuardianToolRegistryRefresh",
    "GuardianLayoutSocAgentTools",
    "GuardianLayoutSocAgentPersona",
    "GuardianLayoutSocAgentMemory",
)
CONTROL_SCRIPT_IDS = (
    "GuardianSocAgentValidateToolPolicy",
    "GuardianSocAgentReadiness",
    "GuardianSocAgentExportConfiguration",
    "GuardianSocAgentApplyToolPolicy",
    "GuardianSocAgentCreateInvestigation",
    "GuardianSocAgentSetState",
)
SCRIPT_IDS = FOUNDATION_SCRIPT_IDS + CONTROL_SCRIPT_IDS
SCRIPT_DIRECTORY_BY_ID: dict[str, str] = {}
LAYOUT_PATH = ROOT / "Packs/Guardian/Layouts/layoutscontainer-GuardianSocAgentLayout.json"
INDICATOR_TYPE_PATH = ROOT / "Packs/Guardian/IndicatorTypes/reputation-SOC_Agent.json"
INDICATOR_FIELDS_DIR = ROOT / "Packs/Guardian/IndicatorFields"
INDICATOR_TYPE = "SOC Agent"
INDICATOR_VALUE = "guardian:primary"
MIN_CALL_GAP_SECONDS = 1.5


class ApiError(RuntimeError):
    """An XSOAR API request did not complete successfully."""


def load_environment() -> dict[str, str]:
    """Merge the repo-local, untracked .env into the process environment.

    Explicit environment variables win, so CI or an operator can override the
    local connection without changing the tracked command or source files.
    """
    environment = dict(os.environ)
    dotenv = ROOT / ".env"
    if not dotenv.exists():
        return environment
    for raw_line in dotenv.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        environment.setdefault(key, value)
    return environment


def artifact_paths() -> tuple[Path, ...]:
    return tuple(script_path(script_id) for script_id in SCRIPT_IDS) + (
        *indicator_field_paths(),
        LAYOUT_PATH,
        INDICATOR_TYPE_PATH,
    )


def indicator_field_paths() -> tuple[Path, ...]:
    return tuple(sorted(INDICATOR_FIELDS_DIR.glob("*.json")))


def script_path(script_id: str) -> Path:
    return ROOT / "Packs/Guardian/Scripts" / SCRIPT_DIRECTORY_BY_ID.get(script_id, script_id)


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return data


def validate_artifacts() -> None:
    """Catch reference mistakes locally, before a tenant API call is made."""
    missing = [path.relative_to(ROOT) for path in artifact_paths() if not path.exists()]
    if missing:
        raise ValueError(f"missing provisioning artifacts: {', '.join(map(str, missing))}")

    indicator_type = load_json(INDICATOR_TYPE_PATH)
    if indicator_type.get("id") != INDICATOR_TYPE or indicator_type.get("details") != INDICATOR_TYPE:
        raise ValueError("SOC Agent indicator type must use SOC Agent for both id and details")
    if indicator_type.get("layout") != "GuardianSocAgentLayout":
        raise ValueError("SOC Agent indicator type is not bound to GuardianSocAgentLayout")

    fields = [load_json(path) for path in indicator_field_paths()]
    if len(fields) != 10:
        raise ValueError("expected exactly ten Guardian SOC Agent indicator fields")
    field_ids = {str(field.get("id")) for field in fields}
    cli_names = {str(field.get("cliName")) for field in fields}
    expected_cli_names = {
        "socagentstate", "socagentowner", "socagentmodelintegration", "socagentlasthealthcheck",
        "socagentpolicyrevision", "socagentpersona", "socagenttoolpolicy", "socagentmemorypolicy",
        "socagentoperatorguide", "socagenttoolapprovals",
    }
    if cli_names != expected_cli_names or len(field_ids) != len(fields):
        raise ValueError("SOC Agent indicator fields have missing or duplicate machine names")
    for field in fields:
        if field.get("group") != 2 or field.get("associatedTypes") != [INDICATOR_TYPE]:
            raise ValueError("every SOC Agent indicator field must be group 2 and scoped only to SOC Agent")

    layout = load_json(LAYOUT_PATH)
    if layout.get("id") != "GuardianSocAgentLayout" or layout.get("group") != "indicator":
        raise ValueError("SOC Agent layout must be an indicator layoutscontainer with the expected id")

    dynamic_references: set[str] = set()
    button_references: set[str] = set()
    for view in ("indicatorsDetails", "indicatorsQuickView"):
        for tab in (layout.get(view) or {}).get("tabs") or []:
            for section in tab.get("sections") or []:
                if section.get("type") == "dynamicIndicator" and section.get("queryType") == "script":
                    dynamic_references.add(str(section.get("query")))
                for item in section.get("items") or []:
                    if item.get("sectionItemType") == "button":
                        button_references.add(str(item.get("scriptId")))

    expected_dynamic = {
        "GuardianLayoutSocAgentTools",
        "GuardianLayoutSocAgentPersona",
        "GuardianLayoutSocAgentMemory",
        "GuardianSocAgentReadiness",
    }
    if not expected_dynamic.issubset(dynamic_references):
        missing_dynamic = sorted(expected_dynamic - dynamic_references)
        raise ValueError(f"layout is missing dynamic script references: {', '.join(missing_dynamic)}")
    expected_buttons = {
        "GuardianToolRegistryRefresh",
        "GuardianSocAgentValidateToolPolicy",
        "GuardianSocAgentReadiness",
        "GuardianSocAgentExportConfiguration",
        "GuardianSocAgentSetState",
        "GuardianSocAgentApplyToolPolicy",
        "GuardianSocAgentCreateInvestigation",
    }
    if button_references != expected_buttons:
        raise ValueError("SOC Agent layout button scripts do not match the expected operator controls")


def ssl_context(environment: dict[str, str]) -> ssl.SSLContext:
    verify = environment.get("DEMISTO_VERIFY_SSL", "true").lower() not in {"false", "0", "no"}
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


class PacedXSOAR:
    """Raw-key XSOAR client with a conservative tenant-call cadence."""

    def __init__(self, environment: dict[str, str]) -> None:
        self.base = (environment.get("DEMISTO_BASE_URL") or "").rstrip("/")
        self.key = environment.get("DEMISTO_API_KEY") or ""
        if not self.base or not self.key:
            raise ApiError("DEMISTO_BASE_URL and DEMISTO_API_KEY must be set (environment or .env)")
        self.context = ssl_context(environment)
        self._last_call = 0.0
        self.calls = 0

    def _wait(self) -> None:
        delay = MIN_CALL_GAP_SECONDS - (time.monotonic() - self._last_call)
        if delay > 0:
            time.sleep(delay)

    def request(self, method: str, path: str, body: bytes | None = None, content_type: str | None = None) -> Any:
        self._wait()
        headers = {"Authorization": self.key, "Accept": "application/json"}
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=180) as response:
                raw = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            raise ApiError(f"{method} {path} returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise ApiError(f"{method} {path} could not reach the tenant: {exc.reason}") from exc
        self._last_call = time.monotonic()
        self.calls += 1
        return json.loads(raw) if raw.strip() else {}

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post_json(self, path: str, payload: dict[str, Any]) -> Any:
        return self.request("POST", path, json.dumps(payload).encode("utf-8"), "application/json")

    def post_file(self, path: str, filename: str, content: bytes) -> Any:
        boundary = f"----guardian-{secrets.token_hex(16)}"
        body = b"".join(
            (
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode(),
                b"Content-Type: application/json\r\n\r\n",
                content,
                f"\r\n--{boundary}--\r\n".encode(),
            )
        )
        return self.request("POST", path, body, f"multipart/form-data; boundary={boundary}")


def upload_script(environment: dict[str, str], script_id: str) -> None:
    """Let demisto-sdk unify the split script source before API import."""
    sdk = ROOT / ".venv/bin/demisto-sdk"
    executable = str(sdk) if sdk.is_file() else shutil.which("demisto-sdk")
    if not executable:
        raise ApiError("demisto-sdk is required to upload split automation source")
    command = [executable, "upload", "--input", str(script_path(script_id)), "--override-existing"]
    if environment.get("DEMISTO_VERIFY_SSL", "true").lower() in {"false", "0", "no"}:
        command.append("--insecure")
    sdk_environment = dict(environment)
    sdk_environment.setdefault("DEMISTO_SDK_IGNORE_CONTENT_WARNING", "true")
    completed = subprocess.run(command, cwd=ROOT, env=sdk_environment, text=True, capture_output=True, timeout=300)
    if completed.returncode != 0:
        detail = (completed.stdout + completed.stderr).strip().splitlines()
        message = detail[-1] if detail else "no diagnostic returned"
        raise ApiError(f"automation upload failed for {script_id}: {message[:500]}")


def upload_scripts(environment: dict[str, str], script_ids: tuple[str, ...]) -> None:
    for script_id in script_ids:
        upload_script(environment, script_id)
        # The SDK import itself is one tenant write. Start the next operation
        # only after the same safety gap used for raw REST calls.
        time.sleep(MIN_CALL_GAP_SECONDS)
        print(f"  ✓ automation uploaded: {script_id}")


def import_indicator_fields(tenant: PacedXSOAR) -> None:
    payload = {"incidentFields": [load_json(path) for path in indicator_field_paths()]}
    response = tenant.post_file("/incidentfields/import", "guardian_soc_agent_indicator_fields.json", json.dumps(payload).encode("utf-8"))
    print(f"  ✓ imported {len(payload['incidentFields'])} SOC Agent indicator fields ({response_id(response)})")


def check_indicator_fields_present(tenant: PacedXSOAR) -> None:
    fields = tenant.get("/incidentfields")
    if not isinstance(fields, list):
        raise ApiError("GET /incidentfields returned an unexpected response")
    expected = {load_json(path)["cliName"] for path in indicator_field_paths()}
    actual = {field.get("cliName") for field in fields if isinstance(field, dict) and field.get("group") == 2}
    missing = sorted(expected - actual)
    if missing:
        raise ApiError("foundation phase is incomplete; missing indicator fields: {}".format(", ".join(missing)))


def ensure_primary_indicator(tenant: PacedXSOAR) -> None:
    existing = tenant.post_json(
        "/indicators/search",
        {"query": f'type:"{INDICATOR_TYPE}" and value:"{INDICATOR_VALUE}"', "page": 0, "size": 1},
    )
    iocs = existing.get("iocObjects") if isinstance(existing, dict) else None
    if isinstance(iocs, list) and iocs:
        print("  ✓ primary SOC Agent indicator already exists; left unchanged")
        return
    created = tenant.post_json(
        "/indicator/create",
        {
            "indicator": {
                "value": INDICATOR_VALUE,
                "indicator_type": INDICATOR_TYPE,
                "source": "Guardian Harness",
                "comment": "Primary Guardian SOC Agent control-plane record.",
            },
            "seenNow": True,
        },
    )
    print(f"  ✓ primary SOC Agent indicator created ({response_id(created)})")


def provision(environment: dict[str, str], phase: str) -> None:
    tenant = PacedXSOAR(environment)
    about = tenant.get("/about")
    version = about.get("demistoVersion") if isinstance(about, dict) else None
    print(f"Tenant preflight passed{f' (XSOAR {version})' if version else ''}.")

    if phase == "fields":
        import_indicator_fields(tenant)
        return

    if phase == "foundation":
        upload_scripts(environment, FOUNDATION_SCRIPT_IDS)
        import_indicator_fields(tenant)
        return

    check_indicator_fields_present(tenant)
    if phase == "state":
        upload_scripts(environment, ("GuardianSocAgentSetState",))
        return
    if phase == "controls":
        upload_scripts(environment, CONTROL_SCRIPT_IDS)
        return

    layout_response = tenant.post_file("/layouts/import", LAYOUT_PATH.name, LAYOUT_PATH.read_bytes())
    print(f"  ✓ indicator layout imported: GuardianSocAgentLayout ({response_id(layout_response)})")

    indicator_type_bytes = json.dumps([load_json(INDICATOR_TYPE_PATH)]).encode("utf-8")
    type_response = tenant.post_file("/reputation/import", INDICATOR_TYPE_PATH.name, indicator_type_bytes)
    print(f"  ✓ indicator type imported: {INDICATOR_TYPE} ({response_id(type_response)})")

    ensure_primary_indicator(tenant)


def response_id(response: Any) -> str:
    """Return only non-sensitive response identity for a concise operator log."""
    if isinstance(response, dict):
        identifier = response.get("id") or response.get("name")
        if identifier:
            return f"id={identifier}"
    return "accepted"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="perform the paced API provisioning run")
    parser.add_argument("--phase", choices=("foundation", "controls", "finalize", "fields", "state"), help="foundation, controls, then finalize; fields/state are narrow recovery phases")
    args = parser.parse_args(argv)

    try:
        validate_artifacts()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"provision_soc_agent_indicator: local validation failed: {exc}", file=sys.stderr)
        return 2

    if not args.apply:
        print("Local validation passed. Dry run; no tenant calls were made.")
        print("Foundation: upload 4 display automations and import 10 SOC Agent indicator fields (5 writes).")
        print("Controls: verify fields and upload 6 action/readiness automations (6 writes).")
        print("Finalize: verify fields, import layout/type, and create guardian:primary if absent (at most 3 writes).")
        print("Run --apply --phase foundation, then --apply --phase controls, then --apply --phase finalize.")
        return 0

    if not args.phase:
        print("provision_soc_agent_indicator: --phase is required with --apply", file=sys.stderr)
        return 2

    try:
        provision(load_environment(), args.phase)
    except (ApiError, OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError) as exc:
        print(f"provision_soc_agent_indicator: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
