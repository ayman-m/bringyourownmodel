"""Faithful CommonServerPython shim for the Guardian lab — just the surface GuardianCohere uses,
with a REAL-HTTP BaseClient._http_request (via requests) that honors the exact kwargs the
integration passes (full_url / headers / json_data / params / timeout / ok_codes / resp_type /
retries / status_list_to_retry / backoff_factor). This runs the integration code UNCHANGED against
the live middleware — nothing about GuardianCohere.py is modified."""
import time
from urllib.parse import quote  # noqa: F401 (re-exported for GuardianCohere's explicit import safety)

import requests


class DemistoException(Exception):
    def __init__(self, message, res=None, exception=None):
        super().__init__(message)
        self.message = message
        self.res = res
        self.exception = exception


class CommandResults:
    def __init__(self, readable_output=None, outputs_prefix=None, outputs=None, raw_response=None,
                 outputs_key_field=None, **kwargs):
        self.readable_output = readable_output
        self.outputs_prefix = outputs_prefix
        self.outputs = outputs
        self.raw_response = raw_response
        self.outputs_key_field = outputs_key_field
        for k, v in kwargs.items():
            setattr(self, k, v)


class BaseClient:
    def __init__(self, base_url, verify=True, proxy=False, timeout=None, **kwargs):
        self._base_url = base_url
        self._verify = verify
        self._proxy = proxy
        self.timeout = timeout
        self._session = requests.Session()

    def _http_request(self, method, full_url=None, url_suffix="", headers=None, json_data=None,
                      params=None, timeout=None, ok_codes=None, resp_type="json", retries=0,
                      status_list_to_retry=None, backoff_factor=0, **kwargs):
        url = full_url or (self._base_url + (url_suffix or ""))
        attempts = int(retries or 0) + 1
        last_resp = None
        for i in range(attempts):
            resp = self._session.request(
                method, url, headers=headers, json=json_data, params=params,
                timeout=timeout or self.timeout, verify=self._verify,
            )
            last_resp = resp
            if ok_codes and resp.status_code not in ok_codes:
                if status_list_to_retry and resp.status_code in status_list_to_retry and i < attempts - 1:
                    time.sleep(float(backoff_factor or 0) * (i + 1))
                    continue
                raise DemistoException(f"Error in API call [{resp.status_code}] - {resp.reason}", res=resp)
            if resp_type == "text":
                return resp.text
            if resp_type == "content":
                return resp.content
            if resp_type == "response":
                return resp
            return resp.json()
        raise DemistoException("Error in API call - retries exhausted", res=last_resp)


def tableToMarkdown(name, t, headers=None, **kwargs):
    lines = [f"### {name}"]
    if isinstance(t, dict):
        for k, v in t.items():
            lines.append(f"- **{k}:** {v}")
    return "\n".join(lines)


class ScheduledCommand:
    """Shim of CommonServerPython.ScheduledCommand -- just stores what was passed so unit tests can
    assert on the re-scheduling contract (command / next_run_in_seconds / args / timeout_in_seconds).
    No platform polling behaviour."""

    def __init__(self, command, next_run_in_seconds, args=None, timeout_in_seconds=None, items_remaining=None):
        self.command = command
        self.next_run_in_seconds = next_run_in_seconds
        self.args = args
        self.timeout_in_seconds = timeout_in_seconds
        self.items_remaining = items_remaining


#: Public entries list. Tests read/clear ``CommonServerPython.RESULTS``; ``return_results`` appends here.
RESULTS = []


def return_results(results):
    RESULTS.append(results)


def return_error(message, error=None, outputs=None):
    raise SystemExit(str(message))


def argToBoolean(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    v = str(value).strip().lower()
    if v in ("true", "yes", "1", "y"):
        return True
    if v in ("false", "no", "0", "n", ""):
        return False
    raise ValueError(f"cannot convert {value!r} to boolean")


def arg_to_number(x, arg_name=None, required=False):
    if x in (None, ""):
        return None
    try:
        return int(x)
    except (TypeError, ValueError):
        try:
            return int(float(x))
        except (TypeError, ValueError):
            return None


def handle_proxy(*a, **k):
    return {}


class BaseWidget:
    def to_display(self):
        raise NotImplementedError


class BarColumnPieWidget(BaseWidget):
    """Faithful copy of CommonServerPython's Bar/Column/Pie Widget representation."""

    def __init__(self, categories=None):
        self.categories = categories if categories else []

    def add_category(self, name, number):
        self.categories.append({"name": name, "data": [number]})

    def to_display(self):
        import json
        return json.dumps(self.categories)


class LineWidget(BaseWidget):
    """Faithful copy of CommonServerPython's Line Widget representation."""

    def __init__(self, categories=None):
        self.categories = categories if categories else []

    def add_category(self, name, number, group):
        self.categories.append({
            "name": name,
            "data": [number],
            "groups": [{"name": group, "data": [number]}],
        })

    def to_display(self):
        import json
        processed_names = []
        processed_categories = []
        for cat in self.categories:
            if cat["name"] in processed_names:
                for processed_category in processed_categories:
                    if cat["name"] == processed_category["name"]:
                        processed_category["data"] = [processed_category["data"][0] + cat["data"][0]]
                        processed_category["groups"].extend(cat["groups"])
                        break
            else:
                processed_categories.append(cat)
                processed_names.append(cat["name"])
        return json.dumps(processed_categories)


class TableOrListWidget(BaseWidget):
    """Faithful copy of CommonServerPython's Table/List Widget representation."""

    def __init__(self, data=None):
        self.data = data if data else []
        if not isinstance(self.data, list):
            self.data = [data]

    def add_row(self, data):
        self.data.append(data)

    def to_display(self):
        import json
        return json.dumps({"total": len(self.data), "data": self.data})
