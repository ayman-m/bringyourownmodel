import json

import pytest

import GuardianLookup as gl

IP_ENTRY = {"Type": 1, "ContentsFormat": "json", "Contents": {"ip": "203.0.113.50"}, "HumanReadable": "ip table",
            "EntryContext": {"IP(val.Address && val.Address == obj.Address)": [{"Address": "203.0.113.50", "Score": 3}],
                             "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)": [
                                 {"Indicator": "203.0.113.50", "Vendor": "VendorA", "Score": 3}]}}
IP_ENTRY_B = {"Type": 1, "Contents": {}, "EntryContext": {
    "IP(val.Address && val.Address == obj.Address)": [{"Address": "203.0.113.50", "Geo": "XX"}],
    "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)": [
        {"Indicator": "203.0.113.50", "Vendor": "VendorB", "Score": 1}]}}
NO_MODULES = {"Type": 4, "ContentsFormat": "text",
              "Contents": "Couldnt find any modules to run for command `!endpoint` - stopping playbook"}


class Tenant(object):
    def __init__(self, reply=None, exc=None):
        self.reply, self.exc, self.calls, self.results = reply, exc, [], []

    def install(self, monkeypatch):
        monkeypatch.setattr(gl.demisto, "executeCommand", self.execute)
        monkeypatch.setattr(gl.demisto, "results", self.results.append)
        monkeypatch.setattr(gl.demisto, "error", lambda *_: None)
        return self

    def execute(self, command, args):
        self.calls.append((command, dict(args)))
        if self.exc:
            raise self.exc
        return self.reply


def _run(monkeypatch, command, args, reply=None, exc=None):
    tenant = Tenant(reply, exc).install(monkeypatch)
    monkeypatch.setattr(gl.demisto, "args", lambda: dict(args, command=command))
    gl.main()
    assert len(tenant.results) == 1
    return tenant, tenant.results[0]


def test_a_successful_generic_command_re_emits_its_context(monkeypatch):
    tenant, entry = _run(monkeypatch, "ip", {"ip": "203.0.113.50"}, reply=[IP_ENTRY])
    assert tenant.calls == [("ip", {"ip": "203.0.113.50"})]
    assert entry["Type"] == 1 and entry["Type"] != 4
    context = entry["EntryContext"]
    assert context["IP(val.Address && val.Address == obj.Address)"] == [{"Address": "203.0.113.50", "Score": 3}]
    assert len(context["DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)"]) == 1
    record = context["Guardian.Lookup.ip"]
    assert record["ok"] is True and record["error"] == "" and isinstance(record["seconds"], float)
    assert entry["Contents"].startswith("GuardianLookup ip: ok") and "\n" not in entry["Contents"]


def test_the_context_of_several_integrations_is_merged_under_the_same_keys(monkeypatch):
    _tenant, entry = _run(monkeypatch, "ip", {"ip": "203.0.113.50"}, reply=[IP_ENTRY, IP_ENTRY_B])
    scores = entry["EntryContext"]["DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)"]
    assert [s["Vendor"] for s in scores] == ["VendorA", "VendorB"]
    assert len(entry["EntryContext"]["IP(val.Address && val.Address == obj.Address)"]) == 2


@pytest.mark.parametrize("text", [
    "Couldnt find any modules to run for command `!endpoint` - stopping playbook",
    "Command is not supported by any enabled integration", "unsupported command", "Item not found (601)"])
def test_no_modules_and_unsupported_error_entries_are_recorded_not_raised(monkeypatch, text):
    _tenant, entry = _run(monkeypatch, "endpoint", {"hostname": "WS-0142"}, reply=[{"Type": 4, "Contents": text}])
    record = entry["EntryContext"]["Guardian.Lookup.endpoint"]
    assert record["ok"] is False and text[:40] in record["error"]
    assert set(entry["EntryContext"]) == {"Guardian.Lookup.endpoint"}
    assert "nothing came back" in entry["Contents"] and "The playbook goes on" in entry["Contents"] and entry["Type"] == 1


def test_a_mix_of_success_and_error_entries_keeps_the_success(monkeypatch):
    _tenant, entry = _run(monkeypatch, "ip", {"ip": "203.0.113.50"}, reply=[
        {"Type": 4, "Contents": "VendorC: 401 unauthorized api_key=abcdef0123456789abcdef"}, IP_ENTRY,
        {"Type": 4, "Contents": {"error": "VendorD timed out"}}])
    record = entry["EntryContext"]["Guardian.Lookup.ip"]
    assert record["ok"] is True and "VendorC: 401 unauthorized" in record["error"] and "VendorD timed out" in record["error"]
    assert "abcdef0123456789abcdef" not in record["error"]
    assert "IP(val.Address && val.Address == obj.Address)" in entry["EntryContext"]
    assert "ok (2 errors from other integrations)" in entry["Contents"]


def test_execute_command_raising_is_recorded_and_nothing_escapes(monkeypatch):
    tenant, entry = _run(monkeypatch, "domain", {"domain": "example.org"}, exc=RuntimeError("server went away"))
    record = entry["EntryContext"]["Guardian.Lookup.domain"]
    assert record["ok"] is False and "server went away" in record["error"] and len(tenant.calls) == 1


def test_an_unexpected_failure_still_returns_a_note(monkeypatch):
    tenant = Tenant([IP_ENTRY]).install(monkeypatch)
    monkeypatch.setattr(gl.demisto, "args", lambda: (_ for _ in ()).throw(RuntimeError("args broke")))
    gl.main()
    assert tenant.calls == [] and "failed" in tenant.results[0]["Contents"] and "The playbook goes on" in tenant.results[0]["Contents"]


@pytest.mark.parametrize("command", ["setIncident", "demisto-api-post", "GuardianToolBridge", "IP", "ip ", "", "!ip", "core-api-get", None])
def test_a_command_outside_the_fixed_set_is_refused_and_never_run(monkeypatch, command):
    tenant = Tenant([IP_ENTRY]).install(monkeypatch)
    monkeypatch.setattr(gl.demisto, "args", lambda: {"command": command, "ip": "203.0.113.50"})
    gl.main()
    entry = tenant.results[0]
    assert tenant.calls == [] or command == "ip "          # "ip " is trimmed to a command of the set
    if command != "ip ":
        record = entry["EntryContext"]["Guardian.Lookup.refused"]
        assert record["ok"] is False and "is not a lookup this script runs" in record["error"]
        assert set(entry["EntryContext"]) == {"Guardian.Lookup.refused"}


def test_the_fixed_set_is_exactly_the_eight_lookups_with_the_arguments_the_playbooks_use():
    assert gl.GUARDIAN_LOOKUP_COMMANDS == {
        "ip": ("ip",), "domain": ("domain",), "url": ("url",), "file": ("file",), "endpoint": ("hostname", "ip"),
        "cve": ("cve_id",), "GetUserData": ("user_name",), "GetEndpointData": ("endpoint_hostname",)}


def test_empty_arguments_are_dropped_and_nothing_is_run_when_none_is_left(monkeypatch):
    tenant, entry = _run(monkeypatch, "endpoint", {"hostname": "  ", "ip": ""}, reply=[IP_ENTRY])
    assert tenant.calls == [] and entry["EntryContext"]["Guardian.Lookup.endpoint"]["ok"] is False
    assert "no argument was given" in entry["EntryContext"]["Guardian.Lookup.endpoint"]["error"]
    tenant, _entry = _run(monkeypatch, "endpoint", {"hostname": "WS-0142", "ip": ""}, reply=[IP_ENTRY])
    assert tenant.calls == [("endpoint", {"hostname": "WS-0142"})]
    tenant, _entry = _run(monkeypatch, "endpoint", {"hostname": "", "ip": " 203.0.113.50 "}, reply=[IP_ENTRY])
    assert tenant.calls == [("endpoint", {"ip": "203.0.113.50"})]


def test_only_the_arguments_of_the_command_are_forwarded(monkeypatch):
    tenant, _entry = _run(monkeypatch, "ip", {"ip": "203.0.113.50", "hostname": "WS-0142", "using": "VendorA", "extra": "x"},
                          reply=[IP_ENTRY])
    assert tenant.calls == [("ip", {"ip": "203.0.113.50"})]


def test_the_argument_names_of_each_command(monkeypatch):
    for command, name in (("ip", "ip"), ("domain", "domain"), ("url", "url"), ("file", "file"), ("cve", "cve_id"),
                          ("GetUserData", "user_name"), ("GetEndpointData", "endpoint_hostname"), ("endpoint", "hostname")):
        tenant, _entry = _run(monkeypatch, command, {name: "value-1"}, reply=[IP_ENTRY])
        assert tenant.calls == [(command, {name: "value-1"})], command


@pytest.mark.parametrize("command, arg", [("GetUserData", "user_name"), ("GetEndpointData", "endpoint_hostname")])
@pytest.mark.parametrize("reply", [
    [{"Type": 4, "Contents": "Script GetUserData not found"}], [{"Type": 4, "Contents": "Unable to find script"}], [], None])
def test_a_content_script_that_is_not_installed_ends_in_a_note_not_a_stop(monkeypatch, command, arg, reply):
    tenant, entry = _run(monkeypatch, command, {arg: "jdoe"}, reply=reply)
    record = entry["EntryContext"]["Guardian.Lookup." + command]
    assert record["ok"] is False and record["error"] and entry["Type"] == 1 and len(tenant.calls) == 1


def test_entries_that_are_not_errors_but_carry_no_context_still_count_as_an_answer(monkeypatch):
    _tenant, entry = _run(monkeypatch, "cve", {"cve_id": "CVE-2026-0001"}, reply=[{"Type": 1, "Contents": "nothing known"}])
    assert entry["EntryContext"]["Guardian.Lookup.cve"]["ok"] is True and set(entry["EntryContext"]) == {"Guardian.Lookup.cve"}


def test_the_context_merge_joins_lists_merges_dicts_and_keeps_a_clash_as_a_list():
    merged = gl.guardian_lookup_merge_context([{"A": [1], "B": {"x": 1}, "C": "one"}, {"A": [2], "B": {"y": 2}, "C": "two"}, {}])
    assert merged == {"A": [1, 2], "B": {"x": 1, "y": 2}, "C": ["one", "two"]}


def test_an_overlong_value_is_cut():
    assert len(gl.guardian_lookup_args("url", {"url": "u" * 5000})["url"]) == gl.GUARDIAN_LOOKUP_VALUE_MAX_CHARS
    assert gl.guardian_lookup_args("url", {"url": {"a": 1}}) == {} and gl.guardian_lookup_args("url", None) == {}


def test_the_script_is_well_formed():
    import pathlib

    import yaml

    folder = pathlib.Path(gl.__file__).parent
    doc = yaml.safe_load((folder / "GuardianLookup.yml").read_text())
    assert doc["commonfields"]["id"] == doc["name"] == "GuardianLookup" and doc["marketplaces"] == ["xsoar"]
    arguments = {a["name"]: a for a in doc["args"]}
    assert arguments["command"]["required"] is True and set(arguments["command"]["predefined"]) == set(gl.GUARDIAN_LOOKUP_COMMANDS)
    assert set(arguments) == {"command", "ip", "domain", "url", "file", "hostname", "cve_id", "user_name", "endpoint_hostname"}
    assert all(a["required"] is False for n, a in arguments.items() if n != "command")
    assert (folder / "README.md").exists()
    source = (folder / "GuardianLookup.py").read_text()
    assert source.count("# <GUARDIAN_COMMON_INJECT>") == 1 and source.count("# </GUARDIAN_COMMON>") == 1
