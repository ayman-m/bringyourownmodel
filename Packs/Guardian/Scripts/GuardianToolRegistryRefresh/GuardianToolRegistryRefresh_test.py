import json

import GuardianToolRegistryRefresh as refresh

if not hasattr(refresh.demisto, "getAllSupportedCommands"):
    refresh.demisto.getAllSupportedCommands = lambda: {}


def _install(monkeypatch, lists=None):
    lists = dict(lists or {})
    calls = []

    def fake_execute(command, args):
        calls.append((command, dict(args)))
        if command == "getList":
            name = args["listName"]
            if name not in lists:
                return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(name)}]
            return [{"Type": 1, "Contents": json.dumps(lists[name])}]
        if command in ("createList", "setList"):
            lists[args["listName"]] = json.loads(args["listData"])
            return [{"Type": 1, "Contents": "Done"}]
        raise AssertionError("unexpected command: {} {}".format(command, args))

    monkeypatch.setattr(refresh.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(refresh.demisto, "error", lambda _message: None)
    monkeypatch.setattr(refresh.demisto, "info", lambda _message: None)
    return lists, calls


def test_discovery_deduplicates_commands_and_keeps_instance_sources():
    result = refresh.guardian_registry_discover_commands(
        {
            "Splunk Primary": [{"name": "splunk-search"}, {"name": "ip"}],
            "IPInfo": [{"name": "ip"}, {"name": "domain"}],
            "Broken": "not-a-list",
        }
    )

    assert result["ok"] is True
    assert result["data"] == [
        {"name": "domain", "instances": ["IPInfo"]},
        {"name": "ip", "instances": ["IPInfo", "Splunk Primary"]},
        {"name": "splunk-search", "instances": ["Splunk Primary"]},
    ]


def test_refresh_initializes_runtime_allowlist_once_and_writes_snapshot(monkeypatch):
    lists, _calls = _install(
        monkeypatch,
        {
            "guardian_tool_allowlist": {"commands": ["ip", "domain"]},
        },
    )

    result = refresh.guardian_tool_registry_refresh_run(
        get_all_supported_fn=lambda: {"IPInfo": [{"name": "ip"}], "Whois": [{"name": "whois"}]},
        now_fn=lambda: "2026-08-18T00:00:00Z",
    )

    assert result["ok"] is True
    assert result["data"]["allowlist_action"] == "initialized_from_baseline"
    assert lists["guardian_tool_allowlist_runtime"]["commands"] == ["ip", "domain"]
    assert lists["guardian_tool_available"]["refreshed_at"] == "2026-08-18T00:00:00Z"
    assert lists["guardian_tool_available"]["commands"] == [
        {"name": "ip", "instances": ["IPInfo"]},
        {"name": "whois", "instances": ["Whois"]},
    ]


def test_refresh_preserves_operator_allowlist_on_later_refresh(monkeypatch):
    lists, _calls = _install(
        monkeypatch,
        {
            "guardian_tool_allowlist": {"commands": ["ip", "domain"]},
            "guardian_tool_allowlist_runtime": {"commands": ["splunk-search"]},
            "guardian_tool_available": {"commands": []},
        },
    )

    result = refresh.guardian_tool_registry_refresh_run(
        get_all_supported_fn=lambda: {"Splunk": [{"name": "splunk-search"}]},
        now_fn=lambda: "2026-08-18T00:01:00Z",
    )

    assert result["ok"] is True
    assert result["data"]["allowlist_action"] == "already_present"
    assert lists["guardian_tool_allowlist_runtime"]["commands"] == ["splunk-search"]
    assert lists["guardian_tool_available"]["total_commands"] == 1


def test_refresh_does_not_overwrite_unreadable_runtime_allowlist(monkeypatch):
    _lists, _calls = _install(
        monkeypatch,
        {
            "guardian_tool_allowlist": {"commands": ["ip"]},
            "guardian_tool_allowlist_runtime": {"wrong": []},
        },
    )

    result = refresh.guardian_tool_registry_refresh_run(get_all_supported_fn=lambda: {})

    assert result["ok"] is False
    assert "commands" in result["error"]


# --- main() message shape: the layout UI supplies the "<button> ..." wrapper
# itself (verified live via POST /indicator/execute/{id}); this script must
# not restate it, or the toast reads the sentence twice. --------------------


def test_main_success_leaves_the_ui_wrapper_unrestated(monkeypatch):
    refresh.RESULTS.clear()
    _install(monkeypatch, {"guardian_tool_allowlist": {"commands": ["ip"]}})
    monkeypatch.setattr(refresh.demisto, "args", lambda: {})
    monkeypatch.setattr(refresh.demisto, "getAllSupportedCommands", lambda: {"Core": [{"name": "ip"}]})
    refresh.main()
    assert len(refresh.RESULTS) == 1
    # short and non-empty: empty triggers XSOAR's own outputs-table fallback
    assert refresh.RESULTS[0].readable_output == "1 command(s) across 1 instance(s)."
    assert refresh.RESULTS[0].outputs["available_commands"] == 1


def test_main_failure_carries_no_manual_button_prefix(monkeypatch):
    import pytest

    _install(monkeypatch)  # no guardian_tool_allowlist -- baseline unreadable
    monkeypatch.setattr(refresh.demisto, "args", lambda: {})
    with pytest.raises(SystemExit) as exc_info:
        refresh.main()
    assert not str(exc_info.value).startswith('"')  # no manual prefix -- the UI adds '"Refresh Tools" failed.' itself
