import json

import pytest

import GuardianToolsCommand as tools


# --- fixtures / test harness --------------------------------------------------


def _install(monkeypatch, getlist_handler=None, catalog_handler=None):
    """Wire the configured List plus the live catalogue-builder result."""

    def default_handler(args):
        raise AssertionError("no getList handler installed for this test")

    handler = getlist_handler or default_handler

    def default_catalog_handler(_args):
        entries = handler({"listName": "guardian_tool_allowlist"})
        if any(entry.get("Type") == 4 for entry in entries if isinstance(entry, dict)):
            return entries
        contents = entries[-1].get("Contents") if entries else None
        if isinstance(contents, str):
            contents = json.loads(contents)
        if not isinstance(contents, dict) or not isinstance(contents.get("commands"), list):
            return [{"Type": 1, "Contents": {"catalog": []}}]
        names = contents.get("commands") if isinstance(contents, dict) else []
        catalog = [
            {"type": "function", "function": {"name": name}}
            for name in names or []
            if isinstance(name, str) and name.strip()
        ]
        return [
            {
                "Type": 1,
                "Contents": {
                    "catalog": catalog,
                    "configured_commands": names or [],
                    "allowlist_source": "baseline_fallback",
                    "warning": None,
                    "dropped_by_budget": [],
                    "missing_on_box": [],
                    "excluded_by_denylist": [],
                    "max_tool_def_tokens": 4000,
                },
            }
        ]

    def fake_execute(command, args):
        if command == "getList":
            return handler(args)
        if command == "GuardianToolCatalogBuilder":
            return (catalog_handler or default_catalog_handler)(args)
        raise AssertionError("unexpected command dispatched: {} {}".format(command, args))

    monkeypatch.setattr(tools.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(tools.demisto, "error", lambda msg: None)
    monkeypatch.setattr(tools.demisto, "info", lambda msg: None)


def _getlist_ok(contents):
    def handler(args):
        return [{"Type": 1, "Contents": contents}]

    return handler


def _getlist_error(message):
    def handler(args):
        return [{"Type": 4, "Contents": message}]

    return handler


# --- guardian_tools_run ---------------------------------------------------------


def test_missing_list_is_a_failure(monkeypatch):
    _install(monkeypatch, _getlist_error("Item not found (8) on list [guardian_tool_allowlist]"))
    result = tools.guardian_tools_run()
    assert result["ok"] is False
    assert "guardian_tool_allowlist" in result["error"]


def test_malformed_json_is_a_failure(monkeypatch):
    _install(monkeypatch, _getlist_ok("not json"))
    result = tools.guardian_tools_run()
    assert result["ok"] is False
    assert "GuardianToolCatalogBuilder" in result["error"]


def test_non_object_payload_is_a_failure(monkeypatch):
    _install(monkeypatch, _getlist_ok(json.dumps([1, 2, 3])))
    result = tools.guardian_tools_run()
    assert result["ok"] is False
    assert "configured_commands" in result["error"]


def test_missing_commands_array_is_a_failure(monkeypatch):
    _install(monkeypatch, _getlist_ok(json.dumps({"_comment": "x"})))
    result = tools.guardian_tools_run()
    assert result["ok"] is False
    assert "commands" in result["error"]


def test_commands_deduplicated_and_order_preserved(monkeypatch):
    payload = {"commands": ["ip", "domain", "ip", "url"], "_comment": "Curated read-only allowlist. More detail."}
    _install(monkeypatch, _getlist_ok(json.dumps(payload)))
    result = tools.guardian_tools_run()
    assert result["ok"] is True
    data = result["data"]
    assert data["commands"] == ["ip", "domain", "url"]
    assert data["count"] == 3
    assert data["curation_note"] is None


def test_non_string_entries_are_dropped(monkeypatch):
    payload = {"commands": ["ip", 42, None, "", "domain"]}
    _install(monkeypatch, _getlist_ok(json.dumps(payload)))
    result = tools.guardian_tools_run()
    assert result["ok"] is True
    assert result["data"]["commands"] == ["ip", "domain"]


def test_already_parsed_dict_contents_accepted(monkeypatch):
    # Some server versions/mocks may hand back already-parsed dict Contents rather than a
    # JSON string -- guardian_tools_load_list_json accepts both.
    _install(monkeypatch, _getlist_ok({"commands": ["ip"]}))
    result = tools.guardian_tools_run()
    assert result["ok"] is True
    assert result["data"]["commands"] == ["ip"]


def test_no_comment_means_no_curation_note(monkeypatch):
    _install(monkeypatch, _getlist_ok(json.dumps({"commands": ["ip"]})))
    result = tools.guardian_tools_run()
    assert result["ok"] is True
    assert result["data"]["curation_note"] is None


def test_live_catalogue_count_and_budget_drops_are_reported(monkeypatch):
    payload = {"commands": ["ip", "domain"]}

    def catalog_handler(_args):
        return [
            {
                "Type": 1,
                "Contents": {
                    "catalog": [{"type": "function", "function": {"name": "ip"}}],
                    "configured_commands": ["ip", "domain"],
                    "allowlist_source": "baseline_fallback",
                    "warning": "Tool catalogue exceeded max_tool_def_tokens (4000); TRUNCATED.",
                    "dropped_by_budget": ["domain"],
                    "missing_on_box": [],
                    "excluded_by_denylist": [],
                    "max_tool_def_tokens": 4000,
                },
            }
        ]

    _install(monkeypatch, _getlist_ok(json.dumps(payload)), catalog_handler=catalog_handler)
    result = tools.guardian_tools_run()

    assert result["ok"] is True
    data = result["data"]
    assert data["commands"] == ["ip"]
    assert data["count"] == 1
    assert data["configured_commands"] == ["ip", "domain"]
    assert data["configured_count"] == 2
    assert data["dropped_by_budget"] == ["domain"]
    assert data["allowlist_source"] == "baseline_fallback"
    assert data["excluded_by_denylist"] == []
    assert data["max_tool_def_tokens"] == 4000
    rendered = tools.guardian_tools_render(data)
    assert "1 tool(s)" in rendered
    assert "Dropped by token budget: domain" in rendered
    assert "WARNING:" in rendered


def test_list_name_reflects_runtime_source_when_catalog_builder_reports_runtime(monkeypatch):
    """list_name is no longer unconditionally "guardian_tool_allowlist" --
    once an operator has populated the runtime List, it must read
    "guardian_tool_allowlist_runtime" instead, matching whatever
    GuardianToolCatalogBuilder actually built from."""

    def catalog_handler(_args):
        return [
            {
                "Type": 1,
                "Contents": {
                    "catalog": [{"type": "function", "function": {"name": "whois"}}],
                    "configured_commands": ["whois"],
                    "allowlist_source": "runtime",
                    "warning": None,
                    "dropped_by_budget": [],
                    "missing_on_box": [],
                    "excluded_by_denylist": [],
                    "excluded_by_operator_boundary": ["guardian-approve"],
                    "max_tool_def_tokens": 4000,
                },
            }
        ]

    _install(monkeypatch, _getlist_ok(json.dumps({"commands": ["whois"]})), catalog_handler=catalog_handler)
    result = tools.guardian_tools_run()

    assert result["ok"] is True
    data = result["data"]
    assert data["list_name"] == "guardian_tool_allowlist_runtime"
    assert data["allowlist_source"] == "runtime"
    assert data["excluded_by_operator_boundary"] == ["guardian-approve"]
    rendered = tools.guardian_tools_render(data)
    assert "Excluded by Guardian operator-only boundary: guardian-approve" in rendered


# --- guardian_tools_curation_note ------------------------------------------------


def test_curation_note_single_sentence_no_trailing_period_space():
    assert tools.guardian_tools_curation_note("Just one sentence with no other period") == (
        "Just one sentence with no other period"
    )


def test_curation_note_blank_or_non_string():
    assert tools.guardian_tools_curation_note("   ") is None
    assert tools.guardian_tools_curation_note(None) is None
    assert tools.guardian_tools_curation_note(123) is None


# --- guardian_tools_render --------------------------------------------------------


def test_render_lists_every_command_numbered():
    text = tools.guardian_tools_render({"list_name": "guardian_tool_allowlist", "commands": ["ip", "domain"], "count": 2, "curation_note": None})
    assert "1. `ip`" in text
    assert "2. `domain`" in text
    assert "**2 tool(s)**" in text


def test_render_empty_commands():
    text = tools.guardian_tools_render({"list_name": "guardian_tool_allowlist", "commands": [], "count": 0, "curation_note": None})
    assert "none configured" in text


def test_render_includes_curation_note_when_present():
    text = tools.guardian_tools_render(
        {"list_name": "guardian_tool_allowlist", "commands": ["ip"], "count": 1, "curation_note": "A short note."}
    )
    assert "Curation note: A short note." in text


# --- main() smoke tests --------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    _install(monkeypatch, _getlist_ok(json.dumps({"commands": ["ip", "domain"]})))

    import CommonServerPython as csp

    csp.RESULTS.clear()
    tools.main()

    assert len(csp.RESULTS) == 1
    result = csp.RESULTS[0]
    assert result.outputs["count"] == 2
    assert "ip" in result.readable_output


def test_main_failure_calls_return_error(monkeypatch):
    _install(monkeypatch, _getlist_error("Item not found (8) on list [guardian_tool_allowlist]"))

    import CommonServerPython as csp

    csp.RESULTS.clear()
    with pytest.raises(SystemExit):
        tools.main()
    assert len(csp.RESULTS) == 0


# --- the "on this tenant but not allowlisted" section -----------------------------------------------


def test_render_lists_the_commands_the_allowlist_leaves_out():
    data = {"list_name": "guardian_tool_allowlist", "count": 1, "commands": ["core-get-issues"], "configured_count": 1,
            "allowlist_source": "baseline_fallback",
            "on_box": {"total_commands": 142, "brand_count": 13, "allowlisted_present": 9, "not_allowlisted": 133,
                       "brands": [{"brand": "Core - IR", "commands": 80, "read": 30, "write": 45, "unknown": 5,
                                   "read_examples": ["core-get-asset-details", "core-list-users"]}]}}
    text = tools.guardian_tools_render(data)
    assert "### On this tenant but not allowlisted" in text
    assert "142 command(s) on 13 brand(s)" in text and "**133** are not offered" in text
    assert "| Core - IR | 80 | 30 | 45 | 5 | `core-get-asset-details`, `core-list-users` |" in text


def test_render_without_the_summary_is_unchanged():
    data = {"list_name": "guardian_tool_allowlist", "count": 1, "commands": ["ip"], "configured_count": 1, "allowlist_source": "baseline_fallback"}
    assert "not allowlisted" not in tools.guardian_tools_render(data)


def test_render_with_everything_allowlisted_says_so():
    data = {"list_name": "x", "count": 0, "commands": [], "on_box": {"total_commands": 3, "brand_count": 1, "allowlisted_present": 3, "not_allowlisted": 0, "brands": []}}
    assert "every installed command is already on the allowlist" in tools.guardian_tools_render(data)


def test_run_passes_the_summary_through(monkeypatch):
    def catalog_handler(args):
        return [{"Type": 1, "Contents": {"catalog": [], "configured_commands": ["ip"], "allowlist_source": "baseline_fallback",
                                           "on_box": {"total_commands": 2, "brand_count": 1, "allowlisted_present": 1, "not_allowlisted": 1, "brands": []}}}]
    _install(monkeypatch, _getlist_ok({"commands": ["ip"]}), catalog_handler)
    result = tools.guardian_tools_run()
    assert result["data"]["on_box"]["not_allowlisted"] == 1
