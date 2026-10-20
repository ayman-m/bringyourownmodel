import json
import re
from pathlib import Path

import GuardianToolCatalogBuilder as tcb

# The off-platform shim intentionally grows script-only methods on demand;
# the real XSOAR demisto object always supplies this one.
if not hasattr(tcb.demisto, "getAllSupportedCommands"):
    tcb.demisto.getAllSupportedCommands = lambda: {}


# --- test fixtures ------------------------------------------------------------


def _command(name, description="A command.", arguments=None, **extra):
    cmd = {
        "name": name,
        "deprecated": False,
        "hidden": False,
        "description": description,
        "arguments": arguments or [],
        "outputs": [],
    }
    cmd.update(extra)
    return cmd


def _all_supported_stub(brands_to_commands):
    def fake_get_all_supported_commands():
        return brands_to_commands

    return fake_get_all_supported_commands


def _lists_stub(data_by_name, missing=None, bad_json=None):
    """Fake demisto.executeCommand that answers getList calls from a
    {list_name: python_value} map, JSON-serializing the value into Contents
    exactly as the real getList command does (Task 1.2 discovery: Contents
    is always the raw JSON *string*, never pre-parsed).
    """
    missing = missing or set()
    bad_json = bad_json or set()

    def fake_execute(command, args):
        assert command == "getList"
        name = args["listName"]
        if name in missing:
            return [{"Type": 4, "Contents": "Item not found: {}".format(name)}]
        if name in bad_json:
            return [{"Type": 1, "Contents": "{not valid json"}]
        if name not in data_by_name:  # e.g. guardian_model_profile, which a box may not have yet
            return [{"Type": 4, "Contents": "Item not found (8)"}]
        return [{"Type": 1, "Contents": json.dumps(data_by_name[name])}]

    return fake_execute


DEFAULT_ALLOWLIST = {"_comment": "x", "commands": ["ip", "whois", "demisto-api-delete"]}
DEFAULT_DENYLIST = {
    "_comment": "x",
    "protected_lists": ["guardian_policy"],
    "denied": ["demisto-api-delete", "setList:guardian_policy"],
}
DEFAULT_SETTINGS = {"max_tool_def_tokens": None}

REPO_ROOT = Path(__file__).resolve().parents[4]


def _shipped_list_payload(list_name):
    """Load the exact seed payload rather than a hand-written fixture."""
    path = REPO_ROOT / "Packs" / "Guardian" / "Lists" / "list-{}.json".format(list_name)
    return json.loads(json.loads(path.read_text())["data"])


def _shipped_script_comment(script_name):
    """Extract a shipped script.yml's top-level `comment:` field (the text
    GuardianToolCatalogBuilder actually uses as a command's `description`)
    without a YAML dependency this file doesn't otherwise need -- every
    shipped Guardian script.yml uses the plain `comment: >-` folded-scalar
    form, indented exactly 2 spaces."""
    path = REPO_ROOT / "Packs" / "Guardian" / "Scripts" / script_name / "{}.yml".format(script_name)
    match = re.search(r"^comment: >-\n((?:  .*\n?)+)", path.read_text(), re.M)
    assert match, "{}.yml comment field not in the expected folded-scalar form".format(script_name)
    return " ".join(line[2:].rstrip("\n") for line in match.group(1).splitlines())


def _install_default_lists(monkeypatch, allowlist=None, denylist=None, settings=None, profile=None, extra_lists=None):
    data_by_name = {
        "guardian_tool_allowlist": allowlist if allowlist is not None else DEFAULT_ALLOWLIST,
        "guardian_tool_allowlist_runtime": allowlist if allowlist is not None else DEFAULT_ALLOWLIST,
        "guardian_tool_denylist": denylist if denylist is not None else DEFAULT_DENYLIST,
        "guardian_settings": settings if settings is not None else DEFAULT_SETTINGS,
    }
    if profile is not None:
        data_by_name["guardian_model_profile"] = profile
    data_by_name.update(extra_lists or {})
    monkeypatch.setattr(tcb.demisto, "executeCommand", _lists_stub(data_by_name))


IP_COMMAND = _command(
    "ip",
    description="Checks the reputation of an IP address.",
    arguments=[
        {
            "name": "ip",
            "required": True,
            "description": "IP address(es) to check.",
            "isArray": True,
        },
        {
            "name": "threshold",
            "required": False,
            "description": "Score threshold.",
        },
        {
            "name": "verbose",
            "required": False,
            "description": "Verbose output.",
            "auto": "PREDEFINED",
            "predefined": ["true", "false"],
        },
    ],
)

WHOIS_COMMAND = _command("whois", description="Domain whois lookup.", arguments=[{"name": "query", "required": True}])

DELETE_COMMAND = _command("demisto-api-delete", description="Deletes data via the Core REST API.")


# --- guardian_collect_commands_by_name ----------------------------------------


def test_collect_commands_by_name_flattens_brands():
    by_name = tcb.guardian_collect_commands_by_name({"BrandA": [IP_COMMAND], "BrandB": [WHOIS_COMMAND]})
    assert set(by_name.keys()) == {"ip", "whois"}
    assert by_name["ip"]["name"] == "ip"


def test_collect_commands_by_name_first_seen_wins_across_brands():
    dup_a = _command("ip", description="From brand A")
    dup_b = _command("ip", description="From brand B")
    by_name = tcb.guardian_collect_commands_by_name({"ZBrand": [dup_b], "ABrand": [dup_a]})
    # sorted-brand order: "ABrand" < "ZBrand", so ABrand's definition wins
    assert by_name["ip"]["description"] == "From brand A"


def test_collect_commands_by_name_skips_malformed_entries():
    by_name = tcb.guardian_collect_commands_by_name({"Brand": [None, {"no_name": True}, IP_COMMAND]})
    assert list(by_name.keys()) == ["ip"]


# --- guardian_split_denylist_entries ------------------------------------------


def test_split_denylist_entries_separates_bare_and_rules():
    bare, rules = tcb.guardian_split_denylist_entries(
        ["demisto-api-delete", "setList:guardian_policy", "addToList:guardian_tool_denylist"]
    )
    assert bare == {"demisto-api-delete"}
    assert set(rules) == {"setList:guardian_policy", "addToList:guardian_tool_denylist"}


def test_split_denylist_entries_ignores_non_strings():
    bare, rules = tcb.guardian_split_denylist_entries(["ok", None, 5, ""])
    assert bare == {"ok"}
    assert rules == []


# --- guardian_arg_to_property -------------------------------------------------


def test_arg_to_property_required_string_with_description():
    prop = tcb.guardian_arg_to_property({"name": "query", "required": True, "description": "The query."})
    assert prop == {"type": "string", "description": "The query."}


def test_arg_to_property_array_maps_to_array_of_strings():
    prop = tcb.guardian_arg_to_property({"name": "ip", "isArray": True, "description": "IPs."})
    assert prop["type"] == "array"
    assert prop["items"] == {"type": "string"}


def test_arg_to_property_predefined_maps_to_enum():
    prop = tcb.guardian_arg_to_property(
        {"name": "verbose", "auto": "PREDEFINED", "predefined": ["true", "false"], "description": "d"}
    )
    assert prop["enum"] == ["true", "false"]
    assert prop["type"] == "string"


def test_arg_to_property_array_plus_predefined_puts_enum_on_items():
    """If an argument is both an array and predefined-valued (allowed
    values per element, not one fixed array value), the enum belongs under
    items, not the array property itself."""
    prop = tcb.guardian_arg_to_property({"name": "sort_by", "isArray": True, "predefined": ["asc", "desc"]})
    assert prop["type"] == "array"
    assert prop["items"] == {"type": "string", "enum": ["asc", "desc"]}
    assert "enum" not in prop


def test_arg_to_property_no_description_omits_key():
    prop = tcb.guardian_arg_to_property({"name": "x"})
    assert "description" not in prop


# --- guardian_command_to_tool_schema ------------------------------------------


def test_command_to_tool_schema_required_array_and_predefined():
    schema = tcb.guardian_command_to_tool_schema(IP_COMMAND)

    assert schema["type"] == "function"
    fn = schema["function"]
    assert fn["name"] == "ip"
    assert fn["description"] == "Checks the reputation of an IP address."

    params = fn["parameters"]
    assert params["type"] == "object"
    assert params["additionalProperties"] is False
    assert params["required"] == ["ip"]

    assert params["properties"]["ip"] == {
        "type": "array",
        "items": {"type": "string"},
        "description": "IP address(es) to check.",
    }
    assert params["properties"]["threshold"] == {"type": "string", "description": "Score threshold."}
    assert params["properties"]["verbose"]["enum"] == ["true", "false"]


def test_command_to_tool_schema_truncates_long_description():
    long_desc = "OPENING CONTRACT: " + ("x" * 500) + " CLOSING PURPOSE: use for focused sub-investigations."
    schema = tcb.guardian_command_to_tool_schema(_command("longcmd", description=long_desc))
    description = schema["function"]["description"]
    assert len(description) <= tcb.GUARDIAN_TOOL_DESCRIPTION_MAX_LEN
    assert description.startswith("OPENING CONTRACT:")
    assert description.endswith("focused sub-investigations.")
    assert tcb.GUARDIAN_TOOL_DESCRIPTION_ELLIPSIS in description


def test_command_to_tool_schema_falls_back_when_description_blank():
    schema = tcb.guardian_command_to_tool_schema(_command("getList", description=""))
    assert schema["function"]["description"] == "Execute the XSOAR command 'getList'."


def test_command_to_tool_schema_skips_malformed_arguments():
    cmd = _command("cmd", arguments=[None, {"no_name": True}, {"name": "ok"}])
    schema = tcb.guardian_command_to_tool_schema(cmd)
    assert list(schema["function"]["parameters"]["properties"].keys()) == ["ok"]


# --- guardian_load_curation_list ----------------------------------------------


def test_load_curation_list_parses_json_string_contents(monkeypatch):
    monkeypatch.setattr(
        tcb.demisto,
        "executeCommand",
        _lists_stub({"guardian_tool_allowlist": DEFAULT_ALLOWLIST}),
    )
    result = tcb.guardian_load_curation_list("guardian_tool_allowlist")
    assert result["ok"] is True
    assert result["data"] == DEFAULT_ALLOWLIST


def test_load_curation_list_reports_needs_context_on_invalid_json(monkeypatch):
    monkeypatch.setattr(
        tcb.demisto,
        "executeCommand",
        _lists_stub({}, bad_json={"guardian_tool_allowlist"}),
    )
    result = tcb.guardian_load_curation_list("guardian_tool_allowlist")
    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_load_curation_list_propagates_getlist_failure(monkeypatch):
    monkeypatch.setattr(
        tcb.demisto,
        "executeCommand",
        _lists_stub({}, missing={"guardian_tool_allowlist"}),
    )
    result = tcb.guardian_load_curation_list("guardian_tool_allowlist")
    assert result["ok"] is False
    assert "allowlist" in result["error"]


# --- guardian_build_tool_catalog: curation (allowlist \ denylist) ------------


def test_build_tool_catalog_curates_allowlist_minus_denylist(monkeypatch):
    monkeypatch.setattr(
        tcb.demisto,
        "getAllSupportedCommands",
        _all_supported_stub({"BrandA": [IP_COMMAND, WHOIS_COMMAND, DELETE_COMMAND]}),
    )
    _install_default_lists(monkeypatch)

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is True
    data = result["data"]
    names = {fn["function"]["name"] for fn in data["catalog"]}
    assert names == {"ip", "whois"}
    assert data["count"] == 2


def test_build_tool_catalog_excludes_bare_denylisted_command_even_if_allowlisted(monkeypatch):
    """demisto-api-delete is on this fixture's allowlist AND on the
    denylist's bare 'denied' entries -- deny must win (defense-in-depth
    enforcement inside the catalogue builder itself)."""
    monkeypatch.setattr(
        tcb.demisto,
        "getAllSupportedCommands",
        _all_supported_stub({"CoreRestApi": [DELETE_COMMAND, IP_COMMAND]}),
    )
    _install_default_lists(monkeypatch)

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is True
    data = result["data"]
    names = {fn["function"]["name"] for fn in data["catalog"]}
    assert "demisto-api-delete" not in names
    assert data["excluded_by_denylist"] == ["demisto-api-delete"]


def test_build_tool_catalog_notes_colon_rules_without_excluding_bare_command(monkeypatch):
    """A command:targetList denylist rule (e.g. setList:guardian_policy)
    must NOT bare-exclude 'setList' entirely from the catalogue -- that
    argument-level rule is the executeCommand bridge's job. Confirm it's
    surfaced as informational only."""
    set_list_command = _command("setList", description="Sets a list.")
    monkeypatch.setattr(
        tcb.demisto,
        "getAllSupportedCommands",
        _all_supported_stub({"Core": [set_list_command]}),
    )
    _install_default_lists(
        monkeypatch,
        allowlist={"_comment": "x", "commands": ["setList"]},
        denylist=DEFAULT_DENYLIST,  # denied only has "setList:guardian_policy", no bare "setList"
    )

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is True
    data = result["data"]
    names = {fn["function"]["name"] for fn in data["catalog"]}
    assert "setList" in names  # not bare-excluded
    assert "setList:guardian_policy" in data["denylist_arg_rules"]


def test_build_tool_catalog_reports_missing_on_box(monkeypatch):
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"BrandA": [IP_COMMAND]}))
    _install_default_lists(
        monkeypatch,
        allowlist={"_comment": "x", "commands": ["ip", "whois"]},  # whois not present on this box
    )

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is True
    assert result["data"]["missing_on_box"] == ["whois"]


def test_build_tool_catalog_uses_runtime_allowlist_after_initialization(monkeypatch):
    monkeypatch.setattr(
        tcb.demisto,
        "getAllSupportedCommands",
        _all_supported_stub({"IPInfo": [IP_COMMAND], "Whois": [WHOIS_COMMAND]}),
    )
    data_by_name = {
        "guardian_tool_allowlist": {"commands": ["ip"]},
        "guardian_tool_allowlist_runtime": {"commands": ["whois"]},
        "guardian_tool_denylist": DEFAULT_DENYLIST,
        "guardian_settings": DEFAULT_SETTINGS,
    }
    monkeypatch.setattr(tcb.demisto, "executeCommand", _lists_stub(data_by_name))

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is True
    assert result["data"]["allowlist_source"] == "runtime"
    assert [tool["function"]["name"] for tool in result["data"]["catalog"]] == ["whois"]


def test_build_tool_catalog_never_exposes_selected_operator_command(monkeypatch):
    command = _command("guardian-approve", description="Approve a pending Guardian action.")
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"Guardian": [command]}))
    _install_default_lists(monkeypatch, allowlist={"commands": ["guardian-approve"]})

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is True
    assert result["data"]["catalog"] == []
    assert result["data"]["excluded_by_operator_boundary"] == ["guardian-approve"]


def test_build_tool_catalog_needs_context_when_get_all_supported_commands_shape_is_wrong(monkeypatch):
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", lambda: ["not", "a", "dict"])

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_build_tool_catalog_needs_context_when_allowlist_shape_is_wrong(monkeypatch):
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({}))
    _install_default_lists(monkeypatch, allowlist={"_comment": "x", "no_commands_key": []})

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]
    assert "guardian_tool_allowlist" in result["error"]


def test_build_tool_catalog_bare_array_runtime_allowlist_is_accepted(monkeypatch):
    """Mirror-pair test: GuardianToolBridge_test.py's
    test_check_allowlist_bare_array_runtime_list_is_accepted_matching_baseline_contract
    exercises the SAME bare-array runtime-list content through
    guardian_bridge_check_allowlist(). Both must agree -- this was a live,
    confirmed divergence (Bridge accepted a bare array, this builder
    rejected it with ok=False, which would have silently halted the WHOLE
    tool catalogue every single agent tick, not just the runtime-allowlist
    feature) until guardian_validate_allowlist_payload was loosened to
    accept a bare array too, matching the pack-seeded baseline's own
    documented "a bare array is also accepted for robustness" contract."""
    monkeypatch.setattr(
        tcb.demisto,
        "getAllSupportedCommands",
        _all_supported_stub({"IPInfo": [IP_COMMAND], "Whois": [WHOIS_COMMAND]}),
    )
    data_by_name = {
        "guardian_tool_allowlist": DEFAULT_ALLOWLIST,
        "guardian_tool_allowlist_runtime": ["ip", "whois"],
        "guardian_tool_denylist": DEFAULT_DENYLIST,
        "guardian_settings": DEFAULT_SETTINGS,
    }
    monkeypatch.setattr(tcb.demisto, "executeCommand", _lists_stub(data_by_name))

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is True
    assert result["data"]["allowlist_source"] == "runtime"
    assert sorted(tool["function"]["name"] for tool in result["data"]["catalog"]) == ["ip", "whois"]


def test_build_tool_catalog_needs_context_when_denylist_shape_is_wrong(monkeypatch):
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({}))
    _install_default_lists(monkeypatch, denylist={"_comment": "x", "no_denied_key": []})

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]
    assert "guardian_tool_denylist" in result["error"]


# --- guardian_build_tool_catalog: size check ----------------------------------


def test_build_tool_catalog_size_check_no_warning_within_ceiling(monkeypatch):
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"BrandA": [IP_COMMAND]}))
    _install_default_lists(
        monkeypatch,
        allowlist={"_comment": "x", "commands": ["ip"]},
        settings={"max_tool_def_tokens": 250000},
    )

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is True
    assert result["data"]["warning"] is None
    assert result["data"]["max_tool_def_tokens"] == 250000


def test_build_tool_catalog_size_check_truncates_to_priority_prefix_when_over_ceiling(monkeypatch):
    errors = []
    monkeypatch.setattr(tcb.demisto, "error", lambda *a: errors.append(" ".join(str(x) for x in a)))
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"BrandA": [IP_COMMAND, WHOIS_COMMAND]}))
    _install_default_lists(
        monkeypatch,
        allowlist={"_comment": "x", "commands": ["ip", "whois"]},  # priority order: ip first, whois in the tail
        settings={"max_tool_def_tokens": 1},  # absurdly small ceiling -> keeps only the top-priority tool
    )

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is True
    data = result["data"]
    assert data["warning"] is not None and "TRUNCATED" in data["warning"]
    # ENFORCED truncation to the priority prefix: keeps at least the first tool (ip), drops the tail (whois)
    assert data["count"] == 1
    assert [fn["function"]["name"] for fn in data["catalog"]] == ["ip"]
    assert data["dropped_by_budget"] == ["whois"]
    assert errors and "TRUNCATED" in errors[0]


def test_build_tool_catalog_no_truncation_and_empty_dropped_within_ceiling(monkeypatch):
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"BrandA": [IP_COMMAND, WHOIS_COMMAND]}))
    _install_default_lists(
        monkeypatch,
        allowlist={"_comment": "x", "commands": ["ip", "whois"]},
        settings={"max_tool_def_tokens": 250000},  # generous -> both kept, nothing dropped
    )

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is True
    data = result["data"]
    assert data["warning"] is None
    assert data["count"] == 2
    assert data["dropped_by_budget"] == []


def test_build_tool_catalog_size_check_uses_tier_default_when_settings_null(monkeypatch):
    # A null (not merely absent) max_tool_def_tokens falls back to the
    # RESOLVED TIER's own default, not a fixed constant -- model_tier is also
    # absent here, so guardian_resolve_tier fails safe to "small" (4000).
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"BrandA": [IP_COMMAND]}))
    _install_default_lists(
        monkeypatch,
        allowlist={"_comment": "x", "commands": ["ip"]},
        settings={"max_tool_def_tokens": None},
    )

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is True
    assert result["data"]["max_tool_def_tokens"] == tcb.GUARDIAN_TIER_PROFILES["small"]["max_tool_def_tokens"]
    assert result["data"]["model_tier"] == "small"


def test_build_tool_catalog_size_check_uses_large_tier_default(monkeypatch):
    # The reverse of the above: an explicit model_tier (with no
    # max_tool_def_tokens override) must widen the budget to that tier's own
    # default, not stay pinned at the small-tier value.
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"BrandA": [IP_COMMAND]}))
    _install_default_lists(
        monkeypatch,
        allowlist={"_comment": "x", "commands": ["ip"]},
        settings={"max_tool_def_tokens": None, "model_tier": "large"},
    )

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is True
    assert result["data"]["max_tool_def_tokens"] == tcb.GUARDIAN_TIER_PROFILES["large"]["max_tool_def_tokens"]
    assert result["data"]["model_tier"] == "large"


def test_build_tool_catalog_explicit_max_tool_def_tokens_overrides_tier_default(monkeypatch):
    # An operator's own explicit setting must still win over the tier
    # default in EITHER direction (both narrower and wider than the tier).
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"BrandA": [IP_COMMAND]}))
    _install_default_lists(
        monkeypatch,
        allowlist={"_comment": "x", "commands": ["ip"]},
        settings={"max_tool_def_tokens": 9999, "model_tier": "large"},
    )

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is True
    assert result["data"]["max_tool_def_tokens"] == 9999


def test_shipped_guardiansubagentdispatch_description_survives_every_tier_budget():
    """LIVE-CAUGHT: GuardianSubagentDispatch's shipped description was 986
    chars -- past even the large tier's 1024-char cap on paper, and
    guardian_shorten_tool_description's middle elision cut the "Use this
    when a focused, self-contained sub-task ..." purpose clause entirely at
    the small tier's 300-char default (the ONLY tier every fix in this pack
    has been validated against). A model offered this tool never saw the
    one sentence telling it when to actually use it. Pin that the shipped
    description now comfortably fits under even the smallest tier budget,
    so it survives guardian_shorten_tool_description unmodified at every
    tier -- and that the boundary-setting "NOT for containment/case
    mutation" clause is intact either way."""
    comment = _shipped_script_comment("GuardianSubagentDispatch")
    small_budget = tcb.GUARDIAN_TIER_PROFILES["small"]["description_max_len"]
    assert len(comment) <= small_budget
    for tier in ("small", "medium", "large"):
        max_len = tcb.GUARDIAN_TIER_PROFILES[tier]["description_max_len"]
        shortened = tcb.guardian_shorten_tool_description(comment, max_len=max_len)
        assert shortened == comment  # never actually truncated at any shipped tier
        assert "containment" in shortened and "case mutation" in shortened


def test_shipped_allowlist_and_4000_token_budget_are_exercised_together(monkeypatch):
    """Guard against a fixture-only catalogue test missing shipped curation.

    The test deliberately loads the pack's actual allowlist and settings
    List. Verbose synthetic command descriptions make the real 4,000-token
    setting exercise the same priority-tail truncation path it uses on a live
    tenant, while remaining independent of whatever integrations happen to
    be installed on a developer machine.
    """
    allowlist = _shipped_list_payload("guardian_tool_allowlist")
    denylist = _shipped_list_payload("guardian_tool_denylist")
    settings = _shipped_list_payload("guardian_settings")
    # The 4,000 budget comes from the "small" tier a model with no catalogue entry gets while the shipped
    # model_tier is "auto"; it is not an explicit settings value.
    assert "max_tool_def_tokens" not in settings and settings["model_tier"] == "auto"

    errors = []
    monkeypatch.setattr(tcb.demisto, "error", lambda *a: errors.append(" ".join(str(x) for x in a)))
    commands = [
        _command(name, description=("{} documentation. ".format(name) * 100))
        for name in allowlist["commands"]
    ]
    monkeypatch.setattr(
        tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"Shipped": commands}), raising=False
    )
    _install_default_lists(monkeypatch, allowlist=allowlist, denylist=denylist, settings=settings)

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is True
    data = result["data"]
    assert data["max_tool_def_tokens"] == 4000
    assert data["warning"] is not None and "TRUNCATED" in data["warning"]
    assert data["dropped_by_budget"]
    assert data["count"] < len(allowlist["commands"])
    assert data["catalog"][0]["function"]["name"] == allowlist["commands"][0]
    assert errors and "TRUNCATED" in errors[0]


def test_build_tool_catalog_size_check_tolerates_unreadable_settings_list(monkeypatch):
    """A missing/unreadable guardian_settings List must not block catalogue
    synthesis -- guardian_resolve_tier's own fail-safe (an unreadable
    settings dict is treated the same as an absent model_tier key) means the
    size ceiling falls back to the "small" tier's default, the same safe
    direction as every other tier-gated knob, not a large permissive one."""
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"BrandA": [IP_COMMAND]}))
    data_by_name = {
        "guardian_tool_allowlist": {"_comment": "x", "commands": ["ip"]},
        "guardian_tool_allowlist_runtime": {"_comment": "x", "commands": ["ip"]},
        "guardian_tool_denylist": DEFAULT_DENYLIST,
    }
    monkeypatch.setattr(
        tcb.demisto, "executeCommand", _lists_stub(data_by_name, missing={"guardian_settings"})
    )

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is True
    assert result["data"]["max_tool_def_tokens"] == tcb.GUARDIAN_TIER_PROFILES["small"]["max_tool_def_tokens"]
    assert result["data"]["model_tier"] == "small"


# --- main() ---------------------------------------------------------------


def test_main_writes_catalog_and_meta_as_sibling_context_keys(monkeypatch):
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"BrandA": [IP_COMMAND]}))
    _install_default_lists(monkeypatch, allowlist={"_comment": "x", "commands": ["ip"]})

    written = {}
    monkeypatch.setattr(tcb.demisto, "setContext", lambda path, value: written.update({path: value}))

    captured = {}
    monkeypatch.setattr(
        tcb, "return_results", lambda cr: captured.setdefault("result", cr), raising=False
    )

    tcb.main()

    assert "Guardian.ToolCatalog" in written
    assert isinstance(written["Guardian.ToolCatalog"], list)
    assert written["Guardian.ToolCatalog"][0]["function"]["name"] == "ip"

    assert "Guardian.ToolCatalogMeta" in written
    meta = written["Guardian.ToolCatalogMeta"]
    assert meta["Count"] == 1
    assert isinstance(meta["TokenEstimate"], int)


def test_main_calls_return_error_on_failure(monkeypatch):
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", lambda: "not a dict")

    errors = []
    monkeypatch.setattr(tcb, "return_error", lambda msg: errors.append(msg), raising=False)

    tcb.main()

    assert len(errors) == 1
    assert "NEEDS_CONTEXT" in errors[0]


def test_shipped_settings_leave_the_catalogue_budget_to_the_model_tier():
    """An explicit guardian_settings.max_tool_def_tokens beats every tier. The pack once shipped
    4000 (the small budget), so model_tier=medium/large never widened the catalogue. The shipped
    List must leave it unset; operators may still set it to hand-tune one box."""
    import pathlib
    lists = pathlib.Path(__file__).resolve().parents[2] / "Lists"
    data = json.loads(json.loads((lists / "list-guardian_settings.json").read_text())["data"])
    assert "max_tool_def_tokens" not in data



def test_medium_tier_actually_widens_the_shipped_catalogue(monkeypatch):
    """The adaptation the tier exists for: the SAME shipped Lists with model_tier=medium get the
    medium budget (16000) and keep more tools than small. Before the shipped explicit 4000 was
    removed, this silently stayed at the small catalogue."""
    allowlist = _shipped_list_payload("guardian_tool_allowlist")
    denylist = _shipped_list_payload("guardian_tool_denylist")
    commands = [_command(name, description=("{} documentation. ".format(name) * 100)) for name in allowlist["commands"]]
    monkeypatch.setattr(tcb.demisto, "error", lambda *a: None)
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"Shipped": commands}), raising=False)

    counts = {}
    for tier in ("small", "medium"):
        settings = dict(_shipped_list_payload("guardian_settings"), model_tier=tier)
        _install_default_lists(monkeypatch, allowlist=allowlist, denylist=denylist, settings=settings)
        data = tcb.guardian_build_tool_catalog()["data"]
        counts[tier] = (data["max_tool_def_tokens"], data["count"])
    assert counts["small"][0] == 4000 and counts["medium"][0] == 16000
    assert counts["medium"][1] > counts["small"][1]


def _many_tools(monkeypatch, settings, profile=None):
    allowlist = _shipped_list_payload("guardian_tool_allowlist")
    denylist = _shipped_list_payload("guardian_tool_denylist")
    commands = [_command(name, description=("{} documentation. ".format(name) * 100)) for name in allowlist["commands"]]
    monkeypatch.setattr(tcb.demisto, "error", lambda *a: None)
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"Shipped": commands}), raising=False)
    _install_default_lists(monkeypatch, allowlist=allowlist, denylist=denylist, settings=settings, profile=profile)


def test_a_small_measured_window_caps_the_tier_budget(monkeypatch):
    """A medium-tier model served with a small context must not be offered 16000 tokens of tool schema."""
    settings = dict(_shipped_list_payload("guardian_settings"), model_tier="medium")
    profile = {"active": "p:i", "profiles": {"p:i": {"max_input_tokens": 8000}}}
    _many_tools(monkeypatch, settings, profile)
    data = tcb.guardian_build_tool_catalog()["data"]
    assert data["max_tool_def_tokens"] == 4800
    assert data["max_tool_def_tokens_source"] == "tier, capped to 60% of max_input_tokens"
    assert data["token_estimate"] <= 4800


def test_an_operator_override_in_the_profile_list_sets_the_budget_without_a_cap(monkeypatch):
    settings = dict(_shipped_list_payload("guardian_settings"), model_tier="small")
    profile = {"active": "p:i", "profiles": {"p:i": {"max_input_tokens": 8000}}, "overrides": {"max_tool_def_tokens": 7000}}
    _many_tools(monkeypatch, settings, profile)
    data = tcb.guardian_build_tool_catalog()["data"]
    assert (data["max_tool_def_tokens"], data["max_tool_def_tokens_source"]) == (7000, "override")


def test_a_missing_profile_list_changes_nothing(monkeypatch):
    settings = dict(_shipped_list_payload("guardian_settings"), model_tier="small")
    _many_tools(monkeypatch, settings)
    data = tcb.guardian_build_tool_catalog()["data"]
    assert (data["max_tool_def_tokens"], data["max_tool_def_tokens_source"]) == (4000, "tier")


def test_the_playbook_snapshot_is_used_when_asked_and_ignored_otherwise(monkeypatch):
    settings = dict(_shipped_list_payload("guardian_settings"), model_tier="small")
    _many_tools(monkeypatch, settings)
    snap = {"tier": "large", "tier_source": "override", "max_input_tokens": None, "max_input_tokens_source": "none",
            "max_tool_def_tokens": 24000, "max_tool_def_tokens_source": "tier", "profile": None,
            "max_ticks": 60, "max_ticks_source": "tier", "limits": tcb.guardian_derive_limits(None)}
    monkeypatch.setattr(tcb, "guardian_ctx_read", lambda key, default=None: snap)
    assert tcb.guardian_build_tool_catalog(use_snapshot=True)["data"]["max_tool_def_tokens"] == 24000
    assert tcb.guardian_build_tool_catalog(use_snapshot=False)["data"]["max_tool_def_tokens"] == 4000


def _layout_button_script_names():
    """Every GuardianButton* automation shipped in this pack (the incident-layout action buttons)."""
    return sorted(path.name for path in Path(__file__).resolve().parents[1].glob("GuardianButton*") if path.is_dir())


def test_every_layout_button_script_is_operator_only_in_code():
    names = _layout_button_script_names()
    assert names, "no GuardianButton* scripts found"
    for name in names:
        assert name in tcb.GUARDIAN_OPERATOR_ONLY_COMMANDS, name


def test_build_tool_catalog_never_exposes_a_selected_layout_button(monkeypatch):
    names = _layout_button_script_names()
    commands = [_command(name, description="A layout button.") for name in names]
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"Guardian": commands}))
    _install_default_lists(monkeypatch, allowlist={"commands": names})

    result = tcb.guardian_build_tool_catalog()

    assert result["ok"] is True
    assert result["data"]["catalog"] == []
    assert sorted(result["data"]["excluded_by_operator_boundary"]) == names


def test_a_localisation_key_description_is_replaced_by_a_plain_sentence():
    schema = tcb.guardian_command_to_tool_schema({"name": "getIncidents", "description": "commands.local.cmd.get.incs", "arguments": []})
    assert "pass its id as `id`" in schema["function"]["description"]
    other = tcb.guardian_command_to_tool_schema({"name": "someOther", "description": "commands.local.cmd.x", "arguments": []})
    assert other["function"]["description"].startswith("Execute the ")


# --- model size follows the catalogue; a large model reads every tool description in full ------------------------


def _shipped_catalog_payload():
    return json.loads(json.loads((Path(__file__).resolve().parents[2] / "Lists" / "list-guardian_model_catalog.json").read_text())["data"])


def test_a_zero_description_cap_means_no_shortening():
    long_description = "Opening clause. " + "middle " * 400 + "Closing clause."
    command = _command("ip", description=long_description)
    assert tcb.guardian_shorten_tool_description(long_description, 0) == long_description
    assert tcb.guardian_tool_description_is_truncated(command, 0) is False
    assert tcb.guardian_command_to_tool_schema(command, 0)["function"]["description"].strip() == long_description.strip()
    assert tcb.guardian_tool_description_is_truncated(command, 300) is True   # a cap still cuts
    assert len(tcb.guardian_shorten_tool_description(long_description, 300)) <= 300


def test_a_catalogued_large_model_gets_the_large_budget_and_full_descriptions(monkeypatch):
    allowlist = _shipped_list_payload("guardian_tool_allowlist")
    denylist = _shipped_list_payload("guardian_tool_denylist")
    # descriptions as long as the longest real ones (under 1024 characters): a large model reads them in full
    commands = [_command(name, description=("{} documentation. ".format(name) * 40)[:1000]) for name in allowlist["commands"]]
    monkeypatch.setattr(tcb.demisto, "error", lambda *a: None)
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"Shipped": commands}), raising=False)
    record = {"model": "gpt-5-mini", "catalog_id": "gpt-5-mini", "max_input_tokens": 173400}
    # an old explicit "small" in guardian_settings no longer applies to a model the catalogue knows
    settings = dict(_shipped_list_payload("guardian_settings"), model_tier="small")
    _install_default_lists(monkeypatch, allowlist=allowlist, denylist=denylist, settings=settings,
                           profile={"active": "p:i", "profiles": {"p:i": record}},
                           extra_lists={"guardian_model_catalog": _shipped_catalog_payload()})
    data = tcb.guardian_build_tool_catalog()["data"]
    assert data["model_tier"] == "large"
    assert (data["max_tool_def_tokens"], data["max_tool_def_tokens_source"]) == (43350, "tier (25% of the input budget)")
    assert data["description_truncated"] == [] and data["dropped_by_budget"] == []
    assert data["count"] == len(allowlist["commands"])   # every allowlisted tool is offered, none dropped for budget
    assert max(len(entry["function"]["description"]) for entry in data["catalog"]) >= 990   # not shortened to a few hundred
    # the 1024-character limit is a provider-safety limit, still applied to an over-long description
    long_command = _command("ip", description="Opening clause. " + "middle " * 400 + "Closing clause.")
    shortened = tcb.guardian_command_to_tool_schema(long_command, tcb.GUARDIAN_TIER_PROFILES["large"]["description_max_len"])
    assert len(shortened["function"]["description"]) <= 1024 and "Closing clause." in shortened["function"]["description"]
    assert tcb.GUARDIAN_TIER_PROFILES["large"]["description_max_len"] == 1024


def test_the_ticks_model_params_are_used_as_they_are(monkeypatch):
    allowlist = _shipped_list_payload("guardian_tool_allowlist")
    commands = [_command(name, description="short") for name in allowlist["commands"]]
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"Shipped": commands}), raising=False)
    _install_default_lists(monkeypatch, allowlist=allowlist, settings=dict(_shipped_list_payload("guardian_settings"), model_tier="small"))
    params = tcb.guardian_resolve_model_params({"model_tier": "medium", "max_input_tokens": 100000}, {})
    data = tcb.guardian_build_tool_catalog(model_params=params)["data"]
    assert data["model_tier"] == "medium" and data["max_tool_def_tokens"] == 16000 and data["model_params"] == params
    # a malformed argument is ignored: the builder resolves the numbers itself
    data = tcb.guardian_build_tool_catalog(model_params={"tier": "large"})["data"]
    assert data["model_tier"] == "small" and data["max_tool_def_tokens"] == 4000
    assert tcb.guardian_catalog_builder_parse_model_params(json.dumps(params)) == params
    assert tcb.guardian_catalog_builder_parse_model_params("{not json") is None
    assert tcb.guardian_catalog_builder_parse_model_params("[1]") is None


def test_the_report_names_the_size_with_its_source_and_the_derived_limits(monkeypatch):
    allowlist = _shipped_list_payload("guardian_tool_allowlist")
    commands = [_command(name, description="short") for name in allowlist["commands"]]
    monkeypatch.setattr(tcb.demisto, "getAllSupportedCommands", _all_supported_stub({"Shipped": commands}), raising=False)
    _install_default_lists(monkeypatch, allowlist=allowlist, settings=dict(_shipped_list_payload("guardian_settings")))
    params = tcb.guardian_resolve_model_params({"max_input_tokens": 28258}, {}, {"model_id": "gpt-5-mini", "size_class": "large", "params_b": None})
    shown = []
    monkeypatch.setattr(tcb, "return_results", lambda r: shown.append(r.readable_output))
    monkeypatch.setattr(tcb, "guardian_ctx_write", lambda *a, **k: None)
    monkeypatch.setattr(tcb.demisto, "args", lambda: {"model_params": json.dumps(params)})
    tcb.main()
    text = shown[0]
    assert "Model profile: size large (catalogue (gpt-5-mini)); input budget 28,258;" in text
    assert "tool result limit 22,606 bytes" in text and "incident details 5,651 characters" in text
    assert "history compacted by tokens at 28,258" in text
