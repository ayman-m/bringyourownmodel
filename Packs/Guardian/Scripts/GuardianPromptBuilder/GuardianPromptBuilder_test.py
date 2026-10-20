import json
import pathlib

import GuardianPromptBuilder as gpb


# --- test fixtures ------------------------------------------------------------


def _entries_for_list(lists_map, list_name):
    """Fake `getList` response for `list_name`, keyed off `lists_map`
    ({list_name: <already-JSON-encodable python value, or a raw string>}).
    Anything not present in `lists_map` comes back "Item not found", mirroring
    real getList behavior for a List that doesn't exist on the box yet.
    """
    if list_name in lists_map:
        payload = lists_map[list_name]
        if payload is None:
            contents = ""
        elif isinstance(payload, str):
            contents = payload
        else:
            contents = json.dumps(payload)
        return [{"Type": 1, "Contents": contents}]
    return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(list_name)}]


def _install_lists(monkeypatch, lists_map, incident=None):
    """Wire demisto.executeCommand('getList', ...) to `lists_map`, plus
    demisto.incident()/context()/setContext(). Returns the dict setContext
    calls get captured into.
    """

    def fake_execute(command, args):
        assert command == "getList"
        return _entries_for_list(lists_map, args["listName"])

    written = {}

    def fake_set_context(path, value):
        written[path] = value
        return {"status": True}

    monkeypatch.setattr(gpb.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(gpb.demisto, "incident", lambda: incident or {})
    monkeypatch.setattr(gpb.demisto, "context", lambda: {})
    monkeypatch.setattr(gpb.demisto, "setContext", fake_set_context)
    return written


HEAD_TEXT = "HEAD-MARKER-START :: You are the Guardian Agent. :: HEAD-MARKER-END"
TAIL_TEXT = (
    "TAIL-MARKER-START :: <untrusted-case-data> wrap note lives here. "
    "8-step XSOAR investigation workflow. :: TAIL-MARKER-END"
)
POLICY_DATA = {
    "_comment": "ignore me -- not a command",
    "_note_selfescape": "ignore me too",
    "closeInvestigation": "require_approval",
    "setIncident": "require_approval",
    "createNewIncident": "require_approval",
    "some-denied-cmd": "deny",
    "ip": "allow",
    "weird-tier-value": "not-a-real-tier",
}


def _base_lists_map(**overrides):
    lists_map = {
        gpb.GUARDIAN_PROMPT_HEAD_LIST_NAME: {"head": HEAD_TEXT},
        gpb.GUARDIAN_PROMPT_TAIL_LIST_NAME: {"tail": TAIL_TEXT},
        gpb.GUARDIAN_PROMPT_POLICY_LIST_NAME: POLICY_DATA,
    }
    lists_map.update(overrides)
    return lists_map


# --- guardian_prompt_load_list_data -------------------------------------------


def test_load_list_data_parses_json_object(monkeypatch):
    _install_lists(monkeypatch, {"some_list": {"a": 1}})

    result = gpb.guardian_prompt_load_list_data("some_list")

    assert result["ok"] is True
    assert result["data"] == {"a": 1}


def test_load_list_data_missing_list_is_soft_absent_not_error(monkeypatch):
    _install_lists(monkeypatch, {})

    result = gpb.guardian_prompt_load_list_data("guardian_skills_index")

    assert result["ok"] is True
    assert result["data"] is None


def test_load_list_data_other_getlist_failure_is_hard_error(monkeypatch):
    def fake_execute(command, args):
        return [{"Type": 4, "Contents": "Error 503: Service Unavailable"}]

    monkeypatch.setattr(gpb.demisto, "executeCommand", fake_execute)

    result = gpb.guardian_prompt_load_list_data("guardian_policy")

    assert result["ok"] is False
    assert "503" in result["error"]


def test_load_list_data_malformed_json_is_error(monkeypatch):
    _install_lists(monkeypatch, {"broken_list": "{not json"})

    result = gpb.guardian_prompt_load_list_data("broken_list")

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_load_list_data_empty_string_contents_is_soft_absent(monkeypatch):
    _install_lists(monkeypatch, {"empty_list": ""})

    result = gpb.guardian_prompt_load_list_data("empty_list")

    assert result["ok"] is True
    assert result["data"] is None


# --- guardian_prompt_render_head / render_tail --------------------------------


def test_render_head_extracts_text():
    text, error = gpb.guardian_prompt_render_head({"head": "hello"})
    assert text == "hello"
    assert error is None


def test_render_head_missing_key_is_error():
    text, error = gpb.guardian_prompt_render_head({"nope": "hello"})
    assert text is None
    assert "guardian_prompt_head" in error


def test_render_head_wrong_shape_is_error():
    text, error = gpb.guardian_prompt_render_head(["not", "a", "dict"])
    assert text is None
    assert "unexpected shape" in error


def test_render_tail_extracts_text():
    text, error = gpb.guardian_prompt_render_tail({"tail": "world"})
    assert text == "world"
    assert error is None


def test_render_tail_blank_string_is_error():
    text, error = gpb.guardian_prompt_render_tail({"tail": "   "})
    assert text is None
    assert "guardian_prompt_tail" in error


# --- guardian_prompt_group_policy_tiers / render_policy_block -----------------


def test_group_policy_tiers_skips_comment_keys_and_unknown_tiers():
    tiers = gpb.guardian_prompt_group_policy_tiers(POLICY_DATA)

    assert tiers["require_approval"] == ["closeInvestigation", "createNewIncident", "setIncident"]
    assert tiers["deny"] == ["some-denied-cmd"]
    assert tiers["allow"] == ["ip"]
    # "_comment"/"_note_selfescape" (leading underscore) and "weird-tier-value"
    # (unrecognized tier) must never show up anywhere.
    all_names = tiers["require_approval"] + tiers["deny"] + tiers["allow"]
    assert "_comment" not in all_names
    assert "weird-tier-value" not in all_names


def test_render_policy_block_lists_require_approval_and_deny_commands():
    block = gpb.guardian_prompt_render_policy_block(POLICY_DATA)

    assert "## ACTION POLICY" in block
    assert "`closeInvestigation`" in block
    assert "`setIncident`" in block
    assert "`createNewIncident`" in block
    assert "`some-denied-cmd`" in block
    assert "pending_approval" in block
    # allow-tiered commands are the default and are NOT enumerated
    assert "`ip`" not in block


def test_render_policy_block_empty_tiers_render_placeholder():
    block = gpb.guardian_prompt_render_policy_block({"ip": "allow"})

    assert "(none currently configured)" in block


def test_render_policy_fallback_block_fails_closed():
    block = gpb.guardian_prompt_render_policy_fallback_block("connection refused")

    assert "failing closed" in block
    assert "connection refused" in block
    assert "requires human approval" in block


# --- guardian_prompt_render_persona_block -------------------------------------


def test_render_persona_block_present():
    block = gpb.guardian_prompt_render_persona_block({"persona": "Be terse."})

    assert "## OPERATOR-DEFINED PERSONA" in block
    assert "Be terse." in block


def test_render_persona_block_absent_data_is_empty_string():
    assert gpb.guardian_prompt_render_persona_block(None) == ""


def test_render_persona_block_blank_persona_is_empty_string():
    assert gpb.guardian_prompt_render_persona_block({"persona": "   "}) == ""


def test_render_persona_block_wrong_shape_is_empty_string():
    assert gpb.guardian_prompt_render_persona_block(["not", "a", "dict"]) == ""


# --- guardian_prompt_render_skills_block --------------------------------------


def test_render_skills_block_none_is_empty_string():
    assert gpb.guardian_prompt_render_skills_block(None) == ""


def test_render_skills_block_empty_list_is_empty_string():
    assert gpb.guardian_prompt_render_skills_block([]) == ""


def test_render_skills_block_filters_disabled_and_renders_enabled():
    skills = [
        {"name": "triage-phishing", "displayName": "Triage Phishing", "category": "workflows",
         "description": "Full phishing triage.", "attack": ["T1566", "T1204"], "enabled": True},
        {"name": "old-skill", "displayName": "Old Skill", "category": "workflows",
         "description": "Deprecated.", "enabled": False},
        {"name": "no-enabled-key", "displayName": "Implicitly Enabled", "category": "reference",
         "description": "Absence of 'enabled' means enabled."},
    ]

    block = gpb.guardian_prompt_render_skills_block(skills)

    assert "## AVAILABLE SKILLS" in block
    assert "`triage-phishing`" in block
    assert "T1566" in block
    assert "`no-enabled-key`" in block  # absent 'enabled' key => treated as enabled
    assert "old-skill" not in block  # enabled: False => excluded


def test_render_skills_block_all_disabled_is_empty_string():
    skills = [{"name": "x", "displayName": "X", "category": "c", "description": "d", "enabled": False}]

    assert gpb.guardian_prompt_render_skills_block(skills) == ""


# --- guardian_prompt_get_approval_mode / render_approval_mode_block ----------


def test_get_approval_mode_defaults_to_manual_with_no_incident(monkeypatch):
    monkeypatch.setattr(gpb.demisto, "incident", lambda: {})

    assert gpb.guardian_prompt_get_approval_mode() == "manual"


def test_get_approval_mode_reads_bypass_from_incident_custom_fields(monkeypatch):
    monkeypatch.setattr(
        gpb.demisto, "incident", lambda: {"CustomFields": {"guardianapprovalmode": "bypass"}}
    )

    assert gpb.guardian_prompt_get_approval_mode() == "bypass"


def test_get_approval_mode_invalid_value_defaults_to_manual(monkeypatch):
    monkeypatch.setattr(
        gpb.demisto, "incident", lambda: {"CustomFields": {"guardianapprovalmode": "yolo"}}
    )

    assert gpb.guardian_prompt_get_approval_mode() == "manual"


def test_get_approval_mode_incident_raises_defaults_to_manual(monkeypatch):
    def raise_it():
        raise RuntimeError("no incident context")

    monkeypatch.setattr(gpb.demisto, "incident", raise_it)

    assert gpb.guardian_prompt_get_approval_mode() == "manual"


def test_render_approval_mode_block_manual_promises_no_execution():
    block = gpb.guardian_prompt_render_approval_mode_block("manual")

    assert "**manual**" in block
    assert "pending_approval" in block
    assert "does not execute" in block


def test_render_approval_mode_block_bypass_with_no_classes_describes_nothing_auto_executes():
    """Task 4.4 honesty property: with NO `guardian_preapproved` classes
    configured (or the List unreadable -- both render the same placeholder),
    bypass mode must still say plainly that nothing auto-executes -- it must
    NOT overclaim just because the mode itself is "bypass"."""
    block = gpb.guardian_prompt_render_approval_mode_block("bypass", None)

    assert "**bypass**" in block
    assert "pending_approval" in block
    assert "no pre-approved classes are currently configured" in block


def test_render_approval_mode_block_bypass_names_the_configured_preapproved_class():
    """Task 4.4: when a class IS configured, the bypass block must name it
    and its argument constraints (so the model can actually hit the
    auto-execute path), while STILL promising every other require_approval
    command (destructive/credential included) parks exactly as in manual
    mode -- bypass narrowly widens, it never blanket-waives."""
    classes = [
        {
            "command": "xdr-endpoint-tag-add",
            "arg_constraints": {
                "endpoint_ids": {"required": True},
                "tag": {"required": True, "allowed_values": ["guardian-auto-flagged"]},
            },
        }
    ]
    block = gpb.guardian_prompt_render_approval_mode_block("bypass", classes)

    assert "**bypass**" in block
    assert "pending_approval" in block
    assert "`xdr-endpoint-tag-add`" in block
    assert "guardian-auto-flagged" in block
    assert "still PARKS" in block
    assert "auto_approved" in block


# --- guardian_prompt_render_preapproved_classes -------------------------------


def test_render_preapproved_classes_empty_or_none_is_placeholder():
    placeholder = "no pre-approved classes are currently configured"
    assert placeholder in gpb.guardian_prompt_render_preapproved_classes(None)
    assert placeholder in gpb.guardian_prompt_render_preapproved_classes([])
    assert placeholder in gpb.guardian_prompt_render_preapproved_classes("not-a-list")


def test_render_preapproved_classes_renders_command_and_constraints():
    classes = [
        {
            "command": "xdr-endpoint-tag-add",
            "description": "Adds a review tag; it does not isolate or otherwise contain the endpoint.",
            "arg_constraints": {
                "endpoint_ids": {"required": True},
                "tag": {"required": True, "allowed_values": ["guardian-auto-flagged", "guardian-suspicious-endpoint"]},
            },
        }
    ]
    rendered = gpb.guardian_prompt_render_preapproved_classes(classes)

    assert "`xdr-endpoint-tag-add`" in rendered
    assert "guardian-auto-flagged" in rendered
    assert "guardian-suspicious-endpoint" in rendered
    assert "endpoint_ids" in rendered
    assert "does not isolate" in rendered


def test_render_preapproved_classes_excludes_shadowed_entries():
    """A shadowed class never actually auto-executes -- narrating it as
    something that "may auto-execute without a human step" would be wrong,
    not just imprecise, so it must not appear in this rendering at all."""
    classes = [
        {"command": "xdr-endpoint-tag-add", "arg_constraints": {"tag": {"required": True}}},
        {"command": "GuardianContainmentSimulate", "shadow": True, "arg_constraints": {}},
    ]
    rendered = gpb.guardian_prompt_render_preapproved_classes(classes)

    assert "`xdr-endpoint-tag-add`" in rendered
    assert "GuardianContainmentSimulate" not in rendered


def test_render_preapproved_classes_all_shadowed_falls_back_to_placeholder():
    classes = [{"command": "xdr-endpoint-tag-add", "shadow": True, "arg_constraints": {}}]
    rendered = gpb.guardian_prompt_render_preapproved_classes(classes)

    assert "no pre-approved classes are currently configured" in rendered


def test_render_preapproved_classes_skips_malformed_entries():
    classes = ["not-a-dict", {"no_command_key": True}, {"command": "xdr-endpoint-tag-add", "arg_constraints": {}}]
    rendered = gpb.guardian_prompt_render_preapproved_classes(classes)

    # The one well-formed-enough entry (has a command name) still renders,
    # with the "no constraints recorded" fallback since arg_constraints is
    # empty.
    assert "`xdr-endpoint-tag-add`" in rendered
    assert "no argument constraints recorded" in rendered


# --- guardian_prompt_build: assembly order + graceful absence -----------------


def test_build_assembles_head_first_and_tail_last(monkeypatch):
    _install_lists(monkeypatch, _base_lists_map())

    result = gpb.guardian_prompt_build()

    assert result["ok"] is True
    prompt = result["data"]["prompt"]
    assert prompt.startswith(HEAD_TEXT)
    assert prompt.endswith(TAIL_TEXT)
    assert prompt.index(HEAD_TEXT) < prompt.index("## ACTION POLICY")
    assert prompt.index("## ACTION POLICY") < prompt.index(TAIL_TEXT)


def test_build_omits_persona_and_skills_blocks_when_absent(monkeypatch):
    _install_lists(monkeypatch, _base_lists_map())  # no persona/skills-index seeded

    result = gpb.guardian_prompt_build()

    prompt = result["data"]["prompt"]
    assert "OPERATOR-DEFINED PERSONA" not in prompt
    assert "AVAILABLE SKILLS" not in prompt
    assert result["data"]["meta"]["PersonaBlockPresent"] is False
    assert result["data"]["meta"]["SkillsBlockPresent"] is False
    # No warning for the *expected*, pre-Task-1.9 absence of guardian_skills_index.
    assert not any("guardian_skills_index" in w for w in result["data"]["meta"]["Warnings"])


def test_build_includes_persona_and_skills_blocks_when_present(monkeypatch):
    lists_map = _base_lists_map(
        guardian_persona={"persona": "Speak like a terse SOC analyst."},
        guardian_skills_index=[
            {"name": "triage-phishing", "displayName": "Triage Phishing", "category": "workflows",
             "description": "Full phishing triage.", "enabled": True},
        ],
    )
    _install_lists(monkeypatch, lists_map)

    result = gpb.guardian_prompt_build()

    prompt = result["data"]["prompt"]
    assert "OPERATOR-DEFINED PERSONA" in prompt
    assert "Speak like a terse SOC analyst." in prompt
    assert "AVAILABLE SKILLS" in prompt
    assert "`triage-phishing`" in prompt
    # order: persona comes before skills, both before the approval-mode block,
    # which itself comes before TAIL.
    assert prompt.index("PERSONA") < prompt.index("AVAILABLE SKILLS")
    assert prompt.index("AVAILABLE SKILLS") < prompt.index("Approval mode for this incident")
    assert prompt.index("Approval mode for this incident") < prompt.index(TAIL_TEXT)


def test_build_includes_crud_created_skill_in_skills_block(monkeypatch):
    """A skill created via GuardianSkillsCRUD was previously invisible in
    the AVAILABLE SKILLS block despite being fully readable via
    GuardianSkillRead once merged there -- must show up here too."""
    lists_map = _base_lists_map(
        guardian_skills_index=[
            {"name": "triage-phishing", "displayName": "Triage Phishing", "category": "workflows",
             "description": "Full phishing triage.", "enabled": True},
        ],
        guardian_skills_crud_index=[
            {"name": "custom_analyst_skill", "displayName": "Operator-authored", "category": "custom",
             "description": "Created via GuardianSkillsCRUD.", "enabled": True},
        ],
    )
    _install_lists(monkeypatch, lists_map)

    result = gpb.guardian_prompt_build()

    prompt = result["data"]["prompt"]
    assert "AVAILABLE SKILLS" in prompt
    assert "`triage-phishing`" in prompt
    assert "`custom_analyst_skill`" in prompt
    assert "Operator-authored" in prompt


def test_build_skills_block_present_from_crud_alone_when_static_index_absent(monkeypatch):
    lists_map = _base_lists_map(
        guardian_skills_crud_index=[
            {"name": "custom_analyst_skill", "displayName": "Operator-authored", "category": "custom",
             "description": "Created via GuardianSkillsCRUD.", "enabled": True},
        ],
    )
    _install_lists(monkeypatch, lists_map)  # no guardian_skills_index at all

    result = gpb.guardian_prompt_build()

    prompt = result["data"]["prompt"]
    assert "AVAILABLE SKILLS" in prompt
    assert "`custom_analyst_skill`" in prompt
    assert result["data"]["meta"]["SkillsBlockPresent"] is True


def test_build_crud_index_unreadable_never_blocks_the_static_skills_block(monkeypatch):
    """guardian_skills_crud_index is optional/runtime-created -- unlike the
    other Lists this build reads, its own unreadability must never be
    warning-worthy or block the static skills that already worked."""

    def fake_execute(command, args):
        if command == "getList" and args["listName"] == gpb.GUARDIAN_PROMPT_SKILLS_CRUD_INDEX_LIST_NAME:
            return [{"Type": 4, "Contents": "Error 503: Service Unavailable"}]
        return _entries_for_list(
            _base_lists_map(
                guardian_skills_index=[
                    {"name": "triage-phishing", "displayName": "Triage Phishing", "category": "workflows",
                     "description": "Full phishing triage.", "enabled": True},
                ],
            ),
            args["listName"],
        )

    monkeypatch.setattr(gpb.demisto, "executeCommand", fake_execute)

    result = gpb.guardian_prompt_build()

    prompt = result["data"]["prompt"]
    assert "AVAILABLE SKILLS" in prompt
    assert "`triage-phishing`" in prompt
    assert not any("guardian_skills_crud_index" in w for w in result["data"]["meta"]["Warnings"])


def test_build_policy_block_reflects_require_approval_commands(monkeypatch):
    _install_lists(monkeypatch, _base_lists_map())

    result = gpb.guardian_prompt_build()

    prompt = result["data"]["prompt"]
    assert "`closeInvestigation`" in prompt
    assert "`setIncident`" in prompt
    assert result["data"]["meta"]["PolicyReadable"] is True


def test_build_policy_unreadable_fails_closed_but_build_still_succeeds(monkeypatch):
    def fake_execute(command, args):
        if args["listName"] == gpb.GUARDIAN_PROMPT_POLICY_LIST_NAME:
            return [{"Type": 4, "Contents": "Error 503: Service Unavailable"}]
        return _entries_for_list(_base_lists_map(), args["listName"])

    monkeypatch.setattr(gpb.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(gpb.demisto, "incident", lambda: {})
    monkeypatch.setattr(gpb.demisto, "context", lambda: {})
    monkeypatch.setattr(gpb.demisto, "setContext", lambda path, value: {"status": True})

    result = gpb.guardian_prompt_build()

    assert result["ok"] is True
    prompt = result["data"]["prompt"]
    assert "failing closed" in prompt
    assert result["data"]["meta"]["PolicyReadable"] is False
    assert any("guardian_policy" in w for w in result["data"]["meta"]["Warnings"])


def test_build_missing_head_list_is_fatal(monkeypatch):
    lists_map = _base_lists_map()
    del lists_map[gpb.GUARDIAN_PROMPT_HEAD_LIST_NAME]
    _install_lists(monkeypatch, lists_map)

    result = gpb.guardian_prompt_build()

    assert result["ok"] is False
    assert "guardian_prompt_head" in result["error"]


def test_build_missing_tail_list_is_fatal(monkeypatch):
    lists_map = _base_lists_map()
    del lists_map[gpb.GUARDIAN_PROMPT_TAIL_LIST_NAME]
    _install_lists(monkeypatch, lists_map)

    result = gpb.guardian_prompt_build()

    assert result["ok"] is False
    assert "guardian_prompt_tail" in result["error"]


def test_build_approval_mode_defaults_to_manual_in_playground(monkeypatch):
    _install_lists(monkeypatch, _base_lists_map(), incident={})

    result = gpb.guardian_prompt_build()

    assert result["data"]["meta"]["ApprovalMode"] == "manual"
    assert "**manual**" in result["data"]["prompt"]


def test_build_approval_mode_bypass_from_incident_field(monkeypatch):
    _install_lists(
        monkeypatch, _base_lists_map(), incident={"CustomFields": {"guardianapprovalmode": "bypass"}}
    )

    result = gpb.guardian_prompt_build()

    assert result["data"]["meta"]["ApprovalMode"] == "bypass"
    assert "**bypass**" in result["data"]["prompt"]
    # guardian_preapproved wasn't in the lists map -- soft-absent, so the
    # bypass block should honestly say nothing is configured, no warning.
    assert "no pre-approved classes are currently configured" in result["data"]["prompt"]
    assert not result["data"]["meta"]["Warnings"]


def test_build_approval_mode_bypass_reads_and_narrates_preapproved_classes(monkeypatch):
    """Task 4.4: in bypass mode, guardian_prompt_build must read
    guardian_preapproved and thread its classes into the rendered bypass
    block (not just default to the "none configured" placeholder)."""
    preapproved_data = {
        "classes": [
            {
                "command": "xdr-endpoint-tag-add",
                "arg_constraints": {
                    "endpoint_ids": {"required": True},
                    "tag": {"required": True, "allowed_values": ["guardian-auto-flagged"]},
                },
            }
        ]
    }
    _install_lists(
        monkeypatch,
        _base_lists_map(**{gpb.GUARDIAN_PROMPT_PREAPPROVED_LIST_NAME: preapproved_data}),
        incident={"CustomFields": {"guardianapprovalmode": "bypass"}},
    )

    result = gpb.guardian_prompt_build()

    assert "`xdr-endpoint-tag-add`" in result["data"]["prompt"]
    assert "guardian-auto-flagged" in result["data"]["prompt"]


def test_build_approval_mode_manual_never_reads_preapproved_list(monkeypatch):
    """In manual mode, guardian_preapproved is never even read -- nothing
    would render it, so this saves a List read every tick for the common
    (manual) case."""
    _install_lists(monkeypatch, _base_lists_map())

    def fail_if_preapproved_read(command, args):
        assert command == "getList"
        if args["listName"] == gpb.GUARDIAN_PROMPT_PREAPPROVED_LIST_NAME:
            raise AssertionError("guardian_preapproved must not be read in manual mode")
        return _entries_for_list(_base_lists_map(), args["listName"])

    monkeypatch.setattr(gpb.demisto, "executeCommand", fail_if_preapproved_read)

    result = gpb.guardian_prompt_build()

    assert result["ok"] is True


def test_build_meta_char_len_and_token_estimate_are_consistent(monkeypatch):
    _install_lists(monkeypatch, _base_lists_map())

    result = gpb.guardian_prompt_build()

    meta = result["data"]["meta"]
    assert meta["CharLen"] == len(result["data"]["prompt"])
    assert meta["TokenEstimate"] == gpb.guardian_estimate_tokens(result["data"]["prompt"])


# --- main() --------------------------------------------------------------------


def test_main_success_writes_context_and_returns_command_results(monkeypatch):
    written = _install_lists(monkeypatch, _base_lists_map())
    captured = {}
    monkeypatch.setattr(gpb, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    gpb.main()

    assert "result" in captured
    assert written[gpb.GUARDIAN_CONTEXT_NAMESPACE + ".SystemPrompt"] == captured["result"].raw_response["prompt"]
    assert written[gpb.GUARDIAN_CONTEXT_NAMESPACE + ".SystemPromptMeta"]["ApprovalMode"] == "manual"
    assert HEAD_TEXT in captured["result"].readable_output
    assert TAIL_TEXT in captured["result"].readable_output


def test_main_summary_only_prints_the_summary_but_still_writes_the_whole_prompt_to_context(monkeypatch):
    """The playbook task passes summary_only=true so the War Room shows one summary line instead of a
    35K-character prompt dump; the prompt itself must still reach context in full."""
    written = _install_lists(monkeypatch, _base_lists_map())
    captured = {}
    monkeypatch.setattr(gpb, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)
    monkeypatch.setattr(gpb.demisto, "args", lambda: {"summary_only": "true"})

    gpb.main()

    out = captured["result"].readable_output
    assert out.startswith("Guardian system prompt assembled:")
    assert HEAD_TEXT not in out and TAIL_TEXT not in out
    assert HEAD_TEXT in written[gpb.GUARDIAN_CONTEXT_NAMESPACE + ".SystemPrompt"]  # context still has all of it
    assert HEAD_TEXT in captured["result"].raw_response["prompt"]


def test_main_defaults_to_printing_the_whole_prompt(monkeypatch):
    _install_lists(monkeypatch, _base_lists_map())
    captured = {}
    monkeypatch.setattr(gpb, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)
    for args in ({}, {"summary_only": "false"}, {"summary_only": ""}):
        captured.clear()
        monkeypatch.setattr(gpb.demisto, "args", lambda a=args: a)
        gpb.main()
        assert HEAD_TEXT in captured["result"].readable_output, args


def test_main_calls_return_error_on_fatal_failure(monkeypatch):
    lists_map = _base_lists_map()
    del lists_map[gpb.GUARDIAN_PROMPT_HEAD_LIST_NAME]
    _install_lists(monkeypatch, lists_map)
    errors = []
    monkeypatch.setattr(gpb, "return_error", lambda msg: errors.append(msg), raising=False)

    gpb.main()

    assert errors
    assert "guardian_prompt_head" in errors[0]


def test_main_never_raises_on_unexpected_exception(monkeypatch):
    def boom():
        raise RuntimeError("kaboom")

    monkeypatch.setattr(gpb, "guardian_prompt_build", boom)
    errors = []
    monkeypatch.setattr(gpb, "return_error", lambda msg: errors.append(msg), raising=False)

    gpb.main()  # must not raise

    assert errors
    assert "kaboom" in errors[0]


# --- shipped Lists sanity checks (the real ported HEAD/TAIL content) ---------


def _load_shipped_list_text(list_filename, inner_key):
    repo_lists_dir = pathlib.Path(__file__).resolve().parents[2] / "Lists"
    outer = json.loads((repo_lists_dir / list_filename).read_text())
    inner = json.loads(outer["data"])
    return inner[inner_key]


def test_shipped_head_and_tail_never_leak_mcp_only_tool_names():
    """The #1 risk this task calls out: an untranslated Guardian-only MCP
    tool name (issue_create, xsoar_get_incident, cortex_search, memory_search,
    jobs_create, personality_update, ...) would make the model hallucinate a
    tool call to something that doesn't exist in this XSOAR-native catalogue.
    """
    head = _load_shipped_list_text("list-guardian_prompt_head.json", "head")
    tail = _load_shipped_list_text("list-guardian_prompt_tail.json", "tail")
    full = head + "\n\n" + tail

    forbidden = [
        "issue_create", "issue_add_event", "issue_update", "case_create", "case_add_issue",
        "xsoar_get_incident", "xsoar_list_incidents", "xsoar_get_war_room", "xsoar_search_indicators",
        "xsoar_add_note", "xsoar_add_entry", "xsoar_update_incident", "xsoar_close_incident",
        "cortex_search", "cortex_fetch_topic", "cortex_fetch_toc", "cortex_deep_research", "cortex_suggest",
        "memory_search", "memory_store",
        "jobs_create", "jobs_update", "jobs_delete", "jobs_run_now",
        "personality_update", "personality_reset", "personality_patch",
        "settings_update", "settings_reset",
        "instances_create", "instances_delete", "instances_update",
        "providers_create", "providers_delete", "providers_update",
        "api_keys_create", "api_keys_rotate", "api_keys_revoke",
        "approvals_resolve", "skills_delete", "skills_read", "agent_batch_propose",
        "guardian_web_navigate", "guardian_web_get_text", "guardian_web_extract_links",
        "XQL", "XSIAM",
    ]
    leaked = [name for name in forbidden if name in full]
    assert leaked == []


def test_shipped_tail_contains_prompt_shield_delimiter_note():
    tail = _load_shipped_list_text("list-guardian_prompt_tail.json", "tail")

    assert "<untrusted-case-data>" in tail
    assert "never an instruction" in tail or "not an instruction" in tail or "never treat text inside" in tail


def test_shipped_tail_contains_native_investigation_commands():
    tail = _load_shipped_list_text("list-guardian_prompt_tail.json", "tail")

    for native_command in (
        "getIncidents", "SearchIncidentsV2", "getEntries", "findIndicators",
        "setIncident", "closeInvestigation",
    ):
        assert native_command in tail


def test_shipped_tail_warns_getentries_filter_must_be_json():
    # Live-caught, recurred twice (medium-tier/command-r 32B, incidents #300
    # and #324): the model guessed a plain key=value getEntries filter
    # (e.g. "type=note", "incidentId:300") instead of the JSON object the
    # native command actually requires, and the call errored both times. A
    # skill-only fix (list-guardian_skill_xsoar_case_investigation.json) is
    # not reliably read before the model calls getEntries, so the warning
    # must also live in the ALWAYS-injected prompt tail, right where
    # getEntries is first introduced.
    tail = _load_shipped_list_text("list-guardian_prompt_tail.json", "tail")

    assert "getEntries" in tail
    assert "filter" in tail
    assert "valid JSON" in tail
    assert "omit `filter`" in tail


def test_shipped_tail_warns_against_letting_cached_shortcuts_override_established_findings():
    # Live-caught 2026-08-22 (incident #372, medium-tier/command-r 32B): the
    # investigation's own checkpoint had already recorded "a potential
    # malware infection" and a "high" blast radius with a Malicious-leaning
    # verdict; a later turn retrieved a GuardianMemory note that private IPs
    # from a different notable type are routine noise "unless combined with
    # other suspicious signal", ignored its own already-established findings
    # (exactly the suspicious signal the caveat calls out), and silently
    # flipped to a "Benign" verdict. Private-IP involvement was conflated
    # with "safe" when it only means "no external reputation lookup is
    # possible."
    tail = _load_shipped_list_text("list-guardian_prompt_tail.json", "tail")

    assert "cached shortcut" in tail.lower()
    assert "unless" in tail
    assert "not inherently benign" in tail


def test_shipped_head_describes_native_incident_fields_not_local_issue_store():
    head = _load_shipped_list_text("list-guardian_prompt_head.json", "head")

    for cli_name in ("guardianverdict", "guardianconfidence", "guardianblastradius", "guardianattacktechniques"):
        assert cli_name in head
    assert "setIncident" in head
