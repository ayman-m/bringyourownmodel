import json

import GuardianSkillRead as gsr


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


def _install_lists(monkeypatch, lists_map):
    """Wire demisto.executeCommand('getList', ...) to `lists_map`."""

    def fake_execute(command, args):
        assert command == "getList"
        return _entries_for_list(lists_map, args["listName"])

    monkeypatch.setattr(gsr.demisto, "executeCommand", fake_execute)


INDEX_ENTRIES = [
    {
        "name": "cortex_case_triage",
        "displayName": "Cortex platform case triage reference",
        "category": "foundation",
        "description": "triage codes",
        "attack": [],
        "enabled": True,
    },
    {
        "name": "cortex_case_investigation",
        "displayName": "Investigate a Cortex platform case end-to-end",
        "category": "workflows",
        "description": "the flagship lifecycle",
        "attack": [],
        "enabled": True,
    },
    {
        "name": "disabled_skill",
        "displayName": "A disabled skill",
        "category": "foundation",
        "description": "should never load",
        "attack": [],
        "enabled": False,
    },
    {
        "name": "no_enabled_key_skill",
        "displayName": "Absent enabled key defaults true",
        "category": "foundation",
        "description": "enabled defaults to true when the key is absent",
        "attack": [],
    },
]


def _base_lists_map(**overrides):
    lists_map = {
        gsr.GUARDIAN_SKILLREAD_INDEX_LIST_NAME: INDEX_ENTRIES,
        "guardian_skill_cortex_case_triage": "---\nname: cortex_case_triage\n---\n\nTriage body text.",
        "guardian_skill_cortex_case_investigation": "---\nname: cortex_case_investigation\n---\n\nFlagship body text.",
    }
    lists_map.update(overrides)
    return lists_map


# --- guardian_skillread_load_list_raw -----------------------------------------


def test_load_list_raw_parses_string_contents(monkeypatch):
    _install_lists(monkeypatch, {"some_list": "raw text body"})

    result = gsr.guardian_skillread_load_list_raw("some_list")

    assert result["ok"] is True
    assert result["data"] == "raw text body"


def test_load_list_raw_missing_list_is_soft_absent(monkeypatch):
    _install_lists(monkeypatch, {})

    result = gsr.guardian_skillread_load_list_raw("guardian_skill_nonexistent")

    assert result["ok"] is True
    assert result["data"] is None


def test_load_list_raw_other_getlist_failure_is_hard_error(monkeypatch):
    def fake_execute(command, args):
        return [{"Type": 4, "Contents": "Error 503: Service Unavailable"}]

    monkeypatch.setattr(gsr.demisto, "executeCommand", fake_execute)

    result = gsr.guardian_skillread_load_list_raw("guardian_skills_index")

    assert result["ok"] is False
    assert "503" in result["error"]


def test_load_list_raw_empty_string_contents_is_soft_absent(monkeypatch):
    _install_lists(monkeypatch, {"blank_list": ""})

    result = gsr.guardian_skillread_load_list_raw("blank_list")

    assert result["ok"] is True
    assert result["data"] is None


# --- guardian_skillread_load_index ---------------------------------------------


def test_load_index_parses_json_array(monkeypatch):
    _install_lists(monkeypatch, _base_lists_map())

    result = gsr.guardian_skillread_load_index()

    assert result["ok"] is True
    assert result["data"] == INDEX_ENTRIES


def test_load_index_missing_fails_closed_not_soft_absent(monkeypatch):
    """The index itself missing must be a HARD failure (ok=False), never a
    soft ok=True/data=None -- callers must not treat "index absent" as
    "anything goes". This is also the 'index-missing -> graceful' case: it
    must degrade to a clean error, not raise.
    """
    _install_lists(monkeypatch, {})

    result = gsr.guardian_skillread_load_index()

    assert result["ok"] is False
    assert "guardian_skills_index" in result["error"]


def test_load_index_malformed_json_is_error(monkeypatch):
    _install_lists(monkeypatch, {gsr.GUARDIAN_SKILLREAD_INDEX_LIST_NAME: "{not json"})

    result = gsr.guardian_skillread_load_index()

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_load_index_non_list_payload_is_error(monkeypatch):
    _install_lists(monkeypatch, {gsr.GUARDIAN_SKILLREAD_INDEX_LIST_NAME: {"not": "a list"}})

    result = gsr.guardian_skillread_load_index()

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


# --- guardian_skillread_load_index: CRUD-created skills merge ------------------


CRUD_INDEX_ENTRIES = [
    {
        "name": "custom_analyst_skill",
        "displayName": "Operator-authored custom skill",
        "category": "custom",
        "description": "created via GuardianSkillsCRUD",
        "attack": [],
        "enabled": True,
    },
]


def test_load_index_merges_in_crud_created_skills(monkeypatch):
    """A skill created via GuardianSkillsCRUD is durably stored and fully
    manageable, but was previously invisible to this read path -- the
    static index was the only List ever consulted."""
    _install_lists(
        monkeypatch, _base_lists_map(**{gsr.GUARDIAN_SKILLREAD_CRUD_INDEX_LIST_NAME: CRUD_INDEX_ENTRIES})
    )

    result = gsr.guardian_skillread_load_index()

    assert result["ok"] is True
    assert result["data"] == INDEX_ENTRIES + CRUD_INDEX_ENTRIES


def test_load_index_crud_absent_is_not_an_error(monkeypatch):
    """guardian_skills_crud_index is optional/runtime-created -- its own
    absence must never block the static skills that already worked."""
    _install_lists(monkeypatch, _base_lists_map())  # no CRUD index entry at all

    result = gsr.guardian_skillread_load_index()

    assert result["ok"] is True
    assert result["data"] == INDEX_ENTRIES


def test_load_index_crud_unreadable_fails_open_static_skills_unaffected(monkeypatch):
    def fake_execute(command, args):
        if args["listName"] == gsr.GUARDIAN_SKILLREAD_CRUD_INDEX_LIST_NAME:
            return [{"Type": 4, "Contents": "Error 503: Service Unavailable"}]
        return _entries_for_list(_base_lists_map(), args["listName"])

    monkeypatch.setattr(gsr.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(gsr.demisto, "error", lambda msg: None)

    result = gsr.guardian_skillread_load_index()

    assert result["ok"] is True
    assert result["data"] == INDEX_ENTRIES


def test_load_index_crud_malformed_fails_open_static_skills_unaffected(monkeypatch):
    _install_lists(
        monkeypatch, _base_lists_map(**{gsr.GUARDIAN_SKILLREAD_CRUD_INDEX_LIST_NAME: "{not json"})
    )
    logged = []
    monkeypatch.setattr(gsr.demisto, "error", lambda msg: logged.append(msg))

    result = gsr.guardian_skillread_load_index()

    assert result["ok"] is True
    assert result["data"] == INDEX_ENTRIES
    assert logged and gsr.GUARDIAN_SKILLREAD_CRUD_INDEX_LIST_NAME in logged[0]


def test_load_index_static_entry_wins_on_name_collision_with_crud(monkeypatch):
    """A CRUD-created skill must never be able to shadow a pack-shipped
    skill of the same name -- guardian_skillread_find_entry returns the
    FIRST match, so static entries are listed first."""
    colliding_crud_entry = dict(CRUD_INDEX_ENTRIES[0], name="cortex_case_triage", displayName="Impostor")
    _install_lists(
        monkeypatch, _base_lists_map(**{gsr.GUARDIAN_SKILLREAD_CRUD_INDEX_LIST_NAME: [colliding_crud_entry]})
    )

    result = gsr.guardian_skillread_load_index()
    assert result["ok"] is True

    found = gsr.guardian_skillread_find_entry("cortex_case_triage", result["data"])
    assert found["displayName"] == "Cortex platform case triage reference"  # the real, shipped entry -- not "Impostor"


# --- guardian_skillread_available_names / find_entry ---------------------------


def test_available_names_filters_disabled_and_dedupes_sorted():
    names = gsr.guardian_skillread_available_names(INDEX_ENTRIES)

    assert names == sorted(names)
    assert "disabled_skill" not in names
    assert "cortex_case_triage" in names
    assert "cortex_case_investigation" in names
    assert "no_enabled_key_skill" in names  # absent 'enabled' key defaults to True


def test_available_names_handles_empty_or_none():
    assert gsr.guardian_skillread_available_names([]) == []
    assert gsr.guardian_skillread_available_names(None) == []


def test_find_entry_returns_enabled_match():
    entry = gsr.guardian_skillread_find_entry("cortex_case_triage", INDEX_ENTRIES)

    assert entry is not None
    assert entry["displayName"] == "Cortex platform case triage reference"


def test_find_entry_treats_disabled_as_absent():
    entry = gsr.guardian_skillread_find_entry("disabled_skill", INDEX_ENTRIES)

    assert entry is None


def test_find_entry_unknown_name_returns_none():
    entry = gsr.guardian_skillread_find_entry("totally_unknown", INDEX_ENTRIES)

    assert entry is None


# --- guardian_skillread_validate_name ------------------------------------------


def test_validate_name_empty_string_is_needs_context_error():
    result = gsr.guardian_skillread_validate_name("", INDEX_ENTRIES)

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_validate_name_none_is_needs_context_error():
    result = gsr.guardian_skillread_validate_name(None, INDEX_ENTRIES)

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_validate_name_known_enabled_name_succeeds():
    result = gsr.guardian_skillread_validate_name("cortex_case_triage", INDEX_ENTRIES)

    assert result["ok"] is True
    assert result["data"]["name"] == "cortex_case_triage"


def test_validate_name_unknown_name_lists_available_skills():
    result = gsr.guardian_skillread_validate_name("does_not_exist", INDEX_ENTRIES)

    assert result["ok"] is False
    assert "unknown skill 'does_not_exist'" in result["error"]
    assert "cortex_case_triage" in result["error"]
    assert "cortex_case_investigation" in result["error"]
    assert "disabled_skill" not in result["error"]  # disabled skills aren't advertised


def test_validate_name_disabled_skill_is_rejected_like_unknown():
    result = gsr.guardian_skillread_validate_name("disabled_skill", INDEX_ENTRIES)

    assert result["ok"] is False
    assert "unknown skill 'disabled_skill'" in result["error"]


def test_validate_name_no_available_skills_reports_none_configured():
    result = gsr.guardian_skillread_validate_name("anything", [])

    assert result["ok"] is False
    assert "(none configured)" in result["error"]


# --- guardian_skillread_load_body ----------------------------------------------


def test_load_body_returns_raw_text(monkeypatch):
    _install_lists(monkeypatch, _base_lists_map())

    result = gsr.guardian_skillread_load_body("cortex_case_triage")

    assert result["ok"] is True
    assert "Triage body text." in result["data"]


def test_load_body_missing_list_is_soft_absent(monkeypatch):
    _install_lists(monkeypatch, {gsr.GUARDIAN_SKILLREAD_INDEX_LIST_NAME: INDEX_ENTRIES})

    result = gsr.guardian_skillread_load_body("cortex_case_triage")

    assert result["ok"] is True
    assert result["data"] is None


# --- guardian_skillread (top-level orchestration) ------------------------------


def test_guardian_skillread_known_name_returns_body(monkeypatch):
    _install_lists(monkeypatch, _base_lists_map())

    result = gsr.guardian_skillread("cortex_case_investigation")

    assert result["ok"] is True
    assert result["data"]["name"] == "cortex_case_investigation"
    assert result["data"]["display_name"] == "Investigate a Cortex platform case end-to-end"
    assert result["data"]["category"] == "workflows"
    assert "Flagship body text." in result["data"]["body"]


def test_guardian_skillread_unknown_name_clean_error_lists_available(monkeypatch):
    _install_lists(monkeypatch, _base_lists_map())

    result = gsr.guardian_skillread("not_a_real_skill")

    assert result["ok"] is False
    assert "unknown skill 'not_a_real_skill'" in result["error"]
    assert "cortex_case_triage" in result["error"]


def test_guardian_skillread_index_missing_is_graceful_not_a_crash(monkeypatch):
    """index-missing -> graceful: no exception escapes, just a clean
    ok=False envelope with a message naming the real cause.
    """
    _install_lists(monkeypatch, {})

    result = gsr.guardian_skillread("cortex_case_triage")

    assert result["ok"] is False
    assert "guardian_skills_index" in result["error"]


def test_guardian_skillread_body_list_missing_is_distinct_from_unknown_name(monkeypatch):
    """Name IS valid per the index, but its own guardian_skill_<name> List
    was never shipped -- a packaging gap, reported distinctly from "unknown
    skill".
    """
    _install_lists(monkeypatch, {gsr.GUARDIAN_SKILLREAD_INDEX_LIST_NAME: INDEX_ENTRIES})

    result = gsr.guardian_skillread("cortex_case_triage")

    assert result["ok"] is False
    assert "could not be found" in result["error"]
    assert "unknown skill" not in result["error"]


def test_guardian_skillread_disabled_name_is_rejected(monkeypatch):
    _install_lists(monkeypatch, _base_lists_map())

    result = gsr.guardian_skillread("disabled_skill")

    assert result["ok"] is False
    assert "unknown skill 'disabled_skill'" in result["error"]


# --- main() ---------------------------------------------------------------------


def _capture_context_writes(monkeypatch):
    writes = {}
    monkeypatch.setattr(gsr.demisto, "setContext", lambda path, value: writes.update({path: value}) or {"status": True})
    return writes


def test_main_success_writes_the_skill_to_context_without_the_append_trap(monkeypatch):
    """CommandResults outputs under a bare 'Guardian' prefix make Cortex platform APPEND, turning the whole Guardian context
    into a list (live-caught). The skill text is written with setContext to Guardian.Skill*; the entry's outputs are the small
    Guardian.Skill object (never the text), under its own prefix and keyed by the skill name."""
    _install_lists(monkeypatch, _base_lists_map())
    monkeypatch.setattr(gsr.demisto, "args", lambda: {"name": "cortex_case_triage"})
    writes = _capture_context_writes(monkeypatch)
    captured = {}
    monkeypatch.setattr(gsr, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    gsr.main()

    result = captured["result"]
    assert result.outputs_prefix == "Guardian.Skill" and result.outputs_key_field == "name"
    assert result.outputs == writes["Guardian.Skill"] == {
        "name": "cortex_case_triage", "display_name": "Cortex platform case triage reference", "category": "foundation",
        "chars": len(writes["Guardian.SkillBody"]), "token_estimate": result.outputs["token_estimate"]}
    assert "Triage body text." not in json.dumps(result.outputs)
    assert writes["Guardian.SkillName"] == "cortex_case_triage"
    assert writes["Guardian.SkillDisplayName"] == "Cortex platform case triage reference"
    assert writes["Guardian.SkillCategory"] == "foundation"
    assert "Triage body text." in writes["Guardian.SkillBody"]
    assert "Triage body text." in result.readable_output
    assert "Triage body text." in result.raw_response["body"]  # what the agent receives as the tool result


def test_main_missing_name_arg_calls_return_error(monkeypatch):
    monkeypatch.setattr(gsr.demisto, "args", lambda: {})

    errors = []
    monkeypatch.setattr(gsr, "return_error", lambda msg: errors.append(msg), raising=False)

    gsr.main()

    assert len(errors) == 1
    assert "NEEDS_CONTEXT" in errors[0]


def test_main_unknown_name_calls_return_error(monkeypatch):
    _install_lists(monkeypatch, _base_lists_map())
    monkeypatch.setattr(gsr.demisto, "args", lambda: {"name": "nope"})

    errors = []
    monkeypatch.setattr(gsr, "return_error", lambda msg: errors.append(msg), raising=False)

    gsr.main()

    assert len(errors) == 1
    assert "unknown skill 'nope'" in errors[0]


def test_main_unexpected_exception_is_caught_and_reported(monkeypatch):
    def boom(name):
        raise RuntimeError("boom")

    monkeypatch.setattr(gsr, "guardian_skillread", boom)
    monkeypatch.setattr(gsr.demisto, "args", lambda: {"name": "cortex_case_triage"})

    errors = []
    monkeypatch.setattr(gsr, "return_error", lambda msg: errors.append(msg), raising=False)

    gsr.main()

    assert len(errors) == 1
    assert "unexpectedly" in errors[0]
    assert "boom" in errors[0]


def test_main_summary_only_prints_one_line_but_still_writes_the_whole_body_to_context(monkeypatch):
    _install_lists(monkeypatch, _base_lists_map())
    monkeypatch.setattr(gsr.demisto, "args", lambda: {"name": "cortex_case_triage", "summary_only": "true"})
    writes = _capture_context_writes(monkeypatch)
    captured = {}
    monkeypatch.setattr(gsr, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    gsr.main()

    result = captured["result"]
    assert result.readable_output.startswith("Skill loaded: Cortex platform case triage reference (`cortex_case_triage`)")
    assert "Triage body text." not in result.readable_output
    assert "Triage body text." in writes["Guardian.SkillBody"]  # the body is still written to context in full
