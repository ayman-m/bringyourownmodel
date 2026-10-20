import json

import GuardianSkillsCRUD as gsc


# --- test fixtures -------------------------------------------------------------


class FakeLists:
    """In-memory Cortex platform List store + a `demisto.executeCommand` fake, shared
    across one test so multi-call sequences (e.g. create-then-update) see a
    consistent, evolving state -- mirrors real `getList`/`setList`/
    `createList` semantics closely enough for this script's own logic
    (setList only updates an EXISTING list; createList always succeeds,
    create-or-overwrite).

    List DELETION is faked via `demisto-api-post uri=/lists/delete` (NOT a
    `deleteList` command -- confirmed live on Cortex platform.14.0 that no such
    native command exists; see GuardianSkillsCRUD.py's own module docstring
    "SECOND CRITICAL FINDING" section). The fake's response shape mirrors
    the real Core REST API integration's response verbatim: `{"response":
    "{}"}` -- a bare STRING, not a JSON object -- which is exactly why
    `guardian_crud_delete_list_via_rest` only ever checks `ok`, never the
    response payload's shape.
    """

    def __init__(self, initial=None):
        self.lists = dict(initial or {})
        self.calls = []

    def executeCommand(self, command, args):
        self.calls.append((command, dict(args)))

        if command == "getList":
            name = args["listName"]
            if name in self.lists:
                return [{"Type": 1, "Contents": self.lists[name]}]
            return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(name)}]

        if command == "createList":
            self.lists[args["listName"]] = args["listData"]
            return [{"Type": 1, "Contents": "list {} created".format(args["listName"])}]

        if command == "setList":
            name = args["listName"]
            if name not in self.lists:
                return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(name)}]
            self.lists[name] = args["listData"]
            return [{"Type": 1, "Contents": "list {} updated".format(name)}]

        if command == "demisto-api-post":
            body = json.loads(args["body"])
            if args["uri"] == "/lists/delete":
                name = body.get("id")
                if name not in self.lists:
                    return [{"Type": 4, "Contents": "Could not delete list '{}': not found".format(name)}]
                del self.lists[name]
                # Real, confirmed-live response shape: "response" is a bare
                # STRING "{}", not a JSON object.
                return [{"Type": 1, "Contents": {"response": "{}"}}]
            raise AssertionError("unexpected demisto-api-post uri {!r}".format(args["uri"]))

        if command == "GetTime":
            return [{"Type": 1, "Contents": "2026-07-06T00:00:00Z"}]

        raise AssertionError("unexpected command {!r}".format(command))


def _install(monkeypatch, initial=None):
    fake = FakeLists(initial)
    monkeypatch.setattr(gsc.demisto, "executeCommand", fake.executeCommand)
    monkeypatch.setattr(gsc.demisto, "incident", lambda: {})
    return fake


STATIC_INDEX = [
    {
        "name": "cortex_case_triage",
        "displayName": "Cortex platform case triage reference",
        "category": "foundation",
        "description": "triage codes",
        "attack": [],
        "enabled": True,
    }
]


def _base_lists(**overrides):
    lists = {gsc.GUARDIAN_SKILLSCRUD_STATIC_INDEX_LIST_NAME: json.dumps(STATIC_INDEX)}
    lists.update(overrides)
    return lists


# --- guardian_crud_validate_name -------------------------------------------------


def test_validate_name_accepts_lowercase_snake_case():
    result = gsc.guardian_crud_validate_name("incident_triage_v2")
    assert result["ok"] is True
    assert result["data"] == "incident_triage_v2"


def test_validate_name_strips_whitespace():
    result = gsc.guardian_crud_validate_name("  my_skill  ")
    assert result["ok"] is True
    assert result["data"] == "my_skill"


def test_validate_name_rejects_empty_and_none():
    assert gsc.guardian_crud_validate_name("")["ok"] is False
    assert gsc.guardian_crud_validate_name(None)["ok"] is False
    assert "NEEDS_CONTEXT" in gsc.guardian_crud_validate_name("")["error"]


def test_validate_name_rejects_uppercase_and_bad_chars():
    for bad in ("MySkill", "my-skill", "my skill", "1skill", "my.skill"):
        result = gsc.guardian_crud_validate_name(bad)
        assert result["ok"] is False, bad
        assert "NEEDS_CONTEXT" in result["error"]


def test_validate_name_rejects_reserved_prefixes():
    for reserved in ("deleted_foo", "history_bar"):
        result = gsc.guardian_crud_validate_name(reserved)
        assert result["ok"] is False
        assert "reserved prefix" in result["error"]


# --- guardian_crud_split_frontmatter ---------------------------------------------


def test_split_frontmatter_extracts_body_after_delimiters():
    raw = "---\nname: foo\n---\n\nActual body text.\nMore text."
    assert gsc.guardian_crud_split_frontmatter(raw) == "Actual body text.\nMore text."


def test_split_frontmatter_falls_back_to_whole_string_when_no_delimiters():
    raw = "Just plain text, no frontmatter."
    assert gsc.guardian_crud_split_frontmatter(raw) == raw


def test_split_frontmatter_falls_back_when_only_one_delimiter():
    raw = "---\nname: foo\nno closing delimiter"
    assert gsc.guardian_crud_split_frontmatter(raw) == raw


# --- guardian_crud_render_skill_markdown -----------------------------------------


def test_render_skill_markdown_shape():
    rendered = gsc.guardian_crud_render_skill_markdown(
        "my_skill", "My Skill", "custom", "A description", ["T1566"], "Body content here."
    )
    assert rendered.startswith("---\n")
    assert 'name: "my_skill"' in rendered
    assert 'displayName: "My Skill"' in rendered
    assert 'source: "agent"' in rendered
    assert "locked: false" in rendered
    assert 'attack: ["T1566"]' in rendered
    assert rendered.endswith("Body content here.")
    # Round-trips through the frontmatter splitter.
    assert gsc.guardian_crud_split_frontmatter(rendered) == "Body content here."


def test_render_skill_markdown_defaults_empty_attack():
    rendered = gsc.guardian_crud_render_skill_markdown("s", "S", "custom", "d", None, "body")
    assert "attack: []" in rendered


# --- guardian_crud_sha256 --------------------------------------------------------


def test_sha256_matches_known_digest():
    import hashlib

    assert gsc.guardian_crud_sha256("hello") == hashlib.sha256(b"hello").hexdigest()


def test_sha256_differs_for_different_content():
    assert gsc.guardian_crud_sha256("a") != gsc.guardian_crud_sha256("b")


# --- guardian_crud_load_static_index ---------------------------------------------


def test_load_static_index_parses_existing(monkeypatch):
    _install(monkeypatch, _base_lists())
    result = gsc.guardian_crud_load_static_index()
    assert result["ok"] is True
    assert result["data"] == STATIC_INDEX


def test_load_static_index_missing_fails_closed(monkeypatch):
    _install(monkeypatch, {})
    result = gsc.guardian_crud_load_static_index()
    assert result["ok"] is False
    assert gsc.GUARDIAN_SKILLSCRUD_STATIC_INDEX_LIST_NAME in result["error"]


# --- guardian_crud_load_registry (self-bootstrap) --------------------------------


def test_load_registry_bootstraps_when_missing(monkeypatch):
    fake = _install(monkeypatch, {})
    result = gsc.guardian_crud_load_registry()
    assert result["ok"] is True
    assert result["data"] == []
    assert gsc.GUARDIAN_SKILLSCRUD_REGISTRY_LIST_NAME in fake.lists
    assert fake.lists[gsc.GUARDIAN_SKILLSCRUD_REGISTRY_LIST_NAME] == "[]"


def test_load_registry_parses_existing_content(monkeypatch):
    existing = [{"name": "foo", "enabled": True}]
    _install(monkeypatch, {gsc.GUARDIAN_SKILLSCRUD_REGISTRY_LIST_NAME: json.dumps(existing)})
    result = gsc.guardian_crud_load_registry()
    assert result["ok"] is True
    assert result["data"] == existing


# --- op=create --------------------------------------------------------------------


def _create_args(**overrides):
    args = {
        "op": "create",
        "name": "my_new_skill",
        "displayName": "My New Skill",
        "category": "custom",
        "description": "A test skill.",
        "body": "## Body\n\nSome content.",
    }
    args.update(overrides)
    return args


def test_create_adds_skill_body_and_registry_entry(monkeypatch):
    fake = _install(monkeypatch, _base_lists())

    result = gsc.guardian_skills_crud(_create_args())

    assert result["ok"] is True
    assert result["data"]["op"] == "create"
    assert result["data"]["name"] == "my_new_skill"

    list_name = "guardian_skill_my_new_skill"
    assert list_name in fake.lists
    assert "Some content." in fake.lists[list_name]
    assert 'source: "agent"' in fake.lists[list_name]

    registry = json.loads(fake.lists[gsc.GUARDIAN_SKILLSCRUD_REGISTRY_LIST_NAME])
    assert len(registry) == 1
    assert registry[0]["name"] == "my_new_skill"
    assert registry[0]["displayName"] == "My New Skill"
    assert registry[0]["enabled"] is True
    assert registry[0]["historySeq"] == 0


def test_create_defaults_category_and_enabled(monkeypatch):
    fake = _install(monkeypatch, _base_lists())
    args = _create_args()
    del args["category"]

    result = gsc.guardian_skills_crud(args)

    assert result["ok"] is True
    registry = json.loads(fake.lists[gsc.GUARDIAN_SKILLSCRUD_REGISTRY_LIST_NAME])
    assert registry[0]["category"] == "custom"
    assert registry[0]["enabled"] is True


def test_create_missing_body_is_needs_context_error(monkeypatch):
    _install(monkeypatch, _base_lists())
    args = _create_args()
    del args["body"]

    result = gsc.guardian_skills_crud(args)

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]
    assert "body" in result["error"]


def test_create_missing_displayname_is_needs_context_error(monkeypatch):
    _install(monkeypatch, _base_lists())
    args = _create_args()
    del args["displayName"]

    result = gsc.guardian_skills_crud(args)

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_create_missing_description_is_needs_context_error(monkeypatch):
    _install(monkeypatch, _base_lists())
    args = _create_args()
    del args["description"]

    result = gsc.guardian_skills_crud(args)

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_create_collides_with_pack_shipped_skill(monkeypatch):
    _install(monkeypatch, _base_lists())

    result = gsc.guardian_skills_crud(_create_args(name="cortex_case_triage"))

    assert result["ok"] is False
    assert "already exists as a pack-shipped" in result["error"]


def test_create_collides_with_existing_registry_entry(monkeypatch):
    existing_entry = {"name": "my_new_skill", "displayName": "X", "enabled": True, "historySeq": 0}
    _install(
        monkeypatch,
        _base_lists(**{gsc.GUARDIAN_SKILLSCRUD_REGISTRY_LIST_NAME: json.dumps([existing_entry])}),
    )

    result = gsc.guardian_skills_crud(_create_args())

    assert result["ok"] is False
    assert "already exists in" in result["error"]
    assert "op=update" in result["error"]


def test_create_fails_closed_when_static_index_unreadable(monkeypatch):
    _install(monkeypatch, {})  # static index missing entirely

    result = gsc.guardian_skills_crud(_create_args())

    assert result["ok"] is False
    assert "cannot verify name availability" in result["error"]


def test_create_invalid_name_never_touches_lists(monkeypatch):
    fake = _install(monkeypatch, _base_lists())

    result = gsc.guardian_skills_crud(_create_args(name="Not Valid"))

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]
    assert fake.calls == []  # validation failed before any List I/O


# --- op=update --------------------------------------------------------------------


def _seed_created_skill(monkeypatch, name="my_skill", enabled=True):
    fake = _install(monkeypatch, _base_lists())
    create_result = gsc.guardian_skills_crud(
        {
            "op": "create",
            "name": name,
            "displayName": "My Skill",
            "category": "custom",
            "description": "Original description.",
            "body": "Original body.",
            "enabled": "true" if enabled else "false",
        }
    )
    assert create_result["ok"] is True
    return fake


def test_update_snapshots_first_and_audits_sha256(monkeypatch):
    fake = _seed_created_skill(monkeypatch)
    list_name = "guardian_skill_my_skill"
    before_body = fake.lists[list_name]

    result = gsc.guardian_skills_crud({"op": "update", "name": "my_skill", "body": "Updated body."})

    assert result["ok"] is True
    assert result["data"]["history_seq"] == 1
    before_hash = result["data"]["sha256_before"]
    after_hash = result["data"]["sha256_after"]
    assert before_hash == gsc.guardian_crud_sha256(before_body)
    assert before_hash != after_hash

    # The live body was actually updated.
    assert "Updated body." in fake.lists[list_name]

    # A history snapshot List exists and carries both sides.
    history_list_name = "guardian_skill_history_my_skill_1"
    assert history_list_name in fake.lists
    history_record = json.loads(fake.lists[history_list_name])
    assert history_record["sha256_before"] == before_hash
    assert history_record["sha256_after"] == after_hash
    assert history_record["body_before"] == before_body
    assert "Updated body." in history_record["body_after"]

    # The registry entry's historySeq advanced.
    registry = json.loads(fake.lists[gsc.GUARDIAN_SKILLSCRUD_REGISTRY_LIST_NAME])
    assert registry[0]["historySeq"] == 1


def test_update_preserves_body_when_not_given(monkeypatch):
    fake = _seed_created_skill(monkeypatch)

    result = gsc.guardian_skills_crud({"op": "update", "name": "my_skill", "displayName": "Renamed"})

    assert result["ok"] is True
    list_name = "guardian_skill_my_skill"
    assert "Original body." in fake.lists[list_name]
    registry = json.loads(fake.lists[gsc.GUARDIAN_SKILLSCRUD_REGISTRY_LIST_NAME])
    assert registry[0]["displayName"] == "Renamed"


def test_update_requires_at_least_one_field(monkeypatch):
    _seed_created_skill(monkeypatch)

    result = gsc.guardian_skills_crud({"op": "update", "name": "my_skill"})

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]
    assert "at least one" in result["error"]


def test_update_unknown_skill_lists_available(monkeypatch):
    _seed_created_skill(monkeypatch, name="known_skill")

    result = gsc.guardian_skills_crud({"op": "update", "name": "totally_unknown", "body": "x"})

    assert result["ok"] is False
    assert "unknown or non-CRUD-managed skill 'totally_unknown'" in result["error"]
    assert "known_skill" in result["error"]


def test_update_pack_shipped_skill_is_a_clean_system_locked_error(monkeypatch):
    _install(monkeypatch, _base_lists())

    result = gsc.guardian_skills_crud({"op": "update", "name": "cortex_case_triage", "body": "x"})

    assert result["ok"] is False
    assert "system-locked" in result["error"]
    assert "pack-shipped" in result["error"]


def test_update_multiple_calls_increment_history_seq(monkeypatch):
    fake = _seed_created_skill(monkeypatch)

    first = gsc.guardian_skills_crud({"op": "update", "name": "my_skill", "body": "v2"})
    second = gsc.guardian_skills_crud({"op": "update", "name": "my_skill", "body": "v3"})

    assert first["data"]["history_seq"] == 1
    assert second["data"]["history_seq"] == 2
    assert "guardian_skill_history_my_skill_1" in fake.lists
    assert "guardian_skill_history_my_skill_2" in fake.lists


# --- guardian_crud_delete_list_via_rest (the deleteList-doesn't-exist fix) -------


def test_delete_list_via_rest_succeeds_via_demisto_api_post(monkeypatch):
    fake = _install(monkeypatch, {"some_list": "[]"})

    result = gsc.guardian_crud_delete_list_via_rest("some_list")

    assert result["ok"] is True
    assert "some_list" not in fake.lists


def test_delete_list_via_rest_falls_back_to_core_api_post_when_unregistered(monkeypatch):
    def fake_execute(command, args):
        if command == "demisto-api-post":
            raise Exception("simulated: demisto-api-post not found in module")
        if command == "core-api-post":
            body = json.loads(args["body"])
            assert body["id"] == "some_list"
            return [{"Type": 1, "Contents": {"response": "{}"}}]
        raise AssertionError("unexpected command {!r}".format(command))

    monkeypatch.setattr(gsc.demisto, "executeCommand", fake_execute)

    result = gsc.guardian_crud_delete_list_via_rest("some_list")

    assert result["ok"] is True


def test_delete_list_via_rest_reports_real_failure(monkeypatch):
    fake = _install(monkeypatch, {})  # "some_list" doesn't exist -> fake 404s it

    result = gsc.guardian_crud_delete_list_via_rest("some_list")

    assert result["ok"] is False
    assert "some_list" in result["error"]


# --- op=delete --------------------------------------------------------------------


def test_delete_soft_deletes_and_is_restorable(monkeypatch):
    fake = _seed_created_skill(monkeypatch)
    list_name = "guardian_skill_my_skill"
    body_before_delete = fake.lists[list_name]

    result = gsc.guardian_skills_crud({"op": "delete", "name": "my_skill"})

    assert result["ok"] is True
    assert result["data"]["restorable_list"] == "guardian_skill_deleted_my_skill"

    # Live List is gone.
    assert list_name not in fake.lists

    # Restorable copy exists with the full body + index entry.
    deleted_record = json.loads(fake.lists["guardian_skill_deleted_my_skill"])
    assert deleted_record["body"] == body_before_delete
    assert deleted_record["index_entry"]["name"] == "my_skill"
    assert deleted_record["sha256"] == gsc.guardian_crud_sha256(body_before_delete)

    # History snapshot was written before the delete.
    assert "guardian_skill_history_my_skill_1" in fake.lists

    # Registry entry removed.
    registry = json.loads(fake.lists[gsc.GUARDIAN_SKILLSCRUD_REGISTRY_LIST_NAME])
    assert registry == []


def test_delete_unknown_skill_is_clean_error(monkeypatch):
    _install(monkeypatch, _base_lists())

    result = gsc.guardian_skills_crud({"op": "delete", "name": "never_existed"})

    assert result["ok"] is False
    assert "unknown or non-CRUD-managed skill" in result["error"]


def test_delete_pack_shipped_skill_is_a_clean_system_locked_error(monkeypatch):
    _install(monkeypatch, _base_lists())

    result = gsc.guardian_skills_crud({"op": "delete", "name": "cortex_case_triage"})

    assert result["ok"] is False
    assert "system-locked" in result["error"]


# --- op=toggle --------------------------------------------------------------------


def test_toggle_flips_enabled_true_to_false(monkeypatch):
    fake = _seed_created_skill(monkeypatch, enabled=True)

    result = gsc.guardian_skills_crud({"op": "toggle", "name": "my_skill", "enabled": "false"})

    assert result["ok"] is True
    assert result["data"]["entry"]["enabled"] is False
    registry = json.loads(fake.lists[gsc.GUARDIAN_SKILLSCRUD_REGISTRY_LIST_NAME])
    assert registry[0]["enabled"] is False


def test_toggle_flips_enabled_false_to_true(monkeypatch):
    fake = _seed_created_skill(monkeypatch, enabled=False)

    result = gsc.guardian_skills_crud({"op": "toggle", "name": "my_skill", "enabled": "true"})

    assert result["ok"] is True
    assert result["data"]["entry"]["enabled"] is True


def test_toggle_does_not_touch_the_skill_body(monkeypatch):
    fake = _seed_created_skill(monkeypatch)
    list_name = "guardian_skill_my_skill"
    before_body = fake.lists[list_name]

    gsc.guardian_skills_crud({"op": "toggle", "name": "my_skill", "enabled": "false"})

    assert fake.lists[list_name] == before_body
    assert "guardian_skill_history_my_skill_1" not in fake.lists  # no snapshot for toggle


def test_toggle_missing_enabled_is_needs_context_error(monkeypatch):
    _seed_created_skill(monkeypatch)

    result = gsc.guardian_skills_crud({"op": "toggle", "name": "my_skill"})

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_toggle_unknown_skill_is_clean_error(monkeypatch):
    _install(monkeypatch, _base_lists())

    result = gsc.guardian_skills_crud({"op": "toggle", "name": "never_existed", "enabled": "true"})

    assert result["ok"] is False
    assert "unknown or non-CRUD-managed skill" in result["error"]


# --- guardian_skills_crud dispatcher (op validation) -----------------------------


def test_dispatcher_rejects_unknown_op(monkeypatch):
    _install(monkeypatch, _base_lists())

    result = gsc.guardian_skills_crud({"op": "destroy", "name": "x"})

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]
    assert "op" in result["error"]


def test_dispatcher_rejects_missing_op(monkeypatch):
    _install(monkeypatch, _base_lists())

    result = gsc.guardian_skills_crud({"name": "x"})

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


# --- main() -----------------------------------------------------------------------


def test_main_create_success_returns_command_results(monkeypatch):
    _install(monkeypatch, _base_lists())
    monkeypatch.setattr(gsc.demisto, "args", lambda: _create_args())

    captured = {}
    monkeypatch.setattr(gsc, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    gsc.main()

    result = captured["result"]
    assert result.outputs_prefix == "Guardian.SkillsCRUD"
    assert result.outputs["op"] == "create"
    assert result.outputs["name"] == "my_new_skill"


def test_main_unknown_op_calls_return_error(monkeypatch):
    _install(monkeypatch, _base_lists())
    monkeypatch.setattr(gsc.demisto, "args", lambda: {"op": "nope", "name": "x"})

    errors = []
    monkeypatch.setattr(gsc, "return_error", lambda msg: errors.append(msg), raising=False)

    gsc.main()

    assert len(errors) == 1
    assert "NEEDS_CONTEXT" in errors[0]


def test_main_unexpected_exception_is_caught_and_reported(monkeypatch):
    def boom(args):
        raise RuntimeError("boom")

    monkeypatch.setattr(gsc, "guardian_skills_crud", boom)
    monkeypatch.setattr(gsc.demisto, "args", lambda: {"op": "create", "name": "x"})

    errors = []
    monkeypatch.setattr(gsc, "return_error", lambda msg: errors.append(msg), raising=False)

    gsc.main()

    assert len(errors) == 1
    assert "unexpectedly" in errors[0]
    assert "boom" in errors[0]
