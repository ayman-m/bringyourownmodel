import json

import GuardianSeedContent as gsc


# --- test fixtures ------------------------------------------------------------


def _multi_command_stub(handlers):
    """Fake demisto.executeCommand dispatching by command name to a
    {command_name: fn(args) -> entries} map. Raises on an unhandled command
    so a test can't silently pass over an unexpected call -- mirrors
    GuardianBootstrap_test.py's identically-named helper.
    """

    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command: {} {}".format(command, args))
        return handlers[command](args)

    return fake_execute


def _not_found(args):
    return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(args.get("listName"))}]


def _present(contents_by_list, default_contents="[]"):
    """A getList fake that returns per-list contents from a dict, falling
    back to `default_contents` for any list name not explicitly listed."""

    def handler(args):
        name = args.get("listName")
        return [{"Type": 1, "Contents": contents_by_list.get(name, default_contents)}]

    return handler


def _capturing_create(sink):
    def handler(args):
        sink.setdefault("calls", []).append(dict(args))
        return [{"Type": 1, "Contents": "Done: list {} was created".format(args["listName"])}]

    return handler


def _bootstrap_ok(args):
    """A GuardianBootstrap fake that reports a clean, no-op sweep -- the
    common case (every runtime-mutable List already exists on a previously-
    bootstrapped box). Final-review FIX 3: `guardian_seed_run` now calls
    `GuardianBootstrap` as its first step, so every test that exercises
    `guardian_seed_run`/`main()` needs this command wired, mirroring how
    every other `_multi_command_stub` dict already wires `getList`/
    `createList`.
    """
    return [{"Type": 1, "Contents": "GuardianBootstrap: 0 created, 8 already present, 0 errors."}]


def _bootstrap_error(args):
    return [{"Type": 4, "Contents": "GuardianBootstrap: failed to bootstrap 1 of 8 target List(s): boom"}]


# --- guardian_seed_hash / canonical_json --------------------------------------


def test_hash_is_stable_regardless_of_key_order():
    a = gsc.guardian_seed_hash({"a": 1, "b": 2})
    b = gsc.guardian_seed_hash({"b": 2, "a": 1})
    assert a == b


def test_hash_differs_for_different_content():
    assert gsc.guardian_seed_hash({"a": 1}) != gsc.guardian_seed_hash({"a": 2})


def test_canonical_json_passes_through_raw_strings():
    assert gsc.guardian_seed_canonical_json("hello") == "hello"


# --- guardian_seed_ensure_scalar: fresh box (List genuinely missing) ----------


def test_ensure_scalar_creates_when_missing(monkeypatch):
    sink = {}
    monkeypatch.setattr(
        gsc.demisto, "executeCommand", _multi_command_stub({"getList": _not_found, "createList": _capturing_create(sink)})
    )
    result, record = gsc.guardian_seed_ensure_scalar(
        "guardian_settings", "1.0.0", {"MAX_TICKS": 25}, {}, set(), {}
    )
    assert result["ok"] is True
    assert result["data"]["action"] == "ensured"
    assert record == {"seed_version": "1.0.0", "content_sha256": gsc.guardian_seed_hash({"MAX_TICKS": 25})}
    assert json.loads(sink["calls"][0]["listData"]) == {"MAX_TICKS": 25}


# --- guardian_seed_ensure_scalar: first-run baseline adoption -----------------


def test_ensure_scalar_adopts_baseline_on_first_look_without_writing(monkeypatch):
    """The core "never clobber pack-authored content" case: a List already
    holds real (e.g. pack-delivered) content and this script has NEVER
    tracked it before -- it must be adopted as the baseline, untouched."""
    sink = {}
    real_policy = {"default_tier": "allow", "commands": {"ip": "allow"}}
    monkeypatch.setattr(
        gsc.demisto,
        "executeCommand",
        _multi_command_stub(
            {"getList": _present({"guardian_policy": json.dumps(real_policy)}), "createList": _capturing_create(sink)}
        ),
    )
    result, record = gsc.guardian_seed_ensure_scalar(
        "guardian_policy", "1.0.0", {"_guardian_seed_placeholder": True}, {}, set(), {}
    )
    assert result["ok"] is True
    assert result["data"]["action"] == "left_alone"
    assert record == {"seed_version": "1.0.0", "content_sha256": gsc.guardian_seed_hash(real_policy)}
    assert sink == {}  # createList never called -- the real content was never touched


# --- guardian_seed_ensure_scalar: re-run is a true no-op ----------------------


def test_ensure_scalar_rerun_with_unchanged_content_and_version_is_noop(monkeypatch):
    sink = {}
    real_policy = {"default_tier": "allow"}
    monkeypatch.setattr(
        gsc.demisto,
        "executeCommand",
        _multi_command_stub(
            {"getList": _present({"guardian_policy": json.dumps(real_policy)}), "createList": _capturing_create(sink)}
        ),
    )
    recorded = {"guardian_policy": {"seed_version": "1.0.0", "content_sha256": gsc.guardian_seed_hash(real_policy)}}
    result, record = gsc.guardian_seed_ensure_scalar(
        "guardian_policy", "1.0.0", {"_guardian_seed_placeholder": True}, recorded, set(), {}
    )
    assert result["data"]["action"] == "left_alone"
    assert record == recorded["guardian_policy"]
    assert sink == {}


# --- guardian_seed_ensure_scalar: safe reseed on a version bump ---------------


def test_ensure_scalar_safely_reseeds_when_unchanged_and_newer_version_available(monkeypatch):
    sink = {}
    old_default = {"MAX_TICKS": 25}
    new_default = {"MAX_TICKS": 30}
    monkeypatch.setattr(
        gsc.demisto,
        "executeCommand",
        _multi_command_stub(
            {"getList": _present({"guardian_settings": json.dumps(old_default)}), "createList": _capturing_create(sink)}
        ),
    )
    recorded = {"guardian_settings": {"seed_version": "1.0.0", "content_sha256": gsc.guardian_seed_hash(old_default)}}
    snapshots = {}
    result, record = gsc.guardian_seed_ensure_scalar(
        "guardian_settings", "2.0.0", new_default, recorded, set(), snapshots
    )
    assert result["data"]["action"] == "ensured"
    assert record["seed_version"] == "2.0.0"
    assert record["content_sha256"] == gsc.guardian_seed_hash(new_default)
    assert json.loads(sink["calls"][0]["listData"]) == new_default
    # the OUTGOING value was snapshotted before being overwritten
    assert "guardian_settings" in snapshots
    assert snapshots["guardian_settings"]["content_sha256"] == gsc.guardian_seed_hash(old_default)


# --- guardian_seed_ensure_scalar: operator-edited drift -- snapshot, NEVER overwrite


def test_ensure_scalar_snapshots_but_never_overwrites_drifted_content(monkeypatch):
    sink = {}
    seeded_default = {"MAX_TICKS": 25}
    operator_edited = {"MAX_TICKS": 999, "operator_note": "raised for an incident response drill"}
    monkeypatch.setattr(
        gsc.demisto,
        "executeCommand",
        _multi_command_stub(
            {"getList": _present({"guardian_settings": json.dumps(operator_edited)}), "createList": _capturing_create(sink)}
        ),
    )
    recorded = {
        "guardian_settings": {"seed_version": "1.0.0", "content_sha256": gsc.guardian_seed_hash(seeded_default)}
    }
    snapshots = {}
    result, record = gsc.guardian_seed_ensure_scalar(
        "guardian_settings", "1.0.0", seeded_default, recorded, set(), snapshots
    )
    assert result["data"]["action"] == "snapshotted"
    assert sink == {}  # createList NEVER called -- the operator's edit is never clobbered
    assert record["content_sha256"] == gsc.guardian_seed_hash(operator_edited)
    assert record["seed_version"] == "1.0.0"  # still "behind" -- not bumped to a version it never actually got
    snap = snapshots["guardian_settings"]
    assert snap["content_sha256"] == gsc.guardian_seed_hash(operator_edited)
    assert json.loads(snap["content_preview"]) == operator_edited


def test_ensure_scalar_drift_is_not_re_snapshotted_on_a_second_identical_run(monkeypatch):
    """Once drift has been recorded once, an unchanged-since-then re-run
    must be a no-op (not an endless re-snapshot loop)."""
    sink = {}
    seeded_default = {"MAX_TICKS": 25}
    operator_edited = {"MAX_TICKS": 999}
    monkeypatch.setattr(
        gsc.demisto,
        "executeCommand",
        _multi_command_stub(
            {"getList": _present({"guardian_settings": json.dumps(operator_edited)}), "createList": _capturing_create(sink)}
        ),
    )
    # `recorded` already reflects the drifted hash from a PRIOR run (as
    # guardian_seed_ensure_scalar itself would have written it).
    recorded = {
        "guardian_settings": {"seed_version": "1.0.0", "content_sha256": gsc.guardian_seed_hash(operator_edited)}
    }
    snapshots = {}
    result, record = gsc.guardian_seed_ensure_scalar(
        "guardian_settings", "1.0.0", seeded_default, recorded, set(), snapshots
    )
    assert result["data"]["action"] == "left_alone"
    assert snapshots == {}  # nothing new to snapshot -- content matches the already-recorded (drifted) baseline
    assert sink == {}


# --- guardian_seed_ensure_scalar: denylist ------------------------------------


def test_ensure_scalar_denylisted_target_is_skipped_entirely(monkeypatch):
    def boom(args):
        raise AssertionError("should never call getList for a denylisted target")

    monkeypatch.setattr(gsc.demisto, "executeCommand", _multi_command_stub({"getList": boom}))
    result, record = gsc.guardian_seed_ensure_scalar(
        "guardian_persona", "1.0.0", {"persona": "x"}, {}, {"guardian_persona"}, {}
    )
    assert result["ok"] is True
    assert result["data"]["action"] == "denylisted"
    assert record is None


# --- guardian_seed_ensure_array: merge semantics ------------------------------


def test_ensure_array_creates_when_missing_with_seed_entries(monkeypatch):
    sink = {}
    monkeypatch.setattr(
        gsc.demisto, "executeCommand", _multi_command_stub({"getList": _not_found, "createList": _capturing_create(sink)})
    )
    seed_entries = ({"name": "built_in_skill", "body": "..."},)
    result, record = gsc.guardian_seed_ensure_array(
        "guardian_skills_crud_index", "1.0.0", "name", seed_entries, {}, set(), {}
    )
    assert result["data"]["action"] == "ensured"
    assert result["data"]["added"] == ["built_in_skill"]
    assert json.loads(sink["calls"][0]["listData"]) == list(seed_entries)
    assert record["seeded_names"] == ["built_in_skill"]


def test_ensure_array_never_touches_operator_authored_entries(monkeypatch):
    """An operator-added custom skill entry (via GuardianSkillsCRUD) must
    survive a merge untouched, alongside the newly-added seed entry."""
    sink = {}
    operator_entry = {"name": "my_custom_skill", "body": "operator wrote this"}
    monkeypatch.setattr(
        gsc.demisto,
        "executeCommand",
        _multi_command_stub(
            {
                "getList": _present({"guardian_skills_crud_index": json.dumps([operator_entry])}),
                "createList": _capturing_create(sink),
            }
        ),
    )
    seed_entries = ({"name": "built_in_skill", "body": "seed body"},)
    result, record = gsc.guardian_seed_ensure_array(
        "guardian_skills_crud_index", "1.0.0", "name", seed_entries, {}, set(), {}
    )
    assert result["data"]["action"] == "ensured"
    written = json.loads(sink["calls"][0]["listData"])
    assert operator_entry in written
    assert {"name": "built_in_skill", "body": "seed body"} in written
    assert len(written) == 2


def test_ensure_array_skips_already_present_seed_entry_by_key(monkeypatch):
    sink = {}
    already_there = {"name": "built_in_skill", "body": "was already there, maybe operator-edited"}
    monkeypatch.setattr(
        gsc.demisto,
        "executeCommand",
        _multi_command_stub(
            {
                "getList": _present({"guardian_skills_crud_index": json.dumps([already_there])}),
                "createList": _capturing_create(sink),
            }
        ),
    )
    seed_entries = ({"name": "built_in_skill", "body": "seed default -- should NOT replace the existing entry"},)
    result, record = gsc.guardian_seed_ensure_array(
        "guardian_skills_crud_index", "1.0.0", "name", seed_entries, {}, set(), {}
    )
    assert result["data"]["action"] == "left_alone"
    assert sink == {}  # nothing to add -- never writes


def test_ensure_array_honors_deleted_skills_denylist(monkeypatch):
    """A seed entry whose name an operator deleted must NOT be resurrected,
    even though it's absent from the current List (which would otherwise
    look identical to "never seeded")."""
    sink = {}
    monkeypatch.setattr(
        gsc.demisto, "executeCommand", _multi_command_stub({"getList": _not_found, "createList": _capturing_create(sink)})
    )
    seed_entries = ({"name": "deleted_skill", "body": "x"}, {"name": "keep_me", "body": "y"})
    result, record = gsc.guardian_seed_ensure_array(
        "guardian_skills_crud_index", "1.0.0", "name", seed_entries, {}, {"deleted_skill"}, {}
    )
    assert result["data"]["action"] == "ensured"
    assert result["data"]["added"] == ["keep_me"]
    assert result["data"]["skipped_denylisted"] == ["deleted_skill"]


# --- guardian_seed_run: full sweep --------------------------------------------


def test_seed_run_fresh_box_ensures_everything_and_persists_version_doc(monkeypatch):
    sink = {}
    monkeypatch.setattr(
        gsc.demisto,
        "executeCommand",
        _multi_command_stub(
            {"getList": _not_found, "createList": _capturing_create(sink), "GuardianBootstrap": _bootstrap_ok}
        ),
    )
    result = gsc.guardian_seed_run()
    assert result["ok"] is True
    # Every scalar target is genuinely missing -> ensured. The one array
    # target ships with an EMPTY seed-entries table today (a documented
    # deferral -- see the module docstring), so there's nothing to add even
    # though the List itself is absent -> left_alone, not ensured.
    assert set(result["data"]["ensured"]) == {name for name, _, _ in gsc.GUARDIAN_SEED_SCALAR_TARGETS}
    assert result["data"]["left_alone"] == ["guardian_skills_crud_index"]
    assert result["data"]["snapshotted"] == []
    assert result["data"]["errors"] == []
    version_write = json.loads(sink["calls"][-1]["listData"])
    assert version_write["version"] == gsc.GUARDIAN_SEED_CONTENT_VERSION
    assert set(version_write["scalar_targets"]) == {name for name, _, _ in gsc.GUARDIAN_SEED_SCALAR_TARGETS}


def test_seed_run_rerun_on_already_seeded_box_is_a_full_noop(monkeypatch):
    """The literal acceptance criterion for this task: run once (fresh),
    then run again against the resulting state -- the second run must be a
    pure no-op (every target left_alone, no createList calls at all)."""
    store = {}

    def handle_get_list(args):
        name = args["listName"]
        if name in store:
            return [{"Type": 1, "Contents": store[name]}]
        return _not_found(args)

    def handle_create_list(args):
        store[args["listName"]] = args["listData"]
        return [{"Type": 1, "Contents": "Done"}]

    monkeypatch.setattr(
        gsc.demisto,
        "executeCommand",
        _multi_command_stub(
            {"getList": handle_get_list, "createList": handle_create_list, "GuardianBootstrap": _bootstrap_ok}
        ),
    )

    first = gsc.guardian_seed_run()
    assert first["ok"] is True
    # The array target's empty seed table means it's "left_alone" (nothing
    # to add) even on this first run -- see the fresh-box test above.
    assert len(first["data"]["ensured"]) == len(gsc.GUARDIAN_SEED_SCALAR_TARGETS)
    assert first["data"]["left_alone"] == ["guardian_skills_crud_index"]

    second = gsc.guardian_seed_run()
    assert second["ok"] is True
    assert second["data"]["ensured"] == []
    assert second["data"]["snapshotted"] == []
    assert second["data"]["errors"] == []
    assert set(second["data"]["left_alone"]) == {name for name, _, _ in gsc.GUARDIAN_SEED_SCALAR_TARGETS} | {
        name for name, _, _, _ in gsc.GUARDIAN_SEED_ARRAY_TARGETS
    }


def test_seed_run_tolerates_bootstrap_placeholder_version_doc(monkeypatch):
    """guardian_seed_version may already exist holding ONLY
    GuardianBootstrap's own placeholder default ({"version": "0.0.1"}) --
    this must be treated as "nothing tracked yet", never a crash."""
    sink = {}

    def handle_get_list(args):
        if args["listName"] == "guardian_seed_version":
            return [{"Type": 1, "Contents": json.dumps({"version": "0.0.1"})}]
        return _not_found(args)

    monkeypatch.setattr(
        gsc.demisto,
        "executeCommand",
        _multi_command_stub(
            {"getList": handle_get_list, "createList": _capturing_create(sink), "GuardianBootstrap": _bootstrap_ok}
        ),
    )
    result = gsc.guardian_seed_run()
    assert result["ok"] is True
    # every scalar target was genuinely absent -> ensured; the placeholder
    # version doc itself never caused an error/crash.
    assert len(result["data"]["ensured"]) == len(gsc.GUARDIAN_SEED_SCALAR_TARGETS)


def test_seed_run_is_best_effort_across_targets(monkeypatch):
    def handle_get_list(args):
        if args["listName"] == "guardian_policy":
            return [{"Type": 4, "Contents": "Error: connection reset by peer"}]
        return _not_found(args)

    sink = {}
    monkeypatch.setattr(
        gsc.demisto,
        "executeCommand",
        _multi_command_stub(
            {"getList": handle_get_list, "createList": _capturing_create(sink), "GuardianBootstrap": _bootstrap_ok}
        ),
    )
    result = gsc.guardian_seed_run()
    assert result["ok"] is False
    assert len(result["data"]["errors"]) == 1
    assert result["data"]["errors"][0]["list_name"] == "guardian_policy"
    # every OTHER target still got ensured despite the one failure
    other_targets = {name for name, _, _ in gsc.GUARDIAN_SEED_SCALAR_TARGETS if name != "guardian_policy"}
    assert other_targets.issubset(set(result["data"]["ensured"]))


# --- Final-review FIX 3: guardian_seed_run also invokes GuardianBootstrap -----


def test_seed_run_invokes_guardian_bootstrap(monkeypatch):
    """The literal FIX 3 acceptance criterion: GuardianSeedContent (which
    already runs at install/upgrade) must ALSO invoke GuardianBootstrap, so
    every genuinely runtime-mutable Guardian List exists at install time
    with no separate operator step."""
    calls = []

    def handle_bootstrap(args):
        calls.append(args)
        return _bootstrap_ok(args)

    monkeypatch.setattr(
        gsc.demisto,
        "executeCommand",
        _multi_command_stub(
            {"getList": _not_found, "createList": _capturing_create({}), "GuardianBootstrap": handle_bootstrap}
        ),
    )

    result = gsc.guardian_seed_run()

    assert result["ok"] is True
    assert len(calls) == 1  # invoked exactly once per sweep


def test_seed_run_records_bootstrap_failure_but_sweep_still_completes(monkeypatch):
    """A GuardianBootstrap failure must be recorded (so the overall `ok`
    reflects it) but must NEVER block this script's own scalar/array sweep
    -- mirrors the "one target's failure never stops the rest" discipline
    this script already applies to its own targets."""
    sink = {}
    errors = []
    monkeypatch.setattr(gsc.demisto, "error", lambda *a: errors.append(" ".join(str(x) for x in a)))
    monkeypatch.setattr(
        gsc.demisto,
        "executeCommand",
        _multi_command_stub(
            {"getList": _not_found, "createList": _capturing_create(sink), "GuardianBootstrap": _bootstrap_error}
        ),
    )

    result = gsc.guardian_seed_run()

    assert result["ok"] is False
    bootstrap_errors = [e for e in result["data"]["errors"] if e["list_name"] == "GuardianBootstrap"]
    assert len(bootstrap_errors) == 1
    assert "boom" in bootstrap_errors[0]["error"]
    assert errors and "boom" in errors[0]
    # every scalar target still got ensured despite GuardianBootstrap's failure
    assert set(result["data"]["ensured"]) == {name for name, _, _ in gsc.GUARDIAN_SEED_SCALAR_TARGETS}


# --- main() --------------------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch):
    monkeypatch.setattr(
        gsc.demisto,
        "executeCommand",
        _multi_command_stub(
            {"getList": _not_found, "createList": _capturing_create({}), "GuardianBootstrap": _bootstrap_ok}
        ),
    )
    captured = {}
    monkeypatch.setattr(gsc, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    gsc.main()

    assert "result" in captured
    assert "ensured" in captured["result"].readable_output
    assert captured["result"].outputs_prefix == "Guardian.SeedContent"


def test_main_calls_return_error_on_partial_failure(monkeypatch):
    def handle_get_list(args):
        return [{"Type": 4, "Contents": "Error: connection reset by peer"}]

    monkeypatch.setattr(
        gsc.demisto,
        "executeCommand",
        _multi_command_stub(
            {"getList": handle_get_list, "createList": _capturing_create({}), "GuardianBootstrap": _bootstrap_ok}
        ),
    )
    errors = []
    monkeypatch.setattr(gsc, "return_error", lambda msg: errors.append(msg), raising=False)
    results = []
    monkeypatch.setattr(gsc, "return_results", lambda cr: results.append(cr), raising=False)

    gsc.main()

    assert errors
    assert not results


def test_main_unexpected_exception_calls_return_error(monkeypatch):
    def boom():
        raise RuntimeError("kaboom")

    monkeypatch.setattr(gsc, "guardian_seed_run", boom)
    errors = []
    monkeypatch.setattr(gsc, "return_error", lambda msg: errors.append(msg), raising=False)

    gsc.main()

    assert errors
    assert "kaboom" in errors[0]
