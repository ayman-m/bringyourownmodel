import json
from pathlib import Path

import pytest

import GuardianToolBridge as gtb


REPO_ROOT = Path(__file__).resolve().parents[4]


def _shipped_list_text(list_name):
    path = REPO_ROOT / "Packs" / "GuardianXSIAM" / "Lists" / "list-{}.json".format(list_name)
    data = json.loads(path.read_text())["data"]
    try:
        data = json.loads(data)
    except ValueError:
        pass
    return json.dumps(data, sort_keys=True) if isinstance(data, (dict, list)) else data


# --- fixtures / test harness --------------------------------------------------

DEFAULT_KILL_SWITCH = {"enabled": False}

DEFAULT_DENYLIST = {
    "protected_lists": [
        "guardian_policy",
        "guardian_tool_allowlist",
        "guardian_tool_denylist",
        "guardian_kill_switch",
    ],
    "denied": [
        "setList:guardian_policy",
        "setList:guardian_tool_allowlist",
        "setList:guardian_tool_denylist",
        "setList:guardian_kill_switch",
        "addToList:guardian_policy",
        "addToList:guardian_tool_allowlist",
        "addToList:guardian_tool_denylist",
        "addToList:guardian_kill_switch",
        "setIntegration",
        "demisto-api-delete",
    ],
}

DEFAULT_POLICY = {
    "setIncident": "require_approval",
    "closeInvestigation": "deny",
    # Task 4.4 -- mirrors the real guardian_policy: xdr-endpoint-tag-add is
    # require_approval (like every other state-changing command), same as
    # xdr-isolate-endpoint below is destructive-tier-and-require_approval.
    "xdr-endpoint-tag-add": "require_approval",
    "xdr-isolate-endpoint": "require_approval",
}

# Mirrors (a subset of) the real pack-seeded guardian_tool_allowlist's
# {"commands": [...]} shape -- read-only enrichment commands that are
# curated onto the allowlist but deliberately NOT in guardian_policy at all
# (see guardian_tool_allowlist's own "never add a state-changing command
# here" rule). Used by the Task 1.3 default-deny gate tests below.
DEFAULT_ALLOWLIST = {"commands": ["ip", "whois", "domain", "url", "file", "getList", "getIncidents"]}

DEFAULT_SETTINGS = {"evidence_truncate_bytes": 16384, "evidence_head_tail_bytes": 4096}

# Task 4.4 -- illustrative fixture for guardian_preapproved (NOT a mirror of
# the real pack-seeded List, which now carries TWO classes -- xdr-endpoint-
# tag-add and GuardianContainmentSimulate; see
# Lists/list-guardian_preapproved.json). Only the xdr-endpoint-tag-add class
# is needed by default here since most tests below exercise that command.
DEFAULT_PREAPPROVED = {
    "classes": [
        {
            "command": "xdr-endpoint-tag-add",
            "arg_constraints": {
                "endpoint_ids": {"required": True},
                "tag": {
                    "required": True,
                    "allowed_values": [
                        "guardian-auto-flagged",
                        "guardian-suspicious-endpoint",
                        "guardian-under-investigation",
                    ],
                },
            },
        }
    ]
}


def _getlist_handler(list_payloads, list_errors):
    def handle(args):
        name = args["listName"]
        if name in list_errors:
            return [{"Type": 4, "Contents": list_errors[name]}]
        if name not in list_payloads:
            raise AssertionError("no fixture wired for getList listName={}".format(name))
        payload = list_payloads[name]
        contents = payload if isinstance(payload, str) else json.dumps(payload)
        return [{"Type": 1, "Contents": contents}]

    return handle


def _install_gates(
    monkeypatch,
    kill_switch=None,
    denylist=None,
    allowlist=None,
    runtime_allowlist=None,
    policy=None,
    settings=None,
    approvals_ledger=None,
    preapproved=None,
    incident=None,
    list_errors=None,
    command_handlers=None,
):
    """Wires demisto.executeCommand to answer getList (per-List fixture, or
    a "not found"/error Contents from `list_errors`), GuardianAuditWrite
    (captured into the returned sink), a REAL, working
    guardian_approvals_ledger read/write/bootstrap pipeline (getList/setList/
    createList all operate on the SAME mutable `list_payloads["guardian_
    approvals_ledger"]` object, so a test can create-then-consume an
    approval across two `guardian_tool_bridge_run` calls exactly like the
    real ledger persists across two real bridge invocations), `addEntries`
    (captured into the returned sink) and `GetTime` (a fixed ISO stamp), and
    any tool commands supplied via `command_handlers` -- anything else
    raises AssertionError so a test can't silently pass over an unexpected
    dispatch (e.g. code proceeding to execute when it should have
    short-circuited).

    :return: the audit sink dict, `{"calls": [...], "notes": [...], "ledger":
        <live list_payloads entry>}` -- `calls` gets one entry per
        GuardianAuditWrite invocation, `notes` one per `addEntries` call,
        `ledger` is the SAME list object `guardian_approvals_ledger` reads/
        writes operate on (so a test can inspect it directly after a call).
    """
    list_payloads = {
        "guardian_kill_switch": DEFAULT_KILL_SWITCH if kill_switch is None else kill_switch,
        "guardian_tool_denylist": DEFAULT_DENYLIST if denylist is None else denylist,
        "guardian_tool_allowlist": DEFAULT_ALLOWLIST if allowlist is None else allowlist,
        "guardian_tool_allowlist_runtime": (
            (DEFAULT_ALLOWLIST if allowlist is None else allowlist)
            if runtime_allowlist is None
            else runtime_allowlist
        ),
        "guardian_policy": DEFAULT_POLICY if policy is None else policy,
        "guardian_settings": DEFAULT_SETTINGS if settings is None else settings,
        "guardian_approvals_ledger": [] if approvals_ledger is None else approvals_ledger,
        "guardian_preapproved": DEFAULT_PREAPPROVED if preapproved is None else preapproved,
    }
    list_errors = list_errors or {}
    if "guardian_tool_allowlist" in list_errors and "guardian_tool_allowlist_runtime" not in list_errors:
        # Legacy fixture intent maps to the active runtime boundary after the
        # allowlist migration.
        list_errors["guardian_tool_allowlist_runtime"] = list_errors["guardian_tool_allowlist"]

    audit_sink = {"calls": [], "notes": [], "ledger": list_payloads["guardian_approvals_ledger"]}

    def handle_audit(args):
        audit_sink["calls"].append(args)
        return [{"Type": 1, "Contents": "Guardian audit row written: action=x status=y target=z"}]

    def handle_add_entries(args):
        audit_sink["notes"].append(args)
        return [{"Type": 1, "Contents": "Done"}]

    def _replace_list_payload(name, new_value):
        # Preserve the OLD object's identity when both old/new are lists --
        # `audit["ledger"]` (and any test's own captured reference) is a
        # snapshot of the list OBJECT at `_install_gates` call time; a test
        # that then does `audit["ledger"].append(...)`/inspects it after a
        # `guardian_tool_bridge_run` call needs that same object to keep
        # reflecting reality, not silently go stale because a `setList`
        # rebound the dict entry to a brand-new list.
        old = list_payloads.get(name)
        if isinstance(old, list) and isinstance(new_value, list):
            old[:] = new_value
            list_payloads[name] = old
        else:
            list_payloads[name] = new_value

    def handle_set_list(args):
        _replace_list_payload(args["listName"], json.loads(args["listData"]))
        return [{"Type": 1, "Contents": "Done: list updated"}]

    def handle_create_list(args):
        name = args["listName"]
        _replace_list_payload(name, json.loads(args["listData"]))
        list_errors.pop(name, None)
        return [{"Type": 1, "Contents": "Done: list created"}]

    def handle_get_time(args):
        return [{"Type": 1, "Contents": "2026-07-05T12:00:00Z"}]

    handlers = {
        "getList": _getlist_handler(list_payloads, list_errors),
        "GuardianAuditWrite": handle_audit,
        "setList": handle_set_list,
        "createList": handle_create_list,
        "addEntries": handle_add_entries,
        "GetTime": handle_get_time,
    }
    if command_handlers:
        handlers.update(command_handlers)

    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command dispatched: {} {}".format(command, args))
        return handlers[command](args)

    monkeypatch.setattr(gtb.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(gtb.demisto, "context", lambda: {})
    monkeypatch.setattr(gtb.demisto, "setContext", lambda path, value: {"status": True})
    monkeypatch.setattr(gtb.demisto, "incident", lambda: dict(incident) if incident else {})
    monkeypatch.setattr(gtb.demisto, "error", lambda msg: None)

    return audit_sink


def _ok_handler(contents):
    return lambda args: [{"Type": 1, "Contents": contents}]


def _error_handler(contents):
    return lambda args: [{"Type": 4, "Contents": contents}]


# --- Step 1: kill switch (the one fail-open gate) -----------------------------


def test_run_halted_when_kill_switch_enabled(monkeypatch):
    audit = _install_gates(monkeypatch, kill_switch={"enabled": True})

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"})

    assert result["ok"] is True  # the bridge itself completed a decision
    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "halted"
    assert tool_result["ok"] is False
    assert "kill switch" in tool_result["error"]
    assert len(audit["calls"]) == 1
    assert audit["calls"][0]["status"] == "halted"
    assert audit["calls"][0]["action"] == "ip"
    assert "kill_switch_note" in audit["calls"][0]["detail"]  # key always present, None when there's nothing to say


def test_run_proceeds_when_kill_switch_unreadable_fail_open(monkeypatch):
    logged = []
    audit = _install_gates(
        monkeypatch,
        list_errors={"guardian_kill_switch": "Item not found (8) on list [...]"},
        policy={"ip": "allow"},
        command_handlers={"ip": _ok_handler({"score": 1})},
    )
    monkeypatch.setattr(gtb.demisto, "error", lambda msg: logged.append(msg))

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "ok"  # proceeded past the kill switch
    assert any("kill_switch" in m.lower() or "kill switch" in m.lower() for m in logged)


def test_check_kill_switch_enabled_direct(monkeypatch):
    _install_gates(monkeypatch, kill_switch={"enabled": True})
    result = gtb.guardian_bridge_check_kill_switch()
    assert result == {"halted": True, "note": None}


def test_check_kill_switch_malformed_shape_treated_as_not_halted(monkeypatch):
    logged = []
    _install_gates(monkeypatch, kill_switch=["not", "a", "dict"])
    monkeypatch.setattr(gtb.demisto, "error", lambda msg: logged.append(msg))

    result = gtb.guardian_bridge_check_kill_switch()

    assert result["halted"] is False
    assert result["note"] is not None
    assert logged


# --- FIX 2 (final-review hardening): kill switch fails CLOSED in bypass mode --


def test_run_halts_when_kill_switch_unreadable_in_bypass_mode(monkeypatch):
    """SECURITY-CRITICAL: unlike manual mode, an unreadable kill switch in
    bypass mode must HALT the call, never proceed -- autonomous
    pre-approved auto-execution must not keep running unattended while the
    kill switch itself can't be read."""
    logged = []
    audit = _install_gates(
        monkeypatch,
        incident={"CustomFields": {"guardianapprovalmode": "bypass"}},
        list_errors={"guardian_kill_switch": "Item not found (8) on list [...]"},
        command_handlers={"xdr-endpoint-tag-add": lambda args: [{"Type": 1, "Contents": "done"}]},
    )
    monkeypatch.setattr(gtb.demisto, "error", lambda msg: logged.append(msg))

    result = gtb.guardian_tool_bridge_run(
        "xdr-endpoint-tag-add", {"endpoint_ids": "ep-1", "tag": "guardian-auto-flagged"}
    )

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "halted"
    assert tool_result["ok"] is False
    assert len(audit["calls"]) == 1
    assert audit["calls"][0]["status"] == "halted"
    assert any("bypass" in m.lower() for m in logged)
    # The bypass-mode fail-closed rationale must land in the audit trail, not
    # just the server log -- SEC-08 (this was previously dropped on this one
    # branch only, every other decision path already threaded it through).
    assert audit["calls"][0]["detail"]["kill_switch_note"] is not None
    assert "bypass" in audit["calls"][0]["detail"]["kill_switch_note"].lower()


def test_run_proceeds_when_kill_switch_unreadable_in_manual_mode_is_unchanged(monkeypatch):
    """The pre-existing fail-open behavior in manual mode (the default) is
    unchanged by FIX 2 -- only bypass mode flips this gate to fail-closed."""
    audit = _install_gates(
        monkeypatch,
        incident={"CustomFields": {"guardianapprovalmode": "manual"}},
        list_errors={"guardian_kill_switch": "Item not found (8) on list [...]"},
        policy={"ip": "allow"},
        command_handlers={"ip": _ok_handler({"score": 1})},
    )

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"})

    assert result["data"]["tool_result"]["status"] == "ok"
    assert len(audit["calls"]) == 1
    assert audit["calls"][0]["status"] == "ok"
    assert audit["calls"][0]["detail"]["risk_tier"] == "soft"
    assert audit["calls"][0]["detail"]["would_require_approval"] is False


def test_check_kill_switch_unreadable_direct_bypass_mode_halts(monkeypatch):
    logged = []
    audit = _install_gates(
        monkeypatch,
        incident={"CustomFields": {"guardianapprovalmode": "bypass"}},
        list_errors={"guardian_kill_switch": "connection refused"},
    )
    monkeypatch.setattr(gtb.demisto, "error", lambda msg: logged.append(msg))

    result = gtb.guardian_bridge_check_kill_switch()

    assert result["halted"] is True
    assert result["note"] is not None
    assert logged


def test_check_kill_switch_malformed_shape_bypass_mode_halts(monkeypatch):
    logged = []
    _install_gates(
        monkeypatch,
        incident={"CustomFields": {"guardianapprovalmode": "bypass"}},
        kill_switch=["not", "a", "dict"],
    )
    monkeypatch.setattr(gtb.demisto, "error", lambda msg: logged.append(msg))

    result = gtb.guardian_bridge_check_kill_switch()

    assert result["halted"] is True
    assert result["note"] is not None
    assert logged


# --- Step 2: denylist (the security boundary; fail-closed) -------------------


def test_run_denied_bare_denylist_command(monkeypatch):
    audit = _install_gates(monkeypatch, denylist={"denied": ["demisto-api-delete"], "protected_lists": []})

    result = gtb.guardian_tool_bridge_run("demisto-api-delete", {})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "bare guardian_tool_denylist" in tool_result["error"]
    assert len(audit["calls"]) == 1
    assert audit["calls"][0]["status"] == "denied"


def test_run_denied_arg_level_self_escape_explicit_rule(monkeypatch):
    """The exact brief scenario: setList targeting guardian_policy must be
    denied by the arg-level "setList:guardian_policy" denylist entry."""
    audit = _install_gates(monkeypatch, denylist={"denied": ["setList:guardian_policy"], "protected_lists": []})

    result = gtb.guardian_tool_bridge_run("setList", {"listName": "guardian_policy", "listData": "x"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "guardian_policy" in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_run_denied_arg_level_self_escape_via_protected_lists_cross_check(monkeypatch):
    """Even without an explicit "addToList:guardian_kill_switch" entry in
    `denied`, the generic protected_lists cross-check must still deny an
    addToList call targeting a List named in `protected_lists`."""
    audit = _install_gates(
        monkeypatch, denylist={"denied": [], "protected_lists": ["guardian_kill_switch"]}
    )

    result = gtb.guardian_tool_bridge_run("addToList", {"listName": "guardian_kill_switch", "listData": "x"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "protected_list" in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_shipped_denylist_protects_the_agents_own_prompt_shield_lists():
    """SEC-96: guardian_prompt_tail/guardian_prompt_head/guardian_persona/
    guardian_settings/guardian_skills_index/guardian_skills_crud_index used
    to be absent from protected_lists -- a model-emitted setList/addToList
    against any of them fell through to guardian_policy's generic
    setList/addToList=require_approval tier instead of being denied outright,
    one human approval click away from rewriting the agent's own system
    prompt, persona, tuning knobs, or skill index. Pin that the shipped
    denylist now protects all six, so a future edit can't silently drop one."""
    shipped = json.loads(_shipped_list_text("guardian_tool_denylist"))
    protected = set(shipped["protected_lists"])
    assert {
        "guardian_prompt_tail",
        "guardian_prompt_head",
        "guardian_persona",
        "guardian_settings",
        "guardian_skills_index",
        "guardian_skills_crud_index",
    } <= protected


def test_run_denies_setlist_against_each_prompt_shield_list(monkeypatch):
    """End-to-end: the real shipped protected_lists set (not a hand-built
    test fixture) actually denies a setList against each of the six -- proves
    the fix works through the bridge's real cross-check, not just that the
    List names are present in the JSON."""
    shipped = json.loads(_shipped_list_text("guardian_tool_denylist"))
    for list_name in (
        "guardian_prompt_tail",
        "guardian_prompt_head",
        "guardian_persona",
        "guardian_settings",
        "guardian_skills_index",
        "guardian_skills_crud_index",
    ):
        audit = _install_gates(monkeypatch, denylist=shipped)
        result = gtb.guardian_tool_bridge_run("setList", {"listName": list_name, "listData": "{}"})
        tool_result = result["data"]["tool_result"]
        assert tool_result["status"] == "denied", list_name
        assert "protected_list" in tool_result["error"]
        assert len(audit["calls"]) == 1


def test_run_denied_when_agent_targets_runtime_tool_registry_list(monkeypatch):
    audit = _install_gates(
        monkeypatch,
        denylist={"denied": [], "protected_lists": []},
        policy={"setList": "allow"},
    )

    result = gtb.guardian_tool_bridge_run(
        "setList", {"listName": "guardian_tool_allowlist_runtime", "listData": '{"commands": ["bad"]}'}
    )

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "protected_list" in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_run_setlist_to_unprotected_list_is_not_denied(monkeypatch):
    """setList targeting a List that is NOT protected must reach the policy
    check (and here, execute), proving the denylist rule is scoped, not a
    blanket ban on setList."""
    audit = _install_gates(
        monkeypatch,
        denylist={"denied": ["setList:guardian_policy"], "protected_lists": ["guardian_policy"]},
        policy={"setList": "allow"},
        command_handlers={"setList": _ok_handler("Done: list updated")},
    )

    result = gtb.guardian_tool_bridge_run("setList", {"listName": "some_other_list", "listData": "y"})

    assert result["data"]["tool_result"]["status"] == "ok"


def test_run_denied_createlist_targeting_protected_list_via_cross_check(monkeypatch):
    """The self-escape hole this fix closes: `createList` CREATES-OR-
    OVERWRITES, so a `createList` call against the real
    `guardian_tool_denylist` (with valid-but-empty content) would silently
    disarm this entire security boundary if `createList` weren't in
    `GUARDIAN_LIST_MUTATING_COMMANDS`. No explicit `createList:...` entry in
    `denied` -- this must be caught by the generic `protected_lists`
    cross-check alone."""
    audit = _install_gates(
        monkeypatch, denylist={"denied": [], "protected_lists": ["guardian_tool_denylist"]}
    )

    result = gtb.guardian_tool_bridge_run(
        "createList", {"listName": "guardian_tool_denylist", "listData": '{"denied": []}'}
    )

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "protected_list" in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_run_denied_deletelist_targeting_protected_list_via_cross_check(monkeypatch):
    """Same self-escape shape as createList, from the deletion side --
    removing a protected control-plane List out from under the bridge is
    just as much a self-escape as overwriting it."""
    audit = _install_gates(
        monkeypatch, denylist={"denied": [], "protected_lists": ["guardian_policy"]}
    )

    result = gtb.guardian_tool_bridge_run("deleteList", {"listName": "guardian_policy"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "protected_list" in tool_result["error"]
    assert len(audit["calls"]) == 1


# --- Task 3.1 security-review fix (FIX 1): the security ledgers themselves
# (guardian_approvals_ledger, guardian_audit) must be exactly as tamper-proof
# as the config Lists -- both are non-system, runtime-writable Lists (by
# design, so the harness can bootstrap/write them; see the
# xsoar-content-engineering skill's List gotcha #22), which is exactly what
# made them writable by a model-emitted setList/addToList/createList/
# deleteList call too, before `protected_lists` grew these two entries. These
# tests mirror the REAL, updated `Lists/list-guardian_tool_denylist.json`
# `protected_lists` array (not just an ad-hoc single-entry fixture) so a
# future accidental removal of either entry from the real pack file would
# show up as a meaningful assertion here, not just "some list got denied".
_PROTECTED_LISTS_WITH_LEDGERS = [
    "guardian_policy",
    "guardian_tool_allowlist",
    "guardian_tool_denylist",
    "guardian_kill_switch",
    "guardian_approvals_ledger",
    "guardian_audit",
]


def test_run_denied_setlist_targeting_approvals_ledger_via_cross_check(monkeypatch):
    """Forging the approvals ledger (e.g. writing a fake 'approved' row
    directly instead of going through a real human !guardian-approve) must
    be denied -- a model-emitted setList against guardian_approvals_ledger
    is exactly as impossible as one against guardian_policy."""
    audit = _install_gates(
        monkeypatch, denylist={"denied": [], "protected_lists": _PROTECTED_LISTS_WITH_LEDGERS}
    )

    result = gtb.guardian_tool_bridge_run(
        "setList", {"listName": "guardian_approvals_ledger", "listData": "[]"}
    )

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "protected_list" in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_run_denied_createlist_targeting_audit_via_cross_check(monkeypatch):
    """Wiping the audit trail via createList's create-or-overwrite semantics
    (valid-but-empty content) must be denied -- guardian_audit is exactly as
    protected as guardian_tool_denylist."""
    audit = _install_gates(
        monkeypatch, denylist={"denied": [], "protected_lists": _PROTECTED_LISTS_WITH_LEDGERS}
    )

    result = gtb.guardian_tool_bridge_run("createList", {"listName": "guardian_audit", "listData": "[]"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "protected_list" in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_run_denied_addtolist_targeting_audit_via_cross_check(monkeypatch):
    audit = _install_gates(
        monkeypatch, denylist={"denied": [], "protected_lists": _PROTECTED_LISTS_WITH_LEDGERS}
    )
    result = gtb.guardian_tool_bridge_run("addToList", {"listName": "guardian_audit", "listData": "x"})
    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "protected_list" in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_run_denied_deletelist_targeting_approvals_ledger_via_cross_check(monkeypatch):
    audit = _install_gates(
        monkeypatch, denylist={"denied": [], "protected_lists": _PROTECTED_LISTS_WITH_LEDGERS}
    )
    result = gtb.guardian_tool_bridge_run("deleteList", {"listName": "guardian_approvals_ledger"})
    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "protected_list" in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_run_createlist_to_unprotected_list_is_not_denied(monkeypatch):
    """Proves the createList rule is scoped to protected lists, not a
    blanket ban -- createList against an ordinary, non-control-plane list
    must still reach policy and execute."""
    audit = _install_gates(
        monkeypatch,
        denylist={"denied": [], "protected_lists": ["guardian_policy"]},
        policy={"createList": "allow"},
        command_handlers={"createList": _ok_handler("Done: list created")},
    )

    result = gtb.guardian_tool_bridge_run("createList", {"listName": "some_other_list", "listData": "{}"})

    assert result["data"]["tool_result"]["status"] == "ok"
    assert len(audit["calls"]) == 1


def test_run_destructive_command_with_allow_policy_still_requires_approval(monkeypatch):
    """Code-level risk must outrank an editable ``allow`` policy entry.

    ``deleteList`` deliberately targets an unprotected List here, so the
    outcome proves the risk gate itself (not the anti-self-escape denylist)
    blocks direct dispatch.
    """
    executed = []
    audit = _install_gates(
        monkeypatch,
        denylist={"denied": [], "protected_lists": ["guardian_policy"]},
        policy={"deleteList": "allow"},
        command_handlers={"deleteList": lambda args: executed.append(args) or _ok_handler("Done: list deleted")(args)},
    )

    result = gtb.guardian_tool_bridge_run("deleteList", {"listName": "some_other_list"})

    assert result["data"]["tool_result"]["status"] == "pending_approval"
    assert executed == []
    detail = audit["calls"][0]["detail"]
    assert detail["risk_tier"] == "destructive"
    assert detail["would_require_approval"] is True


def test_sensitive_argument_name_promotes_allowlisted_call_to_credential_approval(monkeypatch):
    """A credential-shaped argument key gates even a nominally read-only tool.

    The test uses a throwaway value and asserts only the key-derived tier, so
    it also proves the audit row never needs the secret value to explain why
    the request was parked.
    """
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"ip": "allow"},
        command_handlers={"ip": lambda args: executed.append(args) or _ok_handler({"score": 1})(args)},
    )

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1", "api_key": "do-not-log"})

    assert result["data"]["tool_result"]["status"] == "pending_approval"
    assert executed == []
    detail = audit["calls"][0]["detail"]
    assert detail["risk_tier"] == "credential"
    assert detail["would_require_approval"] is True
    assert "do-not-log" not in repr(detail)
    assert len(audit["calls"]) == 1


def test_sensitive_argument_name_nested_one_level_is_not_promoted(monkeypatch):
    """KNOWN, ACCEPTED GAP (pinned, not a bug to silently fix here): the
    sensitive-key check inspects only TOP-LEVEL argument names by design
    (see guardian_bridge_risk_tier's docstring). A credential nested one
    level down is invisible to it -- this test documents the current
    behavior explicitly so a future change to that design is deliberate."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"ip": "allow"},
        command_handlers={"ip": lambda args: executed.append(args) or _ok_handler({"score": 1})(args)},
    )

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1", "lookup": {"api_key": "do-not-log"}})

    assert result["data"]["tool_result"]["status"] == "ok"
    assert executed == [{"ip": "1.1.1.1", "lookup": {"api_key": "do-not-log"}}]
    assert audit["calls"][0]["detail"]["risk_tier"] == "soft"
    assert audit["calls"][0]["detail"]["would_require_approval"] is False


def test_sensitive_argument_key_rename_bypasses_both_risk_tier_and_redaction(monkeypatch):
    """KNOWN, ACCEPTED GAP (pinned, not a bug to silently fix here): a
    top-level key that avoids every GUARDIAN_SENSITIVE_KEY_SUBSTRINGS entry
    (e.g. "cred", which does not contain "credential") is invisible to BOTH
    the risk-tier promotion AND the pre-existing redaction masking, since
    both call the same _guardian_is_sensitive_key helper against the same
    vocabulary. This test pins that the value is neither gated nor masked,
    so a future vocabulary change is deliberate rather than an accidental
    behavior change caught only in production."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"ip": "allow"},
        command_handlers={"ip": lambda args: executed.append(args) or _ok_handler({"score": 1})(args)},
    )

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1", "cred": "sk" "-live-secret"})

    assert result["data"]["tool_result"]["status"] == "ok"
    assert executed == [{"ip": "1.1.1.1", "cred": "sk" "-live-secret"}]
    assert audit["calls"][0]["detail"]["risk_tier"] == "soft"
    # unmasked in the audit target summary too -- documents the shared-vocabulary gap
    assert "sk" "-live-secret" in audit["calls"][0]["target"]


def test_run_denied_arg_level_self_escape_listname_whitespace_stripped(monkeypatch):
    """A leading/trailing space around `listName` must not dodge the
    self-escape check -- Cortex platform resolves list names server-side exactly, so
    ' guardian_policy ' and 'guardian_policy' name the SAME real list."""
    audit = _install_gates(monkeypatch, denylist={"denied": ["setList:guardian_policy"], "protected_lists": []})

    result = gtb.guardian_tool_bridge_run("setList", {"listName": "  guardian_policy  ", "listData": "x"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert len(audit["calls"]) == 1


def test_run_denylist_listname_comparison_is_case_sensitive(monkeypatch):
    """Case-sensitivity is intentional, not a gap: a differently-cased
    listName names a DIFFERENT real Cortex platform list (list names are
    case-sensitive server-side) and must NOT be treated as a match."""
    audit = _install_gates(
        monkeypatch,
        denylist={"denied": ["setList:guardian_policy"], "protected_lists": ["guardian_policy"]},
        policy={"setList": "allow"},
        command_handlers={"setList": _ok_handler("Done: list updated")},
    )

    result = gtb.guardian_tool_bridge_run("setList", {"listName": "Guardian_Policy", "listData": "y"})

    assert result["data"]["tool_result"]["status"] == "ok"
    assert len(audit["calls"]) == 1


def test_run_denied_when_denylist_unreadable_fail_closed(monkeypatch):
    audit = _install_gates(monkeypatch, list_errors={"guardian_tool_denylist": "connection refused"})

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "fail-closed" in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_run_denied_when_denylist_shape_unexpected(monkeypatch):
    audit = _install_gates(monkeypatch, denylist={"not_the_denied_key": []})

    result = gtb.guardian_tool_bridge_run("ip", {})

    assert result["data"]["tool_result"]["status"] == "denied"
    assert "NEEDS_CONTEXT" in result["data"]["tool_result"]["error"]


def test_split_denylist_entries_bare_and_arg_level():
    bare, rules = gtb.guardian_bridge_split_denylist_entries(
        ["setIntegration", "setList:guardian_policy", "addToList:guardian_kill_switch"]
    )
    assert bare == {"setIntegration"}
    assert rules == {("setList", "guardian_policy"), ("addToList", "guardian_kill_switch")}


def test_split_denylist_entries_ignores_malformed_entries():
    bare, rules = gtb.guardian_bridge_split_denylist_entries([None, "", "justcolon:", ":notarget", "ok", 42])
    assert bare == {"ok"}
    assert rules == set()


# --- Step 3: allowlist / default-deny gate (Task 1.3 security-review fix) ----
#
# CONFIRMED CRITICAL vulnerability this section proves is closed: prior to
# this fix, GuardianToolBridge was default-ALLOW -- any command that was
# neither on the bare guardian_tool_denylist NOR a key in guardian_policy
# executed ungated. Since the model can emit off-catalogue tool_calls (never
# offered by GuardianToolCatalogBuilder), a call like
# `demisto-api-post {"uri": "/apikeys", "body": {...}}` would reach Cortex platform's
# entire REST API. These tests prove: (a) such a call is now DENIED, never
# dispatched; (b) a genuine read-only allowlist command still executes;
# (c) an in-policy require_approval command is NOT swept up by the new
# default-deny gate (it still parks to pending_approval, precisely because
# it IS policy-classified); (d) the pre-existing denylist still hard-denies
# regardless of allowlist/policy; (e) an unreadable allowlist fails closed,
# denying even a command that would otherwise have been fine.


def test_run_off_catalogue_command_denied_by_default(monkeypatch):
    """THE fix, exercised end-to-end: `demisto-api-post` is not on
    guardian_tool_allowlist and not a key in guardian_policy (DEFAULT_POLICY
    carries neither) -- it must be denied by the new default-deny gate,
    never reach `demisto.executeCommand`. No `command_handlers` entry is
    wired for `demisto-api-post` at all: if the bridge regressed and tried
    to dispatch it anyway, `_install_gates`'s `fake_execute` would itself
    raise `AssertionError("unexpected command dispatched: ...")` before this
    test's own assertions even ran -- proving non-dispatch, not just
    asserting the returned status."""
    audit = _install_gates(monkeypatch)

    result = gtb.guardian_tool_bridge_run(
        "demisto-api-post", {"uri": "/apikeys", "body": {"name": "backdoor"}}
    )

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert tool_result["ok"] is False
    assert "not on guardian_tool_allowlist" in tool_result["error"]
    assert "not classified in guardian_policy" in tool_result["error"]
    assert len(audit["calls"]) == 1
    assert audit["calls"][0]["status"] == "denied"
    assert audit["calls"][0]["action"] == "demisto-api-post"


def test_run_allowlisted_readonly_command_allowed_despite_absent_from_policy(monkeypatch):
    """Requirement (b): `ip` is on guardian_tool_allowlist and absent from
    guardian_policy entirely -- the default-deny gate must let it through to
    execute, proving the gate is an OR (allowlist OR policy), not an AND."""
    audit = _install_gates(monkeypatch, policy={}, command_handlers={"ip": _ok_handler({"score": 1})})

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "ok"
    assert tool_result["ok"] is True
    assert len(audit["calls"]) == 1


def test_run_policy_known_require_approval_not_default_denied(monkeypatch):
    """Requirement (c): `setIncident` is NOT on guardian_tool_allowlist
    (explicitly emptied here) but IS a guardian_policy key
    (`require_approval`) -- it must still park to `pending_approval`, NOT
    fall into the new default-deny branch. Proves the gate is scoped to
    "on neither List", not an accidental blanket tightening of every
    policy-absent-from-allowlist command."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        allowlist={"commands": []},
        policy={"setIncident": "require_approval"},
        command_handlers={"setIncident": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )

    result = gtb.guardian_tool_bridge_run("setIncident", {"id": "1"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "pending_approval"
    assert tool_result["ok"] is False
    assert executed == []
    assert len(audit["calls"]) == 1
    assert audit["calls"][0]["status"] == "pending_approval"


def test_run_denylist_still_wins_over_allowlist_and_policy(monkeypatch):
    """Requirement (d): the pre-existing denylist is still checked first and
    still hard-denies, regardless of what the (new) allowlist gate or
    policy would otherwise say -- proves Part 2's defense-in-depth denylist
    additions (demisto-api-post et al.) are a real, independent second
    layer, not merely redundant with the default-deny gate."""
    audit = _install_gates(
        monkeypatch,
        denylist={"denied": ["demisto-api-post"], "protected_lists": []},
        allowlist={"commands": ["demisto-api-post"]},  # even if hypothetically allowlisted...
        policy={"demisto-api-post": "allow"},  # ...and hypothetically policy-tiered allow...
    )

    result = gtb.guardian_tool_bridge_run("demisto-api-post", {"uri": "/apikeys", "body": {}})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "bare guardian_tool_denylist" in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_run_denied_when_allowlist_unreadable_fail_closed(monkeypatch):
    """Requirement (e): an unreadable guardian_tool_allowlist must fail
    CLOSED -- denying even `ip`, a command that would otherwise have
    executed cleanly, and WITHOUT ever consulting guardian_policy (mirrors
    the denylist's own unconditional fail-closed short-circuit)."""
    audit = _install_gates(monkeypatch, list_errors={"guardian_tool_allowlist": "connection refused"})

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "fail-closed" in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_run_denied_when_allowlist_shape_unexpected(monkeypatch):
    audit = _install_gates(monkeypatch, allowlist={"not_the_commands_key": []})

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "NEEDS_CONTEXT" in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_run_canonicalizes_tool_name_whitespace_before_denylist_check(monkeypatch):
    """A whitespace-padded tool_name must resolve to the SAME (denied)
    decision as the trimmed name -- proves stripping happens before the
    denylist bare-name comparison, so padding can't dodge it."""
    audit = _install_gates(monkeypatch, denylist={"denied": ["demisto-api-delete"], "protected_lists": []})

    result = gtb.guardian_tool_bridge_run("  demisto-api-delete  ", {})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert tool_result["tool_name"] == "demisto-api-delete"
    assert len(audit["calls"]) == 1


# --- FIX B: hyphen<->underscore alias resolution (SECURITY-PRESERVING) -------


def test_run_underscore_alias_resolves_to_hyphen_form_and_gated_as_same_tier(monkeypatch):
    """`xdr_endpoint_tag_add` (mangled, underscores) must resolve to the
    real `xdr-endpoint-tag-add` (DEFAULT_POLICY tiers it `require_approval`,
    same as calling it with the correct spelling directly) -- proving the
    reliability fix helps a mangled ALIAS resolve to an ALREADY-PERMITTED
    command, without ever auto-allowing it: it still parks to
    `pending_approval`, never executes, exactly like the hyphen form would
    (see `test_run_pending_approval_for_require_approval_tier_never_executes`)."""
    audit = _install_gates(monkeypatch)

    result = gtb.guardian_tool_bridge_run("xdr_endpoint_tag_add", {"endpoint_ids": ["1"], "tag": "x"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "pending_approval"
    assert tool_result["ok"] is False
    assert tool_result["tool_name"] == "xdr-endpoint-tag-add"  # canonical name, not the mangled alias
    assert len(audit["calls"]) == 1
    assert audit["calls"][0]["action"] == "xdr-endpoint-tag-add"


def test_run_mangled_name_with_no_permitted_variant_still_denied(monkeypatch):
    """A mangled name with NEITHER spelling recognized (not on the
    allowlist, not a `guardian_policy` key, in either separator form) must
    still be denied by the ordinary default-deny gate -- the resolver must
    never invent a false match."""
    audit = _install_gates(monkeypatch)

    result = gtb.guardian_tool_bridge_run("totally_unknown_tool", {})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert tool_result["tool_name"] == "totally_unknown_tool"  # left unchanged -- nothing to resolve to
    assert "not on guardian_tool_allowlist" in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_run_denylist_still_wins_over_underscore_alias(monkeypatch):
    """Security-preservation check: resolving an alias must not let a
    denylisted command dodge the denylist by having the model spell it with
    the "wrong" separator -- the resolved (real, hyphenated) name is what
    the denylist bare-name check compares against."""
    audit = _install_gates(
        monkeypatch,
        denylist={"denied": ["xdr-endpoint-tag-add"], "protected_lists": []},
    )

    result = gtb.guardian_tool_bridge_run("xdr_endpoint_tag_add", {"endpoint_ids": ["1"], "tag": "x"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "bare guardian_tool_denylist" in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_resolve_tool_alias_prefers_asis_name_when_already_recognized(monkeypatch):
    """When `tool_name` as given is already recognized, no swap is even
    attempted -- confirms the common/healthy path is a no-op passthrough."""
    _install_gates(monkeypatch)

    assert gtb.guardian_bridge_resolve_tool_alias("ip") == "ip"
    assert gtb.guardian_bridge_resolve_tool_alias("xdr-endpoint-tag-add") == "xdr-endpoint-tag-add"


def test_resolve_tool_alias_leaves_mixed_or_separator_free_names_untouched(monkeypatch):
    """A name with both separators (ambiguous swap) or neither (nothing to
    swap) is left exactly as given -- never guessed at."""
    _install_gates(monkeypatch)

    assert gtb.guardian_bridge_resolve_tool_alias("foo_bar-baz") == "foo_bar-baz"
    assert gtb.guardian_bridge_resolve_tool_alias("ping") == "ping"


def test_run_rejects_whitespace_only_tool_name(monkeypatch):
    audit = _install_gates(monkeypatch)

    result = gtb.guardian_tool_bridge_run("   ", {})

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]
    assert audit["calls"] == []


# --- guardian_bridge_check_allowlist -------------------------------------------


def test_check_allowlist_dict_with_commands_shape(monkeypatch):
    _install_gates(monkeypatch, allowlist={"commands": ["ip", "whois"]})
    result = gtb.guardian_bridge_check_allowlist("ip")
    assert result == {
        "ok": True,
        "data": {"on_allowlist": True, "source": "runtime"},
        "error": None,
        "retryable": False,
        "is_auth_error": False,
    }


def test_check_allowlist_bare_array_shape_accepted(monkeypatch):
    """A bare `[...]` array (not wrapped in `{"commands": [...]}`) must be
    accepted too -- defensive robustness beyond the real pack-seeded shape."""
    _install_gates(monkeypatch, allowlist=["ip", "whois"])
    result = gtb.guardian_bridge_check_allowlist("ip")
    assert result["ok"] is True
    assert result["data"]["on_allowlist"] is True


def test_check_allowlist_not_present_returns_false(monkeypatch):
    _install_gates(monkeypatch, allowlist={"commands": ["ip"]})
    result = gtb.guardian_bridge_check_allowlist("demisto-api-post")
    assert result["ok"] is True
    assert result["data"]["on_allowlist"] is False


def test_check_allowlist_unreadable_fails_closed(monkeypatch):
    _install_gates(monkeypatch, list_errors={"guardian_tool_allowlist": "boom"})
    result = gtb.guardian_bridge_check_allowlist("ip")
    assert result["ok"] is False
    assert "fail-closed" in result["error"]


def test_check_allowlist_malformed_shape_fails_closed(monkeypatch):
    _install_gates(monkeypatch, allowlist={"commands": "not-a-list"})
    result = gtb.guardian_bridge_check_allowlist("ip")
    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_check_allowlist_getlist_auth_error_is_forwarded(monkeypatch):
    """A real getList auth failure must survive into the envelope's
    is_auth_error field, matching GuardianToolCatalogBuilder's equivalent
    loader -- previously silently dropped to False regardless of the
    underlying failure's real classification."""
    _install_gates(
        monkeypatch,
        list_errors={
            "guardian_tool_allowlist_runtime": "Item not found (8) on list [...]",
            "guardian_tool_allowlist": "Error 401: authentication failed - invalid API key",
        },
    )
    result = gtb.guardian_bridge_check_allowlist("ip")
    assert result["ok"] is False
    assert result["is_auth_error"] is True


def test_check_allowlist_runtime_not_found_falls_back_to_baseline(monkeypatch):
    """The conclusive "item not found" case (not yet bootstrapped/no operator
    edit made) must genuinely fall back to a DIFFERENT command set from the
    static baseline -- distinct from every other allowlist test above, which
    (via _install_gates' legacy fixture shim) all exercise the runtime
    list's OWN failure, never this fallback mechanism succeeding."""
    _install_gates(
        monkeypatch,
        allowlist={"commands": ["whois"]},
        list_errors={"guardian_tool_allowlist_runtime": "Item not found (8) on list [...]"},
    )
    result = gtb.guardian_bridge_check_allowlist("whois")
    assert result == {
        "ok": True,
        "data": {"on_allowlist": True, "source": "baseline_fallback"},
        "error": None,
        "retryable": False,
        "is_auth_error": False,
    }


def test_check_allowlist_runtime_not_found_and_baseline_unreadable_fails_closed(monkeypatch):
    """Two-hop fail-closed: the runtime list is conclusively absent (so a
    fallback is attempted), but the baseline itself is also unreadable --
    distinct from every other fail-closed test, none of which actually
    reach the baseline read at all (they fail on the runtime list itself)."""
    _install_gates(
        monkeypatch,
        list_errors={
            "guardian_tool_allowlist_runtime": "Item not found (8) on list [...]",
            "guardian_tool_allowlist": "connection refused",
        },
    )
    result = gtb.guardian_bridge_check_allowlist("ip")
    assert result["ok"] is False
    assert "fail-closed" in result["error"]
    assert "guardian_tool_allowlist" in result["error"]


def test_check_allowlist_bare_array_runtime_list_is_accepted_matching_baseline_contract(monkeypatch):
    """Mirror-pair test: GuardianToolCatalogBuilder_test.py's
    test_build_tool_catalog_bare_array_runtime_allowlist_is_accepted exercises
    the SAME bare-array runtime-list content through
    guardian_build_tool_catalog(). Both must agree -- this was a live,
    confirmed divergence (Bridge accepted, CatalogBuilder rejected, which
    would have silently halted the whole tool catalogue every tick) until
    GuardianToolCatalogBuilder.guardian_validate_allowlist_payload was
    loosened to match this file's existing leniency."""
    _install_gates(monkeypatch, runtime_allowlist=["ip", "whois"])
    result = gtb.guardian_bridge_check_allowlist("ip")
    assert result["ok"] is True
    assert result["data"] == {"on_allowlist": True, "source": "runtime"}


# --- Step 4: policy tier (fail-closed) ----------------------------------------


def test_run_denied_by_policy_deny_tier(monkeypatch):
    audit = _install_gates(monkeypatch, policy={"closeInvestigation": "deny"})

    result = gtb.guardian_tool_bridge_run("closeInvestigation", {})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "deny" in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_run_pending_approval_for_require_approval_tier_never_executes(monkeypatch):
    executed = []

    def handle_set_incident(args):
        executed.append(args)
        return [{"Type": 1, "Contents": "done"}]

    audit = _install_gates(
        monkeypatch, policy={"setIncident": "require_approval"}, command_handlers={"setIncident": handle_set_incident}
    )

    result = gtb.guardian_tool_bridge_run("setIncident", {"id": "1"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "pending_approval"
    assert tool_result["ok"] is False
    assert executed == []  # never dispatched to demisto.executeCommand
    assert "Task 3.1" in tool_result["error"] or "approval" in tool_result["error"].lower()
    assert len(audit["calls"]) == 1
    assert audit["calls"][0]["status"] == "pending_approval"


def test_run_denied_when_policy_unreadable_fail_closed(monkeypatch):
    audit = _install_gates(monkeypatch, list_errors={"guardian_policy": "boom"})

    result = gtb.guardian_tool_bridge_run("ip", {})

    assert result["data"]["tool_result"]["status"] == "denied"
    assert "fail-closed" in result["data"]["tool_result"]["error"]


def test_run_denied_when_policy_shape_unexpected(monkeypatch):
    audit = _install_gates(monkeypatch, policy=["not", "a", "dict"])

    result = gtb.guardian_tool_bridge_run("ip", {})

    assert result["data"]["tool_result"]["status"] == "denied"


def test_check_policy_unrecognized_tier_denies(monkeypatch):
    _install_gates(monkeypatch, policy={"ip": "sometimes"})

    result = gtb.guardian_bridge_check_policy("ip")

    assert result["decision"] == "deny"
    assert "NEEDS_CONTEXT" in result["error"]


def test_check_policy_allow_explicit(monkeypatch):
    _install_gates(monkeypatch, policy={"ip": "allow"})
    assert gtb.guardian_bridge_check_policy("ip")["decision"] == "allow"


def test_check_policy_absent_defaults_to_allow(monkeypatch):
    """`decision` still defaults to "allow" when `tool_name` is absent from
    `guardian_policy` -- but `in_policy` is `False`, which is what the
    Task 1.3 default-deny gate in `guardian_tool_bridge_run` uses to tell
    "known-but-untiered" apart from "never classified at all" (the latter
    only proceeds if ALSO on `guardian_tool_allowlist` -- see the dedicated
    `guardian_tool_bridge_run`-level tests for that gate)."""
    _install_gates(monkeypatch, policy={})
    result = gtb.guardian_bridge_check_policy("ip")
    assert result == {"decision": "allow", "in_policy": False, "error": None}


# --- Step 4/5: execute + result shaping ---------------------------------------


def test_run_allow_tier_executes(monkeypatch):
    audit = _install_gates(monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _ok_handler({"Score": 1})})

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "ok"
    assert tool_result["ok"] is True
    assert tool_result["result"] == {"Score": 1}
    assert len(audit["calls"]) == 1
    assert audit["calls"][0]["status"] == "ok"


def test_run_ip_bogon_short_circuits_before_dispatch(monkeypatch):
    # No "ip" handler registered at all -- _install_gates' fake_execute raises
    # AssertionError on any unhandled dispatch, so a passing call here proves
    # the bogon short-circuit answered without ever reaching guardian_execute.
    audit = _install_gates(monkeypatch, policy={"ip": "allow"})

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "10.0.114.30"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "ok"
    assert tool_result["ok"] is True
    assert "not internet-routable" in tool_result["result"]
    assert "STOP calling" in tool_result["result"]
    assert audit["calls"][0]["duration_ms"] is None


def test_run_ip_link_local_short_circuits_before_dispatch(monkeypatch):
    audit = _install_gates(monkeypatch, policy={"ip": "allow"})

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "169.254.1.1"})

    assert result["data"]["tool_result"]["status"] == "ok"
    assert audit["calls"][0]["duration_ms"] is None


def test_run_ip_public_address_still_dispatches(monkeypatch):
    # Negative case: a real, non-bogon address must still reach the real
    # command -- the short-circuit is scoped to private/reserved ranges only.
    audit = _install_gates(monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _ok_handler({"Score": 1})})

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "8.8.8.8"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "ok"
    assert tool_result["result"] == {"Score": 1}
    assert isinstance(audit["calls"][0]["duration_ms"], int)


def test_runtime_allowlist_replaces_pack_baseline_for_default_deny_gate(monkeypatch):
    executed = []
    audit = _install_gates(
        monkeypatch,
        allowlist={"commands": ["ip"]},
        runtime_allowlist={"commands": ["whois"]},
        policy={},
        command_handlers={"whois": lambda args: executed.append(args) or [{"Type": 1, "Contents": "ok"}]},
    )

    result = gtb.guardian_tool_bridge_run("whois", {"query": "example.com"})

    assert result["data"]["tool_result"]["status"] == "ok"
    assert executed == [{"query": "example.com"}]
    assert audit["calls"][0]["detail"]["allowlist_source"] == "runtime"


def test_operator_only_command_is_denied_even_if_runtime_selected(monkeypatch):
    audit = _install_gates(
        monkeypatch,
        runtime_allowlist={"commands": ["guardian-approve"]},
        policy={},
    )

    result = gtb.guardian_tool_bridge_run("guardian-approve", {"approval_id": "x"})

    assert result["data"]["tool_result"]["status"] == "denied"
    assert "operator-only" in result["data"]["tool_result"]["error"]
    assert len(audit["calls"]) == 1


def test_operator_only_command_is_denied_even_on_static_baseline(monkeypatch):
    """The boundary is source-agnostic: an operator-only name reaching this
    far via the pack-seeded STATIC baseline (not just an operator's runtime
    edit) must be denied identically -- proves the check isn't accidentally
    scoped to only the runtime-list code path."""
    audit = _install_gates(
        monkeypatch,
        allowlist={"commands": ["guardian-approve"]},
        list_errors={"guardian_tool_allowlist_runtime": "Item not found (8) on list [...]"},
        policy={},
    )

    result = gtb.guardian_tool_bridge_run("guardian-approve", {"approval_id": "x"})

    assert result["data"]["tool_result"]["status"] == "denied"
    assert "operator-only" in result["data"]["tool_result"]["error"]
    assert len(audit["calls"]) == 1


def test_operator_only_command_denied_even_with_valid_approval_token_present(monkeypatch):
    """A forged/stale/mismatched-looking concern the other way: even a
    GENUINELY approved, unconsumed ledger token for this exact tool_name
    must not let the call through -- the operator-only check short-circuits
    (Step 2.5) BEFORE Step 4's approval-token consumption logic is ever
    reached, so the token is never touched."""
    ledger = [
        {
            "approval_id": "appr-1",
            "kind": "tool",
            "status": "approved",
            "tool_name": "guardian-approve",
            "tool_args": {"approval_id": "x"},
            "consumed": False,
            "risk_tier": "soft",
        }
    ]
    audit = _install_gates(
        monkeypatch,
        runtime_allowlist={"commands": ["guardian-approve"]},
        policy={},
        approvals_ledger=ledger,
    )

    result = gtb.guardian_tool_bridge_run("guardian-approve", {"approval_id": "x"}, approval_id="appr-1")

    assert result["data"]["tool_result"]["status"] == "denied"
    assert "operator-only" in result["data"]["tool_result"]["error"]
    assert ledger[0]["consumed"] is False  # token never touched -- proves the short-circuit


def test_denylist_and_operator_only_overlap_precedence_is_documented(monkeypatch):
    """Pins the intended precedence when a name is BOTH denylisted and
    operator-only (e.g. an operator adds one as extra defense-in-depth, or
    by copy-paste): the denylist (Step 2) wins the reported reason over the
    operator-only boundary (Step 2.5), since denylist is checked first.
    Outcome (denied) is identical either way -- this only pins WHICH message
    the audit trail shows, so a future reordering is a deliberate choice."""
    audit = _install_gates(
        monkeypatch,
        denylist={"denied": ["GuardianBootstrap"], "protected_lists": []},
        policy={},
    )

    result = gtb.guardian_tool_bridge_run("GuardianBootstrap", {})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "guardian_tool_denylist" in tool_result["error"]
    assert "operator-only" not in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_run_absent_from_policy_still_executes(monkeypatch):
    """A command with no guardian_policy entry at all (and not denylisted)
    still executes -- but ONLY because it's on guardian_tool_allowlist
    (Task 1.3 fix: "absent from policy" alone is no longer sufficient, see
    test_run_off_catalogue_command_denied_by_default below for the
    complementary case where a command is absent from BOTH)."""
    audit = _install_gates(
        monkeypatch, policy={}, allowlist=DEFAULT_ALLOWLIST, command_handlers={"whois": _ok_handler("whois data")}
    )

    result = gtb.guardian_tool_bridge_run("whois", {"domain": "example.com"})

    assert result["data"]["tool_result"]["status"] == "ok"
    assert len(audit["calls"]) == 1


def test_run_execute_failure_type4_returns_error_status_not_ok(monkeypatch):
    """Benign-error control case: ordinary error text with no secret shape
    must pass through unchanged (proves the scrub isn't a wholesale wipe of
    error text, only of secret-looking substrings)."""
    audit = _install_gates(
        monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _error_handler("host unreachable")}
    )

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "9.9.9.9"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "error"
    assert tool_result["ok"] is False
    assert "host unreachable" in tool_result["error"]
    assert len(audit["calls"]) == 1
    assert audit["calls"][0]["status"] == "error"


def test_run_warning_with_platform_failure_text_is_error_status_in_result_and_audit(monkeypatch):
    """A command that reports a failed platform call through a warning entry (`return_warning`, Type 11)
    must be an error for the model-facing result and the audit row, not a clean ok."""
    text = "Example module is not enabled.\nFull error message: request to [/api/example/] failed client execute - returned non-whitelisted status [500]"
    audit = _install_gates(
        monkeypatch,
        policy={"ip": "allow"},
        command_handlers={"ip": lambda args: [{"Type": 11, "ContentsFormat": "text", "Contents": text}]},
    )

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "9.9.9.9"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "error"
    assert tool_result["ok"] is False
    assert "non-whitelisted status [500]" in tool_result["error"]
    assert len(audit["calls"]) == 1
    assert audit["calls"][0]["status"] == "error"


def test_run_plain_warning_reply_stays_ok(monkeypatch):
    audit = _install_gates(
        monkeypatch,
        policy={"ip": "allow"},
        command_handlers={"ip": lambda args: [{"Type": 11, "Contents": "Example: no results found."}]},
    )

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "9.9.9.9"})

    assert result["data"]["tool_result"]["status"] == "ok"
    assert audit["calls"][0]["status"] == "ok"


def test_run_text_note_quoting_the_platform_failure_wording_stays_ok(monkeypatch):
    """Only a lone warning entry (Type 11) reports a failed platform call; a text note that quotes the wording is data."""
    text = "Example failed.\nFull error message: request to [/api/example/] returned non-whitelisted status [500] body: {}"
    audit = _install_gates(monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _ok_handler(text)})

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "9.9.9.9"})

    assert result["data"]["tool_result"]["status"] == "ok"
    assert audit["calls"][0]["status"] == "ok"


def test_run_structured_result_quoting_the_failure_wording_stays_ok(monkeypatch):
    """A case note, memory value or evidence packet can quote a failed lookup verbatim; the structured result is data."""
    quote = "Full error message: request to [/api/example/] failed client execute - returned non-whitelisted status [500]"
    audit = _install_gates(
        monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _ok_handler({"documented": True, "note": quote})}
    )

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "9.9.9.9"})

    assert result["data"]["tool_result"]["status"] == "ok"
    assert audit["calls"][0]["status"] == "ok"


def test_run_normal_result_that_mentions_error_stays_ok(monkeypatch):
    audit = _install_gates(
        monkeypatch,
        policy={"ip": "allow"},
        command_handlers={"ip": _ok_handler({"summary": "0 errors", "rows": [{"note": "Full error message: none"}]})},
    )

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "9.9.9.9"})

    assert result["data"]["tool_result"]["status"] == "ok"
    assert audit["calls"][0]["status"] == "ok"


def test_run_execute_failure_scrubs_secret_from_error(monkeypatch):
    """The error path is a leak vector too, and was previously
    unaddressed: `guardian_execute` flattens a failing entry's raw text
    straight into `tool_result["error"]`, which reaches the War Room
    readable output, `raw_response`, and (via the model's tool message) the
    LLM's own context. Real integration errors routinely echo back
    credentials (e.g. an upstream API's own "401 Unauthorized: invalid
    api_key '...'" message, or a DB driver exception with a connection
    string password). This proves the scalar-string scrub
    (`guardian_scrub_secrets`) actually reaches `tool_result["error"]`."""
    secret_error = (
        "401 Unauthorized: invalid api_key 'sk-SECRET123ABCDEFGHIJK'; connection string "
        "postgres://dbuser:hunter2@db.internal:5432/prod failed; password=hunter2 rejected"
    )
    audit = _install_gates(
        monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _error_handler(secret_error)}
    )

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "9.9.9.9"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "error"
    assert "sk-SECRET123ABCDEFGHIJK" not in tool_result["error"]
    assert "hunter2" not in tool_result["error"]
    assert "***" in tool_result["error"]
    assert len(audit["calls"]) == 1


def test_main_secret_in_error_absent_from_readable_output(monkeypatch):
    """Same scenario as above, but exercised through `main()` end-to-end --
    confirms the scrub also reaches the War Room `readable_output` and
    `raw_response`, not just the returned `tool_result` dict."""
    secret_error = "invalid api_key 'sk-SECRETTOKEN1234567890'; password=hunter2 rejected"
    _install_gates(monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _error_handler(secret_error)})
    monkeypatch.setattr(
        gtb.demisto, "args", lambda: {"tool_name": "ip", "tool_args": json.dumps({"ip": "9.9.9.9"})}
    )
    monkeypatch.setattr(gtb, "guardian_ctx_write", lambda key, value: None)

    results = []
    monkeypatch.setattr(gtb, "return_results", lambda x: results.append(x), raising=False)

    gtb.main()

    assert len(results) == 1
    command_results = results[0]
    assert "sk-SECRETTOKEN1234567890" not in command_results.readable_output
    assert "hunter2" not in command_results.readable_output
    assert "sk-SECRETTOKEN1234567890" not in json.dumps(command_results.raw_response, default=str)
    assert "hunter2" not in json.dumps(command_results.raw_response, default=str)
    assert command_results.outputs["error"] is not None
    assert "sk-SECRETTOKEN1234567890" not in command_results.outputs["error"]


def test_run_passes_using_through_to_executed_command(monkeypatch):
    captured = {}

    def handle_ip(args):
        captured.update(args)
        return [{"Type": 1, "Contents": "ok"}]

    _install_gates(monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": handle_ip})

    gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"}, using="MyInstance")

    assert captured.get("using") == "MyInstance"


def test_run_redacts_secret_in_result(monkeypatch):
    _install_gates(
        monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _ok_handler({"api_key": "sekret", "score": 1})}
    )

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["result"]["api_key"] == "***"
    assert tool_result["result"]["score"] == 1


def test_run_redacts_secret_in_target_summary(monkeypatch):
    audit = _install_gates(monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _ok_handler("ok")})

    gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1", "api_key": "sekret"})

    call_target = audit["calls"][0]["target"]
    assert "sekret" not in call_target
    assert "***" in call_target


def test_run_truncates_oversized_evidence(monkeypatch):
    big_contents = "X" * 20000
    audit = _install_gates(
        monkeypatch,
        settings={"evidence_truncate_bytes": 100, "evidence_head_tail_bytes": 10},
        policy={"ip": "allow"},
        command_handlers={"ip": _ok_handler(big_contents)},
    )

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "ok"
    assert isinstance(tool_result["result"], str)
    assert "truncated" in tool_result["result"]
    assert len(tool_result["result"]) < 20000
    assert audit["calls"][0]["detail"]["truncated"] is True


def test_run_does_not_truncate_small_evidence(monkeypatch):
    audit = _install_gates(monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _ok_handler({"a": 1})})

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"})

    assert result["data"]["tool_result"]["result"] == {"a": 1}
    assert audit["calls"][0]["detail"]["truncated"] is False


def test_run_records_duration_ms_only_when_executed(monkeypatch):
    audit_executed = _install_gates(
        monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _ok_handler("ok")}
    )
    gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"})
    assert isinstance(audit_executed["calls"][0]["duration_ms"], int)
    assert audit_executed["calls"][0]["duration_ms"] >= 0


def test_run_duration_ms_none_when_never_executed(monkeypatch):
    audit_halted = _install_gates(monkeypatch, kill_switch={"enabled": True})
    gtb.guardian_tool_bridge_run("ip", {})
    assert audit_halted["calls"][0]["duration_ms"] is None


def test_run_passes_tick_id_and_run_id_to_audit(monkeypatch):
    audit = _install_gates(monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _ok_handler("ok")})

    gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"}, tick_id="tick-7", run_id="run-3")

    call = audit["calls"][0]
    assert call["tick_id"] == "tick-7"
    assert call["run_id"] == "run-3"


def test_run_echoes_tool_call_id(monkeypatch):
    _install_gates(monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _ok_handler("ok")})

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"}, tool_call_id="call-42")

    assert result["data"]["tool_result"]["tool_call_id"] == "call-42"


# --- exactly-one-audit-row invariant, across every status --------------------


def test_exactly_one_audit_row_across_every_status(monkeypatch):
    # halted
    audit = _install_gates(monkeypatch, kill_switch={"enabled": True})
    result = gtb.guardian_tool_bridge_run("ip", {})
    assert result["data"]["tool_result"]["status"] == "halted"
    assert len(audit["calls"]) == 1

    # denied (bare denylist)
    audit = _install_gates(monkeypatch, denylist={"denied": ["demisto-api-delete"], "protected_lists": []})
    result = gtb.guardian_tool_bridge_run("demisto-api-delete", {})
    assert result["data"]["tool_result"]["status"] == "denied"
    assert len(audit["calls"]) == 1

    # pending_approval
    audit = _install_gates(monkeypatch, policy={"setIncident": "require_approval"})
    result = gtb.guardian_tool_bridge_run("setIncident", {})
    assert result["data"]["tool_result"]["status"] == "pending_approval"
    assert len(audit["calls"]) == 1

    # ok
    audit = _install_gates(monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _ok_handler("ok")})
    result = gtb.guardian_tool_bridge_run("ip", {})
    assert result["data"]["tool_result"]["status"] == "ok"
    assert len(audit["calls"]) == 1

    # error (Type==4 execute result)
    audit = _install_gates(monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _error_handler("boom")})
    result = gtb.guardian_tool_bridge_run("ip", {})
    assert result["data"]["tool_result"]["status"] == "error"
    assert len(audit["calls"]) == 1


def test_run_rejects_missing_tool_name_and_never_audits(monkeypatch):
    audit = _install_gates(monkeypatch)

    result = gtb.guardian_tool_bridge_run(None, {})

    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]
    assert audit["calls"] == []


def test_run_rejects_non_string_tool_name(monkeypatch):
    audit = _install_gates(monkeypatch)

    result = gtb.guardian_tool_bridge_run(123, {})

    assert result["ok"] is False
    assert audit["calls"] == []


# --- guardian_bridge_parse_tool_args ------------------------------------------


def test_parse_tool_args_json_string():
    parsed, warning = gtb.guardian_bridge_parse_tool_args('{"a": 1}')
    assert parsed == {"a": 1}
    assert warning is None


def test_parse_tool_args_dict_passthrough():
    parsed, warning = gtb.guardian_bridge_parse_tool_args({"a": 1})
    assert parsed == {"a": 1}
    assert warning is None


def test_parse_tool_args_none_and_blank_string():
    assert gtb.guardian_bridge_parse_tool_args(None) == ({}, None)
    assert gtb.guardian_bridge_parse_tool_args("   ") == ({}, None)


def test_parse_tool_args_malformed_json_warns_and_treats_as_empty():
    parsed, warning = gtb.guardian_bridge_parse_tool_args("{not json")
    assert parsed == {}
    assert warning is not None


def test_parse_tool_args_non_object_json_warns_and_treats_as_empty():
    parsed, warning = gtb.guardian_bridge_parse_tool_args("[1, 2, 3]")
    assert parsed == {}
    assert warning is not None


def test_parse_tool_args_unexpected_type_warns():
    parsed, warning = gtb.guardian_bridge_parse_tool_args(12345)
    assert parsed == {}
    assert warning is not None


# --- guardian_bridge_summarize_target -----------------------------------------


def test_summarize_target_none_when_no_args():
    assert gtb.guardian_bridge_summarize_target({}) is None
    assert gtb.guardian_bridge_summarize_target(None) is None


def test_summarize_target_redacts_and_truncates():
    summary = gtb.guardian_bridge_summarize_target({"note": "y" * 300, "password": "hunter2"})
    assert summary is not None
    assert len(summary) <= gtb.GUARDIAN_TARGET_SUMMARY_MAX_LEN
    assert "hunter2" not in summary


# --- guardian_bridge_load_evidence_limits -------------------------------------


def test_load_evidence_limits_uses_configured_settings_values(monkeypatch):
    _install_gates(monkeypatch, settings={"evidence_truncate_bytes": 500, "evidence_head_tail_bytes": 50})
    truncate, head_tail = gtb.guardian_bridge_load_evidence_limits()
    assert (truncate, head_tail) == (500, 50)


def test_load_evidence_limits_falls_back_to_defaults_when_unreadable(monkeypatch):
    _install_gates(monkeypatch, list_errors={"guardian_settings": "boom"})
    truncate, head_tail = gtb.guardian_bridge_load_evidence_limits()
    assert truncate == gtb.GUARDIAN_DEFAULT_EVIDENCE_TRUNCATE_BYTES
    assert head_tail == gtb.GUARDIAN_DEFAULT_EVIDENCE_HEAD_TAIL_BYTES


def test_load_evidence_limits_ignores_invalid_configured_values(monkeypatch):
    _install_gates(monkeypatch, settings={"evidence_truncate_bytes": -5, "evidence_head_tail_bytes": "nope"})
    truncate, head_tail = gtb.guardian_bridge_load_evidence_limits()
    assert truncate == gtb.GUARDIAN_DEFAULT_EVIDENCE_TRUNCATE_BYTES
    assert head_tail == gtb.GUARDIAN_DEFAULT_EVIDENCE_HEAD_TAIL_BYTES


# --- guardian_bridge_extract_contents -----------------------------------------


def test_extract_contents_single_entry_returned_directly():
    assert gtb.guardian_bridge_extract_contents([{"Type": 1, "Contents": {"a": 1}}]) == {"a": 1}


def test_extract_contents_multi_entry_returns_list():
    entries = [{"Type": 1, "Contents": "a"}, {"Type": 1, "Contents": "b"}]
    assert gtb.guardian_bridge_extract_contents(entries) == ["a", "b"]


def test_extract_contents_none_when_no_contents_key_present():
    assert gtb.guardian_bridge_extract_contents([{"Type": 1}]) is None


def test_extract_contents_empty_or_none_entries():
    assert gtb.guardian_bridge_extract_contents([]) is None
    assert gtb.guardian_bridge_extract_contents(None) is None


# --- guardian_bridge_shape_result: redact BEFORE truncate ---------------------


def test_shape_result_small_payload_untouched(monkeypatch):
    _install_gates(monkeypatch)
    payload, truncated, note, full_payload = gtb.guardian_bridge_shape_result([{"Type": 1, "Contents": {"a": 1}}])
    assert (payload, truncated, note, full_payload) == ({"a": 1}, False, None, None)


def test_shape_result_redacts_before_truncating(monkeypatch):
    """A secret must be masked BEFORE the head/tail truncation slice is
    taken -- otherwise a partial, still-readable fragment of the secret
    could survive at the truncation boundary. This payload is small enough
    to stay under the (unpatched, real-default 16384-byte) ceiling, so
    `payload` here is still the structured dict -- confirms redaction alone,
    independent of truncation (see the dedicated truncation test below for
    the combined case)."""
    _install_gates(monkeypatch)
    entries = [{"Type": 1, "Contents": {"password": "hunter2" * 20, "note": "y" * 200}}]

    payload, truncated, note, full_payload = gtb.guardian_bridge_shape_result(entries)

    assert truncated is False
    assert payload["password"] == "***"
    assert "hunter2" not in json.dumps(payload)
    assert full_payload is None  # only set on the truncated path


def test_shape_result_truncation_never_reveals_pretruncation_secret(monkeypatch):
    _install_gates(monkeypatch, settings={"evidence_truncate_bytes": 30, "evidence_head_tail_bytes": 5})
    entries = [{"Type": 1, "Contents": {"password": "hunter2" * 20, "note": "y" * 200}}]

    payload, truncated, note, full_payload = gtb.guardian_bridge_shape_result(entries)

    assert truncated is True
    assert "hunter2" not in payload
    assert note is not None
    # full_payload is the REDACTED pre-truncation payload -- the secret must
    # never survive here either, even though it's the "complete" copy.
    assert full_payload["password"] == "***"
    assert "hunter2" not in json.dumps(full_payload)


def test_run_truncated_dispatch_surfaces_truncation_in_tool_result_and_returns_full_payload(monkeypatch):
    """End-to-end (item 14): the truncated/truncation_note signal used to
    only reach the audit row, never `tool_result` itself -- and the full
    payload was discarded once truncated, never returned anywhere for the
    reasoning tick to attach as a War Room file. Both must now flow all the
    way out of guardian_tool_bridge_run."""
    _install_gates(
        monkeypatch,
        policy={"ip": "allow"},
        settings={"evidence_truncate_bytes": 30, "evidence_head_tail_bytes": 5},
        command_handlers={"ip": _ok_handler({"note": "y" * 500})},
    )

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["truncated"] is True
    assert tool_result["truncation_note"] is not None
    assert result["data"]["full_payload"] == {"note": "y" * 500}
    # The full payload must never itself appear inside the (small, by
    # definition) truncated result the model sees.
    assert "y" * 500 not in json.dumps(tool_result["result"])


def test_run_untruncated_dispatch_has_no_full_payload(monkeypatch):
    _install_gates(monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _ok_handler({"score": 1})})

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["truncated"] is False
    assert tool_result["truncation_note"] is None
    assert result["data"]["full_payload"] is None


# --- guardian_bridge_reduce_list_structurally (harvest candidate #17) ----------


def test_reduce_list_structurally_keeps_every_item_within_budget():
    items = [{"id": i} for i in range(5)]
    kept, omitted = gtb.guardian_bridge_reduce_list_structurally(items, budget_bytes=10_000)
    assert kept == items
    assert omitted == 0


def test_reduce_list_structurally_drops_trailing_items_over_budget():
    items = [{"id": i, "pad": "x" * 20} for i in range(10)]
    # Each item serializes to roughly 35-40 bytes; a small budget should only
    # fit the first few.
    kept, omitted = gtb.guardian_bridge_reduce_list_structurally(items, budget_bytes=120)
    assert len(kept) < len(items)
    assert omitted == len(items) - len(kept)
    assert kept == items[: len(kept)]  # leading items, in original order, unmodified


def test_reduce_list_structurally_never_returns_empty_even_when_first_item_exceeds_budget():
    items = [{"id": 0, "pad": "x" * 500}, {"id": 1}]
    kept, omitted = gtb.guardian_bridge_reduce_list_structurally(items, budget_bytes=10)
    assert kept == [items[0]]  # one real item, never an empty list
    assert omitted == 1


def test_reduce_list_structurally_every_item_intact_not_sliced():
    # The defining difference from a byte-slice: every KEPT item is byte-for-byte
    # what went in, never a partial/truncated fragment of one.
    items = [{"id": i, "value": "unique-marker-{}".format(i)} for i in range(20)]
    kept, omitted = gtb.guardian_bridge_reduce_list_structurally(items, budget_bytes=200)
    assert omitted > 0
    for item in kept:
        assert item in items  # byte-identical to some original item, never mangled


# --- Guardian's own description section never reaches the model -------------------------------------------------------

def test_shape_result_drops_guardians_description_section_before_the_result_reaches_the_model():
    section = gtb.GUARDIAN_ISSUE_SECTION_GAP + gtb.GUARDIAN_ISSUE_SECTION_MARKER + "\nTriage: type x, severity high.\nInvestigation: Benign, confidence 90."
    entries = [{"Type": 1, "Contents": [{"internal_id": "9001", "description": "The VM has admin rights." + section,
                                         "comments": [{"text": "note" + section}]}]}]
    payload, truncated, note, full_payload = gtb.guardian_bridge_shape_result(entries)
    assert payload == [{"internal_id": "9001", "description": "The VM has admin rights.", "comments": [{"text": "note"}]}]
    assert truncated is False and gtb.GUARDIAN_ISSUE_SECTION_MARKER not in json.dumps(payload)


def test_shape_result_strips_the_section_before_it_truncates_so_a_cut_cannot_keep_a_piece_of_it():
    section = gtb.GUARDIAN_ISSUE_SECTION_GAP + gtb.GUARDIAN_ISSUE_SECTION_MARKER + "\nInvestigation: Benign."
    entries = [{"Type": 1, "Contents": "x" * 5000 + section}]
    payload, truncated, _note, full_payload = gtb.guardian_bridge_shape_result(entries, truncate_arg=1000, head_tail_arg=300)
    assert truncated is True and "Benign" not in payload and "Benign" not in json.dumps(full_payload)


# --- guardian_bridge_shape_result: structural reduction (harvest candidate #17) ---


def test_shape_result_reduces_oversized_list_structurally_not_via_byte_slice(monkeypatch):
    _install_gates(monkeypatch, settings={"evidence_truncate_bytes": 200, "evidence_head_tail_bytes": 50})
    entries = [
        {"Type": 1, "Contents": {"id": i, "note": "finding-{}".format(i)}} for i in range(30)
    ]

    payload, truncated, note, full_payload = gtb.guardian_bridge_shape_result(entries)

    assert truncated is True
    assert isinstance(payload, list)  # structurally reduced, NOT the byte-slice string path
    assert payload[-1]["_guardian_truncated"] is True
    assert payload[-1]["omitted_items"] > 0
    # Every kept item (all but the trailing marker) is intact, valid JSON --
    # never a partial fragment.
    for item in payload[:-1]:
        assert isinstance(item, dict) and "id" in item and "note" in item
    assert "reduced structurally" in note
    # full_payload is the complete, un-reduced 30-item list -- what gets
    # attached as a War Room file, distinct from the 30-item-reduced payload.
    assert full_payload == [{"id": i, "note": "finding-{}".format(i)} for i in range(30)]


def test_shape_result_structural_reduction_preserves_leading_order():
    kept, _ = gtb.guardian_bridge_reduce_list_structurally([{"id": i} for i in range(50)], budget_bytes=300)
    ids = [row["id"] for row in kept]
    assert ids == sorted(ids)  # leading items kept in original order, none reordered


def test_shape_result_falls_back_to_byte_slice_when_single_item_still_oversized(monkeypatch):
    # A ceiling so small that even ONE item can't fit -- structural reduction
    # can't help (guardian_bridge_reduce_list_structurally returns omitted=0
    # for a single-item list), so this must fall through to the byte-slice path.
    _install_gates(monkeypatch, settings={"evidence_truncate_bytes": 20, "evidence_head_tail_bytes": 5})
    entries = [{"Type": 1, "Contents": {"note": "y" * 500}}]

    payload, truncated, note, full_payload = gtb.guardian_bridge_shape_result(entries)

    assert truncated is True
    assert isinstance(payload, str)  # the byte-slice fallback, not a structural reduction
    assert "truncated" in payload and "bytes" in payload
    assert full_payload == {"note": "y" * 500}


def test_shape_result_dict_payload_still_uses_byte_slice_not_structural_reduction(monkeypatch):
    # A dict-shaped (not list-shaped) oversized result has no list to reduce --
    # confirms the structural path is scoped to lists only, never attempted on a dict.
    _install_gates(monkeypatch, settings={"evidence_truncate_bytes": 30, "evidence_head_tail_bytes": 5})
    entries = [{"Type": 1, "Contents": {"note": "z" * 500}}]

    payload, truncated, note, full_payload = gtb.guardian_bridge_shape_result(entries)

    assert truncated is True
    assert isinstance(payload, str)
    assert "reduced structurally" not in note
    assert full_payload == {"note": "z" * 500}


def test_shape_result_empty_list_payload_is_never_over_ceiling():
    # A degenerate but real case: len(json.dumps([])) == 2 bytes, always under
    # any sane ceiling -- confirms the `redacted and` guard is just defensive,
    # never actually reachable via a real oversized-empty-list scenario.
    kept, omitted = gtb.guardian_bridge_reduce_list_structurally([], budget_bytes=100)
    assert kept == []
    assert omitted == 0


# --- main() --------------------------------------------------------------------


def test_main_success_writes_context_and_returns_results(monkeypatch):
    _install_gates(monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _ok_handler({"a": 1})})
    monkeypatch.setattr(
        gtb.demisto, "args", lambda: {"tool_name": "ip", "tool_args": json.dumps({"ip": "1.1.1.1"})}
    )

    ctx_writes = {}
    monkeypatch.setattr(gtb, "guardian_ctx_write", lambda key, value: ctx_writes.setdefault(key, value))

    results = []
    monkeypatch.setattr(gtb, "return_results", lambda x: results.append(x), raising=False)

    gtb.main()

    assert ctx_writes["ToolResult"]["status"] == "ok"
    assert len(results) == 1
    assert results[0].outputs["tool_name"] == "ip"


def test_main_calls_return_error_on_missing_tool_name(monkeypatch):
    _install_gates(monkeypatch)
    monkeypatch.setattr(gtb.demisto, "args", lambda: {})

    errors = []
    monkeypatch.setattr(gtb, "return_error", lambda msg: errors.append(msg), raising=False)

    gtb.main()

    assert len(errors) == 1
    assert "NEEDS_CONTEXT" in errors[0]


def test_main_handles_unexpected_exception(monkeypatch):
    monkeypatch.setattr(gtb.demisto, "args", lambda: {"tool_name": "ip"})

    def boom(*_args, **_kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(gtb, "guardian_tool_bridge_run", boom)

    errors = []
    monkeypatch.setattr(gtb, "return_error", lambda msg: errors.append(msg), raising=False)

    gtb.main()

    assert len(errors) == 1
    assert "kaboom" in errors[0]


# --- Task 3.1: the real approval gate (ledger + risk tiers + token consumption) ---


def test_risk_tier_destructive_commands():
    assert gtb.guardian_bridge_risk_tier("closeInvestigation") == "destructive"
    assert gtb.guardian_bridge_risk_tier("xdr-isolate-endpoint") == "destructive"
    assert gtb.guardian_bridge_risk_tier("deleteList") == "destructive"


def test_risk_tier_credential_substring_match_beats_destructive():
    assert gtb.guardian_bridge_risk_tier("GuardianApiKeysRotate") == "credential"
    assert gtb.guardian_bridge_risk_tier("some-credential-thing") == "credential"


def test_risk_tier_defaults_to_soft():
    assert gtb.guardian_bridge_risk_tier("setIncident") == "soft"
    assert gtb.guardian_bridge_risk_tier("createNewIncident") == "soft"


def test_risk_tier_guardianskillscrud_delete_op_is_credential_tier():
    """Task 3.3: GuardianSkillsCRUD's op=delete gets the stronger
    typed-CONFIRM ceremony by being promoted to the 'credential' tier --
    the only typed-confirm lane this codebase has -- via its ARGUMENTS, not
    its command name alone.
    """
    assert gtb.guardian_bridge_risk_tier("GuardianSkillsCRUD", {"op": "delete", "name": "x"}) == "credential"


def test_risk_tier_guardianskillscrud_other_ops_are_soft():
    """Every other GuardianSkillsCRUD op stays at the default 'soft' tier --
    only delete is special-cased."""
    assert gtb.guardian_bridge_risk_tier("GuardianSkillsCRUD", {"op": "create", "name": "x"}) == "soft"
    assert gtb.guardian_bridge_risk_tier("GuardianSkillsCRUD", {"op": "update", "name": "x"}) == "soft"
    assert gtb.guardian_bridge_risk_tier("GuardianSkillsCRUD", {"op": "toggle", "name": "x"}) == "soft"
    assert gtb.guardian_bridge_risk_tier("GuardianSkillsCRUD", None) == "soft"
    assert gtb.guardian_bridge_risk_tier("GuardianSkillsCRUD") == "soft"


def test_canonical_json_is_key_order_independent():
    a = gtb.guardian_bridge_canonical_json({"b": 1, "a": 2})
    b = gtb.guardian_bridge_canonical_json({"a": 2, "b": 1})
    assert a == b


def test_format_approval_note_destructive_is_loud_and_soft_is_plain():
    destructive_note = gtb.guardian_bridge_format_approval_note("abc123", "closeInvestigation", {}, "destructive")
    soft_note = gtb.guardian_bridge_format_approval_note("abc123", "setIncident", {}, "soft")
    credential_note = gtb.guardian_bridge_format_approval_note("abc123", "GuardianApiKeysRotate", {}, "credential")

    assert "DESTRUCTIVE" in destructive_note
    assert "🔴" in destructive_note
    assert "!guardian-approve approval_id=abc123`" in destructive_note

    assert "DESTRUCTIVE" not in soft_note
    assert "CREDENTIAL" not in soft_note
    assert "!guardian-approve approval_id=abc123`" in soft_note

    assert "CREDENTIAL" in credential_note
    assert "confirm=CONFIRM" in credential_note


# --- Task 3.1 security-review fix (FIX 4): approval note shows FULL args ---


def test_format_approval_note_shows_full_args_not_200_char_summary():
    """The War Room approval note must show the FULL args being authorized,
    not the 200-char `guardian_bridge_summarize_target` preview used for the
    audit `target` field -- a human approver must be able to see
    essentially the whole payload, not a preview that could hide the
    dangerous part of a large call."""
    big_args = {"note": "y" * 500, "other_field": "z" * 500}
    note = gtb.guardian_bridge_format_approval_note("abc123", "setIncident", big_args, "soft")

    assert "y" * 500 in note
    assert "z" * 500 in note


def test_format_approval_note_still_redacts_secrets_in_full_args():
    note = gtb.guardian_bridge_format_approval_note(
        "abc123", "setIncident", {"note": "hello", "password": "hunter2"}, "soft"
    )
    assert "hunter2" not in note
    assert "***" in note


def test_full_args_preview_caps_at_generous_ceiling_not_200_chars():
    huge = {"payload": "x" * 10000}
    preview = gtb.guardian_bridge_full_args_preview(huge)
    assert len(preview) <= gtb.GUARDIAN_APPROVAL_NOTE_ARGS_MAX_LEN
    assert len(preview) > gtb.GUARDIAN_TARGET_SUMMARY_MAX_LEN


def test_full_args_preview_none_when_no_args():
    assert gtb.guardian_bridge_full_args_preview({}) == "(no arguments)"
    assert gtb.guardian_bridge_full_args_preview(None) == "(no arguments)"


def test_audit_target_summary_still_capped_at_200_unaffected_by_fix4():
    """FIX 4 must NOT change the audit `target` field's own budget --
    `guardian_bridge_summarize_target` stays capped at 200 chars."""
    summary = gtb.guardian_bridge_summarize_target({"note": "y" * 500})
    assert len(summary) <= gtb.GUARDIAN_TARGET_SUMMARY_MAX_LEN


def test_require_approval_creates_ledger_row_and_does_not_execute(monkeypatch):
    """The core Task 3.1 contract: on a fresh require_approval ask (no
    approval_id), the bridge appends a `pending`, `kind:"tool"` row to
    guardian_approvals_ledger, posts a War Room note, and returns
    pending_approval carrying that approval_id -- WITHOUT ever dispatching
    the underlying command."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"closeInvestigation": "require_approval"},
        incident={"id": "555"},
        command_handlers={"closeInvestigation": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )

    result = gtb.guardian_tool_bridge_run("closeInvestigation", {"id": "555"}, tick_id="3", run_id="555")

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "pending_approval"
    assert tool_result["ok"] is False
    assert executed == []

    approval_id = tool_result["result"]["approval_id"]
    assert tool_result["result"]["risk_tier"] == "destructive"
    assert tool_result["result"]["tool_name"] == "closeInvestigation"

    assert len(audit["ledger"]) == 1
    row = audit["ledger"][0]
    assert row["approval_id"] == approval_id
    assert row["kind"] == "tool"
    assert row["status"] == "pending"
    assert row["tool_name"] == "closeInvestigation"
    assert row["tool_args"] == {"id": "555"}
    assert row["risk_tier"] == "destructive"
    assert row["requested_by"] == "agent"
    assert row["consumed"] is False
    assert row["incident_id"] == "555"
    assert row["tick_id"] == "3"

    assert len(audit["notes"]) == 1
    assert approval_id in audit["notes"][0]["entries"][0]["Contents"]
    assert "guardian-approval" in audit["notes"][0]["entries"][0]["Tags"]

    # exactly one audit row for the pending_approval decision itself
    assert len(audit["calls"]) == 1
    assert audit["calls"][0]["status"] == "pending_approval"


def test_pending_approval_redacts_sensitive_args_from_model_and_context_visible_result(monkeypatch):
    """SEC-73b: the model-visible/Guardian.ToolResult-context-visible `result`
    dict on the park path must never re-echo a secret back into the model's
    own transcript -- unlike the ledger row's own `tool_args`/`canonical_args`
    (kept raw on purpose, see below), this copy is display-only."""
    audit = _install_gates(
        monkeypatch,
        policy={"closeInvestigation": "require_approval"},
        command_handlers={"closeInvestigation": lambda args: [{"Type": 1, "Contents": "done"}]},
    )

    result = gtb.guardian_tool_bridge_run(
        "closeInvestigation", {"id": "1", "password": "hunter2secret"}
    )

    tool_result = result["data"]["tool_result"]
    assert tool_result["result"]["tool_args"]["id"] == "1"
    assert "hunter2secret" not in json.dumps(tool_result["result"]["tool_args"])
    assert "hunter2secret" not in json.dumps(result)  # the whole envelope -- what actually lands in Context


def test_pending_approval_ledger_row_keeps_real_args_but_adds_a_redacted_copy(monkeypatch):
    """The ledger row's OWN `tool_args`/`canonical_args` must stay the exact,
    unredacted original -- GuardianReasoningTick reads `row["tool_args"]` back
    to re-dispatch on approval, and `canonical_args` is the exact-match token
    a re-presented call is validated against; redacting either would silently
    corrupt approved re-dispatch. `tool_args_redacted` (SEC-73b) is the new,
    separate, display-only field."""
    audit = _install_gates(
        monkeypatch,
        policy={"closeInvestigation": "require_approval"},
        command_handlers={"closeInvestigation": lambda args: [{"Type": 1, "Contents": "done"}]},
    )

    gtb.guardian_tool_bridge_run("closeInvestigation", {"id": "1", "password": "hunter2secret"})

    row = audit["ledger"][0]
    assert row["tool_args"] == {"id": "1", "password": "hunter2secret"}  # real, unredacted
    assert "hunter2secret" not in json.dumps(row["tool_args_redacted"])
    assert row["canonical_args"] == gtb.guardian_bridge_canonical_json(row["tool_args"])


def test_approval_redaction_never_breaks_the_real_approve_then_execute_flow(monkeypatch):
    """The whole point of keeping the ledger's tool_args/canonical_args raw:
    the exact SAME real args must still successfully re-dispatch on approval,
    end to end, exactly like before this fix."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"closeInvestigation": "require_approval"},
        command_handlers={"closeInvestigation": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )
    real_args = {"id": "1", "password": "hunter2secret"}

    park_result = gtb.guardian_tool_bridge_run("closeInvestigation", real_args)
    approval_id = park_result["data"]["tool_result"]["result"]["approval_id"]
    audit["ledger"][0]["status"] = "approved"
    audit["ledger"][0]["resolved_by"] = "alice"

    exec_result = gtb.guardian_tool_bridge_run("closeInvestigation", real_args, approval_id=approval_id)

    assert exec_result["data"]["tool_result"]["status"] == "ok"
    assert executed == [real_args]  # the REAL value reached the actual command, not a redacted one


def test_approved_token_executes_exactly_once_then_replay_is_denied(monkeypatch):
    """The single-use approved-token contract end-to-end: park -> (human
    approves out of band, simulated by flipping the ledger row directly,
    mirroring what GuardianApprovalResolve does) -> re-dispatch WITH the
    token executes exactly once (audited ok, detail.approved_via set,
    token marked consumed) -> re-dispatching with the SAME token again is
    DENIED (replay), and the underlying command is never called a second
    time."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"closeInvestigation": "require_approval"},
        command_handlers={"closeInvestigation": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )

    park_result = gtb.guardian_tool_bridge_run("closeInvestigation", {"id": "1", "severity": 4})
    approval_id = park_result["data"]["tool_result"]["result"]["approval_id"]
    assert executed == []

    # Simulate GuardianApprovalResolve's resolution (tested separately in
    # GuardianApprovalResolve_test.py) by flipping the ledger row directly --
    # this test's job is the BRIDGE's token-consumption contract, not the
    # resolve script.
    audit["ledger"][0]["status"] = "approved"
    audit["ledger"][0]["resolved_by"] = "alice"

    exec_result = gtb.guardian_tool_bridge_run("closeInvestigation", {"id": "1", "severity": 4}, approval_id=approval_id)
    tool_result = exec_result["data"]["tool_result"]
    assert tool_result["status"] == "ok"
    assert tool_result["ok"] is True
    assert executed == [{"id": "1", "severity": 4}]
    assert audit["ledger"][0]["consumed"] is True

    # exactly one MORE audit row for the real execution (plus the earlier
    # pending_approval row = 2 total across this whole scenario)
    assert len(audit["calls"]) == 2
    assert audit["calls"][-1]["status"] == "ok"

    # REPLAY: presenting the SAME approval_id again must be denied, and the
    # underlying command must NOT be dispatched a second time.
    replay_result = gtb.guardian_tool_bridge_run("closeInvestigation", {"id": "1", "severity": 4}, approval_id=approval_id)
    replay_tool_result = replay_result["data"]["tool_result"]
    assert replay_tool_result["status"] == "denied"
    assert replay_tool_result["ok"] is False
    assert "consumed" in replay_tool_result["error"].lower()
    assert executed == [{"id": "1", "severity": 4}]  # still only ONE real dispatch


# --- Task 3.1 security-review fix (FIX 2): double-invocation hardening ---
# (the documented xsoar-content-engineering skill gotcha #26 double-dispatch
# risk -- two concurrent GuardianReasoningTick re-entries presenting the SAME
# approval_id must not BOTH execute a destructive command).


def test_two_concurrent_consumers_race_exactly_one_confirms(monkeypatch):
    """Simulates two genuinely concurrent consumers of the SAME approved
    single-tool token by directly manipulating the shared ledger between two
    `guardian_bridge_consume_approval_token` calls: consumer A reads
    approved-and-unconsumed and writes `consumed:True` + its own
    `claim_token`; this test then resets `consumed` back to False on the
    SAME ledger object to model consumer B's read having genuinely predated
    A's write landing (true concurrency, not a new bug) -- B then ALSO
    consumes successfully (mirroring the documented, unavoidable
    read-then-write race `guardian_bridge_consume_approval_token`'s own
    docstring describes) and, since `setList` fully overwrites the List,
    B's write is the one that survives. The NEW pre-execute
    re-confirmation (`guardian_bridge_confirm_tool_claim`) must then tell
    them apart: A's claim no longer matches what's persisted (lost the
    race -- MUST NOT execute), B's still does (won the race -- safe to
    execute). Of the two, EXACTLY ONE confirms."""
    audit = _install_gates(
        monkeypatch,
        policy={"closeInvestigation": "require_approval"},
        approvals_ledger=[
            {
                "approval_id": "race-1",
                "kind": "tool",
                "tool_name": "closeInvestigation",
                "tool_args": {"id": "1"},
                "canonical_args": gtb.guardian_bridge_canonical_json({"id": "1"}),
                "status": "approved",
                "consumed": False,
            }
        ],
    )

    result_a = gtb.guardian_bridge_consume_approval_token("race-1", "closeInvestigation", {"id": "1"})
    assert result_a["ok"] is True
    claim_a = result_a["data"]["claim_token"]
    assert audit["ledger"][0]["claim_token"] == claim_a

    # Model consumer B's read having predated A's write (true concurrency).
    audit["ledger"][0]["consumed"] = False

    result_b = gtb.guardian_bridge_consume_approval_token("race-1", "closeInvestigation", {"id": "1"})
    assert result_b["ok"] is True
    claim_b = result_b["data"]["claim_token"]
    assert claim_b != claim_a
    assert audit["ledger"][0]["claim_token"] == claim_b  # B's write survived

    confirm_a = gtb.guardian_bridge_confirm_tool_claim("race-1", claim_a)
    confirm_b = gtb.guardian_bridge_confirm_tool_claim("race-1", claim_b)

    assert confirm_a["ok"] is False
    assert "concurrent" in confirm_a["error"].lower()
    assert confirm_b["ok"] is True


def test_run_aborts_execute_when_claim_clobbered_by_concurrent_consumer(monkeypatch):
    """The full wiring, end-to-end through `guardian_tool_bridge_run`: when
    the pre-execute re-confirmation detects that a concurrent consumer's
    write clobbered THIS call's own claim_token in the window between
    consume and execute, the bridge must DENY and NEVER dispatch the
    underlying (here, destructive) command -- proving the hardening is
    actually wired into the real dispatch path, not just exercised via the
    two helper functions in isolation. Simulates the clobber by having the
    SECOND `getList` read of `guardian_approvals_ledger` within this one
    call (the consume step's own read is the first; the NEW pre-execute
    re-confirmation's read is the second) return a row bearing a foreign
    `claim_token`, as if a concurrent consumer's write had already landed."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"closeInvestigation": "require_approval"},
        approvals_ledger=[
            {
                "approval_id": "race-2",
                "kind": "tool",
                "tool_name": "closeInvestigation",
                "tool_args": {"id": "1"},
                "canonical_args": gtb.guardian_bridge_canonical_json({"id": "1"}),
                "status": "approved",
                "consumed": False,
            }
        ],
        command_handlers={
            "closeInvestigation": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]
        },
    )

    original_execute = gtb.demisto.executeCommand
    read_count = {"n": 0}

    def racy_execute(command, args):
        if command == "getList" and args.get("listName") == "guardian_approvals_ledger":
            read_count["n"] += 1
            if read_count["n"] >= 2:
                clobbered = dict(audit["ledger"][0])
                clobbered["claim_token"] = "someone-elses-claim"
                return [{"Type": 1, "Contents": json.dumps([clobbered])}]
        return original_execute(command, args)

    monkeypatch.setattr(gtb.demisto, "executeCommand", racy_execute)

    result = gtb.guardian_tool_bridge_run("closeInvestigation", {"id": "1"}, approval_id="race-2")
    tool_result = result["data"]["tool_result"]

    assert tool_result["status"] == "denied"
    assert "concurrent" in tool_result["error"].lower()
    assert executed == []  # the destructive command was NEVER dispatched
    assert read_count["n"] >= 2


def test_two_concurrent_plan_step_consumers_race_exactly_one_confirms(monkeypatch):
    """Plan-step counterpart of the single-tool race test above --
    `guardian_bridge_confirm_plan_step_claim` must likewise distinguish the
    step-consumer whose write survived from the one whose claim was
    clobbered by a concurrent consumer."""
    audit = _install_gates(monkeypatch)
    audit["ledger"].append(
        {
            "approval_id": "plan-race-1",
            "kind": "plan",
            "status": "approved",
            "steps": [
                {
                    "tool_name": "setIncident",
                    "tool_args": {"id": "1"},
                    "canonical_args": gtb.guardian_bridge_canonical_json({"id": "1"}),
                    "consumed": False,
                }
            ],
        }
    )

    result_a = gtb.guardian_bridge_consume_plan_step("plan-race-1", 0, "setIncident", {"id": "1"})
    assert result_a["ok"] is True
    claim_a = result_a["data"]["claim_token"]

    audit["ledger"][-1]["steps"][0]["consumed"] = False

    result_b = gtb.guardian_bridge_consume_plan_step("plan-race-1", 0, "setIncident", {"id": "1"})
    assert result_b["ok"] is True
    claim_b = result_b["data"]["claim_token"]
    assert claim_b != claim_a

    confirm_a = gtb.guardian_bridge_confirm_plan_step_claim("plan-race-1", 0, claim_a)
    confirm_b = gtb.guardian_bridge_confirm_plan_step_claim("plan-race-1", 0, claim_b)

    assert confirm_a["ok"] is False
    assert confirm_b["ok"] is True


def test_approved_token_rejected_when_tool_name_mismatches(monkeypatch):
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"setIncident": "require_approval", "closeInvestigation": "require_approval"},
        command_handlers={
            "setIncident": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}],
            "closeInvestigation": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}],
        },
    )
    park_result = gtb.guardian_tool_bridge_run("setIncident", {"id": "1"})
    approval_id = park_result["data"]["tool_result"]["result"]["approval_id"]
    audit["ledger"][0]["status"] = "approved"

    # Try to spend the setIncident approval against a DIFFERENT command.
    result = gtb.guardian_tool_bridge_run("closeInvestigation", {"id": "1"}, approval_id=approval_id)
    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert executed == []


def test_approved_token_rejected_when_args_mismatch(monkeypatch):
    """The token is scoped to the EXACT canonical args it was approved for
    -- a model (or a compromised resolve path) cannot approve one args
    payload and then execute a DIFFERENT one against the same token."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"setIncident": "require_approval"},
        command_handlers={"setIncident": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )
    park_result = gtb.guardian_tool_bridge_run("setIncident", {"id": "1", "severity": 1})
    approval_id = park_result["data"]["tool_result"]["result"]["approval_id"]
    audit["ledger"][0]["status"] = "approved"

    result = gtb.guardian_tool_bridge_run("setIncident", {"id": "1", "severity": 4}, approval_id=approval_id)
    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert executed == []


def test_approved_token_rejected_when_still_pending(monkeypatch):
    """A token presented before a human ever resolved it must be denied,
    not silently treated as a fresh ask."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"setIncident": "require_approval"},
        command_handlers={"setIncident": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )
    park_result = gtb.guardian_tool_bridge_run("setIncident", {"id": "1"})
    approval_id = park_result["data"]["tool_result"]["result"]["approval_id"]

    result = gtb.guardian_tool_bridge_run("setIncident", {"id": "1"}, approval_id=approval_id)
    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "not approved" in tool_result["error"].lower()
    assert executed == []


def test_approved_token_rejected_when_denied_by_analyst(monkeypatch):
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"setIncident": "require_approval"},
        command_handlers={"setIncident": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )
    park_result = gtb.guardian_tool_bridge_run("setIncident", {"id": "1"})
    approval_id = park_result["data"]["tool_result"]["result"]["approval_id"]
    audit["ledger"][0]["status"] = "denied"

    result = gtb.guardian_tool_bridge_run("setIncident", {"id": "1"}, approval_id=approval_id)
    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert executed == []


def test_unknown_approval_id_is_denied_not_a_fresh_ask(monkeypatch):
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"setIncident": "require_approval"},
        command_handlers={"setIncident": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )
    result = gtb.guardian_tool_bridge_run("setIncident", {"id": "1"}, approval_id="not-a-real-id")
    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "not found" in tool_result["error"].lower()
    assert executed == []
    # No NEW pending row should have been created either -- a bad token must
    # never quietly fall back to "ok, here's a fresh ask instead".
    assert len(audit["ledger"]) == 0


def test_kill_switch_halts_even_an_approved_token(monkeypatch):
    """SAFETY invariant: kill-switch halts an approved action too -- the
    token is never consumed (still usable once the kill switch clears), the
    underlying command is never dispatched."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"setIncident": "require_approval"},
        command_handlers={"setIncident": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )
    park_result = gtb.guardian_tool_bridge_run("setIncident", {"id": "1"})
    approval_id = park_result["data"]["tool_result"]["result"]["approval_id"]
    audit["ledger"][0]["status"] = "approved"

    # Flip the kill switch on for the NEXT call only.
    audit2 = _install_gates(
        monkeypatch,
        kill_switch={"enabled": True},
        policy={"setIncident": "require_approval"},
        approvals_ledger=audit["ledger"],
        command_handlers={"setIncident": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )

    result = gtb.guardian_tool_bridge_run("setIncident", {"id": "1"}, approval_id=approval_id)
    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "halted"
    assert executed == []
    # The token was never touched -- still approved, still unconsumed.
    assert audit2["ledger"][0]["status"] == "approved"
    assert audit2["ledger"][0]["consumed"] is False


def test_denylist_still_wins_over_an_approved_token(monkeypatch):
    """SAFETY invariant: an approved token bypasses ONLY the require_approval
    park -- it can never bypass the denylist. Simulates a data
    inconsistency (a command both require_approval-tiered AND bare-
    denylisted) to prove the denylist gate (Step 2, unconditional) still
    wins regardless of a validly-approved, validly-consumable token."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        denylist={"denied": ["setIncident"], "protected_lists": []},
        policy={"setIncident": "require_approval"},
        command_handlers={"setIncident": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )
    # Manually seed an "approved" ledger row -- can't park normally since the
    # denylist denies before ever reaching the require_approval branch.
    audit["ledger"].append(
        {
            "approval_id": "forged-1",
            "kind": "tool",
            "tool_name": "setIncident",
            "tool_args": {"id": "1"},
            "canonical_args": gtb.guardian_bridge_canonical_json({"id": "1"}),
            "status": "approved",
            "consumed": False,
        }
    )

    result = gtb.guardian_tool_bridge_run("setIncident", {"id": "1"}, approval_id="forged-1")
    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "bare guardian_tool_denylist" in tool_result["error"]
    assert executed == []
    assert audit["ledger"][-1]["consumed"] is False  # never even reached the token check


def test_plan_step_consumption_executes_each_step_exactly_once(monkeypatch):
    """The plan-approval counterpart: two steps in one approved kind:"plan"
    row, each consumed and executed independently, each producing its own
    audit row, and each step's own token is single-use."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"xdr-isolate-endpoint": "require_approval", "closeInvestigation": "require_approval"},
        command_handlers={
            "xdr-isolate-endpoint": lambda args: executed.append(("xdr-isolate-endpoint", args)) or [{"Type": 1, "Contents": "done"}],
            "closeInvestigation": lambda args: executed.append(("closeInvestigation", args))
            or [{"Type": 1, "Contents": "done"}],
        },
    )
    plan_row = {
        "approval_id": "plan-1",
        "kind": "plan",
        "status": "approved",
        "steps": [
            {
                "tool_name": "xdr-isolate-endpoint",
                "tool_args": {"id": "1"},
                "canonical_args": gtb.guardian_bridge_canonical_json({"id": "1"}),
                "consumed": False,
            },
            {
                "tool_name": "closeInvestigation",
                "tool_args": {"id": "1"},
                "canonical_args": gtb.guardian_bridge_canonical_json({"id": "1"}),
                "consumed": False,
            },
        ],
    }
    audit["ledger"].append(plan_row)

    step0_result = gtb.guardian_tool_bridge_run(
        "xdr-isolate-endpoint", {"id": "1"}, plan_approval_id="plan-1", plan_step_index=0
    )
    assert step0_result["data"]["tool_result"]["status"] == "ok"

    step1_result = gtb.guardian_tool_bridge_run(
        "closeInvestigation", {"id": "1"}, plan_approval_id="plan-1", plan_step_index=1
    )
    assert step1_result["data"]["tool_result"]["status"] == "ok"

    assert executed == [("xdr-isolate-endpoint", {"id": "1"}), ("closeInvestigation", {"id": "1"})]
    assert audit["ledger"][-1]["steps"][0]["consumed"] is True
    assert audit["ledger"][-1]["steps"][1]["consumed"] is True
    # 2 execution audit rows -- one per step, both individually audited.
    assert len(audit["calls"]) == 2

    # Replaying step 0 must be denied and must not re-execute it.
    replay = gtb.guardian_tool_bridge_run("xdr-isolate-endpoint", {"id": "1"}, plan_approval_id="plan-1", plan_step_index=0)
    assert replay["data"]["tool_result"]["status"] == "denied"
    assert executed == [("xdr-isolate-endpoint", {"id": "1"}), ("closeInvestigation", {"id": "1"})]


def test_plan_step_pending_plan_is_denied_not_executed(monkeypatch):
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"setIncident": "require_approval"},
        command_handlers={"setIncident": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )
    audit["ledger"].append(
        {
            "approval_id": "plan-2",
            "kind": "plan",
            "status": "pending",
            "steps": [
                {
                    "tool_name": "setIncident",
                    "tool_args": {"id": "1"},
                    "canonical_args": gtb.guardian_bridge_canonical_json({"id": "1"}),
                    "consumed": False,
                }
            ],
        }
    )
    result = gtb.guardian_tool_bridge_run("setIncident", {"id": "1"}, plan_approval_id="plan-2", plan_step_index=0)
    assert result["data"]["tool_result"]["status"] == "denied"
    assert executed == []


def test_approved_via_recorded_in_audit_detail_not_a_new_status(monkeypatch):
    """task-3.1-context.md: "audit status:'ok' auto/approved" -- this build
    keeps `status` as the ordinary ok/error the execution produced, and
    records the approval provenance in `detail.approved_via` instead of
    inventing a new status value (see the bridge's own module docstring).
    """
    audit = _install_gates(
        monkeypatch,
        policy={"closeInvestigation": "require_approval"},
        command_handlers={"closeInvestigation": lambda args: [{"Type": 1, "Contents": "done"}]},
    )
    park_result = gtb.guardian_tool_bridge_run("closeInvestigation", {"id": "1"})
    approval_id = park_result["data"]["tool_result"]["result"]["approval_id"]
    audit["ledger"][0]["status"] = "approved"

    gtb.guardian_tool_bridge_run("closeInvestigation", {"id": "1"}, approval_id=approval_id)

    exec_audit_row = audit["calls"][-1]
    assert exec_audit_row["status"] == "ok"
    assert exec_audit_row["detail"]["approved_via"] == {"approval_id": approval_id}


# --- setIncident routing (bug 3): always target THIS run's incident, write via REST ------------
def test_run_set_incident_targets_current_incident_ignoring_model_id(monkeypatch):
    """The model routinely hallucinates the setIncident `id` (observed live: id:54). The write must
    always target demisto.incident()'s id, and the model's id/version/using are dropped as control
    args -- never persisted as fields."""
    captured = {}
    monkeypatch.setattr(gtb.demisto, "incident", lambda: {"id": "29676", "name": "case"})
    monkeypatch.setattr(
        gtb,
        "guardian_set_incident_fields",
        lambda incident_id, fields: captured.update(id=incident_id, fields=fields)
        or gtb.guardian_envelope(True, data={"id": incident_id, "fields": fields}),
    )

    env = gtb.guardian_bridge_run_set_incident(
        {"id": "54", "version": 7, "using": "inst", "guardianverdict": "Malicious", "guardianconfidence": 90}
    )

    assert env["ok"] is True
    assert captured["id"] == "29676"  # real incident, NOT the model's id:54
    assert captured["fields"] == {"guardianverdict": "Malicious", "guardianconfidence": 90}


def test_run_set_incident_lifts_nested_custom_fields_lowercased(monkeypatch):
    captured = {}
    monkeypatch.setattr(gtb.demisto, "incident", lambda: {"id": "7"})
    monkeypatch.setattr(
        gtb,
        "guardian_set_incident_fields",
        lambda incident_id, fields: captured.update(id=incident_id, fields=fields) or gtb.guardian_envelope(True),
    )

    gtb.guardian_bridge_run_set_incident(
        {
            "severity": 3,
            "guardianverdict": "TopLevel",  # nested member below must WIN
            "customFields": {"GuardianVerdict": "Nested", "guardianconfidence": 20},
        }
    )

    # Top-level + nested members both present; cliNames lowercased; nested wins on collision.
    assert captured["fields"] == {"severity": 3, "guardianverdict": "Nested", "guardianconfidence": 20}


def test_run_set_incident_errors_without_current_incident(monkeypatch):
    monkeypatch.setattr(gtb.demisto, "incident", lambda: {})
    called = []
    monkeypatch.setattr(gtb, "guardian_set_incident_fields", lambda *a, **k: called.append(a))

    env = gtb.guardian_bridge_run_set_incident({"guardianverdict": "Malicious"})

    assert env["ok"] is False
    assert "no current incident" in env["error"]
    assert called == []  # never attempts a write with no target


def test_setincident_e2e_writes_current_incident_via_rest_not_model_id(monkeypatch):
    """End-to-end through the bridge: an approved setIncident writes to THIS run's incident id via the
    REST upsert (guardian_set_incident_fields), NOT the model's hallucinated id, and NOT via
    executeCommand (the command form silently drops custom fields on 6.14.0)."""
    captured = {}
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"setIncident": "require_approval"},
        incident={"id": "29676", "name": "Credential phishing"},
        command_handlers={"setIncident": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )
    monkeypatch.setattr(
        gtb,
        "guardian_set_incident_fields",
        lambda incident_id, fields: captured.update(id=incident_id, fields=fields)
        or gtb.guardian_envelope(True, data={"id": incident_id, "fields": fields}),
    )

    park = gtb.guardian_tool_bridge_run("setIncident", {"id": "54", "guardianverdict": "Malicious"})
    approval_id = park["data"]["tool_result"]["result"]["approval_id"]
    audit["ledger"][0]["status"] = "approved"

    result = gtb.guardian_tool_bridge_run(
        "setIncident", {"id": "54", "guardianverdict": "Malicious"}, approval_id=approval_id
    )

    assert result["data"]["tool_result"]["status"] == "ok"
    assert captured["id"] == "29676"  # wrote the REAL incident, ignoring the model's id:54
    assert captured["fields"] == {"guardianverdict": "Malicious"}
    assert executed == []  # REST path only -- executeCommand never dispatched for setIncident


# --- splunk-search polling normalization ---------------------------------------
# splunk-search's own polling=true path relies on a platform ScheduledCommand
# only the PLAYBOOK TASK ENGINE can drive to completion by re-invoking the
# task later. This bridge only ever dispatches via a plain executeCommand
# call, which can never trigger that re-invocation -- a still-running job
# then returns one static "scheduled to re-check" entry that never fires,
# silently stalling the investigation on what reads as a real response.
# Without polling set at all, splunk-search uses Splunk's own BLOCKING exec
# mode instead and returns complete results in the same dispatch.


def test_normalize_splunk_search_args_strips_polling_true():
    normalized, stripped = gtb.guardian_bridge_normalize_splunk_search_args(
        {"query": "index=* | head 3", "polling": "true"}
    )
    assert normalized == {"query": "index=* | head 3"}
    assert stripped is True


def test_normalize_splunk_search_args_strips_polling_false_too():
    """Even an explicit polling=false is stripped -- the point is that
    splunk-search never sees the key at all from this bridge, not that a
    specific value is filtered."""
    normalized, stripped = gtb.guardian_bridge_normalize_splunk_search_args(
        {"query": "index=* | head 3", "polling": "false"}
    )
    assert normalized == {"query": "index=* | head 3"}
    assert stripped is True


def test_normalize_splunk_search_args_no_op_when_polling_absent():
    args = {"query": "index=* | head 3"}
    normalized, stripped = gtb.guardian_bridge_normalize_splunk_search_args(args)
    assert normalized == args
    assert normalized is args  # no copy made when there's nothing to strip
    assert stripped is False


def test_normalize_splunk_search_args_tolerates_non_dict_input():
    normalized, stripped = gtb.guardian_bridge_normalize_splunk_search_args("not-a-dict")
    assert normalized == "not-a-dict"
    assert stripped is False


def test_run_splunk_search_strips_polling_before_dispatch(monkeypatch):
    """End-to-end: a model-supplied polling=true never reaches
    executeCommand, and the audit row records that the strip happened."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"splunk-search": "allow"},
        command_handlers={
            "splunk-search": lambda args: executed.append(args) or [{"Type": 1, "Contents": {"results": []}}]
        },
    )

    result = gtb.guardian_tool_bridge_run("splunk-search", {"query": "index=* | head 3", "polling": "true"})

    assert result["data"]["tool_result"]["status"] == "ok"
    assert executed == [{"query": "index=* | head 3"}]  # polling never reached the real command
    assert audit["calls"][0]["detail"]["splunk_polling_stripped"] is True


def test_run_splunk_search_without_polling_leaves_detail_flag_false(monkeypatch):
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"splunk-search": "allow"},
        command_handlers={
            "splunk-search": lambda args: executed.append(args) or [{"Type": 1, "Contents": {"results": []}}]
        },
    )

    result = gtb.guardian_tool_bridge_run("splunk-search", {"query": "index=* | head 3"})

    assert result["data"]["tool_result"]["status"] == "ok"
    assert executed == [{"query": "index=* | head 3"}]
    assert audit["calls"][0]["detail"]["splunk_polling_stripped"] is False


def test_run_other_commands_unaffected_by_splunk_polling_strip(monkeypatch):
    """Sanity: the normalization is scoped to splunk-search by name -- a
    DIFFERENT command's own polling-shaped argument (if it ever had one)
    must not be touched by this special-case branch."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={"ip": "allow"},
        command_handlers={"ip": lambda args: executed.append(args) or [{"Type": 1, "Contents": {"score": 1}}]},
    )

    result = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1", "polling": "true"})

    assert result["data"]["tool_result"]["status"] == "ok"
    assert executed == [{"ip": "1.1.1.1", "polling": "true"}]
    assert audit["calls"][0]["detail"]["splunk_polling_stripped"] is False


# --- write-capable SPL in a Splunk query ------------------------------------------
# splunk-search is on the shipped read-only allowlist, but SPL can write
# (collect, outputlookup), send (sendemail, sendalert) and delete. A query
# carrying any such command is "destructive" and parks for a human, exactly
# like splunk-job-create already does by policy.


def _shipped_list(list_name):
    return json.loads(_shipped_list_text(list_name))


def _install_shipped_gates(monkeypatch, executed, incident=None):
    return _install_gates(
        monkeypatch,
        allowlist=_shipped_list("guardian_tool_allowlist"),
        denylist=_shipped_list("guardian_tool_denylist"),
        policy=_shipped_list("guardian_policy"),
        preapproved=_shipped_list("guardian_preapproved"),
        incident=incident,
        command_handlers={
            "splunk-search": lambda args: executed.append(args) or [{"Type": 1, "Contents": {"results": []}}]
        },
    )


@pytest.mark.parametrize(
    "query, expected",
    [
        ("index=main | outputlookup probe.csv", ["outputlookup"]),
        ("index=notable | collect index=main", ["collect"]),
        ("| makeresults | sendemail to=a@example.com", ["sendemail"]),
        ("| makeresults | sendalert notable", ["sendalert"]),
        ("index=main | delete", ["delete"]),
        ("index=main [ search index=_internal | head 1 | outputlookup x.csv ]", ["outputlookup"]),
        ("index=main [| savedsearch nightly]", ["savedsearch"]),
        ('| makeresults | map search="search index=x | outputlookup y.csv"', ["map", "outputlookup"]),
        ("index=main | OutputLookup probe.csv", ["outputlookup"]),  # SPL is case-insensitive
        ("index=main\n| collect index=summary", ["collect"]),
        ("index=main|tscollect namespace=x", ["tscollect"]),
    ],
)
def test_spl_write_commands_found(query, expected):
    assert gtb.guardian_bridge_spl_write_commands("splunk-search", {"query": query}) == expected
    assert gtb.guardian_bridge_risk_tier("splunk-search", {"query": query}) == "destructive"


@pytest.mark.parametrize(
    "query",
    [
        "index=notable | head 10",
        "search index=main sourcetype=access_combined | stats count by src_ip",
        "index=main action=delete OR user=collect | table _time user action",  # words as values, not commands
        "| tstats count where index=main by host",
        "| inputlookup assets.csv | lookup identities user",
        "index=main | eval note=\"sendemail\" | table note",
    ],
)
def test_spl_read_only_queries_stay_soft(query):
    assert gtb.guardian_bridge_spl_write_commands("splunk-search", {"query": query}) == []
    assert gtb.guardian_bridge_risk_tier("splunk-search", {"query": query}) == "soft"


def test_spl_scan_covers_every_string_argument_not_only_query():
    """A renamed or aliased argument must not carry SPL past the scan."""
    args = {"query": "index=main | head 1", "search": "index=main | outputlookup x.csv", "event_limit": 10}
    assert gtb.guardian_bridge_spl_write_commands("splunk-search", args) == ["outputlookup"]


def test_spl_scan_is_scoped_to_splunk_query_commands():
    """The value scan never runs for other tools: an `ip` lookup whose value
    happens to read like SPL stays soft."""
    assert gtb.guardian_bridge_spl_write_commands("ip", {"ip": "| outputlookup x.csv"}) == []
    assert gtb.guardian_bridge_risk_tier("ip", {"ip": "| outputlookup x.csv"}) == "soft"
    assert gtb.guardian_bridge_spl_write_commands("splunk-search", "not-a-dict") == []


def test_run_write_spl_parks_with_shipped_lists(monkeypatch):
    """End to end with the lists the pack actually ships: a write query is held
    for approval, never reaches Splunk, and the audit row says which SPL
    command caused the hold."""
    executed = []
    audit = _install_shipped_gates(monkeypatch, executed)

    result = gtb.guardian_tool_bridge_run("splunk-search", {"query": "index=notable | collect index=main"})

    assert result["data"]["tool_result"]["status"] == "pending_approval"
    assert executed == []
    detail = audit["calls"][0]["detail"]
    assert detail["risk_tier"] == "destructive"
    assert detail["would_require_approval"] is True
    assert detail["spl_write_commands"] == ["collect"]


def test_run_read_only_spl_still_dispatches_with_shipped_lists(monkeypatch):
    executed = []
    audit = _install_shipped_gates(monkeypatch, executed)

    result = gtb.guardian_tool_bridge_run("splunk-search", {"query": "index=notable | head 5"})

    assert result["data"]["tool_result"]["status"] == "ok"
    assert executed == [{"query": "index=notable | head 5"}]
    assert "spl_write_commands" not in audit["calls"][0]["detail"]


def test_run_write_spl_still_parks_in_bypass_mode(monkeypatch):
    executed = []
    _install_shipped_gates(monkeypatch, executed, incident={"CustomFields": {"guardianapprovalmode": "bypass"}})

    result = gtb.guardian_tool_bridge_run("splunk-search", {"query": "index=main | outputlookup x.csv"})

    assert result["data"]["tool_result"]["status"] == "pending_approval"
    assert executed == []


def test_run_write_spl_executes_once_after_human_approval(monkeypatch):
    """The hold is a real approval, not a dead end: once a human approves, the
    exact same query runs once, and the token can't be replayed."""
    executed = []
    audit = _install_shipped_gates(monkeypatch, executed)
    args = {"query": "index=notable | outputlookup triage_snapshot.csv"}

    park = gtb.guardian_tool_bridge_run("splunk-search", args)
    approval_id = park["data"]["tool_result"]["result"]["approval_id"]
    audit["ledger"][0]["status"] = "approved"
    audit["ledger"][0]["resolved_by"] = "alice"

    first = gtb.guardian_tool_bridge_run("splunk-search", args, approval_id=approval_id)
    replay = gtb.guardian_tool_bridge_run("splunk-search", args, approval_id=approval_id)

    assert first["data"]["tool_result"]["status"] == "ok"
    assert replay["data"]["tool_result"]["status"] == "denied"
    assert executed == [args]


def test_consume_approval_token_helper_reports_ledger_unreadable(monkeypatch):
    _install_gates(monkeypatch, list_errors={"guardian_approvals_ledger": "connection refused"})
    result = gtb.guardian_bridge_consume_approval_token("x", "setIncident", {})
    assert result["ok"] is False
    assert "unreadable" in result["error"]


def test_consume_plan_step_helper_rejects_out_of_range_index(monkeypatch):
    audit = _install_gates(monkeypatch)
    audit["ledger"].append({"approval_id": "plan-3", "kind": "plan", "status": "approved", "steps": []})
    result = gtb.guardian_bridge_consume_plan_step("plan-3", 0, "setIncident", {})
    assert result["ok"] is False
    assert "no step index" in result["error"]


# --- Task 4.4: pre-approved autonomous containment (bypass mode) -------------
# SECURITY-CRITICAL: the acceptance-critical behavior is (1) a narrow,
# explicit pre-approved class auto-executes ONLY in bypass mode, fully
# audited; (2) the SAME command in manual mode still parks; (3) a
# destructive/credential-tier command NEVER auto-executes even in bypass
# mode, even if (by data error) it appeared in guardian_preapproved; (4) an
# off-class call (wrong command, wrong/extra args) in bypass mode still
# parks; (5) kill-switch/denylist/default-deny all still win over a
# pre-approved bypass match.

_BYPASS_INCIDENT = {"id": "900", "CustomFields": {"guardianapprovalmode": "bypass"}}
_MANUAL_INCIDENT = {"id": "900", "CustomFields": {"guardianapprovalmode": "manual"}}
_TAG_ADD_ARGS = {"endpoint_ids": "ep-1,ep-2", "tag": "guardian-auto-flagged"}


def test_preapproved_match_in_bypass_mode_auto_executes_and_audits(monkeypatch):
    executed = []
    audit = _install_gates(
        monkeypatch,
        incident=_BYPASS_INCIDENT,
        command_handlers={
            "xdr-endpoint-tag-add": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]
        },
    )

    result = gtb.guardian_tool_bridge_run("xdr-endpoint-tag-add", _TAG_ADD_ARGS, tick_id="7", run_id="900")

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "ok"
    assert tool_result["ok"] is True
    assert executed == [_TAG_ADD_ARGS]

    # No approval ledger row was ever created -- this is a genuinely
    # DIFFERENT path from the human-approval park/resolve/consume flow.
    assert audit["ledger"] == []

    # Exactly one audit row, fully marked as an auto-approved bypass dispatch.
    assert len(audit["calls"]) == 1
    row = audit["calls"][0]
    assert row["status"] == "ok"
    assert row["detail"]["auto_approved"] is True
    assert row["detail"]["bypass_source"] == "bypass"
    assert row["detail"]["approved_via"] == {
        "auto_approved": True,
        "bypass_source": "bypass",
        "preapproved_class": "xdr-endpoint-tag-add",
    }


def test_preapproved_shadow_class_match_parks_instead_of_auto_executing(monkeypatch):
    """harvest candidate #7: a shadow-flagged class that
    WOULD otherwise auto-execute must still park for a human exactly like
    an ordinary require_approval ask -- the shadow flag records evidence,
    it never grants autonomy."""
    shadow_preapproved = {
        "classes": [
            {
                "command": "xdr-endpoint-tag-add",
                "shadow": True,
                "arg_constraints": {
                    "endpoint_ids": {"required": True},
                    "tag": {"required": True, "allowed_values": ["guardian-auto-flagged"]},
                },
            }
        ]
    }
    executed = []
    audit = _install_gates(
        monkeypatch,
        incident=_BYPASS_INCIDENT,
        preapproved=shadow_preapproved,
        command_handlers={
            "xdr-endpoint-tag-add": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]
        },
    )

    result = gtb.guardian_tool_bridge_run("xdr-endpoint-tag-add", _TAG_ADD_ARGS, tick_id="7", run_id="900")

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "pending_approval"
    assert tool_result["ok"] is False
    assert executed == []  # never actually dispatched -- shadow never grants autonomy

    assert len(audit["ledger"]) == 1
    assert audit["ledger"][0]["status"] == "pending"

    assert len(audit["calls"]) == 1
    assert audit["calls"][0]["status"] == "pending_approval"
    assert audit["calls"][0]["detail"]["shadow_would_have_approved"] == "xdr-endpoint-tag-add"


def test_preapproved_non_shadow_match_leaves_shadow_field_none(monkeypatch):
    """Regression guard for the new detail key's default: an ordinary
    (non-shadow) auto-executed match must not report a shadow verdict --
    it genuinely executed, there is nothing hypothetical to record."""
    audit = _install_gates(
        monkeypatch,
        incident=_BYPASS_INCIDENT,
        command_handlers={"xdr-endpoint-tag-add": lambda args: [{"Type": 1, "Contents": "done"}]},
    )

    gtb.guardian_tool_bridge_run("xdr-endpoint-tag-add", _TAG_ADD_ARGS, tick_id="7", run_id="900")

    assert "shadow_would_have_approved" not in audit["calls"][0]["detail"]


def test_preapproved_shadow_flag_does_not_weaken_the_destructive_tier_gate(monkeypatch):
    """Shadow only changes WHICH of the two matching outcomes applies when
    a match is found -- it must not let a shadowed class reach the matcher
    at all for a destructive-tier command; gate 1 (risk tier) still runs
    first and blocks evaluation entirely, same as with no shadow flag."""
    shadow_preapproved = {
        "classes": [{"command": "closeInvestigation", "shadow": True, "arg_constraints": {}}]
    }
    executed = []
    audit = _install_gates(
        monkeypatch,
        incident=_BYPASS_INCIDENT,
        preapproved=shadow_preapproved,
        policy={"closeInvestigation": "require_approval"},
        command_handlers={"closeInvestigation": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )

    result = gtb.guardian_tool_bridge_run("closeInvestigation", {"id": "900"})

    assert result["data"]["tool_result"]["status"] == "pending_approval"
    assert executed == []
    assert audit["calls"][0]["detail"]["shadow_would_have_approved"] is None


def test_preapproved_same_command_in_manual_mode_is_gated(monkeypatch):
    """The identical command+args that auto-executes in bypass mode must
    still PARK in manual mode -- pre-approval is opt-in per incident, never
    a blanket change to the command's tier."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        incident=_MANUAL_INCIDENT,
        command_handlers={
            "xdr-endpoint-tag-add": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]
        },
    )

    result = gtb.guardian_tool_bridge_run("xdr-endpoint-tag-add", _TAG_ADD_ARGS)

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "pending_approval"
    assert tool_result["ok"] is False
    assert executed == []
    assert len(audit["ledger"]) == 1
    assert audit["ledger"][0]["status"] == "pending"


def test_preapproved_no_incident_at_all_defaults_to_manual_and_is_gated(monkeypatch):
    """No incident context (e.g. Playground) -- guardian_bridge_get_approval_mode
    defaults to 'manual', the safer of the two values, so this must park too."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        command_handlers={
            "xdr-endpoint-tag-add": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]
        },
    )

    result = gtb.guardian_tool_bridge_run("xdr-endpoint-tag-add", _TAG_ADD_ARGS)

    assert result["data"]["tool_result"]["status"] == "pending_approval"
    assert executed == []
    assert len(audit["ledger"]) == 1


def test_preapproved_destructive_command_in_bypass_mode_still_gated(monkeypatch):
    """SAFETY invariant: a destructive-tier command NEVER auto-executes in
    bypass mode -- even if (by data error) guardian_preapproved names it.
    The risk-tier check runs BEFORE the class-match check and wins
    unconditionally."""
    executed = []
    misconfigured_preapproved = {
        "classes": [
            {"command": "xdr-isolate-endpoint", "arg_constraints": {"endpoint_id": {"required": True}}}
        ]
    }
    audit = _install_gates(
        monkeypatch,
        incident=_BYPASS_INCIDENT,
        preapproved=misconfigured_preapproved,
        command_handlers={
            "xdr-isolate-endpoint": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]
        },
    )

    result = gtb.guardian_tool_bridge_run("xdr-isolate-endpoint", {"endpoint_id": "ep-1"})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "pending_approval"
    assert executed == []
    assert len(audit["ledger"]) == 1
    assert audit["ledger"][0]["risk_tier"] == "destructive"


def test_preapproved_credential_tier_command_in_bypass_mode_still_gated(monkeypatch):
    """SAFETY invariant, credential side: a credential-flavored command name
    (matched by GUARDIAN_RISK_TIER_CREDENTIAL_SUBSTRINGS) never auto-executes
    in bypass mode either, even with a matching guardian_preapproved class."""
    executed = []
    credential_preapproved = {
        "classes": [{"command": "rotateApiKey", "arg_constraints": {"id": {"required": True}}}]
    }
    audit = _install_gates(
        monkeypatch,
        policy={"rotateApiKey": "require_approval"},
        incident=_BYPASS_INCIDENT,
        preapproved=credential_preapproved,
        command_handlers={"rotateApiKey": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )

    result = gtb.guardian_tool_bridge_run("rotateApiKey", {"id": "1"})

    assert result["data"]["tool_result"]["status"] == "pending_approval"
    assert executed == []
    assert len(audit["ledger"]) == 1


def test_preapproved_off_class_command_in_bypass_mode_is_gated(monkeypatch):
    """A require_approval command that simply has NO matching
    guardian_preapproved class (e.g. setIncident) must still park normally
    in bypass mode -- bypass only ever narrows to the explicit class list,
    never widens to "everything require_approval"."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        incident=_BYPASS_INCIDENT,
        command_handlers={"setIncident": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )

    result = gtb.guardian_tool_bridge_run("setIncident", {"id": "1", "severity": 4})

    assert result["data"]["tool_result"]["status"] == "pending_approval"
    assert executed == []
    assert len(audit["ledger"]) == 1


def test_preapproved_class_match_but_not_code_allowlisted_is_still_gated(monkeypatch):
    """FIX 1 (final-review hardening, SECURITY-CRITICAL): a
    guardian_preapproved List entry ALONE can never widen auto-execution --
    the command must ALSO be a member of this file's own
    GUARDIAN_AUTO_APPROVABLE_COMMANDS frozenset. Here setIncident is a
    soft-tier require_approval command that (by a hypothetical/misconfigured
    List edit) DOES match an explicit guardian_preapproved class, and the
    incident IS in bypass mode -- everything that would have auto-executed
    it before this fix is true except code-level membership, so it must
    still PARK, never auto-execute."""
    executed = []
    misconfigured_preapproved = {
        "classes": [
            {
                "command": "setIncident",
                "arg_constraints": {"id": {"required": True}, "severity": {"required": True}},
            }
        ]
    }
    audit = _install_gates(
        monkeypatch,
        incident=_BYPASS_INCIDENT,
        preapproved=misconfigured_preapproved,
        command_handlers={"setIncident": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]},
    )

    result = gtb.guardian_tool_bridge_run("setIncident", {"id": "1", "severity": 4})

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "pending_approval"
    assert executed == []
    assert len(audit["ledger"]) == 1
    assert audit["ledger"][0]["status"] == "pending"


def test_auto_approvable_commands_frozenset_is_narrowly_scoped():
    """Documents/locks the current, deliberately narrow contents of the
    code-level allow-map -- widening it is a reviewed code change, never
    just a guardian_preapproved List edit (see the module docstring's
    "PART A" section and GUARDIAN_AUTO_APPROVABLE_COMMANDS's own comment).
    Task 2 added GuardianContainmentSimulate (a DUMMY inert command) as the
    second-ever member."""
    assert gtb.GUARDIAN_AUTO_APPROVABLE_COMMANDS == frozenset(
        {"xdr-endpoint-tag-add", "GuardianContainmentSimulate"}
    )


def test_preapproved_wrong_tag_value_in_bypass_mode_is_gated(monkeypatch):
    """The class-match itself must be exact: a tag value OUTSIDE
    allowed_values fails the match and falls back to a normal park, even
    though the command name and every other constraint are otherwise
    satisfied."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        incident=_BYPASS_INCIDENT,
        command_handlers={
            "xdr-endpoint-tag-add": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]
        },
    )

    result = gtb.guardian_tool_bridge_run(
        "xdr-endpoint-tag-add", {"endpoint_ids": "ep-1", "tag": "some-unreviewed-label"}
    )

    assert result["data"]["tool_result"]["status"] == "pending_approval"
    assert executed == []
    assert len(audit["ledger"]) == 1


def test_preapproved_extra_unrecognized_arg_in_bypass_mode_is_gated(monkeypatch):
    """An argument the class never anticipated (e.g. a `using` override or
    any other extra key) fails the match outright -- never silently
    ignored -- so this falls back to a normal park too."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        incident=_BYPASS_INCIDENT,
        command_handlers={
            "xdr-endpoint-tag-add": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]
        },
    )
    smuggled_args = dict(_TAG_ADD_ARGS, unexpected_extra_arg="anything")

    result = gtb.guardian_tool_bridge_run("xdr-endpoint-tag-add", smuggled_args)

    assert result["data"]["tool_result"]["status"] == "pending_approval"
    assert executed == []
    assert len(audit["ledger"]) == 1


def test_preapproved_unreadable_list_fails_closed_to_normal_gate(monkeypatch):
    """guardian_preapproved unreadable -- treated as NO classes at all
    (fail-closed), so even an otherwise-matching call just parks like
    manual mode would, never denied outright and never auto-executed."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        incident=_BYPASS_INCIDENT,
        list_errors={"guardian_preapproved": "connection refused"},
        command_handlers={
            "xdr-endpoint-tag-add": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]
        },
    )

    result = gtb.guardian_tool_bridge_run("xdr-endpoint-tag-add", _TAG_ADD_ARGS)

    assert result["data"]["tool_result"]["status"] == "pending_approval"
    assert executed == []
    assert len(audit["ledger"]) == 1


def test_kill_switch_halts_a_preapproved_bypass_action(monkeypatch):
    """SAFETY invariant: the kill switch halts a pre-approved action before
    ANY of the bypass/class-match logic ever runs -- the command is never
    dispatched, and no auto_approved audit row is produced."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        kill_switch={"enabled": True},
        incident=_BYPASS_INCIDENT,
        command_handlers={
            "xdr-endpoint-tag-add": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]
        },
    )

    result = gtb.guardian_tool_bridge_run("xdr-endpoint-tag-add", _TAG_ADD_ARGS)

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "halted"
    assert executed == []
    assert audit["ledger"] == []
    assert len(audit["calls"]) == 1
    assert audit["calls"][0]["status"] == "halted"


def test_denylist_still_wins_over_a_preapproved_bypass_match(monkeypatch):
    """SAFETY invariant: a bare-denylisted command is denied before the
    require_approval/pre-approved branch is ever reached, regardless of
    bypass mode or a matching guardian_preapproved class."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        denylist={"denied": ["xdr-endpoint-tag-add"], "protected_lists": []},
        incident=_BYPASS_INCIDENT,
        command_handlers={
            "xdr-endpoint-tag-add": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]
        },
    )

    result = gtb.guardian_tool_bridge_run("xdr-endpoint-tag-add", _TAG_ADD_ARGS)

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "bare guardian_tool_denylist" in tool_result["error"]
    assert executed == []
    assert audit["ledger"] == []


def test_preapproved_bypass_still_requires_allowlist_or_policy_membership(monkeypatch):
    """SAFETY invariant: the Task 1.3 default-deny gate (neither on
    guardian_tool_allowlist nor a guardian_policy key) still applies before
    bypass/pre-approval logic is ever reached -- an off-catalogue command a
    model invented can't reach auto-execution just by being in bypass mode."""
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={},  # xdr-endpoint-tag-add NOT classified at all this time
        preapproved={
            "classes": [{"command": "xdr-endpoint-tag-add", "arg_constraints": {"tag": {"required": True}}}]
        },
        incident=_BYPASS_INCIDENT,
        command_handlers={
            "xdr-endpoint-tag-add": lambda args: executed.append(args) or [{"Type": 1, "Contents": "done"}]
        },
    )

    result = gtb.guardian_tool_bridge_run("xdr-endpoint-tag-add", _TAG_ADD_ARGS)

    tool_result = result["data"]["tool_result"]
    assert tool_result["status"] == "denied"
    assert "denied by default" in tool_result["error"]
    assert executed == []


# --- guardian_bridge_get_approval_mode ----------------------------------------


def test_get_approval_mode_defaults_to_manual_with_no_incident(monkeypatch):
    monkeypatch.setattr(gtb.demisto, "incident", lambda: {})
    assert gtb.guardian_bridge_get_approval_mode() == "manual"


def test_get_approval_mode_reads_bypass_from_incident_custom_fields(monkeypatch):
    monkeypatch.setattr(gtb.demisto, "incident", lambda: {"CustomFields": {"guardianapprovalmode": "bypass"}})
    assert gtb.guardian_bridge_get_approval_mode() == "bypass"


def test_get_approval_mode_invalid_value_defaults_to_manual(monkeypatch):
    monkeypatch.setattr(gtb.demisto, "incident", lambda: {"CustomFields": {"guardianapprovalmode": "yolo"}})
    assert gtb.guardian_bridge_get_approval_mode() == "manual"


def test_get_approval_mode_incident_raises_defaults_to_manual(monkeypatch):
    def raise_it():
        raise RuntimeError("no incident context")

    monkeypatch.setattr(gtb.demisto, "incident", raise_it)
    assert gtb.guardian_bridge_get_approval_mode() == "manual"


# --- guardian_bridge_class_matches / guardian_bridge_check_preapproved --------


def test_class_matches_exact_command_and_satisfied_constraints():
    cls = {
        "command": "xdr-endpoint-tag-add",
        "arg_constraints": {
            "endpoint_ids": {"required": True},
            "tag": {"required": True, "allowed_values": ["guardian-auto-flagged"]},
        },
    }
    assert gtb.guardian_bridge_class_matches(cls, "xdr-endpoint-tag-add", _TAG_ADD_ARGS) is True


def test_class_matches_false_for_different_command():
    cls = {"command": "xdr-endpoint-tag-add", "arg_constraints": {"tag": {"required": True}}}
    assert gtb.guardian_bridge_class_matches(cls, "xdr-isolate-endpoint", {"tag": "x"}) is False


def test_class_matches_false_when_required_arg_missing():
    cls = {
        "command": "xdr-endpoint-tag-add",
        "arg_constraints": {"endpoint_ids": {"required": True}, "tag": {"required": True}},
    }
    assert gtb.guardian_bridge_class_matches(cls, "xdr-endpoint-tag-add", {"tag": "guardian-auto-flagged"}) is False


def test_class_matches_false_when_allowed_values_violated():
    cls = {
        "command": "xdr-endpoint-tag-add",
        "arg_constraints": {"tag": {"required": True, "allowed_values": ["guardian-auto-flagged"]}},
    }
    assert gtb.guardian_bridge_class_matches(cls, "xdr-endpoint-tag-add", {"tag": "not-allowed"}) is False


def test_class_matches_false_when_extra_unrecognized_arg_present():
    cls = {"command": "xdr-endpoint-tag-add", "arg_constraints": {"tag": {"required": True}}}
    args = {"tag": "guardian-auto-flagged", "extra": "smuggled"}
    assert gtb.guardian_bridge_class_matches(cls, "xdr-endpoint-tag-add", args) is False


def test_class_matches_false_when_no_arg_constraints_at_all():
    cls = {"command": "xdr-endpoint-tag-add", "arg_constraints": {}}
    assert gtb.guardian_bridge_class_matches(cls, "xdr-endpoint-tag-add", {}) is False


def test_class_matches_false_for_malformed_class_entry():
    assert gtb.guardian_bridge_class_matches("not-a-dict", "xdr-endpoint-tag-add", {}) is False
    assert gtb.guardian_bridge_class_matches({"command": "x"}, "x", {}) is False


def test_check_preapproved_returns_none_when_list_unreadable(monkeypatch):
    _install_gates(monkeypatch, list_errors={"guardian_preapproved": "boom"})
    assert gtb.guardian_bridge_check_preapproved("xdr-endpoint-tag-add", _TAG_ADD_ARGS) is None


def test_check_preapproved_returns_none_when_no_classes_configured(monkeypatch):
    _install_gates(monkeypatch, preapproved={"classes": []})
    assert gtb.guardian_bridge_check_preapproved("xdr-endpoint-tag-add", _TAG_ADD_ARGS) is None


def test_check_preapproved_returns_matched_class(monkeypatch):
    _install_gates(monkeypatch)
    matched = gtb.guardian_bridge_check_preapproved("xdr-endpoint-tag-add", _TAG_ADD_ARGS)
    assert matched is not None
    assert matched["command"] == "xdr-endpoint-tag-add"


# --- Task-2 wiring: GuardianContainmentSimulate through the pre-approved gate -
# The DUMMY inert containment command (GuardianContainmentSimulate) is a
# SECOND class added to guardian_preapproved/GUARDIAN_AUTO_APPROVABLE_COMMANDS
# alongside xdr-endpoint-tag-add -- these tests lock the same invariants the
# Task 4.4 suite above already locks for the tag-add class: (1) it tiers
# "soft" (no destructive/credential substring in the name); (2) an in-class
# call in bypass mode auto-executes and is fully audited
# (detail.auto_approved is True); (3) manual mode still parks; (4) an
# out-of-class call (an argument the class doesn't name) still parks even in
# bypass mode; (5) removing it from the CODE-level frozenset alone (List
# class still present) still parks -- the List can never widen autonomy on
# its own; (6) a genuinely destructive command is never auto-approved by
# bypass mode regardless of what GUARDIAN_AUTO_APPROVABLE_COMMANDS contains.

_CONTAIN = "GuardianContainmentSimulate"
_INCLASS = {"endpoint_id": "EP-1", "reason": "confirmed"}
_PREAPPROVED = {"classes": [{"command": _CONTAIN,
    "arg_constraints": {"endpoint_id": {"required": True}, "reason": {"required": False}}}]}


def test_contain_risk_tier_is_soft(monkeypatch):
    _install_gates(monkeypatch)
    assert gtb.guardian_bridge_risk_tier(_CONTAIN) == "soft"


def test_contain_bypass_inclass_auto_executes_audited(monkeypatch):
    executed = []
    audit = _install_gates(
        monkeypatch,
        policy={_CONTAIN: "require_approval"},
        preapproved=_PREAPPROVED,
        incident={"id": "1", "CustomFields": {"guardianapprovalmode": "bypass"}},
        command_handlers={_CONTAIN: lambda a: executed.append(a) or [{"Type": 1, "Contents": "ok"}]},
    )
    monkeypatch.setattr(gtb, "GUARDIAN_AUTO_APPROVABLE_COMMANDS", frozenset({_CONTAIN}))
    result = gtb.guardian_tool_bridge_run(_CONTAIN, dict(_INCLASS))
    tr = result["data"]["tool_result"]
    assert tr["status"] == "ok" and executed == [_INCLASS]
    assert audit["calls"][-1]["detail"]["auto_approved"] is True


def test_contain_manual_parks(monkeypatch):
    _install_gates(monkeypatch, policy={_CONTAIN: "require_approval"}, preapproved=_PREAPPROVED,
                   incident={"id": "1", "CustomFields": {"guardianapprovalmode": "manual"}})
    monkeypatch.setattr(gtb, "GUARDIAN_AUTO_APPROVABLE_COMMANDS", frozenset({_CONTAIN}))
    r = gtb.guardian_tool_bridge_run(_CONTAIN, dict(_INCLASS))
    assert r["data"]["tool_result"]["status"] == "pending_approval"


def test_contain_out_of_class_parks(monkeypatch):
    _install_gates(monkeypatch, policy={_CONTAIN: "require_approval"}, preapproved=_PREAPPROVED,
                   incident={"id": "1", "CustomFields": {"guardianapprovalmode": "bypass"}})
    monkeypatch.setattr(gtb, "GUARDIAN_AUTO_APPROVABLE_COMMANDS", frozenset({_CONTAIN}))
    # extra arg key the class does not name -> out of class -> parks
    r = gtb.guardian_tool_bridge_run(_CONTAIN, {"endpoint_id": "EP-1", "evil": "x"})
    assert r["data"]["tool_result"]["status"] == "pending_approval"


def test_contain_dual_control_frozenset_removed_parks(monkeypatch):
    _install_gates(monkeypatch, policy={_CONTAIN: "require_approval"}, preapproved=_PREAPPROVED,
                   incident={"id": "1", "CustomFields": {"guardianapprovalmode": "bypass"}})
    monkeypatch.setattr(gtb, "GUARDIAN_AUTO_APPROVABLE_COMMANDS", frozenset())  # List class present, code absent
    r = gtb.guardian_tool_bridge_run(_CONTAIN, dict(_INCLASS))
    assert r["data"]["tool_result"]["status"] == "pending_approval"


def test_real_destructive_still_parks_in_bypass(monkeypatch):
    """SECURITY-CRITICAL, and the point of this test: proves the destructive/
    credential RISK-TIER gate itself stops auto-execution, not merely that
    `xdr-isolate-endpoint` never had a matching guardian_preapproved class or
    frozenset entry. Unlike the other tests in this section, THIS fixture
    deliberately gives `xdr-isolate-endpoint` a real, satisfied
    guardian_preapproved class AND puts it in the code-level
    GUARDIAN_AUTO_APPROVABLE_COMMANDS frozenset -- so gates 1 (frozenset
    membership), 3 (bypass mode), and 4 (class-match) all PASS. The ONLY
    thing left standing between this call and auto-execution is Gate 2 (the
    destructive/credential risk-tier check). If that check were ever deleted
    from `guardian_tool_bridge_run`, this call would now sail through every
    remaining gate and auto-execute -- this test would FAIL. Before this fix,
    the fixture supplied no matching class for xdr-isolate-endpoint and
    omitted it from the frozenset, so the test parked for the WRONG reason
    (gates 1/4 failing) and would have kept passing even with Gate 2 deleted."""
    isolate_preapproved = {
        "classes": [
            {
                "command": "xdr-isolate-endpoint",
                "arg_constraints": {"endpoint_id": {"required": True}},
            },
            _PREAPPROVED["classes"][0],  # GuardianContainmentSimulate, kept for realism
        ]
    }
    _install_gates(
        monkeypatch,
        policy={"xdr-isolate-endpoint": "require_approval"},
        preapproved=isolate_preapproved,
        incident={"id": "1", "CustomFields": {"guardianapprovalmode": "bypass"}},
    )
    monkeypatch.setattr(gtb, "GUARDIAN_AUTO_APPROVABLE_COMMANDS", frozenset({"xdr-isolate-endpoint", _CONTAIN}))

    assert gtb.guardian_bridge_risk_tier("xdr-isolate-endpoint") == "destructive"

    r = gtb.guardian_tool_bridge_run("xdr-isolate-endpoint", {"endpoint_id": "EP-1"})
    assert r["data"]["tool_result"]["status"] == "pending_approval"


# --- Cortex XSIAM native commands -------------------------------------------------------------------


def test_xsiam_core_write_and_response_commands_are_destructive():
    for name in ("core-isolate-endpoint", "core-unisolate-endpoint", "core-block-ip", "core-blocklist-files",
                 "core-execute-command", "core-run-script", "core-run-script-kill-process", "core-terminate-process",
                 "core-delete-endpoints", "core-update-issue", "core-update-case", "core-quarantine-files",
                 "xdr-isolate-endpoint", "xdr-run-script", "xdr-update-incident", "core-api-install-packs"):
        assert gtb.guardian_bridge_risk_tier(name) == "destructive", name


def test_xsiam_read_commands_and_endpoint_tags_stay_soft():
    for name in ("core-get-issues", "core-get-cases", "core-get-endpoints", "core-list-risky-hosts", "xdr-xql-generic-query",
                 "xdr-endpoint-tag-add", "core-add-endpoint-tag"):
        assert gtb.guardian_bridge_risk_tier(name) == "soft", name


def test_xsiam_write_commands_are_require_approval_in_the_shipped_policy():
    import json
    import pathlib
    lst = json.loads((pathlib.Path(__file__).resolve().parents[2] / "Lists" / "list-guardian_policy.json").read_text())
    policy = json.loads(lst["data"])
    for name in ("core-isolate-endpoint", "core-execute-command", "core-run-script", "core-block-ip", "core-update-issue"):
        assert policy[name] == "require_approval", name


def test_xsiam_allowlist_holds_only_reads():
    import json
    import pathlib
    lst = json.loads((pathlib.Path(__file__).resolve().parents[2] / "Lists" / "list-guardian_tool_allowlist.json").read_text())
    commands = json.loads(lst["data"])["commands"]
    for name in commands:
        if name.startswith(("core-", "xdr-")):
            assert gtb.guardian_bridge_risk_tier(name) == "soft", name
            assert any(tok in name for tok in ("-get-", "-list-", "-search-", "xql-")), name


def _layout_button_script_names():
    """Every GuardianButton* automation shipped in this pack (the incident-layout action buttons)."""
    return sorted(path.name for path in Path(__file__).resolve().parents[1].glob("GuardianButton*") if path.is_dir())


def test_every_layout_button_script_is_operator_only_in_code():
    names = _layout_button_script_names()
    assert names, "no GuardianButton* scripts found"
    for name in names:
        assert name in gtb.GUARDIAN_OPERATOR_ONLY_COMMANDS, name


def test_layout_buttons_are_denied_even_if_an_operator_adds_them_to_the_allowlist(monkeypatch):
    for name in _layout_button_script_names():
        audit = _install_gates(monkeypatch, runtime_allowlist={"commands": [name]}, policy={})
        result = gtb.guardian_tool_bridge_run(name, {"approval_id": "x"})
        assert result["data"]["tool_result"]["status"] == "denied", name
        assert "operator-only" in result["data"]["tool_result"]["error"]
        assert len(audit["calls"]) == 1


def test_layout_buttons_are_not_in_the_shipped_allowlist_or_policy():
    for list_file in ("list-guardian_tool_allowlist.json", "list-guardian_policy.json"):
        text = (Path(__file__).resolve().parents[2] / "Lists" / list_file).read_text()
        for name in _layout_button_script_names():
            assert name not in text, (list_file, name)


# --- result-shaping limits: the caller's ceiling, the run's numbers, a fresh resolution -----------------------


def test_the_callers_ceiling_is_used_and_clamped(monkeypatch):
    _install_gates(monkeypatch, settings={"evidence_truncate_bytes": 500, "evidence_head_tail_bytes": 50})
    assert gtb.guardian_bridge_load_evidence_limits(138720, 34680) == (138720, 34680)   # an explicit head/tail is honoured
    assert gtb.guardian_bridge_load_evidence_limits("50000") == (50000, 24936)       # text arguments, about half by default
    assert gtb.guardian_bridge_load_evidence_limits(10) == (2048, 960)               # never below the floor
    assert gtb.guardian_bridge_load_evidence_limits(10 ** 10)[0] == 8 * 1024 * 1024  # never above the ceiling
    assert gtb.guardian_bridge_load_evidence_limits(20000, 90000) == (20000, 10000)  # head+tail never exceed the ceiling
    for bad in (0, -1, "lots", True, None):
        assert gtb.guardian_bridge_load_evidence_limits(bad) == (500, 50), bad       # ignored: falls to the settings value


def test_without_an_argument_the_runs_own_numbers_are_used(monkeypatch):
    _install_gates(monkeypatch, settings={})
    params = gtb.guardian_resolve_model_params({"model_tier": "large"}, {"active": "a", "profiles": {"a": {"max_input_tokens": 173400}}})
    monkeypatch.setattr(gtb, "guardian_run_model_params", lambda: (params, "snapshot"))
    assert gtb.guardian_bridge_load_evidence_limits() == (138720, 69296)


def test_without_run_numbers_the_limits_are_resolved_from_the_profile_and_the_catalogue(monkeypatch):
    catalog = json.loads(json.loads(
        (Path(__file__).resolve().parents[2] / "Lists" / "list-guardian_model_catalog.json").read_text())["data"])
    audit = _install_gates(monkeypatch, settings={"model_tier": "auto", "max_input_tokens": 28258})
    del audit
    plist = {"active": "a", "profiles": {"a": {"model": "gpt-5-mini", "catalog_id": "gpt-5-mini", "max_input_tokens": 173400}}}

    def execute(command, args):
        name = args.get("listName")
        if name == "guardian_settings":
            payload = {"model_tier": "auto", "max_input_tokens": 28258}
        elif name == "guardian_model_profile":
            payload = plist
        elif name == "guardian_model_catalog":
            payload = catalog
        else:
            return {"ok": False, "error": "unexpected", "data": None, "retryable": False, "is_auth_error": False}
        return gtb.guardian_envelope(True, data=[{"Contents": json.dumps(payload)}])

    monkeypatch.setattr(gtb, "guardian_run_model_params", lambda: (None, None))
    monkeypatch.setattr(gtb, "guardian_execute", execute)
    monkeypatch.setattr(gtb, "guardian_bridge_load_list_json", lambda name: gtb.guardian_envelope(True, data={"model_tier": "auto"}))
    assert gtb.guardian_bridge_load_evidence_limits() == (138720, 69296)


def test_with_nothing_known_the_built_in_defaults_apply(monkeypatch):
    _install_gates(monkeypatch, list_errors={"guardian_settings": "boom"})
    monkeypatch.setattr(gtb, "guardian_run_model_params", lambda: (None, None))
    assert gtb.guardian_bridge_load_evidence_limits() == (16384, 8128)


def test_shape_result_cuts_at_the_ceiling_the_caller_passed(monkeypatch):
    _install_gates(monkeypatch, settings={"evidence_truncate_bytes": 16384, "evidence_head_tail_bytes": 4096})
    entries = [{"Type": 1, "Contents": "HEAD-" + "m" * 100000 + "-TAIL"}]
    payload, truncated, note, full_payload = gtb.guardian_bridge_shape_result(entries, 40000, 10000)
    assert truncated is True and isinstance(payload, str) and len(payload) < 40000 + 400
    assert payload.startswith('"HEAD-') and payload.endswith('-TAIL"')  # the head and the tail are what is kept
    small, small_truncated, _n, _f = gtb.guardian_bridge_shape_result([{"Type": 1, "Contents": "x" * 30000}], 40000, 10000)
    assert small_truncated is False and len(small) == 30000


def test_an_oversized_string_or_dict_result_reaches_the_model_at_the_full_ceiling(monkeypatch):
    """head + marker + tail is the per-result ceiling (it used to be about half of it)."""
    _install_gates(monkeypatch, settings={})
    ceiling, head_tail = 138720, gtb.guardian_evidence_head_tail(138720)
    for contents in ("HEAD-" + "m" * 400000 + "-TAIL", {"blob": "HEAD-" + "m" * 400000 + "-TAIL", "n": 1}):
        payload, truncated, _note, _full = gtb.guardian_bridge_shape_result([{"Type": 1, "Contents": contents}], ceiling, head_tail)
        assert truncated is True and isinstance(payload, str)
        assert ceiling - 200 <= len(payload) <= ceiling      # ~138 KB for gpt-5-mini, not ~69 KB
        assert payload.startswith(("HEAD-", '"HEAD-', '{"blob": "HEAD-')) and payload.endswith(('-TAIL"', '-TAIL", "n": 1}'))


def test_the_run_passes_the_callers_ceiling_to_the_shaping_step(monkeypatch):
    _install_gates(monkeypatch, policy={"ip": "allow"}, command_handlers={"ip": _ok_handler("Z" * 60000)})
    capped = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"}, evidence_truncate_bytes=20000, evidence_head_tail_bytes=5000)
    wide = gtb.guardian_tool_bridge_run("ip", {"ip": "1.1.1.1"}, evidence_truncate_bytes=100000, evidence_head_tail_bytes=25000)
    assert capped["data"]["tool_result"]["truncated"] is True
    assert wide["data"]["tool_result"]["truncated"] is False


def test_the_bridge_declares_the_new_arguments():
    import yaml
    text = (Path(__file__).resolve().parent / "GuardianToolBridge.yml").read_text()
    names = [a["name"] for a in yaml.safe_load(text)["args"]]
    assert "evidence_truncate_bytes" in names and "evidence_head_tail_bytes" in names


# --- core-get-case-extra-data: a one-element case_id list ------------------------------------------------------------

def test_normalize_case_id_takes_the_first_item_of_a_one_element_list():
    normalized, error = gtb.guardian_bridge_normalize_case_id_args("core-get-case-extra-data", {"case_id": ["42"], "issues_limit": "5"})
    assert normalized == {"case_id": "42", "issues_limit": "5"} and error is None
    normalized, error = gtb.guardian_bridge_normalize_case_id_args("core-get-case-extra-data", {"case_id": [42]})
    assert normalized == {"case_id": "42"} and error is None


@pytest.mark.parametrize("value", [["1", "2"], [], [None], [""], [["1"]], [{"a": 1}]])
def test_normalize_case_id_refuses_any_other_list(value):
    normalized, error = gtb.guardian_bridge_normalize_case_id_args("core-get-case-extra-data", {"case_id": value})
    assert error and "ONE case_id" in error and "not run" in error


def test_normalize_case_id_leaves_everything_else_alone():
    args = {"case_id": "42"}
    assert gtb.guardian_bridge_normalize_case_id_args("core-get-case-extra-data", args) == (args, None)
    other = {"case_id": ["1", "2"]}
    assert gtb.guardian_bridge_normalize_case_id_args("core-get-cases", other) == (other, None)  # another command: untouched
    assert gtb.guardian_bridge_normalize_case_id_args("core-get-case-extra-data", "junk") == ("junk", None)
    assert gtb.guardian_bridge_normalize_case_id_args("core-get-case-extra-data", {}) == ({}, None)


def test_run_core_get_case_extra_data_passes_a_one_element_list_as_its_item(monkeypatch):
    executed = []
    _install_gates(monkeypatch, policy={"core-get-case-extra-data": "allow"},
                   command_handlers={"core-get-case-extra-data": lambda args: executed.append(args) or [{"Type": 1, "Contents": {"case": {}}}]})
    result = gtb.guardian_tool_bridge_run("core-get-case-extra-data", {"case_id": ["42"], "issues_limit": "5"})
    assert result["data"]["tool_result"]["status"] == "ok"
    assert executed == [{"case_id": "42", "issues_limit": "5"}]


def test_run_core_get_case_extra_data_refuses_a_longer_list_without_running_it(monkeypatch):
    executed = []
    _install_gates(monkeypatch, policy={"core-get-case-extra-data": "allow"},
                   command_handlers={"core-get-case-extra-data": lambda args: executed.append(args) or [{"Type": 1, "Contents": {}}]})
    result = gtb.guardian_tool_bridge_run("core-get-case-extra-data", {"case_id": ["42", "43"]})
    assert executed == []
    assert result["data"]["tool_result"]["status"] == "error" and "ONE case_id" in result["data"]["tool_result"]["error"]
