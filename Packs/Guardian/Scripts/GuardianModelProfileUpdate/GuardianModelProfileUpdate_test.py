import json
import pathlib

import yaml

import GuardianModelProfileUpdate as mpu


def _record(**over):
    rec = {
        "timestamp": "2026-10-01T03:00:05Z", "provider": "GuardianCohere", "instance_name": "lab",
        "model": "command-r:35b", "model_source": "observed", "latency_bounded_window": 32768,
        "correctness_window": 32768, "at_ceiling": False, "truncated": False, "speed_limited_at_floor": False,
        "recommended_max_input_tokens": 28102, "output_reserve_used": 4096, "chars_per_token": 4.1,
        "chars_per_token_measured": True, "capabilities": {"tools": True, "structured_output": True},
        "capabilities_skipped": False,
    }
    rec.update(over)
    return rec


def _ctx(**over):
    return {"Guardian": {"ModelProbe": {"calibration_record": _record(**over)}}}


class _Server:
    """A fake XSOAR for the three List commands plus GetTime, and a read-only guardian_settings."""

    def __init__(self, monkeypatch, stored=None, get_error=None, set_error=None, settings=None):
        self.stored = stored  # None = the List does not exist
        self.get_error, self.set_error = get_error, set_error
        self.settings = settings if settings is not None else {}  # guardian_settings (read-only here)
        self.calls = []
        monkeypatch.setattr(mpu.demisto, "executeCommand", self.handle)

    def handle(self, command, args):
        self.calls.append((command, args))
        if command == "GetTime":
            return [{"Type": 1, "Contents": "2026-10-01T03:01:00Z"}]
        if command == "getList" and args["listName"] == "guardian_settings":
            return [{"Type": 1, "Contents": json.dumps(self.settings)}]
        assert args["listName"] == "guardian_model_profile"
        if command == "getList":
            if self.get_error:
                return [{"Type": 4, "Contents": self.get_error}]
            if self.stored is None:
                return [{"Type": 4, "Contents": "Item not found (8)"}]
            return [{"Type": 1, "Contents": self.stored}]
        if command == "createList":
            self.stored = args["listData"]
            return [{"Type": 1, "Contents": "ok"}]
        if command == "setList":
            if self.set_error:
                return [{"Type": 4, "Contents": self.set_error}]
            self.stored = args["listData"]
            return [{"Type": 1, "Contents": "ok"}]
        raise AssertionError(command)

    def commands(self):
        return [c for c, _ in self.calls]


def test_a_good_probe_creates_the_list_and_the_record(monkeypatch):
    srv = _Server(monkeypatch)
    r = mpu.guardian_profile_update_run({}, _ctx())
    assert r["ok"] and r["updated"] and r["key"] == "GuardianCohere:lab"
    assert srv.commands().count("createList") == 1  # created only after a not-found
    saved = json.loads(srv.stored)
    assert saved["active"] == "GuardianCohere:lab" and saved["overrides"] == {}
    rec = saved["profiles"]["GuardianCohere:lab"]
    assert rec["max_input_tokens"] == 28102 and rec["window"] == 32768 and rec["model"] == "command-r:35b"
    assert rec["tools"] is True and rec["structured_output"] is True and rec["chars_per_token"] == 4.1
    assert rec["probed_at"] == "2026-10-01T03:00:05Z" and rec["updated_at"] == "2026-10-01T03:01:00Z"


def test_the_operators_overrides_and_other_records_survive_an_update(monkeypatch):
    old = {"active": "GuardianVertex:v", "overrides": {"max_input_tokens": 9000, "note": "pinned"},
           "profiles": {"GuardianVertex:v": {"max_input_tokens": 1}}}
    srv = _Server(monkeypatch, stored=json.dumps(old))
    r = mpu.guardian_profile_update_run({}, _ctx())
    assert r["updated"]
    assert "createList" not in srv.commands()
    saved = json.loads(srv.stored)
    assert saved["overrides"] == {"max_input_tokens": 9000, "note": "pinned"}
    assert saved["profiles"]["GuardianVertex:v"] == {"max_input_tokens": 1}
    assert saved["active"] == "GuardianCohere:lab"


def test_no_probe_in_context_changes_nothing(monkeypatch):
    srv = _Server(monkeypatch, stored="{}")
    for ctx in ({}, {"Guardian": {}}, {"Guardian": {"ModelProbe": {}}}, {"Guardian": {"ModelProbe": "x"}}):
        r = mpu.guardian_profile_update_run({}, ctx)
        assert r["ok"] and not r["updated"] and "no probe result" in r["reason"]
    assert srv.calls == []


def test_an_untrustworthy_probe_keeps_the_previous_profile(monkeypatch):
    for over, phrase in (
        ({"recommended_max_input_tokens": None}, "no usable input budget"),
        ({"speed_limited_at_floor": True}, "too slow"),
        ({"capabilities_skipped": True}, "skipped"),
        ({"chars_per_token_measured": False}, "not measured"),
        ({"provider": None}, "could not identify"),
    ):
        srv = _Server(monkeypatch, stored="{}")
        r = mpu.guardian_profile_update_run({}, _ctx(**over))
        assert r["ok"] and not r["updated"] and phrase in r["reason"], (over, r)
        assert "setList" not in srv.commands()
    assert "kept the previous profile" in r["reason"] or "could not identify" in r["reason"]


def test_a_truncated_probe_is_accepted_and_marked_as_a_floor(monkeypatch):
    srv = _Server(monkeypatch, stored="{}")
    r = mpu.guardian_profile_update_run({}, _ctx(truncated=True))
    assert r["updated"]
    assert json.loads(srv.stored)["profiles"]["GuardianCohere:lab"]["truncated"] is True
    assert "confirmed floor" in mpu.guardian_profile_update_render(r)


def test_a_complete_probe_is_marked_not_truncated(monkeypatch):
    srv = _Server(monkeypatch, stored="{}")
    mpu.guardian_profile_update_run({}, _ctx())
    assert json.loads(srv.stored)["profiles"]["GuardianCohere:lab"]["truncated"] is False


def _stored_with(max_input_tokens):
    return json.dumps({"active": "GuardianCohere:lab", "overrides": {}, "profiles": {
        "GuardianCohere:lab": {"max_input_tokens": max_input_tokens}}})


def test_a_truncated_probe_may_not_cut_the_budget_by_more_than_half(monkeypatch):
    srv = _Server(monkeypatch, stored=_stored_with(60000))
    r = mpu.guardian_profile_update_run({}, _ctx(truncated=True, recommended_max_input_tokens=25000))
    assert r["ok"] and not r["updated"] and "under half of the previous budget (60000)" in r["reason"]
    assert "setList" not in srv.commands()
    # a modest drop, or a rise, from a truncated probe is accepted
    srv = _Server(monkeypatch, stored=_stored_with(28102))
    assert mpu.guardian_profile_update_run({}, _ctx(truncated=True, recommended_max_input_tokens=21000))["updated"]


def test_a_complete_probe_may_cut_the_budget_a_lot(monkeypatch):
    """The operator really did shrink the served context: a finished search is believed."""
    srv = _Server(monkeypatch, stored=_stored_with(28102))
    r = mpu.guardian_profile_update_run({}, _ctx(truncated=False, recommended_max_input_tokens=20500))
    assert r["updated"] and json.loads(srv.stored)["profiles"]["GuardianCohere:lab"]["max_input_tokens"] == 20500


def test_a_budget_below_the_prompts_own_floor_is_not_saved_unless_forced(monkeypatch):
    """A 12K budget leaves no room after Guardian's fixed prompt: the loop would drop the task while compacting."""
    srv = _Server(monkeypatch, stored="{}")
    r = mpu.guardian_profile_update_run({}, _ctx(recommended_max_input_tokens=11988))
    assert r["ok"] and not r["updated"] and "Guardian's own prompt needs" in r["reason"]
    assert "setList" not in srv.commands()
    assert mpu.guardian_profile_update_run({"force": "true"}, _ctx(recommended_max_input_tokens=11988))["updated"]


def test_force_overrides_the_truncation_guard(monkeypatch):
    _Server(monkeypatch, stored=_stored_with(28102))
    assert mpu.guardian_profile_update_run({"force": "true"}, _ctx(truncated=True, recommended_max_input_tokens=9000))["updated"]


def test_force_accepts_a_partial_result_but_never_one_without_a_budget(monkeypatch):
    srv = _Server(monkeypatch, stored="{}")
    r = mpu.guardian_profile_update_run({"force": "true"}, _ctx(capabilities_skipped=True))
    assert r["updated"] and "accepted with force=true" in r["reason"]
    assert json.loads(srv.stored)["profiles"]["GuardianCohere:lab"]["forced"] is True
    srv = _Server(monkeypatch, stored="{}")
    r = mpu.guardian_profile_update_run({"force": "true"}, _ctx(recommended_max_input_tokens=None))
    assert not r["updated"] and "setList" not in srv.commands()


def test_a_rerun_in_the_same_incident_uses_the_newest_probe(monkeypatch):
    srv = _Server(monkeypatch, stored="{}")
    ctx = {"Guardian": {"ModelProbe": [
        {"calibration_record": _record(recommended_max_input_tokens=21111)},
        {"calibration_record": _record(recommended_max_input_tokens=22222)}]}}
    assert mpu.guardian_profile_update_run({}, ctx)["updated"]
    assert json.loads(srv.stored)["profiles"]["GuardianCohere:lab"]["max_input_tokens"] == 22222


def test_a_guardian_context_that_older_builds_turned_into_a_list_is_still_read(monkeypatch):
    srv = _Server(monkeypatch, stored="{}")
    ctx = {"Guardian": [{"Loop": {"status": "done"}}, {"ModelProbe": {"calibration_record": _record(recommended_max_input_tokens=27777)}}]}
    assert mpu.guardian_profile_update_run({}, ctx)["updated"]
    assert json.loads(srv.stored)["profiles"]["GuardianCohere:lab"]["max_input_tokens"] == 27777


def test_an_unreadable_existing_list_is_never_overwritten(monkeypatch):
    for stored in ("{broken", "[1, 2]"):
        srv = _Server(monkeypatch, stored=stored)
        r = mpu.guardian_profile_update_run({}, _ctx())
        assert not r["ok"] and not r["updated"] and "fix or delete" in r["reason"]
        assert "setList" not in srv.commands() and "createList" not in srv.commands()


def test_a_read_error_other_than_not_found_does_not_create_the_list(monkeypatch):
    srv = _Server(monkeypatch, get_error="connection reset")
    r = mpu.guardian_profile_update_run({}, _ctx())
    assert not r["ok"] and "createList" not in srv.commands()


def test_a_failed_save_is_reported_as_a_failure(monkeypatch):
    _Server(monkeypatch, stored="{}", set_error="permission denied")
    r = mpu.guardian_profile_update_run({}, _ctx())
    assert not r["ok"] and not r["updated"] and "could not save" in r["reason"]
    assert "FAILED" in mpu.guardian_profile_update_render(r)


def test_the_written_profile_is_what_the_resolver_reads(monkeypatch):
    srv = _Server(monkeypatch)
    mpu.guardian_profile_update_run({}, _ctx())
    params = mpu.guardian_resolve_model_params({"model_tier": "medium", "max_input_tokens": 28258}, json.loads(srv.stored))
    assert params["max_input_tokens"] == 28102 and params["max_input_tokens_source"] == "measured"


def test_render_warns_when_the_model_did_not_honor_tools(monkeypatch):
    _Server(monkeypatch)
    r = mpu.guardian_profile_update_run({}, _ctx(capabilities={"tools": False, "structured_output": True}))
    assert r["updated"] and "WARNING" in mpu.guardian_profile_update_render(r)


# --- the playbook and Job that run it -------------------------------------------------------------

_PACK = pathlib.Path(__file__).resolve().parents[2]


def test_the_adaptation_playbook_probes_then_saves_then_closes_and_halts_on_the_kill_switch():
    pb = yaml.safe_load((_PACK / "Playbooks" / "playbook-GuardianModelAdaptation.yml").read_text())
    tasks = pb["tasks"]
    order, cur = [], pb["starttaskid"]
    while True:  # the default path from start to the end
        nxt = tasks[cur].get("nexttasks") or {}
        ids = nxt.get("#none#") or nxt.get("#default#") or []
        if not ids:
            break
        cur = ids[0]
        order.append(tasks[cur]["task"].get("script") or tasks[cur]["task"]["name"])
    assert order == ["GuardianKillSwitchCheck", "Kill switch on?", "guardian-probe-model",
                     "GuardianModelProfileUpdate", "closeInvestigation", "Done"]
    # the probe, the save and the kill-switch read never stop the run on their own failure
    for tid, task in tasks.items():
        if task["task"].get("script") in ("GuardianKillSwitchCheck", "guardian-probe-model", "GuardianModelProfileUpdate"):
            assert task.get("continueonerror") is True, tid
    cond = tasks["2"]
    op = cond["conditions"][0]["condition"][0][0]
    assert op["left"]["value"]["simple"] == "Guardian.Preflight.KillSwitch.proceed"
    assert op["right"]["value"]["simple"] == "false"  # halts only on an explicit "false"
    assert tasks[cond["nexttasks"]["halted"][0]]["type"] == "title"
    # no agent loop and no model session in this playbook
    assert not any("ReasoningTick" in str(t["task"].get("script")) for t in tasks.values())


def test_the_adaptation_job_runs_that_playbook_daily_and_closes_the_previous_run():
    job = json.loads((_PACK / "Jobs" / "job-guardianmodeladaptation.json").read_text())
    assert job["name"] == job["id"] == job["playbookId"] == "GuardianModelAdaptation"
    assert job["humanCron"] == {"timePeriodType": "hours", "timePeriod": 24}
    assert job["scheduled"] is True and job["recurrent"] is True and job["closePrevRun"] is True
    assert (_PACK / "Playbooks" / "playbook-GuardianModelAdaptation.yml").exists()


def test_the_profile_list_is_runtime_only_never_pack_seeded():
    """A pack-seeded List installs read-only (system:true), so the Job's setList would be rejected."""
    assert not list((_PACK / "Lists").glob("*guardian_model_profile*"))


""" ------------------------- the model catalogue: documented, confirmed, measured and quota records ------------------------- """

import pytest  # noqa: E402


def _catalog_entry(usable=100000, context_window=400000):
    return {"id": "gpt-5-mini", "vendor": "OpenAI", "probe": "skip", "open_weight": False, "checked": "2026-10-09",
            "matched_name": "gpt-5-mini", "matched_by": "configured", "platform": "azure-foundry",
            "limits": {"context_window": context_window, "max_input_tokens": usable, "max_output_tokens": 128000,
                       "basis": "azure-foundry cap", "managed": True},
            "usable_input_tokens": usable, "supports_tools": True, "supports_structured_output": True,
            "documented_budget": int(usable * 0.85 * 0.75)}


def _documented_ctx(**over):
    base = dict(provider="GuardianFoundry", instance_name="lab", model="gpt-5-mini", latency_bounded_window=None,
                recommended_max_input_tokens=None, window_search_skipped=True, catalog=_catalog_entry(),
                chars_per_token=2.5, chars_per_token_measured=True)
    base.update(over)
    return _ctx(**base)


def _searched_ctx(window, **over):
    base = dict(provider="GuardianFoundry", instance_name="lab", model="Cohere-command-a", latency_bounded_window=window,
                recommended_max_input_tokens=int(max(0, window - 4096) * 0.85 * 0.75), catalog=_catalog_entry(),
                chars_per_token=3.0, chars_per_token_measured=True, window_search_skipped=False)
    base.update(over)
    return _ctx(**base)


def test_a_probe_that_ran_no_window_search_writes_a_documented_record(monkeypatch):
    srv = _Server(monkeypatch)
    r = mpu.guardian_profile_update_run({}, _documented_ctx())
    assert r["ok"] and r["updated"] and r["key"] == "GuardianFoundry:lab"
    rec = json.loads(srv.stored)["profiles"]["GuardianFoundry:lab"]
    assert rec["source"] == "documented" and rec["catalog_id"] == "gpt-5-mini" and rec["catalog_checked"] == "2026-10-09"
    # a measured ratio that is denser than the assumed one lowers the budget: usable x 0.85 x (2.5 / 4)
    assert rec["max_input_tokens"] == int(100000 * 0.85 * (2.5 / 4.0))
    assert rec["chars_per_token"] == 2.5 and rec["chars_per_token_basis"] == "measured"
    assert rec["documented_input_tokens"] == 100000 and rec["limits"]["basis"] == "azure-foundry cap"
    assert rec["window"] == 400000
    assert rec["budget_inputs"] == {"usable_input_tokens": 100000, "output_reserve": 4096, "chars_per_token": 2.5,
                                    "chars_per_token_source": "measured", "safety_margin": 0.85, "cap": None, "capped": False} and rec["tools"] is True and rec["structured_output"] is True
    assert "probed_at" not in rec                      # nothing was probed: the stale-profile warning must not fire
    assert rec["documented_at"] == "2026-10-01T03:00:05Z" and rec["updated_at"] == "2026-10-01T03:01:00Z"
    assert json.loads(srv.stored)["active"] == "GuardianFoundry:lab"


def test_a_prose_ratio_above_the_assumed_one_does_not_raise_the_documented_budget(monkeypatch):
    srv = _Server(monkeypatch)
    mpu.guardian_profile_update_run({}, _documented_ctx(chars_per_token=4.6))
    rec = json.loads(srv.stored)["profiles"]["GuardianFoundry:lab"]
    assert rec["chars_per_token"] == 3.0 and rec["chars_per_token_basis"] == "assumed"
    assert rec["max_input_tokens"] == int(100000 * 0.85 * 0.75)


def test_a_documented_record_without_a_measured_ratio_uses_the_conservative_assumed_one(monkeypatch):
    srv = _Server(monkeypatch)
    mpu.guardian_profile_update_run({}, _documented_ctx(chars_per_token=4.0, chars_per_token_measured=False))
    rec = json.loads(srv.stored)["profiles"]["GuardianFoundry:lab"]
    assert rec["chars_per_token"] == 3.0 and rec["chars_per_token_basis"] == "assumed"
    assert rec["max_input_tokens"] == int(100000 * 0.85 * 0.75)


def test_a_documented_record_takes_its_capabilities_from_the_catalogue_when_the_probe_skipped_them(monkeypatch):
    srv = _Server(monkeypatch)
    mpu.guardian_profile_update_run({}, _documented_ctx(capabilities_skipped=True, capabilities={"tools": False, "structured_output": False}))
    rec = json.loads(srv.stored)["profiles"]["GuardianFoundry:lab"]
    assert rec["tools"] is True and rec["structured_output"] is True


def test_a_documented_budget_below_the_minimum_is_refused_unless_forced(monkeypatch):
    small = _catalog_entry(usable=10000, context_window=16000)
    srv = _Server(monkeypatch, stored="{}")
    r = mpu.guardian_profile_update_run({}, _documented_ctx(catalog=small))
    assert r["ok"] and not r["updated"] and "documented input budget" in r["reason"]
    forced = mpu.guardian_profile_update_run({"force": "true"}, _documented_ctx(catalog=small))
    assert forced["updated"] and forced["record"]["forced"] is True


def test_a_window_within_80_percent_of_the_documented_limit_is_confirmed_and_uses_the_documented_budget(monkeypatch):
    srv = _Server(monkeypatch)
    r = mpu.guardian_profile_update_run({}, _searched_ctx(85000))
    rec = json.loads(srv.stored)["profiles"]["GuardianFoundry:lab"]
    assert r["updated"] and rec["source"] == "confirmed"
    # the documented-derived budget, limited to what the measured window supports
    assert rec["max_input_tokens"] == min(int(100000 * 0.85 * (3.0 / 4.0)), int(max(0, 85000 - 4096) * 0.85 * 0.75))
    assert rec["window"] == 85000 and rec["documented_input_tokens"] == 100000 and rec["truncated"] is False
    assert "documented limit" in mpu.guardian_profile_update_render(r)


def test_a_window_more_than_20_percent_below_the_documented_limit_is_measured_with_the_evidence(monkeypatch):
    srv = _Server(monkeypatch)
    evidence = "past 60000 tokens the first response took 41.2 s, above the acceptable 30 s"
    r = mpu.guardian_profile_update_run({}, _searched_ctx(60000, limit_evidence=evidence))
    rec = json.loads(srv.stored)["profiles"]["GuardianFoundry:lab"]
    assert r["updated"] and rec["source"] == "measured"
    assert rec["max_input_tokens"] == int((60000 - 4096) * 0.85 * 0.75)
    assert rec["evidence"] == evidence and rec["documented_input_tokens"] == 100000 and rec["probed_at"]
    text = mpu.guardian_profile_update_render(r)
    assert "40% below the documented usable input limit" in text and evidence in text


def test_a_quota_stop_keeps_the_documented_limit_and_says_so(monkeypatch):
    srv = _Server(monkeypatch)
    r = mpu.guardian_profile_update_run({}, _searched_ctx(8000, quota_limited=True, quota_at_tokens=16000))
    rec = json.loads(srv.stored)["profiles"]["GuardianFoundry:lab"]
    assert r["updated"] and rec["source"] == "quota"
    assert rec["max_input_tokens"] == int(100000 * 0.85 * 0.75)
    assert "quota (tokens-per-minute) reached at 16000 tokens; the window was not reached" in rec["evidence"]


def test_an_unknown_model_keeps_todays_behaviour_with_source_measured(monkeypatch):
    srv = _Server(monkeypatch)
    r = mpu.guardian_profile_update_run({}, _ctx())          # the old fixture: no catalog entry at all
    rec = json.loads(srv.stored)["profiles"]["GuardianCohere:lab"]
    assert r["updated"] and rec["source"] == "measured" and rec["max_input_tokens"] == 28102
    assert "catalog_id" not in rec and "documented_input_tokens" not in rec


def test_the_cap_in_guardian_settings_limits_every_kind_of_record(monkeypatch):
    srv = _Server(monkeypatch, settings={"max_input_tokens_cap": 50000})
    mpu.guardian_profile_update_run({}, _documented_ctx(catalog=_catalog_entry(usable=900000, context_window=1000000)))
    rec = json.loads(srv.stored)["profiles"]["GuardianFoundry:lab"]
    assert rec["max_input_tokens"] == 50000 and rec["capped"] is True and rec["source"] == "documented"
    srv = _Server(monkeypatch, settings={"max_input_tokens_cap": 20000})
    mpu.guardian_profile_update_run({}, _ctx(recommended_max_input_tokens=28102))
    assert json.loads(srv.stored)["profiles"]["GuardianCohere:lab"]["max_input_tokens"] == 20000
    srv = _Server(monkeypatch, settings={"max_input_tokens_cap": "huge"})                  # an invalid cap is ignored
    mpu.guardian_profile_update_run({}, _ctx())
    assert json.loads(srv.stored)["profiles"]["GuardianCohere:lab"]["max_input_tokens"] == 28102


def test_the_existing_guards_still_apply_to_a_catalogued_model(monkeypatch):
    # truncation guard: a truncated floor under half of the previous budget keeps the previous record
    stored = json.dumps({"active": "GuardianFoundry:lab", "overrides": {}, "profiles": {
        "GuardianFoundry:lab": {"max_input_tokens": 60000}}})
    srv = _Server(monkeypatch, stored=stored)
    r = mpu.guardian_profile_update_run({}, _searched_ctx(40000, truncated=True))
    assert r["ok"] and not r["updated"] and "under half of the previous budget" in r["reason"]
    # skipped capabilities keep the previous profile unless forced
    srv = _Server(monkeypatch, stored="{}")
    r = mpu.guardian_profile_update_run({}, _searched_ctx(60000, capabilities_skipped=True))
    assert not r["updated"] and "skipped" in r["reason"]
    assert mpu.guardian_profile_update_run({"force": "true"}, _searched_ctx(60000, capabilities_skipped=True))["updated"]


def test_a_truncated_floor_below_the_threshold_is_recorded_as_measured_with_the_time_out_in_the_evidence(monkeypatch):
    srv = _Server(monkeypatch, stored="{}")
    r = mpu.guardian_profile_update_run({}, _searched_ctx(40000, truncated=True))
    rec = json.loads(srv.stored)["profiles"]["GuardianFoundry:lab"]
    assert r["updated"] and rec["source"] == "measured" and rec["truncated"] is True
    assert "ran out of time" in rec["evidence"]


def test_a_documented_report_never_calls_the_figure_measured_or_probed(monkeypatch):
    srv = _Server(monkeypatch)
    text = mpu.guardian_profile_update_render(mpu.guardian_profile_update_run({}, _documented_ctx()))
    assert "DOCUMENTED" in text and "measured window" not in text and "probed" not in text.lower()


""" ------------------------- a self-hosted open-weight model is never sized from the catalogue alone ------------------------- """


def _llama_entry():
    """Llama-3.3-70B on a self-hosted GuardianCohere: documented 123,904 usable, no provider cap, probe: confirm."""
    return {"id": "llama-3.3-70b-instruct", "vendor": "Meta", "probe": "confirm", "open_weight": True,
            "checked": "2026-10-09", "matched_name": "llama-3.3-70b-instruct", "matched_by": "configured", "platform": None,
            "limits": {"context_window": 128000, "max_input_tokens": None, "max_output_tokens": 4096, "basis": "vendor",
                       "managed": False},
            "usable_input_tokens": 123904, "supports_tools": True, "supports_structured_output": True}


def _llama_ctx(window, **over):
    base = dict(provider="GuardianCohere", instance_name="c1", model="llama-3.3-70b-instruct", model_source="declared",
                latency_bounded_window=window, recommended_max_input_tokens=int(max(0, (window or 0) - 4096) * 0.85 * 0.9),
                catalog=_llama_entry(), chars_per_token=3.6, chars_per_token_measured=True, window_search_skipped=False)
    base.update(over)
    return _ctx(**base)


def test_a_quota_stop_after_8k_on_a_self_hosted_model_is_sized_from_the_measured_8k_not_the_catalogue(monkeypatch):
    srv = _Server(monkeypatch, stored="{}")
    r = mpu.guardian_profile_update_run({"force": "true"}, _llama_ctx(8000, quota_limited=True, quota_at_tokens=16000))
    rec = json.loads(srv.stored)["profiles"]["GuardianCohere:c1"]
    assert r["updated"] and rec["source"] == "measured"
    assert rec["max_input_tokens"] == int((8000 - 4096) * 0.85 * 0.9)             # the probe's recommendation, not 94,786
    assert rec["max_input_tokens"] < 5000
    assert "quota (tokens-per-minute) reached at 16000 tokens" in rec["evidence"] and "8000 tokens" in rec["evidence"]


def test_a_quota_stop_at_the_floor_on_a_self_hosted_model_keeps_the_previous_profile_and_says_why(monkeypatch):
    srv = _Server(monkeypatch, stored=json.dumps({"active": "GuardianCohere:c1", "profiles": {"GuardianCohere:c1": {"max_input_tokens": 24000}}}))
    r = mpu.guardian_profile_update_run({}, _llama_ctx(None, quota_limited=True, quota_at_tokens=1000, recommended_max_input_tokens=None))
    assert r["ok"] and not r["updated"]
    assert "quota error" in r["reason"] and "1000 tokens" in r["reason"] and "kept the previous profile" in r["reason"]
    assert "setList" not in srv.commands()


def test_a_confirmed_budget_is_limited_to_the_measured_window_when_the_server_serves_less(monkeypatch):
    # served at 100K, documented 123,904: the probe measures 101,601 (82%) and recommends a budget for that window
    srv = _Server(monkeypatch)
    recommended = int((101601 - 4096) * 0.85 * (3.6 / 4.0))
    r = mpu.guardian_profile_update_run({}, _llama_ctx(101601, recommended_max_input_tokens=recommended))
    rec = json.loads(srv.stored)["profiles"]["GuardianCohere:c1"]
    assert r["updated"] and rec["source"] == "confirmed"
    assert rec["max_input_tokens"] == min(int(123904 * 0.85 * 0.75), recommended)
    assert rec["max_input_tokens"] <= recommended
    # real tokens at the measured ratio stay under the served window
    assert rec["max_input_tokens"] * 4 / 3.6 <= 101601
