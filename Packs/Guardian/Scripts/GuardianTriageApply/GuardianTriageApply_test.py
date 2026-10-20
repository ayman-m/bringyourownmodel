import json

import pytest

import GuardianTriageApply as ap


def _triage(**overrides):
    triage = {"status": "structured", "branch": "misconfiguration", "investigation_type": "misconfiguration", "severity": "critical",
              "original_severity": "high", "confidence": 90, "likely_benign": False, "escalate": True,
              "summary": "A production bucket allows public reads.", "next_step": "Close public access.",
              "domain": "posture", "domain_mismatch": False}
    triage.update(overrides)
    return triage


def _issue(**overrides):
    incident = {"id": "1001", "name": "n", "severity": 3, "status": 1, "CustomFields": {}}
    incident.update(overrides)
    return incident


def _plan(triage=None, incident=None, prior=None, apply_changes=True):
    return ap.guardian_apply_plan(_triage() if triage is None else triage, _issue() if incident is None else incident, prior, apply_changes)


# --- severity: raise, lower, repaired, fallback ------------------------------------------------------------------

def test_a_structured_result_raises_the_severity_and_sets_the_phase_in_one_update():
    result, update = _plan()
    assert update == {"id": "1001", "phase": "Guardian triage: misconfiguration", "severity": "critical"}
    assert result["status"] == "applied" and result["severity_before"] == "high" and result["severity_after"] == "critical"
    assert result["phase"] == "Guardian triage: misconfiguration" and "raised from high to critical" in result["reason"]


@pytest.mark.parametrize("before_num, target, expected", [
    (0.5, "low", "low"), (1, "medium", "medium"), (2, "critical", "critical"), (3, "critical", "critical"),
])
def test_every_raise_is_allowed_even_at_low_confidence(before_num, target, expected):
    result, update = _plan(_triage(severity=target, confidence=10), _issue(severity=before_num))
    assert update["severity"] == expected and result["severity_after"] == expected


def test_lowering_needs_a_structured_result_with_confidence_of_80_or_more():
    result, update = _plan(_triage(severity="low", confidence=80, escalate=False))
    assert update["severity"] == "low" and result["severity_after"] == "low" and "lowered from high to low" in result["reason"]
    result, update = _plan(_triage(severity="low", confidence=79, escalate=False))
    assert "severity" not in update and result["severity_after"] == "high" and "needs confidence of at least 80" in result["reason"]
    assert update["phase"] == "Guardian triage: misconfiguration"  # the phase is still set


@pytest.mark.parametrize("confidence", [80, 95, 100])
def test_severity_is_never_lowered_when_the_result_says_escalate(confidence):
    result, update = _plan(_triage(severity="low", confidence=confidence, escalate=True))
    assert "severity" not in update and result["severity_after"] == result["severity_before"] == "high"
    assert "escalate" in result["reason"] and update["phase"] == "Guardian triage: misconfiguration"
    assert "a person must act within hours (escalate)" in result["reason"] and "look at it" not in result["reason"]
    # raising is still allowed, and escalate=False still allows the lowering at this confidence
    raised, update = _plan(_triage(severity="critical", confidence=confidence, escalate=True))
    assert update["severity"] == "critical"
    lowered, update = _plan(_triage(severity="low", confidence=confidence, escalate=False))
    assert update["severity"] == "low"


@pytest.mark.parametrize("status", ["repaired", "fallback"])
@pytest.mark.parametrize("target", ["critical", "low"])
def test_repaired_and_fallback_never_change_the_severity(status, target):
    result, update = _plan(_triage(status=status, severity=target, confidence=99))
    assert "severity" not in update and result["severity_after"] == result["severity_before"] == "high"
    assert "never changes the severity" in result["reason"]


def test_an_unchanged_severity_is_not_written():
    result, update = _plan(_triage(severity="high"))
    assert "severity" not in update and "already high" in result["reason"] and result["status"] == "applied"


def test_a_domain_mismatch_never_changes_the_severity():
    result, update = _plan(_triage(domain_mismatch=True, severity="critical", branch="other"))
    assert "severity" not in update and "did not fit" in result["reason"]


@pytest.mark.parametrize("severity", [0, None, "bogus", 9])
def test_an_unknown_issue_severity_gets_no_severity_write(severity):
    result, update = _plan(incident=_issue(severity=severity))
    assert "severity" not in update and result["severity_before"] == "unknown" and "unknown" in result["reason"]


@pytest.mark.parametrize("proposed", ["", None, "urgent", "SEV_050_CRITICAL", 3, "informational"])
def test_a_severity_outside_the_four_enum_values_is_never_written(proposed):
    result, update = _plan(_triage(severity=proposed))
    assert "severity" not in update and "no valid severity" in result["reason"]


def test_the_severity_text_is_normalized_but_only_the_four_values_are_sent():
    result, update = _plan(_triage(severity=" CRITICAL "))
    assert update["severity"] == "critical"


def test_a_non_numeric_confidence_counts_as_zero_for_lowering():
    result, update = _plan(_triage(severity="low", confidence="95"))
    assert "severity" not in update
    result, update = _plan(_triage(severity="low", confidence=True))
    assert "severity" not in update


# --- phase ---------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("triage, phase", [
    (dict(branch="vulnerability"), "Guardian triage: vulnerability"),
    (dict(branch="other"), "Guardian triage: needs analyst"),
    (dict(branch="", status="fallback"), "Guardian triage: needs analyst"),
    (dict(branch="misconfiguration", status="fallback"), "Guardian triage: needs analyst"),
    (dict(branch="bad name; drop"), "Guardian triage: needs analyst"),
    (dict(branch=None), "Guardian triage: needs analyst"),
])
def test_phase_text(triage, phase):
    assert _plan(_triage(**triage))[0]["phase"] == phase


# --- guards ------------------------------------------------------------------------------------------------------

def test_an_issue_with_an_owner_is_skipped_and_nothing_is_written():
    for incident in (_issue(owner="alice"), _issue(CustomFields={"assigned_user_mail": "a@b.c"}), _issue(CustomFields={"assigneduser": ["bob"]})):
        result, update = _plan(incident=incident)
        assert update is None and result["status"] == "skipped" and "owner" in result["reason"] and result["phase"] == ""


@pytest.mark.parametrize("incident", [
    _issue(status=2), _issue(status=3), _issue(status="STATUS_040_RESOLVED_KNOWN_ISSUE"), _issue(status="Resolved - False Positive"),
    _issue(CustomFields={"resolutionstatus": "STATUS_250_RESOLVED_FIXED"}), _issue(status="closed"),
    _issue(closed="2026-10-11T10:00:00Z"),
])
def test_a_closed_or_resolved_issue_is_skipped(incident):
    result, update = _plan(incident=incident)
    assert update is None and result["status"] == "skipped" and "closed or resolved" in result["reason"]


@pytest.mark.parametrize("incident", [
    _issue(status=0), _issue(status=1), _issue(status="STATUS_020_UNDER_INVESTIGATION"), _issue(status="STATUS_010_NEW"),
    _issue(status="Unresolved"), _issue(closed="0001-01-01T00:00:00Z"), _issue(closed=""),
])
def test_under_investigation_new_and_open_issues_are_fine(incident):
    result, update = _plan(incident=incident)
    assert update is not None and result["status"] == "applied"


def test_a_second_apply_in_the_same_context_is_a_no_op():
    result, update = _plan(prior={"status": "applied"})
    assert update is None and result["status"] == "skipped" and "already applied" in result["reason"]
    # a dry run or an error earlier does not block a real apply
    for prior_status in ("dry_run", "error", "skipped"):
        assert _plan(prior={"status": prior_status})[1] is not None
    assert _plan(prior=[{"status": "applied"}])[1] is not None  # only a dict is read (the caller picks the newest)


@pytest.mark.parametrize("triage", [None, {}, {"status": ""}, "junk"])
def test_no_triage_result_is_skipped(triage):
    result, update = ap.guardian_apply_plan(triage, _issue(), None, True)
    assert update is None and result["status"] == "skipped" and "no Guardian.Triage" in result["reason"]


def test_no_incident_id_is_skipped():
    result, update = _plan(incident={"severity": 3})
    assert update is None and result["status"] == "skipped"


def test_dry_run_computes_and_reports_but_returns_no_update():
    result, update = _plan(apply_changes=False)
    assert update is None and result["status"] == "dry_run"
    assert result["severity_after"] == "critical" and result["phase"] == "Guardian triage: misconfiguration"


@pytest.mark.parametrize("value, expected", [
    (None, True), ("", True), ("  ", True), ("true", True), ("TRUE", True), ("1", True), (True, True),
    ("false", False), ("False", False), ("0", False), ("no", False), (False, False), ("maybe", False), ("tru", False),
])
def test_apply_changes_defaults_to_true_and_an_unreadable_value_never_turns_writes_on(value, expected):
    assert ap.guardian_apply_parse_flag(value) is expected


def test_the_update_never_carries_type_description_name_or_status():
    _result, update = _plan()
    assert set(update) <= {"id", "severity", "phase"}


# --- run: commands, note, audit -----------------------------------------------------------------------------------

def _wire(monkeypatch, update_reply=None):
    calls = []

    def execute(command, args):
        calls.append((command, dict(args)))
        if command == "setIncident":
            return update_reply or [{"Type": 1, "Contents": "ok"}]
        return [{"Type": 1, "Contents": "ok"}]

    monkeypatch.setattr(ap.demisto, "executeCommand", execute)
    return calls


def test_run_makes_one_update_call_then_a_note_and_an_audit_row(monkeypatch):
    calls = _wire(monkeypatch)
    result = ap.guardian_apply_run(_triage(), _issue(), None, True)

    assert result["status"] == "applied"
    assert [c[0] for c in calls] == ["setIncident", "GuardianCaseNote", "GuardianAuditWrite"]
    assert calls[0][1] == {"id": "1001", "phase": "Guardian triage: misconfiguration", "severity": "critical"}
    note = calls[1][1]["content"]
    assert "Guardian triage applied" in note and "high -> critical" in note and "raised from high to critical" in note
    assert "A production bucket allows public reads." in note  # the model's text goes in the note, not on the incident
    audit = calls[2][1]
    assert audit["action"] == "GuardianTriageApply" and audit["status"] == "ok" and audit["target"] == "1001"
    assert json.loads(audit["detail"])["status"] == "applied"


def test_run_dry_run_writes_only_the_note_and_the_audit_row(monkeypatch):
    calls = _wire(monkeypatch)
    result = ap.guardian_apply_run(_triage(), _issue(), None, False)
    assert result["status"] == "dry_run"
    assert [c[0] for c in calls] == ["GuardianCaseNote", "GuardianAuditWrite"]
    assert "dry run" in calls[0][1]["content"] and calls[1][1]["status"] == "ok"


@pytest.mark.parametrize("incident", [_issue(owner="alice"), _issue(status=2)])
def test_run_skips_with_only_an_audit_row(monkeypatch, incident):
    calls = _wire(monkeypatch)
    result = ap.guardian_apply_run(_triage(), incident, None, True)
    assert result["status"] == "skipped"
    assert [c[0] for c in calls] == ["GuardianAuditWrite"] and calls[0][1]["status"] == "skipped"


def test_run_reports_an_update_error_and_does_not_claim_it_applied(monkeypatch):
    calls = _wire(monkeypatch, update_reply=[{"Type": 4, "Contents": "incident not found"}])
    result = ap.guardian_apply_run(_triage(), _issue(), None, True)
    assert result["status"] == "error" and result["severity_after"] == "high" and "incident not found" in result["reason"]
    assert [c[0] for c in calls] == ["setIncident", "GuardianCaseNote", "GuardianAuditWrite"]
    assert calls[1][1]["content"].startswith("**Guardian triage: the update failed")
    assert calls[2][1]["status"] == "error"


def test_run_survives_a_failing_note_or_audit(monkeypatch):
    def execute(command, args):
        if command == "setIncident":
            return [{"Type": 1, "Contents": "ok"}]
        raise RuntimeError("down")

    monkeypatch.setattr(ap.demisto, "executeCommand", execute)
    monkeypatch.setattr(ap.demisto, "error", lambda msg: None)
    assert ap.guardian_apply_run(_triage(), _issue(), None, True)["status"] == "applied"


def test_a_repaired_result_sets_only_the_phase(monkeypatch):
    calls = _wire(monkeypatch)
    ap.guardian_apply_run(_triage(status="repaired", severity="critical"), _issue(), None, True)
    assert calls[0][1] == {"id": "1001", "phase": "Guardian triage: misconfiguration"}


# --- main ---------------------------------------------------------------------------------------------------------

def _main(monkeypatch, args, ctx, incident):
    calls = _wire(monkeypatch)
    written, results = {}, []
    monkeypatch.setattr(ap.demisto, "args", lambda: args)
    monkeypatch.setattr(ap.demisto, "context", lambda: ctx)
    monkeypatch.setattr(ap.demisto, "incident", lambda: incident)
    monkeypatch.setattr(ap.demisto, "setContext", lambda path, value: written.update({path: value}))
    monkeypatch.setattr(ap, "return_results", lambda r: results.append(r))
    ap.main()
    return calls, written, results


def test_main_defaults_to_applying_and_overwrites_the_context_key(monkeypatch):
    calls, written, results = _main(monkeypatch, {}, {"Guardian": {"Triage": _triage()}}, _issue())
    assert written["Guardian.TriageApply"]["status"] == "applied"
    assert [c[0] for c in calls][0] == "setIncident"
    assert "Guardian triage apply" in results[0].readable_output


def test_main_is_idempotent_through_the_context(monkeypatch):
    ctx = {"Guardian": {"Triage": _triage(), "TriageApply": {"status": "applied"}}}
    calls, written, _results = _main(monkeypatch, {}, ctx, _issue())
    assert written["Guardian.TriageApply"]["status"] == "skipped"
    assert "setIncident" not in [c[0] for c in calls]


def test_main_honours_apply_changes_false(monkeypatch):
    calls, written, _results = _main(monkeypatch, {"apply_changes": "false"}, {"Guardian": {"Triage": _triage()}}, _issue())
    assert written["Guardian.TriageApply"]["status"] == "dry_run"
    assert "setIncident" not in [c[0] for c in calls]


def test_main_reads_the_newest_triage_when_an_earlier_run_made_it_a_list(monkeypatch):
    ctx = {"Guardian": {"Triage": [_triage(severity="low"), _triage(severity="critical")]}}
    _calls, written, _results = _main(monkeypatch, {}, ctx, _issue())
    assert written["Guardian.TriageApply"]["severity_after"] == "critical"


@pytest.mark.parametrize("severity", ["inf", "Infinity", "-inf", "nan", "1e999", float("inf"), float("nan")])
def test_an_infinite_or_nan_issue_severity_is_unknown_not_a_crash(severity):
    assert ap.guardian_apply_severity_label({"severity": severity}) == "unknown"


# --- an earlier apply is recognised from the incident's own phase (a cleared context must not write again) -------------

@pytest.mark.parametrize("phase", [
    "Guardian triage: misconfiguration", "Guardian triage: needs analyst", "guardian triage: other", "GUARDIAN TRIAGE: CODE_RISK",
    "  Guardian triage:vulnerability", "Guardian   triage :   attack_path", "\tGuardian triage: x",
])
def test_a_guardian_triage_phase_on_the_issue_skips_the_apply(phase):
    for incident in (_issue(phase=phase), _issue(CustomFields={"phase": phase}), _issue(CustomFields={"Phase": [phase]})):
        result, update = _plan(incident=incident)
        assert update is None and result["status"] == "skipped" and result["phase"] == ""
        assert "already starts with" in result["reason"] and "clear the phase" in result["reason"]
        assert result["severity_before"] == result["severity_after"] == "high"
    # and a dry run reports the skip too, instead of a would-write
    assert _plan(incident=_issue(phase=phase), apply_changes=False)[0]["status"] == "skipped"


@pytest.mark.parametrize("phase", [None, "", "   ", "Investigation", "Triage", "Containment", "Analyst review: guardian triage", "Guardiantriage: x",
                                   "Guardian: triage", "not Guardian triage: x", 5, ["", None]])
def test_an_empty_phase_or_one_an_analyst_set_does_not_skip(phase):
    for incident in (_issue(phase=phase), _issue(CustomFields={"phase": phase})):
        result, update = _plan(incident=incident)
        assert result["status"] == "applied" and update["severity"] == "critical" and update["phase"] == "Guardian triage: misconfiguration"


def test_the_context_check_still_applies_without_a_phase_and_comes_first():
    result, update = _plan(prior={"status": "applied"}, incident=_issue(phase=""))
    assert update is None and "already applied" in result["reason"]
    result, update = _plan(prior={"status": "applied"}, incident=_issue(phase="Guardian triage: other"))
    assert update is None and result["status"] == "skipped"


def test_a_skip_for_the_phase_writes_no_note_and_leaves_an_audit_row(monkeypatch):
    calls = []

    def fake_execute(command, args):
        calls.append((command, args))
        return {"ok": True, "data": [{"Type": 1, "Contents": "ok"}], "error": None}

    monkeypatch.setattr(ap, "guardian_execute", fake_execute)
    result = ap.guardian_apply_run(_triage(), _issue(phase="Guardian triage: misconfiguration"), None, True)
    assert result["status"] == "skipped"
    commands = [c for c, _ in calls]
    assert commands == ["GuardianAuditWrite"]  # no setIncident and no note
    assert "skipped" in calls[0][1]["status"]
