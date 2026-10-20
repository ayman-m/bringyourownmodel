import json
from pathlib import Path

import GuardianCaseNote as case_note


REPO_ROOT = Path(__file__).resolve().parents[4]


def _shipped_list_text(list_name):
    path = REPO_ROOT / "Packs" / "GuardianXSIAM" / "Lists" / "list-{}.json".format(list_name)
    data = json.loads(path.read_text())["data"]
    try:
        data = json.loads(data)
    except ValueError:
        pass
    return json.dumps(data, sort_keys=True) if isinstance(data, (dict, list)) else data


def _install(monkeypatch, addentries_handler=None):
    calls = []

    def handler(args):
        calls.append(args)
        return [{"Type": 1, "Contents": "Done"}]

    def fake_execute(command, args):
        if command != "addEntries":
            raise AssertionError("unexpected command dispatched: {} {}".format(command, args))
        return (addentries_handler or handler)(args)

    monkeypatch.setattr(case_note.demisto, "executeCommand", fake_execute)
    monkeypatch.setattr(case_note.demisto, "error", lambda msg: None)
    monkeypatch.setattr(case_note.demisto, "info", lambda msg: None)
    return calls


def test_case_note_rejects_blank_content(monkeypatch):
    _install(monkeypatch)

    ok, result = case_note.guardian_case_note_run("  ")

    assert ok is False
    assert "required" in result["error"]


def test_case_note_writes_only_the_fixed_current_incident_shape(monkeypatch):
    calls = _install(monkeypatch)

    ok, result = case_note.guardian_case_note_run("IP reputation returned Bad; escalate to the incident owner.")

    assert ok is True
    assert result["status"] == "documented"
    assert len(calls) == 1
    assert calls[0] == {
        "entries": [
            {
                "Contents": "**Guardian Case Note**\n\nIP reputation returned Bad; escalate to the incident owner.",
                "ContentsFormat": "markdown",
                "Tags": ["guardian-case-note"],
                "Note": True,
            }
        ]
    }


def test_case_note_scrubs_scalar_secret_text_before_writing(monkeypatch):
    calls = _install(monkeypatch)

    ok, result = case_note.guardian_case_note_run("The API key is sk-abcdefghijklmnopqrstuvwxyz123456.")

    assert ok is True
    rendered = calls[0]["entries"][0]["Contents"]
    assert "abcdefghijklmnopqrstuvwxyz" not in rendered
    assert "***" in rendered


def test_case_note_keeps_identifiers_but_still_masks_secrets(monkeypatch):
    calls = _install(monkeypatch)

    ok, _ = case_note.guardian_case_note_run(
        "asset 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 "
        "rule 3f2b8c1e-9a4d-4e6f-8b7a-1c2d3e4f5a6b status STATUS_250_RESOLVED_FIXED "
        "key sk-abcdefghijklmnopqrstuvwxyz123456 md5 d41d8cd98f00b204e9800998ecf8427e"
    )

    assert ok is True
    rendered = calls[0]["entries"][0]["Contents"]
    assert "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" in rendered
    assert "3f2b8c1e-9a4d-4e6f-8b7a-1c2d3e4f5a6b" in rendered
    assert "STATUS_250_RESOLVED_FIXED" in rendered
    assert "abcdefghijklmnopqrstuvwxyz" not in rendered
    assert "d41d8cd98f00b204e9800998ecf8427e" not in rendered


def test_case_note_rejects_oversized_content_without_writing(monkeypatch):
    calls = _install(monkeypatch)

    ok, result = case_note.guardian_case_note_run("x" * (case_note.GUARDIAN_CASE_NOTE_MAX_CONTENT_LEN + 1))

    assert ok is False
    assert "over the" in result["error"]
    assert calls == []


def test_shipped_model_surfaces_use_case_note_not_raw_addentries():
    surfaces = (
        "guardian_prompt_head",
        "guardian_prompt_tail",
        "guardian_skill_cortex_case_investigation",
        "guardian_skill_cortex_issue_reference",
        "guardian_skill_cortex_detection_investigation",
        "guardian_skill_cortex_posture_misconfiguration",
        "guardian_skills_index",
    )
    rendered = "\n".join(_shipped_list_text(name) for name in surfaces)

    assert "GuardianCaseNote" in rendered
    assert "addEntries" not in rendered
    assert "positive disconfirming evidence" in rendered
    assert "at least 20 characters" in rendered


def test_case_note_is_in_the_shipped_callable_allowlist():
    assert "GuardianCaseNote" in json.loads(_shipped_list_text("guardian_tool_allowlist"))["commands"]
