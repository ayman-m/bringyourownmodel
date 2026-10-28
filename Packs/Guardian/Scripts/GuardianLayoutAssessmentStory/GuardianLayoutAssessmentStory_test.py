import pathlib

import pytest
import yaml

import GuardianLayoutAssessmentStory as wrapper

HTML_ENTRY = {"Type": 1, "ContentsFormat": "html", "Contents": '<div style="font-size:13px">the part</div>', "HumanReadable": "x"}
NOTE = {"Type": 1, "ContentsFormat": "html",
        "Contents": '<div style="opacity:.7;font-size:12px">The assessment is not available here.</div>'}


def _run(monkeypatch, reply=None, exc=None):
    calls, results = [], []

    def execute(command, args):
        calls.append((command, dict(args)))
        if exc:
            raise exc
        return reply

    monkeypatch.setattr(wrapper.demisto, "executeCommand", execute)
    monkeypatch.setattr(wrapper.demisto, "results", results.append)
    monkeypatch.setattr(wrapper.demisto, "debug", lambda *_: None)
    monkeypatch.setattr(wrapper.demisto, "error", lambda *_: None)
    wrapper.main()
    return calls, results


def test_it_asks_the_assessment_for_its_part_and_shows_the_html_entry_unchanged(monkeypatch):
    calls, results = _run(monkeypatch, [dict(HTML_ENTRY)])
    assert calls == [("GuardianLayoutAssessment", {"part": "story"})]
    assert results == [HTML_ENTRY] and results[0]["Type"] == 1 and results[0]["ContentsFormat"] == "html"


def test_the_last_usable_entry_is_the_one_shown(monkeypatch):
    first = dict(HTML_ENTRY, Contents="<div>first</div>")
    _calls, results = _run(monkeypatch, [first, {"Type": 4, "Contents": "boom"}, dict(HTML_ENTRY)])
    assert results == [HTML_ENTRY]


def test_a_markdown_answer_is_shown_as_it_is(monkeypatch):
    entry = {"Type": 1, "ContentsFormat": "markdown", "Contents": "See the assessment above."}
    assert _run(monkeypatch, [entry])[1] == [entry]


@pytest.mark.parametrize("reply", [
    None, [], [{"Type": 4, "Contents": "Script not found"}], [{"Type": 1, "Contents": ""}], [{"Type": 1, "Contents": "   "}],
    [{"Type": 1, "Contents": None}], ["not a dict"], [{"Type": 1, "ContentsFormat": "html", "Contents": {"a": 1}}]])
def test_an_error_or_an_empty_answer_is_one_muted_line(monkeypatch, reply):
    _calls, results = _run(monkeypatch, reply)
    assert results == [NOTE]


def test_execute_command_raising_is_one_muted_line(monkeypatch):
    calls, results = _run(monkeypatch, exc=RuntimeError("server went away"))
    assert len(calls) == 1 and results == [NOTE]


def test_a_failure_of_the_result_call_still_ends_in_a_note(monkeypatch):
    seen = []

    def results(entry):
        seen.append(entry)
        if len(seen) == 1:
            raise RuntimeError("cannot write")

    monkeypatch.setattr(wrapper.demisto, "executeCommand", lambda *_: [dict(HTML_ENTRY)])
    monkeypatch.setattr(wrapper.demisto, "results", results)
    monkeypatch.setattr(wrapper.demisto, "error", lambda *_: None)
    wrapper.main()
    assert seen == [HTML_ENTRY, NOTE]


def test_the_script_is_a_tiny_dynamic_section_like_the_assessment():
    folder = pathlib.Path(wrapper.__file__).parent
    doc = yaml.safe_load((folder / "GuardianLayoutAssessmentStory.yml").read_text())
    assessment = yaml.safe_load((folder.parent / "GuardianLayoutAssessment" / "GuardianLayoutAssessment.yml").read_text())
    assert doc["commonfields"]["id"] == doc["name"] == "GuardianLayoutAssessmentStory" and doc["args"] == []
    assert doc["tags"] == ["dynamic-section"] == assessment["tags"]
    for key in ("dockerimage", "fromversion", "marketplaces", "subtype", "type", "timeout", "system"):
        assert doc[key] == assessment[key], key
    source = (folder / "GuardianLayoutAssessmentStory.py").read_text()
    assert "GUARDIAN_COMMON" not in source and len(source.splitlines()) < 60
