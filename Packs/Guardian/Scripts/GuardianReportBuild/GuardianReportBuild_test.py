import copy
import json
import pathlib

import pytest

import GuardianReportBuild as rb

LISTS = pathlib.Path(__file__).resolve().parents[2] / "Lists"

INCIDENT = {"id": "4217", "name": "Beacon from WS-0142", "type": "Guardian Agent Run", "severity": 3,
            "CustomFields": {"guardianverdict": "Suspicious", "guardianconfidence": 55}}
CONCLUSION = ("powershell.exe on WS-0142 beaconed to cdn.example.org (203.0.113.50) every 60 s. "
              "The user jdoe@example.com opened invoice.docm.\n```json\n{\"verdict\": \"Malicious\", \"confidence\": 90}\n```")


def _call(call_id, tool, **args):
    return {"id": call_id, "type": "function", "function": {"name": tool, "arguments": json.dumps(args)}}


def _result(call_id, tool, result, ok=True, status="ok"):
    body = {"ok": ok, "status": status, "tool_call_id": call_id, "tool_name": tool}
    body["result" if ok else "error"] = result if ok else str(result)
    return {"role": "tool", "name": tool, "tool_call_id": call_id, "content": json.dumps(body)}


def _messages():
    return [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "<untrusted-case-data> Investigate the beacon. </untrusted-case-data>"},
        {"role": "assistant", "content": None, "tool_calls": [_call("c1", "GuardianSkillRead", name="xsoar_case_investigation")]},
        _result("c1", "GuardianSkillRead", "SKILL BODY with an example IOC 198.51.100.99"),
        {"role": "assistant", "content": None, "tool_calls": [_call("c2", "getEntries", id="4217")]},
        _result("c2", "getEntries", ["WS-0142 ran powershell.exe -enc AAAA", "path C:\\Users\\jdoe\\Downloads\\invoice.docm"]),
        {"role": "assistant", "content": None, "tool_calls": [_call("c3", "domain", domain="cdn.example.org")]},
        _result("c3", "domain", {"Domain": "cdn.example.org", "Resolves": "203.0.113.50", "Reputation": "Bad"}),
        {"role": "assistant", "content": CONCLUSION},
    ]


LOOP = {"run_id": "4217", "tick": 6, "status": "done", "messages": _messages(), "conclusion": CONCLUSION,
        "verdict": {"verdict": "Malicious", "confidence": 90, "techniques": ["T1071.001"], "summary": "Beacon."},
        "model_params": {"max_input_tokens": 28258}, "cost_usd": 0.5}
TOOLS = ["getEntries", "domain", "GuardianCaseNote", "setIncident"]
PROMPTS = dict(rb.GUARDIAN_REPORT_DEFAULT_PROMPTS)

CORE = {"v": 1, "headline": "powershell.exe on WS-0142 beaconed to cdn.example.org.",
        "entities": [
            {"id": "e1", "type": "host", "value": "WS-0142", "rep": "unknown", "role": "victim", "ref": ["t1"]},
            {"id": "e2", "type": "process", "value": "powershell.exe", "rep": "malicious", "role": "tool", "ref": ["t1"]},
            {"id": "e3", "type": "domain", "value": "cdn.example.org", "rep": "malicious", "role": "infra", "ref": ["t1", "t2"]},
            {"id": "e4", "type": "ip", "value": "203.0.113.50", "rep": "malicious", "role": "infra", "ref": ["t2"]}],
        "edges": [{"from": "e2", "to": "e3", "rel": "connected", "ref": ["t1"]},
                  {"from": "e3", "to": "e4", "rel": "resolved", "ref": ["t2"]}]}
STORY = {"v": 1,
         "attack": [{"tactic": "command-and-control", "tech": "t1071.001", "name": "Web protocols", "time": "2026-10-27T21:34:00Z",
                     "evidence": "Beacon every 60 s", "ents": ["e2", "e3"], "ref": ["t2"]}],
         "timeline": [{"t": "2026-10-27T21:31:00Z", "event": "powershell.exe started", "src": "EDR", "ents": ["e2"], "ref": ["t1"]}],
         "tree": [{"id": "n1", "parent": None, "ent": "e2", "name": "powershell.exe", "cmd": "powershell.exe -enc AAAA",
                   "pid": 6644, "flag": "malicious", "ref": ["t1"]}]}
CLOSE = {"v": 1, "findings": [{"text": "Beacon to cdn.example.org", "ref": ["t2"]}],
         "actions": [{"p": 1, "action": "Block the domain", "owner": "analyst", "approval": True, "cmd": "domain --block"}],
         "gaps": ["No proxy logs were available"]}


class Model(object):
    """A scripted model: one reply per call, in order. A reply is a dict (sent as JSON), a string, or an exception."""

    def __init__(self, *replies):
        self.replies, self.calls = list(replies), []

    def __call__(self, messages):
        self.calls.append(messages)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        content = json.dumps(reply) if isinstance(reply, dict) else reply
        return {"ok": True, "content": content, "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
                "model": "model-x", "error": ""}


def _inputs(loop=None, incident=INCIDENT, triage=None, apply_record=None, tools=TOOLS, archive=()):
    return rb.guardian_report_inputs(incident, copy.deepcopy(loop or LOOP), triage or {}, apply_record or {}, tools,
                                     list(archive), PROMPTS)


def _generate(model, inp=None, max_calls=3, charges=None, halted=None):
    charged = charges if charges is not None else []

    def charge(turn):
        charged.append(turn)
        return 0.01

    return rb.guardian_report_generate(inp or _inputs(), PROMPTS, max_calls, model, charge, run_id="4217", tick=6,
                                       clock=iter(range(0, 1000, 2)).__next__, now="2026-10-28T10:00:00Z", halted=halted)


# --- the evidence list -----------------------------------------------------------------------------------------------

def test_evidence_numbers_every_tool_call_in_order_and_skips_procedure_reads():
    inp = _inputs()
    assert [(e["id"], e["tool"]) for e in inp["evidence"]] == [("t1", "getEntries"), ("t2", "domain")]
    assert "SKILL BODY" not in inp["evidence_text"] and "198.51.100.99" not in inp["grounding"]
    assert inp["evidence_text"].startswith('[t1] getEntries {"id": "4217"}\nWS-0142 ran powershell.exe')
    assert '"Domain":"cdn.example.org"' in inp["evidence_text"]


def test_the_bridge_envelope_is_removed_and_a_failure_or_denial_says_so():
    messages = [{"role": "assistant", "tool_calls": [_call("a", "x"), _call("b", "y"), _call("c", "z")]},
                _result("a", "x", "boom", ok=False, status="error"),
                _result("b", "y", "waiting", status="pending_approval"),
                {"role": "tool", "tool_call_id": "c", "content": "plain text, not an envelope"}]
    evidence = rb.guardian_report_evidence(messages)
    assert [e["body"] for e in evidence] == ["FAILED: boom", "[status=pending_approval] waiting", "plain text, not an envelope"]


def test_a_call_without_a_recorded_result_is_still_listed():
    evidence = rb.guardian_report_evidence([{"role": "assistant", "tool_calls": [_call("a", "getEntries")]}])
    assert evidence[0]["body"] == "(no result was recorded)"


def test_the_archive_comes_first_and_a_call_is_never_listed_twice():
    archive = [{"run_id": "4217", "tick": 3, "dropped_messages": [
        {"role": "assistant", "tool_calls": [_call("old", "getIncidents", id="4217")]}, _result("old", "getIncidents", {"n": 1})]}]
    inp = _inputs(archive=archive)
    assert [e["tool"] for e in inp["evidence"]] == ["getIncidents", "getEntries", "domain"]
    again = rb.guardian_report_evidence(archive[0]["dropped_messages"] * 2)
    assert len(again) == 1


def test_grounding_text_has_the_values_as_printed_not_as_json_escaped():
    inp = _inputs()
    assert "c:\\users\\jdoe\\downloads\\invoice.docm" in inp["grounding"]


def test_the_archive_is_read_only_for_a_compacted_run_and_only_this_run_this_session(monkeypatch):
    rows = [
        {"run_id": "4217", "tick": 4, "dropped_messages": ["earlier session"]},
        {"run_id": "4217", "tick": 2, "dropped_messages": ["this session, first"]},
        {"run_id": "4217", "tick": 5, "dropped_messages": ["this session, second"]},
        {"run_id": "4217", "tick": 9, "dropped_messages": ["a later run"]},
        {"run_id": "other", "tick": 3, "dropped_messages": ["another incident"]},
    ]
    monkeypatch.setattr(rb, "guardian_report_load_list_json", lambda name: (copy.deepcopy(rows), ""))
    assert rb.guardian_report_load_archive("4217", 6, compacted=False) == []
    kept = rb.guardian_report_load_archive("4217", 6, compacted=True)
    assert [row["dropped_messages"][0] for row in kept] == ["this session, first", "this session, second"]
    monkeypatch.setattr(rb, "guardian_report_load_list_json", lambda name: (None, "unreadable"))
    assert rb.guardian_report_load_archive("4217", 6, compacted=True) == []


def test_compaction_is_seen_from_the_dropped_count_or_a_checkpoint():
    assert rb.guardian_report_compacted({"dropped_count": 3})
    assert rb.guardian_report_compacted({"messages": [{"role": "system", "guardian_checkpoint": True}]})
    assert not rb.guardian_report_compacted({"dropped_count": 0, "messages": [{"role": "user"}]})


# --- the evidence budget -------------------------------------------------------------------------------------------------

def _evidence(count, length):
    return [{"id": "t{}".format(i + 1), "tool": "getEntries", "args": "{}", "body": "x" * length, "grounding": ""}
            for i in range(count)]


def test_heads_scale_to_the_budget_and_a_short_result_leaves_its_share_to_the_others():
    evidence = _evidence(10, 10000)
    text, shown = rb.guardian_report_fit_evidence(evidence, 8000)
    assert len(text) <= 8000 and shown == ["t{}".format(i) for i in range(1, 11)]
    assert rb.GUARDIAN_REPORT_CUT_MARK in text
    mixed = _evidence(3, 10000) + [{"id": "t4", "tool": "t", "args": "", "body": "short", "grounding": ""}]
    text, _shown = rb.guardian_report_fit_evidence(mixed, 6000)
    assert "short" in text and len(text) <= 6000 and "short" + rb.GUARDIAN_REPORT_CUT_MARK not in text


def test_plenty_of_room_keeps_every_head_at_the_ceiling():
    text, _shown = rb.guardian_report_fit_evidence(_evidence(2, 5000), 100000)
    assert text.count("x") == 2 * rb.GUARDIAN_REPORT_HEAD_MAX_CHARS


def test_when_even_the_shortest_heads_do_not_fit_the_oldest_calls_are_left_out():
    evidence = _evidence(50, 5000)
    text, shown = rb.guardian_report_fit_evidence(evidence, 3000)
    assert len(text) <= 3000 and 0 < len(shown) < 50 and shown[-1] == "t50"
    assert rb.guardian_report_fit_evidence(evidence, 0) == ("", [])


def test_the_whole_prompt_fits_the_runs_input_budget():
    loop = copy.deepcopy(LOOP)
    big = [{"role": "user", "content": "task"}]
    for index in range(40):
        big += [{"role": "assistant", "tool_calls": [_call("k%d" % index, "getEntries", id=str(index))]},
                _result("k%d" % index, "getEntries", "y" * 20000)]
    loop["messages"] = big + [{"role": "assistant", "content": CONCLUSION}]
    loop["model_params"] = {"max_input_tokens": 6000}
    inp = _inputs(loop=loop)
    budget = (6000 - rb.GUARDIAN_REPORT_REPLY_RESERVE_TOKENS) * rb.GUARDIAN_CHARS_PER_ESTIMATED_TOKEN
    assert inp["budget_chars"] == budget
    for group in rb.GUARDIAN_REPORT_GROUPS:
        entities = [{"id": "e1", "type": "host", "value": "h" * 120}] * 20 if group != "core" else None
        messages = rb.guardian_report_messages(PROMPTS, group, inp, inp["evidence_text"], entities)
        assert sum(len(m["content"]) for m in messages) <= budget
    assert len(inp["evidence"]) == len(inp["evidence_text"].split("\n\n[t")) and inp["evidence"][-1]["id"] == "t40"


def test_a_missing_input_budget_uses_the_shipped_default():
    assert rb.guardian_report_budget_chars(None) == (rb.GUARDIAN_REPORT_DEFAULT_INPUT_TOKENS - 2048) * 4
    assert rb.guardian_report_budget_chars({"max_input_tokens": 100000}) == (100000 - 2048) * 4


# --- the three calls -----------------------------------------------------------------------------------------------------

def test_three_valid_replies_make_the_report():
    charged = []
    model = Model(CORE, STORY, CLOSE)
    record = _generate(model, charges=charged)
    assert record["calls"] == 3 and record["errors"] == [] and len(charged) == 3
    assert record["tokens"] == 450 and record["cost_usd"] == 0.03 and record["model"] == "model-x"
    assert record["seconds"] == 2.0 and record["generated_at"] == "2026-10-28T10:00:00Z"
    report = record["report"]
    assert report["v"] == 1 and report["headline"].startswith("powershell.exe")
    assert [e["value"] for e in report["entities"]] == ["WS-0142", "powershell.exe", "cdn.example.org", "203.0.113.50"]
    assert len(report["edges"]) == 2
    assert report["attack"][0]["tactic"] == "Command and Control" and report["attack"][0]["tech"] == "T1071.001"
    assert report["tree"][0]["pid"] == "6644" and report["tree"][0]["flag"] == "malicious"
    assert report["findings"][0]["ref"] == ["t2"] and report["gaps"] == ["No proxy logs were available"]
    # the story and close calls are given the entity ids
    assert '"id": "e3"' in model.calls[1][1]["content"] and '"id": "e3"' in model.calls[2][1]["content"]
    assert "ENTITIES ALREADY DEFINED" not in model.calls[0][1]["content"]


def test_verdict_confidence_and_severity_come_from_the_run_not_from_the_model():
    core = dict(CORE, verdict="benign", confidence=1, severity={"from": "low", "to": "low", "reason": "model"})
    record = _generate(Model(core, STORY, CLOSE), inp=_inputs(apply_record={
        "status": "applied", "severity_before": "high", "severity_after": "critical", "reason": "Confirmed beacon."}))
    report = record["report"]
    assert (report["verdict"], report["confidence"]) == ("malicious", 90)
    assert report["severity"] == {"from": "high", "to": "critical", "reason": "Confirmed beacon."}
    prompt = rb.guardian_report_messages(PROMPTS, "core", _inputs(), "")[0]["content"]
    assert "Do not return them" in prompt and '"verdict"' not in prompt


def test_the_recorded_verdict_falls_back_to_the_incident_fields_then_the_triage_result():
    no_verdict = dict(LOOP, verdict=None)
    assert rb.guardian_report_recorded_verdict(INCIDENT, no_verdict, {}) == {"verdict": "suspicious", "confidence": 55}
    assert rb.guardian_report_recorded_verdict({"CustomFields": {}}, no_verdict, {"likely_benign": True, "confidence": 70}) == \
        {"verdict": "benign", "confidence": 70}
    assert rb.guardian_report_recorded_verdict({}, {}, {}) == {}
    assert rb.guardian_report_recorded_verdict({}, {"verdict": {"verdict": "Likely benign", "confidence": 250}}, {}) == \
        {"confidence": 100}


def test_the_severity_is_one_badge_when_guardian_did_not_change_it():
    assert rb.guardian_report_recorded_severity({"severity": 3}, {}) == {
        "from": "high", "to": "", "reason": "Severity was not changed by Guardian in this run."}
    unchanged = rb.guardian_report_recorded_severity({"severity": 3}, {"status": "dry_run", "severity_before": "high",
                                                                        "severity_after": "high", "reason": "same"})
    assert unchanged["to"] == "" and unchanged["from"] == "high"


def test_a_fenced_reply_with_a_preamble_is_read():
    fenced = "Here is the report:\n```json\n{}\n```\nDone.".format(json.dumps(CORE))
    record = _generate(Model(fenced, STORY, CLOSE))
    assert record["calls"] == 3 and len(record["report"]["entities"]) == 4


def test_json_with_quotes_and_braces_inside_strings_is_read_whole():
    reply = json.dumps({"headline": 'ran "cmd /c echo }" then {x}', "entities": [], "edges": []})
    assert rb.guardian_report_extract_json("note {not json} " + reply + " tail", ("headline",))["headline"] == 'ran "cmd /c echo }" then {x}'
    assert rb.guardian_report_extract_json('```json\n{"headline": "a \\"b\\" }"}\n```', ("headline",)) == {"headline": 'a "b" }'}
    assert rb.guardian_report_extract_json('{"unrelated": 1}', ("headline",)) is None
    assert rb.guardian_report_extract_json("no json at all", ("headline",)) is None
    assert rb.guardian_report_extract_json(None, ("headline",)) is None


def test_an_invalid_reply_gets_one_repair_request_and_the_repaired_one_is_used():
    model = Model("I think the report is about a beacon.", CORE, STORY, CLOSE)
    charged = []
    record = _generate(model, charges=charged)
    assert record["calls"] == 4 and record["errors"] == [] and len(charged) == 4
    repair = model.calls[1]
    assert repair[-1] == {"role": "user", "content": "Return only the JSON object."}
    assert repair[-2] == {"role": "assistant", "content": "I think the report is about a beacon."}
    assert len(record["report"]["entities"]) == 4


def test_a_group_that_stays_unusable_is_recorded_while_the_others_succeed():
    model = Model("no json", "still none", STORY, CLOSE)
    record = _generate(model)
    assert record["calls"] == 4
    assert record["errors"] == ["core: the reply held no usable JSON, even after one repair request"]
    report = record["report"]
    assert "entities" not in report and "headline" not in report
    assert report["attack"] and report["findings"] and report["tree"][0]["ent"] is None


def test_a_failed_call_is_recorded_and_not_repaired():
    def failing(messages):
        return {"ok": False, "content": "", "usage": {}, "model": "", "error": "HTTP 500 api_key=abcdef0123456789abcdef"}

    record = _generate(failing)
    assert record["calls"] == 3 and record["report"] is None and record["refs"] == {}
    assert len(record["errors"]) == 3 and record["errors"][0].startswith("core: model call failed: HTTP 500")
    assert "abcdef0123456789abcdef" not in " ".join(record["errors"])


def test_the_model_helper_raising_is_recorded_and_nothing_escapes():
    model = Model(RuntimeError("provider exploded"), STORY, CLOSE)
    record = _generate(model)
    assert record["errors"] == ["core: provider exploded"]
    assert record["report"] and record["calls"] == 3


def test_every_group_raising_leaves_no_report():
    record = _generate(Model(ValueError("a"), ValueError("b"), ValueError("c")))
    assert record["report"] is None and len(record["errors"]) == 3


def test_report_max_calls_limits_the_groups_asked_for_in_order():
    model = Model(CORE)
    record = _generate(model, max_calls=1)
    assert record["calls"] == 1 and set(record["report"]) >= {"headline", "entities"} and "attack" not in record["report"]


# --- validation and grounding -------------------------------------------------------------------------------------------

def test_refs_that_are_not_evidence_ids_are_dropped_and_the_item_shows_as_unverified():
    core = copy.deepcopy(CORE)
    core["entities"][0]["ref"] = ["t99", "t1", "t1", "nope", 7]
    core["entities"][1]["ref"] = ["t99"]
    record = _generate(Model(core, STORY, CLOSE))
    entities = {e["id"]: e for e in record["report"]["entities"]}
    assert entities["e1"]["ref"] == ["t1"] and entities["e2"]["ref"] == []
    assert rb.guardian_report_unverified(record["report"]) >= 1
    assert set(record["refs"]) <= {"t1", "t2"}


def test_an_invented_entity_is_dropped_with_its_edges_and_a_conclusion_only_one_has_no_refs():
    core = copy.deepcopy(CORE)
    core["entities"] += [
        {"id": "e5", "type": "host", "value": "FS-77", "ref": ["t1"]},                    # nowhere
        {"id": "e6", "type": "user", "value": "jdoe@example.com", "ref": ["t1", "t2"]},   # only in the conclusion
        {"id": "e7", "type": "host", "value": "ws-0142", "ref": ["t1"]}]                  # case-insensitive match, in the evidence
    core["edges"].append({"from": "e1", "to": "e5", "rel": "ran", "ref": ["t1"]})
    record = _generate(Model(core, STORY, CLOSE))
    by_id = {e["id"]: e for e in record["report"]["entities"]}
    assert "e5" not in by_id and by_id["e6"]["ref"] == [] and by_id["e7"]["ref"] == ["t1"]
    assert all(e["to"] != "e5" for e in record["report"]["edges"])
    assert any("FS-77" not in err and "1 entity not found" in err for err in record["errors"])


def test_a_value_that_names_a_kind_of_thing_is_not_an_entity():
    core = copy.deepcopy(CORE)
    core["entities"].append({"id": "e9", "type": "host", "value": "Workstation", "ref": ["t1"]})
    record = _generate(Model(core, STORY, CLOSE), inp=_inputs(loop=dict(LOOP, conclusion=CONCLUSION + " the workstation")))
    assert "Workstation" not in [e["value"] for e in record["report"]["entities"]]


def test_unknown_entity_ids_are_dropped_from_the_story_and_unknown_parents_become_roots():
    story = copy.deepcopy(STORY)
    story["attack"][0]["ents"] = ["e2", "zz"]
    story["tree"] += [{"id": "n2", "parent": "nope", "ent": "zz", "name": "child.exe"}, {"id": "n3", "parent": "n3", "name": "self.exe"},
                      {"id": "n1", "name": "duplicate id"}, {"id": "bad id!", "name": "x"}]
    report = _generate(Model(CORE, story, CLOSE))["report"]
    assert report["attack"][0]["ents"] == ["e2"]
    assert [(n["id"], n["parent"], n["ent"]) for n in report["tree"]] == [("n1", None, "e2"), ("n2", None, None), ("n3", None, None)]


def test_caps_enums_and_lengths_are_enforced():
    core = {"headline": "h" * 500,
            "entities": [{"id": "e%d" % i, "type": "bogus", "value": "WS-0142" + " abc" * 50, "rep": "red", "role": "boss"}
                         for i in range(60)],
            "edges": []}
    inp = _inputs(loop=dict(LOOP, conclusion="WS-0142" + " abc" * 50))
    story = {"attack": [{"tactic": "Execution", "name": "n%d" % i} for i in range(40)],
             "timeline": [{"t": "2026-10-27T21:31:00Z", "event": "e" * 400} for _ in range(60)],
             "tree": [{"id": "n%d" % i, "parent": "n%d" % (i - 1) if i else None, "name": "p%d" % i} for i in range(60)]}
    close = {"findings": [{"text": "f" * 400}] * 30, "actions": [{"p": 9, "action": "a" * 400, "owner": "robot", "approval": "no"}] * 20,
             "gaps": ["g" * 400] * 20}
    report = _generate(Model(core, story, close), inp=inp)["report"]
    caps = rb.GUARDIAN_REPORT_CAPS
    assert len(report["headline"]) == 140 and len(report["entities"]) == caps["entities"]
    entity = report["entities"][0]
    assert len(entity["value"]) == 120 and (entity["type"], entity["rep"], entity["role"]) == ("other", "unknown", "other")
    assert len(report["attack"]) == caps["attack"] and len(report["timeline"]) == caps["timeline"]
    assert len(report["tree"]) == caps["tree"] and len(report["findings"]) == caps["findings"]
    assert len(report["actions"]) == caps["actions"] and len(report["gaps"]) == caps["gaps"]
    assert len(report["timeline"][0]["event"]) == 160 and len(report["findings"][0]["text"]) == 200
    action = report["actions"][0]
    assert (action["p"], action["owner"], action["approval"], len(action["action"])) == (3, "analyst", False, 160)


def test_an_action_may_only_name_a_command_of_the_run_and_never_touches_guardians_bookkeeping():
    close = {"actions": [
        {"action": "Look at the domain", "cmd": "!domain --domain cdn.example.org"},
        {"action": "Isolate the host", "cmd": "xdr-isolate-endpoint --host workstation"},
        {"action": "Record the verdict", "cmd": "setIncident guardianverdict=Malicious"},
        {"action": "Update guardianconfidence on the incident"},
        {"action": "Write a case note", "cmd": "GuardianCaseNote text=x"},
        {"action": "Call the user"}]}
    actions = _generate(Model(CORE, STORY, close))["report"]["actions"]
    assert [(a["action"], a["cmd"]) for a in actions] == [
        ("Look at the domain", "!domain --domain cdn.example.org"), ("Isolate the host", ""), ("Call the user", "")]
    assert all(a["approval"] is True and a["owner"] == "analyst" and a["p"] == 3 for a in actions)


def test_techniques_are_ids_and_tactics_are_the_full_names():
    story = {"attack": [{"tactic": "TA0011", "tech": "T1071", "name": "a"}, {"tactic": "Priv-Esc", "tech": "powershell", "name": "b"},
                        {"tactic": "Mystery", "tech": "t1059.001", "name": "c"}]}
    attack = _generate(Model(CORE, story, CLOSE))["report"]["attack"]
    assert [(a["tactic"], a["tech"]) for a in attack] == [("Command and Control", "T1071"), ("Privilege Escalation", ""),
                                                          ("Mystery", "T1059.001")]


def test_secrets_in_the_models_text_are_masked():
    core = copy.deepcopy(CORE)
    core["headline"] = "Used password=hunter2 against WS-0142"
    report = _generate(Model(core, STORY, CLOSE))["report"]
    assert "hunter2" not in report["headline"]


def test_the_refs_map_is_built_from_the_evidence_and_holds_only_cited_calls():
    record = _generate(Model(CORE, STORY, CLOSE))
    assert record["refs"] == {"t1": {"tool": "getEntries", "summary": '{"id": "4217"}'},
                              "t2": {"tool": "domain", "summary": '{"domain": "cdn.example.org"}'}}
    forged = _generate(Model(dict(CORE, refs={"t1": {"tool": "forged", "summary": "forged"}}), STORY, CLOSE))
    assert forged["refs"]["t1"]["tool"] == "getEntries"


def test_the_run_id_and_tick_are_written_to_the_record():
    record = _generate(Model(CORE, STORY, CLOSE))
    assert (record["run_id"], record["tick"], record["v"], record["fingerprint"]) == ("4217", 6, 1, None)
    assert set(record) == {"v", "run_id", "tick", "fingerprint", "generated_at", "model", "calls", "tokens", "cost_usd", "seconds", "report",
                           "refs", "errors"}


# --- the prompt text ---------------------------------------------------------------------------------------------------

def _tenant(monkeypatch, lists=None, context=None, incident=INCIDENT, replies=()):
    """A fake tenant: Lists by name, Guardian context, and a scripted `guardian-llm-chat`. Returns the call log."""
    log = {"execute": [], "context": [], "results": [], "llm": []}
    store = {"guardian_settings": {"report_enabled": True}} if lists is None else lists
    replies = list(replies)

    def execute(command, args, using=None):
        log["execute"].append((command, args))
        if command == "getList":
            if args["listName"] not in store:
                return {"ok": False, "data": None, "error": "Item not found (601)", "retryable": False, "is_auth_error": False}
            value = store[args["listName"]]
            return {"ok": True, "data": [{"Type": 1, "Contents": value if isinstance(value, str) else json.dumps(value)}], "error": None}
        if command == "guardian-llm-chat":
            log["llm"].append(args)
            reply = replies.pop(0)
            if isinstance(reply, dict) and "ok" in reply:
                return reply
            content = json.dumps(reply) if isinstance(reply, dict) else reply
            completion = {"model": "model-x", "usage": {"prompt_tokens": 10, "completion_tokens": 5},
                          "choices": [{"message": {"content": content}}]}
            return {"ok": True, "data": [{"Type": 1, "Contents": completion}], "error": None}
        if command == "GuardianCostLedger":
            return {"ok": True, "data": [{"Type": 1, "Contents": {"usd": 0.02}}], "error": None}
        return {"ok": True, "data": [], "error": None}

    ctx = {"Loop": copy.deepcopy(LOOP), "ToolCatalog": [{"function": {"name": n}} for n in TOOLS]} if context is None else context
    monkeypatch.setattr(rb, "guardian_execute", execute)
    monkeypatch.setattr(rb, "guardian_ctx_read", lambda key, default=None: ctx.get(key, default))
    monkeypatch.setattr(rb.demisto, "incident", lambda: incident)
    monkeypatch.setattr(rb.demisto, "setContext", lambda key, value: log["context"].append((key, value)))
    monkeypatch.setattr(rb.demisto, "debug", lambda *_: None)
    monkeypatch.setattr(rb.demisto, "error", lambda *_: None)
    monkeypatch.setattr(rb, "return_results", lambda value: log["results"].append(value))
    return log


def _writes(log):
    """Everything the step did to the tenant besides reading Lists."""
    return [(c, a) for c, a in log["execute"] if c != "getList"]


def test_the_shipped_list_and_the_built_in_prompt_are_the_same_text():
    wrapper = json.loads((LISTS / "list-guardian_prompt_report.json").read_text())
    assert wrapper["id"] == wrapper["name"] == "guardian_prompt_report" and wrapper["type"] == "json" and wrapper["version"] == -1
    assert json.loads(wrapper["data"]) == rb.GUARDIAN_REPORT_DEFAULT_PROMPTS


def test_the_prompt_carries_the_four_rules_that_the_lab_run_needed():
    rules = rb.GUARDIAN_REPORT_DEFAULT_PROMPTS["rules"]
    assert "concrete identifier" in rules and "never an entity" in rules          # an entity is an identifier
    assert "may only name a command from the TOOLS list" in rules                  # a command from the tool list
    assert "bookkeeping" in rules                                                  # no self-referential actions
    assert "Do not return them" in rules                                           # verdict, confidence, severity from the run
    for group in rb.GUARDIAN_REPORT_GROUPS:
        for forbidden in ("\"verdict\"", "\"confidence\"", "\"severity\""):
            assert forbidden not in rb.GUARDIAN_REPORT_DEFAULT_PROMPTS[group]


def test_a_missing_or_malformed_prompt_list_falls_back_to_the_built_in_text(monkeypatch):
    _tenant(monkeypatch, lists={})
    assert rb.guardian_report_load_prompts() == (rb.GUARDIAN_REPORT_DEFAULT_PROMPTS, "default")
    _tenant(monkeypatch, lists={"guardian_prompt_report": "{ not json"})
    assert rb.guardian_report_load_prompts()[1] == "default"
    _tenant(monkeypatch, lists={"guardian_prompt_report": {"rules": "Custom rules.", "core": "  ", "story": 5}})
    prompts, source = rb.guardian_report_load_prompts()
    assert source == "list" and prompts["rules"] == "Custom rules."
    assert prompts["core"] == rb.GUARDIAN_REPORT_DEFAULT_PROMPTS["core"] and prompts["story"] == rb.GUARDIAN_REPORT_DEFAULT_PROMPTS["story"]


def test_the_shipped_settings_carry_the_two_keys_with_their_comments():
    data = json.loads(json.loads((LISTS / "list-guardian_settings.json").read_text())["data"])
    assert data["report_enabled"] is True and data["report_max_calls"] == 3
    assert data["_comment_report_enabled"] and data["_comment_report_max_calls"]


# --- the whole step -----------------------------------------------------------------------------------------------------

def test_the_runs_last_assistant_fingerprint_is_written_to_the_record(monkeypatch):
    log = _tenant(monkeypatch, context={"Loop": dict(copy.deepcopy(LOOP), last_assistant_fingerprint="abc123"),
                                        "ToolCatalog": []}, replies=[CORE, STORY, CLOSE])
    rb.guardian_report_run_all()
    assert log["context"][0][1]["fingerprint"] == "abc123"


def test_the_step_writes_one_report_one_audit_row_one_charge_per_call_and_a_note(monkeypatch):
    log = _tenant(monkeypatch, replies=[CORE, STORY, CLOSE])
    note = rb.guardian_report_run_all()
    assert len(log["context"]) == 1 and log["context"][0][0] == "Guardian.Report"
    record = log["context"][0][1]
    assert record["run_id"] == "4217" and record["tick"] == 6 and record["calls"] == 3 and record["cost_usd"] == 0.06
    commands = [c for c, _ in log["execute"]]
    assert commands.count("guardian-llm-chat") == 3 and commands.count("GuardianCostLedger") == 3
    ledger = [a for c, a in log["execute"] if c == "GuardianCostLedger"][0]
    assert ledger["trigger"] == "report_build" and ledger["run_id"] == "4217"
    audit = [a for c, a in log["execute"] if c == "GuardianAuditWrite"]
    assert len(audit) == 1 and audit[0]["action"] == "report_build" and audit[0]["status"] == "ok" and audit[0]["run_id"] == "4217"
    assert json.loads(audit[0]["detail"])["entities"] == 4
    for word in ("Calls", "Seconds", "Entities", "Techniques", "Unverified items", "Errors"):
        assert word in note
    assert all(not a.get("tools") and "response_format" not in a and a["tool_choice"] == "none" for a in log["llm"])
    assert all("model" not in a for a in log["llm"])


def test_report_enabled_false_writes_nothing_and_asks_no_model(monkeypatch):
    log = _tenant(monkeypatch, lists={"guardian_settings": {"report_enabled": False}}, replies=[])
    note = rb.guardian_report_run_all()
    assert "turned off" in note
    assert log["context"] == [] and _writes(log) == [("DeleteContext", {"key": "Guardian.Report"})]
    for value in (False, "false", "no", "0"):
        _tenant(monkeypatch, lists={"guardian_settings": {"report_enabled": value}})
        assert not rb.guardian_report_read_settings()["enabled"]
    for value in (True, "true", None, "yes", 1):
        _tenant(monkeypatch, lists={"guardian_settings": {"report_enabled": value}})
        assert rb.guardian_report_read_settings()["enabled"]


def test_the_kill_switch_on_writes_nothing_and_asks_no_model(monkeypatch):
    log = _tenant(monkeypatch, lists={"guardian_settings": {}, "guardian_kill_switch": {"enabled": True}}, replies=[])
    note = rb.guardian_report_run_all()
    assert "kill switch is on" in note
    assert log["context"] == [] and _writes(log) == [("DeleteContext", {"key": "Guardian.Report"})]


@pytest.mark.parametrize("switch", [{"enabled": False}, "garbage", None, [], {"enabled": "true"}])
def test_an_off_or_unreadable_kill_switch_does_not_stop_the_report(monkeypatch, switch):
    lists = {"guardian_settings": {}}
    if switch is not None:
        lists["guardian_kill_switch"] = switch
    log = _tenant(monkeypatch, lists=lists, replies=[CORE, STORY, CLOSE])
    rb.guardian_report_run_all()
    assert len(log["context"]) == 1 and log["context"][0][1]["report"]


def test_report_max_calls_is_read_and_capped_at_the_three_groups(monkeypatch):
    for raw, expected in ((None, 3), (1, 1), (2, 2), (3, 3), (9, 3), (0, 3), ("x", 3), (True, 3)):
        _tenant(monkeypatch, lists={"guardian_settings": {} if raw is None else {"report_max_calls": raw}})
        assert rb.guardian_report_read_settings()["max_calls"] == expected, raw
    _tenant(monkeypatch, lists={})
    assert rb.guardian_report_read_settings() == {"enabled": True, "max_calls": 3}


def test_the_runs_routed_model_is_passed_and_dropped_for_a_provider_that_cannot_serve_it(monkeypatch):
    loop = dict(copy.deepcopy(LOOP), model_params={"max_input_tokens": 28258, "routed": True, "model": "big-model"})
    log = _tenant(monkeypatch, context={"Loop": loop}, replies=[CORE, STORY, CLOSE])
    rb.guardian_report_run_all()
    assert [a.get("model") for a in log["llm"]] == ["big-model"] * 3

    calls = []

    def execute(command, args, using=None):
        calls.append(dict(args))
        if "model" in args:
            return {"ok": False, "data": None, "error": "MODEL_NOT_AVAILABLE: no such deployment", "retryable": False}
        return {"ok": True, "data": [{"Contents": {"model": "m", "usage": {}, "choices": [{"message": {"content": "{}"}}]}}]}

    monkeypatch.setattr(rb, "guardian_execute", execute)
    turn = rb.guardian_report_call_llm([{"role": "user", "content": "x"}], "big-model")
    assert turn["ok"] and [("model" in c) for c in calls] == [True, False]
    dropped = dict(loop, model_route_dropped="refused")
    log = _tenant(monkeypatch, context={"Loop": dropped}, replies=[CORE, STORY, CLOSE])
    rb.guardian_report_run_all()
    assert all("model" not in a for a in log["llm"])


def test_the_call_helper_reads_the_completion_and_treats_a_filtered_one_as_final():
    def execute_with(completion):
        return lambda command, args, using=None: {"ok": True, "data": [{"Contents": completion}], "error": None}

    original = rb.guardian_execute
    try:
        rb.guardian_execute = execute_with({"model": "m", "usage": {"total_tokens": 3}, "choices": [{"message": {"content": " hi "}}]})
        assert rb.guardian_report_call_llm([]) == {"ok": True, "content": "hi", "usage": {"total_tokens": 3}, "model": "m", "error": ""}
        rb.guardian_execute = execute_with({"model": "m", "content_filter": True, "usage": {}})
        turn = rb.guardian_report_call_llm([])
        assert not turn["ok"] and turn["filtered"] and "content filter" in turn["error"]
        rb.guardian_execute = execute_with("not a completion")
        assert not rb.guardian_report_call_llm([])["ok"]
    finally:
        rb.guardian_execute = original


def test_a_content_filtered_reply_is_not_repaired(monkeypatch):
    log = _tenant(monkeypatch, replies=[
        {"ok": True, "data": [{"Contents": {"model": "m", "content_filter": True, "usage": {"total_tokens": 4}}}]}, STORY, CLOSE])
    rb.guardian_report_run_all()
    record = log["context"][0][1]
    assert record["calls"] == 3 and "content filter" in record["errors"][0]


def test_an_unexpected_error_still_writes_a_record_with_errors_and_no_report(monkeypatch):
    log = _tenant(monkeypatch, replies=[])

    def boom(*_args, **_kwargs):
        raise RuntimeError("catalogue exploded")

    monkeypatch.setattr(rb, "guardian_report_tool_names", boom)
    rb.main()
    assert len(log["context"]) == 1
    record = log["context"][0][1]
    assert record["report"] is None and record["refs"] == {} and "catalogue exploded" in record["errors"][0]
    assert record["run_id"] == "4217"
    assert "not built" in log["results"][0].readable_output


def test_main_never_raises_even_when_the_context_cannot_be_written(monkeypatch):
    log = _tenant(monkeypatch, replies=[])
    monkeypatch.setattr(rb, "guardian_report_run_all", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    monkeypatch.setattr(rb.demisto, "setContext", lambda *_: (_ for _ in ()).throw(RuntimeError("no write")))
    rb.main()
    assert "not built" in log["results"][0].readable_output


def test_no_run_state_is_a_failure_record_not_an_exception(monkeypatch):
    log = _tenant(monkeypatch, context={}, replies=[])
    rb.guardian_report_run_all()
    record = log["context"][0][1]
    assert record["report"] is None and "no Guardian.Loop" in record["errors"][0] and record["run_id"] == "4217"
    assert not [c for c, _ in log["execute"] if c == "guardian-llm-chat"]


def test_the_note_says_when_no_report_was_built():
    record = {"v": 1, "run_id": "1", "tick": 1, "calls": 3, "seconds": 4.5, "report": None, "refs": {}, "errors": ["core: x"]}
    text = rb.guardian_report_readable(record, rb.guardian_report_summary(record))
    assert "not built" in text and "core: x" in text


def test_the_script_is_well_formed():
    source = pathlib.Path(rb.__file__).read_text()
    assert source.count("# <GUARDIAN_COMMON_INJECT>") == 1 and source.count("# </GUARDIAN_COMMON>") == 1
    after = source.split("# </GUARDIAN_COMMON_INJECT>")[1]
    for word in ("core-", "XQL", "marketplacev2", "Cortex platform"):
        assert word not in after, word


# --- a Job run, a stale report, the kill switch during the step, a small budget -----------------------------------------

def _job_incident(source):
    return dict(INCIDENT, CustomFields={"guardiantriggersource": source})


@pytest.mark.parametrize("source", ["job:intake-sweep", "JOB:other", " job:x "])
def test_a_run_started_by_a_scheduled_job_builds_no_report_and_clears_the_old_one(monkeypatch, source):
    log = _tenant(monkeypatch, incident=_job_incident(source), replies=[])
    note = rb.guardian_report_run_all()
    assert "scheduled Job" in note and "No model call was made" in note
    assert log["context"] == [] and log["llm"] == []
    assert _writes(log) == [("DeleteContext", {"key": "Guardian.Report"})]


@pytest.mark.parametrize("source", ["simulate", "analyst", "", None, "jobless", 5])
def test_any_other_trigger_source_builds_the_report(monkeypatch, source):
    log = _tenant(monkeypatch, incident=_job_incident(source), replies=[CORE, STORY, CLOSE])
    rb.guardian_report_run_all()
    assert len(log["llm"]) == 3 and log["context"][0][1]["report"]
    assert ("DeleteContext", {"key": "Guardian.Report"}) not in _writes(log)


def test_a_failing_delete_never_stops_the_step(monkeypatch):
    log = _tenant(monkeypatch, lists={"guardian_settings": {"report_enabled": False}})
    original = rb.guardian_execute

    def execute(command, args, using=None):
        if command == "DeleteContext":
            raise RuntimeError("no delete")
        return original(command, args, using)

    monkeypatch.setattr(rb, "guardian_execute", execute)
    assert "turned off" in rb.guardian_report_run_all() and log["context"] == []


def test_the_tick_is_coerced_to_a_whole_number():
    for raw, expected in ((15, 15), (15.0, 15), ("15", 15), (" 7 ", 7), ("x", None), (None, None), (True, None), (2.5, None),
                          ("", None), (float("inf"), None)):
        assert rb.guardian_report_int(raw) == expected, raw


def test_a_numeric_tick_from_the_run_state_is_written_as_an_int(monkeypatch):
    for raw in ("6", 6.0):
        log = _tenant(monkeypatch, context={"Loop": dict(copy.deepcopy(LOOP), tick=raw), "ToolCatalog": []}, replies=[CORE, STORY, CLOSE])
        rb.guardian_report_run_all()
        tick = log["context"][0][1]["tick"]
        assert tick == 6 and isinstance(tick, int) and not isinstance(tick, bool)


def _archive_rows():
    old = {"role": "assistant", "tool_calls": [_call("o1", "getEntries", id="old")]}
    return [
        {"run_id": "4217", "tick": 5, "session_id": "old-session", "dropped_messages": [old, _result("o1", "getEntries", "OLD RUN EVIDENCE")]},
        {"run_id": "4217", "tick": 12, "session_id": "new-session", "dropped_messages": [
            {"role": "assistant", "tool_calls": [_call("n1", "domain", domain="new.example")]}, _result("n1", "domain", "NEW RUN EVIDENCE")]},
        {"run_id": "4217", "tick": 13, "dropped_messages": ["written before the session id existed"]},
        {"run_id": "other", "tick": 12, "session_id": "new-session", "dropped_messages": ["another incident"]},
    ]


def test_a_rerun_keeps_only_the_archive_rows_of_its_own_session(monkeypatch):
    """The reviewer's case: rows at tick 5 from the old run and tick 12 from the new one, read at tick 15."""
    monkeypatch.setattr(rb, "guardian_report_load_list_json", lambda name: (copy.deepcopy(_archive_rows()), ""))
    kept = rb.guardian_report_load_archive("4217", 15, True, "new-session")
    assert [row["tick"] for row in kept] == [12]
    inp = _inputs(loop=dict(LOOP, tick=15), archive=kept)
    assert "NEW RUN EVIDENCE" in inp["evidence_text"] and "OLD RUN EVIDENCE" not in inp["evidence_text"]
    assert rb.guardian_report_load_archive("4217", 15, True, "unknown-session") == []
    # a run state saved before the session id existed falls back to the tick rule
    assert [row["tick"] for row in rb.guardian_report_load_archive("4217", 15, True, None)] == [5, 12, 13]


def test_the_step_reads_the_session_id_of_the_run_state(monkeypatch):
    rows = _archive_rows()
    loop = dict(copy.deepcopy(LOOP), tick=15, dropped_count=3, session_id="new-session")
    log = _tenant(monkeypatch, lists={"guardian_settings": {}, "guardian_dropped_transcript_archive": rows},
                  context={"Loop": loop, "ToolCatalog": []}, replies=[CORE, STORY, CLOSE])
    rb.guardian_report_run_all()
    sent = log["llm"][0]["messages"][1]["content"]
    assert "NEW RUN EVIDENCE" in sent and "OLD RUN EVIDENCE" not in sent


def test_the_kill_switch_is_read_again_before_every_later_call():
    reads = []

    def halted():
        reads.append(1)
        return len(reads) >= 2          # off before the second call, on before the third

    model = Model(CORE, STORY, CLOSE)
    record = _generate(model, halted=halted)
    assert len(model.calls) == 2 and record["calls"] == 2
    assert record["errors"] == ["close: the kill switch is on, so the remaining calls were not made"]
    assert "entities" in record["report"] and "attack" in record["report"] and "findings" not in record["report"]


def test_a_kill_switch_thrown_before_a_repair_request_stops_it():
    model = Model("no json", CORE)
    record = _generate(model, halted=lambda: True)
    assert len(model.calls) == 1 and record["report"] is None
    assert record["errors"] == ["core: the kill switch is on, so the remaining calls were not made"]


def test_the_first_call_does_not_read_the_kill_switch_again():
    reads = []
    _generate(Model(CORE, STORY, CLOSE), halted=lambda: reads.append(1) or False)
    assert len(reads) == 2


def test_a_budget_the_fixed_text_does_not_fit_makes_no_call_and_says_so(monkeypatch):
    loop = dict(copy.deepcopy(LOOP), model_params={"max_input_tokens": 4096}, conclusion="The host beaconed. " * 300)
    loop["messages"][1] = {"role": "user", "content": "Investigate the beacon in detail. " * 60}
    tools = ["GuardianTool%03d" % i for i in range(150)]
    inp = _inputs(loop=loop, tools=tools)
    assert inp["fits"] is False and inp["fixed_chars"] > inp["budget_chars"] == (4096 - 2048) * 4
    model = Model()
    record = _generate(model, inp=inp)
    assert record["calls"] == 0 and model.calls == [] and record["report"] is None and record["refs"] == {}
    assert len(record["errors"]) == 1 and "does not fit the run's input budget" in record["errors"][0]
    assert "no model call was made" in record["errors"][0]
    log = _tenant(monkeypatch, context={"Loop": loop, "ToolCatalog": [{"function": {"name": n}} for n in tools]}, replies=[])
    rb.guardian_report_run_all()
    assert log["llm"] == [] and log["context"][0][1]["report"] is None and "input budget" in log["context"][0][1]["errors"][0]
    audit = [a for c, a in log["execute"] if c == "GuardianAuditWrite"]
    assert len(audit) == 1 and audit[0]["status"] == "error"


def test_the_shipped_budget_fits_the_fixed_text():
    assert _inputs()["fits"] is True
