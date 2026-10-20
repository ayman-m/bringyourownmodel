"""Local checks for the lab model service's recovery of tool calls Ollama swallows (run: python -m pytest lab/cohere-north)."""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault("LAB_BEARER_TOKEN", "x")
import north_mock as nm

NAMES = {"getIncidents", "ip"}

def test_a_native_action_block_becomes_tool_calls():
    text = 'Action: ```json\n[\n  {"tool_name": "getIncidents", "parameters": {"details": true, "id": "52350"}}\n]\n```'
    assert nm.parse_action_block(text, NAMES) == [{"name": "getIncidents", "parameters": {"details": True, "id": "52350"}}]

def test_text_before_the_block_and_several_calls_are_handled():
    text = 'I will look both up.\nAction: ```json\n[{"tool_name": "ip", "parameters": {"ip": "1.1.1.1"}}, {"tool_name": "ip", "parameters": {"ip": "8.8.8.8"}}]\n```'
    assert [c["parameters"]["ip"] for c in nm.parse_action_block(text, NAMES)] == ["1.1.1.1", "8.8.8.8"]

def test_tools_that_were_not_offered_and_bad_json_are_ignored():
    assert nm.parse_action_block('Action: ```json\n[{"tool_name": "rm_rf", "parameters": {}}]\n```', NAMES) == []
    assert nm.parse_action_block('Action: ```json\n[{"tool_name": "ip", ```', NAMES) == []
    assert nm.parse_action_block("a plain answer", NAMES) == []
    assert nm.parse_action_block(None, NAMES) == []
