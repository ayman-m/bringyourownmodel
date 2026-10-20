import json

import GuardianWidgetCost as gwc


# --- fixtures / test harness --------------------------------------------------


def _entries(contents):
    return [{"Type": 1, "Contents": contents}]


def _not_found(list_name):
    return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(list_name)}]


SAMPLE_ROLLUP = {
    "2026-07-01": {
        "gemini-2.5-flash": {"tick": {"usd": 0.01, "calls": 1}, "chat": {"usd": 0.02, "calls": 2}},
        "gpt-4": {"tick": {"usd": 0.05, "calls": 1}},
    },
    "2026-07-02": {
        "gemini-2.5-flash": {"tick": {"usd": 0.03, "calls": 3}},
    },
}


# --- _guardian_widget_cost_day_model_usd --------------------------------------


def test_day_model_usd_sums_across_triggers():
    assert gwc._guardian_widget_cost_day_model_usd({"tick": {"usd": 0.01}, "chat": {"usd": 0.02}}) == 0.03


def test_day_model_usd_ignores_malformed():
    assert gwc._guardian_widget_cost_day_model_usd({"tick": {"usd": "bad"}, "chat": {"usd": None}}) == 0.0
    assert gwc._guardian_widget_cost_day_model_usd("not-a-dict") == 0.0
    assert gwc._guardian_widget_cost_day_model_usd({}) == 0.0


# --- _guardian_widget_cost_to_milli_usd ---------------------------------------


def test_to_milli_usd_rounds_to_nearest_integer():
    assert gwc._guardian_widget_cost_to_milli_usd(0.243359) == 243
    assert gwc._guardian_widget_cost_to_milli_usd(0.015768) == 16
    assert gwc._guardian_widget_cost_to_milli_usd(0.0) == 0
    assert isinstance(gwc._guardian_widget_cost_to_milli_usd(0.01), int)


# --- guardian_widget_cost_build ------------------------------------------------


def test_build_merges_same_day_categories_and_sums_totals():
    # Values are INTEGER milli-USD (thousandths of a dollar) -- the platform
    # rejects fractional widget data (see the module docstring's "INTEGER
    # DATA ONLY" section), so 0.03 USD -> 30, 0.05 USD -> 50, etc.
    widget = gwc.guardian_widget_cost_build(SAMPLE_ROLLUP)
    displayed = json.loads(widget.to_display())

    by_name = {cat["name"]: cat for cat in displayed}
    assert set(by_name.keys()) == {"2026-07-01", "2026-07-02"}

    day1 = by_name["2026-07-01"]
    assert day1["data"] == [80]
    assert all(isinstance(v, int) for v in day1["data"])
    groups_by_name = {g["name"]: g["data"][0] for g in day1["groups"]}
    assert groups_by_name == {"gemini-2.5-flash": 30, "gpt-4": 50}

    day2 = by_name["2026-07-02"]
    assert day2["data"] == [30]
    assert day2["groups"] == [{"name": "gemini-2.5-flash", "data": [30]}]


def test_build_empty_rollup_is_graceful():
    widget = gwc.guardian_widget_cost_build({})
    assert widget.to_display() == "[]"

    widget_none = gwc.guardian_widget_cost_build(None)
    assert widget_none.to_display() == "[]"


def test_build_tolerates_malformed_day_bucket():
    widget = gwc.guardian_widget_cost_build({"2026-07-01": "not-a-dict"})
    assert widget.to_display() == "[]"


# --- guardian_widget_cost_load_rollup ------------------------------------------


def test_load_rollup_not_found_is_empty_dict(monkeypatch):
    def fake_execute(command, args):
        assert command == "getList"
        assert args["listName"] == gwc.GUARDIAN_COST_LEDGER_LIST_NAME
        return _not_found(gwc.GUARDIAN_COST_LEDGER_LIST_NAME)

    monkeypatch.setattr(gwc.demisto, "executeCommand", fake_execute)
    result = gwc.guardian_widget_cost_load_rollup()
    assert result == {"ok": True, "data": {}, "error": None, "retryable": False, "is_auth_error": False}


def test_load_rollup_parses_json_string_contents(monkeypatch):
    def fake_execute(command, args):
        return _entries(json.dumps(SAMPLE_ROLLUP))

    monkeypatch.setattr(gwc.demisto, "executeCommand", fake_execute)
    result = gwc.guardian_widget_cost_load_rollup()
    assert result["ok"] is True
    assert result["data"] == SAMPLE_ROLLUP


def test_load_rollup_malformed_json_fails(monkeypatch):
    def fake_execute(command, args):
        return _entries("{not json")

    monkeypatch.setattr(gwc.demisto, "executeCommand", fake_execute)
    result = gwc.guardian_widget_cost_load_rollup()
    assert result["ok"] is False


def test_load_rollup_wrong_type_fails(monkeypatch):
    def fake_execute(command, args):
        return _entries(["not", "a", "dict"])

    monkeypatch.setattr(gwc.demisto, "executeCommand", fake_execute)
    result = gwc.guardian_widget_cost_load_rollup()
    assert result["ok"] is False


# --- main() end-to-end ---------------------------------------------------------


def test_main_returns_widget_json(monkeypatch):
    def fake_execute(command, args):
        return _entries(json.dumps(SAMPLE_ROLLUP))

    monkeypatch.setattr(gwc.demisto, "executeCommand", fake_execute)
    gwc.RESULTS.clear()
    gwc.main()
    assert len(gwc.RESULTS) == 1
    displayed = json.loads(gwc.RESULTS[0])
    assert isinstance(displayed, list)
    assert len(displayed) == 2


def test_main_empty_ledger_is_graceful(monkeypatch):
    def fake_execute(command, args):
        return _not_found(gwc.GUARDIAN_COST_LEDGER_LIST_NAME)

    monkeypatch.setattr(gwc.demisto, "executeCommand", fake_execute)
    gwc.RESULTS.clear()
    gwc.main()
    assert gwc.RESULTS == ["[]"]
