import GuardianRunCapture as cap

LOOP = {"verdict": {"verdict": "Malicious", "confidence": 85, "techniques": ["T1071"],
                    "summary": "The binary beacons to a newly registered domain every five minutes."}}
ROUTE = {"family": "endpoint", "signals": {"rule_id": "Suspicious beacon", "entities": ["jdoe", "203.0.113.9", "lt-042"]}}


class Fake:
    def __init__(self, ok=True):
        self.calls, self.ok = [], ok

    def __call__(self, command, args):
        self.calls.append((command, dict(args)))
        return [{"Type": 1 if self.ok else 4, "Contents": {"status": "stored"} if self.ok else "boom"}]


def test_a_run_is_remembered_with_rule_and_entities_in_the_value_and_tags(monkeypatch):
    fake = Fake()
    monkeypatch.setattr(cap.demisto, "executeCommand", fake)
    status, detail = cap.guardian_run_capture_run({"id": "9001"}, LOOP, ROUTE, "2026-10-12")
    assert (status, detail) == ("stored", "run:9001")
    command, args = fake.calls[0]
    assert command == "GuardianMemory" and args["op"] == "store" and args["key"] == "run:9001" and args["scope"] == "9001"
    assert "rule Suspicious beacon" in args["value"] and "jdoe, 203.0.113.9, lt-042" in args["value"]
    assert "Malicious (confidence 85)" in args["value"] and args["value"].startswith("2026-10-12 incident 9001 [endpoint]")
    assert args["tags"] == "run,endpoint,Suspicious beacon,jdoe,203.0.113.9,lt-042" and args["ttl"] == str(180 * 24 * 3600)


def test_without_signals_the_rule_and_entities_say_so(monkeypatch):
    fake = Fake()
    monkeypatch.setattr(cap.demisto, "executeCommand", fake)
    loop = {"verdict": {"verdict": "Suspicious", "confidence": 60, "summary": "A burst of failed sign-ins from a new network."}}
    cap.guardian_run_capture_run({"id": "5"}, loop, {"family": "identity", "signals": {}}, "2026-10-12")
    value = fake.calls[0][1]["value"]
    assert "Suspicious (confidence 60)" in value and "rule unknown" in value and "entities none" in value
    assert fake.calls[0][1]["tags"] == "run,identity"


def test_a_comma_in_a_tag_does_not_split_it():
    route = {"family": "phishing", "signals": {"rule_id": "Reported, urgent", "entities": ["a,b"]}}
    _key, _value, tags = cap.guardian_run_capture_row("1", LOOP, route, "d")
    assert tags == "run,phishing,Reported  urgent,a b"


def test_at_most_five_entities_are_kept():
    route = {"family": "network", "signals": {"entities": ["e%d" % i for i in range(9)] + [5, None, "  "]}}
    _key, value, tags = cap.guardian_run_capture_row("1", LOOP, route, "d")
    assert tags.split(",")[2:] == ["e0", "e1", "e2", "e3", "e4"] and "e5" not in value


def test_nothing_is_written_without_a_verdict(monkeypatch):
    fake = Fake()
    monkeypatch.setattr(cap.demisto, "executeCommand", fake)
    for loop in (None, {}, {"verdict": {}}, {"verdict": "x"}):
        assert cap.guardian_run_capture_run({"id": "9"}, loop, ROUTE, "d")[0] == "skipped"
    assert fake.calls == []


def test_no_incident_in_context_is_skipped():
    for incident in ({}, None, "junk"):
        assert cap.guardian_run_capture_run(incident, LOOP, ROUTE, "d")[0] == "skipped"


def test_a_failed_store_is_reported_not_raised(monkeypatch):
    monkeypatch.setattr(cap.demisto, "executeCommand", Fake(ok=False))
    status, detail = cap.guardian_run_capture_run({"id": "9"}, LOOP, ROUTE, "d")
    assert status == "error" and "boom" in detail


def test_summary_is_capped_and_flattened():
    loop = {"verdict": {"verdict": "Benign", "confidence": 80, "summary": "word\n" * 400}}
    _key, value, _tags = cap.guardian_run_capture_row("1", loop, {}, "d")
    assert "\n" not in value and len(value) < 450


def test_the_unstructured_placeholder_verdict_is_not_remembered(monkeypatch):
    fake = Fake()
    monkeypatch.setattr(cap.demisto, "executeCommand", fake)
    loop = {"verdict": dict(LOOP["verdict"], verdict="Inconclusive", confidence=0, source="unstructured")}
    assert cap.guardian_run_capture_row("1", loop, ROUTE, "d") is None
    assert cap.guardian_run_capture_run({"id": "9"}, loop, ROUTE, "d")[0] == "skipped"
    assert fake.calls == []
    extracted = {"verdict": dict(LOOP["verdict"], source="extracted")}
    assert cap.guardian_run_capture_row("1", extracted, ROUTE, "d") is not None
