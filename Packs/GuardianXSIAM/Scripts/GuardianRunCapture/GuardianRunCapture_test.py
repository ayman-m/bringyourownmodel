import GuardianRunCapture as cap

LOOP = {"verdict": {"verdict": "Confirmed", "confidence": 75, "techniques": [], "kind": "posture", "priority": "P2",
                    "summary": "P2 | exposure: private | owner: unknown | fix: deny | The setting still holds."}}
ROUTE = {"family": "misconfiguration", "signals": {"rule_id": "rule-7", "asset_ids": ["asset-a", "asset-b"]}}


class Fake:
    def __init__(self, ok=True):
        self.calls, self.ok = [], ok

    def __call__(self, command, args):
        self.calls.append((command, dict(args)))
        return [{"Type": 1 if self.ok else 4, "Contents": {"status": "stored"} if self.ok else "boom"}]


def test_posture_run_is_remembered_with_ids_in_the_value_and_tags(monkeypatch):
    fake = Fake()
    monkeypatch.setattr(cap.demisto, "executeCommand", fake)
    status, detail = cap.guardian_run_capture_run({"id": "9001"}, LOOP, ROUTE, "2026-10-10")
    assert (status, detail) == ("stored", "run:9001")
    command, args = fake.calls[0]
    assert command == "GuardianMemory" and args["op"] == "store" and args["key"] == "run:9001"
    assert "rule rule-7" in args["value"] and "asset-a, asset-b" in args["value"] and "Confirmed P2" in args["value"]
    assert args["tags"] == "run,misconfiguration,rule-7,asset-a,asset-b" and args["ttl"] == str(180 * 24 * 3600)


def test_detection_run_records_verdict_and_confidence(monkeypatch):
    fake = Fake()
    monkeypatch.setattr(cap.demisto, "executeCommand", fake)
    loop = {"verdict": {"verdict": "Suspicious", "confidence": 60, "summary": "Burst of IAM changes from a new network."}}
    cap.guardian_run_capture_run({"id": "5"}, loop, {"family": "detection", "signals": {}}, "2026-10-10")
    assert "Suspicious (confidence 60)" in fake.calls[0][1]["value"] and "rule unknown" in fake.calls[0][1]["value"]


def test_nothing_is_written_without_a_verdict(monkeypatch):
    fake = Fake()
    monkeypatch.setattr(cap.demisto, "executeCommand", fake)
    for loop in (None, {}, {"verdict": {}}, {"verdict": "x"}):
        assert cap.guardian_run_capture_run({"id": "9"}, loop, ROUTE, "d")[0] == "skipped"
    assert fake.calls == []


def test_no_issue_in_context_is_skipped(monkeypatch):
    assert cap.guardian_run_capture_run({}, LOOP, ROUTE, "d")[0] == "skipped"


def test_a_failed_store_is_reported_not_raised(monkeypatch):
    monkeypatch.setattr(cap.demisto, "executeCommand", Fake(ok=False))
    status, detail = cap.guardian_run_capture_run({"id": "9"}, LOOP, ROUTE, "d")
    assert status == "error" and "boom" in detail


def test_summary_is_capped_and_flattened():
    loop = {"verdict": {"verdict": "Benign", "confidence": 80, "summary": "word\n" * 400}}
    key, value, _tags = cap.guardian_run_capture_row("1", loop, {}, "d")
    assert "\n" not in value and len(value) < 450


def test_digest_run_also_stores_the_rule_marker(monkeypatch):
    fake = Fake()
    monkeypatch.setattr(cap.demisto, "executeCommand", fake)
    evidence = {"mode": "digest", "digest_key": "rule-digest:rule-7:2026-10-10"}
    status, detail = cap.guardian_run_capture_run({"id": "9001"}, LOOP, ROUTE, "2026-10-10", evidence)
    assert status == "stored" and "rule-digest:rule-7:2026-10-10" in detail
    assert [a["key"] for _c, a in fake.calls] == ["run:9001", "rule-digest:rule-7:2026-10-10"]
    assert fake.calls[1][1]["ttl"] == "172800"


def test_a_normal_run_stores_no_marker(monkeypatch):
    fake = Fake()
    monkeypatch.setattr(cap.demisto, "executeCommand", fake)
    cap.guardian_run_capture_run({"id": "9001"}, LOOP, ROUTE, "d", {"mode": "issue", "digest_key": ""})
    assert len(fake.calls) == 1


def test_route_and_evidence_survive_an_appended_second_copy(monkeypatch):
    ctx = {"Route": [{"family": "identity"}, {"family": "attack_path"}], "Evidence": {"issue_id": "1"}}
    monkeypatch.setattr(cap, "guardian_ctx_read", lambda key, default=None: ctx.get(key, default))
    assert cap.guardian_run_capture_ctx_latest("Route") == {"family": "attack_path"}
    assert cap.guardian_run_capture_ctx_latest("Evidence") == {"issue_id": "1"}
    assert cap.guardian_run_capture_ctx_latest("Loop") is None
