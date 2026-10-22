"""The Inconclusive placeholder that GuardianReasoningTick writes when the model returns no usable verdict block is
recognised by marker in the issue field (`guardianblastradius`) by the scripts that only read the fields. The marker
must be the same literal everywhere, and the audit writer must accept the status the violation rows use."""
import ast
import re
from pathlib import Path

import yaml

PACK = Path(__file__).resolve().parents[2] / "Packs" / "Guardian"
SCRIPTS = PACK / "Scripts"


def _constant(script, name):
    tree = ast.parse((SCRIPTS / script / (script + ".py")).read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError("{} not found in {}".format(name, script))


def test_the_placeholder_marker_is_the_same_in_every_reader():
    written = _constant("GuardianReasoningTick", "GUARDIAN_UNSTRUCTURED_SUMMARY_MARKER")
    for script in ("GuardianEval", "GuardianEvalHarvest", "GuardianCaseCapture"):
        assert _constant(script, "GUARDIAN_UNSTRUCTURED_SUMMARY_MARKER") == written.strip()
    assert written.endswith(" ") and re.match(r"^\[[^\]]+\]", written)


def test_the_source_value_run_capture_skips_is_the_one_the_tick_writes():
    source = _constant("GuardianReasoningTick", "GUARDIAN_UNSTRUCTURED_SOURCE")
    assert 'verdict.get("source") == "%s"' % source in (SCRIPTS / "GuardianRunCapture" / "GuardianRunCapture.py").read_text()


def test_the_audit_writer_accepts_the_status_of_the_violation_rows():
    assert "warning" in _constant("GuardianAuditWrite", "GUARDIAN_AUDIT_VALID_STATUSES")
    tick = (SCRIPTS / "GuardianReasoningTick" / "GuardianReasoningTick.py").read_text()
    assert '"status": "warning"' in tick and '"verdict_format_violation"' in tick
    triage = (SCRIPTS / "GuardianTriageResult" / "GuardianTriageResult.py").read_text()
    assert '"status": "warning"' in triage and '"triage_format_violation"' in triage


def test_the_tick_documents_the_format_violation_outputs():
    doc = yaml.safe_load((SCRIPTS / "GuardianReasoningTick" / "GuardianReasoningTick.yml").read_text())
    paths = {o["contextPath"] for o in doc["outputs"]}
    assert {"Guardian.Loop.format_violation", "Guardian.Loop.verdict.source"} <= paths
