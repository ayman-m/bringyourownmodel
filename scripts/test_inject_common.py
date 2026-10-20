"""Regression tests for the non-mutating GuardianCommon injector check."""

import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("inject_common.py")
SPEC = importlib.util.spec_from_file_location("inject_common_under_test", MODULE_PATH)
inject_common = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inject_common)


def _configure_fixture(tmp_path, monkeypatch):
    repo_root = tmp_path / "repo"
    scripts_dir = repo_root / "Packs" / "Guardian" / "Scripts"
    common_path = scripts_dir / "GuardianCommon" / "GuardianCommon.py"
    consumer_path = scripts_dir / "Consumer" / "Consumer.py"
    common_path.parent.mkdir(parents=True)
    consumer_path.parent.mkdir(parents=True)
    common_path.write_text("# <GUARDIAN_COMMON>\nCANONICAL = True\n# </GUARDIAN_COMMON>\n")
    consumer_path.write_text(
        "before\n# <GUARDIAN_COMMON_INJECT>\nstale\n# </GUARDIAN_COMMON_INJECT>\nafter\n"
    )
    monkeypatch.setattr(inject_common, "REPO_ROOT", repo_root)
    monkeypatch.setattr(inject_common, "PACK_NAMES", ("Guardian",))
    return consumer_path


def test_check_reports_drift_without_changing_the_consumer(tmp_path, monkeypatch, capsys):
    consumer_path = _configure_fixture(tmp_path, monkeypatch)
    before = consumer_path.read_text()

    assert inject_common.main(["--check"]) == 1

    assert consumer_path.read_text() == before
    assert "1 file(s) out of sync" in capsys.readouterr().out


def test_sync_then_check_reports_consumer_in_sync(tmp_path, monkeypatch, capsys):
    consumer_path = _configure_fixture(tmp_path, monkeypatch)

    assert inject_common.main([]) == 0
    assert "CANONICAL = True" in consumer_path.read_text()
    capsys.readouterr()

    assert inject_common.main(["--check"]) == 0
    assert "1 consumer file(s) in sync" in capsys.readouterr().out
