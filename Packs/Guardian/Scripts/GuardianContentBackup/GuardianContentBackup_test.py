import io
import os
import tarfile

import GuardianContentBackup as gcb


# --- test fixtures ------------------------------------------------------------


def _multi_command_stub(handlers):
    def fake_execute(command, args):
        if command not in handlers:
            raise AssertionError("unexpected command: {} {}".format(command, args))
        return handlers[command](args)

    return fake_execute


def _build_test_tar(path, members):
    """Write a real tar.gz at `path` containing `members` -- a list of
    (name, content_bytes) pairs -- so tests exercise the REAL tarfile
    parsing path, not a mock of it.
    """
    with tarfile.open(path, mode="w:gz") as tf:
        for name, content in members:
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


# --- guardian_backup_bucket_name ------------------------------------------------


def test_bucket_name_splits_on_first_hyphen():
    assert gcb.guardian_backup_bucket_name("playbook-Foo-Bar.yml") == "playbook"
    assert gcb.guardian_backup_bucket_name("incidentfield-guardianverdict.json") == "incidentfield"


def test_bucket_name_strips_leading_path():
    assert gcb.guardian_backup_bucket_name("some/dir/list-guardian_settings.json") == "list"


def test_bucket_name_falls_back_to_other_when_no_hyphen():
    assert gcb.guardian_backup_bucket_name("metadata.json") == "other"


# --- guardian_backup_summarize_tar ----------------------------------------------


def test_summarize_tar_counts_by_type(tmp_path):
    path = str(tmp_path / "bundle.tar.gz")
    _build_test_tar(
        path,
        [
            ("playbook-Foo.yml", "a"),
            ("playbook-Bar.yml", "b"),
            ("automation-Baz.yml", "c"),
            ("list-guardian_settings.json", "{}"),
        ],
    )
    result = gcb.guardian_backup_summarize_tar(path)
    assert result["ok"] is True
    assert result["data"]["total_items"] == 4
    assert result["data"]["by_type"] == {"playbook": 2, "automation": 1, "list": 1}


def test_summarize_tar_excludes_directory_entries(tmp_path):
    path = str(tmp_path / "bundle.tar.gz")
    with tarfile.open(path, mode="w:gz") as tf:
        dir_info = tarfile.TarInfo(name="somedir")
        dir_info.type = tarfile.DIRTYPE
        tf.addfile(dir_info)
        data = b"x"
        file_info = tarfile.TarInfo(name="list-guardian_settings.json")
        file_info.size = len(data)
        tf.addfile(file_info, io.BytesIO(data))

    result = gcb.guardian_backup_summarize_tar(path)
    assert result["ok"] is True
    assert result["data"]["total_items"] == 1
    assert result["data"]["by_type"] == {"list": 1}


def test_summarize_tar_errors_on_invalid_file(tmp_path):
    path = str(tmp_path / "not_a_tar.tar.gz")
    with open(path, "wb") as fh:
        fh.write(b"not actually gzip content")
    result = gcb.guardian_backup_summarize_tar(path)
    assert result["ok"] is False
    assert "failed to open/parse" in result["error"]


# --- guardian_backup_fetch_bundle ------------------------------------------------


def test_fetch_bundle_uses_demisto_api_download_and_extracts_file_entry(monkeypatch):
    def handle_download(args):
        assert args["uri"] == "/content/bundle"
        return [
            {
                "Type": 3,
                "Contents": "",
                "File": args["filename"],
                "FileID": "abc-123",
                "FileMetadata": {"type": "application/gzip", "size": 2194541},
            }
        ]

    monkeypatch.setattr(
        gcb.demisto, "executeCommand", _multi_command_stub({"demisto-api-download": handle_download})
    )
    result = gcb.guardian_backup_fetch_bundle("test.tar.gz")
    assert result["ok"] is True
    assert result["data"] == {"file_id": "abc-123", "file_name": "test.tar.gz", "size_bytes": 2194541}


def test_fetch_bundle_fails_loudly_when_command_unregistered_never_falls_back_to_get(monkeypatch):
    """The whole point of this script: never silently substitute the lossy
    demisto-api-get path for a missing demisto-api-download command."""

    def handle_download(args):
        raise Exception("Command not found in module")

    def handle_get_should_never_be_called(args):
        raise AssertionError("must NEVER fall back to demisto-api-get -- it corrupts binary payloads")

    monkeypatch.setattr(
        gcb.demisto,
        "executeCommand",
        _multi_command_stub({"demisto-api-download": handle_download, "demisto-api-get": handle_get_should_never_be_called}),
    )
    result = gcb.guardian_backup_fetch_bundle("test.tar.gz")
    assert result["ok"] is False
    assert "demisto-api-download is not available" in result["error"]


def test_fetch_bundle_errors_when_no_file_entry_returned(monkeypatch):
    def handle_download(args):
        return [{"Type": 1, "Contents": "done, but no file for some reason"}]

    monkeypatch.setattr(
        gcb.demisto, "executeCommand", _multi_command_stub({"demisto-api-download": handle_download})
    )
    result = gcb.guardian_backup_fetch_bundle("test.tar.gz")
    assert result["ok"] is False
    assert "no file entry" in result["error"]


# --- guardian_backup_run: end to end --------------------------------------------


def test_backup_run_end_to_end(monkeypatch, tmp_path):
    path = str(tmp_path / "bundle.tar.gz")
    _build_test_tar(path, [("playbook-Foo.yml", "a"), ("list-guardian_settings.json", "{}")])

    def handle_download(args):
        return [
            {
                "Type": 3,
                "Contents": "",
                "File": args["filename"],
                "FileID": "file-1",
                "FileMetadata": {"type": "application/gzip", "size": 999},
            }
        ]

    monkeypatch.setattr(
        gcb.demisto, "executeCommand", _multi_command_stub({"demisto-api-download": handle_download})
    )
    monkeypatch.setattr(gcb.demisto, "getFilePath", lambda file_id: {"path": path, "name": "bundle.tar.gz"})

    result = gcb.guardian_backup_run()
    assert result["ok"] is True
    assert result["data"]["total_items"] == 2
    assert result["data"]["by_type"] == {"playbook": 1, "list": 1}
    assert result["data"]["file_id"] == "file-1"
    # size_bytes is recomputed from the local file, NOT trusted from
    # FileMetadata (confirmed live to be unreliable via executeCommand's
    # normalized entry -- see guardian_backup_run's own comment).
    assert result["data"]["size_bytes"] == os.path.getsize(path)
    assert "generated_at" in result["data"]


def test_backup_run_propagates_get_file_path_failure(monkeypatch):
    def handle_download(args):
        return [{"Type": 3, "Contents": "", "File": "x", "FileID": "file-1", "FileMetadata": {"size": 1}}]

    monkeypatch.setattr(
        gcb.demisto, "executeCommand", _multi_command_stub({"demisto-api-download": handle_download})
    )

    def boom(file_id):
        raise Exception("no such file")

    monkeypatch.setattr(gcb.demisto, "getFilePath", boom)
    result = gcb.guardian_backup_run()
    assert result["ok"] is False
    assert "getFilePath" in result["error"]


# --- main() ----------------------------------------------------------------------


def test_main_success_returns_command_results(monkeypatch, tmp_path):
    path = str(tmp_path / "bundle.tar.gz")
    _build_test_tar(path, [("playbook-Foo.yml", "a")])

    def handle_download(args):
        return [{"Type": 3, "Contents": "", "File": "x", "FileID": "file-1", "FileMetadata": {"size": 1}}]

    monkeypatch.setattr(
        gcb.demisto, "executeCommand", _multi_command_stub({"demisto-api-download": handle_download})
    )
    monkeypatch.setattr(gcb.demisto, "getFilePath", lambda file_id: {"path": path})
    captured = {}
    monkeypatch.setattr(gcb, "return_results", lambda cr: captured.setdefault("result", cr), raising=False)

    gcb.main()

    assert "result" in captured
    assert "custom-content item" in captured["result"].readable_output
    assert captured["result"].outputs_prefix == "Guardian.ContentBackup"


def test_main_calls_return_error_on_failure(monkeypatch):
    def handle_download(args):
        raise Exception("Command not found in module")

    monkeypatch.setattr(
        gcb.demisto, "executeCommand", _multi_command_stub({"demisto-api-download": handle_download})
    )
    errors = []
    monkeypatch.setattr(gcb, "return_error", lambda msg: errors.append(msg), raising=False)

    gcb.main()

    assert errors
    assert "demisto-api-download" in errors[0]


def test_main_unexpected_exception_calls_return_error(monkeypatch):
    def boom():
        raise RuntimeError("kaboom")

    monkeypatch.setattr(gcb, "guardian_backup_run", boom)
    errors = []
    monkeypatch.setattr(gcb, "return_error", lambda msg: errors.append(msg), raising=False)

    gcb.main()

    assert errors
    assert "kaboom" in errors[0]
