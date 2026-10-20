import GuardianHelpCommand as help_cmd


# --- guardian_help_text ----------------------------------------------------------


def test_mentions_every_documented_command():
    text = help_cmd.guardian_help_text()
    assert "!guardian-chat" in text
    assert "!GuardianAskAnalyst" in text
    assert "!guardian-cost" in text
    assert "!guardian-tools" in text
    assert "!guardian-plan" in text
    assert "!guardian-compact" in text
    assert "!guardian-model" in text
    assert "!guardian-help" in text


def test_mentions_direct_native_dispatch():
    text = help_cmd.guardian_help_text()
    assert "native XSOAR command" in text
    assert "!ip ip=1.2.3.4" in text


def test_notes_operator_only_scope():
    text = help_cmd.guardian_help_text()
    assert "guardian_tool_allowlist" in text
    assert "operator-only" in text


def test_is_deterministic():
    assert help_cmd.guardian_help_text() == help_cmd.guardian_help_text()


def test_no_demisto_calls_required(monkeypatch):
    # Assert this really is a zero-dependency command -- any executeCommand call at all is a
    # bug for this specific script.
    def unexpected_execute(command, args):
        raise AssertionError("GuardianHelpCommand must never call executeCommand ({})".format(command))

    monkeypatch.setattr(help_cmd.demisto, "executeCommand", unexpected_execute)
    help_cmd.guardian_help_text()


# --- main() smoke test -----------------------------------------------------------


def test_main_returns_command_results(monkeypatch):
    import CommonServerPython as csp

    csp.RESULTS.clear()
    help_cmd.main()

    assert len(csp.RESULTS) == 1
    result = csp.RESULTS[0]
    assert "!guardian-help" in result.outputs["text"]
    assert result.readable_output == result.outputs["text"]
