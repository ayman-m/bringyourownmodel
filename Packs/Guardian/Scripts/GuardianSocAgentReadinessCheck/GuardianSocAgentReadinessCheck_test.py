import GuardianSocAgentReadinessCheck as check


def test_main_success_is_short_and_non_empty(monkeypatch):
    check.RESULTS.clear()
    monkeypatch.setattr(
        check.demisto, "executeCommand",
        lambda command, args: [{"Type": 1, "Contents": "### Guardian Agent Readiness\n**Status: Ready**"}],
    )
    check.main()
    assert len(check.RESULTS) == 1
    out = check.RESULTS[0].readable_output
    assert out  # non-empty: empty triggers XSOAR's own outputs-table fallback
    assert "###" not in out and "**" not in out  # plain text, not markdown


def test_main_propagates_the_underlying_check_error(monkeypatch):
    import pytest

    monkeypatch.setattr(
        check.demisto, "executeCommand",
        lambda command, args: [{"Type": 4, "Contents": "kill switch list is unreadable"}],
    )
    with pytest.raises(SystemExit) as exc_info:
        check.main()
    # no manual '"Agent Readiness" failed.' prefix -- the layout UI adds that itself
    assert "kill switch list is unreadable" in str(exc_info.value)
    assert not str(exc_info.value).startswith('"')


def test_main_unexpected_exception_carries_no_manual_prefix(monkeypatch):
    import pytest

    def boom(_command, _args):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(check.demisto, "executeCommand", boom)
    with pytest.raises(SystemExit) as exc_info:
        check.main()
    assert str(exc_info.value) == "kaboom"
