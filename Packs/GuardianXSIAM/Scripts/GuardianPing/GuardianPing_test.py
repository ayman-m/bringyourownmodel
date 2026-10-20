from GuardianPing import guardian_ping


def test_guardian_ping():
    """guardian_ping() should always report readiness with a static "pong" payload."""
    result = guardian_ping()

    assert result.readable_output == "pong"
    assert result.outputs_prefix == "Guardian.Ping"
    assert result.outputs == "pong"
