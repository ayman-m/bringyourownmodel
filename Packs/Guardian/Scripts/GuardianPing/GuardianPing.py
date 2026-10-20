import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def guardian_ping() -> CommandResults:
    """Trivial liveness check that proves a Guardian automation can be uploaded
    and executed on the server.

    :return: CommandResults with a static "pong" payload.
    :rtype: ``CommandResults``
    """
    return CommandResults(
        readable_output="pong",
        outputs_prefix="Guardian.Ping",
        outputs="pong",
    )


def main():
    try:
        return_results(guardian_ping())
    except Exception as ex:
        return_error(f"Failed to execute GuardianPing. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
