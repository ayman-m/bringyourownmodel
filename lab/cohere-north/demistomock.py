"""Minimal demistomock for the Guardian lab driver."""
_PARAMS = {}
_ARGS = {}
_COMMAND = "guardian-llm-chat"
RESULTS = []


def params():
    return _PARAMS


def args():
    return _ARGS


def command():
    return _COMMAND


def debug(*a, **k):
    pass


def info(*a, **k):
    pass


def error(*a, **k):
    pass


def results(r):
    RESULTS.append(r)


def getParam(k):
    return _PARAMS.get(k)


# --- Broader surface so scripts that touch incident/context/command APIs are importable and
# --- unit-testable here (tests monkeypatch these; unpatched source calls get sane empty defaults
# --- rather than an AttributeError). Kept intentionally inert -- no real platform behaviour.
def context():
    return {}


def incident():
    return {}


def incidents():
    return []


def getFilePath(file_id):
    return {}


def executeCommand(command, args=None):
    return []


def setContext(path, value):
    return {"status": True}


def get(obj, path, default_param=None):
    """demisto.get: safe dotted-path lookup into a dict, else ``default_param``."""
    if not isinstance(obj, dict):
        return default_param
    cur = obj
    for part in str(path).split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default_param
    return cur
