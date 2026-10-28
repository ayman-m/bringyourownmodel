"""GuardianLayoutAssessmentFindings -- the third dynamic section of the Guardian tab: the findings, the recommended actions, the gaps and the footer.

The incident page limits how much one dynamic section may return, so the assessment page is three sections, and a
section cannot pass an argument to its script. This one runs `GuardianLayoutAssessment` with `part=findings` and shows the
HTML entry it returns unchanged. Scripts cannot import each other, hence the command call. It never raises: an error or
an empty answer is one muted line. Display only.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

GUARDIAN_LAYOUT_SCRIPT = "GuardianLayoutAssessment"
GUARDIAN_LAYOUT_PART = "findings"
GUARDIAN_LAYOUT_ERROR_ENTRY_TYPE = 4
GUARDIAN_LAYOUT_NOTE = "The assessment is not available here."


def guardian_layout_part_entry():
    """The entry `GuardianLayoutAssessment` returns for this part, unchanged, or a one-line note."""
    try:
        entries = demisto.executeCommand(GUARDIAN_LAYOUT_SCRIPT, {"part": GUARDIAN_LAYOUT_PART})
    except Exception as exc:
        demisto.debug("{}: executeCommand raised: {}".format(GUARDIAN_LAYOUT_SCRIPT, exc))
        entries = []
    for entry in reversed([e for e in entries or [] if isinstance(e, dict)]):
        contents = entry.get("Contents")
        if entry.get("Type") != GUARDIAN_LAYOUT_ERROR_ENTRY_TYPE and isinstance(contents, str) and contents.strip():
            return entry
    return {"Type": 1, "ContentsFormat": "html",
            "Contents": '<div style="opacity:.7;font-size:12px">{}</div>'.format(GUARDIAN_LAYOUT_NOTE)}


def main():
    try:
        demisto.results(guardian_layout_part_entry())
    except Exception as exc:  # a display section must never surface a traceback
        demisto.error("GuardianLayoutAssessmentFindings failed: {}".format(exc))
        demisto.results({"Type": 1, "ContentsFormat": "html",
                         "Contents": '<div style="opacity:.7;font-size:12px">{}</div>'.format(GUARDIAN_LAYOUT_NOTE)})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
