#!/usr/bin/env python3
"""Build-time code-sharing injector for Guardian XSOAR content.

XSOAR 6 automations can't `import` one another, and Guardian deliberately
does NOT hijack the global `CommonServerUserPython` slot (that would affect
every script on the box, including other customers' content). Instead,
`Packs/Guardian/Scripts/GuardianCommon/GuardianCommon.py` is the single
canonical source of the `guardian_*` helper library, and this script copies
its marked block into every other Guardian script at build time.

How it works:

1. Extract the text between the exact marker lines
   `# <GUARDIAN_COMMON>` / `# </GUARDIAN_COMMON>` in GuardianCommon.py
   (markers included, for provenance in the consumer copy).
2. For every `Packs/Guardian/Scripts/<Name>/<Name>.py` (except
   `GuardianCommon` itself) that contains a placeholder region delimited by
   `# <GUARDIAN_COMMON_INJECT>` / `# </GUARDIAN_COMMON_INJECT>`, replace the
   contents of that placeholder with the extracted block.
3. Print which files were changed. Idempotent: re-running against files
   already in sync makes no changes and reports 0 updates. ``--check`` is a
   non-mutating CI mode: it exits nonzero and lists every consumer whose
   injected region differs from the canonical source.

Safety: each marker (START/END in GuardianCommon.py, and each target file's
own INJECT-START/INJECT-END) must appear EXACTLY ONCE in its file. A stray
extra occurrence -- e.g. the marker text quoted inside a comment describing
this mechanism -- would make the plain-string search silently grab the wrong
span and corrupt the shared block for every consumer with no visible error.
This script asserts the count and raises (failing the build) rather than
proceeding on a violation.

Run BEFORE `demisto-sdk upload` — `scripts/deploy.sh` wires this in.

Run ``python3 scripts/inject_common.py --check`` in CI before validation to
ensure a contributor did not update the canonical source without refreshing
its consumers.
"""

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
#: Every pack that carries its own copy of the shared block. Each pack is synchronized from ITS OWN
#: GuardianCommon.py: the XSOAR 6 pack and the XSIAM pack are maintained as two versions
#: (see Packs/GuardianXSIAM/DIVERGENCE.md), so their blocks are allowed to differ.
PACK_NAMES = ("Guardian", "GuardianXSIAM")
GUARDIAN_COMMON_DIR_NAME = "GuardianCommon"


def scripts_dir(pack_name: str) -> pathlib.Path:
    return REPO_ROOT / "Packs" / pack_name / "Scripts"


def common_py(pack_name: str) -> pathlib.Path:
    return scripts_dir(pack_name) / GUARDIAN_COMMON_DIR_NAME / f"{GUARDIAN_COMMON_DIR_NAME}.py"

START_MARKER = "# <GUARDIAN_COMMON>"
END_MARKER = "# </GUARDIAN_COMMON>"
INJECT_START_MARKER = "# <GUARDIAN_COMMON_INJECT>"
INJECT_END_MARKER = "# </GUARDIAN_COMMON_INJECT>"


def _assert_marker_count_one(haystack: str, marker: str, where: pathlib.Path) -> None:
    """Fail loud if `marker` doesn't appear in `haystack` exactly once.

    A stray second occurrence (e.g. the marker text quoted inside a comment
    or docstring describing the mechanism) would make `.index()` silently
    grab the wrong span -- corrupting the shared block for every consuming
    script with no visible error. Zero occurrences is just as bad (nothing
    to extract/inject). Either way this must raise, not proceed.
    """
    count = haystack.count(marker)
    if count != 1:
        raise SystemExit(f"error: {where} must contain exactly one {marker!r} marker, found {count}")


def extract_common_block(source_text: str, where: pathlib.Path) -> str:
    """Return the exact text between START_MARKER and END_MARKER (inclusive)."""
    _assert_marker_count_one(source_text, START_MARKER, where)
    _assert_marker_count_one(source_text, END_MARKER, where)
    start = source_text.index(START_MARKER)
    end = source_text.index(END_MARKER)
    if end < start:
        raise SystemExit(f"error: {GUARDIAN_COMMON_PY} markers are out of order")
    block_end = end + len(END_MARKER)
    return source_text[start:block_end]


def rendered_injection(target_path: pathlib.Path, block: str):
    """Return ``(existing, expected)`` injection text, or ``None`` if absent.

    The helper performs all marker validation without modifying the target,
    allowing ``--check`` to use exactly the same rendering logic as the
    updating mode.
    """
    text = target_path.read_text()
    if INJECT_START_MARKER not in text or INJECT_END_MARKER not in text:
        return None

    _assert_marker_count_one(text, INJECT_START_MARKER, target_path)
    _assert_marker_count_one(text, INJECT_END_MARKER, target_path)

    start = text.index(INJECT_START_MARKER)
    end = text.index(INJECT_END_MARKER)
    if end < start:
        raise SystemExit(f"error: {target_path} has out-of-order inject markers")
    end += len(INJECT_END_MARKER)

    new_region = f"{INJECT_START_MARKER}\n{block}\n{INJECT_END_MARKER}"
    new_text = text[:start] + new_region + text[end:]
    return text, new_text


def inject_into(target_path: pathlib.Path, block: str) -> bool:
    """Replace the INJECT placeholder region in target_path with `block`.

    Returns True if the file's contents changed, False if the file had no
    placeholder region or was already in sync (idempotent no-op).
    """
    rendered = rendered_injection(target_path, block)
    if rendered is None:
        return False
    text, new_text = rendered

    if new_text == text:
        return False

    target_path.write_text(new_text)
    return True


def iter_consumer_targets(pack_name: str):
    """Yield the conventional Python entry point for each Guardian script of one pack."""
    for script_dir in sorted(scripts_dir(pack_name).iterdir()):
        if not script_dir.is_dir() or script_dir.name == GUARDIAN_COMMON_DIR_NAME:
            continue
        target = script_dir / f"{script_dir.name}.py"
        if target.exists():
            yield target


def main(argv=None) -> int:
    """Synchronize consumers, or report drift when invoked with ``--check``."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv not in ([], ["--check"]):
        print("usage: inject_common.py [--check]", file=sys.stderr)
        return 2
    check_only = argv == ["--check"]

    status = 0
    for pack_name in PACK_NAMES:
        if not scripts_dir(pack_name).exists():
            continue
        status = max(status, _sync_pack(pack_name, check_only))
    return status


def _sync_pack(pack_name: str, check_only: bool) -> int:
    common = common_py(pack_name)
    if not common.exists():
        print(f"error: {common} not found", file=sys.stderr)
        return 1

    block = extract_common_block(common.read_text(), common)

    targets = list(iter_consumer_targets(pack_name))
    if check_only:
        drifted = []
        for target in targets:
            rendered = rendered_injection(target, block)
            if rendered is not None and rendered[0] != rendered[1]:
                drifted.append(str(target.relative_to(REPO_ROOT)))

        if drifted:
            print(f"inject_common.py [{pack_name}]: {len(drifted)} file(s) out of sync:")
            for path in drifted:
                print(f"  - {path}")
            return 1
        print(f"inject_common.py [{pack_name}]: {len(targets)} consumer file(s) in sync")
        return 0

    updated = []
    for target in targets:
        if inject_into(target, block):
            updated.append(str(target.relative_to(REPO_ROOT)))

    if updated:
        print(f"inject_common.py [{pack_name}]: updated {len(updated)} file(s):")
        for path in updated:
            print(f"  - {path}")
    else:
        print(f"inject_common.py [{pack_name}]: 0 files updated (nothing to sync)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
