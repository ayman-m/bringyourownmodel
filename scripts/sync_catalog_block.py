#!/usr/bin/env python3
"""Copy the canonical model-catalogue block into every script that carries it, in both packs.

Canonical source: scripts/guardian_catalog_block.py (the text between its two marker lines, inclusive).
Targets: the four scripts below, in Packs/Guardian and Packs/GuardianXSIAM. In each, the block sits right
after the injected-common region. If the target already holds a block it is replaced; otherwise the block
is inserted. Idempotent. ``--check`` changes nothing and exits 1 if any copy differs.

XSOAR scripts cannot import one another, so the block is duplicated; a parity test in each pack's
GuardianModelProfileCheck test also asserts that all copies are byte-identical.
"""
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CANONICAL = REPO_ROOT / "scripts" / "guardian_catalog_block.py"
PACKS = ("Guardian", "GuardianXSIAM")
SCRIPTS = ("GuardianModelProfileCheck", "GuardianProbeModel", "GuardianModelProfileUpdate", "GuardianModelCommand")
START = "# <GUARDIAN_CATALOG>"
END = "# </GUARDIAN_CATALOG>"
INJECT_END = "# </GUARDIAN_COMMON_INJECT>"


def canonical_block():
    text = CANONICAL.read_text()
    if text.count(START) != 1 or text.count(END) != 1:
        raise SystemExit("error: {} must contain exactly one start and one end marker".format(CANONICAL))
    return text[text.index(START):text.index(END) + len(END)]


def render(target_text, block, where):
    if START in target_text or END in target_text:
        if target_text.count(START) != 1 or target_text.count(END) != 1:
            raise SystemExit("error: {} must contain exactly one start and one end marker".format(where))
        start, end = target_text.index(START), target_text.index(END) + len(END)
        return target_text[:start] + block + target_text[end:]
    if target_text.count(INJECT_END) != 1:
        raise SystemExit("error: {} has no single injected-common end marker".format(where))
    cut = target_text.index(INJECT_END) + len(INJECT_END)
    return target_text[:cut] + "\n\n" + block + "\n" + target_text[cut:]


def main(argv):
    check = "--check" in argv
    block = canonical_block()
    stale = []
    for pack in PACKS:
        for script in SCRIPTS:
            path = REPO_ROOT / "Packs" / pack / "Scripts" / script / (script + ".py")
            text = path.read_text()
            new = render(text, block, path)
            if new != text:
                stale.append(path)
                if not check:
                    path.write_text(new)
    for path in stale:
        print(("STALE " if check else "updated ") + str(path.relative_to(REPO_ROOT)))
    print("sync_catalog_block.py: {} of {} copies {}".format(
        len(stale), len(PACKS) * len(SCRIPTS), "out of date" if check else "updated"))
    return 1 if (check and stale) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
