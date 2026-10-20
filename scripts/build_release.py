#!/usr/bin/env python3
"""Build the two customer release packages for Guardian into release/ and verify them.

There is one package per platform, released separately; a customer downloads only the one for their platform, unzips it and follows its README.md:

  Guardian-XSOAR-v<ver>.zip   (Cortex XSOAR 6)          Guardian-Cortex-Platform-v<ver>.zip   (Cortex platform)
    Guardian-<EDITION>-v<ver>/
      README.md                 the install guide for this platform (start here)
      pack/<Pack>-<ver>.zip     the pack, ready to install (unified YAML inside)
      tools/                    install_pack.py, create_jobs.py, the job definitions (and, on the Cortex platform, adopt_playbooks.py and the playbooks)
      integrations/             the Foundry model integration alone, one unified YAML
      docs/                     model setup, the operator runbook, the capabilities guide, the model contract, an overview
      SHA256SUMS                checksums of every file in the package

Every integration and automation inside the pack zips is a single unified YAML file (code, image and description embedded);
there are no separate .py files to build. The repository keeps the split source layout that demisto-sdk expects, and this script
makes the unified form with `demisto-sdk zip-packs`.

The build FAILS when a check fails: a loose .py or image file inside Integrations/ or Scripts/, an empty script, an item
count that does not match the source folder, an item tagged for the wrong marketplace, or text that matches a forbidden
pattern (tenant hostnames, home-folder paths, key-looking strings, and every regular expression listed one per line in
scripts/release_forbidden.local.txt, a local file that is not committed: put customer names there).

Usage: python3 scripts/build_release.py [--out release] [--edition xsoar|platform|all] [--skip-inject]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
#: pack folder name -> marketplace tag every item in it must carry
PACKS = {"Guardian": "xsoar", "GuardianXSIAM": "marketplacev2"}
#: edition key -> (pack folder, display name used in the package name, install guide, runbook shipped with it)
EDITIONS = {
    "xsoar": {"pack": "Guardian", "label": "XSOAR", "guide": "xsoar/README.md", "manual": "xsoar/MANUAL_UPLOAD.md", "runbook": "OPERATOR_RUNBOOK.md", "zip": "Guardian"},
    "platform": {"pack": "GuardianXSIAM", "label": "Cortex-Platform", "guide": "cortex-platform/README.md", "manual": "cortex-platform/MANUAL_UPLOAD.md", "runbook": "CORTEX_PLATFORM_RUNBOOK.md", "zip": "GuardianCortexPlatform"},
}
#: patterns that must never appear in a release file
GENERIC_FORBIDDEN = [
    r"\.xdr\.[a-z]{2,4}\.paloaltonetworks\.com",
    r"api-[a-z0-9-]+\.xdr\.",
    r"(?i)\bsshpass\b",
    r"/Users/[A-Za-z0-9._-]+/",
    r"(?i)\b(?:api[_-]?key|secret|password)\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{16,}['\"]",
]
LOCAL_FORBIDDEN_FILE = ROOT / "scripts" / "release_forbidden.local.txt"
EMAIL_ALLOW: set[str] = set()
TEXT_SUFFIXES = {".yml", ".yaml", ".json", ".md", ".txt", ".py", ".ps1"}


def fail(message: str) -> None:
    print(f"\nBUILD FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def sdk_command() -> list[str]:
    venv = ROOT / ".venv" / "bin" / "demisto-sdk"
    return [str(venv)] if venv.exists() else ["demisto-sdk"]


def pack_version(pack: str) -> str:
    return json.loads((ROOT / "Packs" / pack / "pack_metadata.json").read_text())["currentVersion"]


def forbidden_patterns() -> list[re.Pattern]:
    patterns = list(GENERIC_FORBIDDEN)
    if LOCAL_FORBIDDEN_FILE.exists():
        patterns += [ln.strip() for ln in LOCAL_FORBIDDEN_FILE.read_text().splitlines() if ln.strip() and not ln.startswith("#")]
    else:
        print("note: scripts/release_forbidden.local.txt not found; only the generic checks run (add customer names there)")
    return [re.compile(p) for p in patterns]


def scan_text(label: str, text: str, patterns: list[re.Pattern]) -> list[str]:
    hits = []
    for pattern in patterns:
        for match in pattern.finditer(text):
            if match.group(0) in EMAIL_ALLOW:
                continue
            hits.append(f"{label}: matches /{pattern.pattern[:40]}/ at '{match.group(0)[:50]}'")
            break
    return hits


def expected_counts(pack: str) -> dict[str, int]:
    src = ROOT / "Packs" / pack
    return {
        "Integrations": len([d for d in (src / "Integrations").iterdir() if d.is_dir()]),
        "Scripts": len([d for d in (src / "Scripts").iterdir() if d.is_dir()]),
        "Playbooks": len(list((src / "Playbooks").glob("playbook-*.yml"))),
        "Lists": len(list((src / "Lists").glob("list-*.json"))),
        "Jobs": len(list((src / "Jobs").glob("job-*.json"))),
    }


def verify_zip(pack: str, marketplace: str, zip_path: Path, patterns: list[re.Pattern]) -> None:
    zf = zipfile.ZipFile(zip_path)
    names = zf.namelist()
    problems: list[str] = []
    # 1. unified: no loose code, image or description files under Integrations/ or Scripts/
    for n in names:
        if n.startswith(("Integrations/", "Scripts/")) and not n.endswith("/"):
            if not n.endswith(".yml"):
                problems.append(f"{n}: not a unified YAML (only .yml allowed under Integrations/ and Scripts/)")
    # 2. every integration and script has code embedded
    for n in names:
        if n.startswith("Integrations/") and n.endswith(".yml"):
            body = yaml.safe_load(zf.read(n))
            if not (body.get("script") or {}).get("script", "").strip() or (body["script"]["script"].strip() == "-"):
                problems.append(f"{n}: integration has no embedded script")
            if not body.get("image"):
                problems.append(f"{n}: integration has no embedded image")
        if n.startswith("Scripts/") and n.endswith(".yml"):
            body = yaml.safe_load(zf.read(n))
            if not isinstance(body.get("script"), str) or body["script"].strip() in ("", "-"):
                problems.append(f"{n}: script has no embedded code")
    # 3. counts match the source folders
    want = expected_counts(pack)
    got = {
        "Integrations": len([n for n in names if n.startswith("Integrations/") and n.endswith(".yml")]),
        "Scripts": len([n for n in names if n.startswith("Scripts/") and n.endswith(".yml")]),
        "Playbooks": len([n for n in names if n.startswith("Playbooks/") and n.endswith(".yml")]),
        "Lists": len([n for n in names if n.startswith("Lists/") and n.endswith(".json")]),
        "Jobs": len([n for n in names if n.startswith("Jobs/") and n.endswith(".json")]),
    }
    for kind, count in want.items():
        if got[kind] != count:
            problems.append(f"{kind}: source has {count}, zip has {got[kind]}")
    # 4. marketplace tags
    for n in names:
        if n.endswith((".yml", ".json")) and n.split("/")[0] in {"Integrations", "Scripts", "Playbooks", "Lists", "Jobs", "Layouts", "IncidentFields", "IncidentTypes"}:
            raw = zf.read(n)
            body = yaml.safe_load(raw)
            tags = body.get("marketplaces") if isinstance(body, dict) else None
            if tags is not None and marketplace not in tags:
                problems.append(f"{n}: marketplaces {tags} does not include {marketplace}")
    # 5. forbidden text
    for n in names:
        if Path(n).suffix in TEXT_SUFFIXES:
            problems += scan_text(n, zf.read(n).decode("utf-8", errors="replace"), patterns)
    if problems:
        fail(f"{zip_path.name} failed verification:\n  - " + "\n  - ".join(problems[:40]))
    print(f"  verified {zip_path.name}: {got['Integrations']} integrations, {got['Scripts']} automations, {got['Playbooks']} playbooks, "
          f"{got['Lists']} lists, {got['Jobs']} jobs; all unified; no forbidden text")


COMMON_DOCS = ["GUARDIAN_GUIDE.md", "GUARDIAN_LLM_CHAT_CONTRACT.md", "MODEL_SETUP.md", "CONTENT_REFERENCE.md"]


def stage_package(stage: Path, edition: str, pack_zip: Path, patterns: list[re.Pattern]) -> None:
    """Lay out one edition's customer package under `stage`."""
    ed = EDITIONS[edition]
    pack = ed["pack"]
    (stage / "pack").mkdir(parents=True)
    shutil.copyfile(pack_zip, stage / "pack" / f"{ed['zip']}-{pack_version(pack)}.zip")
    tools = stage / "tools"
    tools.mkdir()
    for src, dst in (("install_pack.py", "install_pack.py"), ("deploy_jobs.py", "create_jobs.py")):
        shutil.copyfile(ROOT / "scripts" / src, tools / dst)
    (tools / "jobs").mkdir(parents=True)
    for job in sorted((ROOT / "Packs" / pack / "Jobs").glob("job-*.json")):
        shutil.copyfile(job, tools / "jobs" / job.name)
    zf = zipfile.ZipFile(pack_zip)
    if edition == "platform":
        shutil.copyfile(ROOT / "scripts" / "adopt_playbooks.py", tools / "adopt_playbooks.py")
        (tools / "playbooks").mkdir()
        for n in zf.namelist():
            if n.startswith("Playbooks/") and n.endswith(".yml"):
                (tools / "playbooks" / Path(n).name).write_bytes(zf.read(n))
    (stage / "integrations").mkdir()
    (stage / "integrations" / f"integration-GuardianFoundry-{ed['label']}.yml").write_bytes(zf.read("Integrations/integration-GuardianFoundry.yml"))
    (stage / "docs").mkdir()
    for name in COMMON_DOCS + [ed["runbook"]]:
        shutil.copyfile(ROOT / "docs" / name, stage / "docs" / name)
    shutil.copyfile(ROOT / "README.md", stage / "docs" / "OVERVIEW.md")
    # the install guide sits at the package root, so its links (relative to docs/xsoar or docs/xsiam in the repository) are re-pointed
    guide = (ROOT / "docs" / ed["guide"]).read_text().replace("](../", "](docs/")
    (stage / "README.md").write_text(guide)
    # links that only work inside the repository (the other edition's guide, files outside docs/) become plain text
    for md in stage.rglob("*.md"):
        text = md.read_text()

        def _drop_dead(match: re.Match) -> str:
            target = match.group(2).split("#")[0]
            if not target or target.startswith(("http://", "https://", "mailto:")) or (md.parent / target).exists():
                return match.group(0)
            return match.group(1)

        md.write_text(re.sub(r"\[([^\]]+)\]\(([^)]*)\)", _drop_dead, text))
    problems = []
    for f in stage.rglob("*"):
        if f.is_file() and f.suffix in TEXT_SUFFIXES:
            problems += scan_text(str(f.relative_to(stage)), f.read_text(errors="replace"), patterns)
    if problems:
        fail("package files failed the forbidden-text check:\n  - " + "\n  - ".join(problems[:30]))
    lines = [f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(stage)}" for f in sorted(stage.rglob("*")) if f.is_file()]
    (stage / "SHA256SUMS").write_text("\n".join(lines) + "\n")


#: content types the console imports one file at a time; a Cortex platform tenant does not install widgets or dashboards
MANUAL_SKIP = {"platform": {"Widgets", "Dashboards"}, "xsoar": set()}


def stage_manual_package(stage: Path, edition: str, pack_zip: Path, patterns: list[re.Pattern]) -> None:
    """Lay out the file-by-file package: every item in the form the console's one-at-a-time upload expects.

    The console takes the file name as an item's name and the file text as its content. That is correct for unified
    integrations, automations and playbooks, but a pack's list file wraps the data (id, name, type, data), so each list
    is written here as a file that holds only its data, named exactly as the list must be named.
    """
    ed = EDITIONS[edition]
    stage.mkdir(parents=True)
    zf = zipfile.ZipFile(pack_zip)
    lists = []
    for n in sorted(zf.namelist()):
        parts = Path(n).parts
        if n.endswith("/") or parts[0] in ("metadata.json", "pack_metadata.json", "README.md", "ReleaseNotes", "Author_image.png", "DIVERGENCE.md"):
            continue
        if parts[0] in MANUAL_SKIP[edition] or parts[0] == "Jobs" or not n.endswith((".yml", ".json")):
            continue
        if parts[0] == "Lists":
            item = json.loads(zf.read(n))
            ext = "md" if item["type"] == "markdown" else "json"
            if item["name"].startswith("list-") or item["name"] != Path(n).stem.removeprefix("list-"):
                fail(f"list file {n} has an unexpected name {item['name']!r}")
            (stage / "Lists").mkdir(exist_ok=True)
            (stage / "Lists" / f"{item['name']}.{ext}").write_text(item["data"])
            lists.append(item["name"])
            continue
        dest = stage / n
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(zf.read(n))
    guide = (ROOT / "docs" / ed["manual"]).read_text()
    missing = [name for name in lists if f"`{name}`" not in guide]
    if missing or not lists:
        fail(f"{ed['manual']} does not describe these lists: {missing}")
    (stage / "README.md").write_text(guide.replace("](../", "](docs/"))
    shutil.copyfile(ROOT / "docs" / "MODEL_SETUP.md", stage / "MODEL_SETUP.md")
    for md in stage.rglob("*.md"):
        text = md.read_text()

        def _drop_dead(match: re.Match) -> str:
            target = match.group(2).split("#")[0]
            if not target or target.startswith(("http://", "https://", "mailto:")) or (md.parent / target).exists():
                return match.group(0)
            return match.group(1)

        md.write_text(re.sub(r"\[([^\]]+)\]\(([^)]*)\)", _drop_dead, text))
    problems = []
    for f in stage.rglob("*"):
        if f.is_file() and f.suffix in TEXT_SUFFIXES:
            problems += scan_text(str(f.relative_to(stage)), f.read_text(errors="replace"), patterns)
    if problems:
        fail("manual package files failed the forbidden-text check:\n  - " + "\n  - ".join(problems[:30]))
    lines = [f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(stage)}" for f in sorted(stage.rglob("*")) if f.is_file()]
    (stage / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def add_missing_xsiam_items(pack: str, pack_zip: Path) -> None:
    """demisto-sdk's pack zip leaves out XSIAMDashboards; add them from the pack folder so both packages carry them."""
    folder = ROOT / "Packs" / pack / "XSIAMDashboards"
    if not folder.is_dir():
        return
    with zipfile.ZipFile(pack_zip, "a", zipfile.ZIP_DEFLATED) as zf:
        present = set(zf.namelist())
        for f in sorted(folder.glob("*.json")):
            name = f"XSIAMDashboards/{f.name}"
            if name not in present:
                zf.write(f, name)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default="release", help="output folder (default: release)")
    parser.add_argument("--edition", choices=["xsoar", "platform", "all"], default="all")
    parser.add_argument("--skip-inject", action="store_true", help="do not run scripts/inject_common.py first")
    args = parser.parse_args()
    out = (ROOT / args.out).resolve()
    patterns = forbidden_patterns()
    editions = list(EDITIONS) if args.edition == "all" else [args.edition]

    if not args.skip_inject:
        subprocess.run([sys.executable, str(ROOT / "scripts" / "inject_common.py")], cwd=ROOT, check=True)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    packages = []
    with tempfile.TemporaryDirectory() as tmp:
        for edition in editions:
            pack, marketplace = EDITIONS[edition]["pack"], PACKS[EDITIONS[edition]["pack"]]
            version = pack_version(pack)
            print(f"\n{pack} {version} ({marketplace})")
            work = Path(tmp) / edition
            work.mkdir()
            result = subprocess.run(sdk_command() + ["zip-packs", "-i", f"Packs/{pack}", "-o", str(work)], cwd=ROOT, capture_output=True, text=True)
            built = work / "uploadable_packs" / f"{pack}.zip"
            if result.returncode != 0 or not built.exists():
                fail(f"demisto-sdk zip-packs failed for {pack}:\n{result.stdout[-1500:]}\n{result.stderr[-1500:]}")
            pack_zip = work / f"{pack}-{version}.zip"
            shutil.copyfile(built, pack_zip)
            add_missing_xsiam_items(pack, pack_zip)
            verify_zip(pack, marketplace, pack_zip, patterns)

            name = f"Guardian-{EDITIONS[edition]['label']}-v{version}"
            stage = work / name
            stage_package(stage, edition, pack_zip, patterns)
            bundle = out / f"{name}.zip"
            with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as zout:
                for f in sorted(stage.rglob("*")):
                    if f.is_file():
                        zout.write(f, f"{name}/{f.relative_to(stage)}")
            digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
            (out / f"{bundle.name}.sha256").write_text(f"{digest}  {bundle.name}\n")
            packages.append((bundle, digest))

            manual_name = f"Guardian-{EDITIONS[edition]['label']}-Manual-Upload-v{version}"
            manual_stage = work / manual_name
            stage_manual_package(manual_stage, edition, pack_zip, patterns)
            manual_bundle = out / f"{manual_name}.zip"
            with zipfile.ZipFile(manual_bundle, "w", zipfile.ZIP_DEFLATED) as zout:
                for f in sorted(manual_stage.rglob("*")):
                    if f.is_file():
                        zout.write(f, f"{manual_name}/{f.relative_to(manual_stage)}")
            manual_digest = hashlib.sha256(manual_bundle.read_bytes()).hexdigest()
            (out / f"{manual_bundle.name}.sha256").write_text(f"{manual_digest}  {manual_bundle.name}\n")
            packages.append((manual_bundle, manual_digest))

    for bundle, digest in packages:
        print(f"\nRelease package: {bundle.relative_to(ROOT)} ({bundle.stat().st_size / 1024:.0f} KB)")
        for n in zipfile.ZipFile(bundle).namelist():
            print("  ", n)
        print(f"sha256 {digest}")


if __name__ == "__main__":
    main()
