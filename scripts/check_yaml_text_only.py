#!/usr/bin/env python3
"""Prove that edits to content YAML files changed only descriptive text.

Loads each YAML file of a pack and its baseline copy, removes the descriptive keys (`comment`, `description`, `additionalinfo`,
`detaileddescription`) everywhere, and requires everything else to be identical. Also requires that the file still parses.

Usage: python3 scripts/check_yaml_text_only.py --baseline <dir> --pack <PackName> [path-prefix ...]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TEXT_KEYS = {"comment", "description", "additionalinfo", "detaileddescription"}


def strip(obj):
    if isinstance(obj, dict):
        return {k: strip(v) for k, v in obj.items() if k not in TEXT_KEYS}
    if isinstance(obj, list):
        return [strip(v) for v in obj]
    return obj


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--pack", required=True)
    parser.add_argument("prefixes", nargs="*")
    args = parser.parse_args()
    base_root, pack_root = Path(args.baseline) / args.pack, ROOT / "Packs" / args.pack
    bad, checked = [], 0
    for path in sorted(pack_root.rglob("*.yml")):
        rel = path.relative_to(pack_root)
        if args.prefixes and not any(str(rel).startswith(p) for p in args.prefixes):
            continue
        old = base_root / rel
        if not old.exists():
            bad.append(f"{rel}: not in the baseline")
            continue
        checked += 1
        try:
            same = strip(yaml.safe_load(old.read_text())) == strip(yaml.safe_load(path.read_text()))
        except yaml.YAMLError as exc:
            bad.append(f"{rel}: does not parse: {exc}")
            continue
        if not same:
            bad.append(f"{rel}: something other than descriptive text changed")
    for line in bad:
        print("FAIL ", line)
    print(f"{checked} file(s) checked, {len(bad)} problem(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
