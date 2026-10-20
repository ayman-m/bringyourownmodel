#!/usr/bin/env python3
"""Prove that edits to Python files changed only comments and docstrings.

Parses every non-test .py file of a pack in the working tree and in a baseline copy, removes the docstrings from both syntax trees,
and requires the trees to be identical. Any change to code, string literals (other than docstrings), names or structure is reported.

Usage: python3 scripts/check_code_unchanged.py --baseline <dir> --pack <PackName> [path-prefix ...]
  <dir> holds a copy of the pack's files laid out as <dir>/<PackName>/Scripts/<Name>/<Name>.py (make one with `cp -R Packs/<PackName> <dir>/`).
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _strip_docstrings(tree: ast.AST) -> ast.AST:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                node.body = body[1:] or [ast.Pass()]
    return tree


def fingerprint(path: Path) -> str:
    return ast.dump(_strip_docstrings(ast.parse(path.read_text(encoding="utf-8"))), include_attributes=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--pack", required=True)
    parser.add_argument("prefixes", nargs="*", help="only files whose path (relative to the pack) starts with one of these")
    args = parser.parse_args()
    base_root = Path(args.baseline) / args.pack
    pack_root = ROOT / "Packs" / args.pack
    bad, checked = [], 0
    for path in sorted(pack_root.rglob("*.py")):
        rel = path.relative_to(pack_root)
        if path.name.endswith("_test.py") or "__pycache__" in rel.parts:
            continue
        if args.prefixes and not any(str(rel).startswith(p) for p in args.prefixes):
            continue
        old = base_root / rel
        if not old.exists():
            bad.append(f"{rel}: not in the baseline")
            continue
        checked += 1
        try:
            same = fingerprint(old) == fingerprint(path)
        except SyntaxError as exc:
            bad.append(f"{rel}: syntax error: {exc}")
            continue
        if not same:
            bad.append(f"{rel}: code differs from the baseline (more than comments and docstrings changed)")
    for line in bad:
        print("FAIL ", line)
    print(f"{checked} file(s) checked, {len(bad)} problem(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
