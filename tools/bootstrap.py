#!/usr/bin/env python3
"""
bootstrap.py - make a fresh clone runnable.

Creates the runtime directories that are intentionally not tracked in git (they hold research
output, not pipeline code), and seeds the investigation ledger from its example. Idempotent:
existing files are never overwritten.

Usage:
  python tools/bootstrap.py
  python tools/bootstrap.py --check    # report state, change nothing
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DIRS = [
    "work",                 # cloned targets, scan DBs, per-target profiles
    "reports",              # disclosure drafts (machinery is tracked, output is not)
    "evidence",             # per-finding evidence bundles
    "state",                # ledger + gate receipts
    "state/audit",          # report-auditor / report-editor verdicts
    "state/dup",            # duplicate-check results
    "state/gate",           # delivery-gate receipts
    "state/session",        # per-session run state
    "targets",              # candidate list (tracked) + clones (not)
    "tools/bin",            # binaries from install_tools.py
]

SEEDS = [
    ("state/ledger.example.json", "state/ledger.json"),
]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bootstrap")
    ap.add_argument("--check", action="store_true", help="report only, change nothing")
    a = ap.parse_args(argv)

    missing = 0
    for rel in DIRS:
        p = ROOT / rel
        if p.is_dir():
            print(f"  ok      {rel}/")
            continue
        missing += 1
        if a.check:
            print(f"  MISSING {rel}/")
        else:
            p.mkdir(parents=True, exist_ok=True)
            print(f"  created {rel}/")

    for src_rel, dst_rel in SEEDS:
        src, dst = ROOT / src_rel, ROOT / dst_rel
        if dst.exists():
            print(f"  ok      {dst_rel} (kept - not overwritten)")
            continue
        if not src.exists():
            print(f"  !! seed missing: {src_rel}", file=sys.stderr)
            missing += 1
            continue
        missing += 1
        if a.check:
            print(f"  MISSING {dst_rel}")
        else:
            shutil.copyfile(src, dst)
            print(f"  seeded  {dst_rel} <- {src_rel}")

    if a.check:
        print(f"\n{missing} item(s) missing." if missing else "\nready.")
        return 1 if missing else 0

    print("\nbootstrap complete. Next:")
    print("  python tools/install_tools.py --with-codeql")
    print("  python tools/install_tools.py --check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
