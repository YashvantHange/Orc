#!/usr/bin/env python3
"""
merge.py — correlate every scanner's output into one de-duplicated lead list.

Reads work/<slug>/scan/*.json (normalized) + *.sarif, and writes:
  * work/<slug>/findings.json    — de-duplicated, with cross-tool agreement annotated
  * work/<slug>/findings.sarif   — combined SARIF (GitHub Code-Scanning compatible)

Cross-tool agreement (two tools flag the same file:line) raises confidence — a strong
signal for which leads to chase first.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "static"))
import _common as C  # noqa: E402


def merge(target: str) -> Path:
    scan = C.scandir(target)
    work = C.workdir(target)

    # ---- normalized json findings from every tool ----
    findings: list[dict] = []
    for jf in sorted(scan.glob("*.json")):
        try:
            findings += json.loads(jf.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

    # de-dup exact (tool, file, line, rule_id); track tool agreement per (file, line)
    seen: set[tuple] = set()
    by_loc: dict[tuple, set] = defaultdict(set)
    uniq: list[dict] = []
    for f in findings:
        loc = (os.path.normpath(f.get("file", "")).lower(), f.get("line", 0))
        by_loc[loc].add(f.get("tool", ""))
        key = (f.get("tool"), *loc, f.get("rule_id"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)

    # annotate agreement + a stable finding id
    for i, f in enumerate(uniq):
        loc = (os.path.normpath(f.get("file", "")).lower(), f.get("line", 0))
        tools = sorted(t for t in by_loc[loc] if t)
        f["agreed_by"] = tools
        f["cross_tool_agreement"] = len(tools) > 1
        f["finding_id"] = f"F{i+1:03d}"
        f.setdefault("status", "NEW")

    out_json = work / "findings.json"
    out_json.write_text(json.dumps(uniq, indent=2), encoding="utf-8")

    # ---- combined SARIF ----
    combined = {"version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []}
    for sf in sorted(scan.glob("*.sarif")):
        try:
            doc = json.loads(sf.read_text(encoding="utf-8"))
            combined["runs"] += doc.get("runs", [])
        except (json.JSONDecodeError, OSError):
            continue
    (work / "findings.sarif").write_text(json.dumps(combined), encoding="utf-8")

    agree = sum(1 for f in uniq if f["cross_tool_agreement"])
    by_tool: dict[str, int] = defaultdict(int)
    for f in uniq:
        by_tool[f.get("tool", "?")] += 1
    print(f"merged {len(uniq)} unique findings -> {out_json}")
    print(f"  by tool: {dict(by_tool)}")
    print(f"  cross-tool agreement: {agree} findings")
    print(f"  next: python correlate/exploit_score.py {target}")
    return out_json


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    args = ap.parse_args()
    merge(args.target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
