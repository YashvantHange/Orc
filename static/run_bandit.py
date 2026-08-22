#!/usr/bin/env python3
"""
run_bandit.py — Python-only SAST (bandit) -> SARIF + normalized JSON.

  python static/run_bandit.py <target>
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402


def run_bandit(target: str) -> Path:
    tool = C.find_tool("bandit")
    out = C.scandir(target) / "bandit.sarif"
    if not tool:
        print("  bandit not found"); out.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8"); return out
    excludes = ",".join(f"*/{d}/*" for d in C.EXCLUDE_DIRS)
    cmd = [tool, "-r", str(target), "-x", excludes, "-f", "sarif", "-o", str(out), "-q"]
    print(f"  bandit -> {out.name}")
    C.run(cmd, timeout=900)
    if not out.exists():
        out.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
    findings = C.load_sarif(out, "bandit")
    C.write_json(C.scandir(target) / "bandit.json", findings)
    print(f"  bandit: {len(findings)} findings")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    args = ap.parse_args()
    run_bandit(args.target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
