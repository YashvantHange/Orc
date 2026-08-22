#!/usr/bin/env python3
"""
verify_patch.py — confirm a maintainer's fix actually resolves the finding (and hunt bypasses).

Given a target clone and a fixed commit/ref, checks out the fix, re-runs the static scan and
(optionally) re-runs the PoC, and reports whether the finding is gone. Also the entry point for
PATCH-BYPASS hunting: if the PoC still works on the "fixed" commit, you have a fresh 0-day.

  python reports/verify_patch.py <src-dir> --fixed <commit-or-tag> [--poc "<command>"]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "static"))
import _common as C  # noqa: E402


def _git(src: Path, *args: str) -> tuple[int, str]:
    p = subprocess.run(["git", "-C", str(src), *args], capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def verify(src: str, fixed: str, poc: str | None) -> int:
    srcp = Path(src)
    if not (srcp / ".git").exists():
        print(f"  {src} is not a git clone — cannot checkout {fixed}")
        return 2
    code, before = _git(srcp, "rev-parse", "HEAD")
    print(f"current HEAD: {before}")
    code, msg = _git(srcp, "fetch", "--depth", "50", "origin", fixed)
    code, msg = _git(srcp, "checkout", fixed)
    if code != 0:
        print(f"  checkout failed: {msg}"); return 2
    code, now = _git(srcp, "rev-parse", "HEAD")
    print(f"checked out fixed ref {fixed} -> {now}")

    print("\n-- re-running static scan on the fixed tree --")
    from run_all import detect_lang
    from run_semgrep import run_semgrep
    from run_bandit import run_bandit
    lang = detect_lang(src)
    findings = C.load_sarif(run_semgrep(src, lang, local_only=True), "semgrep")
    if lang in ("python", "auto"):
        findings += C.load_sarif(run_bandit(src), "bandit")
    print(f"  static findings after fix: {len(findings)}")

    if poc:
        print("\n-- re-run your PoC now against the fixed tree --")
        print(f"  {poc}")
        print("  If it STILL succeeds -> the fix is incomplete (patch-bypass = fresh finding).")
        print("  If it now fails (401/403/sanitized/no exec) -> fix confirmed.")

    print(f"\n(restore your working state with: git -C {src} checkout {before})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("src")
    ap.add_argument("--fixed", required=True, help="commit SHA / tag / branch of the fix")
    ap.add_argument("--poc", help="the PoC command to re-run manually")
    args = ap.parse_args()
    return verify(args.src, args.fixed, args.poc)


if __name__ == "__main__":
    sys.exit(main())
