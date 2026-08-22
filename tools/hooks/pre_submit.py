#!/usr/bin/env python3
"""
PreToolUse hook (Bash) — refuse to send an ungated report anywhere.

The Stop hook stops an ungated report being *presented*. This stops it being *transmitted*, which is
the one that cannot be taken back: a GHSA draft, a huntr submission, a push of a report file. A
maintainer's time and your reporter reputation are both spent the moment it leaves the machine.

Waivers are ignored here on purpose. A waiver means "this draft is not being delivered"; using one to
justify a submission would be exactly the bypass the gate exists to prevent.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _hookutil import ROOT, emit, finding_for_report, read_payload  # noqa: E402

# Commands that put a report in front of somebody else.
SUBMIT = re.compile(
    r"(gh\s+(?:api[^\n|;]*security[-_]advisor|security-advisory\b)"
    r"|gh\s+issue\s+create|gh\s+pr\s+create"
    r"|curl[^\n|;]*(?:huntr\.(?:dev|com)|hackerone\.com|bugcrowd\.com|/security/advisories)"
    r"|git\s+push)", re.IGNORECASE)

REPORT_REF = re.compile(r"reports[/\\]([A-Za-z0-9._-]+\.md)")


def deny(reason: str) -> int:
    return emit({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                        "permissionDecision": "deny",
                                        "permissionDecisionReason": reason}})


def main() -> int:
    d = read_payload()
    cmd = (d.get("tool_input") or {}).get("command", "")
    if not cmd or not SUBMIT.search(cmd):
        return 0

    named = [m.group(0) for m in REPORT_REF.finditer(cmd)]
    if not named:
        # A submission-shaped command that names no report: let it through rather than blocking
        # every `git push` in the repo. The Stop hook still covers the reports themselves.
        return 0

    import gate
    for rel in named:
        f = (ROOT / rel).resolve()
        if not f.exists() or f.name == "TEMPLATE.md":
            continue
        fid = finding_for_report(str(f))
        if not fid:
            return deny(f"{rel} has no finding id in the ledger, so its delivery gate was never "
                        f"run. Add it (`hunt ledger add`) and gate it before sending it anywhere.")
        ok, why = gate.verify_receipt(fid)
        if not ok:
            return deny(
                f"Refusing to submit {rel}: {why}\n"
                f"This report has not cleared the delivery gate, so nothing has verified that its "
                f"PoC ran, that its file:line citations resolve, or that a cold auditor read it. "
                f"Run report-auditor and report-editor, then `python hunt.py validate-report {fid}`. "
                f"A gate waiver does not authorize submission.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
