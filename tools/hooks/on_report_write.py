#!/usr/bin/env python3
"""
PostToolUse hook (Write|Edit) — notice when a report changes under a gate that already passed.

Deliberately quiet. Drafting a report means writing it many times, and a hook that shouted on every
keystroke would train everyone to ignore it. So this stays silent during normal drafting and speaks up
for exactly one thing: the report just changed after it had been audited or gated, which means the
audits now describe bytes that no longer exist. That is the moment a stale approval could sneak
through, and it is worth interrupting for.

It also records which reports this session touched, so the Stop hook knows what to check.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _hookutil import (emit, finding_for_report, is_report,  # noqa: E402
                       read_payload, touch_report)


def main() -> int:
    d = read_payload()
    path = ((d.get("tool_response") or {}).get("filePath")
            or (d.get("tool_input") or {}).get("file_path") or "")
    if not is_report(path):
        return 0

    touch_report(d.get("session_id", ""), path)

    import gate
    fid = finding_for_report(path)
    if not fid:
        return 0

    live = gate.sha256_file(Path(path).resolve())
    stale = []
    for which, agent in (("factual", "report-auditor"), ("editorial", "report-editor")):
        ap = gate.audit_path(fid, which)
        if not ap.exists():
            continue
        try:
            bound = json.loads(ap.read_text(encoding="utf-8")).get("report_sha256", "")
        except json.JSONDecodeError:
            continue
        if bound and bound != live:
            stale.append(f"{which} audit (re-run `{agent}`)")

    receipt_dead = gate.receipt_path(fid).exists() and not gate.verify_receipt(fid)[0]
    if not stale and not receipt_dead:
        return 0

    parts = []
    if stale:
        parts.append("stale: " + ", ".join(stale))
    if receipt_dead:
        parts.append("the gate receipt is void")
    return emit({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": (
                f"{fid}: this report was edited after it was reviewed - {'; '.join(parts)}. "
                f"The audits are bound to the report's exact bytes, so they no longer apply. "
                f"Re-run report-auditor and report-editor on the current draft, then "
                f"`python hunt.py validate-report {fid}`, before this report is delivered or "
                f"submitted."),
        }
    })


if __name__ == "__main__":
    sys.exit(main())
