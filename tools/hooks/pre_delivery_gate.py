#!/usr/bin/env python3
"""
Stop hook — the delivery gate, enforced by the harness rather than by an agent's good intentions.

Everything else in this system can be skipped by an agent that decides it already knows the report is
fine. This cannot: the turn does not end while a report touched in this session lacks a valid gate
receipt for the bytes currently on disk. It is the difference between a rule and a habit.

Two things it deliberately does NOT do:
  * It does not judge the report. It asks reports/gate.py whether the chain of custody holds.
  * It does not let a failure be argued away. There is no flag, no env var, no phrasing that turns a
    block into a pass. The only way through is to fix what is missing.

There is one legitimate exit, and it is not a bypass: a draft that is not being delivered. Recording
that with `python tools/hooks/waive.py <ID> --reason "..."` lets the session end, is written to disk
where anyone can read it, and lapses the moment the draft is edited again. It never authorizes a
submission - the PreToolUse hook ignores waivers entirely.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _hookutil import (ROOT, emit, finding_for_report, is_report,  # noqa: E402
                       is_waived, read_payload, touched_reports)


def main() -> int:
    d = read_payload()
    reports = [r for r in touched_reports(d.get("session_id", "")) if is_report(str(ROOT / r))]
    if not reports:
        return 0

    import gate
    problems = []
    for rel in reports:
        f = ROOT / rel
        if not f.exists():                       # renamed or deleted during the session
            continue
        fid = finding_for_report(str(f))
        if not fid:
            problems.append(f"{rel}: no finding id - add it with `hunt ledger add --id <ID> "
                            f"--set report_path={rel}` so the gate can track it")
            continue
        if is_waived(fid, gate.sha256_file(f)):
            continue
        ok, why = gate.verify_receipt(fid)
        if not ok:
            problems.append(f"{fid} ({rel}): {why}")

    if not problems:
        return 0

    lines = "\n".join(f"  - {p}" for p in problems)
    return emit({
        "decision": "block",
        "reason": (
            f"A report was written this session that has not cleared the delivery gate. Do not "
            f"present it, summarize it as finished, or submit it.\n\n{lines}\n\n"
            f"To clear it, for each finding:\n"
            f"  1. `python hunt.py poc-run <target> <ID> --cmd \"<the PoC command>\"` twice, so the "
            f"output in the report is bound to a real execution.\n"
            f"  2. Run the `report-auditor` agent (cold factual audit) and the `report-editor` agent "
            f"(presentation/voice). Both must return PASS on the CURRENT bytes.\n"
            f"  3. `python hunt.py validate-report <ID>` - this issues the receipt.\n"
            f"Fix whatever each one reports rather than working around it.\n\n"
            f"If a report here is an abandoned draft you are NOT delivering, record that with "
            f"`python tools/hooks/waive.py <ID> --reason \"...\"`. A waiver lets the session end; it "
            f"does not permit submission, and it lapses if the draft is edited again."),
    })


if __name__ == "__main__":
    sys.exit(main())
