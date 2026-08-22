#!/usr/bin/env python3
"""
waive.py — record that a report is a draft you are NOT delivering.

This exists so the delivery gate cannot deadlock a session over an abandoned draft. It is not a way
to ship an ungated report, and it is built so it cannot become one:

  * it never authorizes a submission - tools/hooks/pre_submit.py ignores waivers entirely;
  * it is bound to the draft's exact bytes, so editing the draft lapses it;
  * it requires a written reason and lands in state/gate/ where anyone can read it later.

The honest framing: a waiver says "this is unfinished", not "this is fine".

  python tools/hooks/waive.py F018 --reason "parked: cannot reproduce on 3.15.1, revisiting Monday"
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _hookutil import ROOT, waiver_path  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("finding_id")
    ap.add_argument("--reason", required=True, help="why this draft is not being delivered")
    ap.add_argument("--clear", action="store_true", help="remove an existing waiver")
    a = ap.parse_args()

    import gate
    p = waiver_path(a.finding_id)
    if a.clear:
        if p.exists():
            p.unlink()
            print(f"waiver cleared for {a.finding_id}")
        return 0

    if len(a.reason.strip()) < 10:
        print("error: give a real reason - this is recorded and read later", file=sys.stderr)
        return 2

    rec = next((f for f in json.loads(
        (ROOT / "state" / "ledger.json").read_text(encoding="utf-8")).get("findings", [])
        if f.get("finding_id") == a.finding_id), {})
    rp = rec.get("report_path", "")
    f = ROOT / rp if rp else None
    if not (f and f.exists()):
        print(f"error: no report on disk for {a.finding_id} (ledger report_path={rp!r})",
              file=sys.stderr)
        return 2

    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({
        "finding_id": a.finding_id,
        "report_path": rp,
        "report_sha256": gate.sha256_file(f),
        "reason": a.reason.strip(),
        "waived_at": gate._now(),
        "note": "NOT DELIVERABLE. This records an unfinished draft so the session can end. "
                "It does not authorize submission and lapses if the draft changes.",
    }, indent=2), encoding="utf-8")
    print(f"waived {a.finding_id} as an undelivered draft -> {p.relative_to(ROOT)}")
    print("  This does not permit submission. Clear it with --clear when you resume.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
