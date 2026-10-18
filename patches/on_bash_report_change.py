#!/usr/bin/env python3
"""
PostToolUse hook (Bash) — close the blind spot that let a changed report reach the end of a session
without the gate ever looking at it.

`on_report_write.py` is what records "this session touched that report", and it is matched on
Write|Edit. A report rewritten with `sed -i`, a heredoc, or a python one-liner through Bash was
therefore never recorded, and the Stop gate — which only checks what the session recorded — never
checked it. That is not hypothetical: on 2026-09-22 a HOW-TO-FILE.md was rewritten through a python
heredoc in the same session that a sibling report went through the Write tool. The gate blocked on the
sibling and said nothing about the file whose waiver had just lapsed. Auto mode prefers Bash for file
edits, which makes the invisible path the default one.

This hook makes the check depend on the bytes on disk rather than on which tool wrote them. It keeps a
manifest of every report's sha256 and, after each Bash call, records as touched any report whose bytes
differ from what the manifest last saw, plus any report that has newly appeared. Those land in the
session's touched list and the Stop gate treats them exactly as it treats a Write.

It never blocks. The Stop gate is the only thing that blocks, and this hook's whole job is to make
sure the gate is given the chance to.

Two deliberate restraints:

  * The first run on a repository seeds the manifest and flags nothing. Drift needs a baseline to
    mean anything, and a hook whose first act is to block on a hundred files nobody touched this
    session gets switched off within the day.
  * A report whose receipt or waiver sha no longer matches its bytes is a real problem, but usually an
    inherited one. Blocking every future session on a backlog it did not create is the same mistake,
    so those are written to state/gate/stale_approvals.json for someone to work through, and are not
    flagged unless they also change. One whose bytes move during a session is caught by drift like
    anything else.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _hookutil import (ROOT, finding_for_report, is_report,  # noqa: E402
                       read_payload, touch_report, waiver_path)

MANIFEST = ROOT / "state" / "gate" / "report_shas.json"
STALE = ROOT / "state" / "gate" / "stale_approvals.json"
MAX_BYTES = 4 * 1024 * 1024        # a disclosure report is never this big; skip anything that is


def _load_manifest():
    try:
        return json.loads(MANIFEST.read_text(encoding="utf-8")), True
    except (OSError, json.JSONDecodeError):
        return {}, False


def _bound_sha(fid, gate):
    """The sha256 that this finding's own receipt or waiver claims to describe, if either exists."""
    for p in (gate.receipt_path(fid), waiver_path(fid)):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        sha = rec.get("report_sha256", "")
        if sha:
            return sha
    return ""


def _write_json(path, obj):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        pass                       # a file we cannot write costs drift detection, never a false pass


def main() -> int:
    d = read_payload()
    session = d.get("session_id", "")

    import gate
    manifest, seeded = _load_manifest()
    current, stale, drifted = {}, {}, []

    for f in sorted((ROOT / "reports").rglob("*.md")):
        if not is_report(str(f)) or not f.is_file():
            continue
        try:
            if f.stat().st_size > MAX_BYTES:
                continue
            live = gate.sha256_file(f)
        except OSError:
            continue
        rel = f.relative_to(ROOT).as_posix()
        current[rel] = live

        fid = finding_for_report(str(f))
        bound = _bound_sha(fid, gate) if fid else ""
        if bound and bound != live:
            stale[rel] = {"finding_id": fid, "approved_sha256": bound, "live_sha256": live}

        if seeded and manifest.get(rel, live) != live:
            drifted.append(rel)
        elif seeded and rel not in manifest:
            drifted.append(rel)

    for rel in drifted:
        touch_report(session, rel)

    _write_json(MANIFEST, current)
    _write_json(STALE, {
        "_note": ("Reports whose gate receipt or waiver is bound to a sha256 that no longer matches "
                  "the file. The approval describes bytes that no longer exist. Re-run report-auditor "
                  "and report-editor, then `python hunt.py validate-report <ID>` - or re-waive the "
                  "draft. Informational: this file never blocks a session on its own."),
        "count": len(stale),
        "reports": stale,
    })
    return 0                        # never blocks; the Stop gate is the only thing that blocks


if __name__ == "__main__":
    sys.exit(main())
