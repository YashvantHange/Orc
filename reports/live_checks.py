#!/usr/bin/env python3
"""
live_checks.py — the two evidence checks for live-website targets, moved out of hunt.py unchanged.

These were always the strongest code in the gate and they are exactly the right shape for it: pure
comparison, no judgement. A cited transcript id either exists and its response hash matches the bundle,
or it does not. A scope digest either still matches the file on disk, or the file changed and you no
longer know what authorized the traffic. Neither can produce a false positive.

They live here rather than in hunt.py so gate.py can use them without importing the CLI.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "static"))
import _common as C  # noqa: E402


def _profile(target: str) -> dict:
    p = C.workdir(target) / "profile.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def transcript_ok(rec: dict, report_txt: str) -> tuple[bool, str]:
    """Cited T##### ids must exist in the transcript, and their response hashes must match the
    evidence bundle's copy. A stale or invented id fails exactly like a stale line number."""
    ids = [i.strip() for i in str(rec.get("transcript_ids", "")).split(",") if i.strip()]
    ids += [m for m in re.findall(r"\bT\d{5}\b", report_txt) if m not in ids]
    if not ids:
        return False, "no transcript ids cited (ledger transcript_ids, or T##### in the report)"

    target = rec.get("target_url") or rec.get("repo") or ""
    try:
        tp = C.workdir(target) / "web" / "transcript.jsonl"
    except Exception:                                   # noqa: BLE001
        return False, "could not resolve the target's workdir"
    if not tp.exists():
        return False, f"transcript not found at {tp}"

    found: dict = {}
    for line in tp.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("id") in ids:
            found[r["id"]] = r
    missing = [i for i in ids if i not in found]
    if missing:
        return False, f"cited ids absent from the transcript: {', '.join(missing)}"

    # cross-check against the bundle's sliced copy, when one was collected
    ep = rec.get("evidence_path")
    if ep:
        bundle = ROOT / ep / "transcript.jsonl"
        if bundle.exists():
            for line in bundle.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    b = json.loads(line)
                except json.JSONDecodeError:
                    continue
                src = found.get(b.get("id"))
                if src and b.get("resp_body_sha256") and \
                        b["resp_body_sha256"] != src.get("resp_body_sha256"):
                    return False, (f"{b['id']}: evidence-bundle response hash does not match the "
                                   f"transcript - the bundle was edited or the target changed")
    return True, f"{len(ids)} transcript id(s) verified"


def scope_auth_ok(rec: dict, report_txt: str) -> tuple[bool, str]:
    """The report must name the program that authorized the test, and the scope digest it ran under
    must still match the file on disk."""
    low = report_txt.lower()
    digest = rec.get("scope_digest", "")
    prof = _profile(rec.get("target_url") or rec.get("repo") or "")
    digest = digest or prof.get("scope_digest", "")
    program = rec.get("program") or prof.get("program") or {}
    if not digest:
        return False, "no scope_digest recorded - the report cannot show what authorized the test"
    if digest not in report_txt and digest.split(":")[-1][:16] not in report_txt:
        return False, "the scope digest is not quoted in the report"
    if not (program or "program" in low):
        return False, "the report does not name the bug-bounty program"
    if not (rec.get("test_window") or prof.get("test_window") or "test window" in low):
        return False, "no test window recorded"

    sf = prof.get("scope_file")
    if sf and Path(sf).exists():
        live = "sha256:" + hashlib.sha256(Path(sf).read_bytes()).hexdigest()
        if live != digest:
            return False, (f"{sf} has changed since the test (digest mismatch) - re-verify which "
                           f"scope actually authorized this traffic")
    return True, "program, digest and window present"
