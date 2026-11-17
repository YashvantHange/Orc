#!/usr/bin/env python3
"""
exam_run.py — run a capability exam end to end and WRITE DOWN the result.

The three exam tools each printed to a terminal and recorded nothing, so an exam's outcome lived in
scrollback while every other stage of this pipeline leaves an artifact (`sweep.json`, `model.md`,
`state_diff.json`, `language-coverage.json`). An unrecorded measurement is one nobody can audit,
re-read, or compare the next iteration against - and the whole point of scoring a run is to compare
iterations. So this runs all three and writes one record.

Three stages, in the only order that makes sense:

  1. `exam_check`  — CAN this run measure discovery? Must come first: it is the only stage whose
                     answer can invalidate the other two before they are worth reading.
  2. `model_check` — did the opening pass actually finish, and is every verdict evidenced? Form only.
  3. `model_score` — how does the model compare against the held-out reference?

The record carries `measures_discovery`, and the headline refuses to overstate: a COMPROMISED target
can still produce an excellent model, and the record says so in those words rather than printing a
score that reads like a discovery result.

  python tools/exam_run.py work/php-prepatch/src --reference tests/data/php_prepatch_reference.json

Exit codes: 0 valid discovery measurement and the model passed · 1 the model failed form checks ·
2 integrity UNKNOWN (the key declares no answer locations) · 3 integrity COMPROMISED.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "static"))
sys.path.insert(0, str(ROOT / "tools"))
import _common as C  # noqa: E402
import exam_check  # noqa: E402
import model_check  # noqa: E402
import model_score  # noqa: E402

HEADLINES = {
    "BLIND": "Valid discovery measurement: no instruction the agent loads names this target's "
             "answer.",
    "COMPROMISED": "NOT a discovery measurement. The agent could navigate to the answer, so "
                   "recall here says nothing about whether the method can FIND a defect. What it "
                   "still measures: model quality, evidence discipline and false-positive control.",
    "UNKNOWN": "Unmeasured. The key declares no answer locations, so integrity could not be "
               "checked - a pass reached by searching for nothing is not a pass.",
}


def run(target: str, reference: Path, min_coverage: float = 80.0,
        min_rows: int = 1) -> dict:
    integrity = exam_check.check(reference)
    mc = model_check.check(target, min_coverage, min_rows)

    rec = {
        "target": target,
        "ran_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "reference": str(reference),
        "measures_discovery": integrity["verdict"] == "BLIND",
        "headline": HEADLINES[integrity["verdict"]],
        "integrity": {
            "verdict": integrity["verdict"],
            "terms_searched": integrity["terms_searched"],
            "leak_count": len(integrity["leaks"]),
            # de-duplicated to one entry per file:line, so the record stays readable
            "leaks": [dict(t) for t in {tuple(sorted(l.items())) for l in integrity["leaks"]}],
        },
        "model_check": {
            "verdict": "PASS" if mc.ok else "FAIL",
            "note": "form only - says nothing about whether the model is correct",
            "artifact": str(mc.path),
            "invariant_rows": mc.rows,
            "search_space_coverage_pct": round(mc.coverage, 1),
            "problems": mc.problems,
            "notes": mc.notes,
        },
        "score": None,
    }

    if mc.path.exists():
        rec["score"] = model_score.score(mc.path, reference)

    return rec


def write(target: str, rec: dict) -> Path:
    d = C.workdir(target) / "exam"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "result.json"
    p.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    return p


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("--reference", required=True)
    ap.add_argument("--min-coverage", type=float, default=80.0)
    ap.add_argument("--min-rows", type=int, default=1)
    # The record is a real, user-visible artifact. --no-write exists so a test can exercise the
    # exit codes without clobbering a recorded exam: the first version of those tests ran against
    # the live target with a dummy key and overwrote the php-prepatch result, which then made a
    # later assertion skip with "this record is not compromised". A test that destroys the thing it
    # is checking is worse than no test.
    ap.add_argument("--no-write", action="store_true",
                    help="compute and print, write nothing (for exit-code checks)")
    ap.add_argument("--out", help="write the record here instead of work/<slug>/exam/result.json")
    a = ap.parse_args()

    ref = Path(a.reference)
    if not ref.exists():
        print(f"no reference key at {ref}", file=sys.stderr)
        return 2

    rec = run(a.target, ref, a.min_coverage, a.min_rows)
    if a.no_write:
        out = "(not written: --no-write)"
    elif a.out:
        out = Path(a.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    else:
        out = write(a.target, rec)

    i, m, s = rec["integrity"], rec["model_check"], rec["score"]
    print(f"== exam: {a.target} ==")
    print(f"   key              : {rec['reference']}")
    print(f"\n   1. integrity     : {i['verdict']}  "
          f"({i['leak_count']} leak(s) over {len(i['terms_searched'])} answer location(s))")
    for lk in sorted(i["leaks"], key=lambda d: (d["file"], d["line"]))[:6]:
        print(f"        leak        : {lk['file']}:{lk['line']}  [{lk['term']}]")
    if i["leak_count"] > 6:
        print(f"        ...         : {i['leak_count'] - 6} more in the record")

    print(f"\n   2. model-check   : {m['verdict']}  "
          f"({m['invariant_rows']} invariant rows, {m['search_space_coverage_pct']}% coverage)")
    for p in m["problems"][:5]:
        print(f"        problem     : {p[:110]}")

    if s:
        r = s["invariant_recall"]
        print(f"\n   3. score         : recall {len(r['found'])}/{s['reference_invariants']} "
              f"({100 * r['ratio']:.0f}%)   found={r['found']}  missed={r['missed']}")
        print(f"        decoy FPs   : {len(s['decoy_false_positives'])}")
        print(f"        cited rows  : {s['evidence_cited_rows']['n']}/"
              f"{s['evidence_cited_rows']['of']}")
        print(f"        adjudicate  : {len(s['unmatched_rows_FOR_ADJUDICATION'])} unmatched row(s) "
              f"- NOT scored wrong until adjudicated")
    else:
        print("\n   3. score         : skipped (no model.md to score)")

    print(f"\n   {rec['headline']}")
    print(f"\n   -> {out}")

    if m["verdict"] == "FAIL":
        return 1
    if i["verdict"] == "UNKNOWN":
        return 2
    if i["verdict"] == "COMPROMISED":
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
