#!/usr/bin/env python3
"""
model_score.py — score a model.md against a held-out reference invariant set.

This is the exam's grader. It is deliberately NOT a detector and NOT part of the hunt: the
reference lives outside the fixture tree, the hunter never sees it, and this runs afterwards.

What it computes:
  * invariant recall      — reference invariants the model named
  * decoy hits            — reference entries marked is_decoy that the model called violated.
                            These are false positives and are the metric that cannot be gamed by
                            writing more rows.
  * verdict agreement     — rows whose yes/no/unreachable matches the reference, per fixture
  * evidence citation     — rows carrying a file:line (presence, not correctness; a human still
                            has to open the citation and check it says what the row claims)
  * unmatched rows        — reported for ADJUDICATION, never auto-scored as wrong. An invariant the
                            reference lacks may be real and missed by the reference, conceivably a
                            second defect. Auto-counting it against the run would punish exactly
                            the discovery this whole capability exists to produce.

Matching is lexical and deliberately loose (keyword overlap on the invariant sentence), because an
agent will not reproduce the reference's wording. A loose matcher over-credits rather than
under-credits, so treat recall as an upper bound and read the unmatched list yourself.

  python tools/model_score.py work/php-prepatch --reference tests/data/model_corpus_reference.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "static"))
sys.path.insert(0, str(ROOT / "tools"))
import _common as C  # noqa: E402
import model_check as M  # noqa: E402

STOP = {"the", "a", "an", "must", "only", "that", "this", "is", "are", "be", "no", "not", "any",
        "of", "in", "into", "to", "after", "before", "its", "it", "and", "or", "may", "never",
        "always", "has", "have", "which", "whose", "all", "each", "with", "for", "from", "on"}


def _words(s: str) -> set:
    return {w for w in re.findall(r"[a-z_]{3,}", (s or "").lower()) if w not in STOP}


def _overlap(a: str, b: str) -> float:
    wa, wb = _words(a), _words(b)
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / min(len(wa), len(wb))


def model_rows(path: Path) -> list:
    """The invariant table's rows, as dicts. Reuses model_check's parsing conventions."""
    text = path.read_text(encoding="utf-8", errors="replace")
    body = M._section(text, "4. Invariant map") or M._section(text, "Invariant map")
    rows = []
    for line in body.splitlines():
        s = line.strip()
        if not s.startswith("|") or M._is_separator(s):
            continue
        cells = M._split_row(s)
        if cells and re.fullmatch(r"(?i)inv-\d+", cells[0]) and len(cells) >= 11:
            rows.append({"id": cells[0], "structure": cells[1], "invariant": cells[2],
                         "consumer": cells[8],
                         "verdict": cells[9].lower().strip("*_ "), "evidence": cells[10]})
    return rows


def score(model_path: Path, reference: Path, threshold: float = 0.34) -> dict:
    ref = json.loads(reference.read_text(encoding="utf-8"))
    refs = ref["reference_invariants"]
    rows = model_rows(model_path)

    matched, unmatched = {}, []
    for r in rows:
        best, best_s = None, 0.0
        for ri in refs:
            s = max(_overlap(r["invariant"], ri.get("invariant", "")),
                    _overlap(r["structure"], ri.get("structure", "")))
            if s > best_s:
                best, best_s = ri, s
        if best and best_s >= threshold:
            matched.setdefault(best["id"], []).append({**r, "match_strength": round(best_s, 2)})
        else:
            unmatched.append(r)

    real = [ri for ri in refs if not ri.get("is_decoy")]
    decoys = [ri for ri in refs if ri.get("is_decoy")]
    found = [ri["id"] for ri in real if ri["id"] in matched]
    decoy_hits = [{"ref": ri["id"], "rows": [m["id"] for m in matched[ri["id"]]
                                             if m["verdict"] == "yes"]}
                  for ri in decoys if ri["id"] in matched]
    decoy_hits = [d for d in decoy_hits if d["rows"]]

    cited = [r for r in rows if re.search(r"[\w/.\\-]+[.:]\w+[:#]\d+|:\d+", r["evidence"] or "")]

    return {
        "model": str(model_path),
        "reference": str(reference),
        "rows_in_model": len(rows),
        "reference_invariants": len(real),
        "invariant_recall": {"found": found, "missed": [ri["id"] for ri in real
                                                        if ri["id"] not in matched],
                             "ratio": (len(found) / len(real)) if real else 0.0},
        "decoy_false_positives": decoy_hits,
        "evidence_cited_rows": {"n": len(cited), "of": len(rows)},
        "unmatched_rows_FOR_ADJUDICATION": [
            {"id": r["id"], "invariant": r["invariant"], "verdict": r["verdict"],
             "adjudication": "TODO: real-and-reference-missed | real-not-security-relevant | "
                             "not-an-invariant"}
            for r in unmatched],
        "caveats": [
            "Matching is lexical keyword overlap, so recall is an UPPER BOUND. Read the matches.",
            "evidence_cited_rows counts the PRESENCE of a file:line, not whether it says what the "
            "row claims. Opening the citations is a human step and is not done here.",
            "An unmatched row is NOT scored wrong. Adjudicate it before drawing any conclusion.",
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="target slug whose work/<slug>/model.md to score")
    ap.add_argument("--reference", required=True)
    ap.add_argument("--threshold", type=float, default=0.34)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    mp = C.workdir(a.target) / "model.md"
    if not mp.exists():
        print(f"no model at {mp} - nothing to score", file=sys.stderr)
        return 2
    out = score(mp, Path(a.reference), a.threshold)
    if a.json:
        print(json.dumps(out, indent=2))
        return 0

    r = out["invariant_recall"]
    print(f"== model score: {a.target} ==")
    print(f"   rows in model        : {out['rows_in_model']}")
    print(f"   invariant recall     : {len(r['found'])}/{out['reference_invariants']} "
          f"({100 * r['ratio']:.0f}%)  found={r['found']} missed={r['missed']}")
    print(f"   decoy false positives: {len(out['decoy_false_positives'])} "
          f"{out['decoy_false_positives']}")
    e = out["evidence_cited_rows"]
    print(f"   rows citing file:line: {e['n']}/{e['of']}")
    print(f"   unmatched (adjudicate): {len(out['unmatched_rows_FOR_ADJUDICATION'])}")
    for u in out["unmatched_rows_FOR_ADJUDICATION"]:
        print(f"     - {u['id']} [{u['verdict']}] {u['invariant'][:88]}")
    print("\n   caveats:")
    for c in out["caveats"]:
        print(f"     - {c}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
