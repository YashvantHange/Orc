#!/usr/bin/env python3
"""
exam_check.py — decide whether a capability exam can be blind BEFORE it is run.

## The failure this exists to prevent

The first php-src exam was void by construction, and the construction was the problem:

  1. The hunter's own skills named the defect's file and function outright.
  2. So the brief forbade starting from any location a skill names.
  3. Those locations WERE the answers.

Recall was therefore 0/2 before the run started. The exam could not have measured discovery under
any outcome. The lesson is not "write a better brief" — an exclusion rule cannot fix a leak that
sits AT the answer, because excluding the leak excludes the answer. The only fix is target
selection: an exam target is valid only if its answer appears in no instruction the agent loads.

So this runs first and says BLIND or COMPROMISED, naming every leak with its file:line. A
COMPROMISED target is not fixable by instruction; pick a different target.

## What it searches

Everything the agent can read as instruction: `.claude/skills/**`, `.claude/agents/**`,
`.claude/commands/**`, `RULES.md`, `TOOLS.md`, the mistake log, and — the vector the first exam
missed — the **memory stores**, which a hunter is told to consult as its mandatory first step. A
memory file naming the product and mechanism compromises an exam just as thoroughly as a skill does,
and is easier to forget.

  python tools/exam_check.py tests/data/php_prepatch_reference.json
  python tools/exam_check.py tests/data/model_corpus_reference.json --quiet
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Instruction corpora: anything the agent may load or is told to consult.
CORPORA = [
    ROOT / ".claude" / "skills",
    ROOT / ".claude" / "agents",
    ROOT / ".claude" / "commands",
    ROOT / ".claude" / "mistake-log",
    ROOT / "RULES.md",
    ROOT / "TOOLS.md",
    ROOT / "programs",
]
# The memory stores. Two separate directories, per the standing note that they are not the same
# place - a hunter's MANDATORY FIRST STEP is to read them, so they are first-class leak vectors.
MEMORY_DIRS = [
    ROOT / "memory",
    Path(os.environ.get("USERPROFILE", Path.home())) / ".claude" / "projects" /
    "C--Users-Yashvant-Desktop-OpenSource" / "memory",
]
TEXT_SUFFIXES = {".md", ".py", ".yml", ".yaml", ".json", ".txt", ".toml"}


def answer_terms(ref: dict) -> list:
    """The strings that would let an agent navigate to the answer rather than derive it.

    Taken from the reference key itself: explicit `answer_locations`, the fix sites, and anything
    the key already flags under `do_not_credit_for`. A term is a file path, a function name, a
    config switch or an advisory id - not a generic word like "counter", which would match
    everything and tell you nothing.
    """
    terms: set = set()
    for loc in ref.get("answer_locations") or []:
        terms.add(loc)
    terms.update((ref.get("fix_sites") or {}).keys())
    for inv in ref.get("reference_invariants") or []:
        for s in inv.get("do_not_credit_for") or []:
            terms.update(re.findall(r"[\w/]+\.[ch]\b", s))          # C file paths
            terms.update(re.findall(r"\b[a-zA-Z]\w*_\w+\b", s))     # C identifiers
    for k in ("advisory", "advisory_id"):
        if ref.get(k):
            terms.add(ref[k])
    for s in (ref.get("_derivation") or []):
        terms.update(re.findall(r"(?:GHSA|CVE)-[\w-]+", s))

    # A term must be NAVIGATION - something an agent could go to - not an English word. The first
    # version of this function pulled "integrity" out of "state-integrity" and reported 40 leaks in
    # files that merely discuss the family, which is exactly how a gate gets ignored. So: keep only
    # C-file paths, underscore-bearing identifiers, and advisory ids.
    def navigable(t: str) -> bool:
        return bool(re.fullmatch(r"[\w/]+\.[ch]", t)                      # Zend/zend_hash.c
                    or re.fullmatch(r"(?:GHSA|CVE)-[\w-]+", t)            # GHSA-f883-x959-3vr9
                    or (re.fullmatch(r"[a-zA-Z]\w*_\w+", t) and len(t) >= 8))   # in_rfc1867_update
    # Words that are the family's own vocabulary, not this target's answer.
    noise = {"state_integrity", "target_model", "reference_invariants", "do_not_credit_for"}
    return sorted(t for t in terms if navigable(t) and t not in noise)


def _files() -> list:
    out = []
    for base in CORPORA + MEMORY_DIRS:
        if base.is_file():
            out.append(base)
        elif base.is_dir():
            out += [p for p in base.rglob("*")
                    if p.is_file() and p.suffix.lower() in TEXT_SUFFIXES
                    and "__pycache__" not in p.parts]
    return out


def check(ref_path: Path) -> dict:
    ref = json.loads(ref_path.read_text(encoding="utf-8"))
    terms = answer_terms(ref)
    leaks = []
    for f in _files():
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            for t in terms:
                if t in line:
                    try:
                        rel = f.relative_to(ROOT)
                    except ValueError:
                        rel = f           # a memory store outside the repo
                    leaks.append({"term": t, "file": str(rel), "line": n,
                                  "text": line.strip()[:120]})
    # A "BLIND" verdict reached by searching for nothing is the exact false reassurance this file
    # exists to kill. If the key declares no answer locations, the check DID NOT RUN - say so.
    if not terms:
        verdict = "UNKNOWN"
    elif leaks:
        verdict = "COMPROMISED"
    else:
        verdict = "BLIND"
    return {
        "reference": str(ref_path),
        "target": ref.get("target", "(unnamed)"),
        "terms_searched": terms,
        "verdict": verdict,
        "leaks": leaks,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("reference", help="the exam's grading key (tests/data/*_reference.json)")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    res = check(Path(a.reference))
    print(f"== exam integrity: {res['target']} ==")
    print(f"   key            : {res['reference']}")
    print(f"   terms searched : {len(res['terms_searched'])}")
    if not a.quiet:
        print(f"                    {', '.join(res['terms_searched'][:12])}"
              f"{' ...' if len(res['terms_searched']) > 12 else ''}")

    if res["verdict"] == "UNKNOWN":
        print("\n   UNKNOWN - this key declares no `answer_locations` and no `fix_sites`, so there")
        print("   was nothing to search for. This is NOT a blind certification: a pass reached by")
        print("   searching for nothing is the same false reassurance an empty scan gives.")
        print("   Add `answer_locations`: the files, functions, config switches and advisory ids")
        print("   that would let an agent navigate to the answer instead of deriving it.")
        return 2

    if res["verdict"] == "BLIND":
        print(f"\n   BLIND - none of the {len(res['terms_searched'])} answer location(s) is named by")
        print("   any instruction the agent loads. A blind run on it measures discovery.")
        print("   Record this verdict alongside the result.")
        return 0

    print(f"\n   COMPROMISED - {len(res['leaks'])} leak(s). The agent can navigate to the answer:")
    seen = set()
    for lk in res["leaks"]:
        k = (lk["file"], lk["line"])
        if k in seen:
            continue
        seen.add(k)
        print(f"     {lk['file']}:{lk['line']}  [{lk['term']}]")
        if not a.quiet:
            print(f"       {lk['text']}")
    print("\n   DO NOT 'fix' this with a brief that forbids those locations. An exclusion rule")
    print("   cannot repair a leak that sits AT the answer - it excludes the answer, and recall")
    print("   is 0 before the run starts. That is exactly how the first php-src exam was voided.")
    print("   Pick a target whose answer is in no instruction, or accept that this run measures")
    print("   model quality and false-positive control, NOT discovery - and say so in the result.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
