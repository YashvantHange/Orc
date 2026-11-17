#!/usr/bin/env python3
"""
census.py — enumerate a population of call sites and report the ODD ONES OUT.

## What this is for

The invariant table asks "what is true of *this* structure". That finds a local defect, and it
found one: a request-allocated table retained in a worker-lifetime cache. It does not find a defect
whose essence is that a RULE the codebase relies on everywhere is broken in two places out of two
hundred. PHP's 2026-10-21 fix is that shape - upstream threaded a `fallible` flag through every
hash-table allocation path, which is the signature of a systemic discipline problem, not one broken
function.

The cognitive move that finds those is different: build the population, classify every member, and
**the minority is the suspect**. Asymmetry is the signal, and the ratio is the evidence - "2 of 200"
says something that prose cannot.

## What this tool does, and what it refuses to do

It **counts**. It finds nothing on its own and makes no judgement about security. You name the
population and you name what upholding the discipline looks like; it tells you how many members
there are, which ones do not uphold it, and where they live. Deciding whether the minority is a
defect or a deliberate, documented exception is yours - and it usually is deliberate, which is why
step one of triage is asking whether anything downstream knows.

This division is on purpose: a grep is reliable at building a census and hopeless at judging one.

## Example - the real one this was built from

A hunter found an asymmetry in `main/SAPI.c` by accident, reading an 18-line window: three
`request_info` fields are `efree`d *and nulled*, and the next two are `efree`d without being nulled.
As a census that is mechanical rather than lucky:

  python tools/census.py --root work/php-prepatch/src --glob 'main/SAPI.c' \\
      --population 'efree\\(SG\\(request_info\\)' --upholds '= NULL' --window 2

  python tools/census.py --root work/php-prepatch/src --glob '**/*.c' \\
      --population 'zend_hash_init\\(' --upholds 'persistent' --window 0

Exit 0 when the population is uniform, 1 when there is a minority to look at, 2 on a usage problem.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "static"))
import _common as C  # noqa: E402

DEFAULT_GLOB = "**/*"
TEXT_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".py", ".js", ".ts", ".go", ".java",
                 ".rs", ".php", ".rb", ".cs", ".kt", ".swift", ".m"}


def _files(root: Path, glob: str) -> list:
    skip = set(C.EXCLUDE_DIRS)
    out = []
    for p in root.glob(glob):
        if not p.is_file() or skip.intersection(p.parts):
            continue
        if p.suffix.lower() in TEXT_SUFFIXES or glob != DEFAULT_GLOB:
            out.append(p)
    return sorted(out)


def census(root: Path, population: str, upholds: str, glob: str = DEFAULT_GLOB,
           window: int = 3, ignore_case: bool = False) -> dict:
    flags = re.I if ignore_case else 0
    pop_re = re.compile(population, flags)
    up_re = re.compile(upholds, flags) if upholds else None

    members, violators = [], []
    for f in _files(root, glob):
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            if not pop_re.search(line):
                continue
            # The window is the SITE, not the file: a discipline is upheld near where it is owed.
            near = "\n".join(lines[i: i + window + 1])
            ok = bool(up_re.search(near)) if up_re else False
            rec = {"file": str(f.relative_to(root)) if root in f.parents or root == f.parent
                   else str(f),
                   "line": i + 1, "text": line.strip()[:160], "upholds": ok}
            members.append(rec)
            if not ok:
                violators.append(rec)

    n, v = len(members), len(violators)
    return {
        "root": str(root), "glob": glob, "window": window,
        "population_pattern": population, "upholds_pattern": upholds,
        "population": n,
        "uphold": n - v,
        "minority": v,
        "ratio": f"{v}/{n}" if n else "0/0",
        "minority_share": round(100.0 * v / n, 1) if n else 0.0,
        "odd_ones_out": violators,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", required=True, help="tree to census")
    ap.add_argument("--population", required=True,
                    help="regex whose matches DEFINE the population (every site that owes the rule)")
    ap.add_argument("--upholds", default="",
                    help="regex that, found within --window lines of a member, means it upholds the "
                         "rule. Omit to just count the population.")
    ap.add_argument("--glob", default=DEFAULT_GLOB)
    ap.add_argument("--window", type=int, default=3,
                    help="lines after the member to search for --upholds (default 3)")
    ap.add_argument("-i", "--ignore-case", action="store_true")
    ap.add_argument("--max-show", type=int, default=25)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    root = Path(a.root)
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    r = census(root, a.population, a.upholds, a.glob, a.window, a.ignore_case)

    if a.json:
        import json
        print(json.dumps(r, indent=2))
        return 1 if r["minority"] and r["upholds_pattern"] else 0

    print(f"== census: {a.population!r} over {a.glob} ==")
    print(f"   population : {r['population']} site(s)")
    if not r["upholds_pattern"]:
        print("   (no --upholds given: population count only, nothing classified)")
        return 0
    if r["population"] == 0:
        print("\n   EMPTY POPULATION. The pattern matched nothing, so this says nothing about the")
        print("   discipline - it says the pattern is wrong. Fix the pattern before concluding.")
        return 2

    print(f"   uphold     : {r['uphold']}")
    print(f"   minority   : {r['minority']}  ({r['ratio']}, {r['minority_share']}%)")

    if not r["minority"]:
        print("\n   UNIFORM - every member upholds the rule within the window. Record the ratio so")
        print("   it can be re-measured later. Then ask the question uniformity does NOT answer:")
        print("   is the rule you just tested the SAFE one? A discipline everyone upholds can still")
        print("   be the hazard, and then there is no odd one out to find.")
        return 0

    print(f"\n   THE ODD ONES OUT - these are suspects, not findings:")
    for m in r["odd_ones_out"][: a.max_show]:
        print(f"     {m['file']}:{m['line']}")
        print(f"       {m['text']}")
    if r["minority"] > a.max_show:
        print(f"     ... {r['minority'] - a.max_show} more")

    print("\n   Now do the part a grep cannot. For each: is the exception DELIBERATE, and if it is,")
    print("   does anything downstream know? A documented fast path with every consumer aware of it")
    print("   is not a defect. A documented fast path that one consumer still trusts is.")
    # Uniformity cuts both ways, and this branch is the one that reaches the hard shape.
    if r["minority_share"] >= 80:
        print("\n   NOT AN ASYMMETRY - almost nothing upholds this rule. Two readings, and the")
        print("   second is the one worth your time:")
        print("     (a) the pattern is wrong, or --window is too small. Check one site by hand.")
        print("     (b) the real discipline is not the one you assumed, and it is UNSAFE BY")
        print("         DESIGN. If every allocation site here declines to check for failure, the")
        print("         actual rule is 'failure never returns to the caller' - and then the defect")
        print("         is not one odd site, it is every caller that had already mutated shared")
        print("         state when control left. There is no minority to find; the population IS")
        print("         the finding. That is the shape of PHP's 2026-10-21 fix, which threaded a")
        print("         fallible flag through every one of these paths rather than repairing one.")
        print("     Next move for (b): census the CALLERS, not the allocations - which of them")
        print("     writes to a shared structure before the call that may not return?")
    elif r["minority_share"] > 40:
        print("\n   NOTE: the minority is over 40% of the population, so this is not an asymmetry -")
        print("   the pattern is probably describing two different things. Narrow it.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
