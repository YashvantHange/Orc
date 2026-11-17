#!/usr/bin/env python3
"""
model_check.py — validate a target model's FORM, so a skipped or half-finished opening pass is
visible instead of silent.

Reads `work/<slug>/model.md` (the artifact `target-model` produces) and checks:

  * one section per phase, using the fixed headings the skill prints with --template;
  * the invariant table parses, and every row has an ID, an invariant, a verdict and EVIDENCE;
  * `Violated?` is yes / no / unreachable - never blank. A blank cell is an unfinished sweep,
    not a negative result;
  * every structure the relevance gate dropped is recorded with the question it failed AND a
    reason. An unaudited filter is the loophole that defeats the coverage figure, because
    "coverage 100%" is reachable by filtering away 299 of 300 structures;
  * the coverage block parses and clears the floor.

WHAT IT DELIBERATELY DOES NOT DO. It never judges whether an invariant is TRUE, whether the
evidence supports the verdict, or whether the model understood the target. It cannot: that is
reasoning, and the standing rule for this whole capability is that scripts verify the agent did
the work while the agent does the work. A model that reads well and gets every lifetime wrong
passes this check and fails the exam. Do not quote a PASS here as evidence of a good model.

  python tools/model_check.py work/<target>
  python tools/model_check.py --template > work/<slug>/model.md
  python tools/model_check.py work/<target> --min-coverage 90 --min-rows 5
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "static"))
import _common as C  # noqa: E402

# The six phases of `target-model`, plus the two accounting sections. The heading text is a
# contract between the skill and this file; the skill prints it with --template.
PHASES = [
    (1, "Scope map"),
    (2, "State map"),
    (3, "Exit map"),
    (4, "Invariant map"),
    (5, "Reachability"),
    (6, "State transitions"),
]
EXTRA_SECTIONS = ["Filtered structures", "Coverage"]

VERDICTS = {"yes", "no", "unreachable"}
# Values that look like an answer and are not. Same intent as reports/impact_gate.py's EMPTY set.
EMPTY = {"", "-", "—", "n/a", "na", "none", "tbd", "todo", "unknown", "?", "...", "pending",
         "it follows", "looked fine", "see above", "same as above"}

DEFAULT_MIN_COVERAGE = 80.0
DEFAULT_MIN_ROWS = 1

# ASCII only in TEMPLATE: it is printed to a cp1252 console, which mangles an em dash.
TEMPLATE = """# Target model - <slug>

<!-- Written by `target-model` before any class is swept. Validated by `hunt model-check`.
     The headings below are fixed: the validator reads them. -->

## 1. Scope map

| Scope | Storage with this lifetime |
|---|---|
|  |  |

Short-lived allocator/container:
Long-lived allocator/container:

## 2. State map

| Long-lived storage | Written by | Read by | Cleared by |
|---|---|---|---|
|  |  |  |  |

## 3. Exit map

| Abnormal exit | Cleanup that runs | What that cleanup TRUSTS |
|---|---|---|
|  |  |  |

## 4. Invariant map

| ID | Structure | Invariant | Who mutates | What can interrupt | State at interruption | Cleanup that runs | What cleanup assumes | Later consumer | Violated? | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| INV-01 |  |  |  |  |  |  |  |  |  |  |

## 5. Reachability

| Path | Config needed | Default-on? | Precondition count |
|---|---|---|---|
|  |  |  |  |

## 6. State transitions

| Structure | created | initialised | partially mutated | committed | consumed | destroyed | exits that can fire |
|---|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |  |

## Filtered structures

| Structure | Failed question | Why |
|---|---|---|
|  |  |  |

## Coverage

declared abnormal exits: 0 / analysed: 0
candidate structures: 0 / passed the gate: 0 / filtered: 0
required cells: 0 / evaluated: 0
"""


@dataclass
class Result:
    path: Path
    problems: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    rows: int = 0
    coverage: float = 0.0

    @property
    def ok(self) -> bool:
        return not self.problems


def _blank(v: str) -> bool:
    return v.strip().lower().strip(".") in EMPTY


def _split_row(line: str) -> list:
    """Cells of a markdown table row, without the leading/trailing pipe artefacts."""
    parts = line.strip().strip("|").split("|")
    return [p.strip() for p in parts]


def _is_separator(line: str) -> bool:
    return bool(re.fullmatch(r"\|[\s|:-]+\|?", line.strip()))


def _section(text: str, heading: str) -> str:
    """The body under a `## <heading>` up to the next `## `, or "" if the heading is absent."""
    pat = re.compile(rf"^##\s+{re.escape(heading)}\s*$", re.M)
    m = pat.search(text)
    if not m:
        return ""
    rest = text[m.end():]
    nxt = re.search(r"^##\s+", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


def _headings(text: str) -> list:
    return [h.strip() for h in re.findall(r"^##\s+(.+?)\s*$", text, re.M)]


def check_invariant_table(body: str, res: Result, min_rows: int) -> None:
    """Every row needs an id, an invariant, a verdict in VERDICTS, and real evidence."""
    rows = []
    for line in body.splitlines():
        s = line.strip()
        if not s.startswith("|") or _is_separator(s):
            continue
        cells = _split_row(s)
        if cells and re.fullmatch(r"(?i)inv-\d+", cells[0]):
            rows.append(cells)

    res.rows = len(rows)
    if len(rows) < min_rows:
        res.problems.append(
            f"invariant map has {len(rows)} row(s); at least {min_rows} required. An empty table "
            "means the invariant-first sweep was not run - that is UNTESTED, not a clean result")
        return

    for cells in rows:
        rid = cells[0]
        if len(cells) < 11:
            res.problems.append(
                f"{rid}: row has {len(cells)} cells, expected 11 "
                "(ID..Evidence). Use the --template header")
            continue
        invariant, verdict, evidence = cells[2], cells[9].lower().strip("*_ "), cells[10]
        if _blank(invariant):
            res.problems.append(f"{rid}: no invariant stated. One sentence, 'X must always be "
                                "true of Y' - a vague invariant produces a vague sweep")
        if verdict not in VERDICTS:
            res.problems.append(
                f"{rid}: Violated? is {cells[9]!r}; must be yes / no / unreachable. A blank cell "
                "is an unfinished sweep, not a negative result")
            continue
        if _blank(evidence):
            kind = {"yes": "the file:line of the mutation, the interrupt and the later consumer",
                    "no": "the file:line of the rollback, guard, reset or null that HOLDS it",
                    "unreachable": "the reachability argument - which config or path is absent"}
            res.problems.append(
                f"{rid}: verdict {verdict!r} with no evidence. Needs {kind[verdict]}. "
                "An unevidenced row records a conclusion that was never established, which is "
                "worse than an empty table: it manufactures a finished sweep")
        elif verdict in ("yes", "no") and not re.search(r"[\w/.\\-]+[.:]\w+[:#]\d+|:\d+", evidence):
            res.notes.append(
                f"{rid}: evidence {evidence!r} carries no file:line. Accepted, but a verdict "
                "without a citation is an assumption under guardrails' No-Assumption rule")


def check_filtered(body: str, res: Result) -> None:
    for line in body.splitlines():
        s = line.strip()
        if not s.startswith("|") or _is_separator(s):
            continue
        cells = _split_row(s)
        if len(cells) < 3 or cells[0].lower() in ("structure", ""):
            continue
        if _blank(cells[1]) or _blank(cells[2]):
            res.problems.append(
                f"filtered structure {cells[0]!r}: needs BOTH the question it failed and why. "
                "An unaudited filter defeats the coverage figure - 100% is reachable by "
                "filtering away everything")


def check_coverage(body: str, res: Result, floor: float) -> None:
    def pair(label: str, second: str) -> tuple:
        m = re.search(rf"{label}\s*:\s*(\d+)\s*/\s*{second}\s*:\s*(\d+)", body, re.I)
        return (int(m.group(1)), int(m.group(2))) if m else (None, None)

    exits_d, exits_a = pair("declared abnormal exits", "analysed")
    cells_r, cells_e = pair("required cells", "evaluated")

    if cells_r is None:
        res.problems.append(
            "no coverage block. 'found nothing' at 96% of the search space and at 12% are "
            "different results and must not be recorded the same way - see target-model")
        return
    if cells_r == 0:
        res.problems.append("required cells is 0 - the relevance gate produced nothing to sweep. "
                            "Either the gate filtered everything (record why) or it never ran")
        return

    res.coverage = 100.0 * cells_e / cells_r
    if res.coverage < floor:
        res.problems.append(
            f"search-space coverage {res.coverage:.0f}% is below the {floor:.0f}% floor "
            f"({cells_e}/{cells_r} cells). A low-coverage hunt is UNTESTED, not CLEAR")
    if exits_d is not None and exits_a < exits_d:
        res.notes.append(f"{exits_d - exits_a} of {exits_d} declared abnormal exits were not "
                         "analysed; say so in the verdict")


def check(target: str, min_coverage: float = DEFAULT_MIN_COVERAGE,
          min_rows: int = DEFAULT_MIN_ROWS) -> Result:
    """Validate the model for a target slug (resolves work/<slug>/model.md)."""
    return check_path(C.workdir(target) / "model.md", min_coverage, min_rows)


def check_path(path: Path, min_coverage: float = DEFAULT_MIN_COVERAGE,
               min_rows: int = DEFAULT_MIN_ROWS) -> Result:
    """Validate a model.md by path. Callers that already hold a workdir use this one."""
    res = Result(path=path)
    if not path.exists():
        res.problems.append(
            f"no model at {path}. `target-model` runs BEFORE any class is swept; without it the "
            "hunt is sink-matching only, which cannot find a bug whose essence is a relationship "
            "between a lifetime, an invariant and an abnormal exit. "
            "`hunt model-check --template` prints the skeleton")
        return res

    text = path.read_text(encoding="utf-8", errors="replace")
    present = _headings(text)
    for num, name in PHASES:
        if not any(h == f"{num}. {name}" or h.endswith(name) for h in present):
            res.problems.append(f"missing phase {num} section: '## {num}. {name}'")
    for name in EXTRA_SECTIONS:
        if name not in present:
            res.problems.append(f"missing section: '## {name}'")

    check_invariant_table(_section(text, "4. Invariant map") or _section(text, "Invariant map"),
                          res, min_rows)
    check_filtered(_section(text, "Filtered structures"), res)
    check_coverage(_section(text, "Coverage"), res, min_coverage)
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?", help="target dir / slug whose work/<slug>/model.md to check")
    ap.add_argument("--template", action="store_true", help="print the model.md skeleton and exit")
    ap.add_argument("--min-coverage", type=float, default=DEFAULT_MIN_COVERAGE)
    ap.add_argument("--min-rows", type=int, default=DEFAULT_MIN_ROWS)
    a = ap.parse_args()

    if a.template:
        print(TEMPLATE)
        return 0
    if not a.target:
        ap.error("pass a target, or --template")

    res = check(a.target, a.min_coverage, a.min_rows)
    print(f"== model-check: {a.target} ==")
    print(f"   {res.path}")
    if res.rows or res.coverage:
        print(f"   invariant rows: {res.rows}   search-space coverage: {res.coverage:.0f}%")
    for n in res.notes:
        print(f"   note: {n}")
    if res.ok:
        print("\n   PASS (form only - this says nothing about whether the model is correct;\n"
              "         a plausible model with the lifetimes wrong passes here and fails the exam)")
        return 0
    print(f"\n   FAIL - {len(res.problems)} problem(s):")
    for p in res.problems:
        print(f"     - {p}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
