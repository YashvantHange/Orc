#!/usr/bin/env python3
"""
Tests for the opening discipline: `target-model` and its validator `tools/model_check.py`.

What these guard, and the limit of what they CAN guard: the validator checks a model's FORM, so
these tests check that it rejects the specific shapes of an unfinished sweep — a blank verdict, a
verdict with no evidence, an unaudited filter, a coverage shortfall. None of them can tell a true
invariant from a plausible one. That is measured by the blind exam, not here, and a PASS from this
file must never be quoted as evidence that a model is good.

Run:  .venv/Scripts/python.exe -m pytest tests/test_target_model.py -q
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "static"))
sys.path.insert(0, str(ROOT / "tools"))

import _common as C  # noqa: E402
import model_check as M  # noqa: E402

SKILL = ROOT / ".claude" / "skills" / "target-model" / "SKILL.md"
AGENTS = ROOT / ".claude" / "agents"
TARGET = "work/_test_target_model"

HEADER = ("| ID | Structure | Invariant | Who mutates | What can interrupt "
          "| State at interruption | Cleanup that runs | What cleanup assumes "
          "| Later consumer | Violated? | Evidence |\n"
          "|---|---|---|---|---|---|---|---|---|---|---|\n")

GOOD_ROW = ("| INV-01 | bucket table | count counts only initialised buckets | hash insert "
            "| OOM in key alloc | count up, slot uninitialised | request shutdown "
            "| every counted bucket is valid | destruct loop | yes "
            "| zend_hash.c:1411 increment, :1420 alloc, :980 walk |")


def build_model(rows: str = GOOD_ROW,
                filtered: str = "| render_cache | 1 - crosses no scope boundary | one call |",
                coverage: str = "required cells: 10 / evaluated: 10") -> str:
    phases = "".join(f"\n## {n}. {t}\n\n(content)\n" for n, t in M.PHASES)
    body = phases.replace("## 4. Invariant map\n\n(content)\n",
                          f"## 4. Invariant map\n\n{HEADER}{rows}\n")
    return (f"# Target model - t\n{body}"
            "\n## Filtered structures\n\n| Structure | Failed question | Why |\n|---|---|---|\n"
            f"{filtered}\n"
            f"\n## Coverage\n\ndeclared abnormal exits: 3 / analysed: 3\n{coverage}\n")


@pytest.fixture
def model():
    d = C.workdir(TARGET)
    d.mkdir(parents=True, exist_ok=True)

    def write(text: str):
        (d / "model.md").write_text(text, encoding="utf-8")
        return M.check(TARGET)

    yield write
    shutil.rmtree(d, ignore_errors=True)


# --------------------------------------------------------------------- the happy path ---
def test_a_complete_model_passes(model):
    res = model(build_model())
    assert res.ok, res.problems
    assert res.rows == 1
    assert res.coverage == pytest.approx(100.0)


def test_a_missing_model_fails_and_says_why(model):
    shutil.rmtree(C.workdir(TARGET), ignore_errors=True)
    res = M.check(TARGET)
    assert not res.ok
    assert "no model at" in res.problems[0]


# ------------------------------------------------- the shapes of an unfinished sweep ---
def test_a_blank_verdict_is_not_a_negative_result(model):
    res = model(build_model(GOOD_ROW.replace("| yes |", "|  |")))
    assert not res.ok
    assert any("unfinished sweep" in p for p in res.problems)


@pytest.mark.parametrize("evidence", ["", "  ", "n/a", "TBD", "it follows", "looked fine",
                                      "see above"])
def test_a_verdict_without_evidence_is_rejected(model, evidence):
    """The highest-priority rule: a row may not record a conclusion that was never established."""
    row = GOOD_ROW.replace("| zend_hash.c:1411 increment, :1420 alloc, :980 walk |",
                           f"| {evidence} |")
    res = model(build_model(row))
    assert not res.ok
    assert any("no evidence" in p for p in res.problems), res.problems


def test_evidence_requirement_applies_to_a_no_verdict_too(model):
    """`no` needs the file:line of the guard that HOLDS the invariant, not just the word no."""
    row = GOOD_ROW.replace("| yes |", "| no |").replace(
        "| zend_hash.c:1411 increment, :1420 alloc, :980 walk |", "|  |")
    res = model(build_model(row))
    assert not res.ok
    assert any("rollback, guard, reset or null" in p for p in res.problems), res.problems


def test_unreachable_needs_a_reachability_argument(model):
    row = GOOD_ROW.replace("| yes |", "| unreachable |").replace(
        "| zend_hash.c:1411 increment, :1420 alloc, :980 walk |", "|  |")
    res = model(build_model(row))
    assert not res.ok
    assert any("reachability argument" in p for p in res.problems), res.problems


def test_an_unparseable_verdict_is_rejected(model):
    res = model(build_model(GOOD_ROW.replace("| yes |", "| probably |")))
    assert not res.ok
    assert any("must be yes / no / unreachable" in p for p in res.problems)


def test_a_vague_invariant_is_rejected(model):
    res = model(build_model(GOOD_ROW.replace(
        "count counts only initialised buckets", "unknown")))
    assert not res.ok
    assert any("no invariant stated" in p for p in res.problems)


def test_an_empty_invariant_table_is_untested_not_clean(model):
    res = model(build_model(rows=""))
    assert not res.ok
    assert any("was not run" in p for p in res.problems)


def test_a_missing_phase_section_fails(model):
    text = build_model().replace("## 3. Exit map", "## 3. Exits (renamed)")
    res = model(text)
    assert not res.ok
    assert any("phase 3" in p for p in res.problems)


# ------------------------------------------------- the filter and coverage loopholes ---
def test_a_filtered_structure_needs_a_recorded_reason(model):
    res = model(build_model(filtered="| render_cache | 1 - no boundary |  |"))
    assert not res.ok
    assert any("unaudited filter" in p for p in res.problems)


def test_coverage_below_the_floor_fails(model):
    res = model(build_model(coverage="required cells: 142 / evaluated: 20"))
    assert not res.ok
    assert any("below the" in p and "floor" in p for p in res.problems)
    assert res.coverage == pytest.approx(100 * 20 / 142, abs=0.5)


def test_filtering_everything_does_not_buy_full_coverage(model):
    """The loophole the audited filter exists to close: 0 required cells is not 100%."""
    res = model(build_model(coverage="required cells: 0 / evaluated: 0"))
    assert not res.ok
    assert any("relevance gate produced nothing" in p for p in res.problems)


def test_a_missing_coverage_block_fails(model):
    text = build_model().replace("required cells: 10 / evaluated: 10", "")
    res = model(text)
    assert not res.ok
    assert any("no coverage block" in p for p in res.problems)


def test_unanalysed_exits_are_noted_not_silently_accepted(model):
    res = model(build_model(coverage="required cells: 10 / evaluated: 10").replace(
        "declared abnormal exits: 3 / analysed: 3", "declared abnormal exits: 14 / analysed: 9"))
    assert res.ok, "an exit shortfall is a note, not a hard failure"
    assert any("were not" in n and "analysed" in n for n in res.notes), res.notes


# ------------------------------------------------------------------- the CLI contract ---
def test_template_is_accepted_by_the_validator_once_filled():
    """--template must emit something that can actually reach PASS, not an unfillable skeleton."""
    missing = [f"{n}. {t}" for n, t in M.PHASES if f"## {n}. {t}" not in M.TEMPLATE]
    assert not missing, f"the template omits sections the validator requires: {missing}"
    for name in M.EXTRA_SECTIONS:
        assert f"## {name}" in M.TEMPLATE


def test_template_is_ascii_so_a_cp1252_console_does_not_mangle_it():
    M.TEMPLATE.encode("ascii")           # raises UnicodeEncodeError if an em dash creeps back in


def test_hunt_exposes_model_check():
    out = subprocess.run([sys.executable, str(ROOT / "hunt.py"), "model-check", "--template"],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0
    assert "## 4. Invariant map" in out.stdout


def test_validator_exits_nonzero_on_a_missing_model(tmp_path):
    out = subprocess.run([sys.executable, str(ROOT / "tools" / "model_check.py"),
                          "work/_definitely_no_model_here"],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 1, "a missing model must fail the gate, not warn"


# ------------------------------------------------------------------ the skill's claims ---
def test_skill_exists_and_declares_the_six_phases():
    text = SKILL.read_text(encoding="utf-8")
    for num, name in M.PHASES:
        assert re.search(rf"##\s+Phase\s+{num}\s+[—-]\s+{re.escape(name)}", text), \
            f"phase {num} ({name}) is not documented in the skill"


def test_skill_states_the_relevance_gate_before_the_cross_product():
    text = SKILL.read_text(encoding="utf-8")
    assert "relevance gate" in text.lower()
    gate = text.lower().index("relevance gate")
    assert "never `everything × everything`" in text.lower() or \
           "everything × everything" in text.lower(), "the explosion the gate prevents is unstated"
    assert gate < text.lower().index("## coverage accounting"), \
        "the gate must be documented before the coverage figure it protects"


def test_skill_carries_the_multi_pass_protocol_and_reuses_the_resume_one():
    text = SKILL.read_text(encoding="utf-8")
    assert "## The passes" in text
    assert "dynamic-hunt" in text and "§ 5" in text, \
        "resume must reuse dynamic-hunt's protocol, not invent a second one"
    assert "A pass that ends without writing is a pass that did not happen." in text


def test_skill_carries_two_levels_of_falsification():
    text = SKILL.read_text(encoding="utf-8")
    assert "Level 1" in text and "Level 2" in text
    # the distinction that decides false positive vs finding in this family
    assert "correct isolation" in text and "security context" in text
    assert "independent" in text.lower(), "level 2 must be an independent pass, not self-review"


def test_skill_says_the_validator_checks_form_not_substance():
    """If this claim ever drops out, a PASS starts reading as a good model."""
    text = SKILL.read_text(encoding="utf-8").lower()
    assert "form" in text and "cannot judge whether an invariant is" in text


def test_skill_names_the_evidence_requirement_per_verdict():
    text = SKILL.read_text(encoding="utf-8")
    for verdict in ("yes", "no", "unreachable"):
        assert f"`{verdict}`" in text
    assert "Evidence` is mandatory" in text or "Evidence** is mandatory" in text


# ------------------------------------------------------- the enforcement layer is wired ---
def test_the_model_stage_is_a_recognised_settler():
    """A matrix row may point at the opening pass, and audit_coverage must accept it."""
    sys.path.insert(0, str(ROOT / "tools"))
    import audit_coverage as A
    assert A.MODEL in A.STAGES
    assert A.MODEL in A.reachable_labels()


def test_the_native_s1_rows_are_settled_by_the_model_pass_not_a_vague_read():
    """These two rows are where CVE-2026-109618 lives. 'static read' is not a procedure."""
    sys.path.insert(0, str(ROOT / "tools"))
    import audit_coverage as A
    for row in ("Use-after-free, uninitialised read, double free",
                "Container counter / length desync"):
        assert A.COVERS[row] == A.MODEL, f"{row!r} points at {A.COVERS[row]!r}"


def test_the_matrix_audit_still_maps_every_row():
    sys.path.insert(0, str(ROOT / "tools"))
    import audit_coverage as A
    report = A.audit()
    assert not report["unmapped"], f"rows missing from COVERS: {report['unmapped']}"
    assert not report["stale"], f"COVERS points at things that no longer exist: {report['stale']}"


def test_the_sweep_reports_the_opening_pass():
    """A class list printed with no model behind it is coverage the hunt does not have."""
    for p in (ROOT / "web", ROOT / "tools", ROOT / "static", ROOT / "dynamic"):
        sys.path.insert(0, str(p))
    import sweep
    ok, why = sweep._model_status(Path("work/_no_such_target_model"))
    assert ok is False and "no model at" in why


def test_the_orchestrator_tasks_the_model_before_the_hunters():
    text = (ROOT / ".claude" / "agents" / "sec-orchestrator.md").read_text(encoding="utf-8")
    assert "`target-model`" in text, "the orchestrator never tasks the opening pass"
    assert "hunt model-check" in text
    model_at = text.index("`target-model`")
    routed_at = text.index("Route ranked leads") if "Route ranked leads" in text else len(text)
    assert model_at < routed_at, "the model pass must be tasked before the class hunters"


def test_the_board_opens_with_the_model_row():
    text = (ROOT / ".claude" / "skills" / "run-board" / "SKILL.md").read_text(encoding="utf-8")
    assert "target-model:" in text, "the opening board has no row for the model pass"
    assert "always row 1" in text.lower() or "Row 1 is the opening pass" in text


def test_the_hunt_command_documents_the_opening_pass():
    text = (ROOT / ".claude" / "commands" / "hunt.md").read_text(encoding="utf-8")
    assert "target-model" in text and "model-check" in text


def test_every_hunter_loads_target_model():
    """The wiring half. Honest limit: tools/board.py counts a MENTION as a load, so this proves
    the name is present in the file, not that the agent obeys it."""
    hunters = sorted(p for p in AGENTS.glob("*-hunter.md"))
    assert len(hunters) > 5, "hunter discovery is broken; this test would prove nothing"
    missing = [p.name for p in hunters
               if "`target-model`" not in p.read_text(encoding="utf-8")]
    assert not missing, f"these hunters never load target-model: {missing}"
