#!/usr/bin/env python3
"""
Guards the five-fixture corpus for the opening pass, and the separation of the grading key.

These tests do NOT run a hunter — an agent is not callable from pytest. They assert the corpus has
not rotted (a repaired fixture makes the exam untestable), that the defences in the four controls
are still present so "not reported" can mean *defended* rather than *missed*, and that the
reference invariant set stays out of the fixture tree so the exam stays blind.

Run:  .venv/Scripts/python.exe -m pytest tests/test_model_corpus.py -q
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "work" / "_selftest" / "model_corpus"
REFERENCE = ROOT / "tests" / "data" / "model_corpus_reference.json"

pytestmark = pytest.mark.skipif(not CORPUS.exists(), reason="model_corpus fixture not present")


def seeds() -> dict:
    return json.loads((CORPUS / "seeds.json").read_text(encoding="utf-8"))


def src(name: str) -> str:
    return (CORPUS / name).read_text(encoding="utf-8")


# ------------------------------------------------------------------ the corpus is intact ---
def test_all_five_fixtures_exist():
    files = [f["file"] for f in seeds()["fixtures"]]
    assert len(files) == 5
    for f in files:
        assert (CORPUS / f).exists(), f"{f} is missing"


def test_exactly_one_fixture_is_vulnerable():
    """One defect and four ways of being safe. The controls are the test."""
    vuln = [f["id"] for f in seeds()["fixtures"] if f.get("is_vulnerable")]
    assert len(vuln) == 1, f"expected exactly one vulnerable fixture, got {vuln}"


def test_the_vulnerable_fixture_still_has_its_three_places():
    """DO NOT FIX THE FIXTURE. The defect is a relationship, so all three sites must be present."""
    a = next(f for f in seeds()["fixtures"] if f.get("is_vulnerable"))
    text = src(a["file"])
    for part in ("mutation", "interrupt", "consumer"):
        marker = a[part]["marker"]
        hay = text if part != "interrupt" else text + src("arena.c")
        assert marker in hay, f"{a['file']}: the {part} marker {marker!r} is gone - fixture repaired?"


def test_every_control_still_carries_its_defence():
    """A control that lost its defence would silently become a second vulnerable fixture, and
    'not reported' would then be a miss recorded as a pass."""
    for f in seeds()["fixtures"]:
        if f.get("is_vulnerable"):
            continue
        assert f["defense_marker"] in src(f["file"]), \
            f"{f['file']}: defence {f['defense_marker']!r} is gone - this control is now unsafe"


def test_the_abnormal_exit_is_non_local():
    """A checked-return failure would not exercise this defect class at all."""
    ex = seeds()["abnormal_exit"]
    assert ex["mechanism"] == "longjmp"
    text = src(ex["file"])
    assert "longjmp" in text and "return NULL" not in text, \
        "arena_alloc must longjmp, never return NULL - the caller must not get a chance to clean up"


def test_the_suspicious_control_really_does_look_like_the_defect():
    """Fixture C only earns its place if a pattern would match it. If it stops sharing the
    defect's shape it stops catching anything."""
    a, c = src("a_vulnerable.c"), src("c_suspicious.c")
    assert "t->nNumUsed++" in a and "t->nNumUsed++" in c, \
        "C must keep the increment-first shape, or it no longer catches a shape-matcher"
    assert "i < t->nNumUsed" in a and "i < t->nNumUsed" in c, \
        "C must keep the count-walking destructor"


def test_the_rollback_control_is_interrupted_for_real():
    """Fixture D's whole point is that the exit DOES fire and is repaired elsewhere."""
    d = src("d_rolledback.c")
    assert "t->nNumUsed++" in d, "D must have the same window as A"
    assert "table_rollback" in d and "t->nNumUsed = t->committed;" in d
    assert "table_rollback(&t);" in d, "the rollback must actually be called on the bailout path"


def test_the_cross_scope_control_clears_before_the_arena_dies():
    """Order matters: nulling AFTER arena_reset would leave the very window E exists to lack.

    Asserted as an ordering inside rshutdown, not as adjacent lines - a comment between them is
    not a defect, and a test that breaks on formatting teaches people to delete the test.
    """
    e = src("e_crossscope.c")
    body = e[e.index("static void rshutdown"):]
    body = body[:body.index("\n}")]
    assert "MG(last_upload_name) = NULL;" in body, "rshutdown must null the global"
    assert "arena_reset" in body, "rshutdown must reset the arena"
    assert body.index("MG(last_upload_name) = NULL;") < body.index("arena_reset"), \
        "the global must be nulled BEFORE the arena it points into is reset"


def test_the_cross_scope_control_keeps_its_decoy():
    """request_count is correctly process-scoped; flagging it is a false positive."""
    e = src("e_crossscope.c")
    assert "request_count" in e
    assert "NOT cleared" in e, "the decoy's comment explains why flagging it is wrong - keep it"


# --------------------------------------------------------- the grading key stays held out ---
def test_the_reference_key_exists_and_is_outside_the_fixture_tree():
    assert REFERENCE.exists(), "the exam has no grading key"
    assert CORPUS not in REFERENCE.parents, "the key must not live where a hunter reads"


def test_the_fixture_tree_does_not_leak_the_reference():
    """A hunter reads its target. If the answer is in the target, the exam measures nothing."""
    ref = json.loads(REFERENCE.read_text(encoding="utf-8"))
    ids = [i["id"] for i in ref["reference_invariants"]]
    for p in CORPUS.rglob("*"):
        if not p.is_file() or p.suffix in (".exe", ".obj", ".pdb", ".ilk"):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        leaked = [i for i in ids if i in text]
        assert not leaked, f"{p.name} names reference invariants {leaked} - the exam is no longer blind"


def test_the_reference_covers_both_cve_shapes_and_a_decoy():
    ref = json.loads(REFERENCE.read_text(encoding="utf-8"))
    invs = ref["reference_invariants"]
    assert any("109618" in (i.get("note") or "") for i in invs), "no S1 reference invariant"
    assert any("109619" in (i.get("note") or "") for i in invs), "no S2 reference invariant"
    assert any(i.get("is_decoy") for i in invs), "no decoy - false positives would go unmeasured"


def test_the_reference_says_an_unmatched_invariant_is_adjudicated():
    """Auto-scoring an unmatched row as wrong would punish the discovery this exists to produce."""
    ref = json.loads(REFERENCE.read_text(encoding="utf-8"))
    how = " ".join(ref["_how_to_use"])
    assert "ADJUDICATED" in how
    assert "missed by the reference" in how


def test_the_headline_result_requires_both_halves():
    ref = json.loads(REFERENCE.read_text(encoding="utf-8"))
    assert "silent on all four controls" in ref["headline_result"]
    assert "Both halves are required" in ref["headline_result"]


# ------------------------------------------------------------------- the exam-integrity gate ---
def _exam_check(key: str):
    import subprocess
    import sys as _s
    return subprocess.run([_s.executable, str(ROOT / "tools" / "exam_check.py"), key],
                          capture_output=True, text=True, timeout=600, cwd=str(ROOT))


def test_the_corpus_is_certified_blind_on_real_terms():
    """BLIND must be earned by searching for something. A pass on 0 terms is worthless."""
    out = _exam_check("tests/data/model_corpus_reference.json")
    assert out.returncode == 0, out.stdout + out.stderr
    assert "BLIND" in out.stdout
    n = int(re.search(r"terms searched\s*:\s*(\d+)", out.stdout).group(1))
    assert n >= 5, f"certified BLIND on only {n} terms - the check barely ran"


def test_php_src_is_recorded_as_compromised():
    """The leak is real and permanent: the skills and a memory file both name the answer."""
    out = _exam_check("tests/data/php_prepatch_reference.json")
    assert out.returncode == 1, out.stdout + out.stderr
    assert "COMPROMISED" in out.stdout
    assert "excludes the answer" in out.stdout, \
        "the gate must explain why a brief cannot repair this, or someone will try"


def test_a_key_with_no_declared_answer_locations_is_UNKNOWN_not_blind(tmp_path):
    """The flaw this gate was born with: it certified BLIND after searching for nothing."""
    k = tmp_path / "empty_key.json"
    k.write_text(json.dumps({"target": "nowhere", "reference_invariants": []}), encoding="utf-8")
    out = _exam_check(str(k))
    assert out.returncode == 2, out.stdout + out.stderr
    assert "UNKNOWN" in out.stdout and "NOT a blind certification" in out.stdout


def test_the_gate_searches_the_memory_stores():
    """The vector the first exam missed. Consulting memory is a hunter's mandatory first step."""
    src = (ROOT / "tools" / "exam_check.py").read_text(encoding="utf-8")
    assert "MEMORY_DIRS" in src
    assert src.count("memory") >= 3, "memory must be a first-class corpus, not an afterthought"


def test_the_gate_terms_are_navigable_not_english():
    """It first pulled 'integrity' out of 'state-integrity' and reported 40 phantom leaks."""
    sys.path.insert(0, str(ROOT / "tools"))
    import exam_check as E
    terms = E.answer_terms(json.loads(REFERENCE.read_text(encoding="utf-8")))
    assert terms, "no terms extracted from the corpus key"
    for t in terms:
        assert "_" in t or re.fullmatch(r"[\w/]+\.[ch]", t) or t.startswith(("GHSA-", "CVE-")), \
            f"{t!r} is an English word, not a navigation target"


# ------------------------------------------------- the exam records its result on disk ---
def _exam_run(target: str, key: str, write: bool = False):
    """--no-write by default: these tests check exit codes and must not clobber a real record."""
    import subprocess
    cmd = [sys.executable, str(ROOT / "tools" / "exam_run.py"), target, "--reference", key]
    if not write:
        cmd.append("--no-write")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=900, cwd=str(ROOT))


EXAM_RECORD = ROOT / "work" / "php-prepatch" / "exam" / "result.json"


@pytest.mark.skipif(not EXAM_RECORD.exists(), reason="no recorded php-prepatch exam")
def test_the_exam_record_has_every_stage():
    """An unrecorded measurement cannot be audited or compared against the next iteration."""
    d = json.loads(EXAM_RECORD.read_text(encoding="utf-8"))
    for k in ("target", "ran_at", "reference", "measures_discovery", "headline",
              "integrity", "model_check", "score"):
        assert k in d, f"the exam record is missing {k!r}"
    assert d["integrity"]["verdict"] in ("BLIND", "COMPROMISED", "UNKNOWN")
    assert d["model_check"]["verdict"] in ("PASS", "FAIL")


@pytest.mark.skipif(not EXAM_RECORD.exists(), reason="no recorded php-prepatch exam")
def test_a_compromised_record_never_reads_as_a_discovery_result():
    """The failure mode: printing a recall figure that looks like a capability measurement."""
    d = json.loads(EXAM_RECORD.read_text(encoding="utf-8"))
    if d["integrity"]["verdict"] != "COMPROMISED":
        pytest.skip("this record is not compromised")
    assert d["measures_discovery"] is False
    assert "NOT a discovery measurement" in d["headline"]
    assert d["integrity"]["leak_count"] > 0
    assert d["integrity"]["leaks"], "a compromised verdict must carry the leaks that caused it"


@pytest.mark.skipif(not EXAM_RECORD.exists(), reason="no recorded php-prepatch exam")
def test_the_model_check_block_keeps_its_form_only_caveat():
    d = json.loads(EXAM_RECORD.read_text(encoding="utf-8"))
    assert "form only" in d["model_check"]["note"]


@pytest.mark.skipif(not EXAM_RECORD.exists(), reason="no recorded php-prepatch exam")
def test_unmatched_rows_are_recorded_as_todo_not_as_failures():
    d = json.loads(EXAM_RECORD.read_text(encoding="utf-8"))
    rows = d["score"]["unmatched_rows_FOR_ADJUDICATION"]
    assert rows, "the record lost the adjudication queue"
    for r in rows:
        assert r["adjudication"].startswith("TODO"), \
            "an unmatched row must stay an open question, not be scored wrong"


def test_exam_run_exits_three_on_a_compromised_target():
    out = _exam_run("work/php-prepatch/src", "tests/data/php_prepatch_reference.json")
    assert out.returncode == 3, f"rc={out.returncode}\n{out.stdout}{out.stderr}"
    assert "NOT a discovery measurement" in out.stdout


def test_exam_run_exits_two_when_integrity_cannot_be_checked(tmp_path):
    k = tmp_path / "k.json"
    k.write_text(json.dumps({"target": "x", "reference_invariants": []}), encoding="utf-8")
    out = _exam_run("work/php-prepatch/src", str(k))
    assert out.returncode == 2, f"rc={out.returncode}\n{out.stdout}"
    assert "Unmeasured" in out.stdout


def test_hunt_exposes_exam():
    import subprocess
    out = subprocess.run([sys.executable, str(ROOT / "hunt.py"), "exam", "--help"],
                         capture_output=True, text=True, timeout=180, cwd=str(ROOT))
    assert out.returncode == 0
    assert "--reference" in out.stdout


# --------------------------------------------------------------- documentation integrity ---
def test_readme_forbids_fixing_the_fixtures():
    text = (CORPUS / "README.md").read_text(encoding="utf-8")
    assert "DO NOT FIX" in text
    assert "MSAN" in text, "the ASAN-vs-MSAN caveat must stay; it is why A's evidence is subtle"


def test_seeds_record_the_sanitizer_caveat():
    s = seeds()
    assert "MSAN" in s["sanitizer"]["caveat"]
    assert "BLOCKED" in s["sanitizer"]["caveat"]
