#!/usr/bin/env python3
"""
The discipline sweep: enumerate a population, classify it, and the minority is the suspect.

Why this capability was added, recorded here so the tests are not mysterious. A hunter found a real
asymmetry in PHP's `main/SAPI.c` by accident - three `request_info` fields are freed AND nulled, two
are freed without being nulled - while reading an 18-line window. Nothing in the pipeline looked for
that on purpose: an audit of all 21 agents found zero that enumerate a population of call sites and
look for the odd one out. The one place the move appeared at all was `reasoning-checklist` item 5,
pointed BACKWARDS - grep for siblings once you already have a finding.

The harder shape needs it pointed forwards. PHP's 2026-10-21 fix threaded a `fallible` flag through
EVERY hash-table allocation path, which is a systemic discipline problem no per-structure question
reaches.

Run:  .venv/Scripts/python.exe -m pytest tests/test_discipline_sweep.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "static"))

import census  # noqa: E402

SKILL = ROOT / ".claude" / "skills" / "target-model" / "SKILL.md"
CHECKLIST = ROOT / ".claude" / "skills" / "reasoning-checklist" / "SKILL.md"
AGENTS = ROOT / ".claude" / "agents"
PHP = ROOT / "work" / "php-prepatch" / "src"


# --------------------------------------------------------------------- the census counts ---
def test_census_finds_the_minority_in_a_seeded_population(tmp_path):
    """Five siblings, two of which skip the rule."""
    (tmp_path / "x.c").write_text(
        "void f(void){\n"
        "  if (a) { free(a); a = NULL; }\n"
        "  if (b) { free(b); b = NULL; }\n"
        "  if (c) { free(c); c = NULL; }\n"
        "  if (d) { free(d); }\n"
        "  if (e) { free(e); }\n"
        "}\n", encoding="utf-8")
    r = census.census(tmp_path, r"free\(", r"= NULL", glob="*.c", window=0)
    assert r["population"] == 5
    assert r["minority"] == 2
    assert [m["line"] for m in r["odd_ones_out"]] == [5, 6]


def test_census_reports_uniform_when_every_member_upholds(tmp_path):
    (tmp_path / "x.c").write_text(
        "free(a); a = NULL;\nfree(b); b = NULL;\n", encoding="utf-8")
    r = census.census(tmp_path, r"free\(", r"= NULL", glob="*.c", window=0)
    assert r["minority"] == 0 and r["population"] == 2


def test_census_distinguishes_an_empty_population_from_a_clean_one(tmp_path):
    """A pattern that matches nothing says the pattern is wrong, not that the code is fine."""
    (tmp_path / "x.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    r = census.census(tmp_path, r"nothing_matches_this", r"= NULL", glob="*.c")
    assert r["population"] == 0
    assert r["ratio"] == "0/0"


def test_census_window_is_the_site_not_the_file(tmp_path):
    """A rule upheld 200 lines away is not upheld AT the site that owes it."""
    body = "free(a);\n" + "\n" * 50 + "a = NULL;\n"
    (tmp_path / "x.c").write_text(body, encoding="utf-8")
    near = census.census(tmp_path, r"free\(", r"= NULL", glob="*.c", window=2)
    far = census.census(tmp_path, r"free\(", r"= NULL", glob="*.c", window=60)
    assert near["minority"] == 1, "a distant assignment must not count as upholding"
    assert far["minority"] == 0, "a wide window should find it"


def test_census_skips_vendored_trees(tmp_path):
    (tmp_path / "x.c").write_text("free(a);\n", encoding="utf-8")
    v = tmp_path / "node_modules"
    v.mkdir()
    (v / "y.c").write_text("free(b);\n", encoding="utf-8")
    r = census.census(tmp_path, r"free\(", "", glob="**/*.c")
    assert r["population"] == 1, "vendored code must not join the population"


# ------------------------------------------- the real case it was built from, if present ---
@pytest.mark.skipif(not (PHP / "main" / "SAPI.c").exists(), reason="php-src not cloned")
def test_census_reproduces_the_asymmetry_a_hunter_found_by_luck():
    """main/SAPI.c: 3 fields freed AND nulled, 2 freed without. Found by accident; now mechanical."""
    r = census.census(PHP, r"efree\(SG\(request_info\)", r"= NULL",
                      glob="main/SAPI.c", window=2)
    assert r["population"] >= 5, f"population too small to be the right pattern: {r['population']}"
    assert r["minority"] == 2, f"expected 2 odd ones out, got {r['minority']}"
    odd = {m["text"] for m in r["odd_ones_out"]}
    assert any("content_type_dup" in t for t in odd)
    assert any("current_user" in t for t in odd)


@pytest.mark.skipif(not (PHP / "Zend" / "zend_hash.c").exists(), reason="php-src not cloned")
def test_a_universally_unupheld_rule_is_the_population_not_a_minority():
    """The shape that reaches PHP2Shell: nobody checks, because failure never returns."""
    r = census.census(PHP, r"\b(emalloc|ecalloc|erealloc|pemalloc|safe_emalloc)\b",
                      r"if \(.*(NULL|!)", glob="Zend/zend_hash.c", window=2)
    assert r["population"] >= 15
    assert r["minority_share"] >= 80, \
        "at the pre-fix commit essentially no allocation site checks for failure"


# ------------------------------------------------------------------ the method carries it ---
def _flat(p: Path) -> str:
    """Collapse whitespace before asserting on prose: these files are hard-wrapped at ~100 cols,
    so a phrase assertion that spans a line break fails for no reason that matters."""
    import re as _re
    return _re.sub(r"\s+", " ", p.read_text(encoding="utf-8"))


def test_the_skill_has_phase_seven():
    text = _flat(SKILL)
    assert "Phase 7" in text and "Discipline sweep" in text
    assert "the minority is the suspect" in text


def test_the_skill_says_uniformity_cuts_both_ways():
    """A uniform population is not automatically a clean result - that is the hard-shape branch."""
    text = _flat(SKILL)
    assert "Uniformity cuts both ways" in text
    assert "the population is the finding" in text
    assert "20 of 20" in text, "the measured ratio makes the claim checkable"


def test_the_skill_names_the_inversion_it_is_correcting():
    text = _flat(SKILL)
    assert "reasoning-checklist" in text and "backwards" in text


def test_the_checklist_points_item_five_both_ways():
    text = _flat(CHECKLIST)
    assert "Phase 7" in text, "item 5 must name the forwards version"
    assert "census.py" in text


def test_every_hunter_carries_the_discipline_sweep():
    hunters = sorted(AGENTS.glob("*-hunter.md"))
    assert len(hunters) > 5
    missing = [p.name for p in hunters
               if "Phase 7, the discipline sweep" not in p.read_text(encoding="utf-8")]
    assert not missing, f"these hunters cannot sweep a discipline: {missing}"


def test_census_is_documented_as_counting_not_judging():
    """The division of labour the user asked for: agents reason, scripts count."""
    src = (ROOT / "tools" / "census.py").read_text(encoding="utf-8")
    assert "It finds nothing on its own" in src
    assert "hopeless at judging" in src
