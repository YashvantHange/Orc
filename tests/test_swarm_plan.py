#!/usr/bin/env python3
"""
Sizing must be computed, explained, and reproducible - and it must never buy width with coverage.

Two rules are load-bearing here and each has its own failure mode:

  * Weight sets RESOURCES, not COVERAGE. The tempting optimisation - drop the low-severity classes
    when the budget is tight - contradicts vuln-playbooks ("an unexamined class is an unfinished
    hunt") and would make the swarm systematically blind to whole classes rather than merely slower.
    So the tight-budget test asserts a REFUSAL, not a smaller plan.

  * Planning is deterministic. state.json binds to plan_sha256; if the same inputs can produce two
    hashes, a resume silently continues a swarm that was never planned. The determinism test runs
    across processes because in-process dict ordering is not the interesting case.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import swarm as SW  # noqa: E402

WIDE = {"max_requests": 5000, "concurrency": 2, "rps": 2.0, "burst": 5}
TIGHT = {"max_requests": 500, "concurrency": 2, "rps": 2.0, "burst": 5}


def owners_of(doc) -> set:
    return {m["agent"] for m in doc["members"]}


# ============================================================== width is a maximum ===
def test_hard_ceiling_is_thirty():
    doc = SW.plan("t", "src", requested=999)
    assert doc["width"] <= 30
    assert SW.HARD_CEILING == 30


def test_width_is_a_maximum_never_a_floor():
    small = SW.plan("t", "src", requested=11)
    assert small["width"] == 11, "a requested width below the ceiling must be honoured exactly"
    assert small["sizing"]["requested"] == 11
    big = SW.plan("t", "src", requested=30)
    assert big["width"] > small["width"], "the plan must actually respond to --width"


def test_every_member_has_a_distinct_shard():
    doc = SW.plan("t", "src", requested=30)
    pairs = [(m["agent"], m["shard"]) for m in doc["members"]]
    assert len(pairs) == len(set(pairs)), "two members were given the same class and shard"


# ================================================= src does not pay a network price ===
def test_src_skips_the_budget_branch_entirely():
    """Reading files costs no requests. Sizing a src swarm against a request budget would shrink
    it for a constraint that does not exist."""
    doc = SW.plan("t", "src", requested=30)
    assert doc["sizing"]["budget_allows"] is None
    assert doc["sizing"]["concurrency_allows"] is None
    assert doc["budget"] is None
    assert all(m["request_allowance"] == 0 for m in doc["members"])


def test_src_needs_no_scope_at_all():
    SW.plan("t", "src", requested=30, limits=None)   # must not raise


def test_a_url_swarm_refuses_to_size_without_limits():
    with pytest.raises(SW.SwarmError, match="limits"):
        SW.plan("t", "url", requested=30, limits=None)


# ========================================================= budget shrinks, loudly ===
def test_budget_shrinks_the_width_and_says_why():
    doc = SW.plan("t", "url", requested=30, limits=WIDE)
    s = doc["sizing"]
    assert doc["width"] == min(s["budget_allows"], s["concurrency_allows"], 30)
    assert s["usable"] == s["budget"] - s["reserve"]
    assert s["required_for_floor"] > 0
    assert doc["width"] < 30, "a 2-rps program should not sustain a 30-wide swarm"


def test_concurrency_saturation_caps_width():
    starved = {"max_requests": 10 ** 6, "concurrency": 1, "rps": 2.0, "burst": 5}
    doc = SW.plan("t", "url", requested=30, limits=starved)
    assert doc["sizing"]["concurrency_allows"] == SW.TUNING["saturation"]
    assert doc["width"] <= SW.TUNING["saturation"], (
        "members beyond what the wire can feed are fake rows: they sit blocked on a lease")
    # A thin wire costs passes, never classes.
    assert doc["passes"] > 1
    covered = {r for m in doc["members"] for r in m["rows"]}
    assert covered == {r[1] for r in SW.applicable_rows("url")}


def test_allowances_never_exceed_the_usable_budget():
    doc = SW.plan("t", "url", requested=30, limits=WIDE)
    assert sum(m["request_allowance"] for m in doc["members"]) <= doc["sizing"]["usable"]


def test_higher_weight_gets_at_least_as_much_budget():
    doc = SW.plan("t", "url", requested=30, limits=WIDE)
    by_w = {}
    for m in doc["members"]:
        by_w.setdefault(m["weight"], []).append(m["request_allowance"])
    for lo, hi in ((1, 2), (2, 3)):
        if lo in by_w and hi in by_w:
            assert min(by_w[hi]) >= max(by_w[lo]), "weight did not buy headroom"


# =================================== coverage is not something width is allowed to buy ===
def test_a_tight_budget_refuses_rather_than_dropping_a_class():
    """THE test of this file. Shrinking to fit by dropping low-weight classes would make the swarm
    blind to them while still reporting a completed plan."""
    with pytest.raises(SW.SwarmError) as e:
        SW.plan("t", "url", requested=30, limits=TIGHT)
    msg = str(e.value)
    assert "Coverage is not negotiable" in msg
    assert "cover the matrix" in msg


def test_every_applicable_matrix_row_has_an_owner():
    for kind, limits in (("src", None), ("url", WIDE), ("grey", WIDE)):
        doc = SW.plan("t", kind, requested=30, limits=limits)
        covered = {r for m in doc["members"] for r in m["rows"]}
        expected = {r[1] for r in SW.applicable_rows(kind)}
        assert covered == expected, f"{kind}: {sorted(expected - covered)[:3]} left unowned"


def test_low_weight_classes_still_get_a_member():
    doc = SW.plan("t", "url", requested=30, limits=WIDE)
    weights = {m["weight"] for m in doc["members"]}
    assert 1 in weights, (
        "a weight-1 class got zero members - weight is a priority, not a filter")


def test_even_the_minimum_width_covers_every_owner_across_passes():
    """--width caps CONCURRENT members. Coverage is reached over more passes, never by dropping a
    class - so width 1 means one at a time, not one in total."""
    doc = SW.plan("t", "src", requested=1)
    assert doc["width"] == 1
    assert doc["passes"] == doc["sizing"]["coverage_floor"]
    assert doc["members_total"] == doc["sizing"]["coverage_floor"]
    covered = {r for m in doc["members"] for r in m["rows"]}
    assert covered == {r[1] for r in SW.applicable_rows("src")}


def test_no_pass_is_wider_than_the_concurrent_ceiling():
    doc = SW.plan("t", "src", requested=4)
    per_pass = {}
    for m in doc["members"]:
        per_pass[m["pass"]] = per_pass.get(m["pass"], 0) + 1
    assert max(per_pass.values()) <= 4, f"a pass exceeded the requested concurrent width: {per_pass}"


def test_the_first_pass_carries_the_heaviest_classes():
    """Serious ones first: if the swarm must be split, severity decides who runs now."""
    doc = SW.plan("t", "src", requested=3)
    assert doc["passes"] > 1
    first = [m["weight"] for m in doc["members"] if m["pass"] == 1]
    last = [m["weight"] for m in doc["members"] if m["pass"] == doc["passes"]]
    assert min(first) >= max(last), f"pass 1 weights {first} did not outrank final pass {last}"


# ================================================================== determinism ===
def test_same_inputs_same_plan_in_process():
    a = SW.plan("t", "url", requested=30, limits=WIDE)
    b = SW.plan("t", "url", requested=30, limits=WIDE)
    assert a["plan_sha256"] == b["plan_sha256"]
    assert a["members"] == b["members"]


CHILD = """
import json, sys
sys.path.insert(0, {tools!r})
import swarm as SW
print(SW.plan("t", "url", requested=30, limits={lim!r})["plan_sha256"])
"""


def test_same_inputs_same_plan_across_processes():
    """In-process repetition can hide an ordering dependency that a fresh interpreter exposes."""
    src = CHILD.format(tools=str(ROOT / "tools"), lim=WIDE)
    seen = {subprocess.run([sys.executable, "-c", src], capture_output=True, text=True,
                           timeout=120).stdout.strip() for _ in range(3)}
    assert len(seen) == 1, f"plan hash is not reproducible across processes: {seen}"
    assert seen.pop() == SW.plan("t", "url", requested=30, limits=WIDE)["plan_sha256"]


def test_tuning_is_part_of_the_hash(tmp_path):
    """Overridable constants that are not hashed would break the binding the hash exists for."""
    base = SW.plan("t", "url", requested=30, limits=WIDE)
    (tmp_path / "swarm").mkdir()
    (tmp_path / "swarm" / "tuning.json").write_text(
        json.dumps({"reserve_frac": 0.5}), encoding="utf-8")
    tuned = SW.plan("t", "url", requested=30, limits=WIDE, target_dir=tmp_path)
    assert tuned["tuning"]["reserve_frac"] == 0.5
    assert tuned["plan_sha256"] != base["plan_sha256"], (
        "re-tuning must invalidate an in-flight plan, not silently reuse its hash")


def test_the_hash_ignores_when_it_was_made():
    doc = SW.plan("t", "src", requested=30)
    assert SW.plan_hash(dict(doc, sized_at="1999-01-01T00:00:00Z")) == doc["plan_sha256"]
