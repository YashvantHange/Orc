#!/usr/bin/env python3
"""
Three swarms on one target must not become three times the agents, or three times the budget.

A fleet runs three hunting METHODS as peers - coverage (has every class been examined), depth (what
hides behind the abstraction layers), stack (what exists because of what this is built ON) - plus the
prove lane that turns candidates into findings. They share one target, which means one authorized
request budget and one provider rate limit.

Two failures this file exists to make impossible:

  * a fleet that silently drops a class to afford a second swarm. Coverage is not something width is
    allowed to buy, so an underfunded role must NOT LAUNCH and say why - the fleet never trades
    coverage for breadth.
  * a fleet that multiplies the agent count. 90 concurrent agents is the failure that created the
    wave cap; MAX_AGENTS is a total across all swarms, and the split is tested as such.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import fleet as F  # noqa: E402
import swarm as SW  # noqa: E402

WIDE = {"max_requests": 5000, "concurrency": 2, "rps": 2.0, "burst": 5}
MID = {"max_requests": 1500, "concurrency": 2, "rps": 2.0, "burst": 5}
TIGHT = {"max_requests": 500, "concurrency": 2, "rps": 2.0, "burst": 5}


# ================================================ coverage is structurally guaranteed ===
def test_a_fleet_without_coverage_is_refused():
    """depth and stack are additive. Without coverage nothing owns every applicable matrix row."""
    with pytest.raises(SW.SwarmError, match="exactly one `coverage` swarm"):
        SW.plan_fleet("t", "src", roles=("depth", "stack"))


def test_an_unknown_role_is_refused():
    with pytest.raises(SW.SwarmError, match="unknown role"):
        SW.plan_fleet("t", "src", roles=("coverage", "vibes"))


def test_the_coverage_swarm_still_covers_every_applicable_row():
    import shardsources as SS
    for kind, limits in (("src", None), ("url", WIDE)):
        doc = SW.plan_fleet("t", kind, limits=limits)
        cov = doc["swarms"]["coverage"]
        covered = {r for m in cov["members"] for r in m["rows"]}
        assert covered == {r[1] for r in SS.matrix_rows(kind)}, f"{kind}: coverage lost rows"


def test_coverage_launches_even_when_every_other_role_cannot():
    doc = SW.plan_fleet("t", "url", limits=MID)
    assert "coverage" in doc["roles"]
    assert doc["skipped"], "this budget should not have funded every role"
    for role, why in doc["skipped"].items():
        assert "floor" in why and "not launched" in why, f"{role} was skipped without a reason"


def test_a_budget_too_small_for_coverage_refuses_the_whole_fleet():
    """No number of swarms conjures requests the program has not authorized."""
    with pytest.raises(SW.SwarmError, match="Coverage is not negotiable"):
        SW.plan_fleet("t", "url", limits=TIGHT)


def test_an_underfunded_role_does_not_launch_at_all():
    """Launching it narrower would produce members with no budget to finish - fake rows."""
    doc = SW.plan_fleet("t", "url", limits=MID)
    for role in doc["skipped"]:
        assert role not in doc["swarms"]
        assert role not in doc["roles"]


# ========================================================== one agent ceiling, not three ===
def test_the_agent_split_never_exceeds_the_ceiling():
    for kind, limits in (("src", None), ("url", WIDE)):
        doc = SW.plan_fleet("t", kind, limits=limits)
        total = sum(doc["agents"]["per_role"].values())
        assert total <= doc["agents"]["max"], (
            f"{kind}: {total} agent slots handed out against a ceiling of {doc['agents']['max']} - "
            f"three swarms became three times the agents")


def test_three_swarms_do_not_triple_the_agent_count():
    one = SW.plan_fleet("t", "src", roles=("coverage",))
    three = SW.plan_fleet("t", "src", roles=("coverage", "depth", "stack"))
    assert sum(three["agents"]["per_role"].values()) <= F.MAX_AGENTS
    assert sum(three["agents"]["per_role"].values()) <= 3 * sum(one["agents"]["per_role"].values())


def test_every_launched_role_gets_at_least_one_slot():
    doc = SW.plan_fleet("t", "src")
    for role in doc["roles"]:
        assert doc["agents"]["per_role"][role] >= 1, f"{role} launched with no agents"


def test_a_capped_role_hands_its_surplus_back():
    """A slot given to a role that has no shards left for it is wasted, not conservative."""
    caps = {"coverage": 20, "depth": 2, "stack": 2}
    out = F.split(30, {"coverage": 3, "depth": 2, "stack": 1}, caps=caps)
    assert out["depth"] == 2 and out["stack"] == 2, "a capped role was over-allocated"
    assert out["coverage"] > 10, (
        f"coverage got {out['coverage']} - the capped roles' surplus was not re-offered")
    assert sum(out.values()) <= 30


def test_the_split_respects_caps_exactly():
    out = F.split(30, {"a": 3, "b": 2, "c": 1}, caps={"a": 1, "b": 1, "c": 1})
    assert out == {"a": 1, "b": 1, "c": 1}


def test_more_roles_than_slots_is_narrow_not_broken():
    out = F.split(2, {"a": 3, "b": 2, "c": 1}, caps={"a": 9, "b": 9, "c": 9})
    assert out == {"a": 1, "b": 1, "c": 1}


# ============================================================ one budget, split by priority ===
def test_coverage_floors_are_paid_before_any_other_role():
    doc = SW.plan_fleet("t", "url", limits=WIDE)
    b = doc["budget"]
    assert b["shares"]["coverage"] >= b["floors"]["coverage"]
    for role in doc["roles"]:
        assert b["shares"][role] >= b["floors"][role], f"{role} was funded below its own floor"


def test_the_shares_never_exceed_the_usable_budget():
    doc = SW.plan_fleet("t", "url", limits=WIDE)
    b = doc["budget"]
    assert sum(b["shares"].values()) <= b["usable"]
    assert b["usable"] == b["max_requests"] - b["reserve"]


def test_each_swarms_members_fit_inside_its_own_share():
    doc = SW.plan_fleet("t", "url", limits=WIDE)
    for role, sw in doc["swarms"].items():
        spent = sum(m["request_allowance"] for m in sw["members"])
        assert spent <= doc["budget"]["shares"][role], f"{role} overspent its share"


def test_a_src_fleet_pays_nothing():
    doc = SW.plan_fleet("t", "src")
    assert doc["budget"] is None
    for sw in doc["swarms"].values():
        assert all(m["request_allowance"] == 0 for m in sw["members"])


# ===================================================== shards are assignments, not topics ===
def test_every_member_carries_what_it_needs_to_be_graded():
    doc = SW.plan_fleet("t", "url", limits=WIDE)
    seen = set()
    for role, sw in doc["swarms"].items():
        for m in sw["members"]:
            assert m["shard_id"] not in seen, f"duplicate shard_id {m['shard_id']}"
            seen.add(m["shard_id"])
            assert m["role"] == role and m["swarm"] == role
            assert m["objective"].strip(), f"{m['shard_id']} has no objective"
            assert m["completion"], f"{m['shard_id']} has no completion criteria"
            assert m["member"].startswith(f"{role}/"), "the member label must carry its swarm"


def test_capabilities_are_recorded_and_unmet_ones_block():
    """An unmet precondition must be a plan-time BLOCKED, not a run-time CLEAR."""
    doc = SW.plan_fleet("t", "url", limits=WIDE, capabilities={"runtime": True})
    blocked = [m for sw in doc["swarms"].values() for m in sw["members"] if m["blocked_on"]]
    assert blocked, "a url fleet with no browser should block the browser-only shards"
    assert any("browser" in m["blocked_on"] for m in blocked)
    for m in blocked:
        assert m["requires"], "a member was blocked on a capability it never declared"


def test_a_fully_equipped_run_blocks_nothing():
    doc = SW.plan_fleet("t", "url", limits=WIDE,
                        capabilities={"runtime": True, "browser": True, "identities": True})
    assert not [m for sw in doc["swarms"].values() for m in sw["members"] if m["blocked_on"]]


def test_the_prove_lane_scales_with_the_fleet():
    """One undifferentiated worker would give the lane a single member however wide the fleet is."""
    doc = SW.plan_fleet("t", "src")
    prove = doc["swarms"]["prove"]
    assert prove["members_total"] > 1, "the confirmation lane cannot keep up with the fleet"
    assert all(m["agent"] == "dynamic-prover" for m in prove["members"])
    assert len({m["shard"] for m in prove["members"]}) == prove["members_total"], (
        "prove members must be partitioned by class family - aiming is class-specific")


# ================================================================== determinism ===
def test_the_fleet_hash_is_reproducible_in_process():
    a = SW.plan_fleet("t", "url", limits=WIDE)
    b = SW.plan_fleet("t", "url", limits=WIDE)
    assert a["fleet_sha256"] == b["fleet_sha256"]
    assert a["swarms"] == b["swarms"]


CHILD = """
import sys
sys.path.insert(0, {tools!r})
import swarm as SW
print(SW.plan_fleet("t", "url", limits={lim!r})["fleet_sha256"])
"""


def test_the_fleet_hash_is_reproducible_across_processes():
    src = CHILD.format(tools=str(ROOT / "tools"), lim=WIDE)
    seen = {subprocess.run([sys.executable, "-c", src], capture_output=True, text=True,
                           timeout=180).stdout.strip() for _ in range(3)}
    assert len(seen) == 1, f"fleet hash is not reproducible: {seen}"
    assert seen.pop() == SW.plan_fleet("t", "url", limits=WIDE)["fleet_sha256"]


def test_the_hash_changes_when_the_split_changes():
    base = SW.plan_fleet("t", "src")
    narrower = SW.plan_fleet("t", "src", max_agents=12)
    assert base["fleet_sha256"] != narrower["fleet_sha256"], (
        "a different agent split produced the same fleet hash - a resume could not tell them apart")


def test_the_hash_changes_when_a_role_is_dropped():
    full = SW.plan_fleet("t", "src", roles=("coverage", "depth", "stack"))
    thin = SW.plan_fleet("t", "src", roles=("coverage", "depth"))
    assert full["fleet_sha256"] != thin["fleet_sha256"]


def test_each_swarm_keeps_its_own_binding():
    doc = SW.plan_fleet("t", "src")
    hashes = {r: sw["plan_sha256"] for r, sw in doc["swarms"].items()}
    assert len(set(hashes.values())) == len(hashes), "two roles produced the same plan hash"
