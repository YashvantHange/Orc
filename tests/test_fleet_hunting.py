#!/usr/bin/env python3
"""
Does a fleet actually get a bug from discovery to a ranked finding?

WHAT THIS TEST DOES AND DOES NOT DO - read this before trusting it.

It exercises the full pipeline CONTRACT against a real seeded target: plan a fleet, distribute
shards, record what members return, hand a lead over, confirm it, merge duplicates, rank. The member
returns are SIMULATED - pytest cannot dispatch LLM subagents - so this proves the machinery carries a
finding end to end, and it does NOT prove that an agent's judgment would have found it. Those are
different claims and conflating them is exactly the "looks covered, cannot fire" defect this repo
keeps catching.

What it DOES prove about hunting, independent of any agent:

  * the seeded bugs are still where seeds.json says they are, so the fixture cannot rot silently;
  * the depth-only bug is genuinely invisible to a surface read - the entry file does not contain
    the sink, and only following the registry reaches it. That is the measurable justification for
    the depth role existing at all, and if it ever stops being true this test fails;
  * the negative control really is defended, so "no finding here" means defended rather than missed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "work" / "_selftest" / "src_app"
sys.path.insert(0, str(ROOT / "tools"))

import swarm as SW  # noqa: E402
import swarm_queue as Q  # noqa: E402

pytestmark = pytest.mark.skipif(
    not (FIXTURE / "seeds.json").exists(),
    reason=f"seeded fixture missing at {FIXTURE} - see its README")


def seeds() -> list:
    return json.loads((FIXTURE / "seeds.json").read_text(encoding="utf-8"))["seeds"]


def seed(sid: str) -> dict:
    return next(s for s in seeds() if s["id"] == sid)


def src(name: str) -> str:
    return (FIXTURE / name).read_text(encoding="utf-8")


@pytest.fixture
def target(tmp_path, monkeypatch):
    monkeypatch.setattr(Q, "swarm_dir", lambda t: tmp_path / "swarm")
    return "_selftest_fleet"


# ========================================================= the fixture has not rotted ===
@pytest.mark.parametrize("sid", [s["id"] for s in seeds()])
def test_every_seed_is_still_where_the_manifest_says(sid):
    s = seed(sid)
    text = src(s["file"])
    assert s["symbol"] in text, f"{sid}: {s['symbol']} is gone from {s['file']}"
    assert s["marker"] in text, f"{sid}: the {s['marker']!r} marker is gone from {s['file']}"


def test_the_depth_seed_is_genuinely_invisible_to_a_surface_read():
    """THE justification for the depth role. If a surface read finds it, depth adds nothing here."""
    s = seed("depth-exec")
    entry = src(s["entry"])
    assert s["entry_symbol"] in entry, "the entry route vanished"
    assert s["marker"] not in entry, (
        f"{s['marker']!r} is visible in {s['entry']} - the seed is no longer registry-hidden, so "
        f"this fixture no longer distinguishes depth hunting from surface hunting")
    # ... and following the indirection does reach it.
    assert "REGISTRY" in src("registry.py")
    assert s["marker"] in src(s["file"]), "the sink is not at the end of the registry hop either"


def test_the_negative_control_is_actually_defended():
    """'No finding' must mean defended, not missed - otherwise it tests nothing."""
    s = seed("negative-control")
    text = src(s["file"])
    assert "shell=False" in text and "ALLOWED_FORMATS" in text, "the defense was removed"
    assert s.get("is_vulnerable") is False
    body = text.split("def run_export", 1)[1].split("\ndef ", 1)[0]
    assert "os.system" not in body, "the negative control became a real bug"


def test_the_surface_readable_seeds_really_are_readable():
    for s in seeds():
        if s.get("surface_readable") and s.get("is_vulnerable", True):
            assert s["marker"] in src(s["file"])


# ============================================= a fleet plans over the real fixture ===
def test_a_fleet_sizes_over_the_fixture_and_covers_everything():
    import shardsources as SS
    doc = SW.plan_fleet("_selftest_fleet", "src")
    assert set(doc["roles"]) >= {"coverage", "depth", "stack", "prove"}
    covered = {r for m in doc["swarms"]["coverage"]["members"] for r in m["rows"]}
    assert covered == {r[1] for r in SS.matrix_rows("src")}


def test_the_depth_swarm_actually_shards_the_indirection_that_hides_the_seed():
    doc = SW.plan_fleet("_selftest_fleet", "src")
    shards = [r for m in doc["swarms"]["depth"]["members"] for r in m["rows"]]
    assert seed("depth-exec")["indirection"] in shards, (
        "no depth member is assigned the indirection the seeded bug hides behind")


def test_the_indirection_goes_to_the_hunter_that_owns_the_seeds_class():
    import shardsources as SS
    owner = next(r["owner"] for r in SS.indirection_rows()
                 if r["pattern"] == seed("depth-exec")["indirection"])
    assert owner == "rce-exec-hunter", (
        f"the registry indirection is assigned to {owner}, but the bug behind it is code execution")


# ================================== discovery -> candidate -> handoff -> confirmation ===
def test_a_lead_travels_from_discovery_to_a_ranked_finding(target):
    """The contract, end to end. Member returns are simulated; the pipeline is real."""
    s = seed("depth-exec")
    sink = f"{s['file']}:{s['symbol']}"

    # 1. DISCOVERY - a depth member reaches the sink through the registry, but cannot fire it.
    cand = Q.record(target, vuln_class="code-execution", agent="depth/rce-exec-hunter#1",
                    sink=sink, effect="eval on request body", status="NEW", cwe=s["cwe"])
    assert cand["status"] == "NEW", "a read produced a CONFIRMED without anything being run"

    # 2. HANDOFF - with the aim, which is the prover's measured failure mode.
    ho = Q.handoff(target, from_member="depth/rce-exec-hunter#1", to_agent="prove/dynamic-prover#1",
                   fingerprint=cand["fingerprint"],
                   reason="eval reached via REGISTRY['template']; route only passes a name",
                   aim="POST /plugin?kind=template, body.content")
    assert ho["finding_id"] == cand["finding_id"], "the handoff forked a second finding"
    assert ho["handoffs"][0]["aim"], "the aim was dropped - this recreates the unaimed sweep"
    assert "prove/dynamic-prover#1" in ho["agents"]

    # 3. CONFIRMATION - the prover fires it and the SAME finding is upgraded, not duplicated.
    proved = Q.record(target, vuln_class="code-execution", agent="prove/dynamic-prover#1",
                      sink=sink, effect="eval on request body", status="CONFIRMED",
                      cvss=9.8, preconditions=0, evidence="evidence/F001/")
    assert proved["finding_id"] == cand["finding_id"]
    assert proved["status"] == "CONFIRMED"
    assert len(Q.load(target)["findings"]) == 1, "confirmation created a second finding"

    # 4. RANKED, and it is the one the lane opens on.
    assert Q.lane_candidate(target)["finding_id"] == proved["finding_id"]


def test_two_roles_reaching_one_sink_produce_one_candidate(target):
    """At fleet width this is the DEFAULT, not an edge case: roles overlap by design."""
    for agent in ("coverage/rce-exec-hunter#1", "depth/rce-exec-hunter#2", "stack/rce-exec-hunter#1"):
        Q.record(target, vuln_class="command-injection", agent=agent,
                 sink="app.py:run_report", effect="argv in shell string", status="NEW")
    findings = Q.load(target)["findings"]
    assert len(findings) == 1, f"{len(findings)} findings for one sink - three reports for one bug"
    assert len(findings[0]["agents"]) == 3, "the contributors were not all recorded"
    assert findings[0]["merged"] == 3


def test_the_confirmed_bug_outranks_the_unconfirmed_one(target):
    Q.record(target, vuln_class="code-execution", agent="depth/rce-exec-hunter#1",
             sink="handlers.py:render_template", effect="eval", status="NEW", cvss=9.8)
    Q.record(target, vuln_class="command-injection", agent="coverage/rce-exec-hunter#1",
             sink="app.py:run_report", effect="shell", status="CONFIRMED", cvss=7.8)
    top = Q.rank(target)[0]
    assert top["class"] == "command-injection", (
        "an unproven 9.8 outranked a proven 7.8 - the lane would open on a lead")
    assert Q.lane_candidate(target)["class"] == "command-injection"


def test_the_negative_control_never_becomes_a_finding(target):
    """A CLEAR is a verdict, not a record in the findings index."""
    Q.record(target, vuln_class="command-injection", agent="coverage/rce-exec-hunter#1",
             sink="app.py:run_report", effect="shell", status="CONFIRMED")
    sinks = {f["sink"] for f in Q.load(target)["findings"]}
    assert "app.py:run_export" not in sinks
    assert len(sinks) == 1


def test_the_lane_freeze_is_fleet_wide(target, monkeypatch):
    """One target, several swarms: a lane must stop NEW tasking everywhere, not just its own swarm."""
    monkeypatch.setattr(Q, "_board_counts", lambda t: {})
    Q.set_state(target, "RUNNING")
    assert Q.frozen(target)[0] is False
    Q.set_state(target, "REPORT_LANE", report_lane="F001")
    is_frozen, why = Q.frozen(target)
    assert is_frozen and "any swarm" in why
    assert "already running finish" in why, (
        "killing running members discards proven work and manufactures untested rows")
