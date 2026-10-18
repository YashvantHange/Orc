#!/usr/bin/env python3
"""
A forged agent must be born dispatchable, or it is not capability - it is the appearance of it.

test_agent_wiring.py already encodes the rule: an agent file the orchestrator never names is dead
weight that reads as capability. A swarm that writes agents at run time can produce that defect
dozens of times per hunt, so forging and registering are one operation and these tests exist to
prove the refusals fire.

Two constraints here look like nitpicks and are not:

  * NO DIGITS in a forged name. test_agent_wiring.py's dispatch-validity regex is [a-z]+ with no
    digit class, so `api-v2-hunter` would satisfy the every-agent-is-dispatched test while being
    invisible to the no-phantom-agents test - an agent only half the suite can see.
  * NO `Task` in tools. A swarm member that can spawn its own members is an unbounded swarm.

Every test restores .claude/ afterwards: these touch real repo files, because that is precisely
what is being tested.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import swarm as SW  # noqa: E402

SLUG = "_forge_selftest"
NAME = "selftest-probe-hunter"


@pytest.fixture(autouse=True)
def restore_claude():
    """Snapshot the two registry files and every agent name; put them all back afterwards."""
    orch = SW.ORCHESTRATOR.read_text(encoding="utf-8")
    board = SW.RUNBOARD.read_text(encoding="utf-8")
    before = {p.name for p in SW.AGENTS.glob("*.md")}
    try:
        yield
    finally:
        for p in SW.AGENTS.glob("*.md"):
            if p.name not in before:
                p.unlink()
        SW.ORCHESTRATOR.write_text(orch, encoding="utf-8")
        SW.RUNBOARD.write_text(board, encoding="utf-8")


# ================================================================ the refusals fire ===
@pytest.mark.parametrize("bad", [
    "api-v2-hunter",            # digit - invisible to the dispatch-validity regex
    "some_thing-hunter",        # underscore - same
    "Recon-Hunter",             # capitals
    "swarm-lead",               # suffix not in the dispatch regex's alternation
    "hunter",                   # no prefix
    "graphql-resolver",         # no suffix at all
])
def test_an_undispatchable_name_is_refused(bad):
    with pytest.raises(SW.SwarmError, match="dispatchable"):
        SW.validate_name(bad)


@pytest.mark.parametrize("good", [
    "graphql-resolver-hunter", "cache-hunter", "webhook-replay-prover", "shape-analyzer"])
def test_a_dispatchable_name_is_accepted(good):
    SW.validate_name(good)


def test_the_name_rule_agrees_with_the_wiring_test_regex():
    """The rule is only worth anything if it matches the oracle it claims to satisfy."""
    wiring = re.compile(
        r"(?<![-\w])([a-z]+(?:-[a-z]+)*-(?:hunter|aimer|prover|analyzer|writer|auditor|"
        r"editor|corrector))(?![-\w])")
    for good in ("graphql-resolver-hunter", "cache-hunter", "shape-analyzer"):
        SW.validate_name(good)
        assert wiring.search(good), f"{good} passes the forge but the wiring regex cannot see it"
    for bad in ("api-v2-hunter", "some_thing-hunter"):
        with pytest.raises(SW.SwarmError):
            SW.validate_name(bad)
        assert not wiring.fullmatch(bad), "premise wrong: the wiring regex does see this name"


def test_the_task_tool_is_refused():
    with pytest.raises(SW.SwarmError, match="unbounded swarm"):
        SW.validate_tools("Read, Grep, Task, Write")


def test_empty_tools_are_refused():
    with pytest.raises(SW.SwarmError):
        SW.validate_tools("  ")


def test_a_standing_agent_is_never_overwritten():
    with pytest.raises(SW.SwarmError, match="standing agent"):
        SW.forge("injection-hunter", "anything", SLUG)
    assert "swarm-forged" not in (SW.AGENTS / "injection-hunter.md").read_text(encoding="utf-8")


# ============================================================ what forging produces ===
def test_frontmatter_parses_under_the_board_parser():
    """board.py hand-rolls a line parser rather than using YAML; anything nested flattens silently."""
    sys.path.insert(0, str(ROOT / "tools"))
    import board as B
    dest = SW.forge(NAME, "services/api/** · deserialization", SLUG)
    fm = B._frontmatter(dest)
    assert set(fm) == {"name", "description", "tools", "model"}, (
        f"forged frontmatter has keys the roster parser does not expect: {sorted(fm)}")
    assert fm["name"] == NAME
    assert fm["description"].strip(), "an empty description renders as a blank roster row"


def test_the_verdict_bar_is_copied_verbatim_from_a_standing_hunter():
    """A forged agent with a softer verdict bar is how a 30-wide swarm launders BLOCKED into CLEAR."""
    dest = SW.forge(NAME, "shard", SLUG)
    text = dest.read_text(encoding="utf-8")
    donor = (SW.AGENTS / "injection-hunter.md").read_text(encoding="utf-8")
    for required in ("## MANDATORY FIRST STEP", "## HARDEST RULE", "## Standing guardrails",
                     "## Read it, then test it", "## What you return"):
        assert required in text, f"forged agent is missing {required!r}"
        assert required in donor, f"premise wrong: donor has no {required!r}"
    assert "BLOCKED (untested)" in text


def test_a_forged_agent_is_marked_as_one():
    SW.forge(NAME, "shard", SLUG)
    assert SW.forged_agents().get(NAME) == SLUG, "a forged agent that cannot be identified as one "\
        "can never be retired"


# ======================================================= registration is not optional ===
def test_forging_registers_in_both_places():
    SW.forge(NAME, "shard", SLUG)
    assert NAME in SW.ORCHESTRATOR.read_text(encoding="utf-8"), (
        "the orchestrator does not name the forged agent, so test_agent_wiring would fail and the "
        "agent would never be dispatched")
    assert NAME in SW.RUNBOARD.read_text(encoding="utf-8"), (
        "the forged agent would run invisibly - absent from the board the user watches")


def test_registration_is_idempotent():
    SW.forge(NAME, "shard", SLUG)
    once = SW.ORCHESTRATOR.read_text(encoding="utf-8")
    SW.forge(NAME, "a different shard", SLUG)
    twice = SW.ORCHESTRATOR.read_text(encoding="utf-8")
    assert once == twice, "re-forging duplicated the registry block"
    assert twice.count(SW.BEGIN) == 1 and twice.count(SW.END) == 1


def test_retire_removes_the_file_and_the_registry_lines():
    SW.forge(NAME, "shard", SLUG)
    gone = SW.retire(SLUG)
    assert NAME in gone
    assert not (SW.AGENTS / f"{NAME}.md").exists()
    assert NAME not in SW.ORCHESTRATOR.read_text(encoding="utf-8")
    assert NAME not in SW.RUNBOARD.read_text(encoding="utf-8")


def test_retire_leaves_standing_agents_alone():
    before = {p.name for p in SW.AGENTS.glob("*.md")}
    SW.forge(NAME, "shard", SLUG)
    SW.retire(SLUG)
    assert {p.name for p in SW.AGENTS.glob("*.md")} == before


def test_retire_honours_keep():
    SW.forge(NAME, "shard", SLUG)
    assert SW.retire(SLUG, keep=[NAME]) == []
    assert (SW.AGENTS / f"{NAME}.md").exists()
    assert NAME in SW.ORCHESTRATOR.read_text(encoding="utf-8"), "a kept agent must stay registered"


def test_retire_scopes_to_one_slug():
    other = "selftest-other-hunter"
    SW.forge(NAME, "shard", SLUG)
    SW.forge(other, "shard", "a-different-slug")
    SW.retire(SLUG)
    assert not (SW.AGENTS / f"{NAME}.md").exists()
    assert (SW.AGENTS / f"{other}.md").exists(), "retiring one hunt's swarm killed another's"


# ============================================ the round trip the wiring suite polices ===
def test_the_wiring_suite_passes_with_a_forged_agent_present():
    """The contract, end to end: forge -> the repo's own oracle still agrees -> retire -> agrees."""
    import importlib
    SW.forge(NAME, "shard", SLUG)
    wiring = importlib.import_module("test_agent_wiring") if "tests" in sys.path else None
    if wiring is None:
        sys.path.insert(0, str(ROOT / "tests"))
        wiring = importlib.import_module("test_agent_wiring")
    importlib.reload(wiring)

    assert NAME in wiring.agent_names()
    wiring.test_every_agent_is_dispatched_by_the_orchestrator(NAME)
    wiring.test_the_orchestrator_is_not_dispatching_agents_that_do_not_exist()

    SW.retire(SLUG)
    importlib.reload(wiring)
    assert NAME not in wiring.agent_names()
    wiring.test_the_orchestrator_is_not_dispatching_agents_that_do_not_exist()
