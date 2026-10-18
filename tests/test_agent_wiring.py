#!/usr/bin/env python3
"""
Every agent must be reachable from the orchestrator.

An agent file that nothing dispatches is dead weight that reads as capability: the roster shows it,
`hunt agents` lists it, and it never runs. Four were found this way - target-aimer, dynamic-prover,
chain-analyzer and report-corrector - all present, all documented, none dispatched.

That is the same defect shape as a matrix row in neither TARGETING nor MANUAL_ROWS, and as the CLEAR
fallthrough: a thing that looks covered and cannot fire. It was found by chance, so it gets a test.
"""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
AGENTS = ROOT / ".claude" / "agents"
ORCHESTRATOR = AGENTS / "sec-orchestrator.md"


def agent_names() -> list:
    return sorted(f.stem for f in AGENTS.glob("*.md") if f.stem != "sec-orchestrator")


def test_there_are_agents_to_check():
    assert len(agent_names()) > 10, "agent discovery is broken; the rest of this file proves nothing"


@pytest.mark.parametrize("name", agent_names())
def test_every_agent_is_dispatched_by_the_orchestrator(name):
    text = ORCHESTRATOR.read_text(encoding="utf-8")
    assert name in text, (
        f"{name} exists but sec-orchestrator never names it, so it is never tasked. Either wire it "
        f"into the dispatch flow at the point it belongs, or delete it - an agent nothing dispatches "
        f"reads as capability the pipeline does not have.")


def test_the_orchestrator_is_not_dispatching_agents_that_do_not_exist():
    """The inverse: a dispatch line naming a deleted agent fails at run time, not review time."""
    text = ORCHESTRATOR.read_text(encoding="utf-8")
    known = set(agent_names()) | {"sec-orchestrator"}
    import re
    # Negative lookarounds for [-\w] rather than \b: a hyphen IS a word boundary, so a plain \b
    # match picked "crypto-hunter" out of "authn-crypto-hunter" and reported six phantom agents.
    referenced = set(re.findall(
        r"(?<![-\w])([a-z]+(?:-[a-z]+)*-(?:hunter|aimer|prover|analyzer|writer|auditor|"
        r"editor|corrector))(?![-\w])", text))
    missing = referenced - known
    assert not missing, f"sec-orchestrator dispatches agents that do not exist: {sorted(missing)}"


def test_new_agents_appear_on_the_run_board():
    """The board is how the user sees the fleet; an agent absent from it runs invisibly."""
    board = (ROOT / ".claude" / "skills" / "run-board" / "SKILL.md").read_text(encoding="utf-8")
    for name in ("target-aimer", "dynamic-prover", "chain-analyzer"):
        assert name in board, f"{name} is dispatched but never shown on the run board"
