#!/usr/bin/env python3
"""
A blocked impact gate must still produce bytes the user can act on.

The asymmetry these tests lock down: a PASS obliges an agent to write, audit and receipt a report
with no question owed first, while a BLOCK used to oblige it only to SAY that an upstream issue
would be the ceiling. A real defect that failed the bar therefore produced a blocker and nothing
anyone could use - the hunt that found it died in a sentence. Both branches must end in finished
bytes; only the channel differs, and submitting stays the user's call on both.

Run:  .venv/Scripts/python.exe -m pytest tests/test_blocked_finding_draft.py -q
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GUARDRAILS = ROOT / ".claude" / "skills" / "guardrails" / "SKILL.md"
REPORT_CRAFT = ROOT / ".claude" / "skills" / "report-craft" / "SKILL.md"
GATE = ROOT / "reports" / "impact_gate.py"
EXAMPLE = ROOT / "work" / "php-prepatch" / "upstream-issue-pcre-subpats-table.md"
DECISION = ROOT / "state" / "impact" / "PHP-001.json"


# ------------------------------------------------------------------ the gate itself tells you ---
def test_the_gate_names_the_deliverable_and_its_path():
    """The strongest hook: this fires on every BLOCK, for every agent, with no file to remember."""
    out = subprocess.run(
        [sys.executable, str(GATE), "PHP-TEST-DRAFT", "--program", "github",
         "--vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         "--attacker", "a", "--boundary", "b", "--impact", "c", "--marginal-gain", "d",
         "--gadget", "e", "--precondition", "p1", "--precondition", "p2",
         "--precondition", "p3", "--default-config", "yes"],
        capture_output=True, text=True, timeout=300, cwd=str(ROOT))
    try:
        assert out.returncode == 1, "three preconditions must BLOCK"
        text = out.stdout
        assert "upstream-issue-" in text, "the gate does not name the artifact"
        assert "work/<slug>/" in text, "the gate does not say where it goes"
        assert "YOUR deliverable" in text, "the gate still reads as a dead end"
        assert "not a disclosure report" in text, \
            "the gate must require the refusal line, or a draft gets filed as a report"
        assert "report-craft" in text, "no pointer to the full shape"
    finally:
        (ROOT / "state" / "impact" / "PHP-TEST-DRAFT.json").unlink(missing_ok=True)


def test_the_gate_still_forbids_a_draft_advisory():
    """An issue draft is NOT a licence to open an advisory. Both must stay true at once."""
    text = GATE.read_text(encoding="utf-8")
    assert "do not open a draft advisory" in text


# ------------------------------------------------------------------------ the skills carry it ---
def test_guardrails_says_a_blocked_gate_owes_bytes():
    """guardrails is loaded by every hunter, which is how this reaches all of them."""
    text = GUARDRAILS.read_text(encoding="utf-8")
    assert "upstream-issue-" in text
    assert "no-question-owed" in text or "without being asked" in text
    assert "not** a disclosure report" in text or "not a disclosure report" in text


def test_report_craft_has_the_blocked_branch_with_a_required_shape():
    text = REPORT_CRAFT.read_text(encoding="utf-8")
    assert "When the gate blocks" in text
    for required in ("The invariant", "Rebuttals tried", "Preconditions", "Suggested fix",
                     "How to verify", "Provenance", "Confirmation status"):
        assert required in text, f"the required shape omits {required!r}"
    assert "do not run the report auditors on it" in text.lower(), \
        "a draft issue has no receipt, so auditing it against the delivery gate is wrong"


def test_report_craft_forbids_softening_the_preconditions():
    """The honest precondition list is WHY this is the right channel."""
    text = REPORT_CRAFT.read_text(encoding="utf-8")
    assert "Do not soften the preconditions" in text


# -------------------------------------------------- the worked example satisfies its own rules ---
@pytest.mark.skipif(not EXAMPLE.exists(), reason="no worked example on disk")
def test_the_example_refuses_to_be_a_report_in_the_required_words():
    text = EXAMPLE.read_text(encoding="utf-8")
    assert "not a disclosure report" in text.lower()
    assert "must not be filed as one" in text.lower()


@pytest.mark.skipif(not EXAMPLE.exists(), reason="no worked example on disk")
def test_the_example_states_what_was_not_demonstrated():
    """Overclaiming here is the whole risk: nothing was built and nothing was run."""
    text = EXAMPLE.read_text(encoding="utf-8")
    assert "code-confirmed only" in text.lower()
    assert "no sanitizer was run" in text.lower() or "no sanitizer" in text.lower()
    assert "has **not** been observed" in text or "not been observed" in text


@pytest.mark.skipif(not EXAMPLE.exists(), reason="no worked example on disk")
def test_the_example_quotes_the_gate_verdict_that_sent_it_here():
    text = EXAMPLE.read_text(encoding="utf-8")
    assert "impact-gate" in text and "BLOCK" in text
    assert "state/impact/PHP-001.json" in text, "the decision record must be citable"


@pytest.mark.skipif(not (EXAMPLE.exists() and DECISION.exists()),
                    reason="example or decision missing")
def test_the_examples_preconditions_match_the_recorded_decision():
    """The draft must not quietly list fewer conditions than the gate was given."""
    d = json.loads(DECISION.read_text(encoding="utf-8"))
    recorded = d["answers"]["preconditions"]
    text = EXAMPLE.read_text(encoding="utf-8")
    assert len(recorded) == 3, f"expected 3 recorded preconditions, got {len(recorded)}"
    # Normalise BOTH sides identically before matching: the draft writes `preg_match` where the
    # recorded answer says preg_match/preg_match_all, and an alpha-only squash of one side only
    # turns that into a phantom failure. (It did, on the first run of this test.)
    def squash(x: str) -> str:
        return re.sub(r"[^a-z]", "", x.lower())

    flat = squash(text)
    for p in recorded:
        words = [w for w in re.split(r"[^A-Za-z_/]+", p) if len(w) >= 5][:4]
        assert words, f"precondition has no matchable words: {p}"
        missing = [w for w in words if squash(w) not in flat]
        assert not missing, f"precondition missing from the draft: {p} (missing {missing})"


@pytest.mark.skipif(not EXAMPLE.exists(), reason="no worked example on disk")
def test_the_example_carries_the_rebuttals_and_a_verification_plan():
    text = EXAMPLE.read_text(encoding="utf-8")
    assert "rebuttal" in text.lower(), "a maintainer's first reply is a rebuttal; answer it"
    assert "not yet done" in text.lower() or "How to verify" in text
    assert "negative control" in text.lower()


@pytest.mark.skipif(not EXAMPLE.exists(), reason="no worked example on disk")
def test_the_example_pins_a_commit_for_every_claim():
    text = EXAMPLE.read_text(encoding="utf-8")
    assert re.search(r"c31ae58ecbedc7a85dac0eee5a6a88da73543e70", text), "no pinned commit"
    # Count both forms the draft uses: a full path:line, and the `:NNN` shorthand for a line in the
    # file named by the surrounding sentence. Measured at 4 full + 11 shorthand when written; the
    # floor is set below that rather than at it, so tidying a citation does not fail the suite.
    full = re.findall(r"[\w./]+\.[ch]:\d+(?:-\d+)?", text)
    short = re.findall(r"`:\d+(?:-\d+)?", text)
    assert len(full) >= 3, f"only {len(full)} full file:line citation(s)"
    assert len(full) + len(short) >= 10,         f"a chain with {len(full) + len(short)} line citations is closer to an assertion than a trace"
