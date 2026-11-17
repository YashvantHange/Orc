#!/usr/bin/env python3
"""
The state-integrity capability must be reachable, owned, and honest about what it did not test.

Every assertion here pins a failure that reads as capability. The motivating case: PHP's
CVE-2026-109618/109619 were the "an operation fails and leaves state behind" family, and this
pipeline had no owner, no matrix row, no CWE entries and no verdict for it. A class nobody owns is
not reported BLOCKED - it is invisible, and the matrix prints complete.

Two of these tests pin measured false-verdict traps rather than wiring:

  * ASAN is silent on an in-bounds read of uninitialised memory, so sweeping an S1 class under ASAN
    alone and recording CLEAR is a false NEGATIVE. The skill must route that class to MSAN.
  * Raising the worker count does not distribute requests - on win32 the cluster default pins every
    connection to one worker (measured: 12 sequential requests, 1 of 4 workers). A "control" built
    that way reproduces the leak, so a bogus finding looks robust. That is a false POSITIVE.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / ".claude" / "agents" / "state-integrity-hunter.md"
MATRIX = ROOT / ".claude" / "skills" / "vuln-playbooks" / "SKILL.md"
SKILL = ROOT / ".claude" / "skills" / "state-integrity" / "SKILL.md"
SANITIZER = ROOT / ".claude" / "skills" / "native-sanitizer" / "SKILL.md"
CWEMAP = ROOT / ".claude" / "skills" / "cwe-map" / "SKILL.md"
FIXTURE = ROOT / "work" / "_selftest" / "pool_app"


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


# ----------------------------------------------------------------- the capability exists ---
@pytest.mark.parametrize("path", [AGENT, SKILL, SANITIZER, FIXTURE / "server.js",
                                  FIXTURE / "seeds.json", ROOT / "dynamic" / "state_diff.py"])
def test_the_pieces_exist(path):
    assert path.exists(), f"{path} is missing; the capability is documented but not present"


def test_group_h_rows_are_in_the_matrix():
    text = _read(MATRIX)
    assert "### H. State integrity" in text, "no group H heading"
    for row in ("Error-path state corruption",
                "Cross-request state reuse",
                "Stale authorization or identity context",
                "Pooled object / worker reuse without reset",
                "Thread-local / async-context bleed",
                "Use-after-free, uninitialised read, double free",
                "Container counter / length desync"):
        assert row in text, f"group H row missing from the matrix: {row}"


def test_every_group_h_row_is_reachable_by_something():
    """A row in neither COVERS nor MANUAL_ROWS never appears in coverage output in ANY state."""
    import sys
    sys.path.insert(0, str(ROOT / "tools"))
    sys.path.insert(0, str(ROOT / "web"))
    import audit_coverage as A
    import sweep

    rows = [r for r in A.matrix_rows() if r[0] == "H"]
    assert rows, "group H parsed as zero rows"
    settleable = set(A.STAGES) | set(sweep.MANUAL_ROWS)
    try:
        sys.path.insert(0, str(ROOT / "dynamic"))
        import probe
        settleable |= set(probe.PRIMITIVES)
    except Exception:                                        # noqa: BLE001
        pass
    for group, name, *_rest in rows:
        settler = A.COVERS.get(name)
        assert settler, f"group H row {name!r} has no COVERS entry — invisible in every state"
        assert settler in settleable, (
            f"group H row {name!r} points at {settler!r}, which is not a primitive, "
            f"a MANUAL_ROWS key, or a stage")


def test_cwe_map_carries_the_family():
    text = _read(CWEMAP)
    for cwe in ("CWE-416", "CWE-415", "CWE-824", "CWE-787", "CWE-125",
                "CWE-476", "CWE-488", "CWE-567", "CWE-662"):
        assert cwe in text, f"{cwe} missing from the shared cwe-map"


# ------------------------------------------------------- the honest-verdict vocabulary ---
def test_matrix_legend_documents_every_enforced_state():
    """verdict.py enforces eight states; the legend used to document four.

    The four it omitted included NOT_CONFIRMED - "the attack was sent and nothing came back" - so a
    hunter following the legend had nowhere to record it except CLEAR.
    """
    import sys
    sys.path.insert(0, str(ROOT / "dynamic"))
    import verdict

    legend = _read(MATRIX)
    for state in verdict.State:
        assert state.name in legend or state.value in legend, (
            f"{state.name} is enforced in dynamic/verdict.py but absent from the matrix legend, "
            f"so no hunter knows it may be used")


def test_board_can_count_the_honest_verdicts():
    """A verdict with no counter gets tallied as CLEAR or BLOCKED for want of a bucket."""
    import sys
    sys.path.insert(0, str(ROOT / "tools"))
    import board

    src = _read(Path(board.__file__))
    for key in ("NOT_CONFIRMED", "NEEDS_SIGNAL", "UNTESTED"):
        assert key in src, f"tools/board.py has no {key} counter"
    hunt_src = _read(ROOT / "hunt.py")
    for flag in ("--not-confirmed", "--needs-signal", "--untested"):
        assert flag in hunt_src, f"hunt.py board tally does not accept {flag}"


# ------------------------------------------------------------- the measured false verdicts ---
def test_asan_is_not_accepted_as_coverage_for_uninitialised_state():
    """ASAN reports nothing on an in-bounds read of uninitialised memory. MSAN reports it.

    Sweeping S1 under ASAN alone and recording CLEAR is therefore a false negative, and the
    sanitizer skill has to say so in words a hunter cannot miss.
    """
    text = _read(SANITIZER)
    assert "MSAN" in text and "ASAN" in text
    assert re.search(r"not interchangeable", text, re.I), \
        "native-sanitizer must state that ASAN and MSAN are not interchangeable"
    assert re.search(r"BLOCKED \(wrong instrumentation\)", _read(AGENT)), \
        "the hunter must have a verdict for the wrong-sanitizer case other than CLEAR"


def test_worker_count_alone_is_rejected_as_a_negative_control():
    """Measured: 4 workers + no keep-alive still confirmed 5/5 on win32. Adding workers is not a
    control, and both the skill and the hunter must say the control has to FORCE distribution."""
    for path in (SKILL, AGENT):
        text = _read(path)
        assert "SCHED_RR" in text, f"{path.name} does not name the forced-distribution mechanism"
        assert re.search(r"not a negative control|is \*\*not\*\* a negative control|"
                         r"not a control", text, re.I), \
            f"{path.name} does not warn that raising the worker count is not a control"


def test_pool_boot_refuses_an_unstated_distribution_policy():
    """An unstated policy makes every observed rate meaningless, so it is not defaulted."""
    import sys
    sys.path.insert(0, str(ROOT / "dynamic"))
    from instrument import TargetProcess

    with pytest.raises(ValueError, match="policy"):
        TargetProcess(str(FIXTURE), pool=2)


def test_unsupported_runtime_raises_rather_than_degrading_to_one_process():
    """A silent fallback to a single process would let a hunt record CLEAR for an unexercised
    class. PHP/Java/Go have no runtime here, which is exactly why 109619's shape is unconfirmable."""
    import sys
    sys.path.insert(0, str(ROOT / "dynamic"))
    import instrument

    src = _read(Path(instrument.__file__))
    assert "class PoolUnavailable" in src
    assert "NEEDS_EXTERNAL_SIGNAL" in src, \
        "PoolUnavailable must tell the caller which verdict to record"


# ------------------------------------------------------------------------- the fixture ---
def test_fixture_seeds_both_a_positive_and_an_isolated_control():
    seeds = json.loads(_read(FIXTURE / "seeds.json"))
    expect = {s["id"]: s["expect"] for s in seeds["seeds"]}
    assert expect.get("s2-identity-bleed") == "CONFIRMED"
    assert expect.get("s2-negative-control") == "CLEAR", \
        "without a correctly-isolated control, a false positive is indistinguishable from a finding"


def test_fixture_still_has_its_bug():
    """DO NOT FIX THE FIXTURE. A repaired fixture makes the differential untestable."""
    src = _read(FIXTURE / "server.js")
    assert "let lastIdentity" in src, "the seeded module-scope holder is gone"
    assert "perIdentity" in src, "the isolated-cache control is gone"


def test_live_target_rule_is_stated():
    """This class can surface a real third party's data, so the live rule is not optional."""
    for path in (SKILL, AGENT):
        text = _read(path)
        assert re.search(r"stop,?\s*minimi[sz]e,?\s*purge", text, re.I), \
            f"{path.name} does not carry the stop/minimise/purge rule for live targets"
