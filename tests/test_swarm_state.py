#!/usr/bin/env python3
"""
A swarm must survive the session that started it - without becoming a second source of truth.

Rate limits have killed background agents mid-cycle on this pipeline twice, and a 30-wide run is
long enough that a dead session is the expected case, not the unlucky one. So the phase is
persisted.

The trap this file guards is the OTHER failure: a state file that restates per-row status and the
tally. board.json already owns those. A state.json claiming `active: 21` while the board shows
something else is worse than having no state file at all, because both look authoritative - the
same "two authorities is the bug" this pipeline already learned once for the request budget. So
counts here are DERIVED from the board at write time, and the tests assert they cannot drift.

The plan binding is the other half: if plan.json no longer hashes to what the run recorded, the
membership in front of us is not the membership that was dispatched, and resuming into it would
silently continue a swarm nobody planned.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import swarm as SW  # noqa: E402
import swarm_queue as Q  # noqa: E402


@pytest.fixture
def bench(tmp_path, monkeypatch):
    """A swarm dir plus a board, both redirected into tmp."""
    sw = tmp_path / "swarm"
    monkeypatch.setattr(Q, "swarm_dir", lambda t: sw)

    import board as B
    rows = [{"n": i, "agent": f"a{i}", "scope": "s", "status": "queued",
             "result": "", "started": None, "ended": None} for i in range(1, 6)]
    board_doc = {"target": "t", "kind": "src", "step": [1, 9],
                 "tally": {"covered": [0, 0], "HIT": 0, "CLEAR": 0, "BLOCKED": 0, "CONFIRMED": []},
                 "started": 0, "updated": 0, "rows": rows}
    monkeypatch.setattr(B, "load", lambda t: board_doc)
    monkeypatch.setattr(Q, "_board_counts", lambda t: {
        "rows": len(board_doc["rows"]),
        "running": sum(1 for r in board_doc["rows"] if r["status"] == "running"),
        "queued": sum(1 for r in board_doc["rows"] if r["status"] == "queued"),
        "returned": sum(1 for r in board_doc["rows"]
                        if r["status"] in ("done", "blocked", "na"))})
    return "t", sw, board_doc


# ============================================================== transitions persist ===
def test_every_declared_state_is_reachable(bench):
    target, sw, _ = bench
    for st in Q.STATES:
        Q.set_state(target, st)
        assert Q.read_state(target)["state"] == st
    assert (sw / "state.json").exists()


def test_an_unknown_state_is_refused(bench):
    target, _, _ = bench
    with pytest.raises(Q.QueueError, match="unknown swarm state"):
        Q.set_state(target, "MOSTLY_DONE")


def test_the_plan_binding_survives_a_later_transition(bench):
    target, _, _ = bench
    Q.set_state(target, "RUNNING", plan_sha256="sha256:abc")
    Q.set_state(target, "TRIAGING")
    assert Q.read_state(target)["plan_sha256"] == "sha256:abc", (
        "the binding was dropped by an unrelated transition - a later resume could not prove which "
        "swarm it was continuing")


# ================================== the board is the authority; state never restates it ===
def test_counts_are_derived_from_the_board_not_maintained(bench):
    target, _, board_doc = bench
    Q.set_state(target, "RUNNING")
    assert Q.read_state(target)["derived_from_board"]["queued"] == 5

    board_doc["rows"][0]["status"] = "running"
    board_doc["rows"][1]["status"] = "done"
    Q.set_state(target, "RUNNING")
    d = Q.read_state(target)["derived_from_board"]
    assert (d["queued"], d["running"], d["returned"]) == (3, 1, 1), (
        "state.json drifted from board.json - two authorities for run state is the defect this "
        "design exists to avoid")


def test_state_stores_no_per_row_status(bench):
    target, _, _ = bench
    Q.set_state(target, "RUNNING")
    blob = json.dumps(Q.read_state(target))
    assert '"rows": [' not in blob, "state.json is duplicating the board's rows"
    assert "CLEAR" not in blob and "HIT" not in blob, "state.json is duplicating the tally"


# ========================================================================= resuming ===
def _plan_on_disk(sw, kind="src", width=12):
    doc = SW.plan("t", kind, requested=width)
    sw.mkdir(parents=True, exist_ok=True)
    (sw / "plan.json").write_text(json.dumps(dict(doc, sized_at="whenever")), encoding="utf-8")
    return doc


def test_resume_lists_only_what_never_returned(bench):
    target, sw, board_doc = bench
    doc = _plan_on_disk(sw)
    Q.set_state(target, "RUNNING", plan_sha256=doc["plan_sha256"])
    board_doc["rows"][0]["status"] = "done"
    board_doc["rows"][1]["status"] = "blocked"

    info = Q.resumable(target)
    ns = [r["n"] for r in info["unreturned"]]
    assert ns == [3, 4, 5], f"resume would re-dispatch rows that already returned: {ns}"


def test_resume_refuses_when_the_plan_changed_under_it(bench):
    """The binding earns its keep here: a re-planned swarm is not the swarm that was dispatched."""
    target, sw, _ = bench
    _plan_on_disk(sw)
    Q.set_state(target, "RUNNING", plan_sha256="sha256:something-else-entirely")
    with pytest.raises(Q.QueueError, match="re-planned mid-run"):
        Q.resumable(target)


def test_resume_refuses_without_a_plan_on_disk(bench):
    target, _, _ = bench
    Q.set_state(target, "RUNNING", plan_sha256="sha256:abc")
    with pytest.raises(Q.QueueError, match="cannot prove which swarm"):
        Q.resumable(target)


def test_resume_refuses_with_no_state_at_all(bench):
    target, _, _ = bench
    with pytest.raises(Q.QueueError, match="nothing to resume"):
        Q.resumable(target)


def test_a_plan_written_and_reloaded_still_verifies(bench):
    """sized_at is metadata; round-tripping through disk must not break the binding."""
    target, sw, _ = bench
    doc = _plan_on_disk(sw)
    Q.set_state(target, "RUNNING", plan_sha256=doc["plan_sha256"])
    assert Q.resumable(target)["plan_sha256"] == doc["plan_sha256"]
