#!/usr/bin/env python3
"""
swarm_queue.py - merge what 30 members find, rank it, and remember where the run got to.

THREE PROBLEMS THAT ONLY EXIST AT WIDTH 30:

1. DUPLICATES. Two members with different shards routinely reach one bug from different directions.
   Ranking without merging produces five reports for one defect, and on these programs a duplicate
   is a wasted submission rather than a harmless one. So findings are keyed by SINK IDENTITY, not by
   payload: the same sink reached with two payloads is one finding with two contributors - the
   existing "one finding, two contributors, never two competing reports" rule at swarm scale.

   Path normalisation is not a detail here. correlate/merge.py already keys on
   os.path.normpath(...).lower() because this pipeline runs on win32, where `services\\API\\fetch.py`
   and `services/api/fetch.py` are the same file. The same normalisation is reused rather than
   reinvented, or the commonest duplicate shape silently fails to collapse.

2. RANKING IS TWO-TIER, because reports/impact_gate.py is answer-driven (gadget, default-config, one
   flag per precondition) and is documented as running at report time. Running it on 30 candidates
   is neither possible nor wanted. Tier 1 ranks cheaply on what a member already returns; tier 2 is
   the gate, on the ONE candidate about to get the lane.

3. RECOVERY. A 30-wide run is long, and rate limits have killed background agents on this pipeline
   before. state.json remembers the phase and which plan it belongs to.

   It deliberately does NOT restate per-row status or the tally: board.json is the authority for
   those, and a state file disagreeing with the board is worse than no state file at all. Counts
   here are DERIVED from the board at write time.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

STATES = ["PLANNED", "DISPATCH_READY", "RUNNING", "FINDINGS_QUEUED", "TRIAGING",
          "REPORT_LANE", "DRAINING", "COMPLETE"]

# Evidence strength. A runtime-confirmed PoC beats a read, so a merge keeps the stronger one.
STRENGTH = {"CONFIRMED": 3, "code-confirmed": 2, "NEW": 1, "": 0}


class QueueError(Exception):
    """Refusal with a reason the operator can act on."""


def swarm_dir(target: str) -> Path:
    try:
        import sys
        sys.path.insert(0, str(ROOT / "static"))
        import common as C
        work = Path(C.workdir(target))
    except Exception:                                   # noqa: BLE001
        work = ROOT / "work" / target
    return work / "swarm"


# ========================================================================= fingerprint ===
def _norm_sink(sink: str) -> str:
    """file:line normalised the way correlate/merge.py normalises a finding's file."""
    if not sink:
        return ""
    path, _, line = sink.rpartition(":")
    if not path or not line.isdigit():
        path, line = sink, ""
    return f"{os.path.normpath(path).lower()}:{line}" if line else os.path.normpath(path).lower()


def fingerprint(vuln_class: str, sink: str = "", endpoint: str = "", param: str = "",
                effect: str = "") -> str:
    """Identity of the DEFECT, not of the probe that found it.

    For src the sink file:line carries it. For url there is no file:line, so endpoint + parameter +
    observed effect does - the same substitution black-box reports already make when they cite
    T##### ids instead of lines.
    """
    key = (vuln_class.strip().lower(), _norm_sink(sink),
           endpoint.strip().lower().rstrip("/"), param.strip().lower(), effect.strip().lower())
    if not key[1] and not key[2]:
        raise QueueError("a finding needs either a sink (file:line) or an endpoint to be identified")
    blob = "|".join(key)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ============================================================================= storage ===
def load(target: str) -> dict:
    p = swarm_dir(target) / "findings.json"
    if not p.exists():
        return {"schema": 1, "findings": []}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise QueueError(f"{p}: unreadable findings index: {e}") from e


def save(target: str, doc: dict) -> Path:
    p = swarm_dir(target) / "findings.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return p


def record(target: str, *, vuln_class: str, agent: str, sink: str = "", endpoint: str = "",
           param: str = "", effect: str = "", status: str = "NEW", cwe: str = "",
           cvss: float = 0.0, preconditions: int = 0, evidence: str = "") -> dict:
    """Add a finding, or merge it into the one it duplicates. Returns the surviving record."""
    doc = load(target)
    fp = fingerprint(vuln_class, sink, endpoint, param, effect)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    for rec in doc["findings"]:
        if rec["fingerprint"] == fp:
            if agent not in rec["agents"]:
                rec["agents"].append(agent)
                rec["agents"].sort()
            if evidence and evidence not in rec["evidence"]:
                rec["evidence"].append(evidence)
            # Keep the STRONGEST evidence, not the newest: a runtime PoC outranks a read.
            if STRENGTH.get(status, 0) > STRENGTH.get(rec["status"], 0):
                rec["status"] = status
            rec["cvss"] = max(float(rec.get("cvss") or 0.0), float(cvss or 0.0))
            if preconditions and (not rec.get("preconditions")
                                  or preconditions < rec["preconditions"]):
                rec["preconditions"] = preconditions
            rec["cwe"] = rec.get("cwe") or cwe
            rec["merged"] = int(rec.get("merged", 1)) + 1
            rec["updated_at"] = now
            save(target, doc)
            return rec

    nxt = f"F{len(doc['findings']) + 1:03d}"
    rec = {"finding_id": nxt, "fingerprint": fp, "class": vuln_class, "cwe": cwe,
           "sink": sink, "endpoint": endpoint, "param": param, "effect": effect,
           "status": status, "cvss": float(cvss or 0.0), "preconditions": int(preconditions or 0),
           "agents": [agent], "evidence": [evidence] if evidence else [],
           "merged": 1, "first_seen": now, "updated_at": now}
    doc["findings"].append(rec)
    save(target, doc)
    return rec


def handoff(target: str, *, from_member: str, to_agent: str, fingerprint: str = "",
            vuln_class: str = "", sink: str = "", endpoint: str = "", param: str = "",
            effect: str = "", reason: str = "", evidence: str = "", aim: str = "") -> dict:
    """Record that one member handed a lead to another, WITH the context that caused it.

    The rule already existed as prose - "hand the sink half over with the source half attached and
    say who you handed it to" - and nothing carried it, so the source half was whatever survived in
    a chat message. That matters most for the prove lane, whose measured failure mode is AIMING
    rather than capability: aimed by hand the primitives found 4 of 6 seeded bugs, through the
    unaimed sweep 2 of 6. A handoff that loses the aim recreates the unaimed case.

    Attaches to the existing finding when one matches, so a handoff is part of the finding's history
    rather than a parallel log that can disagree with it.
    """
    if not from_member or not to_agent:
        raise QueueError("a handoff needs both a from-member and a to-agent")
    if not reason.strip():
        raise QueueError(
            "a handoff needs a reason - the receiving member is being asked to spend budget on this "
            "lead, and 'look at this' is not an aim")

    doc = load(target)
    fp = fingerprint or (fingerprint_of(vuln_class, sink, endpoint, param, effect)
                         if (vuln_class and (sink or endpoint)) else "")
    rec = next((r for r in doc["findings"] if r["fingerprint"] == fp), None) if fp else None
    if rec is None:
        rec = record(target, vuln_class=vuln_class or "unclassified", agent=from_member, sink=sink,
                     endpoint=endpoint, param=param, effect=effect, status="NEW",
                     evidence=evidence)
        doc = load(target)
        rec = next(r for r in doc["findings"] if r["finding_id"] == rec["finding_id"])

    entry = {"from": from_member, "to": to_agent, "reason": reason.strip(), "aim": aim.strip(),
             "evidence": evidence, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    rec.setdefault("handoffs", []).append(entry)
    if to_agent not in rec["agents"]:
        rec["agents"].append(to_agent)
        rec["agents"].sort()
    rec["updated_at"] = entry["at"]
    save(target, doc)
    return rec


def fingerprint_of(vuln_class, sink="", endpoint="", param="", effect=""):
    """Alias kept so callers do not have to know the module-level name."""
    return fingerprint(vuln_class, sink, endpoint, param, effect)


# ============================================================================= ranking ===
def rank(target: str) -> list:
    """Tier 1: cheap, over everything, on what members already return.

    Preconditions outrank raw score because a stacked-precondition finding is what gets closed as
    Infeasible regardless of its CVSS - impact_gate.py encodes the same threshold independently.
    """
    out = sorted(
        load(target)["findings"],
        key=lambda r: (-STRENGTH.get(r.get("status", ""), 0),
                       -float(r.get("cvss") or 0.0),
                       int(r.get("preconditions") or 0),
                       r["finding_id"]))
    return out


def lane_candidate(target: str) -> dict | None:
    """The one finding tier 2 (the real impact gate) should be run against next."""
    for rec in rank(target):
        if rec.get("status") == "CONFIRMED" and not rec.get("lane_opened"):
            return rec
    return None


def gate_candidate(target: str, finding_id: str, vector: str = "") -> tuple[bool, str]:
    """Tier 2. Delegates to the real gate rather than second-guessing it."""
    import sys
    sys.path.insert(0, str(ROOT))
    from reports import impact_gate
    return impact_gate.cleared(finding_id, vector)


# ======================================================================= state machine ===
def _board_counts(target: str) -> dict:
    """Derive from board.json. Never maintained here - two authorities for run state is the bug."""
    try:
        import sys
        sys.path.insert(0, str(ROOT / "tools"))
        import board as B
        doc = B.load(target)
    except (Exception, SystemExit):                     # noqa: BLE001
        # board.load raises SystemExit, not Exception, when no board exists yet - and a state file
        # must be writable BEFORE the board is opened (the fleet reaches PLANNED before any row is
        # added). Catching only Exception let that SystemExit escape and kill `hunt swarm state`.
        return {}
    rows = doc.get("rows", [])
    return {"rows": len(rows),
            "running": sum(1 for r in rows if r["status"] == "running"),
            "queued": sum(1 for r in rows if r["status"] == "queued"),
            "returned": sum(1 for r in rows if r["status"] in ("done", "blocked", "na"))}


def state_path(target: str) -> Path:
    return swarm_dir(target) / "state.json"


def read_state(target: str) -> dict:
    p = state_path(target)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise QueueError(f"{p}: unreadable swarm state: {e}") from e


def set_state(target: str, state: str, plan_sha256: str = "", report_lane: str | None = None,
              swarm: str | None = None, fleet_sha256: str = "") -> dict:
    """Advance the fleet's phase, or one swarm's within it.

    The top level is the FLEET. `swarm=` records one member swarm's own phase and binding beside it.
    Neither level ever restates per-row status or the tally: board.json owns those, and a state file
    that disagrees with the board is worse than no state file, because both look authoritative.
    """
    if state not in STATES:
        raise QueueError(f"unknown swarm state {state!r}; expected one of {STATES}")
    cur = read_state(target)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    doc = dict(cur) if cur else {}
    doc.setdefault("schema", 2)
    doc.setdefault("swarms", {})

    if swarm:
        doc["swarms"][swarm] = {"state": state, "plan_sha256": plan_sha256, "updated": now}
        doc.setdefault("state", state)
    else:
        doc["state"] = state
        doc["plan_sha256"] = plan_sha256 or doc.get("plan_sha256", "")
        if fleet_sha256 or doc.get("fleet_sha256"):
            doc["fleet_sha256"] = fleet_sha256 or doc.get("fleet_sha256", "")
        doc["report_lane"] = report_lane if report_lane is not None else doc.get("report_lane")
    doc["derived_from_board"] = _board_counts(target)
    doc["updated"] = now

    p = state_path(target)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return doc


def frozen(target: str) -> tuple[bool, str]:
    """Is the whole fleet barred from tasking new members?

    A confirmation suspends the hunt for the report lane. With several swarms on one target that has
    to be FLEET-wide: letting depth keep tasking while coverage writes a report is how a second
    confirmation lands mid-report and the queue loses its order. Members already RUNNING are not
    killed - that discards proven work and manufactures the untested rows the wave cap existed to
    prevent - so this gates new tasking only.
    """
    st = read_state(target)
    lane = st.get("report_lane")
    if lane:
        return True, (f"report lane open for {lane} - no NEW members in any swarm until it lands; "
                      f"members already running finish")
    return False, ""


def resumable(target: str) -> dict:
    """What a resume may re-dispatch, and whether it is even the same swarm.

    The plan hash is the whole point of binding: if the plan on disk no longer hashes to what the
    state recorded, something re-planned mid-run and the membership in front of us is not the
    membership that was dispatched. Say so rather than continuing into it.
    """
    st = read_state(target)
    if not st:
        raise QueueError(f"no swarm state for {target} - nothing to resume")
    plan_file = swarm_dir(target) / "plan.json"
    if not plan_file.exists():
        raise QueueError(f"{plan_file} is gone - cannot prove which swarm this state belongs to")

    import sys
    sys.path.insert(0, str(ROOT / "tools"))
    import swarm as SW
    plan_doc = json.loads(plan_file.read_text(encoding="utf-8"))
    live = SW.plan_hash(plan_doc)
    bound = st.get("plan_sha256", "")
    if bound and live != bound:
        raise QueueError(
            f"plan.json now hashes to {live} but the run was bound to {bound}. The swarm was "
            f"re-planned mid-run; resuming would continue a membership that was never dispatched. "
            f"Re-plan deliberately and start a new swarm, or restore the original plan.")

    try:
        import board as B
        rows = B.load(target).get("rows", [])
    except Exception:                                   # noqa: BLE001
        rows = []
    return {"state": st.get("state"), "plan_sha256": bound or live,
            "unreturned": [r for r in rows if r["status"] in ("queued", "running")],
            "report_lane": st.get("report_lane")}
