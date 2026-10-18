#!/usr/bin/env python3
"""
impact_gate.py — the impact-bar gate. Runs BEFORE a report lane opens, not after it delivers.

Why this file exists. Every other stage of this pipeline checks that a report's claims are TRUE:
the PoC really ran (runlog), the fences match it (report-auditor), the vector arithmetic is right
(gate.check_cvss), the finding is novel (dup). Nothing checked that the impact clears the bar of the
program it is being sent to. Three reports have now been closed by Google with the same sentence —
"not severe enough for us to track it as a security bug ... feel free to publicly disclose this
issue on GitHub as a public issue":

    FIL-004   filament CI /docs presubmit guard always passes          (2026-09-04)
    FIL-005   filament docs direct-edit guard bypass                   (2026-09-04)
    SHAKA-003 shaka-player Cast-sender prototype pollution, CVSS 3.8   (2026-09-08)

All three were unimpeachably proven and all three were unreportable. The gap was never proof, it was
that the impact question was asked in prose (a skill, a memory file) that a run could sail past. This
module makes it a recorded artifact with a verdict, on the same footing as the dup check and the
runlog, so `hunt report` and the delivery gate can refuse without it.

It grades nothing about the writing. It asks the six questions that killed real reports and refuses
on the answers.

  hunt impact-gate <id> --program google-oss-vrp --vector 'CVSS:3.1/...' \
      --attacker '...' --boundary '...' --impact '...' --marginal-gain '...' \
      --gadget '...' --default-config yes|no --precondition '...' --precondition '...'
  hunt impact-gate <id> --show
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "reports"))

IMPACT_GATE_VERSION = 2

# The observed floor. Google has closed a 3.8 as not worth tracking; nothing below 4.0 has ever been
# accepted by a program in this pipeline's history. This is not the CVSS spec's opinion of "Low", it
# is a record of what actually gets closed.
#
# Read it as a floor and nothing more. Clearing it predicts NOTHING: on 2026-09-21 Google closed
# SHAKA-C8-001 (issue 564006943) at P4/S4 "not severe enough to track" — a runtime-confirmed C:H
# credential disclosure with a one-line fix, self-scored 7.1 High, i.e. at nearly twice the floor.
# What decided it was the precondition stack, which CVSS prices at zero. The precondition check
# below is the load-bearing one in this file; the score check is the cheap one.
SEVERITY_FLOOR = 4.0

# Answers that mean "I have no answer". Cheap, and it catches the real failure — a field filled in to
# get past the gate rather than because the question was asked.
EMPTY = {"", "-", "n/a", "na", "none", "tbd", "todo", "unknown", "unclear", "?", "not demonstrated"}


def record_path(finding_id: str) -> Path:
    return ROOT / "state" / "impact" / f"{finding_id}.json"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _blank(v) -> bool:
    return str(v or "").strip().lower() in EMPTY


def _vector_of(s: str) -> str:
    """The bare CVSS:3.1 vector out of a string that may also carry a score and a severity word."""
    m = re.search(r"CVSS:3\.1/(?:[A-Z]+:[A-Z]+/?)+", s or "")
    return m.group(0).rstrip("/") if m else ""


def _score(vector: str) -> tuple[float, str]:
    import cvss
    score, sev, _canon = cvss.score_vector(vector)
    return score, sev


def _config_named(pre: list) -> bool:
    """Is non-default configuration ALREADY one of the listed preconditions? Keeps the count honest
    rather than charging the same condition twice."""
    pat = re.compile(r"\b(config|configur\w*|opt(?:ed|s)?[- ]in|enabl\w*|set(?:s|ting)?\b|"
                     r"non-default|must have set|drm\.|\.servers\[|\.advanced\[)", re.I)
    return any(pat.search(str(p or "")) for p in pre)


def evaluate(ans: dict) -> tuple[str, list, list]:
    """Return (verdict, blockers, notes). Pure function of the answers — no filesystem, no network."""
    blockers: list = []
    notes: list = []

    for field, question in (
        ("attacker", "who wants this and does not already have the outcome legitimately"),
        ("boundary", "which trust boundary the attack crosses"),
        ("impact", "which C/I/A property breaks, concretely"),
        ("marginal_gain", "what the same attacker can ALREADY do through documented/intended inputs"),
    ):
        if _blank(ans.get(field)):
            blockers.append(f"--{field.replace('_', '-')} is unanswered: {question}")

    # 1. Severity floor.
    vector = (ans.get("vector") or "").strip()
    if not vector:
        blockers.append("--vector is required: the gate scores the finding, it does not take your word")
    else:
        try:
            score, sev = _score(vector)
            ans["score"], ans["severity"] = score, sev
            if score < SEVERITY_FLOOR:
                blockers.append(
                    f"{score:.1f} ({sev}) is below the observed floor of {SEVERITY_FLOOR:.1f}. "
                    f"SHAKA-003 was closed Infeasible at 3.8. The ceiling for this finding is an "
                    f"upstream GitHub issue, not a VRP report")
            elif score < 5.0:
                notes.append(f"{score:.1f} clears the floor but only just — expect no reward, and "
                             f"say so to the user before the report lane is spent")
        except ValueError as e:
            blockers.append(f"--vector does not parse: {e}")

    # 2. Primitive without a gadget. The SHAKA-003 shape exactly: pollution proven, exploitation not.
    if _blank(ans.get("gadget")):
        blockers.append(
            "--gadget is unanswered. A proven PRIMITIVE (a prototype write, an unvalidated font "
            "family, a spoofable field, an out-of-bounds index) is not a finding on its own — name "
            "the demonstrated chain from the primitive to the C/I/A outcome, or drop the lead. "
            "\"The PoC proves the primitive and stops there\" is what got SHAKA-003 closed")

    # 3. Precondition stack. Each one multiplies into the vendor's severity judgement even when CVSS
    #    prices none of them (non-default config, an active user action, a semi-trusted attacker role).
    #
    #    This is the check that decides real outcomes, and the pipeline has now paid to learn it
    #    twice. SHAKA-C8-001 was BLOCKED here on three preconditions, the block was overridden on a
    #    five-point rationale (C:H is the named inclusion class; 7.1 is well clear of the floor; it
    #    terminates in a real credential, not a bare primitive; it violates shaka's own documented
    #    invariant; a Widevine control forecloses working-as-intended) — and Google closed it P4/S4
    #    Infeasible anyway. Every one of those five grounds was true and none of them mattered. The
    #    override is still available below, because the operator owns the decision, but it now has an
    #    observed record and the record is 0 for 1.
    #
    #    3a. Non-default configuration is the heaviest single condition, so it lowers the threshold.
    #    "The application must have configured X" means the finding does not fire on the library as
    #    shipped, and the population it can touch is whoever opted in. Two conditions with that as
    #    one of them is the same shape as three ordinary ones. SHAKA-C10-002 is the pure case: the
    #    victim had to have actively set sameOriginOnly=true, i.e. the only affected deployments were
    #    the ones that opted INTO the protection.
    pre = [p for p in (ans.get("preconditions") or []) if not _blank(p)]
    ans["preconditions"] = pre

    dflt = str(ans.get("default_config") or "").strip().lower()
    if dflt not in {"yes", "no"}:
        blockers.append(
            "--default-config is unanswered (yes|no): does the attack fire on the target's DEFAULT "
            "configuration, as shipped, with no setting the application had to opt into? This is the "
            "question that decided SHAKA-C8-001 at P4/S4 despite a self-scored 7.1 C:H. A finding "
            "that fires on the default config is the only shape worth a report lane at Google OSS VRP")
    ans["default_config"] = dflt if dflt in {"yes", "no"} else ""

    needs_config = (dflt == "no")
    threshold = 2 if needs_config else 3
    effective = len(pre) + (1 if needs_config and not _config_named(pre) else 0)

    if effective >= threshold:
        detail = '; '.join(pre) or "(none listed)"
        if needs_config:
            blockers.append(
                f"non-default configuration plus {effective - 1} further condition(s) must all hold: "
                f"{detail}. The finding does not fire on the target as shipped, so the affected "
                f"population is whoever opted in — that is the heaviest condition there is, and two "
                f"conditions including it is the SHAKA-C10-002 / SHAKA-C8-001 shape. Expected outcome "
                f"is Infeasible whatever the vector says")
        else:
            blockers.append(
                f"{effective} independent preconditions must all hold: {detail}. Three or more is "
                f"below every bar this pipeline has observed — SHAKA-C8-001 stacked three and was "
                f"closed P4/S4 Infeasible at a self-scored 7.1 C:H with a one-line fix")
    elif pre:
        notes.append(f"{len(pre)} precondition(s) recorded — every one of them belongs in the report, "
                     f"stated plainly, not buried. The report that states them honestly is scored on "
                     f"exactly that text; SHAKA-C8-001's Summary enumerated its three and that is "
                     f"what the triager graded")
    if dflt == "yes" and not pre:
        notes.append("fires on the default configuration with no stacked preconditions — this is the "
                     "one shape that has ever been worth a report lane here")

    # 3b. Does the finding's CIA profile match what the destination program calls a vulnerability?
    #
    #     SHAKA-006 was closed "The report is out of scope for the selected VRP" (2026-09-08). It was a
    #     runtime-proven, gate-passed, twice-audited CVSS 6.5 non-terminating loop — and unreportable,
    #     because Google OSS VRP defines a qualifying product vulnerability as one "substantially
    #     affecting the confidentiality or integrity of user data". Availability is absent from that
    #     sentence. There is no bullet anywhere saying "DoS is excluded", which is exactly how it was
    #     missed: the rules were searched for an EXCLUSION, none was found, and scope was inferred from
    #     that absence. The disqualifier was sitting in the report's own vector, C:N/I:N/A:H.
    #
    #     So this check reads the vector rather than the prose: a pure-availability finding cannot
    #     satisfy a confidentiality-or-integrity definition, whatever the score says.
    PROGRAMS_REQUIRING_C_OR_I = {"google-oss-vrp", "google-vrp", "g.co/vulnz", "bughunters"}
    program = (ans.get("program") or "").strip().lower()
    vec = _vector_of(vector)
    if program in PROGRAMS_REQUIRING_C_OR_I and vec:
        pure_availability = ("/C:N" in vec and "/I:N" in vec and "/A:N" not in vec)
        if pure_availability:
            blockers.append(
                f"{program} defines a qualifying product vulnerability as one \"substantially "
                f"affecting the confidentiality or integrity of user data\"; this vector is "
                f"C:N/I:N, i.e. availability-only, so it cannot meet that definition regardless of "
                f"score. SHAKA-006 was closed out-of-scope on exactly this at CVSS 6.5. The ceiling "
                f"for an availability-only finding here is an upstream GitHub issue, not a VRP "
                f"report — and on shaka-player that route produced a merged fix in two days")

    # 4/5. The two classes already closed Infeasible by name. See the 2026-09-04 mistake-log entry.
    if ans.get("dev_tool"):
        blockers.append(
            "the affected component is self-described developer/debug/preview/inspector tooling. An "
            "open transport or missing origin check there is intended functionality (FIL-006). "
            "Require a proven downstream exploitable sink or drop the lead")
    if ans.get("ci_guard"):
        blockers.append(
            "this is a CI / presubmit / release-pipeline guard defect. Confirmed dead with Google "
            "three times (FIL-004, FIL-005). The ceiling is a public GitHub issue")

    # 6. Marginal gain must actually be a comparison, not a restatement of the attack.
    mg = (ans.get("marginal_gain") or "").strip().lower()
    if mg and mg == (ans.get("impact") or "").strip().lower():
        blockers.append("--marginal-gain repeats --impact. The answer must be what the attacker can "
                        "already do WITHOUT the bug, through a different, intended input")

    override = (ans.get("override") or "").strip()
    if blockers and override:
        notes.append(f"OVERRIDDEN by the user: {override}")
        if any("precondition" in b or "non-default configuration" in b for b in blockers):
            notes.append(
                "OVERRIDE RECORD, precondition blocks: 1 resolved, 0 accepted. SHAKA-C8-001 was "
                "overridden 2026-09-09 on a five-point rationale and closed P4/S4 Infeasible on "
                "2026-09-21 (issue 564006943). GCLI-C8-AUTHN was overridden 2026-09-24 on the same "
                "shape, with that precedent on the table, and has no outcome yet. Tell the user this "
                "record before they decide, not after")
        return "PASS_OVERRIDDEN", blockers, notes
    return ("BLOCK" if blockers else "PASS"), blockers, notes


def write(finding_id: str, ans: dict, verdict: str, blockers: list, notes: list) -> Path:
    p = record_path(finding_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "finding_id": finding_id,
        "impact_gate_version": IMPACT_GATE_VERSION,
        "decided_at": _now(),
        "verdict": verdict,
        "program": ans.get("program", ""),
        "vector": ans.get("vector", ""),
        "score": ans.get("score"),
        "severity": ans.get("severity", ""),
        "answers": {k: ans.get(k) for k in
                    ("attacker", "boundary", "impact", "marginal_gain", "gadget",
                     "preconditions", "default_config", "dev_tool", "ci_guard", "override")},
        "blockers": blockers,
        "notes": notes,
    }
    payload["answers_sha256"] = hashlib.sha256(
        json.dumps(payload["answers"], sort_keys=True).encode()).hexdigest()
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return p


def load(finding_id: str):
    p = record_path(finding_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def cleared(finding_id: str, vector: str = "") -> tuple[bool, str]:
    """Is there a decision on file that lets a report lane open? Used by hunt report and gate.py."""
    d = load(finding_id)
    if d is None:
        return False, (f"no impact-bar decision for {finding_id} — run `hunt impact-gate "
                       f"{finding_id} ...` BEFORE writing the report")
    if d.get("impact_gate_version") != IMPACT_GATE_VERSION:
        return False, f"impact decision was made by gate v{d.get('impact_gate_version')}; re-run it"
    if d.get("verdict") == "BLOCK":
        first = (d.get("blockers") or ["below the bar"])[0]
        return False, f"impact gate says BLOCK: {first}"
    # Ledger rows carry the vector with the score appended ("CVSS:3.1/... = 5.3 (Medium)"), so
    # compare the vector token only — a decision must not go stale over a formatting difference.
    now, then = _vector_of(vector), _vector_of(d.get("vector", ""))
    if now and then and now != then:
        return False, (f"the impact decision was made on {then} but the report/ledger now "
                       f"carries {now} — re-run `hunt impact-gate {finding_id}`")
    tag = " (overridden)" if d.get("verdict") == "PASS_OVERRIDDEN" else ""
    return True, f"impact gate PASS{tag}, {d.get('score')} ({d.get('severity')}), {d.get('decided_at')}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hunt impact-gate", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("id")
    ap.add_argument("--show", action="store_true", help="print the decision on file and exit")
    ap.add_argument("--program", default="", help="google-oss-vrp | github | hackerone | huntr | ...")
    ap.add_argument("--vector", default="", help="the CVSS:3.1 vector; the gate scores it itself")
    ap.add_argument("--attacker", default="", help="who wants this and lacks it legitimately")
    ap.add_argument("--boundary", default="", help="the trust boundary crossed")
    ap.add_argument("--impact", default="", help="the C/I/A property that breaks")
    ap.add_argument("--marginal-gain", dest="marginal_gain", default="",
                    help="what that attacker can ALREADY do through intended inputs")
    ap.add_argument("--gadget", default="",
                    help="the DEMONSTRATED chain from the primitive to the impact")
    ap.add_argument("--precondition", dest="preconditions", action="append", default=[],
                    help="repeatable: one independent precondition per flag")
    ap.add_argument("--default-config", dest="default_config", default="", choices=["", "yes", "no"],
                    help="yes|no: does the attack fire on the target's DEFAULT configuration, as "
                         "shipped? 'no' is the heaviest precondition there is and lowers the "
                         "stacking threshold from three conditions to two")
    ap.add_argument("--dev-tool", action="store_true",
                    help="the component is self-described dev/debug/preview tooling")
    ap.add_argument("--ci-guard", action="store_true",
                    help="the defect is in a CI/presubmit/release-pipeline guard")
    ap.add_argument("--override", default="",
                    help="the user's own words authorising a lane the gate blocks; recorded verbatim")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if a.show:
        d = load(a.id)
        if d is None:
            print(f"no impact decision on file for {a.id}", file=sys.stderr)
            return 2
        print(json.dumps(d, indent=2))
        return 0

    ans = {k: getattr(a, k) for k in ("program", "vector", "attacker", "boundary", "impact",
                                      "marginal_gain", "gadget", "preconditions", "default_config",
                                      "override")}
    ans["dev_tool"], ans["ci_guard"] = a.dev_tool, a.ci_guard
    verdict, blockers, notes = evaluate(ans)
    p = write(a.id, ans, verdict, blockers, notes)

    if a.json:
        print(json.dumps(load(a.id), indent=2))
        return 0 if verdict != "BLOCK" else 1

    print(f"impact-bar gate  {a.id}  ->  {verdict}")
    if ans.get("score") is not None:
        print(f"  {ans['vector']} = {ans['score']:.1f} ({ans['severity']})")
    for b in blockers:
        print(f"  BLOCK  {b}")
    for n in notes:
        print(f"  note   {n}")
    print(f"  {p.relative_to(ROOT)}")
    if verdict == "BLOCK":
        print("\n  No report lane. Do not write this up, do not open a draft advisory.")
        print("  If it is a real defect, the ceiling is an upstream GitHub issue — say that to the")
        print("  user, with the blocker above as the reason, and let them decide.")
    return 0 if verdict != "BLOCK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
