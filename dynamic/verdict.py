#!/usr/bin/env python3
"""
verdict.py — what a probe result is allowed to mean.

The pipeline's verdict vocabulary grew one word at a time (HIT / CLEAR / BLOCKED in web/sweep.py,
NEEDS-BROWSER when the browser probes landed, code-confirmed in the dynamic-hunt skill, proven /
not tested in chain-craft). Those words mix two independent questions, and the mixing caused a real
defect: `web/sweep.py:verdict()` derived everything from a `confirmed` bool and returned "CLEAR" as
the FALLTHROUGH, so a timing or blind probe that simply did not fire was recorded as "surface exists,
checked, defended".

That is the one mistake this module exists to make unrepresentable. The two questions are:

  state     — what do we now know about the vulnerability?
  evidence  — what backs that claim up?

They are orthogonal. CONFIRMED+CODE (airtight by inspection, never fired) and CONFIRMED+RUNTIME
(fired and reproduced) are both honest, and they are not the same claim. A single string could never
say which.

THE RULE, and the reason for the whole file:

    CLEAR means the guard was read AND the attack was sent AND it was observed rejected,
    and you can name both. Anything else that failed to fire is NOT_CONFIRMED.

    Absence of signal is not evidence of absence.

CLEAR is therefore only ever constructed through `cleared()`, which demands the guard and the
rejected attack as arguments. There is no code path that reaches CLEAR by falling off the end of an
if-chain.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class State(str, Enum):
    """What we know about the vulnerability. Ordered loosely from 'nothing' to 'proven'."""

    UNTESTED = "UNTESTED"
    """Nothing was sent and nothing was read. The starting state of every matrix row."""

    N_A = "N/A"
    """The surface does not exist on this target. Say why — 'no upload endpoint', not 'n/a'."""

    BLOCKED = "BLOCKED"
    """The surface exists but could not be tested: scope refusal, rate, WAF, missing credentials,
    a tool that isn't installed. Say what stopped you and what would unblock it. Never CLEAR."""

    NEEDS_EXTERNAL_SIGNAL = "NEEDS_EXTERNAL_SIGNAL"
    """Testable only through a channel we do not currently have — a real browser, an out-of-band
    callback the target can actually reach, or a human. The probe was NOT sent. Distinct from
    BLOCKED in that the blocker is a missing capability, not a refusal."""

    NOT_CONFIRMED = "NOT_CONFIRMED"
    """The attack was sent and nothing came back. This is NOT the same as defended: the payload may
    be wrong, the callback egress-filtered, the timing masked by jitter. It is the honest verdict for
    every probe that fires blank, and it is what CLEAR used to silently absorb."""

    CLEAR = "CLEAR"
    """The attack was sent, a guard was observed rejecting it, and both can be named. The only state
    that licenses 'this class is defended here'. Construct via cleared() — never by fallthrough."""

    LEAD = "LEAD"
    """A signal worth pursuing that does not yet meet the confirmation bar — a scanner match, a
    suspicious differential, a stack fingerprint. Never reportable on its own."""

    CONFIRMED = "CONFIRMED"
    """The bug is real and the evidence field says how we know."""

    def is_terminal_negative(self) -> bool:
        """States that close a matrix row without a finding. NOT_CONFIRMED is deliberately absent:
        it means 'we looked and cannot say', which leaves the row open."""
        return self in (State.CLEAR, State.N_A)

    def needs_followup(self) -> bool:
        """Rows a hunt must not silently leave behind."""
        return self in (State.UNTESTED, State.BLOCKED, State.NEEDS_EXTERNAL_SIGNAL,
                        State.NOT_CONFIRMED, State.LEAD)


class Evidence(str, Enum):
    """What backs the state up. Independent of the state itself."""

    NONE = "NONE"
    """Nothing recorded. Valid only for UNTESTED, N/A, BLOCKED and NEEDS_EXTERNAL_SIGNAL."""

    CODE = "CODE"
    """Established by reading the source. Honest for the disclosure-ethics exemptions (detection-only
    classes, anything that would be an availability test on a live host). Never presented as tested."""

    RUNTIME = "RUNTIME"
    """A request was sent and the response recorded — the transcript ids are the proof."""

    BROWSER = "BROWSER"
    """Asserted in a real browser. The only evidence that settles DOM XSS and CSTI."""

    OOB = "OOB"
    """An out-of-band callback arrived carrying our token. The non-timing proof for blind classes."""


# States where claiming runtime evidence would be a contradiction: nothing was sent.
_NO_SEND_STATES = frozenset({State.UNTESTED, State.N_A, State.BLOCKED,
                             State.NEEDS_EXTERNAL_SIGNAL})


@dataclass
class Verdict:
    """A state, the evidence behind it, and the sentence a human needs to check the claim."""

    state: State
    evidence: Evidence = Evidence.NONE
    reason: str = ""
    guard: str = ""             # CLEAR only: what rejected the attack
    attack: str = ""            # CLEAR only: what was sent and rejected
    transcript_ids: list = field(default_factory=list)
    channel: Evidence = Evidence.BROWSER
    """NEEDS_EXTERNAL_SIGNAL only: which signal is MISSING (BROWSER or OOB).

    Deliberately not the `evidence` field. Evidence says what backs the claim up, and in this state
    nothing does — the whole point is that the probe could not be run. Overloading `evidence` to mean
    'the thing we wish we had' is what made an early draft render every browser-needing verdict as
    NEEDS-OOB.
    """

    def __post_init__(self):
        self.state = State(self.state)
        self.evidence = Evidence(self.evidence)
        self.channel = Evidence(self.channel)

        if self.state is State.CLEAR and not (self.guard and self.attack):
            raise ValueError(
                "CLEAR requires both the guard that rejected the attack and the attack that was "
                "sent. A probe that merely failed to fire is NOT_CONFIRMED — see dynamic-hunt's "
                "verdict table. Use cleared() rather than constructing this by hand.")

        if self.state in _NO_SEND_STATES and self.evidence in (Evidence.RUNTIME, Evidence.OOB):
            raise ValueError(
                f"{self.state.value} claims {self.evidence.value} evidence, but nothing was sent in "
                f"that state. Either the state is wrong or the evidence is.")

        if self.state is State.CONFIRMED and self.evidence is Evidence.NONE:
            raise ValueError(
                "CONFIRMED with no evidence is the No-Hallucination violation this schema exists to "
                "catch. Say what proves it: CODE, RUNTIME, BROWSER or OOB.")

    # ------------------------------------------------------------------ legacy rendering ---
    def render(self) -> str:
        """The word the run board, the coverage matrix and the agents already read.

        The vocabulary in the skills does not change — only the set of things that can produce each
        word. NOT_CONFIRMED is the one genuinely new row, and it renders distinctly on purpose: it
        used to be printed as `clear`, which is exactly the laundering being fixed.
        """
        if self.state is State.CONFIRMED:
            return "HIT" if self.evidence is not Evidence.CODE else "code-confirmed"
        if self.state is State.NEEDS_EXTERNAL_SIGNAL:
            return "NEEDS-OOB" if self.channel is Evidence.OOB else "NEEDS-BROWSER"
        if self.state is State.BLOCKED:
            return "BLOCKED"
        if self.state is State.NOT_CONFIRMED:
            return "NOT-CONFIRMED"
        if self.state is State.CLEAR:
            return "CLEAR"
        if self.state is State.LEAD:
            return "LEAD"
        if self.state is State.N_A:
            return "N/A"
        return "UNTESTED"

    def one_line(self) -> str:
        if self.state is State.CLEAR:
            return f"CLEAR — {self.guard} rejected {self.attack}"
        return f"{self.render()}{' — ' + self.reason if self.reason else ''}"


# ------------------------------------------------------------------------- constructors ---
# Every state gets a named constructor so the call site reads as a claim, and so the arguments each
# state actually requires cannot be forgotten.

def confirmed(reason: str, evidence: Evidence = Evidence.RUNTIME, ids: list | None = None) -> Verdict:
    return Verdict(State.CONFIRMED, evidence, reason, transcript_ids=ids or [])


def cleared(guard: str, attack: str, ids: list | None = None) -> Verdict:
    """The ONLY way to produce a CLEAR.

    Both arguments are mandatory and both are load-bearing: `guard` is what the code does to stop the
    attack, `attack` is what was actually sent. A caller that cannot fill in both does not have a
    CLEAR — it has a NOT_CONFIRMED.
    """
    return Verdict(State.CLEAR, Evidence.RUNTIME, guard=guard, attack=attack,
                   transcript_ids=ids or [])


def not_confirmed(reason: str, ids: list | None = None) -> Verdict:
    """Sent, nothing came back, and we are NOT claiming the bug is absent."""
    return Verdict(State.NOT_CONFIRMED, Evidence.RUNTIME, reason, transcript_ids=ids or [])


def lead(reason: str, evidence: Evidence = Evidence.RUNTIME, ids: list | None = None) -> Verdict:
    return Verdict(State.LEAD, evidence, reason, transcript_ids=ids or [])


def blocked(reason: str) -> Verdict:
    return Verdict(State.BLOCKED, Evidence.NONE, reason)


def needs_external(reason: str, channel: Evidence = Evidence.BROWSER) -> Verdict:
    """`channel` says which signal is missing — BROWSER or OOB. It is recorded, not inferred."""
    return Verdict(State.NEEDS_EXTERNAL_SIGNAL, Evidence.NONE, reason, channel=channel)


def not_applicable(reason: str) -> Verdict:
    return Verdict(State.N_A, Evidence.NONE, reason)


def untested(reason: str = "") -> Verdict:
    return Verdict(State.UNTESTED, Evidence.NONE, reason)


# --------------------------------------------------------------------- compatibility shim ---
# word -> (state, evidence, missing channel)
_LEGACY = {
    "HIT": (State.CONFIRMED, Evidence.RUNTIME, Evidence.BROWSER),
    "CLEAR": (State.CLEAR, Evidence.RUNTIME, Evidence.BROWSER),
    "BLOCKED": (State.BLOCKED, Evidence.NONE, Evidence.BROWSER),
    "NEEDS-BROWSER": (State.NEEDS_EXTERNAL_SIGNAL, Evidence.NONE, Evidence.BROWSER),
    "NEEDS-OOB": (State.NEEDS_EXTERNAL_SIGNAL, Evidence.NONE, Evidence.OOB),
    "NOT-CONFIRMED": (State.NOT_CONFIRMED, Evidence.RUNTIME, Evidence.BROWSER),
    "code-confirmed": (State.CONFIRMED, Evidence.CODE, Evidence.BROWSER),
    "LEAD": (State.LEAD, Evidence.RUNTIME, Evidence.BROWSER),
    "N/A": (State.N_A, Evidence.NONE, Evidence.BROWSER),
    "UNTESTED": (State.UNTESTED, Evidence.NONE, Evidence.BROWSER),
}


def from_legacy(word: str, reason: str = "", guard: str = "", attack: str = "") -> Verdict:
    """Parse one of the historic verdict strings.

    Reading an old sweep.json or findings.json must keep working. A legacy "CLEAR" carries no record
    of which guard produced it, so it is admitted with placeholder text rather than being silently
    downgraded — the data is what it is, and rewriting history would be its own dishonesty. New code
    must go through cleared().
    """
    key = (word or "").strip()
    if key not in _LEGACY:
        raise ValueError(f"unknown legacy verdict {word!r}; expected one of {sorted(_LEGACY)}")
    state, ev, chan = _LEGACY[key]
    if state is State.CLEAR:
        return Verdict(state, ev, reason,
                       guard=guard or "(not recorded — legacy verdict)",
                       attack=attack or "(not recorded — legacy verdict)", channel=chan)
    return Verdict(state, ev, reason, channel=chan)


# =================================================== per-class evidence: the write chain ===
#
# A write succeeds silently, so confirming one needs a read-back - and that creates a trap. If the
# only evidence is "we wrote a marker and read it back", the bundle conflates TWO bugs and the report
# leans on a second primitive: a reader might reasonably ask whether the read path was the real
# finding. So the steps are recorded separately and the report can say which one carries the claim.
#
# This is a per-class refinement of the `evidence` dict, NOT a third state machine. Two already
# exist and a third would recreate the drift this module was written to remove:
#
#   probe level     State x Evidence        (this file)
#   finding level   state/ledger.json       NEW -> TRIAGED -> CONFIRMED -> REPORTED -> FIXED ...

WRITE_ATTEMPTED = "write_attempted"
"""A payload naming a destination outside the intended root was sent. Proves nothing on its own."""

DESTINATION_RESOLVED = "destination_resolved"
"""The response or a side channel shows where the path actually resolved to."""

WRITE_CONFIRMED = "write_confirmed"
"""Bytes we chose exist at a destination outside the intended root. THE finding for this class."""

READBACK_CONFIRMED = "readback_confirmed"
"""The marker was retrieved through a read path. One WAY to establish write_confirmed - and a
dependency on another primitive, which is why it is recorded as its own step."""

EXECUTION_POSSIBLE = "execution_possible"
"""The reached directory is on an import path, web root, or cron/rc location. SCORED, from the path
alone - it raises CVSS and belongs in the report as reasoning labelled `not tested`."""

EXECUTION_TESTED = "execution_tested"
"""Never set by this pipeline. Present so its absence is explicit rather than an omission:
disclosure-ethics forbids persistence, and the gadgets here (authorized_keys, .bashrc, cron, .pth)
are exactly what a real attacker uses."""

WRITE_STEPS = (WRITE_ATTEMPTED, DESTINATION_RESOLVED, WRITE_CONFIRMED,
               READBACK_CONFIRMED, EXECUTION_POSSIBLE, EXECUTION_TESTED)


def write_confirmed(evidence: dict) -> bool:
    """Does this evidence support a CONFIRMED verdict for the file-write class?

    Deliberately strict: a read-back alone is not enough unless it is tied to a write we performed.
    An attacker-controlled name reaching a read path is a traversal READ bug - a different finding,
    owned by a different primitive.
    """
    ev = evidence or {}
    if ev.get(EXECUTION_TESTED):
        raise ValueError(
            "execution_tested must never be set: disclosure-ethics forbids persistence, and "
            "reaching a writable location outside the root is already the finding.")
    return bool(ev.get(WRITE_CONFIRMED) and ev.get(WRITE_ATTEMPTED))


def describe_write_evidence(evidence: dict) -> str:
    """One line a report can quote, naming how the write was established."""
    ev = evidence or {}
    if not ev.get(WRITE_CONFIRMED):
        return "write not established"
    how = "read back through a separate read path" if ev.get(READBACK_CONFIRMED) else           "observed directly at the destination"
    extra = ""
    if ev.get(EXECUTION_POSSIBLE):
        extra = ("; destination is on an executed path (" + str(ev[EXECUTION_POSSIBLE]) +
                 ") - scored, not tested")
    return "write confirmed, " + how + extra


# ============================================ mapping the two machines that already exist ===
# The probe says what it observed; the ledger says where the finding stands. Without a mapping the
# two drift by hand, which is how a CONFIRMED probe ends up filed under a stale status.

_LEDGER = {
    State.CONFIRMED: "CONFIRMED",
    State.LEAD: "TRIAGED",          # a signal worth keeping, not yet a finding
    State.NOT_CONFIRMED: "TRIAGED",  # looked and cannot say - the row stays open
    State.CLEAR: "FALSE_POSITIVE",   # attacked, a guard rejected it, and we can name both
    State.N_A: "FALSE_POSITIVE",     # the surface does not exist here
    State.BLOCKED: "BLOCKED",
    State.NEEDS_EXTERNAL_SIGNAL: "BLOCKED",
    State.UNTESTED: "NEW",
}


def ledger_status(v: "Verdict", scope_refused: bool = False) -> str:
    """The `state/ledger.json` status this verdict implies.

    `scope_refused` is separate because the ledger distinguishes it from a general BLOCKED, and the
    difference matters: a scope refusal is an authorization boundary we respected, not a capability
    we lacked.
    """
    if scope_refused:
        return "SCOPE_REFUSED"
    return _LEDGER[State(v.state)]
