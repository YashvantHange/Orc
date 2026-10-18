#!/usr/bin/env python3
"""
chains.py - compose separate findings into the attack path they actually form.

THE GAP THIS CLOSES. `sec-orchestrator` says it plainly: *"Assembling the chain is your job - no
single hunter sees both ends, and no scanner sees any of it."* That instruction had no mechanism
behind it. `correlate/merge.py` dedups SCANNER output; nothing composed the hunters' confirmed
findings, there was no artifact, and no gate. An instruction with no artifact is a suggestion.

THE RULE THE WHOLE MODULE EXISTS TO ENFORCE:

    A chain whose links are each merely SUSPICIOUS is not a chain.

Severity inflation is the failure mode here, and it is seductive: three medium findings that "could"
compose read like a critical. So every adjacency must be DEMONSTRATED - the output of link N shown
to be the input link N+1 actually consumes - and a chain is only as strong as its proven prefix.
`chain-craft` already names the tell: catching yourself writing "this could lead to" without a
request to point at.

WHAT THIS IS NOT. It does not hunt. It reads what the hunters found and asks one question they
cannot: does A feed B? Novelty is still per-link (`variant-analysis`), impact is still the impact
gate, and a chain never launders a link that a published advisory already covers.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

# Per-link confidence. Deliberately the vocabulary `chain-craft` already uses, so a chain's links
# and a hunter's verdicts cannot drift apart.
PROVEN = "proven"                  # runtime evidence: transcript ids, a recorded response
CODE_CONFIRMED = "code-confirmed"  # airtight by inspection, never fired
NOT_TESTED = "not tested"          # reasoning only - carries no severity

STATUSES = (PROVEN, CODE_CONFIRMED, NOT_TESTED)


class ChainError(Exception):
    """A malformed chain. Raised rather than dropped: a chain that silently loses a link is how a
    two-link reality gets reported as a four-link critical."""


@dataclass
class Link:
    """One finding, in the position it occupies in an attack path."""

    finding_id: str
    vuln_class: str
    status: str = NOT_TESTED
    evidence: list = field(default_factory=list)   # T##### ids, or file:line
    consumes: str = ""      # what this link needs from the previous one
    produces: str = ""      # what this link hands to the next one
    demonstrated_by: str = ""
    """How the adjacency was SHOWN, not argued.

    The load-bearing field. "The SSRF reaches the metadata endpoint" is an argument; "T00412 shows
    the response body containing the token that T00415 then submits" is a demonstration. Empty means
    the adjacency is untested, whatever the two links' own statuses say.
    """

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ChainError(
                f"link {self.finding_id}: status {self.status!r} is not one of {STATUSES}. "
                f"Use the same words chain-craft uses, so links and verdicts cannot drift.")
        if self.status in (PROVEN, CODE_CONFIRMED) and not self.evidence:
            raise ChainError(
                f"link {self.finding_id}: claims {self.status!r} with nothing behind it. A link "
                f"carries transcript ids or a file:line, or its status is {NOT_TESTED!r}.")


@dataclass
class Chain:
    """An ordered attack path, and an honest account of how much of it is real."""

    chain_id: str
    links: list
    summary: str = ""

    def __post_init__(self):
        if len(self.links) < 2:
            raise ChainError(f"{self.chain_id}: a chain needs at least two links; one finding is a "
                             f"finding, and calling it a chain inflates it")

    # ------------------------------------------------------------------- the honest part ---
    def proven_prefix(self) -> list:
        """The leading run of links that are genuinely established AND genuinely connected.

        Stops at the first link that is not proven, or whose adjacency to its predecessor was never
        demonstrated. Everything after that is reasoning, and reasoning carries no severity.
        """
        out = []
        for i, link in enumerate(self.links):
            if link.status != PROVEN:
                break
            if i > 0 and not link.demonstrated_by:
                break        # the link is real; the JOIN to the previous one is not
            out.append(link)
        return out

    def broken_at(self) -> int:
        """Index of the first link that does not hold, or -1 when the whole chain is proven."""
        n = len(self.proven_prefix())
        return -1 if n == len(self.links) else n

    def is_complete(self) -> bool:
        return self.broken_at() == -1

    def unevidenced(self) -> list:
        return [l.finding_id for l in self.links if not l.evidence]

    def undemonstrated_joins(self) -> list:
        """Adjacencies asserted but never shown. The severity-inflation surface."""
        return [f"{self.links[i - 1].finding_id} -> {self.links[i].finding_id}"
                for i in range(1, len(self.links)) if not self.links[i].demonstrated_by]

    # ------------------------------------------------------------------------ reporting ---
    def severity_basis(self) -> str:
        """What a CVSS vector may be derived from. Never the whole chain unless the whole chain
        is proven - that substitution is exactly what this module prevents."""
        prefix = self.proven_prefix()
        if not prefix:
            return "nothing proven - this is a hypothesis, not a finding"
        if self.is_complete():
            return f"the full chain ({len(prefix)} links, all proven and connected)"
        return (f"the proven prefix only: {' -> '.join(l.vuln_class for l in prefix)}"
                f" ({len(prefix)} of {len(self.links)} links)")

    def render(self) -> str:
        lines = [f"{self.chain_id}: {self.summary or '(no summary)'}"]
        for i, link in enumerate(self.links):
            join = ""
            if i > 0:
                join = ("  [join: " + link.demonstrated_by + "]") if link.demonstrated_by \
                    else "  [JOIN NOT DEMONSTRATED]"
            ev = ",".join(link.evidence[:3]) if link.evidence else "no evidence"
            lines.append(f"  {i + 1}. {link.vuln_class:28} {link.status:14} {ev}{join}")
        lines.append(f"  severity basis: {self.severity_basis()}")
        return "\n".join(lines)


# ------------------------------------------------------------------------------ the gate ---
def gate(chain: Chain) -> tuple:
    """(ok, reasons). `ok` means this chain may be reported AS A CHAIN.

    A refusal is not a rejection of the findings - each link may still be reported on its own. It
    refuses the COMPOSITION, which is the part that would carry inflated severity.
    """
    reasons = []
    missing = chain.unevidenced()
    if missing:
        reasons.append(
            "links with no evidence at all: " + ", ".join(missing) +
            " - a link carries transcript ids or a file:line, or it is not a link")
    joins = chain.undemonstrated_joins()
    if joins:
        reasons.append(
            "adjacencies asserted but never shown: " + ", ".join(joins) +
            " - show the output of one link being consumed by the next, or report them separately")
    if not chain.proven_prefix():
        reasons.append(
            "no proven prefix - the first link itself is not established at runtime, so there is "
            "no foothold for the rest to build on")
    return (not reasons), reasons


# --------------------------------------------------------------------------------- io ---
def load(path: str | Path) -> list:
    """Read chains.json. Raises rather than skipping a malformed chain."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ChainError(f"{p}: not readable as JSON: {e}") from e
    out = []
    for raw in (doc.get("chains") or []):
        links = [Link(**l) for l in (raw.get("links") or [])]
        out.append(Chain(chain_id=raw.get("chain_id", "?"), links=links,
                         summary=raw.get("summary", "")))
    return out


def save(path: str | Path, chains: list) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({
        "version": 1,
        "chains": [{
            "chain_id": c.chain_id, "summary": c.summary,
            "complete": c.is_complete(), "severity_basis": c.severity_basis(),
            "links": [{"finding_id": l.finding_id, "vuln_class": l.vuln_class,
                       "status": l.status, "evidence": l.evidence,
                       "consumes": l.consumes, "produces": l.produces,
                       "demonstrated_by": l.demonstrated_by} for l in c.links],
        } for c in chains],
    }, indent=2), encoding="utf-8")
    return p
