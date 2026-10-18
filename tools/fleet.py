#!/usr/bin/env python3
"""
fleet.py - the ceiling on how many AGENTS exist at once, across every swarm on a target.

TWO DIFFERENT CEILINGS, AND THEY ARE NOT THE SAME NUMBER.

  * dynamic/limits.py bounds HTTP concurrency: how many requests are on the wire against the
    program's host. That is the program's limit, read from its scope file.
  * this file bounds AGENT concurrency: how many members are alive at once, across coverage, depth,
    stack and prove together. That is the PROVIDER's limit, and it is the one that has actually
    killed hunts on this pipeline.

MAX_AGENTS IS 30 IN TOTAL, NOT 30 PER SWARM. Running three swarms does not mean 90 agents. The wave
cap in sec-orchestrator exists because parallel-spawning the whole roster once killed a hunt on
provider rate limits; multi-swarm re-allocates the tested ceiling across three methods rather than
tripling it. Raising MAX_AGENTS should be a deliberate edit with the reason recorded here, never a
side effect of adding a role.

The lease machinery is SharedLimiter's, unchanged - pid-liveness, bounded extensions, degraded mode,
all already tested. Only the calibration differs, and it differs a lot: an HTTP lease covers one
exchange (seconds), an agent slot covers a member's entire run (minutes to hours). Hence the long
TTL and generous extension budget below, which is exactly why max_extensions had to stop being a
module constant.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dynamic"))

from limits import SharedLimiter  # noqa: E402

# PROVISIONAL - chosen, not measured. 30 is the width part 1 was built and tested around.
MAX_AGENTS = 30

# A member runs for minutes. 10 min x 12 extensions ~= 2h before a slot is presumed leaked; a member
# that dies frees its slot immediately via pid-liveness, so this only covers the case where nothing
# reports the death at all.
AGENT_LEASE_TTL = 600.0
AGENT_MAX_EXTENSIONS = 12

STATE = ROOT / "state" / "fleet.json"


def limiter(max_agents: int = MAX_AGENTS, path: Path | None = None) -> SharedLimiter:
    """The agent-slot limiter. max_requests=0 disables budget semantics - only lease() is used."""
    return SharedLimiter(path or STATE, rps=10_000.0, burst=10_000, max_requests=0,
                         concurrency=max(int(max_agents), 1),
                         lease_ttl=AGENT_LEASE_TTL, max_extensions=AGENT_MAX_EXTENSIONS)


def split(max_agents: int, role_weights: dict, caps: dict) -> dict:
    """Divide the agent ceiling between roles: every role at least 1, the rest by weight.

    `caps[role]` is the most members that role can actually USE - it has only so many shards. A slot
    handed to a role that cannot fill it is not conservative, it is wasted: it counts against
    MAX_AGENTS while no agent occupies it, so another role runs narrower for nothing. Capped roles
    therefore hand their surplus back and it is re-offered to the roles that can still grow.

    Deterministic by construction - integer arithmetic, largest-remainder, ties broken by role name -
    because the fleet hash binds to it and a resume has to reproduce it exactly.
    """
    roles = sorted(role_weights)
    if not roles:
        return {}
    if len(roles) >= max_agents:                 # more roles than slots: one each, honestly narrow
        return {r: min(1, caps.get(r, 1)) or 1 for r in roles}

    out = {r: 1 for r in roles}
    pool = max_agents - len(roles)

    # Re-offer until nothing moves: a capped role returns its share, and the rest absorb it.
    for _ in range(len(roles) + 1):
        growable = [r for r in roles if out[r] < caps.get(r, max_agents)]
        if pool <= 0 or not growable:
            break
        total = sum(role_weights[r] for r in growable) or 1
        exact = {r: pool * role_weights[r] / total for r in growable}
        given = 0
        for r in growable:
            take = min(int(exact[r]), caps.get(r, max_agents) - out[r])
            out[r] += take
            given += take
        spare = pool - given
        for r in sorted(growable, key=lambda r: (-(exact[r] - int(exact[r])), r)):
            if spare <= 0:
                break
            if out[r] < caps.get(r, max_agents):
                out[r] += 1
                given += 1
                spare -= 1
        if given == 0:
            break
        pool -= given
    return out
