#!/usr/bin/env python3
"""
swarm.py - size a target-shaped swarm, forge the agents it needs, and register them atomically.

WHY THIS EXISTS. The pipeline fanned out three hunters at a time, in waves, because parallel-
spawning the whole roster once killed a hunt on provider rate limits (sec-orchestrator step 4). That
cap is a real scar, but it is also a fixed number chosen for a different failure: with concurrency
now shared across processes (dynamic/limits.py), the wire itself is bounded, so the width can be
COMPUTED from the target and the program's own limits instead of guessed.

THE TWO RULES THAT SHAPE EVERY DECISION HERE:

  1. Weight sets RESOURCES, never COVERAGE. vuln-playbooks' matrix says every applicable row must
     come back HIT/CLEAR/N/A/BLOCKED - "didn't look" is not a state. So a low-severity class may get
     exactly one member with the floor allowance; it never gets zero. `plan()` refuses to emit a
     plan that leaves an applicable row unowned, and shrinks allowances before it drops a row.

  2. Planning is DETERMINISTIC. state.json binds to plan_sha256, so a resume can only prove it is
     continuing the same swarm if the same inputs reproduce the same plan. Everything here sorts
     explicitly, uses integer arithmetic, and excludes wall-clock fields from the hash.

The coverage oracle is tools/audit_coverage.matrix_rows() rather than a second copy of the matrix -
that file already parses vuln-playbooks/SKILL.md and is already tested.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENTS = ROOT / ".claude" / "agents"
ORCHESTRATOR = AGENTS / "sec-orchestrator.md"
RUNBOARD = ROOT / ".claude" / "skills" / "run-board" / "SKILL.md"

sys.path.insert(0, str(ROOT / "tools"))

HARD_CEILING = 30            # the stated cap. Not tunable.

# PROVISIONAL - chosen, not measured. Calibrate from the first completed url/grey run: `saturation`
# from lease-wait vs active time in work/<slug>/web/limits.json, `min_useful` from the real
# per-class request counts `hunt web coverage` already derives from transcript.jsonl. Until then,
# treat a width these produce as a starting point, not a finding about the target.
TUNING = {
    "saturation": 6,                        # members per concurrency slot before rows go idle
    "min_useful": {"3": 120, "2": 80, "1": 40},   # per-member request floor, by weight
    "reserve_frac": 0.20,                   # budget held back for replay / dup / re-verification
}

# Severity potential per owner. This is a PRIORITY, not a filter - see rule 1 above.
WEIGHTS = {
    "rce-exec": 3, "authz-logic": 3, "server-side": 3, "authn-crypto": 3,
    "datastore": 2, "xss": 2, "injection": 2, "client-side": 2,
    "resource-dos": 1, "web-recon": 1,
}
DEFAULT_WEIGHT = 2

# The three hunting METHODS, plus the lane that turns candidates into findings. These are not three
# copies of one swarm: coverage asks "has every class been examined", depth asks "what is hiding
# behind the abstraction layers" (sec-orchestrator step 4b), stack asks "what exists because of what
# this is built ON" (step 4c). More members of one method is `--width`; this is three methods.
ROLES = ("coverage", "depth", "stack", "prove")

# Share of the SURPLUS budget, after every launching role's floors are paid. Coverage leads because
# it is the one that may never be short; depth outranks stack because depth is where the severe bugs
# hide and stack surfaces are cheap to check.
# PROVISIONAL - chosen, not measured, like TUNING.
ROLE_WEIGHTS = {"coverage": 3, "depth": 2, "stack": 1, "prove": 2}

# Preconditions a shard needs from the RUN, not from the agent. The owner column already encodes who
# hunts what; what it cannot encode is whether this run can actually exercise it. Recording them at
# plan time turns a silent CLEAR into an up-front BLOCKED with a reason.
# What a member must hand back for its row to be closeable. A shard that says only "investigate
# SSRF" is a topic; these make the return checkable against what was asked for.
COMPLETION = {
    "coverage": ["a HIT/CLEAR/N/A/BLOCKED verdict per row",
                 "the request that produced each verdict",
                 "the defense observed, named, for every CLEAR"],
    "depth":    ["how many hops were walked, and what was enumerated",
                 "the guard's real location, not the handler's",
                 "a handoff for any sink owned by another member"],
    "stack":    ["a verdict per surface, with the response that decided it",
                 "the fingerprint evidence that put this stack in scope"],
    "prove":    ["the probe actually sent, and what came back",
                 "reproduced 2-3x, or an explicit NOT-CONFIRMED with the reason",
                 "an evidence bundle path for anything CONFIRMED"],
}

CAP_BROWSER = ("xss-hunter", "client-side-hunter")
CAP_IDENTITIES = ("authz-logic-hunter",)


def capabilities_required(owner: str, kind: str) -> list:
    """What this shard needs before its verdict can mean anything."""
    req = []
    if kind != "src":
        req.append("runtime")        # a live target: every verdict must cite a request
    if owner in CAP_BROWSER:
        req.append("browser")        # these agents emit NEEDS-BROWSER rather than CLEAR without one
    if owner in CAP_IDENTITIES:
        req.append("identities")     # an authz differential needs at least two principals
    return req


def unmet(requires: list, have: dict | None) -> list:
    """Capabilities this run does not have. An unmet requirement is a BLOCKED row, never a CLEAR."""
    have = have or {}
    return [c for c in requires if not have.get(c)]


NAME_RE = re.compile(
    r"^[a-z]+(?:-[a-z]+)*-(?:hunter|aimer|prover|analyzer|writer|auditor|editor|corrector)$")

BEGIN, END = "<!-- SWARM-REGISTRY:BEGIN -->", "<!-- SWARM-REGISTRY:END -->"


class SwarmError(Exception):
    """Refusal with a reason the operator can act on."""


# ============================================================================ coverage ===
def applicable_rows(kind: str) -> list:
    """Matrix rows in play for this target kind, deterministically ordered."""
    import audit_coverage as A
    want = {"src": {"src", "both"}, "url": {"url", "both"}, "grey": {"src", "url", "both"}}
    if kind not in want:
        raise SwarmError(f"unknown target kind {kind!r} (src|url|grey)")
    rows = [r for r in A.matrix_rows() if r[3] in want[kind]]
    return sorted(rows, key=lambda r: (r[0], r[1]))


def owner_agent(owner: str) -> str:
    """Matrix owner shorthand -> agent file stem."""
    owner = owner.strip()
    if owner.startswith("("):               # "(per row hit)" - no single owner
        return "injection-hunter"
    return owner if owner.endswith("-hunter") else f"{owner}-hunter"


def _shards_for(units: list, k: int) -> list:
    """Split one owner's units into k contiguous, deterministic shards.

    A unit is (label, objective) whatever the role: a matrix class, an indirection pattern, or a
    stack surface. Uniform shape so the sizing, allocation and hashing below are role-agnostic.
    """
    k = max(1, min(k, len(units)))
    out, n, i = [], len(units), 0
    for s in range(k):
        take = n // k + (1 if s < n % k else 0)
        chunk = units[i:i + take]
        i += take
        label = chunk[0][0] if len(chunk) == 1 else f"{chunk[0][0]} .. {chunk[-1][0]}"
        out.append({"rows": [c[0] for c in chunk], "label": label,
                    "objective": chunk[0][1] if len(chunk) == 1 else
                    f"{len(chunk)} units, starting with: {chunk[0][1]}"})
    return out


def owners_for_role(role: str, kind: str, stack: str | None = None) -> list:
    """[(owner, weight, units)] for a role, weight-descending then by name - deterministic.

    Each role reads the skill that already documents its method. Nothing is copied into Python; see
    tools/shardsources.py for why the owner maps are explicit tables rather than name matching.
    """
    import shardsources as SS

    by_owner: dict = {}
    if role == "coverage":
        for r in SS.matrix_rows(kind):
            by_owner.setdefault(owner_agent(r[4]), []).append(
                (r[1], f"every applicable case of {r[1]} in this shard, with a depth-qualified "
                       f"verdict and the request that produced it"))
    elif role == "depth":
        for r in SS.indirection_rows():
            by_owner.setdefault(r["owner"], []).append(
                (r["pattern"],
                 f"{r['pattern']}: {r['resolve_by']}. Usually hides: {r['hides']}. "
                 f"Looks like `{r['looks_like']}`"))
    elif role == "stack":
        for r in SS.stack_rows(stack=stack):
            by_owner.setdefault(r["owner"], []).append(
                (r["surface"], f"{r['stack']} - {r['note']}"
                               + (f" (hand the second half to {r['handoff']})" if r["handoff"]
                                  else "")))
    elif role == "prove":
        # One queue, but partitioned by the class family a handoff came from, because aiming is
        # class-specific: the probe that proves an SSRF is not the probe that proves an IDOR, and
        # aiming - not capability - is this agent's measured failure mode (4 of 6 seeded bugs found
        # when aimed by hand, 2 of 6 through the unaimed sweep). One undifferentiated worker pool
        # would also give the lane a single member however wide the fleet is.
        by_owner["dynamic-prover"] = [
            (f"handoffs from {o.removesuffix('-hunter')}",
             f"confirm or reject leads handed over by {o}: aim the probe at the endpoint and "
             f"parameter the handoff names, run it, read the verdict as a claim about the PROBE "
             f"rather than the target, re-aim, and reproduce anything that fires 2-3x")
            for o, _, _ in owners_for_role("coverage", kind)]
    else:
        raise SwarmError(f"unknown role {role!r}; expected one of {ROLES}")

    if not by_owner:
        raise SwarmError(f"role {role!r} produced no shards for kind {kind!r}")
    return sorted(((o, WEIGHTS.get(o.removesuffix("-hunter"), DEFAULT_WEIGHT), sorted(u))
                   for o, u in by_owner.items()), key=lambda t: (-t[1], t[0]))


# ============================================================================== sizing ===
def _tuning(target_dir: Path | None) -> dict:
    t = json.loads(json.dumps(TUNING))      # deep copy
    if target_dir:
        over = target_dir / "swarm" / "tuning.json"
        if over.exists():
            try:
                user = json.loads(over.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as e:
                raise SwarmError(f"{over}: not valid JSON: {e}") from e
            for k in ("saturation", "reserve_frac"):
                if k in user:
                    t[k] = user[k]
            for w, v in (user.get("min_useful") or {}).items():
                t["min_useful"][str(w)] = int(v)
    return t


def size(kind: str, requested: int, limits: dict | None, tuning: dict,
         owners: list) -> tuple[int, int, dict]:
    """Compute how many members run AT ONCE, and how many passes that takes.

    `requested` is a maximum on CONCURRENT width, never a floor. Coverage is the one thing width is
    not allowed to buy: when the resource ceiling sits below the number of owners, the answer is
    more passes, not fewer classes. That keeps rule 1 intact on a 1-concurrency program instead of
    refusing to plan at all - a refusal there would make the tool useless exactly where it is most
    needed, and the temptation to "just drop the low-severity rows" is what this avoids.

    A budget that cannot fund one floor-sized member per owner is a genuine refusal, because no
    number of passes conjures requests that the program has not authorized.

    src and url/grey take different branches on purpose: reading files costs no requests, so
    applying the network-budget arithmetic to a source-only analysis would shrink a swarm for a
    constraint that does not exist.
    """
    floor = len(owners)                     # coverage: one member per owner with applicable rows
    why = {"requested": requested, "coverage_floor": floor}

    if kind == "src":
        ceiling = HARD_CEILING
        why["budget_allows"] = None
        why["concurrency_allows"] = None
    else:
        if not limits:
            raise SwarmError("a url/grey swarm needs the scope's limits (--scope) to size a budget")
        budget = int(limits["max_requests"])
        reserve = int(budget * float(tuning["reserve_frac"]))
        usable = budget - reserve
        mins = sorted((tuning["min_useful"][str(w)] for _, w, _ in owners), reverse=True)
        run, budget_width = 0, 0
        for m in mins:
            if run + m > usable:
                break
            run += m
            budget_width += 1
        conc_allows = max(1, int(limits["concurrency"]) * int(tuning["saturation"]))
        ceiling = min(budget_width, HARD_CEILING, conc_allows)
        why.update({"budget": budget, "reserve": reserve, "usable": usable,
                    "required_for_floor": sum(mins), "budget_allows": budget_width,
                    "concurrency_allows": conc_allows})

    if kind != "src" and why["required_for_floor"] > why["usable"]:
        raise SwarmError(
            f"the request budget cannot cover the matrix: {floor} owners need "
            f"{why['required_for_floor']} requests at the per-member floor but only "
            f"{why['usable']} are usable of {why['budget']} ({why['reserve']} reserved). "
            f"Coverage is not negotiable - raise the program's authorized budget, or hunt fewer "
            f"classes deliberately and say so. Silently dropping a class is not an option.")

    per_pass = max(1, min(ceiling, requested))
    passes = -(-floor // per_pass)                      # ceil: every owner runs exactly once
    why.update({"final": per_pass, "passes": passes, "total_members": floor if passes > 1 else None})
    return per_pass, passes, why


def _allocate(width: int, owners: list) -> dict:
    """Members per owner: one each (coverage), then the surplus by weight x rows, deterministically."""
    counts = {o: 1 for o, _, _ in owners}
    surplus = width - len(owners)
    if surplus > 0:
        # Largest-remainder over weight*rows, ties broken by owner name so it never depends on
        # dict order or float accumulation.
        share = [(o, w * len(rows)) for o, w, rows in owners]
        total = sum(s for _, s in share) or 1
        exact = [(o, surplus * s / total) for o, s in share]
        base = {o: int(v) for o, v in exact}
        left = surplus - sum(base.values())
        for o, v in sorted(exact, key=lambda kv: (-(kv[1] - int(kv[1])), kv[0]))[:left]:
            base[o] += 1
        for o, extra in base.items():
            counts[o] += extra
    # Never more members than the owner has rows to give.
    for o, _, rows in owners:
        counts[o] = min(counts[o], len(rows))
    return counts


def _allowances(kind: str, members: list, limits: dict | None, tuning: dict,
                usable: int | None = None) -> None:
    """Give each member its floor, then split the surplus by weight. Integer arithmetic only.

    `usable` is passed in by a fleet, which has already divided one authorized budget between its
    swarms. A single swarm computes it from the scope, as before.
    """
    if kind == "src":
        for m in members:
            m["request_allowance"] = 0      # reading files costs no requests
        return
    if usable is None:
        usable = int(limits["max_requests"]) - int(int(limits["max_requests"])
                                                   * float(tuning["reserve_frac"]))
    for m in members:
        m["request_allowance"] = int(tuning["min_useful"][str(m["weight"])])
    surplus = usable - sum(m["request_allowance"] for m in members)
    if surplus <= 0:
        return
    wsum = sum(m["weight"] for m in members) or 1
    for m in members:
        m["request_allowance"] += (surplus * m["weight"]) // wsum


def plan(target: str, kind: str, requested: int = HARD_CEILING, limits: dict | None = None,
         target_dir: Path | None = None, forged: dict | None = None, role: str = "coverage",
         swarm_id: str | None = None, usable: int | None = None,
         capabilities: dict | None = None, stack: str | None = None) -> dict:
    if role not in ROLES:
        raise SwarmError(f"unknown role {role!r}; expected one of {ROLES}")
    swarm_id = swarm_id or role
    owners = owners_for_role(role, kind, stack)

    tuning = _tuning(target_dir)
    per_pass, passes, why = size(kind, requested, limits, tuning, owners)

    # One pass: spend the surplus on extra shards. Several passes: one member per owner, and the
    # pass order is weight-descending, so the classes most likely to carry a critical go first.
    counts = _allocate(per_pass, owners) if passes == 1 else {o: 1 for o, _, _ in owners}

    members, n = [], 0
    for idx, (owner, weight, units) in enumerate(owners):
        wave = (idx // per_pass) + 1 if passes > 1 else 1
        for i, sh in enumerate(_shards_for(units, counts[owner]), start=1):
            n += 1
            requires = capabilities_required(owner, kind)
            blocked = unmet(requires, capabilities)
            members.append({
                "shard_id": f"{swarm_id}-{n:02d}", "role": role, "swarm": swarm_id,
                "agent": owner, "member": f"{swarm_id}/{owner}#{i}", "shard": sh["label"],
                "rows": sh["rows"], "objective": sh["objective"], "weight": weight, "pass": wave,
                "requires": requires, "blocked_on": blocked,
                "completion": COMPLETION[role],
                "forged": bool((forged or {}).get(owner))})
    members.sort(key=lambda m: (m["pass"], -m["weight"], m["agent"], m["shard"]))
    for i, m in enumerate(members, start=1):          # renumber after the sort so ids are stable
        m["shard_id"] = f"{swarm_id}-{i:02d}"
    _allowances(kind, members, limits, tuning, usable)

    # Coverage is the one role that must leave nothing unowned. depth and stack are ADDITIVE: they
    # deepen a class that coverage already has to examine, so requiring them to be exhaustive would
    # be meaningless. plan_fleet() enforces that exactly one coverage swarm exists.
    if role == "coverage":
        covered = {r for m in members for r in m["rows"]}
        expected = {u[0] for _, _, units in owners for u in units}
        missing = sorted(expected - covered)
        if missing:
            raise SwarmError(
                f"{len(missing)} applicable matrix row(s) would have no owner: {missing[:5]}... "
                f"An unexamined class is an unfinished hunt; this plan is refused rather than "
                f"emitted.")

    doc = {"schema": 2, "target": target, "kind": kind, "role": role, "swarm": swarm_id,
           "width": min(per_pass, len(members)), "passes": passes, "members_total": len(members),
           "sizing": why, "tuning": tuning,
           "budget": ({"max_requests": int(limits["max_requests"]),
                       "reserve": why.get("reserve"),
                       "usable": usable if usable is not None else why.get("usable")}
                      if kind != "src" else None),
           "members": members}
    doc["plan_sha256"] = plan_hash(doc)
    return doc


def role_floor(role: str, kind: str, tuning: dict, stack: str | None = None) -> tuple[int, int]:
    """(request cost of one member per owner, number of owners) - what this role costs to launch."""
    owners = owners_for_role(role, kind, stack)
    if kind == "src":
        return 0, len(owners)
    return sum(int(tuning["min_useful"][str(w)]) for _, w, _ in owners), len(owners)


def plan_fleet(target: str, kind: str, roles: tuple = ("coverage", "depth", "stack", "prove"),
               requested: int = HARD_CEILING, limits: dict | None = None,
               target_dir: Path | None = None, capabilities: dict | None = None,
               stack: str | None = None, forged: dict | None = None,
               max_agents: int | None = None) -> dict:
    """Size several swarms on ONE target, each hunting by a different method.

    The order of claim IS the priority order, and it is what keeps rule 1 alive across a fleet:
    coverage's floors are paid first and are never negotiable, the remaining roles launch only if
    what is left funds their floors, and only then is the surplus shared out. A role that cannot be
    funded does not launch and says so - a swarm with no budget to finish its shards produces the
    same fake rows as a member blocked on a lease forever.
    """
    import fleet as F

    roles = tuple(dict.fromkeys(roles))                 # de-dup, keep order
    unknown = [r for r in roles if r not in ROLES]
    if unknown:
        raise SwarmError(f"unknown role(s) {unknown}; expected from {ROLES}")
    if roles.count("coverage") != 1:
        raise SwarmError(
            "a fleet must contain exactly one `coverage` swarm. depth and stack are ADDITIVE - they "
            "deepen classes coverage already examines - so without it nothing guarantees every "
            "applicable matrix row has an owner, and 'an unexamined class is an unfinished hunt'.")

    tuning = _tuning(target_dir)
    max_agents = int(max_agents or F.MAX_AGENTS)

    # ---- which roles can be funded, in priority order --------------------------------------
    launched, skipped, floors = ["coverage"], {}, {}
    budget = reserve = usable = None
    for r in roles:
        floors[r] = role_floor(r, kind, tuning, stack)[0]

    if kind == "src":
        launched = list(roles)
    else:
        if not limits:
            raise SwarmError("a url/grey fleet needs the scope's limits (--scope) to size a budget")
        budget = int(limits["max_requests"])
        reserve = int(budget * float(tuning["reserve_frac"]))
        usable = budget - reserve
        if floors["coverage"] > usable:
            raise SwarmError(
                f"the request budget cannot cover the matrix: coverage needs {floors['coverage']} "
                f"requests at the per-member floor but only {usable} are usable of {budget} "
                f"({reserve} reserved). Coverage is not negotiable - raise the program's authorized "
                f"budget, or hunt fewer classes deliberately and say so.")
        left = usable - floors["coverage"]
        for r in [x for x in roles if x != "coverage"]:
            if floors[r] <= left:
                launched.append(r)
                left -= floors[r]
            else:
                skipped[r] = (f"needs {floors[r]} requests at the floor, {left} left after "
                              f"coverage - not launched rather than launched unable to finish")
        launched = [r for r in roles if r in launched]

    # ---- agent slots: one ceiling shared between the swarms, not one each ------------------
    ceiling = min(requested, HARD_CEILING)
    caps = {r: min(ceiling, sum(len(u) for _, _, u in owners_for_role(r, kind, stack)))
            for r in launched}
    widths = F.split(max_agents, {r: ROLE_WEIGHTS[r] for r in launched}, caps=caps)

    # ---- budget shares: floors first, then the surplus by role weight ----------------------
    shares = {r: floors[r] for r in launched}
    if kind != "src":
        surplus = usable - sum(shares.values())
        if surplus > 0:
            wsum = sum(ROLE_WEIGHTS[r] for r in launched) or 1
            for r in launched:
                shares[r] += (surplus * ROLE_WEIGHTS[r]) // wsum

    swarms = {}
    for r in launched:
        swarms[r] = plan(target, kind, requested=widths[r], limits=limits, target_dir=target_dir,
                         forged=forged, role=r, swarm_id=r,
                         usable=(shares[r] if kind != "src" else None),
                         capabilities=capabilities, stack=stack)

    doc = {"schema": 1, "target": target, "kind": kind, "roles": launched, "skipped": skipped,
           "agents": {"max": max_agents, "per_role": widths,
                      "concurrent": sum(min(widths[r], swarms[r]["width"]) for r in launched)},
           "budget": (None if kind == "src" else
                      {"max_requests": budget, "reserve": reserve, "usable": usable,
                       "floors": {r: floors[r] for r in launched}, "shares": shares}),
           "tuning": tuning,
           "swarms": {r: swarms[r] for r in launched}}
    doc["fleet_sha256"] = fleet_hash(doc)
    return doc


def fleet_hash(doc: dict) -> str:
    """Bind the whole fleet: which roles, how wide, how the budget was split, and each swarm's hash.

    Same reason plan_sha256 exists, one level up. A resume that cannot prove the fleet in front of it
    is the fleet that was dispatched would re-task members from a membership nobody planned.
    """
    payload = {"kind": doc["kind"], "roles": doc["roles"], "agents": doc["agents"],
               "budget": doc["budget"], "tuning": doc["tuning"],
               "swarms": [[r, doc["swarms"][r]["plan_sha256"]] for r in doc["roles"]]}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def plan_hash(doc: dict) -> str:
    """Hash everything that decides the swarm; nothing that merely describes the run.

    The resolved tuning block is INCLUDED. Making the constants overridable without hashing them
    would break the binding the hash exists for: two runs under different tuning would produce
    different memberships under one plan_sha256, and a resume would continue a swarm that was never
    planned. Hashing them makes re-tuning invalidate an in-flight plan instead of corrupting it.
    """
    payload = {k: doc[k] for k in ("kind", "role", "swarm", "width", "passes", "tuning", "budget",
                                   "members") if k in doc}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


# =============================================================================== forge ===
def _donor_sections(donor: Path) -> tuple[str, str]:
    """Take the shared prologue and tail verbatim from a real hunter.

    Copied rather than retyped so a forged agent cannot drift to a softer verdict bar than the
    hunters it runs beside - that drift is how a 30-wide swarm would launder BLOCKED into CLEAR.
    """
    txt = donor.read_text(encoding="utf-8")
    body = txt.split("\n---\n", 1)[1] if txt.startswith("---") else txt
    head_end = body.find("\n## ", body.find("## Standing guardrails"))
    if body.find("## Standing guardrails") < 0 or head_end < 0:
        raise SwarmError(f"{donor.name} has no '## Standing guardrails' section to copy")
    prologue = body[:head_end].strip("\n")

    tail_start = body.find("## Read it, then test it")
    if tail_start < 0:
        raise SwarmError(f"{donor.name} has no '## Read it, then test it' section to copy")
    return prologue, body[tail_start:].strip("\n")


def forge_text(name: str, shard: str, tools: str, model: str, donor: Path, slug: str,
               today: str) -> str:
    prologue, tail = _donor_sections(donor)
    desc = (f"Swarm member forged for {slug}. Owns {shard}. Same verdict bar and guardrails as "
            f"every standing hunter: a class read but not exercised is BLOCKED (untested), never "
            f"CLEAR. Retired with `hunt swarm retire --target {slug}`.")
    return (f"---\nname: {name}\ndescription: >\n  {desc}\ntools: {tools}\nmodel: {model}\n---\n"
            f"<!-- swarm-forged: {slug} {today} -->\n\n{prologue}\n\n"
            f"# You are a swarm member: {shard}\n\n"
            f"Your shard is **{shard}**. Everything outside it belongs to another member - if your "
            f"trace ends in someone else's sink, hand the sink half over with the source half "
            f"attached and say who you handed it to. One finding, two contributors, never two "
            f"competing reports.\n\n{tail}\n")


def validate_name(name: str) -> None:
    if not NAME_RE.match(name):
        raise SwarmError(
            f"{name!r} is not a dispatchable agent name. It must match "
            f"[a-z]+(-[a-z]+)*-<suffix> with suffix in hunter/aimer/prover/analyzer/writer/"
            f"auditor/editor/corrector. Digits and underscores are rejected on purpose: the "
            f"orchestrator dispatch-validity check in tests/test_agent_wiring.py matches [a-z]+ "
            f"with no digit class, so 'api-v2-hunter' would be invisible to it while still being "
            f"required by the every-agent-is-dispatched test - an agent only half the suite sees.")


def validate_tools(tools: str) -> None:
    listed = {t.strip() for t in tools.split(",") if t.strip()}
    if "Task" in listed:
        raise SwarmError(
            "a forged agent may not declare the Task tool: a swarm member that can spawn its own "
            "members is an unbounded swarm. No agent in this repo declares it.")
    if not listed:
        raise SwarmError("--tools cannot be empty")


def _registry_block(names: list, indent: str = "") -> str:
    if not names:
        body = f"{indent}(no forged agents registered)"
    else:
        body = "\n".join(f"{indent}- **{n}** - forged swarm member, dispatched as part of the "
                         f"sized swarm (see `swarm` skill)." for n in sorted(names))
    return f"{indent}{BEGIN}\n{body}\n{indent}{END}"


def _read_registry(path: Path) -> list:
    txt = path.read_text(encoding="utf-8")
    if BEGIN not in txt:
        return []
    block = txt.split(BEGIN, 1)[1].split(END, 1)[0]
    return sorted(set(re.findall(r"\*\*([a-z-]+)\*\*", block)))


def _write_registry(path: Path, names: list, anchor: str | None, indent: str = "") -> None:
    txt = path.read_text(encoding="utf-8")
    block = _registry_block(names, indent)
    if BEGIN in txt:
        head, rest = txt.split(BEGIN, 1)
        _, tail = rest.split(END, 1)
        # `head` already ends with the block's indent, so do not emit it twice.
        txt = head + block[len(indent):] + tail
    elif anchor and anchor in txt:
        txt = txt.replace(anchor, block + "\n\n" + anchor, 1)
    else:
        txt = txt.rstrip("\n") + "\n\n" + block + "\n"
    path.write_text(txt, encoding="utf-8")


def register(names: list) -> None:
    """Name every forged agent where both wiring tests look. Never a follow-up step.

    tests/test_agent_wiring.py fails any .claude/agents/*.md the orchestrator does not name, and the
    run-board test encodes the same norm for the board. An agent that exists unregistered is exactly
    the "capability the pipeline does not have" those tests were written to reject, so forging and
    registering are one operation.
    """
    _write_registry(ORCHESTRATOR, names,
                    anchor="   **Ten hunters exist; do not spawn ten at once.**", indent="   ")
    _write_registry(RUNBOARD, names, anchor=None)


def forged_agents() -> dict:
    """Every forged agent on disk -> the slug it was forged for."""
    out = {}
    for p in sorted(AGENTS.glob("*.md")):
        m = re.search(r"<!-- swarm-forged: (\S+) ", p.read_text(encoding="utf-8"))
        if m:
            out[p.stem] = m.group(1)
    return out


def forge(name: str, shard: str, slug: str, tools: str = "Read, Grep, Glob, Bash, Write",
          model: str = "opus", donor: str = "injection-hunter") -> Path:
    validate_name(name)
    validate_tools(tools)
    dest = AGENTS / f"{name}.md"
    if dest.exists() and name not in forged_agents():
        raise SwarmError(f"{name} is a standing agent, not a forged one - refusing to overwrite it")
    from datetime import date
    dest.write_text(forge_text(name, shard, tools, model, AGENTS / f"{donor}.md", slug,
                               date.today().isoformat()), encoding="utf-8")
    register(sorted(set(forged_agents()) | {name}))
    return dest


def retire(slug: str | None, keep: list | None = None) -> list:
    keep = set(keep or [])
    gone = []
    for name, forged_for in forged_agents().items():
        if name in keep or (slug and forged_for != slug):
            continue
        (AGENTS / f"{name}.md").unlink()
        gone.append(name)
    register(sorted(forged_agents()))
    return gone


# ================================================================================= cli ===
def _limits_from_scope(path: str | None) -> dict | None:
    if not path:
        return None
    sys.path.insert(0, str(ROOT / "dynamic"))
    import scope as S
    return dict(S.Scope.load(path).limits)


def _workdir(target: str) -> Path:
    sys.path.insert(0, str(ROOT / "static"))
    try:
        import common as C
        return Path(C.workdir(target))
    except Exception:                                   # noqa: BLE001 - fall back to the convention
        return ROOT / "work" / target


def cmd_plan(a) -> int:
    work = _workdir(a.target)
    limits = _limits_from_scope(a.scope)

    if limits and a.kind != "src":
        sys.path.insert(0, str(ROOT / "dynamic"))
        import limits as L
        lim = L.SharedLimiter(work / "web" / "limits.json", rps=limits["rps"],
                              burst=limits["burst"], max_requests=int(limits["max_requests"]),
                              concurrency=int(limits["concurrency"]))
        if lim.degraded():
            print("LIMITER_DEGRADED: the shared lease map was lost, so concurrency is forced to 1.\n"
                  "Refusing to size a swarm on a limiter that cannot hold a ceiling.\n"
                  f"Clear it deliberately with:  hunt swarm recover --target {a.target}",
                  file=sys.stderr)
            return 3

    doc = plan(a.target, a.kind, a.width, limits, work)
    out = work / "swarm" / "plan.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    from datetime import datetime, timezone
    written = dict(doc, sized_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    out.write_text(json.dumps(written, indent=2), encoding="utf-8")

    s = doc["sizing"]
    bits = [f"requested {s['requested']}"]
    if s.get("budget_allows") is not None:
        bits.append(f"budget allows {s['budget_allows']}")
    if s.get("concurrency_allows") is not None:
        bits.append(f"concurrency allows {s['concurrency_allows']}")
    bits.append(f"coverage floor {s['coverage_floor']}")
    bits.append(f"final {doc['width']}")
    print(" · ".join(bits))
    if s.get("usable") is not None:
        print(f"budget: {s['usable']} usable of {s['budget']} "
              f"({s['reserve']} reserved) · {s['required_for_floor']} required for the floor")
    print(f"{out}  {doc['plan_sha256']}")
    for m in doc["members"]:
        allow = f"{m['request_allowance']} req" if m["request_allowance"] else "static"
        print(f"  {m['member']:<26} w{m['weight']}  {allow:<9}  {m['shard']}")
    return 0


def cmd_fleet(a) -> int:
    work = _workdir(a.target)
    limits = _limits_from_scope(a.scope)
    roles = tuple(r.strip() for r in (a.roles or "").split(",") if r.strip())

    if limits and a.kind != "src":
        sys.path.insert(0, str(ROOT / "dynamic"))
        import limits as L
        lim = L.SharedLimiter(work / "web" / "limits.json", rps=limits["rps"],
                              burst=limits["burst"], max_requests=int(limits["max_requests"]),
                              concurrency=int(limits["concurrency"]))
        if lim.degraded():
            print("LIMITER_DEGRADED: the shared lease map was lost, so concurrency is forced to 1.\n"
                  "Refusing to size a fleet on a limiter that cannot hold a ceiling.\n"
                  f"Clear it deliberately with:  hunt swarm recover --target {a.target}",
                  file=sys.stderr)
            return 3

    caps = {c: True for c in (a.have or "").split(",") if c.strip()}
    doc = plan_fleet(a.target, a.kind, roles=roles, requested=a.width, limits=limits,
                     target_dir=work, capabilities=caps or None, stack=a.stack,
                     max_agents=a.max_agents)

    out = work / "swarm" / "fleet.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    from datetime import datetime, timezone
    out.write_text(json.dumps(
        dict(doc, sized_at=datetime.now(timezone.utc).isoformat(timespec="seconds")), indent=2),
        encoding="utf-8")
    for role, sw in doc["swarms"].items():
        (out.parent / f"plan-{role}.json").write_text(json.dumps(sw, indent=2), encoding="utf-8")

    print(f"fleet of {len(doc['roles'])} swarm(s): {', '.join(doc['roles'])}")
    print(f"agents {sum(doc['agents']['per_role'].values())}/{doc['agents']['max']} "
          f"({', '.join(f'{r} {n}' for r, n in sorted(doc['agents']['per_role'].items()))})")
    if doc["budget"]:
        b = doc["budget"]
        print(f"budget {b['usable']} usable of {b['max_requests']} ({b['reserve']} reserved) -> "
              + ", ".join(f"{r} {b['shares'][r]}" for r in doc["roles"]))
    for role, why in doc["skipped"].items():
        print(f"NOT LAUNCHED  {role}: {why}")
    print(f"{out}  {doc['fleet_sha256']}")
    for role in doc["roles"]:
        sw = doc["swarms"][role]
        blocked = sum(1 for m in sw["members"] if m["blocked_on"])
        print(f"  {role:<9} width {sw['width']:>2} · {sw['members_total']:>2} members · "
              f"{sw['passes']} pass(es)" + (f" · {blocked} BLOCKED on capability" if blocked else ""))
    return 0


def cmd_handoff(a) -> int:
    import swarm_queue as Q
    rec = Q.handoff(a.target, from_member=a.from_member, to_agent=a.to, fingerprint=a.fingerprint,
                    vuln_class=a.vuln_class or "", sink=a.sink or "", endpoint=a.endpoint or "",
                    param=a.param or "", effect=a.effect or "", reason=a.reason,
                    evidence=a.evidence or "", aim=a.aim or "")
    print(f"handoff recorded on {rec['finding_id']}: {a.from_member} -> {a.to}")
    print(f"  contributors: {', '.join(rec['agents'])}")
    print(f"  mark the handing row with:  hunt board handoff {a.target} <n> "
          f"--result \"handed to {a.to}\"")
    return 0


def cmd_forge(a) -> int:
    dest = forge(a.name, a.shard, a.target, a.tools, a.model, a.donor)
    print(f"forged {dest.relative_to(ROOT)} and registered it in "
          f"{ORCHESTRATOR.name} + {RUNBOARD.parent.name}/{RUNBOARD.name}")
    return 0


def cmd_retire(a) -> int:
    gone = retire(a.target, a.keep)
    print(f"retired {len(gone)} forged agent(s): {', '.join(gone) or '(none)'}")
    if a.keep:
        print(f"kept: {', '.join(sorted(set(a.keep)))}")
    return 0


def cmd_recover(a) -> int:
    work = _workdir(a.target)
    limits = _limits_from_scope(a.scope) or {"rps": 1.0, "burst": 1, "max_requests": 0,
                                             "concurrency": 1}
    sys.path.insert(0, str(ROOT / "dynamic"))
    import limits as L
    lim = L.SharedLimiter(work / "web" / "limits.json", rps=limits["rps"], burst=limits["burst"],
                          max_requests=int(limits["max_requests"]),
                          concurrency=int(limits["concurrency"]))
    if not lim.degraded():
        print("limiter is not degraded - nothing to recover")
        return 0
    st = lim.recover()
    print(f"cleared the degraded lease map · budget preserved at {st['sent']} sent · "
          f"concurrency back to {st['concurrency']}")
    return 0


def cmd_finding(a) -> int:
    import swarm_queue as Q
    rec = Q.record(a.target, vuln_class=a.vuln_class, agent=a.agent, sink=a.sink or "",
                   endpoint=a.endpoint or "", param=a.param or "", effect=a.effect or "",
                   status=a.status, cwe=a.cwe or "", cvss=a.cvss, preconditions=a.preconditions,
                   evidence=a.evidence or "")
    if rec["merged"] > 1:
        print(f"merged into {rec['finding_id']} ({rec['merged']} members reached this sink: "
              f"{', '.join(rec['agents'])}) - one report candidate, every contributor named")
    else:
        print(f"recorded {rec['finding_id']}  {rec['class']}  {rec['fingerprint'][:23]}")
    return 0


def cmd_rank(a) -> int:
    import swarm_queue as Q
    rows = Q.rank(a.target)
    if not rows:
        print("no findings recorded yet")
        return 0
    print(f"{'id':<6} {'status':<14} {'cvss':>5} {'pre':>4} {'by':>3}  class / sink")
    for r in rows:
        where = r.get("sink") or f"{r.get('endpoint','')}?{r.get('param','')}".rstrip("?")
        print(f"{r['finding_id']:<6} {r['status']:<14} {r['cvss']:>5} "
              f"{r['preconditions']:>4} {len(r['agents']):>3}  {r['class']} {where}")
    cand = Q.lane_candidate(a.target)
    print()
    print(f"lane candidate: {cand['finding_id'] if cand else '(none confirmed)'}"
          + ("  -> run `hunt impact-gate` on it before writing (tier 2)" if cand else ""))
    return 0


def cmd_state(a) -> int:
    import swarm_queue as Q
    if a.set:
        doc = Q.set_state(a.target, a.set, a.plan or "", a.lane, swarm=getattr(a, "swarm", None),
                          fleet_sha256=getattr(a, "fleet_hash", ""))
    else:
        doc = Q.read_state(a.target)
        if not doc:
            print("no swarm state recorded")
            return 0
    print(json.dumps(doc, indent=2))
    return 0


def cmd_resume(a) -> int:
    import swarm_queue as Q
    info = Q.resumable(a.target)
    print(f"state {info['state']} · plan {info['plan_sha256'][:23]} · "
          f"report lane {info['report_lane'] or '(none)'}")
    if not info["unreturned"]:
        print("every row returned - nothing to re-dispatch")
        return 0
    print(f"{len(info['unreturned'])} row(s) never returned; re-dispatch exactly these:")
    for r in info["unreturned"]:
        print(f"  {r['n']:>3}. {r['agent']:<26} {r['scope']}")
    return 0


def add_parser(sub) -> None:
    p = sub.add_parser("swarm", help="size, forge and retire a target-shaped agent swarm")
    ssub = p.add_subparsers(dest="swarm_cmd", required=True)

    s = ssub.add_parser("plan", help="compute the swarm width and membership (deterministic)")
    s.add_argument("--target", required=True)
    s.add_argument("--kind", default="src", choices=["src", "url", "grey"])
    s.add_argument("--width", type=int, default=HARD_CEILING,
                   help=f"requested MAXIMUM width (never a floor); hard ceiling {HARD_CEILING}")
    s.add_argument("--scope", help="scope file - required for url/grey to size the budget")
    s.set_defaults(swarm_fn=cmd_plan)

    s = ssub.add_parser("fleet", help="size several swarms on one target, one per hunting method")
    s.add_argument("--target", required=True)
    s.add_argument("--kind", default="src", choices=["src", "url", "grey"])
    s.add_argument("--roles", default="coverage,depth,stack,prove",
                   help="comma-separated; must include exactly one `coverage`")
    s.add_argument("--width", type=int, default=HARD_CEILING,
                   help="requested MAXIMUM concurrent width per swarm")
    s.add_argument("--scope", help="scope file - required for url/grey to size the budget")
    s.add_argument("--stack", help="restrict the stack swarm to one fingerprinted stack")
    s.add_argument("--have", default="",
                   help="capabilities this run actually has: runtime,browser,identities")
    s.add_argument("--max-agents", dest="max_agents", type=int, default=None,
                   help="total concurrent members across ALL swarms (default: fleet.MAX_AGENTS)")
    s.set_defaults(swarm_fn=cmd_fleet)

    s = ssub.add_parser("handoff", help="record one member handing a lead to another")
    s.add_argument("--target", required=True)
    s.add_argument("--from", dest="from_member", required=True)
    s.add_argument("--to", required=True)
    s.add_argument("--reason", required=True, help="why the receiver should spend budget on this")
    s.add_argument("--aim", default="", help="endpoint/parameter to aim at - aiming is the prover's "
                                             "measured failure mode, do not drop it")
    s.add_argument("--fingerprint", default="")
    s.add_argument("--class", dest="vuln_class", default="")
    s.add_argument("--sink", default="")
    s.add_argument("--endpoint", default="")
    s.add_argument("--param", default="")
    s.add_argument("--effect", default="")
    s.add_argument("--evidence", default="")
    s.set_defaults(swarm_fn=cmd_handoff)

    s = ssub.add_parser("forge", help="write a new agent AND register it, in one operation")
    s.add_argument("--name", required=True)
    s.add_argument("--shard", required=True)
    s.add_argument("--target", required=True, help="slug this member is forged for")
    s.add_argument("--tools", default="Read, Grep, Glob, Bash, Write")
    s.add_argument("--model", default="opus")
    s.add_argument("--donor", default="injection-hunter",
                   help="standing hunter whose guardrails and verdict bar are copied verbatim")
    s.set_defaults(swarm_fn=cmd_forge)

    s = ssub.add_parser("retire", help="delete forged agents and strip their registry lines")
    s.add_argument("--target", help="only agents forged for this slug (default: all)")
    s.add_argument("--keep", action="append", default=[])
    s.set_defaults(swarm_fn=cmd_retire)

    s = ssub.add_parser("finding", help="record a member's finding (merges duplicates by sink)")
    s.add_argument("--target", required=True)
    s.add_argument("--class", dest="vuln_class", required=True)
    s.add_argument("--agent", required=True, help="the member that found it, e.g. server-side-hunter#2")
    s.add_argument("--sink", help="file:line (src)")
    s.add_argument("--endpoint", help="path (url)")
    s.add_argument("--param")
    s.add_argument("--effect", help="what was observed, e.g. 'listener hit'")
    s.add_argument("--status", default="NEW", choices=["NEW", "code-confirmed", "CONFIRMED"])
    s.add_argument("--cwe", default="")
    s.add_argument("--cvss", type=float, default=0.0)
    s.add_argument("--preconditions", type=int, default=0)
    s.add_argument("--evidence", default="")
    s.set_defaults(swarm_fn=cmd_finding)

    s = ssub.add_parser("rank", help="tier-1 ranking over the deduplicated findings")
    s.add_argument("--target", required=True)
    s.set_defaults(swarm_fn=cmd_rank)

    s = ssub.add_parser("state", help="read or advance the swarm state machine")
    s.add_argument("--target", required=True)
    s.add_argument("--set", choices=["PLANNED", "DISPATCH_READY", "RUNNING", "FINDINGS_QUEUED",
                                     "TRIAGING", "REPORT_LANE", "DRAINING", "COMPLETE"])
    s.add_argument("--plan", default="", help="plan_sha256 this run is bound to")
    s.add_argument("--lane", default=None, help="finding id holding the report lane")
    s.add_argument("--swarm", default=None, help="record one swarm's phase instead of the fleet's")
    s.add_argument("--fleet-hash", dest="fleet_hash", default="")
    s.set_defaults(swarm_fn=cmd_state)

    s = ssub.add_parser("resume", help="what a dead session left unreturned")
    s.add_argument("--target", required=True)
    s.set_defaults(swarm_fn=cmd_resume)

    s = ssub.add_parser("recover", help="clear a degraded lease map (never resets the budget)")
    s.add_argument("--target", required=True)
    s.add_argument("--scope")
    s.set_defaults(swarm_fn=cmd_recover)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="swarm")
    add_parser(ap.add_subparsers(dest="cmd", required=True))
    a = ap.parse_args(argv)
    try:
        return a.swarm_fn(a)
    except SwarmError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    except Exception as e:                              # noqa: BLE001
        if type(e).__name__ == "QueueError":
            print(f"refused: {e}", file=sys.stderr)
            return 2
        raise


if __name__ == "__main__":
    raise SystemExit(main())
