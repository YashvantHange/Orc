---
name: swarm
description: >
  Run target-shaped swarms instead of fixed waves of three - one swarm, or a FLEET of several on one
  target, each hunting by a different method (coverage of the matrix, depth through the abstraction
  layers, stack-specific surfaces, plus the prove lane that turns candidates into findings). Covers
  how width is computed from the target and the program's own limits, how shards are chosen and what
  a member is actually assigned, how to forge and register a new agent, how a lead is handed over
  for confirmation with its aim intact, how duplicate findings collapse into one report candidate,
  how the most serious confirmed finding takes the report lane first, and how a dead session
  resumes. Load after recon and aiming, BEFORE any class hunter is tasked.
---

# The swarm

Ten hunters in waves of three was a cap chosen for a real failure — parallel-spawning the whole
roster once killed a hunt on provider rate limits. That failure is now bounded in code rather than
by a number in a brief: `concurrency` lives in `work/<slug>/web/limits.json` alongside `rps` and
`max_requests`, so every agent process draws on one ceiling. With the wire bounded, the width can be
**computed from the target** instead of guessed.

Nothing here relaxes a guardrail. It makes more of them mechanical.

## The two rules that decide everything

**1. Weight sets RESOURCES. It never sets COVERAGE.**

`vuln-playbooks` is unchanged: every applicable matrix row comes back `HIT` / `CLEAR` / `N/A` /
`BLOCKED`, and "didn't look" is not a state. A low-severity class may get exactly one member at the
floor allowance. It never gets zero.

`hunt swarm plan` enforces this rather than asking you to remember it: it **refuses to emit a plan
that leaves an applicable row unowned**, and when resources are short it adds passes rather than
dropping classes. A class comes back `N/A` only when recon shows the surface is genuinely absent,
with the reason recorded.

| axis | what it controls | can it reach zero? |
|---|---|---|
| coverage | does this class get tested at all | **no** — refused at plan time |
| priority (weight) | how many shards and how many requests it gets | a weight-1 class gets one member at the floor |

**2. Planning is deterministic.** `state.json` binds to `plan_sha256`. Same target, same recon, same
limits, same requested width → byte-identical membership and hash, across processes. The resolved
tuning block is part of the hash, so re-tuning **invalidates** an in-flight plan instead of quietly
continuing a different one.

## Sizing

```
hunt swarm plan --target <slug> --kind src|url|grey [--width N] [--scope <file>]
```

`--width N` is a **requested maximum on concurrent members**, never a floor. The command always
prints every term, and a shrink is a normal outcome:

```
requested 30 · budget allows 10 · concurrency allows 12 · coverage floor 10 · final 10
```

- **`src`** takes no budget branch at all. Reading files costs no requests, so sizing a source
  analysis against a request budget would shrink it for a constraint that does not exist.
- **`url` / `grey`** reserve 20% of `max_requests` for replay, dup checks and re-verification, give
  every member a per-weight floor (a member below its floor cannot enumerate encodings, dialects and
  identities *and* run a negative control, so it cannot produce a verdict that survives
  `hunt web coverage`), and cap width at `concurrency × saturation` — beyond that, members just sit
  blocked on a lease, which is a fake row on the board.

**When the ceiling is below the coverage floor, the swarm takes more passes, not fewer classes.**
Pass 1 carries the heaviest classes, so the classes most likely to hold a critical run first. A
budget that cannot fund one floor-sized member per owner is a genuine refusal — no number of passes
conjures requests a program has not authorized.

The tunables (`saturation`, `min_useful`, `reserve_frac`) are **PROVISIONAL**: chosen, not measured.
They are recorded in every `plan.json`. Calibrate from the first completed `url` run — lease-wait vs
active time from `limits.json`, per-class request counts from `hunt web coverage` — and treat any
width they produce until then as a starting point, not a finding about the target.

## Shards

A member is one existing hunter given a narrow slice: a subtree, a route group, one sink family.
`hunt swarm plan` shards each owner's matrix rows contiguously, so two members never receive the
same class and shard — the existing "two hunters must never be given the same class" rule, extended.

A member whose trace ends in another member's sink hands the sink half over with the source half
attached and says who it handed it to. One finding, two contributors, never two competing reports.

## Forging an agent

When the target has a surface no standing hunter owns, write one:

```
hunt swarm forge --name graphql-resolver-hunter --shard "schema/** · field authz" --target <slug>
```

Forging and registering are **one operation**, because an agent the orchestrator does not name is
never dispatched — `tests/test_agent_wiring.py` exists to reject exactly that, and at swarm scale
the mistake would repeat dozens of times per hunt. The forge writes the agent, then writes its line
into the `SWARM-REGISTRY` block in `sec-orchestrator.md` and in `run-board/SKILL.md`.

Three constraints the forge enforces, each for a concrete reason:

- **The name must be `[a-z]+(-[a-z]+)*-<suffix>`** with suffix in hunter/aimer/prover/analyzer/
  writer/auditor/editor/corrector. **No digits, no underscores.** The orchestrator's
  dispatch-validity check matches `[a-z]+` with no digit class, so `api-v2-hunter` would be invisible
  to it while still being required by the every-agent-is-dispatched check — an agent only half the
  suite can see.
- **`tools:` may never include `Task`.** A member that can spawn its own members is an unbounded
  swarm. No agent in this repo declares it.
- **Frontmatter is exactly `name, description, tools, model`, flat.** `tools/board.py` hand-rolls a
  line parser rather than using YAML; anything nested flattens silently.

The guardrail prologue and the verdict table are copied **verbatim** from a standing hunter. A forged
agent with a softer verdict bar is how a 30-wide swarm would launder `BLOCKED` into `CLEAR` at scale.

Retire at the end of the hunt: `hunt swarm retire --target <slug> [--keep <name>]`.

## Findings: merge first, then rank

At width 30 two members reaching one bug from different directions is the **default**, not the edge
case. Record every finding as it lands:

```
hunt swarm finding --target <slug> --class ssrf --agent server-side-hunter#2 \
    --sink services/fetch.py:88 --effect "listener hit" --status CONFIRMED --cvss 8.6
```

Identity is the **sink**, not the payload, so the same sink reached with two payloads collapses into
one candidate with both contributors named. Path normalisation matches `correlate/merge.py` —
`services\API\fetch.py` and `services/api/fetch.py` are one file on win32, and that is the commonest
duplicate shape of all. A merge keeps the **strongest** evidence: a runtime-confirmed PoC outranks a
code-confirmed read, whichever landed first.

**Ranking is two-tier, because the impact gate is answer-driven and runs at report time.**

- **Tier 1** (`hunt swarm rank`) — cheap, over every deduplicated finding: proven outranks unproven,
  then CVSS, then **fewest stacked preconditions**. Preconditions rank above raw score because a
  stacked-precondition finding comes back Infeasible whatever it scores.
- **Tier 2** — `hunt impact-gate` on the **one** candidate about to take the lane. A `BLOCK` drops it
  and tier 2 re-runs on the next. A decision whose CVSS vector has since changed is stale and must be
  re-run, not reused.

While a lane is open: **no new members are tasked, and members already running finish rather than
being killed** — killing them discards proven work and manufactures the untested rows the old wave
cap was protecting against. Their returns queue.

## Dispatch is not completion — and at width 30 this is the dominant failure mode

`guardrails`: *"A subagent can return, be killed by a rate limit, or die mid-write, and all three
look identical from the outside."* For every member marked `[x]`, you must have read the return; any
member that was to leave an artifact must have that artifact verified to exist. **A swarm's board is
the most convincing way this pipeline has ever had to display work that did not happen.**

## Two swarm-specific prohibitions

- **No member sends a request outside the scoped path.** A hand-rolled `curl` or `requests` call
  bypasses `dynamic/scope.py` entirely: no host check, no window check, no shared rate or lease, and
  no `T#####` transcript entry. At width 30 that is 30 ways to exceed a program's authorized rate
  with nothing recorded.
- **No member writes `memory/` or `.claude/mistake-log/MISTAKES.md`.** Delegate to the `memory` and
  `mistake` agents, exactly as every standing hunter does.

## If the limiter degrades

A lost lease map forces `concurrency = 1` and raises `LIMITER_DEGRADED` on the board. Sizing refuses
while it is set. Clear it deliberately with `hunt swarm recover --target <slug>` — which preserves
the request budget, because a recovery that reset `sent` would be a way past a refusal.

## Several swarms on one target: the fleet

One swarm hunts one way. `hunt swarm fleet` runs the three methods the orchestrator already mandates
as peers, against one target, with one board, one findings index and one report lane.

**This is not "more agents". More agents is `--width`.** It is more *methods*:

| role | method | shards come from |
|---|---|---|
| `coverage` | has every applicable class been examined | the `vuln-playbooks` matrix |
| `depth` | what hides behind the abstraction layers (step 4b) | `deep-trace` §3, the 12 indirection patterns |
| `stack` | what exists because of what this is built ON (step 4c) | `stack-playbooks`, per-stack surface tables |
| `prove` | turning candidates into findings | the handoff queue, partitioned by class family |

```
hunt swarm fleet --target <slug> --kind url --scope <f> --have runtime,browser,identities
```

**Exactly one `coverage` swarm, always.** `depth` and `stack` are *additive* — they deepen classes
coverage already has to examine. Without coverage nothing guarantees every applicable row has an
owner, so a fleet without it is refused outright.

**Budget order is priority order.** Coverage's per-member floors are paid first and are never
negotiable. What remains funds the other roles' floors, in weight order; **a role that cannot be
funded does not launch and says so** rather than launching unable to finish. Only then is the surplus
shared out. A budget too small for coverage refuses the whole fleet — no number of swarms conjures
requests a program has not authorized.

**One agent ceiling, not one per swarm.** `MAX_AGENTS` (default 30, in `tools/fleet.py`) is the total
concurrent members across every swarm. Three swarms do not mean 90 agents — 90 is the failure that
created the wave cap. A role that has fewer shards than slots hands the surplus back, so the ceiling
is spent rather than reserved. Raising it is a deliberate edit with the reason recorded there.

## Standing agents belong in the fleet

A fleet that only distributes reading work produces candidates, not findings. Four agents already
exist for this and need a place, not new code:

- **`web-recon-hunter`** runs first and alone on `url`/`grey`; the fleet's shards derive from its
  inventory.
- **`target-aimer`** runs before any fleet member probes a live target. Unaimed, 52 of 54 primitives
  touched no real endpoint.
- **`dynamic-prover`** staffs the `prove` lane. It is what turns a candidate into a finding.
- **`chain-analyzer`** runs after the fleet returns and before `report-writer`.

## Discovery and confirmation are different jobs

A suspicious sink is a **candidate**. The contract is
`Discovery → Candidate → Handoff → Confirmation → Evidence → Finding`, and a swarm is not successful
because it found interesting code.

```
hunt swarm handoff --target <slug> --from depth/rce-exec-hunter#1 --to prove/dynamic-prover#1 \
    --fingerprint sha256:... --reason "eval reached via REGISTRY['template'], route passes a name" \
    --aim "POST /plugin?kind=template, body.content" --evidence work/<slug>/evidence/F021/
```

**Never drop the `--aim`.** Aiming, not capability, is the prover's measured failure mode: aimed by
hand the primitives found 4 of 6 seeded bugs; through the unaimed sweep, 2 of 6. A handoff without an
aim recreates the unaimed case.

The handing member's row becomes **`hunt board handoff`** — a new row state, because a member that
handed its lead away is neither `done` (no verdict was produced) nor `blocked` (nothing defeated it).
It is deliberately not counted in the tally; the receiving member's verdict is the one that counts.

## Capabilities: what the RUN has, not what the agent is

`--have runtime,browser,identities` declares what this run can actually do. A shard needing something
the run lacks opens **`BLOCKED` with the reason at plan time** instead of quietly returning `CLEAR`
later: `runtime` for any live verdict, `browser` for xss/client-side (they emit `NEEDS-BROWSER`, never
`CLEAR`), `identities` for authz differentials. This is a precondition check, not a second owner
taxonomy — the matrix's owner column already says who hunts what.

## Resuming

`state.json` records the phase and the plan it is bound to; `board.json` remains the authority for
row status and the tally, and the state file's counts are derived from it at write time. Two
authorities for run state is a bug this pipeline has already learned once.

```
hunt swarm resume --target <slug>
```

re-dispatches only the rows that never returned, and **refuses** if `plan.json` no longer hashes to
what the run was bound to — a re-planned swarm is not the swarm that was dispatched.
