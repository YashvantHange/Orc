---
name: target-model
description: >
  The opening discipline: build an explicit model of a target's INSIDE before hunting it — scopes
  and lifetimes, trust boundaries, abnormal exits, invariants, reachability, state transitions —
  then search invariant-first through a table you must fill. This is what finds bugs whose essence
  is a relationship between a lifetime, an invariant and an abnormal exit rather than a dangerous
  call with untrusted data in it. Load at the START of every hunt, before any class is swept, on
  `src`, `url` and `grey` targets alike. `reasoning-checklist` is its counterpart and runs last.
---

# Target model — the opening discipline

`reasoning-checklist` runs **last** and stops you over-claiming. This runs **first** and is what
makes a hard bug findable at all. Both are mandatory; they do opposite jobs.

## Why this exists

The sink-first method — `rce-exec-hunter`'s "grep for the sink, then walk backwards" — works when
the defect is a **known local shape**: a dangerous call with untrusted data in it. One function
holds the whole bug, so a pattern can point at it.

It cannot find a bug whose essence is a **relationship**. Take the shape PHP's 2026-10-21 release
fixed (`GHSA-f883-x959-3vr9`, CVSS 9.2): there is no dangerous sink anywhere in it. A container's
size field is updated, an allocation fails, the failure never returns to the caller, and the
consequence lands *much later* in code that trusts that field. Every individual line is correct. Its
sibling is the same kind of thing: a worker-lifetime pointer is fine, releasing the request's memory
is fine, and the bug is that one outlives the other.

Those are **shapes to reason with, not sites to navigate to** — `state-integrity` carries the
sourced version, including a correction where an earlier description named a function the upstream
fix never touched. That error is instructive here: a remembered site sends a hunter somewhere
unchanged, while a remembered *shape* makes it ask the right question of whatever it is looking at.

This was measured, not assumed. A pattern-based pass over real corpora returned **4,186 hits** for a
bare counter increment, and the two halves of the defect sit in **different functions** — which
semgrep has no cross-function dataflow for in C/C++. No rule finds these. A model does.

**So the output of this skill is not a list of suspicious lines. It is a model of how the target
holds state, and a table of the invariants that model implies.**

## The artifact

Everything goes in **`work/<slug>/model.md`**, appended phase by phase. One file, because the
phases refer to each other — the exit map is unreadable without the scope map. It is inspectable by
the user, reusable by every other hunter on the same target, and resumable: see
`dynamic-hunt` § 5 for the multi-session protocol, which applies here unchanged.

`hunt model-check <target>` validates the artifact's **form** — one section per phase, no blank
verdicts, every verdict evidenced, every filtered structure justified, coverage above the floor. It
cannot judge whether an invariant is *true*; that is yours, and the exam measures it.

### The headings are fixed, because the validator reads them

Use these exactly. `hunt model-check` fails on a missing one, and `hunt model-check --template`
prints this skeleton ready to fill:

```markdown
# Target model — <slug>

## 1. Scope map
## 2. State map
## 3. Exit map
## 4. Invariant map
<the invariant table goes here>

## 5. Reachability
## 6. State transitions

## Filtered structures
| Structure | Failed question | Why |
|---|---|---|
| render_cache | 1 — crosses no scope boundary | built and read inside one handler call |

## Coverage
declared abnormal exits: 14 / analysed: 14
candidate structures: 31 / passed the gate: 26 / filtered: 5
required cells: 142 / evaluated: 137
```

---

## Phase 1 — Scope map

Which scopes exist in this target, and what lives in each?

Ask the question in the target's own terms: **process**, **worker**, **connection**, **session**,
**request**, **handler**, **job/task**. For each, list the storage that has that lifetime:

| Scope | Storage with this lifetime |
|---|---|
| process / worker | globals, `static` locals, singletons, module-level mutables, class attributes, connection pools, caches, interned tables, thread pools |
| request | the request/response objects, per-request arenas, per-request contexts, locals |

Then the question that is literally `CVE-2026-109619`: **which allocator or container belongs to
which scope?** In PHP, `emalloc` is request-scoped and `pemalloc` is not; in Apache it is
`apr_palloc` against a request pool versus a server pool; in nginx `ngx_palloc` against
`r->pool` versus `cf->pool`. In a managed language the equivalent is the *container*: a dict keyed
per request versus a module-level dict.

Write the two lists side by side. **The bug is any pointer or reference from the long-lived list to
something allocated from the short-lived one.**

## Phase 2 — State map

For each item of long-lived storage: who writes it, who reads it, and is it ever reset?

The three columns that matter are **written by**, **read by**, **cleared by**. An empty
*cleared by* column on something written during a request is the S2 shape.

## Phase 3 — Exit map

Every mechanism in this target that can abandon work **mid-flight**:

exception · `longjmp`/`setjmp` · a bailout (`zend_bailout`, `apr_abortfunc`) · `panic`/`recover` ·
cancellation (a cancelled context, an aborted request, a closed connection) · timeout ·
out-of-memory · signal · early `return` on an error · `goto cleanup` · a rejected promise ·
a failed constructor · process exit during work.

For **each** one, two things:

1. **Which cleanup runs?** The handler, the `finally`, the destructor, the shutdown function, the
   arena release.
2. **What does that cleanup trust?** This is the question that finds the bug. *"It trusts that every
   slot below the count is initialised."* *"It trusts that nothing outside the arena holds a pointer
   into it."* A cleanup's assumptions are invariants someone else has to maintain.

## Phase 4 — Invariant map

For every mutable structure that crosses a scope boundary, state its invariant in **one sentence**,
in the form *"X must always be true of Y"*:

> "The bucket count must only include initialised buckets."
> "No pointer outside the request arena may reference memory inside it."
> "A pooled connection must carry no credentials from its previous borrower."
> "A thread-local principal must be cleared before the thread returns to the pool."

A vague invariant produces a vague sweep. If you cannot state it in one sentence, you do not yet
understand the structure — go back to Phase 2.

## Phase 5 — Reachability

Which of the above does an attacker reach **with no operator opt-in**?

Default configuration is not a detail, it is most of the severity. `session.upload_progress` being
**on by default** is what makes `CVE-2026-109619` a 9.2 rather than a curiosity, and
`google-oss-vrp-preconditions-set-severity` records a 7.1 credential leak returned as P4/S4
*Infeasible* because three conditions had to stack. Name the config state each path needs, and mark
anything needing an opt-in as a precondition **now**, not at report time.

## Phase 6 — State transitions

For each important structure, the lifecycle:

```
created → initialised → partially mutated → committed → consumed → destroyed
```

Annotate each arrow with **which exits from Phase 3 can fire there**. Then ask the general question
this whole skill exists to make askable:

> **Can this object enter a state that another component assumes is impossible?**

That question is not specific to memory safety. It also finds stale privilege state, auth-state
confusion, double cleanup, partially-initialised objects trusted as complete, resource-accounting
drift, and transaction rollback that leaves half a write — which is why this skill is shared by every
hunter rather than owned by one.

## Phase 7 — Discipline sweep: the population, and the odd one out

Phases 1–6 ask *"what is true of **this** structure"*. That finds a local defect. It does not find
one whose essence is that **a rule the codebase relies on everywhere is broken in two places out of
two hundred** — and that is the harder and more valuable shape.

PHP's 2026-10-21 fix is the proof. Upstream did not repair one function; it threaded a `fallible`
flag through *every* hash-table allocation path and replaced `zend_error_noreturn` wholesale. That
is the signature of a **systemic discipline problem**, and no per-structure question reaches it.

The move that does is different in kind: **build the population, classify every member, and the
minority is the suspect.** Asymmetry is the signal, and the ratio is the evidence — "2 of 6" says
something that a paragraph cannot.

### The four steps

1. **Name the discipline**, in the form *"every X must Y"*. You already have a list of candidates:
   **Phase 3's "what does this cleanup trust?" answers are disciplines other code must uphold.**
   *"Every field this cleanup frees must have been nulled by whoever last wrote it"* is a rule with
   a population.
2. **Enumerate the population** — every site that owes the rule. This is where a grep belongs,
   because a grep is reliable at building a census and hopeless at judging one:

   ```bash
   python tools/census.py --root <tree> --glob '<glob>' \
       --population '<regex: every site that owes the rule>' \
       --upholds   '<regex: what upholding it looks like>' --window 3
   ```
3. **Classify every member.** Upholds / violates / not-applicable. **An unclassified member is the
   one you did not look at**, which is where the bug lives by definition.
4. **Triage the minority** — and this is the half a census cannot do. Is the exception *deliberate*?
   It usually is. The question that decides it: **does anything downstream know?** A documented fast
   path with every consumer aware of it is not a defect; a documented fast path that one consumer
   still trusts is exactly one.

### Uniformity cuts both ways — this is the part that reaches the hard shape

A uniform population is not automatically a clean result.

| Census says | What it means |
|---|---|
| a small minority | the asymmetry is the suspect. Triage it per step 4 |
| uniform, and the rule is safe | a real negative. Record it **with the ratio**, so it can be re-measured |
| **nobody upholds it** | the rule you tested is not the real one — and the real one may be unsafe **by design**. There is no odd one out: **the population is the finding** |

That third row is PHP2Shell's root condition, and it is measurable. Censused over
`Zend/zend_hash.c` at the pre-fix commit, **20 of 20** allocation sites decline to check for
failure. Not twenty bugs — one discipline, *"failure never returns to the caller"*, upheld
perfectly. The defect is then every caller that had already mutated shared state when control left,
so the next census is of the **callers**, not the allocations: which of them writes to a shared
structure before a call that may not return?

### Why this is a phase and not a footnote

The pipeline already owns this move and has it pointed the wrong way.
`reasoning-checklist` item 5 says *"grep for sibling routes/sinks/inherited impls with the same
flaw — there are usually more"* — run **after** a finding, to amplify it. Same with the sibling
sweep in `variant-analysis`. Both are the population move used backwards.

Used forwards, the population finds the bug instead of multiplying it. That inversion is exactly the
one Phase 4 makes for invariants: the invariant used to be named *after* a candidate, and naming it
*first* is what makes the search work.

---

## The relevance gate — run it BEFORE the cross-product

The naive sweep is *every exit × every structure*. On a real target that is a Cartesian explosion:
300 structures × 100 exits is 30,000 cells, and you would spend the whole hunt filling a table
instead of hunting. So a structure enters the invariant table only after passing four questions:

1. Does it **cross a lifetime or scope boundary**?
2. Is it **mutated before** an abnormal exit?
3. Can **attacker-controlled execution reach** the mutation?
4. Is there a **later consumer**?

```
target → candidate structures → relevance gate → invariant table → cross-product
```

never `everything × everything`.

**Record every structure you filter out, with the question it failed and one line of why.** This is
not bookkeeping for its own sake: an unaudited filter is the loophole that defeats the coverage
figure below, because "coverage 100%" is reachable by filtering away 299 of 300 structures. A filter
decision is a claim like any other and `guardrails`' No-Assumption rule applies to it.

## The invariant table — the actual search

This is the inversion that does the work. The old order was *find a candidate, then name the
invariant it breaks*. The new order is **enumerate the invariants, then find the path that leaves
one false**. That is how `CVE-2026-109618` surfaces: from *"the count must only include initialised
buckets"*, you look for a path that increments the count without initialising, and the fallible
allocation is right there.

| ID | Structure | Invariant | Who mutates | What can interrupt | State at interruption | Cleanup that runs | What cleanup assumes | Later consumer | Violated? | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| INV-01 | bucket table | count counts only initialised buckets | hash insert | OOM in key alloc | count up, bucket uninitialised | bailout → request shutdown | every counted bucket is valid | cleanup destruct loop | **yes** | `zend_hash.c:NNN` increment · `:NNN` fallible call · `:NNN` walk |
| INV-02 | module globals | no pointer outlives the request arena | request handler | fatal-error bailout | global points into a freed arena | arena release | nothing holds arena pointers | next request, same worker | **yes** | `session.c:NNN` store · `:NNN` free · no null in RSHUTDOWN |

Both rows are the two PHP CVEs, which is the point: **the columns are the traversal.** Filling a row
honestly *is* the hunt for that invariant.

### Two rules about filling it

**`Violated?` is `yes` / `no` / `unreachable` — never blank.** A blank cell is an unfinished sweep,
not a negative result, and `hunt model-check` fails on one.

**`Evidence` is mandatory for every verdict, and this is the most important rule in this skill.**
Without it the table becomes a place to record conclusions you did not establish, which is *worse*
than leaving it empty: it manufactures the appearance of a completed sweep. Each verdict needs its
own kind of proof:

| Verdict | What `Evidence` must carry |
|---|---|
| `yes` | the `file:line` of the mutation, of the interrupt, and of the later consumer |
| `no` | the `file:line` of the rollback, guard, reset or null that **holds** the invariant |
| `unreachable` | the reachability argument — which config, privilege or call path is absent |

This is the opening-phase counterpart of `reasoning-checklist` item 10: every load-bearing claim
marked with how you know it. A row whose evidence is "it follows" or "the structure looked fine" is
an assumption, and the verdict reverts to blank.

## Coverage accounting — so "found nothing" is diagnosable

"I found nothing" has two completely different meanings, needing opposite fixes: *the method does
not work*, or *I traversed 12% of the space*. Record both, with the denominator being the
**post-filter** required set:

```
declared abnormal exits        14      analysed              14
candidate structures           31      passed the gate       26      filtered (with reasons)  5
required cells (post-filter)  142      evaluated            137      coverage  96%
```

Report this on the run board with the pass count. A hunt that ends at low coverage is **not** a
clean result and must not be recorded as one — the honest verdict there is `UNTESTED` or `BLOCKED`,
per `dynamic/verdict.py`.

---

## The passes — and how to survive running out of context

A complex bug does not come out of one read. It also does not survive a context window, so the
passes are numbered and each one **appends to `model.md` before it ends**. The artifact is the
memory; your context is not.

| Pass | Produces | Done when |
|---|---|---|
| 1 | Phases 1–2: scope map, state map | every long-lived store has a *written by / read by / cleared by* row |
| 2 | Phase 3: exit map | every abnormal exit has a cleanup **and** a "what it trusts" |
| 3 | Phases 4 + 6: invariants, state transitions | every boundary-crossing structure has a one-sentence invariant |
| 4 | the relevance gate | every candidate either enters the table or is recorded as filtered, with a reason |
| 5 | the invariant table | no blank `Violated?`, every verdict evidenced |
| 6 | Phase 5 + handoff | reachability per violated invariant; leads handed to the class hunter |

Report the pass number and the filled-row count on the run board at each boundary, so the user can
see depth accumulating rather than a single silent block of work. **Resume is already solved** — use
`dynamic-hunt` § 5's multi-session protocol unchanged: state lives on disk, a new session reads
`model.md` plus `profile.json` and continues at the first unfinished pass. Do not restart at pass 1
because the context went; that is how four passes of real work get thrown away.

A pass that ends without writing is a pass that did not happen.

## Falsification — two levels, because the expensive one must be rationed

This family's dominant failure is the **false positive**, and the reason is structural: a shared
cache, a pooled object and a long-lived global all look exactly like the bug until you check whether
anything resets them. So every candidate gets argued against, and the heavy version is rationed.

**Level 1 — every candidate, immediately, in one or two sentences.** Before the row leaves `yes`,
write the best case that it is *fine*:

- the cache is intended and correctly keyed — a shared cache with correct isolation is **not** a
  vulnerability; only one that retains **security context** is;
- the global is written before every read, so the stale value is never observed;
- the counter is restored on the error path (find the decrement, cite it);
- the structure never crosses an identity boundary — one user's state reaching *the same user* is
  not a finding;
- the exit cannot fire with attacker-controlled timing.

If the rebuttal holds, the verdict is `no` and the citation goes in `Evidence`. That is a **success**:
a cheap negative recorded with its guard is worth more than an expensive maybe. Doing this at level 1
is what stops a weak candidate consuming a confirmation budget.

**Level 2 — high-value candidates only.** A candidate that survives level 1 *and* would be reported
gets an **independent** adversarial pass: a second agent, given the code and the claim but not your
reasoning, whose job is to argue the negative. Same pattern as `report-auditor` and
`chain-analyzer` — the point is that it has not already convinced itself. Reserve it for leads worth
the cost; running it on everything just moves the bottleneck.

Record both levels in the row's `Evidence` or a note beneath the table. A `yes` with no recorded
rebuttal has not been falsified, it has only been asserted.

## What each hunter asks

Every hunter builds Phases 1–3 and 5. The deep phases are where they differ:

| Hunter | The model questions that matter most |
|---|---|
| `state-integrity` | all six — this family *is* the model |
| `rce-exec` | what runs with which privileges; what reaches a loader, a deserialiser or an interpreter; which scope holds the name being resolved |
| `authz-logic` | where authority is decided and what carries it across each boundary; which identity a cached or pooled object was populated for |
| `server-side` | which scope owns a fetched URL, a parsed document, a temp file; what a cleanup deletes and what still points at it |
| `resource-dos` | what is unbounded **per request**, and what accumulates per *worker* across requests |
| `datastore` / `xss` / `client-side` | which scope a value is interpolated from, and whether it was validated in a different scope than it is used in |

## Boundary with the other opening skills

Three skills look at a target before it is hunted. They do not overlap:

- **`web-recon`** owns the target's **outside** — endpoints, identities, baselines, bundles. `url`
  and `grey` only.
- **`authz-audit`** owns **who may do what** — the permission model and its differential.
- **`target-model`** owns **scopes, lifetimes, invariants and state transitions** — the inside.

A `grey` hunt runs `web-recon` **and** this. On a `url`-only target with no source, Phases 1–3 are
built from behaviour instead of code — worker identity from a pid echo or header, scopes from what
survives a reconnect, exits from what an induced error leaves behind — and `BLOCKED` is the honest
verdict for an invariant you cannot see the code for. Do not guess an invariant from a response body.

## If this method is being measured on a target with a known answer

Run **`python tools/exam_check.py <the exam's key>`** first, and record its verdict with the result.
It greps every instruction an agent loads — skills, agents, commands, `RULES.md`, the mistake log
**and both memory stores** — for the strings that would let it navigate to the answer instead of
deriving it. `BLIND` means a run measures discovery. `COMPROMISED` means it cannot.

**A compromised target cannot be rescued by a better brief**, and the attempt is instructive: the
first php-src exam forbade starting from any location a skill named, those locations *were* the
answers, and recall was therefore 0/2 before the run began. An exclusion rule applied to a leak that
sits at the answer excludes the answer. Pick a different target, or state plainly that the run
measures model quality and false-positive control rather than discovery.

Note also what that exam found the hard way: a **memory file** leaks as effectively as a skill, and
is easier to forget, because consulting memory is a hunter's mandatory first step.

## Failure modes, named

- **A plausible model is worse than no model.** `hunt model-check` passes on form alone; a model that
  reads well and gets the lifetimes wrong will send the whole hunt in a confident wrong direction.
  If you are unsure of a scope, write "unknown" and say why — that is a real, usable entry.
- **Imitating a worked example.** `state-integrity` carries the PHP cases; do not go looking for
  `emalloc` in a Go service. Translate the *question*, never the vocabulary.
- **Filling the table to finish it.** A row without evidence is not progress. Fewer honest rows beat
  a full table of assertions, and the coverage figure is there to make the shortfall visible rather
  than to be maximised.
- **Treating the model as the finding.** A violated invariant is a **lead**. It still has to clear
  the family's confirmation bar, the scope gate, novelty (`variant-analysis`) and
  `reasoning-checklist` before it is a finding.
