---
name: state-integrity
description: >
  Hunting playbook for the defect family where an operation fails or ends but leaves state behind
  that later code trusts. Two sub-families: S1 error-path state corruption (an abort leaves a
  structure, object or security context half-updated) and S2 cross-request state reuse (one
  request's data or identity stays reachable by the next). Covers every language — in C/C++ the
  family presents as use-after-free and uninitialised reads, in Python/JS/Go/Java as module-global,
  pooled-worker and thread-local bleed that serves one user's data or auth context to another. Load
  whenever a target has an error path, a worker pool, a cache, or a global.
---

# State integrity — the bug that survives the failure

Most hunting looks for a bad value reaching a dangerous sink. This family is different: **the value
is fine and the state is wrong.** An operation aborts, or a request ends, and something that should
have been rolled back or cleared was not. Later code reads it and trusts it.

The canonical pair, both patched 2026-10-21 at CVSS 9.2, both unauthenticated RCE:

**Read the correction below before you use these as a map.** An earlier version of this section
named `_zend_hash_str_add_or_update_i` as the defect site. That function is real — `Zend/zend_hash.c`
at `php-8.4.26` — but **the fix does not touch it**, so anyone navigating by that name arrives
somewhere the maintainers never changed. Verified against the `php-8.4.26..php-8.4.27` diff at commit
`c31ae58ecbedc7a85dac0eee5a6a88da73543e70`.

* **S1 — an abort inside a container operation leaves its size/count fields describing storage that
  was never obtained.** The upstream fix is what names the invariant: it threads an explicit
  `fallible` flag through the hash-table allocation paths, adds `femalloc`/`fpemalloc` so a failure
  **returns** instead of never returning, replaces `zend_error_noreturn` with
  `zend_mm_delayed_error_or_panic`, and adds explicit rollback (`uint32_t origSize = ht->nTableSize;
  … ht->nTableSize = origSize;`). The changed functions are `_zend_hash_init_int`,
  `_zend_hash_add_or_update_i` and `_zend_hash_index_add_or_update_i` (`Zend/zend_hash.c`, +302
  lines; `Zend/zend_string.c`, +22).
* **S2 — state decoded where no user code may run must not be able to cause user code to run.** The
  upload-progress handler decodes *and re-encodes* the session during request **startup, before
  RINIT**. The fix adds `PS(in_rfc1867_update)` and forces incomplete-classes-only serialization
  while it is set, so objects stay `__PHP_Incomplete_Class`: no autoloading, no
  `unserialize_callback_func`, no `__wakeup()` or `__unserialize()`, written back unchanged
  (`ext/session/session.c` +73, `main/rfc1867.c` +216, `main/php_variables.c` +34). Note this is an
  **ordering** defect, not an abort — the generic "a fatal error interrupts the reset" story this
  skill used to tell was the family's shape, not this bug's mechanism.

**What is NOT verified, stated so the next reader does not inherit a guess.** The release ships as
advisory **GHSA-f883-x959-3vr9**, identifiable objectively because it carries
`tests/basic/GHSA-f883-x959-3vr9_*.phpt` plus sixteen `oom_rfc1867_*.phpt` tests. Which CVE id maps
to which hunk is **not** derivable from the diff, and is not asserted here. `php-8.4.26..php-8.4.27`
is a whole point release — 629 files, 19,642 insertions — so the diff alone is not a map either.

Read these for the **shape**, because the shape is what transfers, and treat every file and function
name above as provenance rather than as a place to go looking on your next target. Neither shape is
about C.

## The two sub-families

| | S1 — error-path state corruption | S2 — cross-request / cross-identity state reuse |
|---|---|---|
| **Invariant violated** | an operation aborts before restoring a valid state | data or security context belonging to one request or identity stays reachable by another |
| **Typical impact** | memory corruption, crash, privilege escalation, RCE | cross-tenant disclosure, **authorization bypass, privilege escalation, credential/session confusion** |
| **Where you look** | every `catch`, `finally`, `except`, `recover`, bailout, cancellation and OOM path | everything with process lifetime: module globals, singletons, class attributes, pools, thread-locals, caches |

**S2 is not just a data leak.** The higher-severity outcome is a *stale authorization context*: the
next request inherits the previous caller's role, tenant or token and the application makes a wrong
authorization decision with it. Hunt for the authorization bleed, not only the data bleed.

### The distinction that decides false positive vs finding

* A cache deliberately shared across requests **with correct isolation** — keyed by tenant, scoped per
  identity, explicitly reset. **Not a vulnerability.** Do not report it.
* A cache that **unintentionally retains request-specific security context** — keyed by nothing, or
  keyed correctly but holding an object that carries the last caller's identity. **The vulnerability.**

If you cannot say which of those two you are looking at, you have not finished reading.

## Sources and sinks, per language

**S1 — where the abort leaves the mess**

| Language | Look for |
|---|---|
| C/C++ | `longjmp`/`setjmp` bailout across a partly-updated container; a counter, length or refcount incremented before a fallible `malloc`; a destructor or cleanup loop that walks a count rather than a validity flag; `goto cleanup` that frees a subset |
| Python | `finally` that frees but does not clear; `__del__` / `__exit__` on a half-constructed object; a module dict or class attribute mutated before the validation that raises; `asyncio` task cancellation mid-update |
| JS/TS | an exception thrown mid-reducer leaving module state inconsistent; a rejected promise after a partial cache write; `finally` that releases without resetting |
| Go | `panic`/`recover` leaving a mutex held, a map partly written, or a `defer` skipped; an error return after a partial struct mutation |
| Java/.NET | a constructor that throws after registering `this` somewhere; a finaliser over a partly-initialised object; a static initialised in two steps |

**S2 — where the state outlives the request**

| Language | Look for |
|---|---|
| C/C++ | process or worker globals pointing at request-arena memory (`emalloc` vs `pemalloc` confusion); any global pointer not nulled in the request-shutdown path |
| Python | module-level or class-attribute caches holding `request`, `user`, `session` or a token; `contextvars` set but never reset; gunicorn/uwsgi worker reuse; a singleton HTTP/DB/LLM client configured per-request with the caller's credentials |
| JS/TS | module-scope `let`/`var` holding `req`, `res`, `user` or a token; a cached middleware or client instance; async-context bleed across `await`; prototype mutation that persists |
| Go | `sync.Pool` objects reused without a reset; a package-level var holding a request `Context`; a reused `http.Request` field |
| Java/.NET | a `ThreadLocal` not cleared on a pooled thread; a request-scoped bean promoted to singleton; a static `Principal` |

**Highest-yield grep starting points:** a global or module-level mutable assigned inside a request
handler; a cleanup function that iterates a count; a `finally` block with a `free`/`del`/`close` but no
assignment to `None`/`null`; a pool `Get` with no corresponding reset.

## Confirmation bar — S1

Three parts. **All three are required**, and a sanitizer trace only discharges the second.

1. **Trigger** — an attacker-controlled input or operation drives the abnormal path. Name the input
   and show it reaching the abort. "An OOM could happen here" is not a trigger.
2. **Invariant violation** — the aborted operation leaves a structure, object or security context
   invalid. **Name the invariant** ("the bucket count must only include initialised buckets"), then
   show it broken.
3. **Security consequence** — the invalid state produces an observable, security-relevant effect.

In a managed language an asserted invariant violation **alone is not a finding** — it must reach an
observable security impact. A crash with no consequence beyond the crash is an availability issue and
this pipeline does not report those; see `guardrails`.

For native targets the instrumentation is not optional and **the choice of sanitizer decides whether
you see the bug at all** — see `native-sanitizer`. ASAN is blind to an in-bounds read of uninitialised
memory, which is exactly S1's shape; MSAN is what sees it. A class swept under the wrong sanitizer is
`BLOCKED (wrong instrumentation)`, never `CLEAR`.

## Confirmation bar — S2

The two-identity, two-request differential:

| Step | Requirement |
|---|---|
| Request A | identity `A` writes a unique marker (see `marker-conventions`) |
| Request B | identity `B` requests the corresponding resource |
| Observation | `B` must not receive `A`'s marker. Receiving it is the finding. |
| Control | a run with requests forced onto **different** workers must **not** reproduce it |

Reuse what exists: `dynamic/authz_diff.py` and the `authz-audit` skill already provision identities
and diff responses. Use the `pool` target shape in `dynamic/instrument.py` to control worker count and
distribution policy.

**Record seven fields with every S2 verdict.** The seventh exists because the first six can all look
healthy while the platform quietly pins every request to one process:

1. worker identification method (pid echo, `X-Worker` header, a pid-revealing error);
2. whether connection reuse (keep-alive) was enabled;
3. **the distribution mechanism in force** — `cluster.SCHED_RR` vs the win32 default, php-fpm pool
   mode, gunicorn worker class, OS accept balancing;
4. attempts;
5. successful observations;
6. observed success rate **under a realistic distribution policy**;
7. negative-control result, naming the mechanism used to force distribution.

### Two traps, measured

* **"Use more workers" is not a negative control.** Measured on win32: 4 workers, no connection reuse,
  5 trials — every trial still landed both requests on one worker and still reproduced the leak. A
  hunter who "ran the control" that way sees the finding confirm and calls it robust. The control must
  **force** distribution: `cluster.schedulingPolicy = cluster.SCHED_RR`, per-worker ports, or a worker
  restart between requests.
* **Worker affinity on win32 is free and total**, so the positive case is too easy. 12 sequential
  requests reached 1 of 4 workers under the default policy; with `SCHED_RR` they reached 4 of 4. A rate
  measured while the platform was pinning everything to one process **is not a rate** — it is an
  artefact of the harness. State the policy, and measure the rate under a realistic one.

A probabilistic result is never written up as deterministic.

## Negative control — mandatory for both sub-families

Every confirmation ships with:

* a **positive** input that triggers the defect;
* a **benign** input that must not;
* a **comparison** of the two evidence sets, both recorded;
* a sentence on **why the positive input is security-relevant**.

For S2 the control must additionally separate intended shared-cache behaviour from unintended
security-context reuse. Without that, a correctly-isolated cache and a cross-tenant leak look
identical in the transcript.

## When the target is a live website (kind `url` / `grey`)

**This class can expose a real third party's data to you**, because the whole defect is "someone
else's state comes back to me". So:

1. **Reproduce on a local instance of the same version.** The live surface is used only to establish
   that the sink and the pooling exist.
2. Any live differential runs **strictly between two accounts you own**, with a seeded marker whose
   value is unmistakably yours.
3. If data belonging to anyone else appears: **stop, minimise, purge, report.** Do not iterate to
   measure a rate. A rate measured from strangers' data is not evidence worth having.
4. **No worker churn** — never restart, exhaust or crash workers on a live host. That is an
   availability attack and it is forbidden; see `disclosure-ethics`.

A live row you could not settle this way is `NEEDS_EXTERNAL_SIGNAL`, naming what was missing.

## Novelty and chaining

Run every candidate through `variant-analysis` before the report lane. This family is well represented
in published advisories for mature targets, so the exclusion map matters more here than usual — and an
incomplete-fix variant is not reportable.

Then load `chain-craft`. An S2 stale-authorization finding is a natural first link: stale context →
wrong authorization decision → privilege escalation or cross-tenant write. That chain, not the leak
alone, is usually where the severity actually lands.

## CWE

From `cwe-map`: CWE-416 use-after-free · CWE-415 double free · CWE-824 / CWE-457 uninitialised ·
CWE-787 / CWE-125 OOB write/read · CWE-476 NULL deref · CWE-488 / CWE-1230 cross-request data leak ·
CWE-567 unsafe shared state in a concurrent context · CWE-662 improper synchronisation. Pick the most
specific thing you actually proved.

## Verdict rules for this family

* Sanitizer or runtime unavailable → `BLOCKED`, naming what was missing. Never `CLEAR`.
* Wrong sanitizer for the sub-family → `BLOCKED (wrong instrumentation)`. Never `CLEAR`.
* Attack sent, nothing observed → `NOT_CONFIRMED`. Never `CLEAR`.
* No worker-pool runtime for the target's language → `NEEDS_EXTERNAL_SIGNAL`, naming the runtime.
* `CLEAR` requires the guard read **and** the attack sent and rejected, both named — including, for
  S2, the reset or isolation that actually defends it.
