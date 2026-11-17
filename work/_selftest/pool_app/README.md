# pool_app — a deliberately vulnerable worker-pool fixture

**DO NOT FIX THE BUGS IN THIS DIRECTORY.** They are seeded on purpose and
`tests/test_state_integrity_pool.py` asserts they are still here. Nothing in this tree is imported by
the pipeline; it is input, not code.

It exists because the cross-request state-reuse class (`state-integrity` § S2) cannot be exercised
against a single-process boot at all: the bug only appears when **two requests are served by the same
pooled worker**, and its control needs them served by different ones. Without a fixture that has the
bug, there is no way to tell a working differential from one that never fires — and a probe that never
fires reads as `CLEAR`.

It has no dependencies: node's `cluster` is built in.

## What is seeded

| seed | endpoint | expect | why |
|---|---|---|---|
| `s2-identity-bleed` | `/whoami` | **CONFIRMED** | `lastIdentity` is module scope, so it has *worker* lifetime, is set from the caller's credentials, and is never cleared at request end. An unauthenticated request reads the previous caller's identity. This is `CVE-2026-109619`'s shape in a managed language. |
| `s2-negative-control` | `/note` | **CLEAR** | the same shape, but keyed per identity and read only with that identity's own key. A correctly isolated cache is not a finding; a run that reports this one is producing false positives. |

`/worker` returns the serving pid, the worker count and the policy in force, so a probe can state
**which** worker handled each request rather than assume.

## The distribution trap this fixture is built to expose

Measured here (win32, node v24.20.0):

* **platform default** — 12 sequential requests reached **1 of 4** workers. Total affinity.
* **`CLUSTER_SCHED_POLICY=rr`** (`cluster.SCHED_RR`) — 12 sequential requests reached **4 of 4**.

So **raising the worker count is not a negative control.** Run with 4 workers and no forced policy and
the leak still reproduces every time, which makes a bogus finding look robust. The control must force
distribution. `dynamic/instrument.py` refuses a `pool` boot without an explicit `policy` for this
reason.

## Running it

```bash
WORKERS=1 CLUSTER_SCHED_POLICY=none PORT=8711 node server.js   # positive case
WORKERS=4 CLUSTER_SCHED_POLICY=rr   PORT=8712 node server.js   # control
```

Or through the pipeline, which is what the test does:
`TargetProcess("work/_selftest/pool_app", pool=1, policy="none")`.
