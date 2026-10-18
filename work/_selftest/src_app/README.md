# src_app — a deliberately vulnerable fixture

**DO NOT FIX THE BUGS IN THIS DIRECTORY.** They are seeded on purpose and `tests/test_fleet_hunting.py`
asserts they are still here. Nothing in this tree is imported by the pipeline; it is input, not code.

It exists because every other test in this repo checks swarm *mechanics* — sizing, budget splitting,
hashing, locking, merging — and none of them checks that a fleet can find a bug. `work/_selftest/` is
the repo's prepared home for exactly this: `.gitignore` ignores `work/` and then negates
`!work/_selftest/**` so a fixture like this one is tracked.

## What is seeded, and which role should find it

| seed | where | why this role |
|---|---|---|
| `coverage-cmdi` | `app.py` `run_report` | a sink in the handler itself — the class-first matrix sweep finds this by reading the route |
| `depth-exec` | `registry.py` → `handlers.py` `render_template` | the handler passes a *name*; the sink is behind a dispatch registry, so a surface read of the route finds nothing. This is the one `depth` must find and `coverage` may not |
| `stack-debug` | `settings.py` | a framework debug surface. Class-first hunting never thinks to ask for it; `stack` does |
| `negative-control` | `app.py` `run_export` | shaped exactly like `coverage-cmdi` and correctly defended. A role that reports this is producing false positives, so the test asserts it comes back CLEAR **with the defense named** |

`seeds.json` is the machine-readable version and is what the test reads.
