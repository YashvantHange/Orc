---
name: poc-craft
description: >
  Build a minimal, benign, reproducible proof-of-concept for a confirmed vulnerability and capture
  a complete evidence bundle (evidence.json manifest). Load when turning a confirmed lead into
  report-ready proof.
---

# PoC + evidence procedure

A credible report needs a PoC a maintainer can run in one step and evidence that removes all doubt.
Markers + rules live in `marker-conventions` (benign only, local only, minimal, redact secrets).

## Steps

1. **Pin what you can pin.** For a source target: `git -C work/<slug>/src rev-parse HEAD` + dependency
   versions. For a **live website** there is no commit, so pin the equivalents — the exact origin, the
   date and time window of testing, the `scope_digest`, any `Server`/`X-Powered-By`/build-hash the app
   discloses, and the sha256 of the JS bundle you analyzed. A live target also *moves*: it can be
   patched or redeployed between your test and the maintainer's read, so state when you observed it and
   re-run the PoC immediately before delivery. Cache all of it in `work/<slug>/profile.json`.

2. **Reduce to a one-liner.** The smallest request that unambiguously demonstrates the bug — a
   `hunt probe --primitive ...` call or a ~10-line curl/requests script. Run it 2–3× for reliability.

3. **When a full boot is impractical, use the faithful-harness PoC** (see
   `dynamic-hunt` §3): `ast.parse` the vulnerable module, extract the vulnerable function(s) verbatim,
   `exec` them behind a minimal `TestClient`, drive with the marker. It proves the target's own bytes
   are vulnerable without building the whole monorepo. Keep the harness script in the bundle.

   **This does not apply to a live target — do not try to rebuild it locally.** The existing `.mjs`
   harnesses in this repo (`work/flowise/.../harness/server.mjs`,
   `work/<target>/evidence/<id>-dns-rebind/`) are local *reconstructions* of a target you had the
   source for. Against a live host there is nothing to reconstruct: the PoC is the request itself, and
   an `.mjs`/HTML harness is purely the **attacker page** the maintainer opens (a framing page for
   clickjacking, a poster page for postMessage, a form for CSRF). Ship that page in the bundle,
   parameterized with the target origin, so the maintainer runs it against their own instance.

4. **Collect the evidence bundle (with the manifest):**
   ```
   hunt evidence work/<slug>/src <finding_id> --poc "<command>" \
       --url "<poc-url>" --root-cause work/<slug>/evidence/<finding_id>/root_cause.md
   ```
   This writes `work/<slug>/evidence/<finding_id>/` with `poc.txt`, `request.txt`, `response.txt`,
   `server_log_excerpt.txt`, `root_cause.md`, `meta.json`, and **`evidence.json`** — the reproducible
   manifest {requests, responses, logs, stack_traces, root_cause, commit, sha256 hashes}. Manual
   equivalent (fully valid): `mkdir` the dir, `curl -s -i "<url>" | tee response.txt`, save the PoC
   command + the server-log/stack lines + `git rev-parse HEAD`, and write the root-cause graph.

   For a live target add `--transcript-ids T00203,T00287` to slice those exchanges out of
   `work/<slug>/web/transcript.jsonl` into the bundle, plus `--screenshot` for the browser-confirmed
   classes. There is no server log to attach — the transcript *is* the log, and its `T#####` ids are
   what the report cites in place of `file:line`. Before shipping, read the sliced transcript and
   redact any real user data or secret that a response body happened to contain; the bundle leaves your
   machine, and "it was in the response" is not a defense.

5. **Write the root-cause graph** into `root_cause.md` before/with collection (see `report-standards`):
   `source → route → middleware → guard → missing/wrong check → framework behavior → sink`. This is the
   spine of the report and the map to the patch + variants.

6. **State observed vs. expected** crisply (e.g. "returns bob's private note to an anonymous caller;
   expected 401/403") and the numbered reproduction from a clean clone.

## Output
The minimal PoC, the evidence bundle path (+ `evidence.json`), the root-cause graph, reproduction
steps, observed-vs-expected — everything `report-craft` needs to fill the template without guessing.
All of it to the production-quality bar (`report-standards`): the PoC copy-pasteable and deterministic
(it ran 2–3×), every captured request/response/stack pasted from a real run (never reconstructed from
memory or fabricated), observed-vs-expected exact, confidence labeled honestly. If you couldn't run it,
say so — don't invent output. Finish with the **reasoning-checklist**.

## Record the run — `poc.txt` is no longer evidence

`hunt evidence --poc "<cmd>"` writes down the command you *say* you ran. That is a note, not proof, and
it is why reports used to ship with output nobody had produced. Run the PoC through the recorder:

```
hunt poc-run <target> <finding_id> --cmd "<the exact command>" [--python <the PoC's venv>] \
    [--volatile '<regex for values that change between runs>']
```

Twice, minimum. It captures real stdout/stderr with hashes, the exit code, `pip freeze` from the
interpreter the PoC actually used, the target commit, and whether the tree was dirty. Declare volatile
values **before** comparing, so the mask is recorded rather than widened later to hide a mismatch.

Two things follow from this, and they are the point:
- **Every output block in the report must appear in a recorded run.** If you cannot find it there, it
  did not happen — go run it, or cut the claim.
- **Every pinned version must appear in a recorded freeze.** This is what stops a plausible-looking
  `requests==2.34.2` from reaching a maintainer who then discovers no such release exists.

Without a runlog there is no receipt, and without a receipt the report cannot be delivered or
submitted — the hooks enforce it. `--python` matters more than it looks: a PoC usually builds its own
venv, and freezing the wrong interpreter records versions the reader can never reproduce.

A non-zero exit is often correct — a crash is frequently the bug. Say so in the report rather than
hiding it.

Live-website findings have no local process to record; the transcript is their anchor instead
(`report-standards`), and the faithful-harness pattern is forbidden there.
