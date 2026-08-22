---
description: Run a full security hunt on a repo, local path, or an authorized live website (static + dynamic, agent-driven)
argument-hint: <owner/repo | local-path | https://host --scope scope.yml> [--with-codeql]
---

Run a complete, responsible-disclosure security hunt on: **$ARGUMENTS**

Print the opening run board (`run-board`), then delegate to the **sec-orchestrator** agent. Give the
agent call a `description` that says what is starting — `Hunt langchain: recon + static scan`, not
`Security hunt` — and tell the orchestrator it **owns the board from that moment**: it is a subagent,
so its output is all the user will see, and the board you just printed goes stale the instant it
starts. Print the final board yourself when it returns. Give it this brief:

- **Standing guardrails — load the `guardrails` skill first; they outrank everything below.**
  **No Assumption:** nothing is known until it was checked *this session* — the code says X only if it
  was opened at the pinned commit, it's exploitable only if the request was sent and the impact seen,
  it's `CLEAR` only if the guard was read **and** the attack sent and rejected, a version is affected
  only if
  it's in a recorded freeze, it's novel only if it cleared the exclusion map. What can't be verified is
  labeled `assumed` / `inferred` / `not tested` in the same sentence. Silence (a clean scan, an empty
  grep, a quiet hunter) is not safety, and a subagent's `CONFIRMED` is a lead until its evidence is
  opened. **No Hallucination:** never write a specific that wasn't obtained — `file:line`, function or
  parameter names, versions, advisory ids, command output, status codes, stack traces, CVSS vectors,
  transcript `T#####` ids, evidence hashes, or a gate receipt (read that out of `state/gate/<id>.json`).
  Paste from recorded runs; re-read before citing. **No bypass:** a guardrail is never a step you
  decide is already satisfied; when a hook or gate blocks, fix what it names rather than routing around
  it, and never edit or work around `.claude/settings.json`, `tools/hooks/**`, `reports/gate.py` or
  `evidence/runlog.py`. Report at the end what was gated, waived, `BLOCKED`, or unverifiable.

- Target: `$ARGUMENTS`. Resolve the **kind** first — it decides the whole workflow:
  - **`src`** — `owner/repo` (shallow-clone into `work/<slug>/src` with
    `git clone --depth 1 https://github.com/<owner/repo>.git`) or a local path (e.g.
    `work/_selftest/py_app`), used directly.
  - **`url`** — an `https://` origin. **Requires `--scope <scope.yml>`**; there is no other way in.
  - **`grey`** — both a URL and a source path. Keep the **source** slug as the workdir id so existing
    findings, evidence and `file:line` paths keep working; record the origin alongside. Always try to
    reach grey: if the site ships JS sourcemaps, web-recon-hunter recovers the front-end sources and a
    black-box target becomes readable.
- Disclosure floor: **authorized targets only** — an instance you launched on `127.0.0.1`, or a live
  host a validated `scope.yml` places inside a published bug-bounty/VDP scope, within its window, at
  its stated rate. Coordinated disclosure, benign markers, no bug claimed without a runtime-confirmed
  PoC + evidence. Read the `disclosure-ethics` skill in full for the live-target limits the scope
  guard cannot enforce. Guardrails are lowered otherwise — hunt every class aggressively.
- **Zero-days only (hard scope):** report only genuinely novel bugs — nothing covered by one of the
  product's published CVEs/GHSAs, and nothing that's an incomplete-fix / patch-bypass / variant of one.
  See the Novelty requirement in `report-standards`; `variant-analysis` is the exclusion map.
- Run the pipeline end-to-end via the `hunt` CLI (`.venv/Scripts/python.exe hunt.py <cmd>`), using
  your own judgment about when each tool earns its keep. **The skills and agents are the product; the
  Python is optional muscle** — every step below has a manual `Read`/`Grep`/`curl` equivalent, and a
  missing or broken helper never excuses an unswept class.
- **Runtime confirmation is also mandatory.** Reading the source is still where findings come from and
  still the first move — it's what tells you which request is worth sending. It is no longer sufficient
  on its own: every class also gets exercised against the running target before it gets a verdict. Have
  an instance available (or, for a live host, scope cleared + baselines captured) before tasking the
  hunters and hand each the live `base_url` and identity credentials, so testing a hypothesis is cheap
  enough that nobody skips it. Every coverage verdict cites both the code read and the request actually
  sent with the response observed; `CLEAR` means the guard was read **and** the attack was sent and
  rejected. A class read but never exercised is `BLOCKED (untested)`. The only exemptions are the
  detection-only and no-availability-testing limits in `disclosure-ethics`, labeled `code-confirmed`.
- **Show the run board — load the `run-board` skill.** Before step 1, print a numbered vertical roster
  of every agent the hunt will use (hunters first, then the report lane), each row `[ ]` queued with its
  scope. Reprint the **whole** board — fenced, numbered, nothing renumbered — at every boundary (step
  entered, hunter tasked, target booted, sweep started, hunter returned, confirmation, gate entered)
  **and between long silent stretches of tool calls**, with the running tally on the header line:
  `step 5/9 · covered 23/47 · 3 HIT · 18 CLEAR · 2 BLOCKED`. Markers: `[ ]` queued · `[>]` running ·
  `[x]` done · `[!]` blocked · `[-]` N/A. Announce long or irreversible steps (boot, fuzz, first packet
  at a live host, submission) before starting them, flip a row to `[!]` the moment it blocks rather than
  saving it for the summary, and mirror the rows in TodoWrite so they're visible in the UI.
- **Make every action legible.** Each tool call carries a `description` written for the user — what it
  does and why, in active voice (`Read the model-init path for an unvalidated provider string`, not the
  raw `sed -n '100,200p' chat_models/base.py`). A column of unexplained shell is the most common way a
  working hunt looks broken. Say what each result changed about the hypothesis.
- **A confirmation interrupts the hunt.** As soon as a lead is CONFIRMED, stop routing new work and take
  that bug to a receipt: record the PoC while the instance is still up, novelty gate, **report-writer**
  writes it, clean-room verify, both auditors, `hunt validate-report`, deliver. Then reprint the board
  and resume. Batched write-ups are written from notes, and that is where stale line numbers and
  re-typed output come from. Add the lane's agents to the board as their own numbered rows.
- **Report layouts — two, and `github` is the default.** `github` = a private GHSA draft on the repo (or
  the huntr on-platform form, same body); `hackerone` = an H1 program submission. `hunt report <id>
  [--layout github|hackerone]` scaffolds the section checklist; **report-writer writes the report**, the
  scaffold is not the report.
  0. **`url`/`grey` only — scope gate, hard stop.** Fill `work/<slug>/scope.yml` from the program's
     published policy, then `hunt scope --file <f> --lint` and `--check` the exact origin. Record
     `scope_digest`, program and test window in the profile. Refuse to proceed on a missing,
     unlintable, or unattested (`authorized_by` empty) scope file.
  1. Recon → cache in `work/<slug>/profile.json`; on resume read that + `state/ledger.json` first.
  2. Prior art → exclusion map: `hunt dup <owner/repo> --query "<class>"`; if advisories exist, load
     `variant-analysis` to map what's already covered and steer AWAY from it (zero-days only).
  2b. **`url`/`grey` only — task `web-recon-hunter` first and alone** (`web-recon` skill): scope
     verification, crawl + render, JS bundle and sourcemap mining, OpenAPI/GraphQL discovery,
     multi-identity provisioning with a seeded owner marker, and the soft-404 / unknown-parameter /
     unauthenticated / owner **baselines**. Its `work/<slug>/web/endpoints.json` is the route table
     every other hunter reads instead of source. Hand its counts and baselines to all of them —
     without the counts nobody can state an enumeration tuple; without the baselines every probe is a
     false positive waiting to happen.
  3. `hunt scan work/<slug>/src` (static → merge → exploit_score → ranked `findings.json`). For a
     `url` target with recovered sourcemaps, run it over `work/<slug>/web/js/src` instead. Leads only —
     never a verdict.
  3b. **Have an instance available before routing** (so no hunter skips runtime for lack of one).
     `src`: launch once (`dynamic/run_target.py` or the first `hunt sweep`) and keep that instance up
     for the whole hunt; record `base_url`, identity credentials and the server-log path in
     `profile.json`. `url`/`grey`: scope cleared + baselines
     captured. If it cannot be booted, say so and treat every class as `BLOCKED (no runtime)` unless
     confirmed via the faithful-harness path in `dynamic-hunt` §3.
  4. Route ranked leads (and code the scanners flagged nothing on) to **authz-logic-hunter**,
     **injection-hunter**, **authn-crypto-hunter**, **client-side-hunter** — in parallel where
     independent. Cover **every applicable row of the coverage matrix** (`vuln-playbooks` § "Required
     coverage — the matrix"): ~55 classes in seven groups — A access control & identity · B injection
     & execution · C untrusted fetch & files · D client-side · E API & protocol · F infrastructure &
     config · G AI/LLM-native. Each row is tagged with the kinds it applies to and its owner. Each
     comes back `HIT` / `CLEAR` / `N/A` / `BLOCKED` with a reason **and the request that produced it**.
     Web, protocol and client-side playbooks live in `web-playbooks`.
  5. Confirm at runtime. `src`: `hunt sweep work/<slug>/src --authz <authz.json> --fuzz <ep>:<param>`
     (boots ONCE: probe + authz-differential + fuzz). `url`: `hunt web probe --url <base> --scope <f>`,
     `hunt authz --url <base> --scope <f> --config <authz.json>`, and the by-hand `curl` recipes in
     `web-playbooks`. Every request lands in `work/<slug>/web/transcript.jsonl` with a `T#####` id —
     those ids are the evidence anchor that replaces `file:line`. See `dynamic-hunt`.
  6. Novelty gate (`variant-analysis`) + `hunt dup` → only a genuine zero-day (not a variant/incomplete-
     fix) proceeds. Fires **the moment a lead confirms**, not at the end: **report-writer** writes the
     report in the chosen layout (default `github`), clean-room verifies it, runs **report-auditor** +
     **report-editor**, then `hunt validate-report <id>` for the receipt. Resume hunting after.
  7. `hunt ledger add/update` to track state.

Report back: the hunt summary, the target kind, the scope attestation for a live target, the **coverage
matrix table** (`HIT`/`CLEAR`/`N/A`/`BLOCKED` + reason, each depth-qualified — hops for `src`, the
enumeration tuple for `url` — and each with a `tested` column naming the request issued and the
response observed, or the transcript `T#####` range; an empty `tested` column is `BLOCKED (untested)`,
not `CLEAR`), each confirmed bug (finding_id, CWE, `file:line` or transcript ids, PoC
command, evidence path, CVSS vector, dedup verdict, report path), any **chains** assembled from
individually-low findings, and any UNCONFIRMED leads with the exact next test. Present nothing
unconfirmed as confirmed, and never launder a `BLOCKED` class into `CLEAR`.

If `$ARGUMENTS` is empty, run `.venv/Scripts/python.exe intel/repo_intel.py` to rank candidates and
recommend a target first.
