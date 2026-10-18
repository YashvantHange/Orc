---
name: report-craft
description: >
  Procedure for writing a submittable disclosure report from a confirmed finding + evidence bundle —
  layout choice (github by default, hackerone on request), agent-written prose, clean-room
  verification, the two audits, and the delivery gate. Load the moment a finding confirms.
---

# Report procedure

House style — required sections, the four quality rules, the Title rule, the root-cause graph, CVSS
anchors — lives in `report-standards`. This skill is the mechanical procedure; it does not repeat it.

**Start the moment the finding confirms, not at the end of the hunt.** The instance that proved the
bug is still up, the payload still fires, and the hunter can still answer a question — all of which
decay within the hour. The orchestrator suspends routing for the duration (`sec-orchestrator` § "A
confirmation interrupts the hunt") and shows this lane as its own numbered rows on the board.

**The main session owns this lane.** Do not delegate the writing, the quote verification, the gated
PoC runs, or the gate reading to a subagent. Long report-lane agents have been killed mid-run by
provider rate limits and API errors five times across targets; a dead writer leaves a half-built
folder that every other rule then treats as a real delivery. Hunters stay delegated — a dead hunter
costs only its own coverage, and that coverage gets labelled `BLOCKED`. The two cold audits are the
one exception, and must stay delegated: their value is that they read the report without having seen
it written. See `RULES.md` Gap 4.

**Nothing is audited before it is written.** The lane is strictly serial: score → write the whole
report → self-edit → clean-room run → *then* the auditors. An auditor tasked on a partial draft files
defects against sections that were about to be written anyway, and its verdict binds to bytes that are
already stale — you pay for a full cold read and get nothing. No auditor is tasked until the file on
disk is the report you would submit.

**Time budget for the whole lane.** This is the most expensive part of the pipeline, so it runs to a
budget, not to exhaustion:

| Stage | Budget |
|---|---|
| Draft | one pass, written straight into the file — no outline, no section-by-section revisit |
| Report length | ~900 words / 8 KB. Longer is not more thorough; it is two auditors re-reading padding |
| Self-edit | one read of the finished draft, all rules at once |
| Clean-room run | one recorded execution (the auditor records the second) |
| Audit rounds | **2 is the ceiling** — round 1, one batch of fixes, round 2. Escalate rather than open a third |

## 0. Security-impact gate
Before anything else, run the Security-impact gate in `report-standards`: a named attacker, a trust
boundary actually crossed, and a C/I/A property that breaks. A performance regression, a self-DoS, a
crash only the operator can reach, or a hardening suggestion is `OUT_OF_SCOPE` — one line in the
ledger and no report. Cheaper here than at the auditor, and far cheaper than at the maintainer.

Then run question 5, the **impact bar** — is this worth *filing*, which is a different question from
whether it is a vulnerability. Record the answers; nothing downstream will open without them:

```
hunt impact-gate <id> --program <google-oss-vrp|github|hackerone|huntr> --vector '<CVSS:3.1/...>'   --attacker '...' --boundary '...' --impact '...' --marginal-gain '...' --gadget '...'   --precondition '...' --precondition '...'
```

It refuses below CVSS 4.0, refuses a primitive with no demonstrated gadget chain, and refuses three or
more independent preconditions — the three shapes that got real, fully-proven reports closed as not
severe enough to track. `hunt report` and `hunt validate-report` both require its PASS, so run it
before you write, not after. A BLOCK is not a setback: say so to the user, name the blocker, and offer
the upstream GitHub issue as the ceiling.

## 1. Score CVSS
`hunt cvss <vector>` (or `reports/cvss.py`). You pick the metrics from what you **proved** — anchors
and metric guidance in `report-standards`. Record the **vector string**, not just the number.

## 2. Pick the layout, then write the report

**`github` is the default** — a private GHSA draft on the repo (the huntr on-platform form takes the
same body). Use `hackerone` only when the destination is an H1 program. Full section sets:
`report-standards` § Layouts.

```
hunt report <finding_id>                      # github  (default)
hunt report <finding_id> --layout hackerone   # HackerOne
```

That drops `reports/<slug>-<cwe>-<finding_id>.md` with the ledger facts (repo, commit, cwe, cvss,
file:line, evidence path) in a header comment. **It is a section checklist, not the report** — filling
placeholders in order is how a draft ends up with real facts in a generated shape. Write each section
yourself from `evidence.json`, `root_cause.md`, the code re-read at the pinned commit, and the
recorded runlog. Delete every scaffold line you did not fill.

- **Title**: `<the vulnerability> in <where>` — ≤10 words, one clause. **Write it last**, from your
  own Impact and CWE with the source file closed; a title drafted next to the code names the code.
  The first half is the security failure (ReDoS, path traversal, missing authorization), never the
  mechanism: "Quadratic image regex in the Markdown parser" and "Uncaught exception in the graph
  legend unmounts the WebUI" are refactor-PR and bug-tracker titles, not vulnerabilities. Verbs about
  program state — *shadows*, *merges*, *unmounts*, *halts writes* — are mechanism too. Outcome
  vocabulary, mechanism blocklist, swap test and worked rewrites: `report-standards`.
- **PoC**: the copy-pasteable benign command + observed output (from `poc-craft`).
- **Evidence**: reference the bundle; paste the key request/response + stack-trace excerpt, redacted.
- **Root cause**: the graph from `evidence.json`/`root_cause.md` — the specific flawed logic.
- **Remediation**: a concrete diff or precise instruction. Maintainers merge reports that come with
  the fix.
- **Duplicate-check note**: what `hunt dup <owner/repo> --query "..."` searched and found, plus the
  novelty verdict (`variant-analysis`). A variant is out of scope — don't write it up.

## 3. Self-edit — one pass, not four

Read the full draft once as the target's maintainer and fix everything in the same pass: the four
production-quality rules (`report-standards`) *and* the voice pass over the prose alone. Sweeping the
document once per rule costs four reads for one result.

What the voice pass looks for — third-person or passive self-reference where first person belongs;
every sentence the same length; bolded-lead-in bullets that are really a paragraph; antithesis and
signposting; rule-of-three lists; self-summarizing section endings; em dashes on every line;
consultant adjectives; hedge stacks; any unfilled `<...>`/TODO/scaffold comment. Softening a
generated-sounding paragraph doesn't work — retype it from scratch in your own words.

## 4. Clean-room verification *is* the recorded run

Make a fresh empty directory. Copy the report's own fenced setup and PoC blocks out of the draft and
run **exactly those, in that order**, with nothing from the hunt's working tree — no pre-installed
package, no leftover environment, no command you know but didn't write down. Record that execution:

```
mkdir -p work/_cleanroom/<id> && cd work/_cleanroom/<id>
# the report's blocks, verbatim, top to bottom
hunt poc-run <target> <id> --cmd "<the exact command the report tells the maintainer to run>" \
    --cwd work/_cleanroom/<id> --python <the venv the PoC uses> \
    --volatile '<uuid|port|timestamp regex>'
```

**Once.** The gate wants two recorded runs, and the second one is `report-auditor`'s cold clean-room
run (§5) — it executes the same report blocks in its own fresh directory and records it the same way.
Two runs by two agents in two directories rule out a fluke better than the same agent running the same
thing twice in a row in the same directory, and it costs one execution instead of two. Do **not**
record a second run yourself to "get to two"; that is the duplication this ordering removes.

One activity, two artifacts: `work/<slug>/evidence/<id>/runlog.json` (what every output block, pinned
version and commit sha is checked against) and proof that the report's own instructions work. Declare
volatile values **before** you compare, so the mask is part of the record rather than something
widened afterwards to make a mismatch go away.

**Runs go stale when the PoC changes.** If a round of audit fixes edits any setup or PoC block, both
recorded runs describe commands the report no longer gives. Re-record yours in a fresh clean-room dir
and say so, so the auditor re-runs too. Editing only prose leaves the runs valid.

What this catches and nothing else does: an install step that only worked because the package was
already in your venv; an env var exported in another terminal; a port assumed free; a `cd` that never
happened; a helper file the script imports that the report never gives the reader; a payload edited
after the recorded run so the pasted output no longer matches; a PoC that shows the endpoint
responding rather than the bug firing.

Fix the report, not your notes. If it doesn't reproduce, the report is wrong — don't hand it to the
auditors with an explanation attached. `report-auditor` repeats this cold and will compare.

Live targets have no local install or local process. The anchor is the transcript instead: re-issue
the report's exact requests against the authorized host inside the test window and confirm the
responses still match the cited `T#####` ids — a live target can be patched between your test and the
maintainer's read.

## 4b. Pre-flight — run the gate BEFORE you spend an audit (hard rule)

An audit round is the most expensive thing in this pipeline: two cold reads of the whole report, and
the factual one re-executes the PoC. The gate is nearly free. **Run `hunt validate-report <id>` first
and fix every mechanical failure it names, before either auditor is dispatched.** A mechanical failure
does not care what the auditors conclude — it will block the receipt anyway, and any edit you make to
clear it voids their verdicts and forces the whole round again.

The failures that are pure waste when found *after* an audit, all of them seen in real runs:

- `CVSS` — the report vector and the ledger vector disagree. Fix with `hunt ledger update --id <id>
  --set cvss="<vector>"`. Keep them equal whenever you change severity, in the report, the ledger and
  `submission-fields/`, in the same edit.
- `PoC executed` — a run recorded against a **dirty target tree**. Check `git status --porcelain` in
  the target and clear it *before* recording anything. Probe files, stray notes and scratch tests
  belong outside the clone.
- Placeholder and prose hints printed under the gate result. They are a regex guessing, not a verdict,
  but `<angle-bracket>` phrasing in your own sentences reads as an unfilled template — reword it.
- A stale `dup` verdict, or a missing `submission-fields/` file.

Then freeze and audit **once**.

**Never re-record a PoC run to make a gate complaint disappear.** The runlog is append-only and
tamper-evident: hand-editing it to drop a bad run changes the stored stdout, every hash stops
matching, and the gate reports `the runlog was edited after the run` — a worse state than the one you
started in. Re-record only when the PoC or the target actually changed. Two clean runs by two agents
in two directories is the target; **seven runs of one PoC is a real number from a real session** and
every one past the second bought nothing.

**If the runlog is poisoned, regenerate it — never hand-edit it.** A run recorded against a dirty
target tree is stamped `tree_dirty` permanently, and the gate then refuses the receipt because the
pinned commit does not describe what ran. This is unrecoverable by editing: the runlog is
tamper-evident, so removing the bad entry changes the stored stdout, every hash stops matching, and you
trade one honest complaint for `the runlog was edited after the run`, which is worse. That has been
tried on this pipeline; it failed exactly that way and had to be restored from a copy.

Prevention is the real fix, and it is cheap: `git status --porcelain` in the target must be empty
*before* any `poc-run`, and every probe, scratch test and note lives outside the clone. The dirt that
caused this was an auditing agent's own test file, not the product's.

When it has already happened, the only sanctioned recovery is to regenerate rather than edit, under
all four of these conditions — if you cannot meet them, stop and tell the user rather than proceeding:

1. The contamination was **our own tooling** (a probe, a scratch file, a stray artifact), not a change
   to the product under test. If the target itself was modified, the runs are genuinely invalid and the
   finding needs re-proving, not re-recording.
2. The original runlog is **preserved verbatim** outside the evidence directory before anything is
   removed, so the full history stays inspectable.
3. The tree is clean, and the PoC is re-recorded from scratch by the normal path — two runs, two
   agents, two directories. You are producing new honest records, not rewriting old ones.
4. The regeneration is **disclosed** in the ledger notes with the reason and the path to the archive.

Regenerating a runlog to hide a failed or non-reproducing run is falsification, not recovery. The test
is whether the new records describe something a stranger can reproduce from the pinned commit — if they
do, the evidence is stronger than before; if they do not, you are covering something up.

**Keep the PoC cheap to execute.** It is run at least twice, by different agents, in different
directories. A PoC that deletes and reinstalls a large dependency tree on every invocation turns each
verification into minutes of network I/O. Cache the expensive setup and reuse it when it is already
present; keep the destructive reset behind a flag. **Run artifacts never ship in the packet** — an
installed `node_modules`, a venv, a build output. They bloat the attachment by orders of magnitude,
and vendored third-party files inside them carry strings that trip the destination's content
classifier. Ship the scripts that regenerate them.

## 5. Freeze the bytes, then send it to both auditors

**The report is finished before this step starts** — drafted, self-edited, clean-room verified, and
sitting on disk in the shape you would submit. Auditing a draft you still intend to change is the most
expensive mistake available in this pipeline: two cold reads bound to bytes you are about to void.

Run **`report-auditor`** (cold factual audit) and **`report-editor`** (presentation and voice) — **in
one message, so they run in parallel**; serially they cost twice the wall-clock for the same result.
Give each only the report path and the target — never your reasoning or the hunt transcript. They write
`state/audit/<id>.factual.json` and `state/audit/<id>.editorial.json`; both must return `PASS`, and
each verdict is bound to the report's sha256, so **any edit voids both**.

That binding is what makes the loop expensive — two full cold reads per round — so run it deliberately:

```
sha256 the report  →  task BOTH auditors in one message, on those bytes  →  no edits until both return
                   →  one batch of fixes  →  re-hash  →  re-run both (delta)  →  gate
```

- **Never edit while an auditor is running.** An edit mid-flight voids the one that already finished
  and you pay for it twice. This has happened: two audits bound to two different hashes, neither
  matching the report on disk.
- **One batch of fixes per round** — all criticals and majors plus the minors you agree with, in a
  single edit pass. Not one edit per defect.
- **Minors never force a round.** They don't block the gate, and each auditor files at most three. A
  round that returns only minors is a pass — take it.
- **Re-runs are delta audits.** Each auditor reads its own previous verdict and re-checks only the
  changed text, the defects it filed, and what it left unchecked, carrying the rest forward. Never ask
  for a fresh full audit "to be safe".
- **Fix the finding, not the flag.** If a quoted snippet doesn't match the file, correct the quote —
  don't delete the citation.
- **Push back when they're wrong.** They're agents and can misread. Say why in your reply and re-run
  rather than making the report worse to satisfy a bad defect.
- **If an auditor returns nothing** — ran long, stopped mid-pass — it must still have written its JSON
  with `stopped_at` and an `unchecked` list; the next run resumes from there. If the file is genuinely
  absent, say so plainly rather than re-tasking blindly.
- **Keep the report short.** Every round re-reads the whole thing, twice. 16 KB of padding costs
  double what 8 KB of the same facts costs, every round, on both agents.

After **two** rounds without a clean pass, stop and escalate to the human with the outstanding list.
Grinding on a report that won't converge usually means the finding is weaker than it looked — and each
round is two full cold reads, which is the single biggest cost in the lane.

## 6. Gate — this is what issues the receipt
`hunt validate-report <finding_id>` verifies the chain: a self-consistent runlog with ≥2 runs, both
audits PASS and bound to the current bytes, a real dup artifact under 14 days old, CVSS arithmetic
that matches. Live/grey also re-verify transcript hashes and the scope digest.

Pass ⇒ `state/gate/<id>.json` is written and the report may be delivered. Fail ⇒ no receipt, and the
Stop hook refuses to let the turn end while you hold an ungated report. Fix what it names.

On failure it also prints the old regex scan under *hints for report-editor*. Those are hints — a
regex guessing at prose. Look where they point; do not obey them.

## 7. Submit + record
`github` layout → a private GHSA via the repo's Security tab / the channel `SECURITY.md` names; on
huntr, submit the same body on-platform (never email). `hackerone` → the program's submission form.
See `docs/disclosure.md`.

**Claude does not submit.** The finished deliverable is a folder the user files from — report `.md`,
`HOW-TO-FILE.md`, a runnable `poc/`, and `submission-fields/` holding one paste-ready value per form
field. Hand over the folder path and the field mapping so filing is mechanical.

**Record the submission the moment it happens** — nothing in the pipeline writes this back on its own,
and a stale status is how a finding gets re-worked or re-filed months later:

```
hunt ledger update --id <id> --set status=SUBMITTED submitted_at=<YYYY-MM-DD>     submitted_to="<program>" submitted_sha256=<the exact bytes filed>     notes="<verification state at submission, in full>"
```

Record the **submitted sha256**, not just the path — packets get edited afterwards, and without the
hash nobody can tell later what was actually filed. If a report id or tracking URL comes back, add it.

### When something is already filed and then found wrong

This happens: a report goes out before an audit finishes, or a later pass finds a defect. Handle it
openly rather than quietly.

- **Do not resubmit.** A second report for the same defect wastes triage time and reads as noise.
  Add a correction as a comment on the existing report.
- **Correct it proactively, even when it lowers your severity.** A researcher who writes "my original
  impact claim overstated this; here is what I actually demonstrated" is trusted on everything else
  they file. One discovered by the triager instead is not.
- **Say what changed and what still stands.** Name the claim being withdrawn, the evidence that
  replaced it, and which parts of the finding are unaffected.
- **Record it in the ledger** against the same id, with the corrected state.
- If a fix landed publicly between your submission and triage, say so — it is better coming from you.

The same applies to a report filed without a gate receipt: note in the ledger exactly which checks did
and did not run on the submitted bytes, so a later session can tell what was verified from what was
merely intended.

Tone: precise, factual, collaborative — you're helping the maintainer fix a real problem.
