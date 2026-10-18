# House rules

The rules this pipeline runs on, and — for each — whether something *makes* you follow it or whether
it is on you. This file ships with the repository, so a clone gets the rules, not just the tooling.

Read this with `.claude/skills/guardrails/SKILL.md`, which holds the two rules that outrank
everything here (No Assumption, No Hallucination). This file is the index and the enforcement map.

## Why this file exists

Rules accumulated in an operator's private memory store, outside the repo. Clone the repo and you got
the hooks and the gates but none of the knowledge that shaped them — which programs reject which
finding classes, which form field truncates at 200 characters, which target has already been swept.
Anything durable belongs here or under `programs/`, not in a private store.

## Rule 0 — the memory store is read first and written last (HARD)

The store lives at **`memory/`** in the project root, indexed by `memory/MEMORY.md`. One fact per
file, one line per fact in the index. It is gitignored and must stay that way: it records unfixed,
unsubmitted findings, and this repository is public.

**Read before acting.** Before hunting a target, writing a report, naming a file, choosing a
disclosure channel, or claiming something is done, read `memory/MEMORY.md` and open the entries that
match. Recall precedes work; it is not a thing to do after being corrected. This session's hunt was
scoped correctly in its first minute because the store already knew that availability-only findings
are ineligible for this program — knowledge that had cost two closed reports to acquire.

**Write when something durable is established**, in the same session it is learned, not at the end of
a run when context is thin:

- a rule, convention or preference the operator states
- a correction — especially one where the previous belief was recorded and wrong
- a target verdict: what was swept, what was closed and why, what is still open
- an external program fact: intake channel, eligibility, form fields and limits
- a technique or trap that will cost time to rediscover

**Do not write** what the repository already records — code structure, git history, what a gate does.
A memory that restates the code rots the moment the code changes.

**Treat a recalled memory as a claim, not a fact.** It reflects what was true when written. If it
names a file, function, flag or version, verify that it still exists before relying on it. Memory
narrows the search; it never closes a question. This is No Assumption applied to your own notes.

**Ownership.** Only the `memory` agent writes `memory/`; only the `mistake` agent writes the mistake
log. Everyone else reads. The exception is structural maintenance of the store itself — migrating it,
repairing the index — which the main session may do, because it is not content.

### Index discipline

`MEMORY.md` is loaded every session, so its size is a running cost, and that cost creates pressure to
compact it. Compaction is where this index gets damaged. The rules that survive that pressure:

- **One line per memory, always.** A compaction pass once merged seven pairs of entries onto shared
  lines to save space. Entry count was preserved and nothing was lost, but the index stopped being
  scannable and stopped matching its own documented shape. If the index is too long, the answer is
  fewer memories or shorter hooks — never two entries on one line.
- **Every file has exactly one index line, and every index line resolves to a file.** Check both
  directions after any bulk edit: files on disk with no line, and lines pointing at no file.
- **Never put content in the index.** It is a pointer list. Detail lives in the topic file.

## When two hunters both return HIT

No hunter ever "gets" the report. Hunters produce leads and evidence; the main session writes every
report (Gap 4). So the question is never *which agent files it* — it is *how many reports there are*,
and *in what order*.

**First test: do both HITs end at the same root cause?** Not the same class, not the same file — the
same defective decision. If two routes reach one unguarded sink, that is **one** finding with two
routes, and the second route becomes another case in the same report.

A worked example from this pipeline: a DASH `RequestParam` element and a legacy `UrlQueryInfo`
descriptor are different schemes, parsed by different code paths, and both were separately
confirmed — but both terminate in the same query-building function with the same missing origin
check. One report, three PoC cases (attack, control, legacy). Filing two would have been a
self-inflicted duplicate and would have read as padding.

**If the root causes genuinely differ**, they are two findings: two ids, two impact-gate records, two
folders, two receipts. They are still processed **serially**, because the report lane is owned by the
main session and cannot be parallelised:

1. Run `hunt impact-gate` on **both** before opening any lane. A HIT that fails the gate never becomes
   a report, whichever hunter found it, and knowing that first can turn "two reports" into one.
2. Take the higher-scoring finding through the lane first. Finish it — gate receipt issued — before
   starting the second. Accumulating unsubmitted findings on one target is how they go stale, and on a
   target with a known internal-duplicate history the marginal finding is also the likeliest duplicate.
3. Keep the second finding's evidence while its instance is still up. It decays within the hour.

**If two hunters claim the same bug**, the one that proved it at runtime owns the evidence; the other
is corroboration, recorded in the ledger and not filed separately. Never two reports for one defect.

## Enforcement map

"Mechanical" means a hook, gate or CLI refuses to proceed. "On you" means nothing catches it — those
are the ones that have actually produced bad deliveries.

| Rule | Enforcement |
|---|---|
| Two hunters both HIT: same root cause = one report; different = two findings, processed serially by impact score | **On you** — nothing detects a split or duplicated root cause |
| `memory/MEMORY.md` is read before acting and written when something durable is learned | **On you** — Rule 0; nothing detects a skipped recall |
| The index keeps one line per memory, and every file has exactly one line | **On you** — verify both directions after any bulk edit |
| A report folder cannot be scaffolded before the impact gate passes | **Mechanical** — `hunt.py` `cmd_report` calls `impact_gate.cleared()` and exits non-zero |
| A finding below CVSS 4.0 does not get a report lane | **Mechanical** — `SEVERITY_FLOOR` in `reports/impact_gate.py` |
| Availability-only findings are refused for programs whose scope is confidentiality/integrity | **Mechanical** — `PROGRAMS_REQUIRING_C_OR_I` in `reports/impact_gate.py` |
| A report cannot be delivered without: report file, impact receipt, 2 recorded PoC runs, factual audit, editorial audit, quoted-output check, dup check, parseable CVSS | **Mechanical** — the eight checks in `reports/gate.py`, run by `hunt validate-report` |
| Every `.md` under `reports/` needs its own receipt or an explicit waiver | **Mechanical** — `tools/hooks/on_report_write.py` |
| Nothing is submitted without a receipt | **Mechanical** — `tools/hooks/pre_submit.py` |
| A session cannot end mid-delivery with an ungated report | **Mechanical** — `tools/hooks/pre_delivery_gate.py` on `Stop` |
| Output quoted in a report must appear in the recorded runlog | **Mechanical** — `check_quoted_output` in `reports/gate.py` |
| Cited `file:line` must be verified at the pinned tag, not from memory | **On you** — the factual auditor checks it, but only after the report is written |
| The title must name the product and stay within 10 words | **On you** — the editorial auditor judges it |
| No other advisory's CVE/GHSA id appears in delivered text | **On you** — the editorial auditor greps it |
| The destination program's tier/eligibility is resolved *before* hunting starts | **On you** — see Gap 2 |
| Dedup includes a per-file `git log` on the affected files, and reading the merged PR bodies | **On you** — see Gap 3 |
| The report lane is driven from the main session, not a subagent | **On you** — standing rule, see Gap 4 |

## Known gaps — where a rule can be walked around by accident

These are recorded because each has already cost something.

**Gap 1 — CLOSED.** A PoC can be extended (a third case added) while `runlog.txt` still holds the
previous run, and the report then quotes lines its own script never produced. That happened on a
delivery-ready report and was caught by hand, one step before the auditors; every existing gate
check passed on it.

Now enforced by `check_quoted_output` in `reports/gate.py`, registered in `CHECKS_COMMON` directly
after `PoC executed` (whose `ctx["runlog"]` it consumes). It extracts fenced blocks that look like
captured output — language-tagged fences such as ```js or ```xml are treated as source and skipped —
and fails delivery if any line is absent from every recorded run. Covered by seven cases in
`tests/test_report_gate.py`, including the exact stale-runlog regression.

**Gap 2 — the program eligibility check runs at report time, not at target-selection time.** The
impact gate correctly refuses an availability-only finding for a Google program, but only once a
finding exists. Hunting effort spent on an ineligible class is already spent by then. Resolve the
destination program's rules *before* the first hunter is tasked, and record them in `programs/`.

**Gap 3 — advisory surfaces and issue searches miss merged-but-unreleased fixes.** A fix that is
merged to `main` and not yet released is invisible to the advisory API, to OSV, and to an issue-title
search. Only `git log <tag>..origin/main -- <each affected file>` finds it. This has twice come
within hours of a wasted report lane. Release branches also complicate it: a repo that cherry-picks
fixes onto a release branch will show the fix commit as *not* an ancestor of the tag while its
content is present, so check content at the tag, never ancestry alone.

**Gap 4 — subagents die.** Long report-lane and hunter agents have been killed mid-run by provider
rate limits and API errors five times across targets. Nothing restarts them and nothing preserves
partial work.

The standing rule, decided after the fifth death: **the main session owns the report lane.** Writing
the report, verifying its quotes, running the PoC through the gate, and reading the gate output all
happen in the main session. Hunters remain subagents — they parallelise well, they are read-mostly,
and a dead hunter costs only its own coverage — but a dead writer costs a half-built delivery in a
folder that other rules then treat as real.

When a hunter dies, label its coverage `BLOCKED`, never `CLEAR`. A hunter that was killed did not
finish, and an unswept class is not a clean one.

**Gap 5 — the impact gate is wired to report *writing*, not to finding *confirmation*, so a session
that never opens a report never meets the bar.** On `anomalyco/opencode` (2026-10-02) two RCE vectors
were confirmed, written up in full at `work/<slug>/CYCLE1-HANDOFF.md`, and presented to the user with
CVSS, quotes and PoC markers — with no `reports/` file, no impact-gate decision and no audit. The Stop
hook stayed silent because it only watches `reports/*.md`. The session disclosed the missing checks
honestly and treated that disclosure as sufficient; it is not. **Naming a bypass while using it is
still using it.**

Two reasoning errors produced it, and both are worth recognising by name:

1. **"It can't be filed, so the pipeline doesn't apply."** The target's policy forbade the submission,
   so the gates looked like ceremony. But the gate protects the *claims*, not the *channel* — the
   impact bar and the audits decide whether a finding is real and worth anyone's attention at all.
   Skipping them because delivery looked blocked means grading your own finding, which is the one
   judgement `guardrails` says is never yours.
2. **"I disclosed the gap" standing in for "I closed the gap."** Honesty about an unmet check is
   mandatory and does not convert it into a met one.

The cost was exact: run belatedly, the impact gate returned **BLOCK — "No report lane. Do not write
this up"** (non-default configuration plus two further conditions ⇒ expected Infeasible). Running it
first, which costs one command, would have produced that verdict *before* the write-up was spent.

**Standing rule: `hunt impact-gate` runs when a lead CONFIRMS, before any write-up is produced in any
location.** Nothing findings-shaped — a report, a handoff, a findings file, or a chat summary carrying
CVSS or a PoC — is produced or presented before that decision exists on disk. A finding you believe
unfilable is not an exemption; it is the case where the bar matters most, because a claim to the user
is then the only output left. This stays honor-system: `tools/hooks/**`, `.claude/settings.json`,
`reports/gate.py` and `evidence/runlog.py` are deny-listed to agents by design, so no hook can be
added from a session. **A hook that notices findings-shaped documents outside `reports/` is the real
fix, and only the user can add it.**

## Rules with no mechanical backing that still bind

- **A class is `CLEAR` only if the guard was read *and* the attack was sent and rejected.** A class
  that was read but never exercised is `BLOCKED (untested)`. Silence from a scanner is not safety.
- **The impact gate runs at confirmation, not at write-up.** See Gap 5. No findings-shaped artifact —
  in `reports/`, in `work/`, or in a chat message — before the decision exists on disk. "It cannot be
  filed anyway" is not an exemption.
- **A document's location never changes which rules bind it.** `reports/`, `work/`, a heredoc, or
  prose typed straight to the user: if it carries findings, it is a disclosure and it is gated.
- **A primitive is not a finding.** Demonstrate the gadget, or say plainly that you did not.
- **Count preconditions.** Three independent ones puts a finding below every bar observed here.
- **Marginal gain must be shown, not argued.** State what the attacker already had without the
  defect, then prove the delta with a control run whose only difference is the defect itself.
- **Never claim a version is affected without evidence.** Runtime-tested and source-read are
  different claims; label which one you have.
- **The report file is the paste.** No internal ids, agent names, gate references, or local paths.

## Where things live

| | |
|---|---|
| `.claude/skills/` | how to hunt, write and audit — the method |
| `.claude/agents/` | the specialists and their scopes |
| `programs/` | destination programs: eligibility, intake, submission form fields and limits |
| `targets/` | per-target dossiers: what was swept, what was closed, what is still open |
| `reports/gate.py`, `reports/impact_gate.py` | the gates |
| `tools/hooks/` | the hooks that run them |

Never edit `.claude/settings.json`, `tools/hooks/**`, `reports/gate.py` or `evidence/runlog.py` to
get *past* a block. Strengthening them is welcome; routing around them is not.
