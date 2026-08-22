---
name: report-standards
description: >
  The house style for a submittable report: required sections, the root-cause graph, CVSS 3.1
  anchors, and the completeness criteria that `hunt validate-report` enforces. Consult when writing
  or reviewing a disclosure. One source of truth for report quality.
---

# Report standards

Style and content live here. The **procedure** — poc-run, clean-room, the audit loop, the gate
mechanics — lives in `report-craft`; this skill does not repeat it.

## Production-quality bar (non-negotiable — governs every field)
A report is production-quality when a senior engineer on the target project reads it and thinks *"a
competent peer found this,"* not *"a model generated this."* Every disclosure — **Summary, Details/
Evidence, PoC** — must clear five rules. `report-editor` judges 3-4 by reading the draft;
`report-auditor` judges 1-2 and 5. You write to them in the first place.

**1. Verifiable — every claim traces to a fact.** No sentence asserts behavior you did not read or
observe. Each technical claim points to a `file:line`, a captured request/response, a stack frame, or
an `evidence.json` hash. If you can't cite it, cut it or go prove it. Never invent a version, line
number, or function name.

**2. Honest — what you proved, not what you hope.** Label the confidence of every load-bearing claim:
**runtime-confirmed** (PoC fired), **code-confirmed** (read the bytes, not executed), or
**theoretical** — never blur them (label a secondary sink you reasoned about but never fired). Don't
inflate: pick CVSS metrics from what you demonstrated, report the conservative base, note any
escalation separately for the maintainer's judgement (a `C:L/I:L` base + a noted token-theft escalation
is the pattern). Scope the version range to what you actually tested; if a step is assumed, write
"assumed."

**3. No padding — every sentence earns its place.** Each section adds information the maintainer needs
to triage or fix. Nothing is restated across sections; no line exists to sound thorough. Cut
throat-clearing intros, summarizing conclusions, and anything deletable without losing a fact. A tight
one-page report beats three padded pages.

**4. Human-written — the reporter typed this, and it reads that way.** Not "polished until the tells
are gone" — actually written the way a person writes.

*Write like this:* first person, past tense, about what you did ("I hit the endpoint with no token and
got the workspace back", "I tested 1.10.2; I didn't check 1.9"); contractions are fine. Uneven rhythm —
short blunt sentences next to longer ones; uniform mid-length sentences are the loudest tell there is.
Say the uncertain thing straight ("I'm not sure the Docker default is affected — I only tested the pip
install"), which reads more human than any amount of careful hedging. One voice everywhere: a crisp
Summary followed by a formal, abstract Impact reads as two authors, i.e. as generated. Prose where
prose fits — bullets are for genuinely parallel items (versions, steps, params), and a paragraph
chopped into bullets with bolded lead-ins is a formatting tic, not structure.

*Never:* filler openers/closers ("In today's landscape", "It is worth noting that", "In conclusion",
"Overall", "This report details"); consultant adjectives (robust, seamless, powerful, comprehensive,
crucial, significantly, plethora, delve, leverage, utilize — write "use", facilitate); hedge stacks
("may potentially possibly"); antithesis scaffolding ("This isn't just X, it's Y", "not only… but
also") and over-signposting (Firstly/Secondly, Additionally/Furthermore/Moreover); rule-of-three
padding; a section that ends by summarizing itself, a Summary that restates the title, the same fact
in two sections; em dashes on every other line (about one per paragraph — a period usually works),
decorative emoji, headings the template didn't ask for; `we`/`the researcher`/`this report`/"As an
AI"; unfilled placeholders (`<...>`, TODO, Lorem), stray scaffold comments, or a wrong
finding-id/version left in from the template.

**Expert voice:** terse, technical, concrete — numbers, versions, exact identifiers, verbs over
adjectives. One precise sentence beats a hedged paragraph. Read the draft as the maintainer; any line
you would not have typed yourself gets rewritten or deleted. The Summary especially: plain sentences a
tired engineer types at the end of the day, not a generated abstract.

**5. Owner-verifiable PoC — the maintainer reproduces it from the report alone.** Not a sketch or a
description of what *would* happen; a complete, self-contained reproduction they can paste and run.
- **Full setup, every step:** exact clone/checkout (pinned commit), install, and launch commands, in
  order, with the exact model/config/flags. No "install it and run" hand-waving.
- **The whole script, inline, with all data.** The trigger (curl / `.py` / request body) in full with
  concrete values — the actual token id, path, header, payload — never `<placeholder>` or "a crafted
  X". If it's a script, the entire runnable script is in the report.
- **Expected vs observed, verbatim.** The real observed result (error text, status code, leaked bytes,
  stack frame) and the safe behavior it should have shown. Real output, not a paraphrase.
- **A path the owner can actually run.** If the true impact needs special hardware (GPU) or state,
  also give a deterministic reproduction that doesn't — a unit-level driver of the exact sink, or a
  CPU fallback exercising the same missing check — and keep the full-impact repro as a second part.
  (A CPU Part A + GPU Part B split is the pattern.)

Minimal in scope (the smallest input that triggers it), complete in reproduction (nothing the reader
has to invent).

## Security-impact gate (is this a vulnerability at all?)
Runs **before** the novelty gate, because a bug that isn't a security bug never needs a dedup check.
We hunt vulnerabilities. A crash, a slow path, a wrong result, a missing validation that only ever
inconveniences the operator — those are bugs the project's issue tracker wants, and filing them as
security reports burns the program's patience and your signal. Three questions, all three `yes`:

1. **Is there an attacker?** Name a concrete party who wants this to happen and who does *not* already
   have the outcome by legitimate means. "An authenticated user" counts only when the outcome exceeds
   what that role is granted.
2. **Is a trust boundary crossed?** The input is attacker-controlled and arrives from across a
   boundary the product defends — unauthenticated → authenticated, user → other user, tenant →
   tenant, low-priv → admin, untrusted document/model/plugin → server. If the "attacker" is the
   operator acting on their own instance, there is no boundary and no finding.
3. **Which security property breaks — C, I, or A?** State it as an outcome the maintainer would
   accept: data read they shouldn't read, state changed they shouldn't change, service denied to
   *other* users. It must survive the CVSS derivation: a vector that comes out `C:N/I:N/A:N` means
   there was no impact to score.

Not findings, however real the bug: a performance regression with no attacker-controlled trigger;
self-DoS (the caller only harms their own request or their own instance); a crash reachable only by
someone who could already shut the service down; missing hardening or a defense-in-depth suggestion
with no demonstrated impact; a config the operator explicitly opted into; a feature working as
documented that you'd have designed differently. Record these as `OUT_OF_SCOPE` with a one-line reason
and move on — do not dress them up with a CVSS vector.

Availability findings get one extra question, because that is where feature bugs disguise themselves:
**does one attacker request degrade the service for everybody else, without privileges the attacker
shouldn't have?** A slow endpoint that only slows its own caller is a performance issue. An
unauthenticated request that pins the event loop for every user is a vulnerability.

## Novelty requirement (zero-day only — gates whether a finding is reportable at all)
Two hard exclusions:
- **Not covered by any published advisory.** No CVE / GHSA / huntr entry for the product describes
  this vulnerability (same class **and** same root cause / code path). Prove it with `hunt dup` before
  writing a line.
- **Not an incomplete-fix / patch-bypass / variant of a published fix.** If the finding's identity is
  *"the fix for CVE-X is incomplete / bypassable,"* or it's the same bug resurfacing in a sibling
  location the patch didn't reach, it is **out of scope** — ledger status `OUT_OF_SCOPE`, drop it. Not
  a finding, no matter how exploitable.

**Litmus:** would the maintainer read this as *a new bug*, or as *"you didn't finish fixing CVE-X"*?
Only the former ships. Use `variant-analysis` as the **exclusion map**, not a bug generator: study the
product's advisories to know precisely what's already covered so you can prove your candidate falls
outside all of it. A fix may point you where to look, but the reported bug must stand on its own, and
the report body stays about the current code (don't anchor it to a prior CVE).

## Title rule (short, plain, one idea — and it must name a vulnerability)
The one line a triager reads before deciding whether to open the report. **10 words or fewer** (12 is
the hard ceiling), saying *what security thing breaks and where*.

Shape: **`<the vulnerability> in <where>`**. The first half is the attacker-visible security failure —
the bug class as a security person names it (ReDoS, path traversal, SSRF, missing authorization,
stored XSS, unauthenticated remote crash). The second half is the component, named the way the
maintainer names it: the route, the function, the file.

### Derive the title, don't summarize the code
This is the step that keeps going wrong. A title written *while looking at the diff* comes out naming
the code property you just stared at — the regex's complexity, the missing ceiling, the uncaught
exception — because that is what is in front of you. Write the title **last**, from your own CWE and
Impact fields, with the source file closed:

1. Read your **Impact** section's first sentence. It already says what an attacker achieves.
2. Take the outcome noun out of it — the thing that breaks for the victim (see the vocabulary below).
   That is the title's first half. Your **CWE** name is the cross-check: if the CWE says
   "Uncontrolled Resource Consumption" and the title has no denial-of-service word in it, the title is
   describing something other than the bug you filed.
3. The second half is `in <component>` — the route, function, or file the maintainer would grep for.
4. Only then, if words remain under the ceiling, add the mechanism as the *route* to the outcome
   (`via decompression bomb`, `via `next``). Mechanism is never the head noun.

### The outcome vocabulary (the title must contain one)
The security failure has to be a word a triager routes on. One of these — or an unmistakable plain
English equivalent — must appear in the title:

> remote code execution · command injection · SQL injection · path traversal · arbitrary file read ·
> arbitrary file write · SSRF · XSS (stored / reflected / DOM) · CSRF · deserialization ·
> template injection · prototype pollution · open redirect · authentication bypass ·
> authorization bypass · missing authorization · privilege escalation · IDOR · mass assignment ·
> session fixation · secret / token / credential leak · information disclosure · account takeover ·
> denial of service (ReDoS, memory-exhaustion DoS, crash, hang, unrecoverable state)

Plain equivalents count and are often better: *hangs the server*, *crashes the worker*, *leaks the API
token*, *lets any user read another tenant's data*, *takes over the daemon channel*. What does **not**
count is a verb whose object is code state rather than a victim: *shadows*, *merges*, *unmounts*,
*halts writes*, *scans quadratically*.

### The mechanism blocklist (head-noun position)
If the title's first half is built on one of these and no outcome word from the vocabulary appears
anywhere in the title, the title fails — no judgement call, rewrite it:

> quadratic · exponential · unbounded · unvalidated · unescaped · unsanitized · uncaught · unhandled ·
> missing check / missing ceiling / missing validation · improper · incorrect · static · regex · loop ·
> allocation · merge · parse · shadowing · race (alone) · null deref

These are all fine *after* the outcome word, as the `via <mechanism>` tail.

**Swap test** (the backstop for anything the lists miss): could this exact title sit on a refactor or
performance PR without anyone blinking? Then it fails. "Quadratic scanning in `PIIMiddleware` input
detectors" is a perf-PR title. "Uncaught exception in the graph legend unmounts the WebUI" is a bug
report. Neither reads as a vulnerability, so neither gets triaged as one.

- One clause. No colon-prefixed framing, no parenthetical qualifiers, no chained "allows X via Y
  leading to Z". If you need "and", pick the primary title.
- Plain words over formal taxonomy: "infinite loop hangs the server", "missing permission check",
  "path traversal" beat "Improper Neutralization of Special Elements". The CWE field carries the
  formal name — but plain does **not** mean dropping the security noun. "Regex denial of service" is
  plain; "quadratic regex" is a mechanism.
- No CVE/GHSA ids, no version numbers, no severity words, no product name if the report is filed
  against that product.
- Backticks only for real identifiers (`get_message_list`, `PUT /api/v1/executions/:id`).
- Sentence case, no trailing period.

| Rejected (each of these shipped) | Title | Why |
|---|---|---|
| Stored XSS in LightRAG WebUI chat rendering allows JavaScript execution in a viewer's browser via ingested content | Stored XSS in the WebUI chat view | too long |
| Mass Assignment in Execution Update Endpoint (`PUT /api/v1/executions/:id`) allows cross-workspace execution injection and protected-field tampering | Mass assignment in `PUT /api/v1/executions/:id` | too long |
| Unbounded loop in `get_message_list` lets any authenticated user permanently take down the server | Infinite loop in `get_message_list` hangs the server | too long |
| Quadratic image regex in the native Markdown parser | Regex denial of service in the Markdown image parser | mechanism head noun ("quadratic", "regex"), no outcome word |
| Quadratic scanning in `PIIMiddleware` input detectors | Regex denial of service in the `PIIMiddleware` PII detectors | mechanism ("quadratic", "scanning"), no outcome word |
| Missing size ceiling on `/api/documents/upload` | Memory-exhaustion DoS via decompression bomb in document upload | mechanism ("missing ceiling"), no outcome word |
| `next_url` passed to the template unescaped | Reflected XSS in `/hub/accept-share` via `next` | mechanism ("unescaped"), no outcome word |
| Uncaught exception in the graph legend unmounts the WebUI | Denial of service in the WebUI graph view via a crafted entity name | mechanism ("uncaught exception"); "unmounts" is code state, not victim impact |
| Unvalidated `updated_data` merge in `/graph/entity/edit` halts graph writes | Persistent denial of service in `/graph/entity/edit` | mechanism ("unvalidated", "merge"); two clauses |
| Static webhook paths shadow another project's dynamic routes | Cross-project webhook hijacking via static path shadowing | "shadow" is code behaviour; no outcome word until the rewrite |

Everything the title drops — attacker position, blast radius, precondition — belongs in Summary and
Impact, which is where a triager looks next. The report **filename** keeps its `<repo>-<CWE>-<id>`
scaffold form; this rule is about the H1 and the submission subject line.

## Required content (the layout decides the headings; this is what must be in them)
Title · Affected repo+versions/commit · CWE · CVSS 3.1 vector+score · Summary · Affected component
(`file:line`) · PoC (minimal, benign, **owner-verifiable** per rule 5) · Evidence (bundle ref + key
req/resp + stack trace, secrets redacted) · Impact (who, blast radius, realistic attacker) · **Root
cause** · Remediation (concrete diff / precise instruction) · Duplicate-check note · Disclosure
timeline · Credit.

**Quote, don't just cite.** Every `file:line` the argument leans on gets its actual code shown inline
in a short fenced snippet, so the reader understands the claim without opening the file. A bare line
reference is not enough for a load-bearing step.

## Root-cause graph (make the "why" mechanical, not a vibe)
State the causal chain, not one isolated line:

```
request/source  →  route/endpoint  →  middleware  →  decorator/guard  →  the missing/wrong check
                →  framework behavior that enables it  →  sink (what actually goes wrong)
```

Example: `POST /api/mcp (auth_type=none)` → `verify_auth() dependency` →
`branch: if auth_type=='none': return SYSTEM_USER` → framework trusts the returned principal → tools
execute as **superuser**. Store it in the bundle (`root_cause.md`, hashed into `evidence.json`) and
paste it into the report's Root-cause section. It also tells you where the patch goes.

## CVSS 3.1 — compute, don't eyeball
Run `hunt cvss <vector>` (or `reports/cvss.py`) for the number; you pick the metrics from what you
**proved**. AV:N for remote HTTP. AC:L unless a race or precise timing is needed. PR: N (unauth) / L
(any logged-in user) / H (admin). UI:R only if a victim must load a page. S:C when the bug crosses a
trust/authority boundary (SSRF→metadata, sandbox escape, cross-tenant). Impact from what you
demonstrated. Anchors: unauth RCE ≈ 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`; IDOR read (normal user)
≈ 6.5 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`; reflected XSS ≈ 6.1
`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`; JWT alg:none bypass ≈ 9.8. Always write the **vector string**.

## Layouts — two, and `github` is the default

Pick by destination, fill the whole set, and **declare which layout you used**. `report-editor` checks
the set you declared, so a mismatch blocks.

| Layout | Use it when | Template | CLI |
|---|---|---|---|
| **`github`** — **the default** | Publishing to the project: a private **GitHub Security Advisory** from the repo's Security tab, or `SECURITY.md`'s stated private channel. The **huntr** on-platform form takes the same body, so huntr uses this layout too. | `templates/report-github.md` | `hunt report <id>` |
| `hackerone` | The destination is a HackerOne program | `templates/report-hackerone.md` | `hunt report <id> --layout hackerone` |

**`github`** — structured advisory fields first, then one delimited description block the submitter
pastes whole: Affected products (**Ecosystem · Package name · Affected versions · Patched versions** —
every row filled, no exceptions; a blank row is what leaves an advisory unreviewed) · Severity (vector
+ score) · Weakness (CWE) · Title · Summary · Details (code **quoted**, root-cause chain) · Proof of
Concept (observed / expected / negative control) · Impact · Suggested fix · Not tested · Duplicate
check · Credit. Live/grey add `### Transcript`. No scaffold comment survives inside the paste region.

**`hackerone`** — platform fields (asset, weakness, severity, program, scope authorization, test
window, tested-from) · Summary · **Steps To Reproduce** · Impact · Supporting Material / References ·
Testing conduct / safe harbour · Not tested / scope-blocked · Duplicate check · Credit. The weight
sits in Steps To Reproduce: H1 triage reproduces from that text alone, so a placeholder or skipped
prerequisite there is a blocking defect, not a nit.

If both destinations are in play, write `github` first and re-cut it — the facts are identical, so the
second is a formatting pass, not a second investigation.

A section that exists but says nothing counts as missing. So does a Root cause (or Details) that
restates the Summary.

**The template is a section checklist, not the report.** `hunt report` gives you the set of sections a
complete disclosure carries so none gets lost; it does not give you a voice or an argument. Filling
placeholders in order produces a document with real facts and a generated shape, which is exactly what
rule 4 and `report-editor` exist to stop.

## Live-website targets (kind `url` / `grey`)

A black-box report has no commit and no `file:line`, so the anchors move — the standard does not
soften.

**`file:line` → the transcript.** Every request the pipeline sent is in
`work/<slug>/web/transcript.jsonl` with a stable `T#####` id and a sha256 of the response body. Those
ids are what a load-bearing claim cites, and "quote, don't just cite" applies identically: paste the
actual request and response inline. An id whose hash doesn't match the bundle is a failed report, the
same way a stale line number is.

**Extra required fields**, in the metadata table:

| Field | Value |
|-------|-------|
| **Target** | the exact origin tested |
| **Program** | name — program URL |
| **Scope authorization** | `scope.yml` sha256, and the date the policy was read |
| **Test window** | start → end; all cited traffic falls inside it |
| **Tested from** | source IP or a description — many programs require it |

**Affected component** becomes *endpoint · parameter · identity · precondition*. **Add a "Not tested /
scope-blocked" line** naming the classes you could not reach and why; programs value that, and
omitting it implies coverage you don't have.

**Grey-box carries both sets.** If a sourcemap gave you front-end sources, cite `file:line` in
`work/<slug>/web/js/src/` *and* the transcript ids. That union is the strongest report this pipeline
produces, and it's why recovering sourcemaps is worth the ten minutes.

**A live target moves.** It can be patched or redeployed between your test and the maintainer's read.
Re-run the PoC immediately before delivery, state the observation time, and say plainly if behavior
changed. Verifying a fix is usually not achievable against production — say that rather than implying
you did.

**Redaction is part of the standard here.** Response bodies may hold real user data or secrets. Scrub
them in the bundle, not only in the prose — the bundle is what ships. Prove cross-user access with one
redacted record, never a dump.

## Delivery gate — nothing ships without a receipt

A report is deliverable when three things exist on disk and agree with each other. Hooks enforce this,
not discipline: the turn will not end, and a submission command will not run, without a valid receipt.
The mechanics are in `report-craft` §4-6; what the gate requires is:

**1. Two recorded runs** — the PoC executed through `hunt poc-run`, writing
`work/<slug>/evidence/<ID>/runlog.json` with real stdout, exit code, `pip freeze`, and target commit.
*Tested* means recorded; output reconstructed from memory is not evidence, and every output block in
the report has to appear in a recorded run. Record it **while the instance is still up** — a confirmed
lead goes to a report immediately (`sec-orchestrator` § "A confirmation interrupts the hunt").

The gate's floor is two runs, because "I ran it twice and got the same thing" is the cheapest defence
against a one-off fluke. **Those two runs come from two different agents, not one agent running twice**
(`report-craft` §4): `report-writer` records one from its clean-room directory, and `report-auditor`
records the other when it reproduces the PoC cold in a fresh directory of its own. Two agents in two
directories is a stronger fluke check than a repeat in the same one, and it costs one execution
instead of two. If the auditor genuinely cannot execute the PoC (hardware, a cloud account, a live
host outside the window), it says so and the writer records the second run before the gate.

Runs go stale when the PoC changes. If a round of audit fixes edits any setup or PoC block, both runs
describe commands the report no longer gives and both must be re-recorded. Editing prose alone leaves
them valid.

**1b. A clean-room reproduction** — the report's own setup and PoC blocks, extracted into a fresh
empty directory and run as written, with nothing from the hunt's working tree. `report-writer` does
this *as* its recorded run; `report-auditor` does it again cold, as its own recorded run. It is the
only check that catches a package already in your venv, an env var set in another terminal, a `cd`
that never happened, a helper file the report never gives, or an edited payload whose output no longer
matches. Live targets: re-issue the exact requests inside the window and confirm the responses still
match the cited transcript ids.

**2. Two agent audits, both PASS, both bound to the current bytes.**

| Agent | Judges | Writes |
|---|---|---|
| `report-auditor` | Facts. Opens every cited `file:line` and compares the quoted code, checks versions against the recorded freeze, matches output to a real run, **runs the report's PoC in a clean directory**, re-derives CVSS metric by metric, hunts unanchored claims and missing prerequisites. | `state/audit/<ID>.factual.json` |
| `report-editor` | Presentation. Title rule, section structure **for the declared layout**, rule-4 voice, concision, rendering, placeholders. | `state/audit/<ID>.editorial.json` |

Both read the report **cold** — no hunt transcript, no access to your reasoning — because that is what
a triager gets. Each verdict binds to the report's sha256, so editing one paragraph voids both. That
is the point, not an inconvenience, and it is why the loop has a protocol: hash, task both at once,
edit nothing until both return, fix in one batch, re-run as a *delta*. Blocking defects
(`critical`/`major`) are uncapped and mandatory to fix; `minor` defects are capped at **three** per
auditor, never block, and never justify a re-audit on their own.

**3. The receipt.** `hunt validate-report <ID>` verifies the chain and, only if everything holds,
writes `state/gate/<ID>.json`. It checks facts, never quality: the runlog is self-consistent, both
audits PASS with a non-empty `checked` list against the current bytes, the dup artifact is real and
under 14 days old, and the CVSS vector's arithmetic matches the printed score. Live and grey also
re-verify transcript hashes and the scope digest.

Why the split: a script that grades prose produces confident nonsense — the old gate flagged
"comprehensive" where it belonged and passed whole pages of generated text, because the real tells are
structural. Judgement moved to agents that can read; the script was cut back to things that cannot be
wrong. `validate-report` still prints the old regex output on failure, labelled *hints for
report-editor*. Treat those as "go look at this", never as a verdict.

**If the gate blocks, fix what it names.** Do not work around it, re-file the finding under a new id,
or present the report anyway with a caveat. If a draft is genuinely abandoned, record that with
`python tools/hooks/waive.py <ID> --reason "..."` — it lets the session end, it is written where
anyone can read it, it lapses when the draft changes, and it never permits a submission.

**Test the prompts themselves.** The agents + skills are the product, not the Python scripts. Before
their output is trusted to ship, the pipeline must pass its own `work/_selftest` fixtures: rediscover
the seeded bugs in `py_app`/`node_app`, confirm each with a PoC, and emit a report that clears this
gate. The auditors get their own regression corpus in `work/_selftest/reports/`: seeded defects each
must catch, **plus a clean report neither may flag** — an auditor that invents defects is as broken as
one that misses them. Run this whenever an agent or skill changes.

## Writing for the people who triage this

**Quality over quantity — do not shotgun.** Many speculative reports reduce your signal and your
reputation with a program. Finish and submit one report per target before starting the next; let
`hunt metrics` show the accepted-vs-submitted ratio rather than the raw count.

**Comprehensive yet concise.** The team needs enough to outline the bug, reproduce it, assess what it
applies to, and check the logs — no more. A Summary over ~120 words, an Impact over ~250, or a Root
cause over ~200 is usually padded, but the test is whether the words are doing work. Density, not
brevity: a long PoC with every step spelled out is right; a long Impact speculating about pivots is
not. `report-editor` makes this call.

**Read the program's own guide before submitting**, and read past disclosed reports for the same class
(HackerOne hacktivity, huntr public reports) — they show the depth of evidence a given triage team
expects, which varies more than you would think.

**Say what you did not test.** Naming the classes you could not reach costs nothing and reads as
competence. Implying coverage you don't have is the fastest way to lose a triager's trust.

## Tone
Precise, factual, collaborative. Help the maintainer fix a real problem; thank them for triaging.
Ground every field in verified fact — no invented versions or lines.
