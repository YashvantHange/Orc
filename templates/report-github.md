# GitHub Security Advisory draft — `<owner/repo>`

> **This is the default layout.** GitHub publishing means a private draft advisory opened from the
> repo's Security tab (or the huntr on-platform form, which takes the same body). Use
> `templates/report-hackerone.md` instead only when the destination is a HackerOne program.
>
> Two parts below: the **structured form fields** you type into GitHub's boxes, and the **description
> block** you paste whole into the advisory's Description box. Delete every instruction line, including
> this one, before submitting.
>
> Title: `<the vulnerability> in <where>` — plain words, one clause, ≤10 words, sentence case, no
> trailing period. Name the security failure (ReDoS, path traversal, missing authorization), not the
> mechanism: if the title could sit on a refactor PR, rewrite it. No colons, no CVE/GHSA
> ids, no versions, no severity words. Prose: first person about what you did and tested, short
> sentences next to long ones, uncertainty stated straight. Full rules in `report-standards`.

## Form fields

### Affected products
Every row filled — a blank here is what makes an advisory sit unreviewed. If a range is genuinely
unknown, write what you tested and say the earlier bound is unconfirmed; do not leave it empty.

| Field | Value |
|-------|-------|
| **Ecosystem** | `<pip / npm / Go / Maven / crates.io / …>` |
| **Package name** | `<the installable name, not the repo name>` |
| **Affected versions** | `<e.g. ">= 1.4.0, <= 1.5.5" — or: present at HEAD <commit> (<date>); earlier bound unconfirmed>` |
| **Patched versions** | `<a released fixed version, or: none yet>` |

### Severity

| Field | Value |
|-------|-------|
| **Severity** | `<Critical / High / Moderate / Low>` |
| **CVSS 3.1 vector** | `CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_` |
| **Score** | `<n.n>` (`hunt cvss <vector>` — computed, not eyeballed) |

### Weakness (CWE)

| CWE | Name |
|-----|------|
| `CWE-___` | `<name from cwe-map>` |

### Provenance — kept out of the advisory body, for our records

| Field | Value |
|-------|-------|
| **Finding ID** | `<Fxxx>` |
| **Tested at commit** | `<sha>` (`<YYYY-MM-DD>`) |
| **Evidence bundle** | `work/<slug>/evidence/<Fxxx>/` |
| **Recorded runs** | `<N>` via `hunt poc-run` |
| **Reporter** | `<name / handle>` |

<!-- ===== LIVE WEBSITE / GREY-BOX — keep this block only if a live host was tested ===== -->

| Field | Value |
|-------|-------|
| **Target** | `<https://app.example.com>` |
| **Program** | `<name>` — `<program URL>` |
| **Scope authorization** | `scope.yml` `sha256:<digest>`, policy read `<YYYY-MM-DD>` |
| **Test window** | `<start>` → `<end>` (all cited traffic falls inside it) |
| **Tested from** | `<source IP or description>` |
| **Observed at** | `<YYYY-MM-DDTHH:MMZ>` — re-verified immediately before submission |

---

<!-- ============ PASTE EVERYTHING BELOW THIS LINE INTO THE DESCRIPTION BOX ============ -->

# `<Title — the vulnerability, and where. ≤10 words. Name the security failure, not the mechanism.>`

## Summary
<2–3 sentences: what the bug is, where it lives, what an attacker gets. Say what you sent and what came
back. Don't restate the title in the first sentence.>

## Details

**Affected component**
- File: `<path>:<line>` — source/grey
- Endpoint / entrypoint: `<METHOD /route or function>`
- Parameter / identity: `<the input you controlled>` as `<which principal>` — live target
- Precondition: `<auth level / config / none>`

<Walk the defect. Quote the code, don't just cite it: every `file:line` the argument leans on gets a
short fenced snippet inline so the reader can follow without opening the file.>

```python
# <path>:<line>
<the actual bytes, elided with ... where they don't matter>
```

**Root cause**

<The specific flawed logic, as a chain — not a restatement of the Summary:>

```
request/source → route → middleware → guard/decorator → the missing or wrong check
               → framework behavior that enables it → sink (what actually goes wrong)
```

## Proof of Concept
Runs against a local instance you launch yourself (or, for a live target, against the authorized host
inside the test window). Benign markers only. The maintainer must be able to paste this and see the bug
without inventing a single value.

```bash
# 1. clone + check out the tested commit
git clone --depth 1 https://github.com/<owner/repo>.git && cd <repo> && git checkout <commit>

# 2. install — exact versions, exact flags
<install commands>

# 3. launch — exact command, exact port, and which terminal it stays in
<launch command>

# 4. trigger — real values, no placeholders
<the minimal curl / script command>
```

<If the trigger is a script, the whole runnable script goes here, inline, with all data.>

**Observed** (pasted verbatim from a recorded run):

```
<real output>
```

**Expected:** `<the safe behavior — e.g. 403, or the request rejected before the sink>`

**Negative control:** `<the same payload against a route that defends correctly, or the baseline —
so the reader can tell a real signal from the app's default behavior>`

<If full impact needs hardware or state the maintainer may not have (GPU, a cloud bucket), also give a
deterministic reproduction that does not — a unit-level driver of the exact sink, or a CPU fallback
that exercises the same missing check — and keep the full-impact repro as a second part.>

### Transcript — live target / grey only
<Every load-bearing claim cites a `T#####` id from `work/<slug>/web/transcript.jsonl`, and the
request/response is pasted in full. Scrub real user data and secrets: the bundle ships with the report.>

| Transcript id | What it shows |
|---|---|
| `T00203` | `<the baseline>` |
| `T00287` | `<the request that proves it>` |

## Impact
<Who is affected, the realistic attacker position, blast radius (one object vs every tenant), and what
they gain. Label confidence: runtime-confirmed / code-confirmed / theoretical. No speculative pivots.>

## Suggested fix
<Concrete — a diff the maintainer can apply, or a precise instruction. Reports that arrive with the fix
get merged.>

```diff
<minimal patch>
```

## Not tested / scope-blocked
<Classes you could not reach, and why. Costs nothing, reads as competence, and omitting it implies
coverage you don't have.>

## Duplicate check
<What was searched (CVE, GHSA, huntr, issues, PRs, commits, releases) and the result. State the novelty
verdict: no published advisory covers this, and it is not an incomplete-fix or patch-bypass of one.
House rule: no other product's CVE/GHSA ids appear in this delivered text.>

## Credit
Please credit `<name / handle>`. Thanks for triaging.

<!-- ============ END OF PASTE REGION ============ -->
