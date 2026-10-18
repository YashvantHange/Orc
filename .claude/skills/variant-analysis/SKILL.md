---
name: variant-analysis
description: >
  The novelty gate. Build the product's advisory exclusion map from its published CVEs/GHSAs, then use
  it to REJECT any candidate that a fix already covers or that is merely an incomplete-fix/patch-bypass.
  Reportable findings must be genuine zero-days. Load whenever a target has prior advisories.
---

# Variant analysis = the novelty gate (exclude, don't emulate)

Policy: **we report genuine zero-days only.** A finding that is the same bug as a published CVE for the
product — or an incomplete-fix / patch-bypass / variant of one of the product's published fixes — is
**out of scope**, however exploitable. So the point of studying advisories here is the opposite of
generating variants: it's to know exactly what's already covered so you can **prove your candidate is
outside all of it**, and to catch and drop candidates that are secretly variants.

## Build the exclusion map (once per target)
For every published advisory (CVE / GHSA / huntr) — `hunt dup <owner/repo> --query "<class + component>"`
surfaces them — record one line: **class · root cause · code path/file · the fix commit · what the fix
assumes safe.** That set is the boundary. Anything inside it cannot be reported. Cache it in
`work/<slug>/profile.json` so hunters and later sessions don't re-derive it.

## The blind spot: a fix that is merged but not yet released

Advisories and the issue tracker cannot see a defect the vendor has **already fixed on the default
branch but not yet shipped**. On a fast-moving target the released tag can sit days behind `main`, and
in that window a bug is simultaneously present in the artifact you tested, fully reproducible, known
to the vendor, and invisible to `hunt dup` and to every tracker search. Filing inside that window
returns "already known" and spends credibility for nothing.

This is not theoretical. On this pipeline a finding was confirmed, written, audited twice, gated, and
was about to be filed when a tag-to-head diff showed the exact function had been rewritten by a PR
**merged two days before the dedup ran**. Nothing else in the pipeline could have caught it.

Run this as part of building the exclusion map, and again before any novelty verdict:

```
gh api repos/<owner>/<repo>/compare/<release-tag>...<default-branch-head> --jq '.commits[].commit.message'
gh api repos/<owner>/<repo>/compare/<tag>...<head> --jq '.files[].filename'
gh api repos/<owner>/<repo>/compare/<tag>...<head> --jq '.files[] | select(.filename=="<path>") | .patch'
```

Read the patch for every file your candidate touches — a commit message is not enough, because a
security fix often rides along inside a change named for something else. Record the compared commit
range in the dedup notes so the check is auditable.

**Run it during recon, not only at the gate.** The same diff is a targeting tool: the batch of fixes
tells you which veins were just closed (and are now worthless) and, more usefully, which source trees
the sweep *skipped* — that is where unswept surface actually concentrates. On the run above, doing
this mid-hunt forced four already-dispatched hunters to be retargeted; doing it during recon would
have aimed them correctly from the start.

## Attacker marginal gain — the test a triager applies first

A candidate that clears every duplicate check can still be worthless, and this is the most common way
a technically-real finding gets rejected. Ask: **what can this attacker already do through an
intended, disclosed channel?** If the answer covers the outcome you are claiming, the finding is the
*difference*, not the outcome.

Two worked examples from this pipeline:

- A guard bypass was runtime-proven, then dropped: the mode it binds in already grants the capability
  by design, so bypassing it bought the attacker nothing.
- A credential-disclosure finding survived, because although the attacker could already reach an
  arbitrary host and could already run local commands in a trusted workspace, **no intended
  configuration hands them the user's cloud credential**, and the consent screen never says credentials
  are attached. The gain was concealment plus a credential — stated as such.

Write the answer down before the report is drafted. If the honest answer is "the attacker already has
this", stop. If it is "the same outcome but undisclosed to the victim", that is often a real finding —
but the report must argue *that*, not the raw capability, or a triager will reject it in one line.

## Run every candidate through the novelty gate
Before a lead becomes a finding, prove it clears **all** of these — otherwise `OUT_OF_SCOPE`, drop it:
1. **Not the same bug.** No advisory shares this candidate's class **and** root cause / code path.
2. **Not a patch-bypass.** Its identity is not *"the fix for CVE-X can be bypassed / is incomplete."*
   Break-the-assumption findings (spoof the trusted header the fix trusts, rebind DNS after the
   allowlist check, send the `auth_type` the branch forgot) are the classic variants — **these are now
   out of scope.**
3. **Not a missed sibling of a patched bug.** The same vulnerable pattern the maintainer already fixed,
   resurfacing in a neighbor route / override / wrapper the patch didn't reach, is still "you didn't
   finish fixing CVE-X" — out of scope.
4. **Novelty litmus (decisive):** would the maintainer log this as *a new bug*, or as *"finish fixing
   CVE-X"*? Only "a new bug" ships.

Studying a fix may legitimately point you at code worth reading — but the bug you ultimately report must
stand on its own as a **distinct, never-advised root cause**, not defined by any prior CVE. Confirm the
fix's presence on your commit anyway (`reports/verify_patch.py --fixed <ref>`): an unpatched HEAD of a
known CVE is also not novel — it's an unpatched-version issue, not a zero-day.

## What still counts as novel (report these)
- A vulnerability in a class or component the product has **no** advisory for.
- A distinct root cause the advisories never touched, even if it's near patched code — provided a
  maintainer would call it a new bug, not an unfinished fix.
When in doubt, treat it as a variant and drop it; quality and true novelty beat CVE-count.

Finish with the **reasoning-checklist** (esp. #8 novelty: proved no advisory covers it and it is not a
variant/incomplete-fix).
