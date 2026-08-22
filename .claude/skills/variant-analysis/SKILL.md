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
