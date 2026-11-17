# Google OSS VRP

Destination program dossier. Resolve this **before** tasking the first hunter, not at report time.

## Intake

`https://g.co/vulnz` (Google Bug Hunters). A repository's own `SECURITY.md` usually says so
explicitly; shaka-project's does. GitHub security advisories on these repos are used by maintainers
for post-triage coordination and are **not** the intake channel — filing a GHSA draft instead of
going through Bug Hunters routes the report nowhere.

The submission form is a login-gated SPA. Claude cannot file it; the operator does. The pipeline's
finish line is a paste-ready folder plus `submission-fields/`, one file per form field.

## CLOSED TO PRODUCT VULNERABILITIES — 2026-10-01 (read this before anything else)

The OSS VRP **no longer accepts product vulnerabilities**. Verbatim from the rules markdown in the
public `google/bughunters` repo (`bughunters/articles/about/rules/open-source/
google-open-source-software-vulnerability-reward-program-rules.md`, § Product vulnerabilities), read
2026-10-20:

> As of October 1, 2026, we are no longer accepting product vulnerabilities submitted to the OSS VRP.
> For some Google Cloud repos impacting Google Cloud products we may still accept reports covering
> product vulnerabilities through the Cloud VRP. We will continue to reformat and work on this aspect
> of the OSS VRP and commit to giving an update in Q1 2027. In the meantime, we encourage you to find
> impact across our other VRP programs and submit there instead, or pursue the Patch Rewards Program.
> This change does not affect product vulnerabilities submitted before October 1, 2026.

Confirmed in practice: `SHAKA-C19-001`, a default-config XSS in `shaka-project/shaka-player`
(CWE-79, 6.1, runtime-confirmed in the project's own karma harness) was filed 2026-10-19 and closed
**out of scope** on the date rule alone — triage agreed it *is* an OSS VRP product vulnerability and
declined it anyway, pointing at the repo's security page, a public GitHub issue, or Patch Rewards.

**What this means for lane selection.** Everything below about `C:`/`I:` impact, preconditions and
tiers now decides nothing for a product defect in a Google OSS repo — the lane is closed before those
questions are reached. **Do not open a VRP report lane for a product vulnerability in Google OSS.**
A finding's ceiling is now the upstream repo: a private advisory on the project's security page, a
public issue, or a merged patch. Only two things still route here:

* **Supply chain** — source or build integrity (branch write, Actions/CI config, release
  infrastructure, signing keys, package-manager credentials), and the PR-approval bypass requirement
  in § Supply chain compromises still applies: a defect that needs a maintainer to approve a PR is
  "Credit" at best.
* **A different program** — Cloud VRP for Cloud-tied repos, AI VRP for AI-tied ones.

**Patch Rewards is not a general fallback.** Its scope is the Tier 1 list in
`patch-rewards-program/scope.md` (core parsers, web/mail servers, toolchains, decompression libs),
plus any project that received a vulnerability report *from Google*, plus Tier 2 = projects
integrated into OSS-Fuzz. Checked 2026-10-20: `shaka-player` is in none of them — not in `scope.md`,
and `google/oss-fuzz/projects/shaka-player` is a 404. Where it does apply, the patch must be merged
and un-reverted for a month *before* submitting, max 3 submissions/month, and one-liner fixes for
non-exploitable crashes are excluded.

## Eligibility — the rule that has cost the most (SUPERSEDED for product vulns; see above)

The qualifying definition of a product vulnerability names **confidentiality and integrity of user
data only**. Availability is absent from it, and the absence of an explicit exclusion bullet is not
evidence of inclusion.

**An availability-only finding is ineligible regardless of CVSS score or repository tier.** A vector
with `C:N/I:N` does not qualify however high `A:` is. This was re-derived from search snippets more
than once and got it wrong both ways; the primary source is the program rules markdown in the public
`google/bughunters` repository, which is readable directly — do not infer it from a results page.

Consequence in practice: hangs, infinite loops, memory exhaustion, decompression bombs and parser
DoS are not reportable here whatever their severity. Their ceiling is an upstream public GitHub
issue, which is an effective channel — one such issue produced a merged upstream fix in two days —
but it pays nothing and no report lane should open for it.

## Repository tier

Scope and tier live in `oss-repository-tier/external_repositories.txtpb` in the public
`google/bughunters` repository. Resolve the exact repository URL there before hunting.

- Tier is **not** implied by the GitHub organisation. `shaka-project/shaka-player` is in the tier
  list at `TIER_OT1 / SCOPE_OSS_VRP` despite not living under `google/*`.
- `TIER_OT0` / `TIER_OT1` accept memory-corruption findings with a solid PoC, but those carry an
  OSS-Fuzz-or-merged-patch precondition. That precondition applies to memory-corruption findings
  only; it does not gate a web-origin or logic defect.
- Many small Google repositories carry a README line saying they are not eligible for the OSS VRP.
  Grep the README before picking a target.

## Out of scope

- **Third-party platforms used to build Google OSS** — GitHub itself, package managers, CI/CD
  providers. Do not probe them.
- **Findings gated behind maintainer PR approval** — a defect in a CI, presubmit or release-pipeline
  guard that an attacker can only reach by getting a PR approved. Credit-only at best; the honest
  ceiling is a public GitHub issue, not a VRP report.

## Severity bar

**Preconditions decide this, not CVSS.** Count the conditions that must hold at the same time for the
attack to work. Three, with any one of them being non-default application configuration, and the
expected outcome is *Infeasible* whatever the vector says. Clearing the CVSS 4.0 floor buys nothing:
observed 2026-09-21, a runtime-confirmed `C:H` credential disclosure self-scored **7.1 High** with a
one-line fix was closed *Infeasible* at **P4/S4** — issue 564006943, `SHAKA-C8-001`, the ClearKey
license-pin bypass. Its three preconditions were stated honestly in the report's Summary, and that is
what got scored. A finding that fires on the library's *default* configuration is the only shape worth
a report lane here; anything precondition-stacked goes straight to a public upstream GitHub issue.

**Non-default configuration counts double, so the threshold is two.** "The application must have
configured X" means the finding does not fire on the library as shipped and the affected population
is whoever opted in. `hunt impact-gate --default-config no` therefore blocks at *two* conditions
rather than three. The pure case is `SHAKA-C10-002`, where the victim had to have actively set
`sameOriginOnly=true` — i.e. the only deployments the bug could touch were the ones that had opted
*into* the protection.

**The override record is 0 for 1.** `SHAKA-C8-001` was blocked on preconditions and overridden on
five specific grounds, every one of them true: `C:H` is the named inclusion class; 7.1 clears the
floor twice over; it ends in a real credential rather than a bare primitive; it violates the
project's own documented invariant; a Widevine control forecloses working-as-intended. Google closed
it P4/S4 regardless. Put that record in front of the operator *before* they decide, not after.

Their closure comment grants explicit permission to disclose publicly on GitHub, so the upstream issue
needs no further coordination.

No finding below **CVSS 4.0** has been accepted here. Observed closures at the bar:

- A CVSS 3.8 prototype-pollution primitive was closed *Infeasible* — "not severe enough for us to
  track it as a security bug". Three factors, all knowable before the report lane opened: under the
  floor, a proven primitive with no demonstrated gadget, and three stacked preconditions
  (non-default configuration, an action the victim must actively be taking, and an attacker already
  occupying a semi-trusted role).
- A technically sound, runtime-confirmed availability finding was closed *out of scope* — the report
  was true and the finding was real; it was never eligible. Audits verify that claims are true, not
  that a finding qualifies. That is what the impact gate is for.

## Duplicates you cannot see

Google's internal tracker is invisible externally. A finding can clear every external dedup check —
empty repository advisories, empty OSV, no matching issues — and still come back **duplicate**. This
has happened on a report that was runtime-confirmed and passed both audits.

The strongest available signal is a **recently hardened neighbour**: if a sibling sink in the same
file was fixed in the last few weeks, whoever fixed it was reading the whole file, so the unfixed
siblings are likely already known internally. Treat that as a duplicate-risk signal that can outweigh
its value as a lead, and say so to the operator before spending a report lane.

## Submission form

Observed fields and limits. Verify before declaring a report submittable — these change.

| Field | Limit / note |
|---|---|
| Vulnerability type | a dropdown; pick the closest listed class |
| Description | **200 characters**, hard — not the 10,000 some other portals allow |
| Report body | the full advisory |

The form runs a content classifier that reacts to the *name* of a known-invalid class of file. A
companion document called `SUBMISSION.md` has tripped it even when the content was correct; name it
`HOW-TO-FILE.md` instead.
