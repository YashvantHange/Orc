# REI BBP (HackerOne) — destination dossier

Resolved 2026-09-16 from the policy text saved at `work/rei-com/policy.txt`
(sha256 `cb46975826cb6cd30c26fc11a3c6dc46974e67d25faa3031110a9ea7577ea7b1`).
Scope file: `work/rei-com/scope.yml` (digest `sha256:ed44f2ff...f2e5ff84`).

## Intake

`https://hackerone.com/rei_bbp` — HackerOne only; anything filed elsewhere earns nothing. The
submission form is login-gated, so the pipeline's finish line is a paste-ready report body plus
`submission-fields/`. The operator files it.

## Scope — one asset

`rei.com`, URL asset, nothing else. **No subdomain wildcard**: the asset list names the apex, and the
policy separately disowns "a multitude of third-party managed sites under the REI name and brand" —
those are closed informational, no bounty. A path on rei.com that is actually rendered by a third
party (chat, reviews, surveys, adventures booking) falls under the same closure. Classify a path as
first- or third-party **before** aiming a probe at it; that classification belongs in the report.

## Severity bar — the rule that decides whether to open a report lane

"We are interested in **Critical and High** severity findings." The bounty table and the 90-day
averages say the same thing more bluntly: Medium averages **$750**, and Low shows `n/a` for average
bounty against 18.07% of submissions — Lows are landing without a payout. High pays $3,000–$5,000,
Critical $5,000–$7,000, with 2x/3x campaign multipliers while the campaign runs (**ends 2026-09-18**).

Practical consequence: a Low-severity primitive is not a finding here, it is a chain component. Take
it to `chain-craft` and either reach High or drop it.

## Availability is out, twice over

"Do not perform DoS or DDoS", "Any activity that could lead to the disruption of our service (DoS)"
and a separate no-spam rule for the feedback form and Gladly chat. `resource-dos-hunter` is **N/A on
this target** — not deferred, not code-confirmed, not reportable. Do not open a lane for it.
(Same shape as the Google OSS VRP availability rule: [[no-dos-findings-google-oss-vrp]].)

## Testing rules that bind every request

- **Authenticated testing must use `@wearehackerone` aliases.** Accounts registered any other way
  disqualify the finding. Alias provisioning needs the operator's HackerOne inbox — Claude cannot
  receive the verification mail, so identities arrive from the operator, never self-registered.
- **The testing IP goes in the report.** Capture it at the start of the run and record it in the
  profile, or the submission is incomplete.
- Only your own accounts. Never touch another user's data — this is a live retailer with real
  member records and real payment instruments.
- No leaked/harvested credentials, in testing or in the report body.
- No social engineering, no physical testing, no MITM.

## Excluded classes — do not spend a wave on these

Open redirect (unless chained to demonstrated impact) · cache poisoning · clickjacking on
non-sensitive pages · CSRF on unauthenticated forms or forms with no sensitive action · tabnabbing ·
CSV injection without demonstrated impact · known-library reports without a working PoC · missing
CSP best practices · SPF/DKIM/DMARC · version/banner disclosure and descriptive errors · rate
limiting on **non-authentication** endpoints (auth endpoints still count) · outdated-browser-only
issues · anything requiring unlikely user interaction · "issues without a clearly defined security
impact". Core Ineligible Findings apply on top.

## Dedup and consolidation

First report wins on duplicates. REI consolidates: the same root cause across many endpoints or
hosts pays **one** bounty. So do not split a systemic defect into per-endpoint reports — file one
report that enumerates the affected endpoints.

## PoC bar

"Reports without a working proof of concept and steps to reproduce" get flipped to *Needs more
information*. Full bounty requires the PoC; without one, a written justification must ship in the
report. This matches the pipeline's own runtime-confirmation rule — nothing leaves without a
recorded request and the response observed.
