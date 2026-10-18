# Circle / Arc (HackerOne) — destination dossier

Resolved 2026-09-20 from the program policy text supplied by the operator (Overview last updated
2026-09-16; Rewards summary last updated 2026-09-15). **Not yet verified against the live policy
page** — re-read `https://hackerone.com/<circle program handle>` and record the handle + a policy
sha256 here before the first report is filed.

## Intake

HackerOne only. The legal counterparty named in the policy is **Circle Internet Contract Services,
LLC**. Submission is login-gated, so the pipeline's finish line is a paste-ready report body plus
`submission-fields/` — the operator files it.

Report language: **English only**. One vulnerability per report, unless a chain is needed to carry
the impact. Multiple vulnerabilities from one underlying cause pay **one** bounty. First valid
reproducible report wins a duplicate race.

## Scope — two tiers, two different games

**Tier A — Arc Mainnet chain / protocol.** Consensus, system contracts, validator set, key
handling. Ceiling is **$1,000,000** (Extreme: unlimited minting, private-key compromise, consensus
safety failure / validator-set takeover, chain halt under clear criteria). Critical $20k–$200k,
High $10k–$20k, Medium $5k–$10k, Low up to $5k.

**Tier B — Arc product / Web 2, `*.arc.io`.** Critical $3,000–$10,000 (unauth account takeover,
RCE, unrestricted admin on Portal/product backends). High $800–$3,000 (ATO with realistic user
interaction, authz bypass into privileged Portal workflows). Medium $400–$800 (stored XSS, IDOR with
limited-scope data, meaningful SSRF with constrained reach). Low up to $400 (verbose errors,
clickjacking on low-sensitivity pages, low-risk reflected XSS).

Note the Tier A bounty table in the policy is written under an "All assets" row spanning
$50–$200,000, with `*.arc.io` shown at $50–$10,000. Where the two disagree, the per-tier criticality
tables above are the specific text and should govern — but **confirm the asset row on the live
program before scoping a report's severity claim**.

`*.arc.io` is a **wildcard** — unlike [[rei-h1]], subdomains are in.

## The rule that binds every single request

**Test on Arc testnet or a local devnet. Never on mainnet.** The policy says this twice (Program
Rules and Test Plan). A mainnet interaction is not a scope slip, it is a live-funds event on a
payments chain: it breaks safe harbour and is unrecoverable. Any chain-facing primitive runs against
a devnet the operator stands up, or it does not run.

Corollaries already stated in the policy: demonstrate exploitability but **do not exploit** — no
accessing/modifying/copying/deleting others' data, no non-public information, no service
degradation, **no loss of funds that are not your own**. Own accounts and own wallets only.

## Availability is out — third program in a row

"Any activity that could lead to the disruption of our service (DoS)" is listed out of scope.
`resource-dos-hunter` is **N/A on the Tier B web surface** — do not open a lane for it.
(Same shape as [[no-dos-findings-google-oss-vrp]] and the REI rule in [[rei-h1]].)

The one asymmetry worth reading carefully: Tier A lists **"chain halt under clear criteria"** at the
Extreme tier. A consensus-level liveness failure is explicitly in scope on the protocol side even
though service DoS is out on the product side. That is a narrow exception — it means a
demonstrable halt of the chain under stated preconditions, proven on devnet, not "this RPC endpoint
gets slow".

## Excluded classes — do not spend a wave on these

Source-manipulation-dependent findings · vulnerabilities in unit tests · clickjacking on pages with
no sensitive action · CSRF on unauthenticated forms or forms with no sensitive action · anything
requiring MITM or physical device access · known-vulnerable libraries without a working PoC · CSV
injection without a demonstrated vulnerability · SSL/TLS best practice · DoS (above) · content
spoofing / text injection without HTML/CSS modification · rate limiting or brute force on
**non-authentication** endpoints (auth endpoints still count) · CSP best practice · missing
HttpOnly/Secure cookie flags · SPF/DKIM/DMARC · outdated-browser-only issues (>2 stable versions
behind) · outdated or non-store mobile app versions · version/banner disclosure and descriptive
errors or stack traces · tabnabbing · open redirect **unless** additional impact is demonstrated ·
issues requiring unlikely user interaction.

Public 0-days patched <1 month ago are case-by-case, not automatic.

Additionally: **HackerOne Core Ineligible Findings are out of scope** — pull that list and treat it
as part of this exclusion set.

## What the numbers actually say

The 90-day rewards summary shows **one** asset carrying 100% of resolved submissions at an average
bounty of **$500**; the other three assets show `n/a` / 0%. Read that as: essentially all paid
volume so far is landing in the Tier B Medium band, and the six- and seven-figure Tier A numbers are
an advertised ceiling nobody in the window has hit. Plan the effort accordingly — a Tier B Medium is
the realistic modal outcome, not the $1M row.

Response performance is good and worth relying on: first response ~4h, triage ~4h, bounty ~1d23h,
submission→bounty ~2d3h, resolution ~2d10h — all far inside the contractual SLAs (5 / 10 / 10
business days). Program is Platform Standards compliant with >90% response efficiency.

## Disclosure

**No public disclosure of anything, including resolved reports, without Circle's prior written
consent.** Follow HackerOne disclosure guidelines. No GHSA fallback lane here — the
[[ghsa-fallback-after-vendor-declines]] play does not apply to a HackerOne-managed program under
this clause.

## Eligibility bars on the researcher

18+ · not a Circle employee or an immediate family member of one · not a resident of a U.S.
embargoed jurisdiction (Iran, North Korea, Cuba, Crimea, Syria) and not on SDN / Denied Persons /
Entity List · tax responsibility is the researcher's; HackerOne shares tax-form personal data with
Circle for compliance checks. Reporting grants Circle a perpetual irrevocable royalty-free licence
over the submission. Payment is at Circle's sole discretion.

## Documents

- Arc Docs — `arc.io`
- Arc testnet connection instructions — linked from the program's Documents section
