# Files.com BBP (HackerOne) — destination dossier

Resolved 2026-09-20 from policy text supplied by the operator (Overview last updated 2026-09-18,
Rewards summary 2026-09-19). Scope file: `work/files-com/scope.yml`
(digest `sha256:5ffdeed0...3328e5f9a`). **policy_sha256 is UNRESOLVED — pin a fetched copy before
filing.**

## Intake

`https://hackerone.com/files_com`. Pays at triage, $250 / $750 / $2,000 / $15,000 by severity.

## The rule that gates every hunt here: you must own a trial site

Testing runs against **your own trial site only**, created at https://www.files.com with:

- Company Name containing the literal `[BUGBOUNTY]` (square brackets, no space)
- Work email = the HackerOne alias `<handle>@wearehackerone.com`

Max **4 trial accounts per 90 days** — do not burn one carelessly. Without a trial site the
authenticated classes (IDOR, cross-tenant, Share Link / Inbox controls, token replay, API-vs-UI
permission drift) cannot be touched at all: the API is uniformly 401 and share-link codes may not be
enumerated. An unauthenticated-only pass has a realistic ceiling of **Low**.

## Documentation is the contract — reports are judged against it

A finding must cite a page that says the product does X and show it does Y. Three sources only:
`https://www.files.com/docs/`, `https://developers.files.com/`, and the Security Reference at
`https://www.files.com/docs/security-reference`. "Should", "best practice", "expected behavior" and
"other products do it differently" are closed as invalid. The web UI is **not** documentation — the
API, SFTP, FTP, WebDAV and the SDKs are equally the product.

## Severity caps — decide the lane before spending a wave

- **Critical ($15k) is platform-wide or cross-customer only.** Escalation inside a single customer
  account caps at **High**.
- Client-side (Desktop, CLI, Agent, Mobile, SDKs, MCP) caps at **Medium ($750)** — the table shows
  $750 in the High and Critical columns too. Only a broader API/cloud-service defect lifts the cap.
- **www.files.com caps at Low** unless it escalates to real customer impact. DoS does not count.
- RCE against Files.com servers is Critical from any role.

## Hard exclusions — do not open a lane

DoS/availability (also a Core Ineligible Finding — same shape as
[[no-dos-findings-google-oss-vrp]]) · brute forcing or automating intended functionality · the
in-app **AI Assistant** (costs them money, explicitly forbidden) · **OnlyOffice** / the Files.com
Editor (own H1 program) · Public Suffix List, for any domain, including as a suggested mitigation ·
DNSSEC · billing/pricing/usage-cost logic · EXIF retention · SDK debug logging (documented to be
unredacted) · Site Admin using documented admin powers on their own site · anything needing
admin/root on the device running a client app · API exposing more than the UI (by design) ·
Folder Admins seeing all users/groups (intended) · "Allow Users To Create API Keys" governing
creation only · Read-Only Site Admin seeing everything · open FTP/SFTP/WebDAV (that is the product) ·
JS served from `subdomain.hosted-by-files.com` (full web hosting; XSS there counts only
customer-to-customer) · timing attacks that only prove existence · a **customer's** leaked
credentials. Core Ineligible Findings apply on top.

**Files.com's own** leaked credentials do count: try once, report with the credential and where it
was found, then stop.

## Excluded hosts

`developers.files.com`, `status.files.com`, `mail.files.com`. Every unlisted files.com subdomain is
unauthorized, not merely out of scope.

## Conduct rules that bind requests

Rate-limit to ~2 rps (this scope file runs 1.0). Never touch another customer's site or data; if
customer data appears, stop that path, say so in the report, delete every copy. No payment card
entry. No public disclosure ever — before or after fix, before or after bounty, including private
forums; you may say you were paid, not how much or for what. No uploading PoC material anywhere you
do not own (YouTube/Vimeo included, even unlisted). Do not dispute a severity decision.

## Report bar

One issue per report, smallest report that demonstrates it. Steps from a fresh state, the request and
response showing the boundary crossed, attacker vs victim identified. Unnecessary material is read as
an attempt to confuse. No video unless it is the only proof; .webm/.mp4 only. Unreviewed-AI-sounding
reports are closed as **Spam** regardless of correctness.

## Recon already done (2026-09-20, unauthenticated) — see `work/files-com/`

- `app.files.com` — Angular SPA, `Server: files.com`. **Returns 200 + an identical 1344-byte shell
  for every path.** Status is a useless 404 oracle; length/body is the only honest one. A
  `.js.map` request returns that same 1344-byte shell — reading it as "sourcemap exposed" is the
  false positive this baseline exists to prevent. Same shape as [[mine-bundles-from-the-soft-404-shell]].
- API inventory recovered from `main.*.js` (an error-tagging route table): 56 templated routes in
  `work/files-com/api-inventory.txt`. Aim the authenticated pass at `users/{id}/2fa/reset`,
  `users/{id}/unlock`, `bundles/{id}/share`, `remote_servers/{id}/configuration_file.toml`,
  `permissions/{id}`, `previews/{id}`, and the path-typed `files/{path}` `folders/{path}`
  `locks/{path}`.
- `email_preferences/{token}` and `leads/{code}` answer **404, not 401** — unauthenticated
  token-only surfaces. Testable only from a trial site that can mint its own token (replay /
  expiry / reuse is explicitly in scope); guessing codes is excluded brute force.
- Public share links live under `/f/{code}`, with alternative-code path variants.
- **Closed clean, unauthenticated:** REST API uniformly 401 with no data leak; no CORS headers
  emitted at all (no origin reflection, no ACAC); Next.js image optimizer on www.files.com rejects
  every remote/internal/`file:` URL while the relative control fetches (real CLEAR — guard read and
  attack sent); no sourcemaps; CSP on app.files.com is `script-src 'self' 'nonce-…'`; HSTS preload.
- **Informational only:** www.files.com echoes the request `User-Agent` verbatim into an
  `X-User-Agent` response header (`<svg/onload=…>` survives). Not exploitable — it is edge-injected
  after cache retrieval so it is not cacheable, CRLF is rejected, and a response header is not a
  script context. www caps at Low regardless.
