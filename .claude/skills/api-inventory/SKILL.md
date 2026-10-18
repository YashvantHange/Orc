---
name: api-inventory
description: >
  Two plays that find the routes nobody is defending. (1) Shadow/zombie API inventory — enumerate the
  full version history, pull and diff every reachable OpenAPI/Swagger spec including archived ones, and
  behaviorally diff old versions against current for auth, rate-limit and validation regressions.
  (2) SPA bundle route-map — recover a single-page app's entire backend route table from its JS bundles
  and lazy chunks, then test each route unauthenticated against a known-gated control. Load on any
  `url`/`grey` target with versioned paths, multiple specs, or a JS-heavy front end.
---

# API inventory — versions nobody retired, routes nobody guarded

`web-recon` builds the surface you can see. This skill builds the surface the owner forgot: the API
version they stopped maintaining but never turned off, and the route group the auth middleware never
reached. Both plays are `url`/`grey`; on `src` the equivalent is reading the router registration and the
middleware mount points and looking for the same two shapes.

Attribution: adapted from the `hunt-shadow-api` and `hunt-spa-api` skills in
[Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) by Sachin Sharma (content CC-BY-4.0).

**Prerequisite, not optional:** `web-recon-hunter`'s soft-404, unknown-parameter, unauthenticated and
owner baselines must already be recorded. Every interpretation below is a *difference from a baseline*.
Without them this skill manufactures false positives at scale.

---

## Play 1 — shadow and zombie APIs (OWASP API9)

The bug is rarely in one endpoint. It is in the **delta** between what an old version enforces and what
the current version enforces for the same operation, because hardening happens forward-only.

### Stage 1 — enumerate the version surface

Three axes, all three worth walking:

- **Path**: `/api/v1/`, `/v2/`, `/v3/`, `/beta/`, `/alpha/`, `/internal/`, `/legacy/`, `/old/`, and
  date-stamped forms like `/api/2023-01-01/`.
- **Header**: `X-API-Version: 1`, `Accept: application/vnd.<vendor>.v1+json`.
- **Subdomain**: `api-v1`, `apiv1`, `legacy-api`, `old-api`, `internal-api`, `staging-api`.

Compare each response against the soft-404 baseline before recording it as live.

### Stage 2 — collect and diff every spec

Probe the usual spec locations (`openapi.json`, `swagger.json`, `v3/api-docs`, `swagger/v1/swagger.json`,
`.well-known/openapi.json`, and the versioned variants). Then check the Wayback CDX index — a deprecated
version's spec routinely stays archived after the live link is pulled.

When two specs resolve, diff their path inventories and take the set that exists **only in the old spec**.
Every one of those that answers anything other than the 404 baseline against the old base URL is a
zombie-endpoint candidate.

### Stage 3 — behavioral diff, not shape diff

For each operation present in **both** versions, compare security-relevant behavior. A different response
shape or a renamed field is informational; a security regression is the finding.

| Compare | The finding | Severity anchor |
|---|---|---|
| Auth strength — does the old version accept no token, an expired token, or a lower-privilege token the current version rejects? | Auth bypass on the old version | Critical when the operation is sensitive |
| Rate limiting — burst both equivalents; is the `429` missing on the old one? | Anti-automation never backported; chain into credential stuffing or OTP brute force | Medium–High, chain-dependent |
| Input validation — send the identical malformed or injection payload to both | Old version accepts what the new one rejects; chain into whichever injection class the payload targets | High, inherits the chained class |
| Field exposure — internal IDs, other users' data, PII present in the old response | Excessive data exposure | Medium–High |

### Stage 4 — routes the current UI never calls

Grep the JS bundles for API calls no visible flow triggers (`/internal/`, `/admin/`, `/debug/`,
`/_internal/`, `/test/`, `/staging/`). Check `robots.txt` and `sitemap.xml` for disallowed API paths —
a self-inflicted disclosure. Where a mobile client is in scope, its hardcoded endpoints are very often an
older backend version than the web app calls, and every one is a version-diff candidate.

### False-positive gate

- A version difference alone is informational. The finding is the **security-relevant regression**.
- Confirm the old path is not simply an alias or proxy to the current implementation. Send a payload that
  would behave differently under old versus new logic, rather than comparing a version string.
- A `200` serving "this API version is deprecated, use v2" is not a finding. Confirm the underlying
  operation still executes.
- A behaviorally identical old version is `CLEAR`, and say so with the requests that showed it.

---

## Play 2 — the SPA ships its own backend route map

A single-page app is a client to an API, and it hands every visitor the map: hosts, routes, sometimes
keys. The login page being SSO-gated says nothing about whether the API validates the token on every
route. Auth is frequently enforced at the gateway and missing on one route group.

**Do not skip this because the app requires login.** That is precisely when it pays.

### Step 1 — get every bundle, including the lazy ones

Pull the shell and enumerate `/static/js/*.js` (CRA/webpack) or `/_next/static/*` (Next.js). Then note
that the HTML references only runtime, main and vendor — the numbered async route chunks are named
inside `main.js`'s chunk map and fetched at runtime. Grep the chunk-id/hash pairs out of main, reconstruct
the chunk URLs, and download those too. Stopping at HTML-referenced bundles truncates route coverage to
eager chunks. `asset-manifest.json`, where present, lists them all.

### Step 2 — harvest hosts, routes and secrets

Minifiers store routes as **concatenated string segments** (`"account/payment/list"`), not full
`/api/v2/...` URLs, so a naive `/api/v*` grep returns nothing. Grep instead for quoted `resource/action`
strings and filter on the vocabulary that matters — login, user, account, order, billing, invoice,
payment, token, otp, password, reset, admin, profile, auth, upload, export, role, permission, wallet —
then prepend the base yourself. Harvest API hosts separately, including `dev-`, `beta-` and `staging-`
variants, which frequently have weaker auth.

Secrets found in bundles are a lead, not a finding, until validated. Most `AIza…` keys are Maps or
analytics keys with no interesting grant. Establish what the key can actually do before claiming impact.
Bundle and sourcemap *exposure* itself is `web-playbooks` § "JS bundle & sourcemap exposure", owned by
web-recon-hunter — do not double-report it here.

### Step 3 — establish a control before you claim anything

Send an unauthenticated request to an endpoint you *expect* to be gated and capture what correct
rejection looks like on this stack. A sibling route group on the same host is the ideal control: same
framework, so a different response is a real authorization gap rather than a quirk.

### Step 4 — test each route family unauthenticated, on both methods

Compare every response to that control:

| Response | Reading |
|---|---|
| `401`, or an explicit "missing authorization" | Gated. Move on. |
| `200` with data | Unauthenticated data exposure. **Finding.** |
| `400 "field X is mandatory"` | The route reached *business-logic validation* without an auth check. **Auth bypass** — supply the field minimally to confirm. |
| `200` plus a verbose DB or stack error | Reached the data layer unauthenticated; also a SQLi-surface signal. |
| Mandatory fields named `is_admin`, `is_internal`, `requested_by`, `role_id`, `account_type` | Authorization derived from client-supplied parameters. Set the flag and you self-elevate. Critical class. |

### Step 5 — pivot, then stop

IDs returned by one endpoint are the keys the others consume, and they prove the whole router is
reachable rather than one lucky route. Check whether `Access-Control-Allow-Origin: *` compounds it, which
lets any web origin read the response from a victim's browser.

Then stop at minimum-necessary proof. A handful of records, or a `totalCount`, confirms the missing check.
Do not enumerate the table — `disclosure-ethics` caps you at n=1 on another user's data, and the finding is
the absent check, not the volume. **Never** use a create, signup or upload endpoint as the proof: read
endpoints demonstrate the gap without writing state.

### Anti-patterns

- "The app requires login, so the API must be protected." Test the API directly, bare. That is the play.
- "It is minified, I cannot read it." You do not need to read it. Grep it.
- "`/api/v1/foo` 404'd, so there is no API." Wrong base or wrong method. Try `/api/`, `/api/v2/`, POST
  instead of GET, and the exact route strings from the bundle.
- "Found an `AIza` key, that is critical." Validate the grant first.
- Dumping the dataset once you get a 200.

---

## Closing

Play 1 hits land on matrix row **E · API & protocol** (and whatever class the regression chains into);
play 2 hits land on **A · Missing function-level authz (BFLA)** or **A · Authentication bypass**, owned by
authz-logic-hunter and authn-crypto-hunter. Qualify every verdict with the enumeration tuple — endpoints
× parameters × methods × identities × versions — plus the transcript id range and the defense you observed.
Then run `chain-craft` on any confirmed hit, and `reasoning-checklist` before calling it a finding.
