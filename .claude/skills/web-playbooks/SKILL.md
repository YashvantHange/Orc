---
name: web-playbooks
description: >
  Per-class hunting playbooks for the web, protocol, API and client-side vulnerability classes —
  CSRF, clickjacking, host-header injection, cache poisoning and deception, request smuggling,
  method override, subdomain takeover, prototype pollution, postMessage, WebSocket, GraphQL,
  OAuth/OIDC, SAML, session lifecycle, password reset and MFA, rate limiting, business logic,
  second-order injection, DOM XSS, CSP, cookies, CORS variants, and JS bundle/sourcemap exposure.
  Load when hunting a live website (kind url/grey) or any of these classes in source.
---

# Web & client-side playbooks

Companion to `vuln-playbooks` — same entry shape (**source → sink → bypass → confirm → CWE**), same
rules. The coverage matrix that says which of these you must sweep lives in `vuln-playbooks`; the CWE
table is `cwe-map`; surface enumeration for a black-box target is `web-recon`.

**Every Confirm line here is a request you can type.** `hunt web probe --primitive <name>` runs the
same check and files the evidence, but the curl is the specification — if the helper is missing a
primitive, or you are working from a phone, the class is still coverable. `$T` is the target origin,
`$M` the engagement marker (`probe-9c2f` by default — see `marker-conventions`).

**Before any request to a host you don't own**, read `disclosure-ethics` and verify the scope
(`hunt scope --file work/<slug>/scope.yml --lint`). Three classes here — cache poisoning, cache
deception and request smuggling — can serve your payload to a real user. They are **detection-only**;
each says how below, and none of them is optional reading.

**The FP rule for every class in this file.** A live target lies to you in ways source never does: SPAs
answer HTTP 200 for paths that don't exist, WAFs answer instead of the app, and CDNs answer instead of
both. Before believing any signal, get the three baselines from `web-recon` — a random path, a random
parameter, and the same request unauthenticated — and show your "hit" differs from all three. A finding
you can't distinguish from the soft-404 is not a finding.

---

## CSRF  (the classic false-positive factory — read the cookie first)
A missing CSRF token is only a bug if the browser would actually attach the session. Modern defaults
(`SameSite=Lax`) already block cross-site POSTs; claiming CSRF without checking the cookie attribute is
the single most common invalid web report.
- Source: an attacker-controlled page in the victim's browser, cross-site.
- Sink: any state-changing endpoint that authenticates by ambient credential (cookie, Basic, NTLM,
  client cert) rather than by a value the attacker cannot read.
- **Check the cookie first:** `SameSite=None` → cross-site sends it, live. `SameSite=Lax` → only
  top-level GET navigations, so a Lax-session app is exploitable via a state-changing **GET** or via a
  method the browser treats as a navigation. `SameSite=Strict` → cross-site is dead; look for a
  same-site subdomain XSS or an open redirect to chain instead. No attribute at all → browser default
  is Lax, but non-browser clients and older embedded webviews still send it.
- Bypass: token present but never validated server-side; token validated only when the header exists
  (drop it → passes); token not bound to the session (use your own); `Referer` check that passes on a
  missing `Referer` (`<meta name="referrer" content="no-referrer">`) or on a substring match
  (`https://evil.com/?x=trusted.com`); JSON endpoints that also accept
  `Content-Type: application/x-www-form-urlencoded` (form-postable, no preflight); method override
  (see below) turning a blocked verb into a form POST; a state-changing endpoint that accepts GET.
- Confirm: replay the state-changing request with the session cookie, **no token, and a foreign
  `Origin`/`Referer`**, writing a benign marker to *your own* object; then re-read the object.
  ```bash
  curl -i -X POST "$T/api/profile" -b "session=$SESSION" \
       -H "Origin: https://evil.example" -H "Referer: https://evil.example/" \
       -H 'Content-Type: application/x-www-form-urlencoded' -d "display_name=$M"
  curl -s "$T/api/profile" -b "session=$SESSION" | grep -o "$M"   # persisted -> confirmed
  ```
  Report the cookie's `Set-Cookie` line verbatim in the evidence; the reviewer will look for it.
- CWE-352 (CSRF). If the enabling flaw is the missing/permissive `SameSite`, name CWE-1275 as secondary.

## Clickjacking / UI redress
- Source: the victim's browser, framing your target from an attacker origin.
- Sink: any authenticated, state-changing UI control reachable in one click (delete, transfer, grant,
  "authorize app", MFA-enrol).
- Bypass: `X-Frame-Options` present on the login page but absent on the sensitive one — **check the
  actual sensitive path, never the root**; `frame-ancestors` missing from CSP while XFO is `ALLOW-FROM`
  (unsupported by every modern browser, therefore no protection); `SAMEORIGIN` plus a same-origin
  open redirect or an iframe-able subdomain; framebusting JS defeated by `sandbox="allow-scripts"`
  (blocks top navigation, still runs the page).
- Confirm: header read first, then a real browser to prove the frame renders — a missing header is a
  weakness, a rendered frame is the finding.
  ```bash
  curl -sI "$T/settings/delete-account" | grep -iE 'x-frame-options|content-security-policy'
  ```
  Then load a local page containing `<iframe src="$T/settings/delete-account" width=800 height=600>`
  and screenshot it with the control visible. Without the screenshot this is a header-posture note.
- CWE-1021 (improper restriction of rendered UI layers).

## Method override
- Source: `X-HTTP-Method-Override`, `X-Method-Override`, `_method` in a form body or query string.
- Sink: a framework that rewrites the verb *before* routing and authorization run (Symfony, Rails,
  Express `method-override`, many API gateways) — the guard sees POST, the router sees DELETE.
- Bypass: this **is** the bypass. Use it to reach a verb the scope or the app denies, to defeat a
  CSRF/CORS policy that only guards non-simple methods, and to reach handlers a WAF filters by verb.
- Confirm: a verb that 405s or 403s directly, succeeding through the override.
  ```bash
  curl -i -X PUT   "$T/api/items/1" -b "session=$SESSION"                     # expect 405/403
  curl -i -X POST  "$T/api/items/1" -b "session=$SESSION" \
       -H 'X-HTTP-Method-Override: PUT' -d '{"name":"'"$M"'"}'                # succeeded -> confirmed
  ```
  Note the scope guard's method allow-list applies to the *real* verb you send; do not use override to
  smuggle past your own authorization file.
- CWE-650 (trusting HTTP verb method). Pair with CWE-352 or CWE-862 when it defeats a specific guard.

## Host-header injection & password-reset poisoning
- Source: `Host`, `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, absolute-URI request lines.
- Sink: anywhere the app builds an absolute URL from the request rather than from configuration —
  password-reset links, email verification, `<base href>`, `Location:` redirects, OAuth
  `redirect_uri` construction, cache keys, HMAC-signed callback URLs.
- Bypass: `Host: evil.example` outright; `X-Forwarded-Host` when a proxy normalizes `Host`; a dual
  header (`Host: real\r\nHost: evil`); port injection (`Host: real:@evil.example`); an absolute request
  line (`GET https://evil.example/reset HTTP/1.1`) which some stacks prefer over `Host`.
- Confirm: request a reset for **an account you control**, with the header set; read the link in *your*
  inbox. Never trigger a reset for someone else's account — that is a real email to a real person.
  ```bash
  curl -i -X POST "$T/api/password/reset" -H "Host: evil.example" \
       -H 'Content-Type: application/json' -d '{"email":"you+test@yourdomain"}'
  # then: does the received link point at evil.example?
  ```
  Reflection into `<base href>` or `Location` is confirmable with one request and no email at all —
  prefer that when it exists.
- CWE-644 (improper neutralization of HTTP headers). Secondary: CWE-640 when it yields account
  takeover via reset, CWE-601 when it only redirects.

## Web cache poisoning  (**detection only — a poisoned entry is served to strangers**)
- Source: an *unkeyed* input — a header the origin reflects but the cache doesn't include in its key
  (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Rewrite-URL`, custom `X-*`), or an
  unkeyed query parameter.
- Sink: the shared cache (CDN, reverse proxy, `Cache-Control: public`) storing a response containing
  attacker-controlled content for a URL other users request.
- Bypass: cache-key normalization gaps (case, trailing slash, `;` params, duplicate params); `Vary`
  omitting the reflected header; fat-GET (a GET with a body that the origin reads and the cache ignores).
- Confirm safely — **always on a URL only you will request**, i.e. append a unique cache-buster, and
  never on a real page path:
  ```bash
  CB="cb=$RANDOM$RANDOM"
  curl -si "$T/?$CB" -H "X-Forwarded-Host: $M.evil.example" | grep -iE 'x-cache|age|'"$M"
  curl -si "$T/?$CB"                                        | grep -iE 'x-cache|age|'"$M"
  # marker present on the SECOND, header-free request + X-Cache: HIT / Age > 0 -> confirmed
  ```
  That proves the class on a key nobody else uses. **Do not** repeat it without the buster to "show
  real impact" — the impact argument is written, not demonstrated. If the finding requires poisoning a
  live path to be believed, report it as detected-not-exploited and say why.
- CWE-524 (use of cache containing sensitive information). Secondary CWE-444 when the desync is the
  cause rather than an unkeyed header.

## Web cache deception
- Source: a path suffix the *cache* treats as a static asset and the *origin* ignores while still
  serving authenticated content.
- Sink: the shared cache storing a logged-in user's page under a URL an unauthenticated attacker can
  fetch.
- Bypass: `/account/nonexistent.css`, `/account%2Fx.js`, `/account;x.css`, `/account/.css`,
  `/account?x=.css` — whichever the origin's router normalizes away. Works when the origin returns 200
  for the padded path (many frameworks do, via a catch-all route or a lenient trailing-segment match).
- Confirm: two sessions, and the second one is the proof.
  ```bash
  curl -si "$T/account/$M.css" -b "session=$SESSION" | head -20      # your data + cacheable headers?
  curl -si "$T/account/$M.css"                       | grep -o "$M\|your-username"   # no cookie
  ```
  The unauthenticated fetch returning the authenticated body is the finding. Use a marker-suffixed
  filename so the poisoned entry is one only you will ever request.
- CWE-525 (use of web browser cache containing sensitive information).

## Request smuggling  (**detection only — never drive a desync on production**)
- Source: disagreement between a front-end proxy and a back-end server about where a request ends —
  `Content-Length` vs `Transfer-Encoding`, or two `Content-Length`s.
- Sink: the back-end's request queue: the next user's request gets your prefix.
- Bypass classes: CL.TE, TE.CL, TE.TE (obfuscated `Transfer-Encoding: chunked ` / `xchunked` /
  `\tchunked` / duplicated), CL.0, plus HTTP/2 downgrade variants (H2.CL, H2.TE) where the front-end
  rewrites h2 to h1.
- Confirm: **timing only.** A CL.TE candidate makes the back-end wait for a body that never arrives, so
  the *same* request that returns instantly normally now hangs. Compare medians, don't act on one
  sample, and stop at the timing delta.
  ```bash
  # baseline
  for i in 1 2 3; do curl -so /dev/null -w '%{time_total}\n' "$T/"; done
  # CL.TE probe: front-end uses CL, back-end uses TE -> back-end blocks awaiting the next chunk
  printf 'POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n' "$HOST" \
    | timeout 12 openssl s_client -quiet -connect "$HOST:443" 2>/dev/null | head -5
  ```
  A reproducible multi-second delay that the baseline doesn't show is a **candidate**, and a candidate
  is what you report. Do **not** send a follow-up request to capture another user's traffic, and do not
  smuggle a prefix that alters anyone's response — both harm bystanders. Say plainly in the report:
  "detected by differential timing; exploitation not attempted, as a successful desync affects other
  users of the shared front-end."
- CWE-444 (inconsistent interpretation of HTTP requests).

## Subdomain takeover  (**detection only — never claim the dangling resource**)
- Source: a DNS record (CNAME, NS, or an A record into a cloud range) pointing at a deprovisioned
  third-party resource.
- Sink: the provider handing the hostname to whoever registers it next — full same-site position:
  cookies scoped to the parent domain, CSP/`frame-ancestors` allowances, SSO redirect allow-lists,
  `SameSite=Lax` cookies (a sibling subdomain is same-site).
- Bypass: none needed; the signal is the provider's "no such bucket / app / space" fingerprint served
  over the target's hostname.
- Confirm: resolve, then fingerprint. Stop there.
  ```bash
  dig +short CNAME sub.target.example
  curl -si https://sub.target.example/ | head -20     # provider's unclaimed-resource page?
  ```
  Report the CNAME, the provider, and the fingerprint string. **Registering the resource to "prove" it
  is claiming an asset you were not authorized to hold** — it is also how a researcher ends up owning
  someone's traffic. If the program explicitly requires a claim as proof, get that in writing first.
- CWE-350 (reliance on reverse DNS in a security decision) for the DNS-trust framing; many programs
  file it as CWE-284. Say which and why.

## CORS variants
Extends the base CORS check in `vuln-playbooks` → Secrets exposure. The header being present is not
the finding; the header being present **with credentials, for an origin the attacker controls** is.
- Source: the `Origin` request header.
- Sink: `Access-Control-Allow-Origin` reflected + `Access-Control-Allow-Credentials: true`, letting
  any page read authenticated responses cross-origin.
- Bypass: full reflection of arbitrary `Origin`; `null` accepted (reachable from a sandboxed iframe or
  a `data:` URL, which is why `null` is never safe); prefix/suffix matching
  (`https://target.example.evil.com`, `https://evil-target.example`); scheme downgrade (`http://` accepted);
  a same-site subdomain that is itself XSS-able or takeover-able; ACAO correct on preflight but wrong on
  the actual response; **missing `Vary: Origin`**, which turns a correct per-origin policy into a cache
  that hands one origin's ACAO to another.
- Confirm: one request per variant; the pair of headers in the response is the whole proof.
  ```bash
  for O in "https://evil.example" "null" "https://$T.evil.example" "http://${T#https://}"; do
    echo "== $O"; curl -si "$T/api/me" -H "Origin: $O" -b "session=$SESSION" \
      | grep -iE 'access-control-allow-(origin|credentials)|^vary'
  done
  ```
  Reflected origin **plus** `allow-credentials: true` = confirmed. ACAO `*` with credentials is
  rejected by browsers — that is a hardening note, not a vulnerability; say so rather than reporting it.
- CWE-942 (permissive cross-domain policy). Secondary CWE-346 (origin validation error).

## Cookie flags & scope
- Source: `Set-Cookie` on login and on every subsequent state change.
- Sink: the session cookie itself — readable by JS (`HttpOnly` missing), sent over plaintext (`Secure`
  missing), sent cross-site (`SameSite=None`), or shared with every sibling subdomain
  (`Domain=.target.example`, which makes any subdomain XSS a full session compromise).
- Bypass / nuance: flags set correctly at login but dropped on refresh/rotate; `__Host-` prefix claimed
  without meeting its rules; a JS-set duplicate of an `HttpOnly` cookie; cookie-jar overflow or a
  `Domain`-scoped cookie shadowing a `__Host-` one (cookie tossing).
- Confirm: read the raw header, and read it in a browser too — `document.cookie` shows what JS can
  actually reach, which is authoritative when a second `Set-Cookie` overwrites the first.
  ```bash
  curl -si -X POST "$T/api/login" -d '{"username":"you","password":"..."}' \
       -H 'Content-Type: application/json' | grep -i '^set-cookie'
  ```
- CWE-1004 (`HttpOnly` missing), CWE-614 (`Secure` missing), CWE-1275 (`SameSite` too permissive).
  Alone these are hardening notes; report them as a finding when chained (with an XSS, a subdomain
  takeover, or a CSRF) and say what the chain is.

## CSP weakness
- Source: the `Content-Security-Policy` header or `<meta>` equivalent.
- Sink: what the policy fails to stop — an injected script that runs anyway.
- Bypass: `unsafe-inline` in `script-src`; `unsafe-eval` plus a client-side template engine; a
  wildcard or a CDN host that serves attacker-hostable content (JSONP endpoints, user content buckets,
  `cdnjs`-style hosts with an AngularJS build); `object-src` unset (Flash/PDF vectors);
  `base-uri` unset (a `<base>` injection re-points every relative script); `frame-ancestors` unset
  (see Clickjacking); a nonce that is static across responses, or reflected into the page.
- Confirm: read the policy, then prove it doesn't stop your marker — a weak policy is only a finding
  when you can show the injection it fails to contain.
  ```bash
  curl -sI "$T/" | grep -i content-security-policy
  ```
  Pair with an actual XSS attempt; in a browser, an empty `securitypolicyviolation` event log while
  your payload executes is the proof.
- CWE-693 (protection mechanism failure). The XSS it enables carries the primary CWE-79.

## DOM XSS  (execution, not reflection)
Extends `vuln-playbooks` → XSS. Server-side reflection checks miss this entirely; string-matching the
response body proves nothing here, because the sink runs on data the server never saw
(`location.hash` is not sent to the server at all).
- Source (client): `location.hash`/`search`/`pathname`, `document.referrer`, `window.name`,
  `postMessage` data, `localStorage`/`sessionStorage`, a WebSocket frame, a JSON API field rendered
  without escaping.
- Sink (client): `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`,
  `Function`, `setTimeout`/`setInterval` with a string, `element.src`/`href` set to `javascript:`,
  jQuery `$(...)`/`.html()`, `dangerouslySetInnerHTML`, Vue `v-html`, Angular `bypassSecurityTrust*`.
- Bypass: a sanitizer applied to the *server*-rendered value while the DOM path is unsanitized;
  DOMPurify with `RETURN_DOM_FRAGMENT` mishandled, an outdated version, or a config allowing
  `<svg><style>`; a framework's escaping skipped for "trusted" internal URLs; mutation XSS.
- Confirm: **the payload has to execute.** Find the source→sink pair in the JS bundle (`web-recon`
  mines these), then load the URL in a real browser with `alert` overridden by an instrumented hook,
  or with the marker written into `document.title`:
  ```
  $T/app#/search?q=<img src=x onerror="document.title='xss-probe-9c2f'">
  ```
  Evidence = the changed title / the fired hook / a screenshot, plus the bundle line showing the sink.
  A reflected-string match with no execution is a lead, not a finding.
- CWE-79 (XSS). Add CWE-83 for attribute-context injection when that's the vector.

## Client-side path traversal & DOM open redirect
- Source: a URL fragment or parameter the front-end concatenates into a request path or a navigation.
- Sink: `fetch("/api/" + userInput)` (traversal into a different API route, carrying the session and
  CSRF token), `location = userInput`, `window.open(userInput)`, a router `redirect` param.
- Bypass: `../` in a path segment the front-end doesn't normalize; a protocol-relative `//evil.example`
  that `location=` treats as an absolute URL; `javascript:` where the sink is `href`.
- Confirm: watch the network panel (or the transcript) for a request to the *unintended* endpoint, or
  a navigation to a foreign origin, driven purely by a URL you control. Chain-worthy: client-side
  traversal is how a CSRF-token-bearing request gets aimed at an endpoint the attacker chooses.
- CWE-22 for the traversal, CWE-601 for the redirect.

## postMessage origin confusion
- Source: `window.postMessage` from an attacker-controlled frame or opener.
- Sink: a `message` listener that acts on `event.data` — writing it to a DOM sink, storing a token,
  calling an authenticated API, or changing app state.
- Bypass: no `event.origin` check at all; `indexOf`/`startsWith`/`includes` matching
  (`https://target.example.evil.com` passes `startsWith("https://target.example")` reversed, and
  `includes("target.example")` passes for anything); a regex missing anchors or with an unescaped `.`;
  origin checked but `event.source` not, allowing a different frame on an allowed origin. The mirror
  image is a **sender** bug: `postMessage(secret, "*")` leaks to whoever framed you.
- Confirm: enumerate listeners, then post from a foreign origin and show the handler acted.
  ```js
  // in the attacker page, after opening the target in an iframe:
  frames[0].postMessage({type:"setName", value:"probe-9c2f"}, "*");
  ```
  Proof = the target's state changed / the marker rendered / a request fired. Also grep the bundle for
  `addEventListener("message"` and read the first ten lines of each handler — a missing origin check is
  visible in source even before you fire anything.
- CWE-346 (origin validation error). If it lands in an HTML sink, primary becomes CWE-79.

## Prototype pollution (client and server)
- Source: any recursive merge/clone/`set`-by-path of attacker-controlled JSON or query string —
  `__proto__`, `constructor.prototype`, `constructor[prototype]` keys.
- Sink (client): a polluted `Object.prototype` property later read as config by a template/DOM
  routine — classic gadgets: `srcdoc`, `innerHTML`, `template`, `sanitizer` options, jQuery
  `$.ajax` options, a router's `hooks`.
- Sink (server): the same pollution reaching `child_process` options (`shell`, `env`, `NODE_OPTIONS`),
  a template engine's compile options (→ RCE), or an authorization object gaining an `isAdmin`.
- Bypass: `JSON.parse` reviver skipped; a deny-list for `__proto__` that misses `constructor.prototype`;
  query-string parsers with `a[__proto__][x]=1` bracket syntax; `Object.create(null)` used for the
  target but not the source.
- Confirm: pollute, then read the property off an unrelated fresh object — that is unambiguous and
  benign.
  ```bash
  curl -i -X POST "$T/api/settings" -H 'Content-Type: application/json' \
       -d '{"__proto__":{"'"$M"'":"polluted"}}'
  ```
  Then in the app (client) `({}).probe_9c2f` returns `"polluted"`, or (server) a subsequent unrelated
  endpoint reflects the injected key. Escalate only to a gadget that changes *observable* behavior,
  never to command execution on a live host.
- CWE-1321 (prototype pollution). Secondary: whatever the gadget reaches (CWE-79, CWE-78, CWE-94).

## GraphQL
- Source: a single `/graphql` endpoint that multiplexes the entire API — one URL, hundreds of
  operations, each with its own authorization requirement.
- Sink: resolvers. Authorization applied at the HTTP layer protects nothing, because every operation
  arrives as the same `POST /graphql`.
- Bypass classes, each its own check:
  - **Introspection enabled in production** → the schema, which is the endpoint inventory.
  - **Field-level authz gaps** — the object-level check passes, then a nested field
    (`user { email paymentMethods { last4 } }`) is resolved without one. This is the highest-yield
    GraphQL bug and it is invisible to any HTTP-layer scanner.
  - **Batching / aliasing** → hundreds of mutations in one HTTP request, defeating per-request rate
    limits and lockouts (brute-force MFA in one round trip).
  - **Depth / complexity unbounded** → a self-referential query as a resource-exhaustion class
    (measure the complexity, do **not** fire it at production; see `disclosure-ethics`).
  - **Introspection disabled but suggestions on** — Apollo's "Did you mean" leaks field names; the
    schema is recoverable a character at a time (clairvoyance).
  - **Mutations reachable via GET** → makes every mutation CSRF-able.
- Confirm:
  ```bash
  curl -s "$T/graphql" -H 'Content-Type: application/json' \
       -d '{"query":"{__schema{queryType{name}}}"}'                       # introspection
  curl -s "$T/graphql" -H 'Content-Type: application/json' -b "session=$LOWPRIV" \
       -d '{"query":"{user(id:2){id email}}"}'                            # field-level authz
  curl -s "$T/graphql" -H 'Content-Type: application/json' \
       -d '{"query":"{a:user(id:1){id} b:user(id:2){id} c:user(id:3){id}}"}'  # aliasing
  ```
- CWE-200 (introspection/info exposure), CWE-863 (field-level authz), CWE-770 (batching/depth
  resource limits). Pick by which one the report is actually about.

## WebSocket auth & origin
- Source: the upgrade handshake, and every frame after it.
- Sink: a socket that authorizes at connect time and then trusts every frame, or authorizes at neither.
- Bypass: no `Origin` validation on upgrade (cross-site WebSocket hijacking — the browser attaches
  cookies to a WS handshake and there is no preflight to save you); auth checked on connect but the
  per-message `userId`/`room` taken from the frame; a token in the query string (logged by every proxy);
  authorization inherited from an HTTP session that has since been revoked.
- Confirm: connect from a foreign origin with the victim's cookie jar and read a frame you shouldn't get.
  ```python
  import websockets, asyncio
  async def go():
      async with websockets.connect(f"{WS}/socket", origin="https://evil.example",
                                    extra_headers={"Cookie": f"session={SESSION}"}) as ws:
          await ws.send('{"action":"subscribe","room":"other-users-room"}')
          print(await ws.recv())          # another principal's data -> confirmed
  asyncio.run(go())
  ```
- CWE-346 (origin validation) for CSWSH; CWE-862 when per-message authorization is simply absent.

## OAuth & OIDC
- Source: the authorization request and the callback, both attacker-influenceable.
- Sink: the token exchange and the session it mints.
- Bypass, in yield order:
  - **`redirect_uri` validation** — prefix match (`https://target.example.evil.com`), path append
    (`/callback/../../open-redirect`), a registered URI plus an open redirect on the same host, `%2F`
    and `#` normalization gaps, `localhost` allowed in production. This is how the code leaks.
  - **`state` missing or unverified** → login CSRF: the victim ends up in *your* account, and whatever
    they do next (add a card, upload a doc) is yours.
  - **PKCE downgrade** — the server accepts a token request without `code_verifier` when the
    authorization request had `code_challenge`.
  - **Implicit flow leakage** — token in the fragment, exfiltrated via `Referer` from a third-party
    resource on the callback page.
  - **`code` reuse** — a code accepted twice, or after logout.
  - **ID-token trust** — `alg:none`, unverified signature, `aud`/`iss` unchecked, `email_verified`
    ignored so an attacker-registered IdP account with the victim's email links to their account.
  - **Account linking by unverified email** — sign in with an IdP claiming the victim's address.
- Confirm: use two accounts you control; the proof is that account A's session ends up bound to
  account B's identity, or that the code arrives at a host you control. Never intercept another
  person's flow.
- CWE-601 (redirect), CWE-352 (missing `state`), CWE-347 (ID-token signature), CWE-1390 (weak
  authentication) for the linking case.

## SAML
- Source: the base64 `SAMLResponse` POSTed to the ACS endpoint.
- Sink: the assertion parser and the identity it trusts.
- Bypass: signature not verified at all; signature verified on the *response* while the *assertion* is
  swapped (XSW — XML signature wrapping, with about eight documented arrangements: test each);
  signature exclusion (strip `<ds:Signature>` and see if it still authenticates); XML comment
  truncation in `NameID` (`admin<!---->@evil.com` parsed as `admin@` by some libraries); `Recipient`,
  `Audience`, `NotOnOrAfter` unchecked; the IdP certificate taken from the assertion itself; XXE in
  the parser (see `vuln-playbooks` → XXE); replay of a captured assertion.
- Confirm: with an account you control, mutate one field at a time and see which mutation is still
  accepted. Changing `NameID` to another *test* account you own and being logged in as it is the
  finding — never target a real user's `NameID`.
- CWE-347 (improper verification of cryptographic signature). Secondary CWE-290 (spoofing).

## Session fixation & lifecycle
- Source: a session identifier the attacker can set or predict before the victim authenticates.
- Sink: the post-login session — if the id doesn't rotate, the attacker's pre-set id is now authenticated.
- Bypass / what to test: id unchanged across login; id accepted from a query parameter or a path
  segment (a link is enough to fix it); logout that clears the cookie client-side but leaves the
  server session valid (replay the old cookie after logout); a session that survives a password
  change; no absolute or idle timeout; concurrent sessions never invalidated; "remember me" tokens
  that are deterministic or non-revocable; a JWT-based session with no revocation list at all, so
  logout is fiction.
- Confirm: three requests.
  ```bash
  curl -si "$T/login" | grep -i set-cookie                    # pre-auth id  -> S1
  curl -si -X POST "$T/api/login" -b "session=$S1" -d '...' | grep -i set-cookie   # post-auth -> S2
  # S1 == S2  -> fixation. Then, after logging out, replay S2:
  curl -si "$T/api/me" -b "session=$S2"                       # 200 -> session not invalidated
  ```
- CWE-384 (session fixation), CWE-613 (insufficient session expiration).

## Password reset & MFA bypass
- Source: the reset token, the OTP, and the state machine that gates them.
- Sink: an authenticated session for an account you don't own.
- Bypass — reset: token predictable (timestamp, sequential, MD5 of the email — collect two and
  compare structure/entropy); token not bound to the account (use yours on their id); token not
  single-use or not expiring; the reset endpoint accepting an `email` array or a second `email`
  parameter so the mail also goes to you; host-header poisoning of the link (above); the user id sent
  alongside the token and trusted; leaking the token in the `Referer` to a third-party asset on the
  reset page.
- Bypass — MFA: the verification step returning a session before the second factor; the second-factor
  endpoint not rate-limited (see below) or bypassable by omitting the parameter; a "remember this
  device" cookie that is forgeable; the OTP validated client-side; the pre-2FA token already having
  full API scope; backup codes not invalidated; a password reset that logs you in *without* 2FA —
  the most common real MFA bypass.
- Confirm: two accounts you own. Drive the flow for account A and finish it as account B, or complete
  the login for an account whose second factor you never satisfied. Stop at the first success.
- CWE-640 (weak password-recovery), CWE-330 (insufficiently random values), CWE-303 (incorrect
  implementation of authentication algorithm) for MFA.

## Rate limiting / anti-automation
- Source: any endpoint where guessing is the attack — login, OTP, reset, coupon, invite code,
  id enumeration, SMS/email send (which also costs the target money).
- Sink: the absence of a counter, or a counter keyed on something the attacker controls.
- Bypass: limit keyed on `X-Forwarded-For` (rotate it); on the account rather than the IP (spread
  across accounts — password spraying) or vice versa; case/whitespace variants of the identifier
  treated as distinct; a limit on the HTML form but not the JSON API, or not on the GraphQL mutation;
  batching (one HTTP request, 100 aliased attempts — see GraphQL); the counter reset by a successful
  request interleaved between failures.
- Confirm: **this class conflicts with your own scope limits.** The engagement's `limits.rps` may be
  slower than the app's threshold, in which case a handful of requests proves nothing and the honest
  verdict is `BLOCKED` — say "scope permits 2 rps; the lockout threshold could not be reached without
  exceeding it". Where the scope does permit it, a modest run with **deliberately wrong** credentials
  for an account you own, and no `429`/lockout/CAPTCHA anywhere in the responses, is the evidence.
  Never spray real accounts, never lock a real user out.
- CWE-307 (improper restriction of excessive authentication attempts), CWE-799 (improper control of
  interaction frequency).

## Business logic & workflow abuse
No scanner finds these and no signature describes them; they come from reading what the application is
*for* and asking what an adversarial user would do.
- Source: values the client sends that the server should compute — price, quantity, currency,
  discount, tier, recipient, timestamp, status.
- Sink: the state machine that trusts them.
- The questions worth asking, concretely: can quantity be negative or fractional (a refund)? can price
  or currency be client-supplied? do discounts stack, or apply twice? can a step be skipped (POST
  straight to `/checkout/complete`)? can a step be replayed? does the total get re-validated after the
  cart changes? can a paid feature be enabled by the field that renders the UI? can you act on another
  tenant's object id inside your own workflow? does cancelling after fulfilment refund without
  reversing? are limits (invites, seats, API keys) enforced on the server or only greyed out in the UI?
- Bypass: the whole class *is* the bypass — send the request the UI would never let you build.
- Confirm: complete the abusive flow end-to-end on **your own** account with the smallest possible
  value (1 cent, 1 unit, a free tier) and show the resulting state. Never leave real financial state
  changed; reverse what you can and say what you couldn't in the report.
- CWE-840 (business logic errors); prefer a more specific id when one fits (CWE-472 for
  externally-controlled assumed-immutable parameters, CWE-863 for incorrect authorization).

## Second-order injection
- Source: data stored now, executed later — a profile field, a filename, a log line, an import row,
  a webhook name — that passes validation on the way in because the *inbound* context is harmless.
- Sink: the later consumer that trusts stored data as trusted-by-provenance: an admin dashboard
  rendering it as HTML, a report generator building SQL from it, a batch job passing it to a shell, a
  templating step, a CSV export opened in Excel (formula injection: a cell starting `=`, `+`, `-`, `@`).
- Bypass: the entire premise — the validator runs at the boundary and the sink runs behind it. Look
  for any place the app writes a value and reads it back with a different parser.
- Confirm: plant `$M` shaped for the *destination* parser, then trigger the consumer and observe the
  destination. The two halves are usually different endpoints, sometimes different users, sometimes a
  cron. Say in the evidence exactly which action triggered the second half.
- CWE-79 / CWE-89 / CWE-78 per sink; note "stored/second-order" explicitly in the title, because it
  changes the fix.

## SSRF via renderers
Extends `vuln-playbooks` → SSRF. The highest-yield SSRF on a modern web app usually isn't a `url=`
parameter — it's a feature that fetches on your behalf.
- Source: HTML/Markdown converted to PDF, a URL preview/unfurl, a screenshot or thumbnail service, a
  webhook you register, an avatar-by-URL import, an SVG or XML upload, a "import from URL" feature,
  an SSO metadata URL, an LLM tool that fetches pages.
- Sink: the headless browser or fetcher, running inside the target's network with its metadata service
  and internal hosts reachable.
- Bypass: the renderer follows redirects the validator never saw (validate then fetch = TOCTOU); it
  loads sub-resources (`<img src>`, `<link>`, `@import`, `<iframe>`) that were never validated;
  `file://` in an `<img>` or an XSL reference; the DNS-rebinding path (`vuln-playbooks` →
  Allowlist DNS-rebinding); `gopher://`/`dict://` where curl backs the fetch.
- Confirm: point it at a listener you control and prove the callback, then stop.
  ```html
  <!-- submitted to the PDF/preview feature -->
  <img src="http://YOUR-LISTENER/probe-9c2f">
  ```
  A hit proves server-side fetch. Reading cloud metadata proves severity — take **one** request, redact
  the response, and do not use any credential you receive.
- CWE-918 (SSRF).

## Signed-URL / presigned-upload abuse
- Source: a URL the server signs on the client's behalf — S3/GCS presigned PUT, a CDN token, a
  download link.
- Sink: the object store. Once signed, the storage layer enforces the signature, not your app's
  authorization.
- Bypass: the key/path taken from the client (write into another tenant's prefix, or overwrite a model
  artifact / config / static JS the app itself serves); no content-type or size condition in the
  policy; expiry too long or unbounded; the signing endpoint itself unauthenticated or missing an
  ownership check; a signed GET whose key parameter is user-controlled (read anyone's object).
- Confirm: ask for a signed URL naming a path outside your own prefix, and see whether the server
  signs it at all — **the signature is the finding**; you do not have to complete the PUT. If you must,
  write a marker file to a fresh key you own and delete it.
  ```bash
  curl -s "$T/api/uploads/presign" -b "session=$SESSION" \
       -H 'Content-Type: application/json' -d '{"key":"../other-tenant/probe-9c2f.txt"}'
  ```
- CWE-639 (authorization bypass through user-controlled key), CWE-434 when it lands as an
  unrestricted upload the app later serves.

## Header posture
Not a vulnerability by itself — the context that decides whether the ones above are exploitable, and
the cheapest first request of any hunt.
- Read on the **authenticated, sensitive** page, not the marketing root: `Content-Security-Policy`,
  `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy`,
  `Permissions-Policy`, `Cache-Control` on authenticated responses, `Access-Control-*`, `Set-Cookie`,
  `Server`/`X-Powered-By` version disclosure.
- ```bash
  curl -sI "$T/account" -b "session=$SESSION"
  ```
- Report these as a single low-severity hardening note, or as the enabling condition inside a real
  finding — never as ten separate submissions. `Cache-Control: public` on an authenticated response is
  the one that is often a finding on its own; it is also the precondition for cache deception.
- CWE-693 (protection mechanism failure), CWE-200 / CWE-598 for the disclosure pieces.

## JS bundle & sourcemap exposure
- Source: the application's own front-end build, served publicly.
- Sink: everything the build embedded — API endpoints (including admin and unreleased ones), role
  names, feature flags, third-party keys, internal hostnames, and, when `.map` files ship with
  `sourcesContent`, the **original source of the front-end**.
- Bypass: none needed. This is the single highest-value ten minutes of a black-box hunt: a sourcemap
  turns a black-box target grey. Once extracted, run the pipeline's existing static chain over the
  recovered sources (`hunt scan work/<slug>/web/js/src`) and you get real `file:line` evidence for a
  target you never cloned.
- Confirm:
  ```bash
  curl -s "$T/static/js/main.a1b2c3.js" | tail -c 200        # //# sourceMappingURL=...
  curl -s "$T/static/js/main.a1b2c3.js.map" -o main.js.map   # sourcesContent? -> full sources
  ```
  Then mine for: `fetch(`/`axios.` call sites (the endpoint inventory), `/api/` string literals,
  `role`/`isAdmin`/`permission` comparisons done client-side (each one is an authz check to test
  server-side), and hardcoded keys. A **live secret** in a bundle is a finding on its own (CWE-798);
  the rest is intelligence that feeds every other row in the matrix.
- CWE-540 (inclusion of sensitive information in source code). CWE-798 when a usable credential is in
  there — verify it is live before claiming it, and redact it in the report.

---

## Closing reflexes

- **Read the cookie before claiming CSRF, read the baseline before claiming anything.** Those two
  habits eliminate most invalid web reports.
- **A header check is not a finding.** Missing `X-Frame-Options` is a note; a screenshot of the framed
  account-deletion button is a report.
- **Detection-only means detection-only.** Cache poisoning, cache deception, request smuggling and
  subdomain takeover all have a version of the proof that harms a bystander and a version that
  doesn't. Take the second one and explain the first in prose.
- **Chain before you submit.** Individually-low findings compose: sourcemap → an admin endpoint →
  missing field-level authz; subdomain takeover → `SameSite=Lax` sibling → CSRF that was "protected";
  open redirect → OAuth `redirect_uri` → account takeover. The chain is usually the real report, and
  it is the part a scanner can never assemble.
- **Novelty still applies.** Run `variant-analysis` before writing anything up; a published advisory's
  incomplete fix is out of scope, not a finding.
