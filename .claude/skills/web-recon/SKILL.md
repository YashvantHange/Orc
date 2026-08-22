---
name: web-recon
description: >
  Build the attack surface of a live website by hand — scope verification, passive discovery,
  crawling, JS bundle and sourcemap mining, API-spec and GraphQL discovery, identity provisioning,
  and the baselines that stop soft-404s from producing false positives. Load at the start of any
  url/grey hunt, before any vulnerability class is probed. This is the black-box replacement for
  "clone the repo and grep the routes".
---

# Web recon — the surface inventory

For a source target, the attack surface comes from `Grep`ping `@app.route`. For a live host there is
no source to grep, so you build the same inventory over the wire. **Everything downstream depends on
this**: the coverage matrix in `vuln-playbooks` is meaningless without an endpoint list, the
authorization differential needs resources and identities, and every probe needs a baseline to
compare against.

Budget this properly. On a real target, recon is the majority of the hunt and the source of most
findings — a hunter who spends ten minutes here and two hours firing payloads at `/` finds nothing.

Output goes in `work/<slug>/web/`. `hunt web recon <url> --scope <f>` automates the mechanical parts
and writes the same files; every step below is also a command you can type, and the manual version is
authoritative when the helper disagrees or isn't there.

---

## 0. Scope, before the first packet

Non-negotiable. `disclosure-ethics` has the full rule; the mechanics:

```bash
cp scope.example.yml work/<slug>/scope.yml     # then fill it from the program's policy
hunt scope --file work/<slug>/scope.yml --lint
hunt scope --file work/<slug>/scope.yml --check https://app.example.com/api/x
```

Record `scope_digest`, the program URL and the test window in `work/<slug>/profile.json`. Every
report cites them. If `--lint` warns that `authorized_by` or `policy_sha256` is empty, fill them —
those two fields are the difference between research and an unauthorized scan.

A host that resolves is not a host that's in scope. A wildcard in the policy is not permission to
guess subdomains — enumerate them, then check each one against the written scope.

---

## 1. Passive first

Nothing here sends a payload, and it often names half the surface.

```bash
curl -s "$T/robots.txt"                        # Disallow entries are a HINT LIST, not a boundary
curl -s "$T/sitemap.xml"                       # follow sitemap-index children
curl -s "$T/.well-known/security.txt"          # the disclosure channel, and often a scope hint
curl -s "$T/.well-known/openid-configuration"  # the whole SSO surface in one document
curl -sI "$T/"                                 # server, framework, cookie names, CDN
```

Also worth a look before you touch the target at all: certificate transparency for sibling hostnames,
the program's own scope page, and the vendor's public docs (which describe endpoints the UI never
calls). Note every hostname you learn — then check each against the scope before using it.

---

## 2. Crawl, and template as you go

Walk links and forms breadth-first from the root and from every authenticated landing page. For each
response record: URL, method, parameters (query, body, path), status, content-type, and whether it
worked unauthenticated.

**Template the paths as you collect them.** `/items/1` and `/items/2` are one endpoint,
`/items/{id}`, with observed values `1, 2`. That collapsed form is what feeds IDOR enumeration and
the authorization differential; a flat URL list does not.

Record forms in full — action, method, every input name including hidden ones, and any CSRF token
field. Hidden inputs are the mass-assignment candidate list, and the token field's presence (or
absence) is the CSRF check's first input.

Two things a raw-HTTP crawl misses, so handle them deliberately:

- **SPA routes.** If the app is a single-page app, HTML crawling finds one page. The real surface is
  in the JS (§3) and in the XHR/fetch traffic a browser generates. Drive the app in a real browser
  with the network panel open, or `hunt web recon --render`, and harvest every request it makes.
- **Endpoints the UI never calls.** Admin routes, deprecated versions, internal-only handlers. These
  come from the bundle, the API spec, and version-guessing (`/api/v1` → try `/api/v2`, `/api/internal`).

---

## 3. Mine the JS bundles — the highest-value step

The front-end build is the application's own description of its API, shipped to you.

```bash
curl -s "$T/" | grep -oE 'src="[^"]+\.js[^"]*"'          # find the bundles
curl -s "$T/static/js/main.abc123.js" -o main.js
tail -c 200 main.js                                       # //# sourceMappingURL=main.js.map
curl -s "$T/static/js/main.js.map" -o main.js.map         # sourcesContent -> original sources
```

If the `.map` carries `sourcesContent`, write those sources out to `work/<slug>/web/js/src/` and the
target stops being black-box. Then run the pipeline's existing static chain over them —

```bash
hunt scan work/<slug>/web/js/src
```

— and you get semgrep + gitleaks findings with real `file:line`, on a target you never cloned. That
turns a `url` hunt into a `grey` one and unlocks the stricter, better-evidenced report path.

With or without a sourcemap, mine the bundle for:

- **Endpoints** — `fetch(`, `axios.`, `$.ajax`, and every `/api/...` string literal. This is usually a
  larger endpoint list than crawling produces.
- **Roles and permissions** — `isAdmin`, `role ===`, `permissions.includes`, feature flags. Every
  client-side check is a server-side check to test: if the UI hides a button by role, request the
  endpoint directly as a lower role. That single habit finds BFLA on most targets.
- **DOM-XSS source→sink pairs** — `location.hash|search`, `document.referrer`, `window.name`,
  `postMessage` handlers flowing into `innerHTML`, `document.write`, `eval`, `Function`,
  `setTimeout(string)`, `dangerouslySetInnerHTML`, `v-html`. Each pair is a `web-playbooks` → DOM XSS
  candidate with a known trigger.
- **Secrets** — hardcoded keys, internal hostnames, bucket names, third-party tokens. Verify a key is
  live before reporting it, and redact it in the write-up.
- **State blobs** — `window.__INITIAL_STATE__`, `__NEXT_DATA__`, embedded config JSON. These leak the
  data model and often the current user's full record, over-serialized.

---

## 4. API specs and GraphQL

One request each; when one lands you have the entire surface with parameter types and declared auth.

```bash
for p in /openapi.json /openapi.yaml /swagger.json /swagger/v1/swagger.json \
         /v2/api-docs /v3/api-docs /api-docs /docs /redoc /api/schema; do
  echo "== $p"; curl -so /dev/null -w '%{http_code}\n' "$T$p"
done
curl -s "$T/graphql" -H 'Content-Type: application/json' \
     -d '{"query":"{__schema{types{name fields{name}}}}"}' | head -c 400
```

An OpenAPI document gives you methods, parameters, request schemas — **and the `security` block**, which
tells you which endpoints are *declared* to need auth. Any endpoint whose declared security you can
ignore in practice is a finding, handed to you by the target's own spec.

A GraphQL schema is the endpoint inventory for everything behind `/graphql`; treat every query and
mutation as a route, with its arguments as parameters. See `web-playbooks` → GraphQL for what to do
with it.

---

## 5. Identities — provision at least three

The authorization plane is the highest-yield part of the matrix and none of it is testable with one
account. Register or obtain:

- **`owner` / userA** — creates the objects that carry the owner-only marker.
- **`other` / userB** — a second account at the *same* privilege level. This is the one that proves IDOR.
- **`anon`** — no credentials at all.
- **`admin` and any other role**, if the program gives you one. Role pairs prove BFLA and privilege
  escalation; without them, that whole group of rows is `BLOCKED`, not `CLEAR`.

Seed a marker into userA's data (`marker-conventions`): a display name, note, or filename containing
`marker-A-9c2f`. Every authorization test then has an unambiguous signal — "userB's response contains
userA's marker" is proof; "userB got a 200" is not.

Store cookie jars and tokens at `work/<slug>/web/auth/<identity>.json`, **never inline in
`profile.json`** — profiles get quoted into reports, and a live session token must not ship with one.

Then generate the authorization differential config from your endpoint inventory and run it:

```bash
hunt authz-scaffold --url "$T"                 # skeleton from endpoints.json; fill owners + markers
hunt authz --url "$T" --scope work/<slug>/scope.yml --config work/<slug>/authz.json
```

The manual equivalent is exactly what it sounds like: for each endpoint, send the same request as
each identity and diff the responses. `authz-audit` has the full procedure.

---

## 6. Baselines — do this before probing anything

**This is the step that decides whether your findings are real.** A live web app answers in ways
source never does: SPAs return HTTP 200 with an HTML shell for every unknown path, WAFs answer instead
of the application, CDNs answer instead of both, and error pages come back 200 with the error in the
body. Capture, and keep:

```bash
curl -si "$T/definitely-not-a-real-path-9c2f"          # soft-404 baseline: status, length, shape
curl -si "$T/api/items?definitely_not_a_param_9c2f=1"  # unknown-parameter baseline
curl -si "$T/api/items"                                # unauthenticated baseline
curl -si "$T/api/items" -b "session=$OWNER"            # per-endpoint owner baseline
```

Note status, body length, and a stable fingerprint of the body for each. Then, for every candidate
finding, show it differs from all of them. Concretely:

- A "missing auth" hit that looks identical to the soft-404 is a soft-404.
- An SQLi boolean difference that also appears between two *identical* requests is noise — always
  compare `1=1` against the untampered baseline **and** against `1=2`, three ways, not two.
- A "reflected" marker that also appears when you don't send it is the app echoing the path.
- A 403→200 flip under a spoofed header that also flips under a random header is a WAF, not a bypass.

Also fingerprint who is answering: if a payload gets a generic block page while a benign request gets
the app, you are testing the WAF. That is a `BLOCKED` verdict for the class, with "WAF intercepts the
payload class" as the reason — not a `CLEAR`.

---

## 7. Header, cookie and cache posture

Zero payloads, and it produces findings plus the preconditions for several classes.

```bash
curl -sI "$T/account" -b "session=$OWNER"
```

Read: CSP, `X-Frame-Options`, HSTS, `X-Content-Type-Options`, `Referrer-Policy`, `Set-Cookie` flags,
`Access-Control-*`, `Vary`, and `Cache-Control` on **authenticated** responses. Do this on a sensitive
authenticated page, never on the marketing root — the root's headers tell you nothing about the page
that matters. `web-playbooks` → Header posture, Cookie flags and CSP cover what each one enables.

---

## 8. Write the inventory down

Before probing, `work/<slug>/profile.json` and `work/<slug>/web/endpoints.json` should hold:

- every endpoint: templated path, methods, parameters, auth required (declared **and** observed),
  content-type, and where you learned it (`crawl` / `rendered` / `openapi` / `graphql` / `jsbundle` /
  `sitemap` / `sourcemap`)
- forms with their inputs and token fields
- identities, roles, and where their credentials live
- the four baselines
- tech fingerprint: server, framework, template engine, database hints, CDN/WAF
- the scope digest, program and test window

That document is the black-box equivalent of a source tree. The coverage matrix is then swept against
*it* — and the enumeration tuple every `CLEAR` verdict needs ("14 endpoints × 4 methods × 3
identities × 6 encodings") is counted from it. If you cannot state your endpoint count, you cannot
close a single class.

---

## Recon reflexes

- **The bundle before the payloads.** Ten minutes of sourcemap mining beats an hour of fuzzing, and it
  is the step most hunters skip.
- **Every client-side check is a server-side test.** A greyed-out button, a hidden route, a
  role-conditional render — request the underlying endpoint directly as the lower role.
- **Old versions stay mounted.** `/api/v2` shipped a fix; `/api/v1` is often still routed, unfixed.
- **Anything the UI never calls is under-tested by definition** — admin handlers, debug routes,
  export jobs, webhook receivers, health endpoints that echo config.
- **Enumerate hosts, then check the scope for each.** Finding a subdomain is not the same as being
  allowed to test it.
