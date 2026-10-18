---
name: stack-playbooks
description: >
  Framework- and platform-specific attack surface: the bugs that exist because of what the target is
  built ON, not what it does. Next.js/SSR, Node/Express, Spring Boot, Laravel/PHP, ASP.NET/Webforms,
  Django/Rails, gRPC, Kubernetes/containers, and CI/CD pipelines. Load once the stack is fingerprinted —
  every entry gives the fingerprint, the crown-jewel sinks, and the confirmation bar that separates a
  real finding from a status code. Complements `vuln-playbooks` (class-first) by going stack-first.
---

# Stack playbooks — hunt what the target is built on

`vuln-playbooks` asks "is there an SSRF here?". This skill asks "it's Spring Boot — is `/actuator/heapdump`
open?". Both passes are required: a class-first sweep misses `/_next/image`, and a stack-first sweep
misses the business logic. Run this **after** fingerprinting, and fold every hit back into the coverage
matrix row it belongs to so nothing is double-counted or lost.

Attribution: fingerprints, endpoint inventories and several confirmation gates below are adapted from
[Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) by Sachin Sharma (content CC-BY-4.0).

## Step 0 — fingerprint before you probe, and record a soft-404 baseline

Modern SPAs and CDNs answer **200 with the app shell for paths that do not exist**. Without a recorded
control, every path in every table below "exists". One request per host, before anything else:

```bash
curl -s -o /dev/null -w "%{http_code} %{size_download}\n" "https://$T/zzz-nonexistent-$RANDOM"
```

Record that status **and** body size in `profile.json`. Any probe below whose response matches the
baseline is `N/A`, not a hit. For `src` targets the equivalent is: read the dependency manifest
(`package.json` / `pom.xml` / `composer.json` / `*.csproj` / `requirements.txt` / `go.mod`) and pin the
framework version **at the release tag**, not at clone HEAD.

## Step 0b — the standing verdict rule still applies

Nothing here is `CLEAR` because a path returned 401/404. `CLEAR` means the guard was read **and** the
attack was sent and rejected (`dynamic-hunt`). Every "highest-value" line below is a lead, not a finding,
until it clears the Security-impact gate and the novelty gate (`variant-analysis`) — most of these
surfaces have published CVEs, and a hit that lands inside the exclusion map is `OUT_OF_SCOPE`.

---

## Next.js / React SSR

**Fingerprint:** `x-nextjs-*` response headers, a `"buildId"` key in the HTML, a `__NEXT_DATA__` script
tag, `/_next/static/chunks/` bundles.

| Surface | What to look for | Matrix row |
|---|---|---|
| `/_next/image?url=` | Image optimizer fetches an attacker-named URL, giving internal scan / metadata reach | C · SSRF |
| Middleware matcher | A `matcher` that skips `/_next/*` or static paths, so the protected page is reachable via `/_next/data/<buildId>/<page>.json` | A · Auth bypass |
| Server Actions | Action ID callable directly; auth enforced only in the client component | A · BFLA |
| `/_next/data/<buildId>/*.json` | Prerendered props for pages you should not see | A · IDOR |
| RSC flight payload | Server-only props serialized into the client stream | F · Secrets exposure |
| ISR revalidate route | Unauthenticated `/api/revalidate` poisons a cached page served to everyone | E · Cache poisoning (**detection only**) |
| `__nextjs_original-stack-frame`, `__nextjs_launch-editor` | Dev-only debug endpoints shipped to production | F · Info disclosure |

**Confirmation bar:** for the middleware bypass, the `/_next/data/` JSON must contain data the
unauthenticated baseline does not. For `/_next/image`, SSRF is confirmed by the fetch reaching your own
collaborator host, never by a 500.

---

## Node / Express / Fastify / NestJS / Koa

**Fingerprint:** `X-Powered-By: Express`, a `Cannot GET /path` 404 body, `.js` frames in stack traces.

| Surface | What to look for | Matrix row |
|---|---|---|
| `__proto__` / `constructor.prototype` in any merged body or query | `lodash.merge`, `Object.assign`, `qs` parsing; then find the gadget that reaches `child_process` or `vm` | B · Prototype pollution (server) |
| `app.set('trust proxy', true)` | Unvalidated `X-Forwarded-For`, so IP allowlists and rate limits fall | A · Trusted-header bypass |
| EJS / Pug / Handlebars rendering a user-controlled template | SSTI reaching `process.mainModule.require('child_process')` | B · Template injection |
| Shell-string interpolation into `child_process.exec` | Command injection; use the argv-vs-shell tree in `vuln-playbooks` | B · Command injection |
| `require(userPath)` or a dynamic import | Module path traversal, loading an arbitrary file as JS | C · Path traversal |
| Exposed `package.json`, `package-lock.json`, `node_modules/.package-lock.json` | Exact dependency versions, which drives the dep-audit row | F · Vulnerable components |

**Prototype pollution confirmation bar:** a reflected `__proto__` key is not the finding. Pollute, then
show a *subsequent, unrelated* request observing the polluted property, and name the sink it reaches.
Pollution with no reachable gadget is a hardening note, not a vulnerability (`report-standards`
Security-impact gate).

---

## Spring Boot / Java

**Fingerprint:** `X-Application-Context` header, a "Whitelabel Error Page", `org.springframework` frames.

Actuator is the crown jewel. Probe the base paths `""`, `/manage`, `/management`, `/app` for:

```
env  heapdump  threaddump  mappings  beans  configprops  loggers  httptrace
sessions  scheduledtasks  caches  flyway  liquibase  refresh  restart  shutdown
```

| Surface | Impact | Matrix row |
|---|---|---|
| `/actuator/heapdump` | Full JVM heap: plaintext passwords, tokens, DB credentials, private keys | F · Secrets exposure |
| `/actuator/env`, `/configprops` | Environment plus Spring properties including secrets | F · Secrets exposure |
| `/actuator/mappings` | The complete route table, which feeds every other class | (recon) |
| `/actuator/shutdown` | POST kills the app — availability, so **never fire it at a live host** | out of scope on `url` |
| `/h2-console` | SQL execution, and the `CREATE ALIAS` path to RCE | B · SQL injection / RCE |
| Jolokia `/jolokia` | JMX over HTTP, so MBean invocation | B · Code injection |
| SpEL-processed input (`@Value`, template fields, routing expressions) | Expression injection to RCE | B · Code / expression injection |

**Confirmation bar:** Spring answers 200 with a Whitelabel page or a login for many paths. Require
**actuator-shaped JSON** (or an actual heapdump body) before calling an endpoint exposed. A bare 200 is
the classic false positive here.

---

## Laravel / PHP

**Fingerprint:** a `laravel_session` cookie, a `csrf-token` meta tag, a Whoops/Ignition error page.

| Surface | Impact | Matrix row |
|---|---|---|
| `APP_DEBUG=true` in production | The Whoops page leaks env vars, the full stack, and file paths | F · Info disclosure |
| `/_ignition/execute-solution` | RCE on old Ignition builds — almost certainly a published CVE, so check the exclusion map before writing anything | B · RCE |
| `/telescope`, `/horizon` | Request/response logs, DB queries, queue payloads, environment | A · BFLA + F · Secrets |
| A reachable `.env` | `APP_KEY` decrypts and forges signed cookies, giving session forgery and ATO | A · Auth bypass |
| `$fillable` / `$guarded` gaps, `Model::update($request->all())` | Mass assignment | A · Mass assignment |
| `URL::signedRoute` validation | A signature covering the wrong parameter set, so a signed action can be tampered | C · Signed-URL abuse |

---

## ASP.NET / Webforms / WCF

**Fingerprint:** `X-AspNet-Version`, `ASP.NET_SessionId` / `.ASPXAUTH` cookies, a `__VIEWSTATE` hidden input.

The single highest-signal read: `__VIEWSTATEENCRYPTED` present but **empty** means ViewState is signed-only
rather than encrypted, and is exploitable the moment a machine key leaks.

| Surface | Impact | Matrix row |
|---|---|---|
| Signed-only `__VIEWSTATE` plus a leaked or known machineKey | Deserialization to RCE | B · Unsafe deserialization |
| `/trace.axd`, `/elmah.axd` | Request traces and error logs, often anonymous | F · Info disclosure |
| `*.svc`, `*.svc?wsdl`, `*.svc/mex`, `*.asmx?WSDL` | Forgotten WCF/SOAP admin services with looser auth than the main app | A · BFLA |
| `customErrors mode="Off"` | Full stack traces with server paths | F · Info disclosure |
| Load-balanced farms with per-node keys | Cross-node ViewState failures leaking key and state detail | F · Info disclosure |

**Never** attempt a deserialization gadget against a live third-party host. On `src` targets, prove it
against your own booted instance and stop at a benign marker (`marker-conventions`).

---

## Django / Rails

**Fingerprint:** a `csrftoken` cookie with `X-Frame-Options: DENY` (Django); `_session_id` with
`X-Runtime` (Rails).

| Surface | Impact | Matrix row |
|---|---|---|
| `DEBUG = True` | The Django debug page lists settings, installed apps and SQL | F · Info disclosure |
| A leaked `SECRET_KEY` | Signed-cookie forgery, so session forgery | A · Auth bypass |
| `.objects.filter(**request.GET)` or `Model.find(params[:id])` | Unscoped ORM lookup giving IDOR; unfiltered kwargs giving field-lookup injection | A · IDOR |
| `permit!` / `attr_accessible` gaps | Mass assignment | A · Mass assignment |
| `Marshal.load`, `YAML.load`, `pickle.loads` on request data | Deserialization to RCE | B · Deserialization |
| Rails `render inline:`, `constantize`, or `send` with user input | Template injection and method dispatch | B · Template injection |

---

## gRPC

**Fingerprint:** ALPN negotiates `h2`, and a bogus method path returns a `grpc-status` trailer
(12 = UNIMPLEMENTED). That trailer confirms the transport only, and is never a finding.

| Surface | Impact | Matrix row |
|---|---|---|
| Server reflection enabled | Full service and method catalog — an enumeration enabler, not a vuln alone | (recon) |
| Backend reachable directly, past the edge proxy | Per-method authorization was never implemented; the proxy was the only gate | A · BFLA |
| Backend trusting proxy-injected metadata (`x-user-id`, `x-tenant-id`) | Inject the header and impersonate any tenant | A · Trusted-header bypass |
| Plaintext h2c on a non-standard port | Metadata and credential interception | F · Header/transport posture |
| HTTP/2 Rapid Reset | Availability — do not fire it; report from the reachable surface only | out of scope on `url` |

---

## Kubernetes / containers

Read the out-of-band gate first, because this class is misreported more than any other here:

- A `200` on `/api/v1/namespaces` is **not** cluster-admin. The API server returns RBAC-filtered (often
  empty) lists to any principal that can reach the verb. Confirm real privilege with
  `SelfSubjectRulesReview` / `SelfSubjectAccessReview`, then by actually reading a Secret value.
- **10255 is not 10250.** 10255 is read-only info disclosure (`/pods`, `/stats`, `/metrics`) with no exec.
  `/run` and `/exec` live on 10250. Do not report "kubelet RCE" off a 10255 hit.
- Blind and outbound vectors need an out-of-band callback. A delayed response is not proof.
- Impact proof is the artifact: the literal `id`/`hostname` output, the decoded Secret bytes (redacted in
  the report), the node's `/etc/hostname` for an escape. Never exec into a production workload to prove RCE.

| Surface | Impact | Matrix row |
|---|---|---|
| `system:anonymous` bound to a powerful ClusterRole | Full cluster control | A · Auth bypass |
| kubelet 10250 `/run`, `/exec` | Pod RCE, then that pod's service-account token | B · RCE |
| A `nodes/proxy` RBAC grant | API-server-mediated kubelet RCE without touching 10250 | A · Priv-esc |
| Unauthenticated etcd on 2379 | Every Secret, often plaintext | F · Secrets exposure |
| `docker.sock` reachable via SSRF or LFI | Privileged container plus host bind-mount, so host root | B · RCE |
| An auto-mounted service-account token | Check its real grants before claiming any impact | A · Priv-esc |

---

## CI/CD pipelines

Read the proof gate first:

1. A reachable `/script` URL that returns a Jenkins login or 403 is **not** an unauthenticated script
   console. Only a `scriptText` POST returning your command's output counts.
2. A `pull_request_target` workflow is not automatically injectable. Confirm untrusted data actually flows
   into an execution sink before opening any PR.
3. Blind injection requires an out-of-band callback. "The workflow ran green" is not proof.
4. A `200` on a `*.tfstate` is not credential exposure until you parse it — many hold only resource IDs.

| Surface | Impact | Matrix row |
|---|---|---|
| Jenkins script console reachable unauthenticated | RCE plus a credential-store dump | B · RCE |
| `pull_request_target` / `workflow_run` that checks out the PR head **and** interpolates untrusted `github.event` data into a shell `run:` | A fork PR exfiltrates `GITHUB_TOKEN` and org secrets with no approval | B · Code injection |
| A non-ephemeral self-hosted runner on a public repo | Fork PR code runs on the runner host, giving persistence | B · RCE |
| An OIDC trust policy with a wildcard `sub` | Any workflow in the org assumes a privileged cloud role | A · Priv-esc |
| Secrets echoed before masking, or left in artifacts and logs | Credential disclosure | F · Secrets exposure |
| A `*.tfstate` in a public bucket | Plaintext infrastructure credentials | F · Secrets exposure |

**Two standing rules from the memory store override enthusiasm here.** A CI finding that only triggers
*after* a maintainer approves the PR is Credit-only on Google OSS VRP, so find a pre-approval trigger or
say so up front. And `pull_request_target` cannot write the default-branch Actions cache scope, which
kills the unguarded-cache class outright.

---

## Closing

Every hit above is a lead for the owning hunter, and the owner is the one named in the matrix row — this
skill creates no new owners. Fold each result back as `HIT` / `CLEAR` / `N/A` / `BLOCKED` against its row,
qualified by hops (`src`) or the enumeration tuple (`url`). Then run `reasoning-checklist`.
