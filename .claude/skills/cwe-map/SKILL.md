---
name: cwe-map
description: >
  The single CWE lookup table for the pipeline's vuln classes. Consult when you need the right CWE
  id for a finding or report. One source of truth (was duplicated across hunters + playbooks).
---

# CWE map (pick the most specific that fits what you proved)

**Access control (n8n class)**
- IDOR / BOLA / direct object ref — CWE-639
- Missing function-level authz (BFLA — no check on an endpoint) — CWE-862
- Missing authentication for a critical function — CWE-306
- Privilege escalation — CWE-269 · Improper access control (generic) — CWE-284
- Auth bypass by spoofing a trusted header (XFF/localhost gate) — CWE-290 · reliance on a less-trusted
  source — CWE-348
- Mass assignment / unsafe field binding — CWE-915
- Prompt-to-tool priv-esc (agent's tool call runs with no per-action authz) — CWE-862 (+CWE-269 if it
  crosses a role boundary, +CWE-1427 for the injection that drives it, + the sink's CWE)
- Incorrect authorization (a check exists and reaches the wrong verdict) — CWE-863. Use this, not 862,
  when the code *did* check and got it wrong — it points the maintainer at a different line.
- Authorization bypass through a user-controlled key (object key, storage path, presigned key) — CWE-639
- Trusting the HTTP verb / method override (`X-HTTP-Method-Override`, `_method`) — CWE-650
- Externally-controlled parameter the app assumes immutable (price, tier, quantity) — CWE-472 ·
  business-logic error with no more specific id — CWE-840
- Authorization bypass via a user-controlled SQL primary key — CWE-566

**Injection / execution**
- Deserialization → RCE — CWE-502
- Code injection (generic) — CWE-94 · eval-style — CWE-95
- Template injection (SSTI) — CWE-1336 · format-string injection (`str.format`/f-string) — CWE-134 ·
  client-side template injection (CSTI) — CWE-79
- OS command injection — CWE-78 · **argument** injection (leading `-`/flag smuggling into argv) — CWE-88
- SQL injection — CWE-89 · NoSQL/operator injection (`$ne`, `$gt`, `$where`) — CWE-943 · Cypher — CWE-89
- XML injection — CWE-91 · XPath injection — CWE-643 · LDAP injection — CWE-90 ·
  expression-language injection (SpEL/OGNL/JEXL) — CWE-917
- Improper neutralization of formula elements in a CSV export — CWE-1236
- Prototype pollution (`__proto__`/`constructor.prototype` through a recursive merge) — CWE-1321
- XSS — CWE-79 (same id for reflected, stored, and DOM — say which in the title/PoC; stored is the
  higher-severity variant, DOM-based sub-class is CWE-79 via CWE-83/CWE-116 depending on the sink)
- Second-order/stored injection — the *sink's* id (79/89/78), with "stored/second-order" stated in the
  title, because the fix location differs from the injection point

**Untrusted fetch / files**
- SSRF — CWE-918 · DNS-rebinding / reverse-DNS trust enabling SSRF — CWE-350
- Open redirect — CWE-601
- Path traversal — CWE-22 · LFI (include) — CWE-98 · Zip-Slip — CWE-22
- External control of filename/path — CWE-73 · files/dirs accessible to an external party — CWE-552
- Arbitrary file **write** / overwrite via traversal — CWE-22 + CWE-73 (say what the write reaches:
  code exec → also CWE-94; overwrite of a config/model → integrity)
- Unrestricted upload of a dangerous file type — CWE-434 · type determined from filename/extension
  instead of content — CWE-646 · improper validation of the *content* — CWE-1289
- Decompression bomb (zip/DOCX expansion ratio) — CWE-409 (generic resource exhaustion — CWE-400)
- XXE — CWE-611

**Auth / crypto / secrets**
- Hardcoded/default signing secret — CWE-798
- JWT verification disabled / alg:none / alg-confusion — CWE-347
- Improper authentication (generic bypass that isn't one of the below) — CWE-287 · auth bypass by an
  alternate path/channel (an unrouted/unmiddlewared endpoint) — CWE-288
- Session fixation (id not rotated on login) — CWE-384 · insufficient session expiration — CWE-613
- Wildcard/reflected CORS + credentials — CWE-942 · origin validation error (postMessage, CSWSH,
  substring origin match) — CWE-346 · CSRF — CWE-352
- Non-constant-time secret compare (timing) — CWE-208
- Missing rate limit (brute force) — CWE-307 · improper control of interaction frequency (any
  anti-automation gap, not just auth) — CWE-799
- Weak password-recovery mechanism (guessable/unbound/replayable reset token) — CWE-640
- Incorrect implementation of an authentication algorithm (MFA step skippable, factor not enforced) —
  CWE-303 · weak authentication (generic, e.g. account linking on an unverified email) — CWE-1390
- Cookie without `HttpOnly` — CWE-1004 · without `Secure` — CWE-614 · with a permissive `SameSite` —
  CWE-1275. Hardening notes alone; report as a finding only inside a chain, and name the chain.
- Broken/weak crypto algorithm (MD5/SHA1/ECB/static IV) — CWE-327 · reversible/weak hash — CWE-328 ·
  insufficiently random token — CWE-330
- Secret returned by an API to an unauthorized actor — CWE-200 · insufficiently protected credentials —
  CWE-522 · secret in a log/prompt/execution record — CWE-532

**Resilience / concurrency**
- Race condition (concurrent check-then-act) — CWE-362 · TOCTOU — CWE-367
- Race in a multi-user context leaking A's data to B (shared global/cache/session) — CWE-362 + CWE-200
  (wrong-session delivery — CWE-488)
- Uncontrolled resource consumption (ReDoS / algorithmic DoS) — CWE-1333 (generic — CWE-400)
- Improper input validation / unhandled condition → crash — CWE-20 / CWE-703

**AI/ML-native (OWASP LLM Top-10)**
- Prompt injection (direct or indirect, incl. improper neutralization of LLM-bound input) — CWE-1427 (LLM01)
- Insecure output handling — model output into a sink → map to the *sink's* CWE (RCE CWE-94 · XSS CWE-79 ·
  SQLi CWE-89 · SSRF CWE-918) (LLM02)
- Excessive agency / over-scoped tools (agent acts without per-action authz) — CWE-862 / CWE-269 (LLM06)
- Sensitive data disclosed via prompt/completion — CWE-200 (LLM06 legacy)

**Web protocol / caching / framing**
- Request smuggling (inconsistent interpretation of a request between proxy and origin) — CWE-444
- HTTP response splitting (CRLF into a header) — CWE-113
- Web cache poisoning (cache stores attacker-influenced content) — CWE-524
- Web cache deception (authenticated response cached under an attacker-chosen key) — CWE-525
- Improper neutralization of HTTP headers (host-header injection into links/`Location`/`<base>`) — CWE-644
- Clickjacking / improper restriction of rendered UI layers — CWE-1021
- Protection-mechanism failure (CSP that doesn't contain the payload, missing framing/transport
  controls) — CWE-693

**Disclosure**
- Raw exception/stack to client — CWE-209
- Secrets in logs / LLM prompts / execution data — CWE-532
- Sensitive info exposed to an unauthorized actor (over-serialized API response) — CWE-200
- Sensitive information in source code — CWE-540 (shipped sourcemaps, comments, embedded config)
- Information exposure through a query string / URL — CWE-598 (tokens in links, `Referer` leakage)
- Sensitive info in a resource not removed before publication — CWE-1230
- Internal system/network info exposed to an outside sphere — CWE-497 (internal IPs, hostnames, network
  topology, cluster/host inventory; e.g. RFC1918 A records published in a public DNS zone, internal
  names in CT logs). Prefer this over the generic CWE-200 when what leaks is *infrastructure* rather
  than user or application data.
- Uncontrolled resource consumption from missing limits (GraphQL depth/batching, unbounded page size) —
  CWE-770 (distinct from CWE-400: 770 is *no limit defined*, 400 is *consumption not controlled*)
- Personal information exposure — CWE-359 (use when the disclosed data is PII specifically)

**Picking between two that both fit:** name the *weakness*, not the outcome — the CWE goes with the flawed
line you're asking the maintainer to change. A secret leaking because a route has no owner check is
CWE-862 with a CWE-200 impact, not the reverse; an upload that later gets `pickle`d is CWE-502 if the
sink is the flaw and CWE-434 if the missing type check is. One primary id per report; mention the second
in the impact sentence.
