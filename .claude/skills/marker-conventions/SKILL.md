---
name: marker-conventions
description: >
  Benign proof markers the pipeline uses to prove impact without doing harm. Consult when building a
  PoC and you need a harmless, unambiguous signal. Also lists the manual curl equivalents.
---

# Benign markers (prove the bug, harm nothing)

Use the smallest signal that is unambiguous and could only appear if the bug is real.

- **Code/expression eval:** `7*7` → response contains `49`. (`{{7*7}}`, `${7*7}`, `#{7*7}` per engine.)
- **XSS reflection:** inject `<xss-probe-9c2f>`; confirm it comes back **unescaped** in an HTML
  content-type. (A DOM/stored path may need a headless-browser check that the script actually runs.)
- **Path traversal (read):** plant a sentinel one dir above the web root and read it back, or read a known
  system file's signature (`root:x:` in /etc/passwd, `for 16-bit app support` in win.ini).
- **Arbitrary file write:** write `upload-probe-9c2f.txt` to a **fresh** name outside the intended dir and
  show it there (`ls`/read-back). Never overwrite an existing file — name the sensitive destination the
  same primitive would reach instead.
- **Upload validation bypass:** the smallest file that violates the stated policy — `x.png.py` with a
  forged `Content-Type`, a `GIF89a;`-prefixed polyglot, or an `.svg` carrying `xss-probe-9c2f` — then the
  response headers when it's served back (`Content-Type`, missing `Content-Disposition`).
- **Template injection:** `{{7*7}}`/`${7*7}`/`#{7*7}` → `49`; `{{7*'7'}}` → `7777777` fingerprints Jinja.
  Escalate only to a read-only reach proof (a config key, truncated `__globals__` keys) — never a command.
- **SSRF:** point the target at a local callback listener you started; a hit on it proves the fetch.
  For blind SSRF, timing or an out-of-band DNS/HTTP hit is the signal.
- **Identity spoof (authz/JWT):** read a resource whose body contains an **owner-only marker string**
  as a different/anon identity; or forge a token with `sub=pwned-subject` and see it accepted.
- **Error/info disclosure:** a request that induces a stack trace / internal path in the response.
- **SQL injection:** a lone `'` that surfaces a DB error string (`sqlite3.`, `psycopg2`,
  `you have an error in your SQL`, `unterminated quoted…`); or a boolean `1=1` vs `1=2` result diff. Never
  a mutating payload.
- **Open redirect / trusted-header:** a `Location:` header pointing at `evil.example`; a gated `403` that
  turns `200` under a spoofed `X-Forwarded-For: 127.0.0.1` or an arbitrary `Host:` accepted.
- **Mass assignment:** send an extra protected field with a marker value (`probe-9c2f`) → re-read the
  object and see the field persisted.
- **Missing rate limit:** ~30 rapid bad logins with no `429`/lockout.
- **Prompt injection / insecure output handling:** the canary `PROMPT-INJECT-OK-9c2f` echoed verbatim
  after an injected instruction; or the model coaxed into emitting a sink marker (`<xss-probe-9c2f>` / `7*7`)
  that the downstream sink then executes. Strongest proof = the obeyed action in the agent's tool-call log.
- **Secrets exposure:** provision the credential with a seeded value `probe-secret-9c2f`, then show it in
  a response fetched by a lower-privileged/anon identity. Quote the marker, never a real key.
- **Prompt-to-tool priv-esc:** the low-priv identity gets `403` on the direct route but the agent path
  returns the same owner-only marker / performs the write — plus the tool-call line from the server log.
- **Race / TOCTOU:** more than one "success" across N concurrent identical requests (double-spend /
  double-admit) — a single winning interleaving is enough. Cross-user variant: run two identities
  concurrently with `marker-A-9c2f` / `marker-B-9c2f` and catch a response carrying the other's marker.

## Web & client-side markers

- **DOM XSS (execution, not reflection):** `document.title='xss-probe-9c2f'`, or an overridden
  `alert`/`print` hook that records the call. The marker must prove the payload **ran** — a string
  match in the response body proves nothing for a DOM sink, which often never reaches the server at
  all (`location.hash` isn't transmitted).
- **CSRF:** the state change lands a marker in a field on **your own** object
  (`display_name=probe-9c2f`), then a re-read shows it persisted — sent with the session cookie, no
  token, and a foreign `Origin`. Quote the `Set-Cookie` line in the evidence; the `SameSite` attribute
  is half the finding.
- **Clickjacking:** a screenshot of the target rendered in an iframe from a foreign origin, with the
  sensitive control visible. A missing header is a note; the screenshot is the proof.
- **postMessage:** post `{"value":"probe-9c2f"}` from a foreign origin and show the handler acted —
  state changed, marker rendered, or a request fired.
- **Prototype pollution:** pollute with `{"__proto__":{"probe_9c2f":"polluted"}}`, then read
  `({}).probe_9c2f` off a **fresh** object. Unambiguous and harmless; stop there rather than chaining
  to a command gadget on a live host.
- **Cache poisoning / deception:** always on a URL only you will ever request — a unique
  `?cb=<random>` for poisoning, a `probe-9c2f.css` suffix for deception. The proof is the marker
  coming back on a *second, clean* request with `X-Cache: HIT` / `Age > 0`. Never on a real page path.
- **Request smuggling:** a reproducible **timing** delta versus a baseline median. Nothing else — a
  captured victim request is a bystander's data.
- **Subdomain takeover:** the CNAME plus the provider's unclaimed-resource fingerprint string. Never
  register the resource.
- **Host-header injection:** the attacker `Host` appearing in a `Location`, a `<base href>`, or a
  reset link delivered **to your own inbox**.
- **Mass assignment / IDOR over HTTP:** the owner-only marker (`marker-A-9c2f`, seeded into userA's
  data during recon) appearing in userB's or anon's response. "Got a 200" is not a marker — an SPA
  returns 200 for everything.
- **Sourcemap / bundle exposure:** the recovered original source path plus one identifying line. If a
  live credential is in there, quote its first four characters and `<REDACTED>` the rest.

**Pick a per-engagement suffix.** `9c2f` is the documented default and it is fine for a local fixture,
but on a live target reuse across hunts makes two engagements indistinguishable in a shared log. Use
`probe-<4 random hex>` per engagement, record it in `scope.yml` under `safety.marker`, and use it
everywhere so every artifact you left behind is greppable and attributable to you.

Rule: never destroy data, exfiltrate real user data, or pivot to prove a point — a marker suffices.
Redact any real secret in the write-up as `<REDACTED>`.

On a live target the marker discipline is stricter, not looser: write markers only to objects you own,
stop at the first record when a marker proves cross-user access, and leave nothing persistent behind
that you cannot point to in the report. `disclosure-ethics` is binding.

Manual equivalents live inline in each hunter agent's probe recipes; `hunt probe --primitive <name>`
and `hunt web probe --primitive <name>` run the same markers and record evidence. Use whichever you
judge faster for the case at hand.
