# [TITLE — what goes wrong, and where]

> Responsible-disclosure report. Submit via huntr (on-platform) or a private GitHub Security
> Advisory — never a public issue/PR before a fix + embargo. Redact real secret values.
>
> Title: plain words, one clause, ≤10 words. "Mass assignment in `PUT /api/v1/executions/:id`",
> not "Mass Assignment in Execution Update Endpoint (…) allows cross-workspace injection and
> protected-field tampering". No colons, no CVE ids, no versions, no severity words.
>
> Prose: write it the way you'd write it to a colleague. First person about what you did and
> tested, short sentences next to long ones, plain uncertainty where it exists. No filler
> openers, no consultant adjectives, no bulleted paragraphs, no self-summarizing sections.
> Full rules: `report-standards` (rule 4 + Title rule). Delete this note before submitting.

> **Two target kinds.** Keep the metadata block that matches yours and delete the other. A
> source finding is anchored on a pinned commit and `file:line`; a live-website finding is anchored
> on the program that authorized it and the `T#####` transcript ids that prove it. Grey-box (you had
> both) keeps **both** blocks — that is the strongest report this pipeline produces.

<!-- ===== SOURCE TARGET (delete if this was a live website) ===== -->

| Field | Value |
|-------|-------|
| **Repository** | `<owner/repo>` |
| **Affected version(s)** | `<version / commit tested>` (range not fully verified unless stated) |
| **Vulnerability type (CWE)** | `CWE-___ : <name>` |
| **CVSS 3.1** | `<vector string>` = `<score>` (`<Critical/High/Medium/Low>`) |
| **Reporter** | `<your name / handle>` |
| **Report date** | `<YYYY-MM-DD>` |
| **Finding ID** | `<Fxxx>` |

<!-- ===== LIVE WEBSITE (delete if this was a source target) ===== -->

| Field | Value |
|-------|-------|
| **Target** | `<https://app.example.com>` |
| **Program** | `<name>` — `<program URL>` |
| **Scope authorization** | `scope.yml` `sha256:<digest>`, policy read `<YYYY-MM-DD>` |
| **Test window** | `<start>` → `<end>` (all cited traffic falls inside it) |
| **Tested from** | `<source IP or description>` |
| **Observed at** | `<YYYY-MM-DDTHH:MMZ>` — re-verified immediately before submission |
| **Vulnerability type (CWE)** | `CWE-___ : <name>` |
| **CVSS 3.1** | `<vector string>` = `<score>` (`<Critical/High/Medium/Low>`) |
| **Reporter** | `<your name / handle>` |
| **Finding ID** | `<Fxxx>` |

## Summary
<2–3 sentences: what the bug is, where, and the impact — a maintainer should grasp it instantly.
Don't restate the title in the first sentence. Say what you sent and what came back.>

## Affected component
- File: `<path>:<line>`  ← source/grey only
- Endpoint / entrypoint: `<METHOD /route or function>`
- Parameter / identity: `<the input you controlled>` as `<which principal>`  ← live-target
- Precondition: `<auth level / config / none>`

## Proof of Concept
Source target: runs against a **local** instance you launch yourself. Live target: runs against the
authorized host, inside the test window, at the program's stated rate. Benign markers only.

```bash
# --- source target ---
# 1. clone + checkout the tested commit
git clone --depth 1 https://github.com/<owner/repo>.git && cd <repo> && git checkout <commit>
# 2. install + launch (local, 127.0.0.1)
<install/launch commands>
# 3. trigger the bug
<the minimal probe.py / curl / script command>

# --- live target (delete the block that does not apply) ---
# 1. verify the scope authorizes this request
hunt scope --file work/<slug>/scope.yml --check <https://app.example.com/api/...>
# 2. trigger the bug — the exact request, with real values, no placeholders
curl -i '<https://app.example.com/api/...>' -H 'Cookie: <session>' -d '<body>'
```

**Observed:** `<what happens — e.g. "returns another user's private note to an anonymous caller">`
**Expected:** `<the safe behavior — e.g. "401/403">`

## Evidence
<Key request/response, and the server-side stack trace excerpt if any. Secrets redacted.
Reference the bundle: `work/<slug>/evidence/<finding_id>/`.>

```
<request>
---
<response>
---
<server log / stack trace excerpt>
```

### Transcript  ← live-target / grey only
<Every load-bearing claim cites a `T#####` id from `work/<slug>/web/transcript.jsonl`, and the
request/response is pasted here in full — cite AND quote, exactly as `file:line` works for source.
`hunt validate-report` re-checks that each id exists and that its response hash still matches the
copy in the evidence bundle, so an invented or stale id fails the gate.

Scrub real user data and secrets here before submitting: the bundle ships with the report, and
"it was in the response" is not a defense.>

| Transcript id | What it shows |
|---|---|
| `T00203` | `<the request that established the baseline>` |
| `T00287` | `<the request that proves the finding>` |

```
<T00287 request, verbatim>
---
<T00287 response, verbatim, redacted>
```

## Not tested / scope-blocked  ← live-target only
<Classes you could not reach, and why: out of scope, rate-limited below the threshold, a role the
program would not grant, a WAF answering instead of the application. Programs value this, and
omitting it implies coverage you do not have. Say what would unblock each one.>

## Impact
<Who is affected, realistic attacker, blast radius (one object vs. all tenants/users), and what
they gain (data read/modify, account takeover, RCE, etc.).>

## Root cause
<The specific flawed line/logic — e.g. "`/items/<id>` looks up `ITEMS[id]` with no ownership check
at app.py:65", or "signature verification disabled via `options={'verify_signature': False}`".>

## Suggested remediation
<Concrete fix — ideally a diff. e.g. add an ownership/role check keyed to the authenticated
principal; use `yaml.safe_load`; verify JWT signatures with a fixed algorithm; allow-list + block
IPv6-transition for outbound URLs; HTML-encode output.>

```diff
<minimal patch>
```

## Duplicate check
<What was searched (CVE, GHSA, huntr, GitHub issues/PRs/commits/releases/closed issues) and the
result — confirming this is not already known/fixed.>

## Disclosure timeline
- `<YYYY-MM-DD>` — reported privately via `<huntr / GHSA>`.
- (maintainer response / fix / CVE — fill in as it progresses.)

## Credit
Please credit: `<name / handle>`. Thank you for triaging.
