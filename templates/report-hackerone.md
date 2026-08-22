# HackerOne submission — `<program>`

> **Use this layout only when the destination is a HackerOne program.** The default is GitHub
> publishing (`templates/report-github.md`) — a private GHSA draft on the repo, or the huntr form, which takes
> the same body.
>
> H1 triage reads Summary → Steps To Reproduce → Impact, in that order, and closes anything it can't
> reproduce from the text alone. Steps To Reproduce carries the weight here; it is not a condensed PoC.
> Delete every instruction line, including this one, before submitting.
>
> Title: `<the vulnerability> in <where>` — plain words, one clause, ≤10 words, sentence case, no
> trailing period. Name the security failure, not the mechanism. Prose: first person
> about what you did and tested. Full rules in `report-standards`.

## Platform fields

| Field | Value |
|-------|-------|
| **Title** | `<the vulnerability> in <where>` — ≤10 words, names the security failure not the mechanism |
| **Asset / scope item** | `<the exact asset as the program lists it>` |
| **Weakness (CWE)** | `CWE-___ : <name from cwe-map>` |
| **Severity** | `<Critical / High / Medium / Low>` |
| **CVSS 3.1** | `CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_` = `<n.n>` |
| **Program** | `<name>` — `<program URL>` |
| **Scope authorization** | `scope.yml` `sha256:<digest>`, policy read `<YYYY-MM-DD>` |
| **Test window** | `<start>` → `<end>` — all cited traffic falls inside it |
| **Tested from** | `<source IP or description>` — most programs require this |
| **Observed at** | `<YYYY-MM-DDTHH:MMZ>` — re-verified immediately before submission |
| **Finding ID (ours)** | `<Fxxx>` · evidence `work/<slug>/evidence/<Fxxx>/` |

## Summary
<2–3 sentences: the affected asset, what the request does, and what comes back that shouldn't. A
triager decides here whether to reproduce it now or later.>

## Steps To Reproduce
Numbered, literal, and complete. Assume an empty machine and no context. Real values — the actual path,
header, token id and body, never `<placeholder>` or "a crafted payload".

1. `<prerequisite — account tier, a second identity, a browser, a listener you control>`
2. `<the exact request>`

```bash
curl -i 'https://<host>/api/...' \
  -H 'Cookie: <session — redacted but structurally real>' \
  -d '<body with concrete values>'
```

3. `<what to look at in the response, and where>`

**Observed** (verbatim, redacted):

```
<real response — status line, the discriminating headers, the bytes that prove it>
```

**Expected:** `<what a correct implementation returns — e.g. 403>`

**Negative control:** `<the same request as a different identity, or against a route that defends
correctly — this is what separates a finding from the app's normal behavior>`

### Transcript
Every load-bearing claim cites a `T#####` id from `work/<slug>/web/transcript.jsonl`, with the
request/response pasted in full. Scrub real user data before submitting — n=1, redacted, never a dump.

| Transcript id | What it shows |
|---|---|
| `T00203` | `<the baseline>` |
| `T00287` | `<the request that proves it>` |

## Impact
<Who is affected, the realistic attacker position, and what they get. Blast radius in concrete terms:
one record or every tenant. Label confidence — runtime-confirmed / code-confirmed / theoretical. No
speculative pivot chains; H1 triage discounts them and they cost you credibility.>

## Supporting Material / References
- Evidence bundle: `work/<slug>/evidence/<Fxxx>/` (`evidence.json`, `root_cause.md`)
- `<screenshots / HAR / video, if the program asks for one>`
- `<the exact requests, as attachments, if they're too long to inline>`

## Testing conduct / safe harbour
- Tested only assets inside the published scope; `scope.yml` `sha256:<digest>` records what was
  authorized and every request was checked against it.
- Stopped at n=1 on any other user's data. Nothing was modified, persisted, or pivoted from.
- No availability testing against production. `<If a DoS-class issue is reported, say it is derived
  from the reachable sink and measured complexity, and was never fired at the live host.>`
- Rate stayed at or under the program's stated limit; `<N>` requests total in the window above.

## Not tested / scope-blocked
<Classes you could not reach, and why: out of scope, rate-limited, a role the program wouldn't grant,
a WAF answering instead of the application. Say what would unblock each one.>

## Duplicate check
<What was searched and the result — the program's disclosed reports, hacktivity for this class, and any
public advisory. State plainly that this is not a known issue as far as you could determine.>

## Credit
Please credit `<name / handle>`. Thanks for triaging.
