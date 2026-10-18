---
name: chain-craft
description: >
  Turn a confirmed low-severity finding into the higher-severity chain it actually enables — and decide
  when to stop. Carries the A→B signal table (if you found A, check B next), the recurring high-value
  chain shapes, the rule that each link must stand on its own, and hard time-box and rabbit-hole limits.
  Load the moment a lead confirms, before the report is written, and again whenever a finding scores Low
  or lands on the "informational alone" list (open redirect, DNS-only SSRF, reflection, introspection).
---

# Chain craft — the second bug is usually adjacent to the first

A confirmed bug is a map, not a destination. The same missing check almost always exists on the sibling
route; the same primitive almost always reaches a bigger sink one hop away. This skill exists because our
pipeline is good at confirming a single finding and then writing it up immediately, which is right for
delivery discipline and wrong for severity: an open redirect written up alone is a Low, and the same open
redirect written up as the OAuth code-theft step is a Critical.

Attribution: the signal table and chain shapes are adapted from the `/chain` command in
[Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) by Sachin Sharma (content CC-BY-4.0).

## When this runs

Right after a lead confirms and **before** report-writer is tasked — the report's severity, CVSS vector
and impact section all change if B exists. It also runs on every finding that would otherwise be Low, and
on every class that is informational standing alone.

It does **not** run in place of the confirmation-interrupts-the-hunt rule. If a chain does not confirm
inside the time box below, write A up and move on.

## The A→B signal table

| Found A | Check B immediately | Then C |
|---|---|---|
| IDOR on `GET /api/user/X/…` | The same IDOR on PUT/DELETE at that path | Every sibling endpoint in the controller |
| IDOR on a `/v2/` route | The same IDOR on `/v1/` — the fix was forward-only | The mobile client's API version |
| Auth bypass on one endpoint | Every sibling in the same controller or route group | The old API version (`api-inventory`) |
| Stored XSS in a user-controlled field | Does an admin or support agent render this? | Email, export and PDF rendering paths |
| SSRF with a DNS-only callback | Does it reach an internal service or the metadata endpoint? | SSRF via an open redirect the filter follows |
| SQLi on one parameter | Every parameter on that endpoint | The same parameter type on sibling endpoints |
| File upload accepting PNG | SVG (XSS), HTML, and server-executable extensions | Double extension and content-type confusion |
| OAuth missing PKCE | Is `state` validated, or is the flow CSRF-able? | Is an authorization code redeemable twice? |
| Open redirect | OAuth `redirect_uri` code theft | Phishing / referrer leak chain |
| GraphQL introspection on | Auth on mutations | IDOR through `node(id:)` and `nodes()` |
| Race condition on coupons | The same race on credits, wallet, or invites | The same race on the rate limiter itself |
| Exposed bucket listing | JS bundles inside it, grepped for keys | `.env` and build artifacts in the same bucket |
| Missing rate limit on OTP | Direct OTP brute force | Password-reset token brute force |
| CSRF on a sensitive action | Chain with any XSS on the origin | Auto-submitting form / image-tag delivery |
| Path traversal (read) | Environment and log files, not just `/etc/passwd` | Log poisoning into an execution sink |
| API key leaked in a bundle | What can that specific key actually do? | Other keys in the same file |
| Prompt injection in an LLM feature | Can the model read another user's data through its tools? | Markdown-image or tool-call exfiltration |
| Vector store reachable | Cross-tenant retrieval | Persistent corpus poisoning reaching a clean session |

## Recurring chain shapes

- **Open redirect → OAuth code theft → ATO.** The redirect is registered or prefix-matched as a
  `redirect_uri`; the authorization code lands on the attacker's host; the code is exchanged for a token.
  Zero interaction beyond clicking a link on the real domain.
- **Stored XSS → CSRF → privileged action.** The payload waits in a field an admin renders, then submits
  a state-changing request with the admin's session.
- **SSRF → internal service → cloud metadata → IAM credentials.** The DNS-only callback is the
  informational floor; the metadata reach is the finding.
- **Subdomain takeover → OAuth `redirect_uri`.** A dangling CNAME that is also a registered callback host
  is ATO of every user, not a defacement note. Detection only on live hosts — never claim the resource.
- **Bucket listing → bundle → secret → OAuth client.** Each link is often its own separate report.
- **Prompt injection → tool-mediated IDOR → exfiltration.** The agent has authorization the caller does
  not, and the model is the confused deputy.

## Rules before you pursue B

1. **A is confirmed first** — the exact request and response recorded, not "I think A works."
2. **B must be a genuinely different bug** — a different endpoint, mechanism, or impact. The same bug
   reached two ways is one finding with two vectors, and padding a report with it is an AI tell that a
   triager will spot.
3. **B passes the Security-impact gate on its own** (`report-standards`): a named attacker, a boundary
   actually crossed, a C/I/A property that breaks.
4. **B passes the novelty gate on its own** (`variant-analysis`). A chain does not launder a link that a
   published advisory already covers. If B is a known CVE, the chain is A plus a known precondition —
   say exactly that in the report rather than implying the whole chain is novel.
5. **One report per bug, unless they are genuinely one attack.** Separate findings ship separately; a
   chain ships as one report only when the links are steps of a single exploitation path, and then the
   report says which links are individually novel.
6. **Chained proof still obeys `disclosure-ethics`.** No availability testing, stop at n=1 on another
   user's data, detection-only classes stay detection-only, and no persistence or pivoting on a live host.
   A chain that would require crossing one of those lines is described from the confirmed link, with the
   remaining step stated as reasoning and labelled `not tested`.

## Time-box and stop rules

- B not confirmed in ~20 minutes of focused work → write A up and move on.
- A, B and C all confirmed → stop looking for D. Ship.
- B needs a precondition you cannot test → note it in A's report as a stated, labelled assumption.
- Three consecutive B candidates fail the impact gate → the cluster is dry.

**Rabbit-hole signals, any one of which means stop now:** thirty minutes on B with no request that
demonstrates it; a fourth "maybe" candidate; B requiring three simultaneous preconditions; or catching
yourself writing "this could lead to" without a request to point at. That last phrase is the tell —
`guardrails` No Assumption applies to chains exactly as it applies to findings, and an unproven link
gets labelled or deleted, never implied.

## Output

Record the chain in the ledger as its links, each with its own status, and hand report-writer the
confirmed path plus an explicit list of which links are proven, which are `code-confirmed`, and which are
`not tested`. The CVSS vector is derived from what was proven, not from where the chain could have gone.
