---
name: disclosure-ethics
description: >
  The minimal responsible-disclosure floor for the hunting pipeline, covering both local source
  targets and live authorized websites. Short by design. Consult if unsure whether an action is
  in scope.
---

# Disclosure floor (lowered — we enumerate every vuln class, aggressively)

> This is the *ethics* floor. The pipeline's other standing rules — **No Assumption**, **No
> Hallucination**, and the anti-bypass rule, plus the inventory of which guardrails are
> hook-enforced and which are on you — live in **`guardrails`**. Both bind at once.

We hunt hard and confirm real, high-impact bugs. The only standing constraints:

- **Authorized targets only.** Either a copy you cloned and launched yourself on `127.0.0.1`, **or**
  a live host that a published bug-bounty/VDP scope authorizes — inside its stated window, at its
  stated rate, on its listed hosts and paths. Nothing else. A host being reachable is not permission.
- **Coordinated disclosure.** Report through the maintainer's channel (huntr on-platform, the
  program's platform, or a private GHSA / `SECURITY.md`). Don't publish a 0-day before the
  maintainer can fix it.
- **Don't destroy or exfiltrate real user data** to prove a point — a benign marker proves impact
  just as well (see `marker-conventions`). Redact any real secret you happen to observe.

Everything else is fair game *technically*: full PoC development, sandbox escapes, auth bypasses,
chaining. No per-call payload policing — use judgment.

## Live websites: what "authorized" actually requires

Before the first request to a host you don't own, all four must be true. Write them into
`work/<slug>/scope.yml` (start from `scope.example.yml`) and verify with `hunt scope --file <f> --lint`.

1. **A published policy that names the host.** Read it yourself, hash the text into
   `program.policy_sha256`. A wildcard in a program's scope list is not an invitation to guess
   which subdomains it meant — enumerate, then check each against the policy.
2. **You are inside the test window**, and the window is recorded.
3. **The rate is one the policy permits.** Default `rps: 2.0`. If the policy is silent, stay slow.
4. **A human typed `program.authorized_by`.** This is the field that carries legal weight; it is
   not something an agent should generate for itself.

`dynamic/scope.py` enforces hosts, paths, methods, rate, budget and window on every request and
writes `work/<slug>/web/transcript.jsonl`. **It is a safety net, not permission.** It cannot know
whether the program is real, whether the host belongs to it, or whether the policy changed
yesterday. You can.

### Beyond what the guard can check

The guard blocks the mechanical mistakes. These are on you:

- **No availability testing.** No volumetric floods, no ReDoS payloads at production scale, no
  connection exhaustion, no fork bombs through a rendering service. A DoS you "proved" is an outage
  you caused. Reason about the class, report the reachable sink, don't fire it.
- **No destructive verbs against real records.** Prove write access by writing a benign marker to
  *your own* object, not by deleting someone else's.
- **Stop at the first record.** If an IDOR returns another user's data, you have your proof at
  n=1. Do not enumerate the range to "measure impact" — a screenshot of one redacted record is a
  better report than a dump, and the dump is the part that gets a researcher banned.
- **Redact in the evidence bundle, not just in the report.** The transcript stores response bodies.
  Scrub real names, emails, tokens and PII before the bundle leaves your machine.
- **No persistence and no pivoting.** Don't plant a webshell, don't keep a foothold, don't use one
  in-scope host to reach an out-of-scope one, don't touch internal hosts an SSRF exposes beyond the
  minimum needed to show the boundary is crossed.
- **Third parties are not in scope even when they answer.** A dangling CNAME, an S3 bucket, a CDN,
  an OAuth provider — confirm the *dangling pointer*, never claim the resource.
- **Cache and shared-state attacks touch other users.** Web cache poisoning, cache deception and
  request smuggling can serve your payload to a stranger. Detection only: unique cache-buster
  paths, timing-based smuggling probes, no desync you actually drive. If you cannot demonstrate it
  without a bystander receiving it, write it up as unconfirmed and say why.
- **No social engineering, no physical, no attacks on staff accounts.** Test the software.
- **If you appear to have hit a live incident** — real customer data in an error, evidence of
  someone else's compromise, an accidental state change you cannot undo — stop, preserve what you
  have, and report it immediately as an urgent finding. Do not keep probing.

If a check cannot be run safely against production, that is not a `CLEAR`. It is `BLOCKED` — say
what blocked it and what would unblock it (a staging instance, written permission, a lower rate).

**Scope note (not an ethics limit, a reporting policy):** we report **genuine zero-days only** — nothing
covered by one of the product's published CVEs/GHSAs, and nothing that's an incomplete-fix / patch-bypass
/ variant of one. You may still *study* published fixes, but only to prove novelty and exclude variants
(`variant-analysis`); a patch-bypass is out of scope, not a finding. Full rule: `report-standards`.
