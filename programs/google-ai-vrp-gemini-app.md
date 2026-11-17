# Google AI VRP — Gemini App (Flagship)

Destination program dossier for the **Gemini App** target. Resolved **2026-10-20** from the primary
source: the rules markdown in the public `google/bughunters` repo. Not from bughunters.google.com —
that site is a client-rendered SPA and returns only a page shell to curl/WebFetch
(see `memory/google-vrp-rules-check.md`).

Reproduction commands:

```sh
gh api repos/google/bughunters/contents/bughunters/articles/about/rules/google-friends/ai-vulnerability-reward-program-rules.md --jq '.content' | base64 -d
gh api repos/google/bughunters/contents/bughunters/articles/about/rules/google-friends/google-and-alphabet-vulnerability-reward-program-vrp-rules.md --jq '.content' | base64 -d
gh api repos/google/bughunters/contents/bughunters/articles/about/rules/other/code-of-conduct-for-our-vulnerability-reward-programs.md --jq '.content' | base64 -d
gh api repos/google/bughunters/contents/domain-tiers/external_domains_google.asciipb --jq '.content' | base64 -d
```

## This is NOT the OSS VRP

`programs/google-oss-vrp.md` is a different program and its 2026-10-01 closure to product
vulnerabilities **does not apply here**. Gemini App is a Google production service, not a Google OSS
repo. Nothing in this target routes through the OSS VRP, and `google-gemini/gemini-cli` (the CLI,
`TIER_OT1 / SCOPE_CLOUD_VRP`, see `memory/gemini-cli-hunt-triaged.md`) is a **separate target** —
do not merge the two surfaces or reuse those findings here.

## Two lanes, and the lane decides the payout

The deciding question is whether **interaction with the LLM is an integral part of the
vulnerability**. Verbatim from the AI VRP scope: *"AI-related issues are those issues where
interaction with a Large Language Model (LLM) or other Generative AI (GenAI) system, such as a
natural language interaction, is an integral part of the vulnerability or abuse issue."*

| Lane | When | Reward basis |
|---|---|---|
| **AI VRP** | the LLM interaction is integral (prompt injection, tool invocation, memory, model output handling) | AI VRP Product Tier × Category |
| **Google & Alphabet VRP** | a classic web defect that happens to live on this host (XSS, IDOR, CSRF, authz) | Domain Tier × Information Tier / Action Criticality |

### Lane 1 — AI VRP tier: FLAGSHIP (confirmed verbatim)

The AI VRP product-tier list names **Gemini Apps** explicitly under *Flagship*, covering
`https://gemini.google.com` (Web), the Android app `com.google.android.apps.bard`, and the iOS app
`id6477489729`. Flagship is the top tier — same band as Google Search on google.com and Workspace
core apps.

Reward table, Flagship column:

| Category | Flagship |
|---|---|
| **S1: Rogue Actions** — modify the state of the victim's account or data with a clear security impact | **$20,000** |
| **S2: Sensitive Data Exfiltration** — leak the victim's SPII/PII or other sensitive data without an effective opportunity for user approval | **$15,000** |
| **A1: Phishing Enablement** — persistent, cross-user HTML injection on a Google-branded site with no user-generated-content warning | $5,000 |
| **A2: Model Theft** — exfiltrate complete, detailed, confidential model parameters ("successful reports in this category are extremely rare") | $5,000 |
| **A3: Context Manipulation (cross-account)** — repeatable, persistent, hidden manipulation of a victim's AI context without significant victim interaction | $5,000 |
| **A4: Access Control Bypass (limited security impact)** — exfiltrate data otherwise inaccessible | $2,500 |
| **A5: Unauthorized Product Usage** — enable functional server-side features without authorization/billing | $1,000 |
| **A6: Cross-user Denial of Service** — persistent DoS of a feature in a non-attacker victim account from a limited set of requests | $500 |

Quality multiplier **0.8x / 1x / 1.2x**, panel discretion. Novelty bonus **+$1k–$5k** for reports
that "caused our security teams to think differently about a problem."

**Downgrade axes** (each is a predetermined step down, and they stack): minor **Impact**; **Prior
access** to a victim resource required; **Project access** required; significant **User
interaction** by the victim required; **Exploitability** — "still possible, but we consider the
vulnerability unexploitable in practice," which can also cut the quality rating or fail triage
outright.

Read those four axes as the design brief for the PoC, not as fine print. The same defect is worth
$20,000 with no preconditions and far less behind a stack of them. This is the same
precondition-stacking effect already recorded for Google in
`memory/google-oss-vrp-preconditions-set-severity.md` — three stacked conditions turned a 7.1 into
P4/S4 Infeasible there.

### Lane 2 — Google & Alphabet VRP domain tier: TIER0 (confirmed verbatim)

`domain-tiers/external_domains_google.asciipb`:

```
domain: {
  fqdn: "gemini.google.com"
  tier: TIER0
}
```

`bard.google.com` is also `TIER0`. Two subdomains are explicitly **TIER2**, not TIER0, and must not
be confused with the apex: `enterprise.gemini.google.com` and `lti.gemini.google.com`.

TIER0 is the top domain column (`T0`). Relevant T0 amounts:

| Category | T0 |
|---|---|
| Remote code execution (S0) | $101,010 |
| Logic flaw leaking/bypassing significant security controls, Information Tier 0 or Critical Actions — e.g. IDOR, remote user impersonation (S2a) | $50,000 |
| Same, Information Tier 1 / Impactful Actions (S2b) | $31,337 |
| Execute code on the client — XSS (C0) | $20,000 |
| Other valid security vulnerability / state-changing action, Information Tier 0 leak or Critical Actions (C1a) | $15,000 |

A Gemini conversation contains whatever the user typed and whatever the connectors pulled in, so an
exfiltration primitive here plausibly reaches **Information Tier 0** (the tier that covers "contents
of a user's emails", credentials, OAuth tokens). Do not assert a tier in a report — state the data
observed and let the panel tier it.

## Ineligible — read before building any PoC

From the AI VRP's own "Read this before you submit!" list and its non-qualifying table. These are
not severity discounts; the report is closed:

* Violative, misleading or factually incorrect content **within the attacker's own session** —
  standard jailbreaks, safety bypasses, alignment bypasses, hallucinations. The entire
  content-generation family is out. In-product feedback links are the channel.
* **Preamble/system-prompt extraction** without sensitive-information leakage. System prompts and
  training corpora are "almost always non-confidential and specifically out of scope."
* **Execution of arbitrary code inside the sandbox** — "Gemini provides access to code execution
  tools." The sandbox is a feature. Only a documented **escape** is a finding.
* Insecure/unsafe **MCP server interaction when configured by the victim**.
* **Harm achievable through existing non-AI tools** — if the same outcome is already reachable
  without the AI, there is no finding. This is the marginal-gain test from
  `memory/security-vulns-not-feature-bugs.md`, written into the program's own rules.
* **Intended functionality** — accessing or summarizing the user's own data when permitted.
* Incorrect output/classification with no compelling attack scenario or feasible path to user harm.
* Low-impact UX disruptions; IP/copyright issues; compliance/legal/privacy-law issues.
* Imprecise weight extraction, or weights from a non-confidential model (e.g. Gemma).

Additively, the **whole Google VRP non-qualifying list** applies. The ones that will actually come
up on this target: **URL redirection** (open redirect does not qualify — well-designed redirectors
are an accepted risk); **XSS in sandbox domains** such as `*.googleusercontent.com` unless impact on
sensitive user data is demonstrated; **logout CSRF**; **bugs requiring exceedingly unlikely user
interaction**; **banner/version disclosure**; **user enumeration** unless rate limits are absent;
flaws affecting only out-of-date browsers.

**A1's own carve-out:** sites intended for user-generated content are excluded from Phishing
Enablement, and the injection must be *persistent and cross-user*. Self-HTML in your own session is
not A1.

**S1's own carve-out, verbatim footnote:** *"a bug which can create an email draft with arbitrary
content does modify the state of a victim's account, but it does not clearly demonstrate an impact
of the attack."* A state change is not automatically a Rogue Action — the security impact must be
clear. Aim at an action with a consequence (sharing, sending, permission change, deletion,
purchase), not at a draft.

## Testing conduct — binding, and account-destroying if ignored

Intake: **https://bughunters.google.com/report** (`g.co/vulnz`). Login-gated SPA; Claude cannot
file it. The pipeline's finish line is a paste-ready folder plus `submission-fields/`.

* **Only ever target your own accounts.** "Never attempt to access anyone else's data." Cross-user
  classes (S1/S2/A3/A6 all need a victim ≠ attacker) must be proven with **two accounts you own**.
* **Use a dedicated test account.** The rules say outright that Google cannot guarantee restoring an
  account disabled by testing, and recommend creating a testing-only account first. Do not point
  this at a primary Google account.
* **No DoS, no volumetric testing.** Verbatim: "please do not attempt to carry out DoS attacks... We
  also discourage the use of any vulnerability testing tools that automatically generate very
  significant volumes of traffic." The Code of Conduct calls service degradation "strictly
  forbidden." **No sweep, no fuzz, no scanner against this host.** A6 is the one availability
  category and it is capped at "a limited set of requests" against an account you own —
  self-DoS is explicitly excluded.
* **If real user data appears:** cease testing immediately, limit access to the minimum needed to
  prove the bug, do not download excessive amounts, report immediately, purge it.
* **Verify everything yourself.** The Code of Conduct names "lack of verification" — especially of
  automated or **AI-tool** output — as unprofessional conduct, and a high volume of invalid
  submissions as a Code violation. Speculative findings with no practical PoC are discouraged.
* **No third-party brokers**, no public disclosure before coordination.
* **First in, best dressed** — reward only for the first report of a previously unknown flaw.
* Participation is 18+. Sanctions-list territories, Russia and Belarus cannot be paid.

## Lane-selection checklist before opening a report lane

1. Is the LLM interaction integral? → AI VRP (Flagship). Otherwise → Google VRP (TIER0).
2. Which AI VRP category does it land in, by its own words? If none fit, "Other Abuse or Security
   Issues" still requires the page's qualifications to be met.
3. Run the marginal-gain test in the program's own form: **is this harm achievable through existing
   non-AI tools, or through the product's intended functionality?** If yes, stop.
4. Is it on the ineligible list above? Content generation, sandbox code execution and non-sensitive
   preamble extraction kill the majority of candidate "Gemini bugs" — check first, not after a PoC.
5. Count the downgrade axes the PoC requires (prior access, project access, user interaction,
   practical exploitability). Each one is a step down from the headline number.
6. `hunt impact-gate` still applies, including the availability blocker for `google-vrp` —
   A6 is the only availability lane and it is a $500 category at Flagship.
