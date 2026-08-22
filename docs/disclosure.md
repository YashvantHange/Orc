# Responsible disclosure — how to submit, and the ethics checklist

This project exists to get real bugs **fixed**. Disclosure is coordinated, private, and respectful.
Follow this every time.

## Pre-submission checklist (all must be true)

The first item is not a checkbox you tick — it is a file the machine writes. The rest are the human
judgements it cannot make for you.

- [ ] **A gate receipt exists** at `state/gate/<id>.json` and is still valid for the report's current
      bytes (`hunt validate-report <id>`). That receipt means the PoC was recorded by `hunt poc-run`,
      and both `report-auditor` and `report-editor` returned PASS on this exact draft. Without it the
      submission hook will refuse the command, and it should.
- [ ] Testing was **local-only** — against an instance you launched on 127.0.0.1 from a clone — or, for
      a live target, inside a published scope, its window and its rate (`disclosure-ethics`).
- [ ] You ran the **duplicate check** (`hunt dup` / `reports/dup_check.py`) across CVE/GHSA/huntr +
      issues/PRs/commits/releases and it is a **genuine zero-day**. An incomplete-fix or patch-bypass of
      a published advisory is `OUT_OF_SCOPE` under the current policy — not a finding. (This line used
      to say the opposite; `report-standards` § Novelty requirement is authoritative.)
- [ ] The report has: CWE, CVSS 3.1 vector, exact `file:line`, minimal PoC, impact, root cause, and
      a concrete remediation/diff — every one of them filled, none left as a placeholder.
- [ ] **No real secret values, destructive payloads, or weaponized exploits** are included. Secrets
      are redacted; exposed secrets get a private report + a rotation recommendation.
- [ ] The target is **in scope** (huntr program, or a `SECURITY.md` inviting reports).
- [ ] You are not shotgunning: this target's previous report is submitted and triaged, not still open.

## Channel 1 — huntr (preferred for AI/ML; assigns CVEs)

huntr.com is Palo Alto Networks' AI/ML bug-bounty. Two programs: **OSV** (open-source apps/
libraries) and **MFV** (model file formats). Flow: submit **on-platform** (they do NOT accept email
disclosures) → the maintainer is invited to validate (~45-day target) → if validated you get a
bounty and a **CVE is assigned if applicable**.

1. Check the target is in scope at https://huntr.com/bounties.
2. Read https://huntr.com/guidelines.
3. Submit the report on-platform; paste the filled `reports/<...>.md` content.
4. Engage with the maintainer's questions; keep it collaborative.

## Channel 2 — GitHub Security Advisory (GHSA), when not on huntr

1. Go to the repo's **Security → Advisories → Report a vulnerability** (private draft), or follow the
   repo's `SECURITY.md`.
2. Paste the report. The maintainer can request a CVE via GitHub as a CNA.
3. If there is no `SECURITY.md` and no private-advisory option, look for a documented security email;
   if none exists, do **not** open a public issue with exploit details — ask the maintainer privately
   how they prefer to receive security reports.

## After submitting

- Set the finding to `REPORTED` in `state/ledger.json` (report path + channel).
- Respect the embargo: no public writeup until a fix ships and the maintainer agrees.
- When a fix lands, run `reports/verify_patch.py --fixed <commit>` to confirm it — and check for a
  **patch bypass** (a very common source of a follow-up CVE).
- Update the ledger through `FIXED` / `CVE_ASSIGNED`.

## Ethics, plainly

Find bugs to help projects, not to farm CVEs or clout. Report privately, prove impact benignly,
credit the maintainers' time, and never use a finding against a live system or user. If in doubt
about scope or harm, stop and ask.
