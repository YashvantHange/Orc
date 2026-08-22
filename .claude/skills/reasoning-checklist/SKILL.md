---
name: reasoning-checklist
description: >
  The closing self-check every hunting skill ends by running before a lead is called a finding.
  Consult to pressure-test a candidate bug for consistency and completeness.
---

# Reasoning checklist (run before you call a lead a finding)

Answer each explicitly. A "no" or "unsure" means the finding is `UNCONFIRMED` — say which item and the
exact next step, don't inflate it.

1. **Did I verify exploitability at runtime, on top of the trace?** The code trace is necessary and
   not sufficient: I also sent the request against a running instance and observed the impact,
   reproduced it 2–3×, and showed it differs from the baseline / a negative control. A bug proved only
   by reading is `code-confirmed`,
   which is an honest label for the `disclosure-ethics` exemptions (detection-only classes, anything
   that would be an availability test on a live host) and for nothing else. Same rule inverted for the
   classes you closed: did each `CLEAR` come from an attack I actually sent, or only from a guard I
   read? The second is `BLOCKED (untested)`.
2. **Is this a security vulnerability, not a bug?** The Security-impact gate in `report-standards`,
   all three `yes`: a named attacker who doesn't already have this outcome legitimately; a trust
   boundary actually crossed (unauth→auth, user→user, tenant→tenant, low-priv→admin,
   untrusted-input→server); and a C/I/A property that breaks — one that survives CVSS derivation
   rather than scoring `C:N/I:N/A:N`. Checked docs/config/defaults/threat-model, so this isn't a
   feature, an admin-only surface, a knob the operator opted into, self-DoS, a performance regression,
   or a hardening suggestion with no demonstrated impact. Any "no" is `OUT_OF_SCOPE` with a one-line
   reason — we hunt vulnerabilities, and the issue tracker is where the rest belongs.
3. **Did I locate the root cause?** The specific flawed line/logic, captured as a root-cause graph
   (`report-standards`) — not a generic description.
4. **Did I identify the patch location?** The exact boundary where the fix belongs.
5. **Did I sweep for more instances of this novel bug?** Grepped for sibling routes/sinks/inherited
   impls with the same flaw — there are usually more. (But a sibling that a *published* fix simply
   didn't reach is an incomplete-fix, not novel — see #8.)
6. **Did I estimate impact honestly?** Who's affected, blast radius (one object vs all tenants),
   realistic attacker + preconditions; mapped to a CVSS vector I can defend. **Name the variant** — the
   severity lives there, and a vague label is an over- or under-claim: reflected vs **stored** XSS, file
   **read** vs **write** (and what the write reaches), object-level vs function-level authz, one user's
   data vs cross-tenant, evaluation vs proven sandbox escape for SSTI, a redaction gap vs a genuinely
   unauthenticated secret read.
7. **Did I collect sufficient evidence?** Request+response, server-log/stack excerpt, commit, and the
   PoC command — bundled (`evidence.json`) so a maintainer can reproduce it.
8. **Is it a genuine zero-day?** Dedup + checked HEAD/the latest advisory (`variant-analysis` /
   `hunt dup`), and proved: **no published CVE/GHSA for this product covers this bug, AND it is not an
   incomplete-fix / patch-bypass / variant of one** (incl. a sibling a patch didn't reach). If it fails
   this, it's `OUT_OF_SCOPE` — not a finding. Novelty litmus: a maintainer would log it as a *new* bug,
   not as "finish fixing CVE-X."
9. **Does it have a gate receipt?** (The Delivery gate in `report-standards`.) The PoC was executed
   through `hunt poc-run` (≥2 recorded runs) and every output in the report appears in one of them;
   `report-auditor` and `report-editor` both returned PASS against the report's current bytes;
   `hunt validate-report <id>` wrote `state/gate/<id>.json`. Any "no" means the report is **not
   deliverable** — name the failed item and the next step. This one isn't on your honour: the hooks
   refuse to end the turn or run a submission command without the receipt.
10. **Did I assume or invent anything?** (`guardrails`.) Walk the finding sentence by sentence and mark
    each load-bearing claim with how you know it — read at the pinned commit / observed in a recorded
    run / derived metric by metric. Any claim whose source is "it follows", "that's the usual default",
    "the hunter said so", or memory is an **assumption**: verify it now or label it in the text. Any
    specific you could not point at a source for — a `file:line`, a version, an id, an output line, a
    status code, a hash — is a **hallucination**: delete it or go obtain it. Both rules fail closed;
    an unverifiable claim makes the finding `UNCONFIRMED`, not "probably fine".
