# AI/ML Security Research & Responsible-Disclosure Pipeline

A repeatable workflow for finding **real, previously-unknown** vulnerabilities in open-source AI/ML
tools (Python **and** JS/TypeScript), confirming them with runtime evidence, and reporting them
responsibly via [huntr.com](https://huntr.com/guidelines) or GitHub Security Advisories — the path
by which CVEs get assigned and credited to you.

> **The Markdown layer is the product.** The Python scripts are deterministic *muscle* (run scanners,
> launch targets, send probes, collect evidence). The **`.claude/agents` + `.claude/skills`** are the
> *brain* — they read the source, reason about logic/authorization bugs the tools can't see, confirm
> with a PoC, and write the report. Run `/hunt <repo>` and the agents drive everything.

## Ethics & guardrails (non-negotiable)

- **Local-only testing.** Only self-hosted instances you launch. Never probe a third-party live
  service or anyone else's deployment.
- **Responsible disclosure only.** Report via huntr or a private GHSA/`SECURITY.md`. Never publicly
  disclose an unpatched bug or publish a working exploit before a fix + embargo. Exposed secrets →
  private report + advise rotation; never post them.
- **Quality over CVE-farming.** Every reported bug needs a runtime-confirmed PoC + evidence bundle,
  and a full duplicate check first.
- **Scope.** Only repos in huntr scope or with a `SECURITY.md` inviting reports.

## Quickstart

Requires **Python 3.10+** and **git**. Node/npm is needed only for JS/TS targets.
The complete tool inventory — every binary, package and what invokes it — is in **[TOOLS.md](TOOLS.md)**.

```bash
# 1. python "muscle"
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt     # Windows; use .venv/bin/pip on *nix
.venv/Scripts/python -m playwright install chromium   # headless browser for web targets

# 2. runtime dirs + a clean ledger (research output is not tracked in git)
python tools/bootstrap.py

# 3. binary tools (gitleaks, osv-scanner; add --with-codeql for the dataflow engine)
python tools/install_tools.py --with-codeql
python tools/install_tools.py --check

# 4. verify
python hunt.py --help
python hunt.py agents            # the roster: 9 agents, 18 skills
python -m pytest tests/ -q
```

> **Known gap:** the deliberately-vulnerable fixture apps under `work/_selftest/` are not built yet,
> so the `tests/test_web_acceptance.py` acceptance suite (7 tests) and one gate test fail with
> `SKIP: no interpreter with flask available for the fixture`. The other 30 tests pass. This is a
> missing fixture, not a broken pipeline.

Then hunt:

```bash
python intel/repo_intel.py      # ranked candidate table -> pick a target
/hunt <owner/repo>              # (inside Claude Code) full agent-driven hunt
```

## What a clone does and does not contain

You get the whole pipeline: the agents and skills (`.claude/`), the orchestrator (`hunt.py`),
every stage (`intel/ static/ correlate/ dynamic/ evidence/ web/`), the rules, report templates,
and the tests.

You do not get anyone's research output. Cloned target source, scan databases, evidence bundles,
disclosure drafts, PoC scripts, submission packets and the investigation ledger are all excluded
by `.gitignore` — findings stay embargoed until the vendor ships a fix and publishes the advisory.
`tools/bootstrap.py` recreates those directories empty so a fresh clone runs immediately.

## Pipeline stages

```
Target (Python and/or JS/TS)
  → Repository Intelligence   intel/       selection: maturity + complexity + attack/auth surface
  → Static Analysis           static/      semgrep + bandit + CodeQL[py+js] + dep-audit + secrets
  → Finding Correlation       correlate/   multi-lang AST de-dupe -> findings.sarif/json
  → Exploitability Scoring    correlate/   gate what gets dynamic testing
  → Dynamic Validation        dynamic/     instrumented run + probes + AUTHZ-DIFFERENTIAL + fuzz
  → Evidence Collection       evidence/    auto-bundle per confirmed finding
  → Report                    reports/     huntr/GHSA report + CVSS + dup-check + patch-verify
```

## The agent team (`.claude/agents/`)

| Agent | Owns |
|-------|------|
| `sec-orchestrator`   | plans the hunt, routes leads, enforces guardrails, owns the ledger and run board |
| `web-recon-hunter`   | builds a live site's attack surface first: scope check, crawl, JS/sourcemap mining, API specs, baselines |
| `authz-logic-hunter` | broken access control / IDOR / BOLA / privilege escalation / mass assignment / TOCTOU |
| `injection-hunter`   | RCE / SSRF / SSTI / command + SQL injection / traversal / deserialization / ReDoS / prompt injection |
| `authn-crypto-hunter`| auth-by-default / JWT / session / secrets exposure / CORS / weak crypto / constant-time |
| `client-side-hunter` | DOM XSS, prototype pollution, postMessage, CSRF, clickjacking, CSP and cookie posture |
| `report-writer`      | evidence → GHSA/huntr report with CWE + CVSS 3.1 + duplicate check + remediation diff |
| `report-auditor`     | cold hostile fact-check of a finished report; PASS/BLOCK bound to its sha256 |
| `report-editor`      | structure, voice and presentation audit of the same report; PASS/BLOCK |

`report-auditor` and `report-editor` read the report cold — never the hunt's reasoning — and the
delivery gate in `reports/gate.py` refuses to release anything without both verdicts on the exact
bytes on disk, on top of a PoC that was actually executed and recorded.

Invoke with `/hunt <repo>` or the Task tool. Skills in `.claude/skills/` are the executable
methodology each agent performs.

## Novel-vulnerability ("0-day") strategy

Six mechanisms, wired across the stages: custom **dataflow/taint** (CodeQL), **semantic agent
review** (logic/authz bugs no rule encodes), **multi-user differential testing** (IDOR/priv-esc),
**fuzzing**, **variant analysis** (hunt one advisory's pattern everywhere), and **patch-bypass**
hunting. Discovery is probabilistic — the pipeline maximizes odds; the agent converts a lead into a
confirmed, evidenced, responsibly-disclosed report.

See `docs/methodology.md` (per-class playbooks, grounded in real LightRAG/n8n advisories) and
`docs/disclosure.md` (huntr + GHSA submission steps + ethics checklist).
