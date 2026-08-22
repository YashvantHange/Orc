# Orca — AI/ML Security Research Pipeline

Find unknown vulnerabilities in open-source AI/ML software (Python and JS/TypeScript), prove them
at runtime, and disclose them responsibly through a private GitHub Security Advisory or
[huntr](https://huntr.com/guidelines).

Nine agents in `.claude/` do the reasoning. The Python in this repo is the muscle that runs
scanners, boots targets, sends probes and records evidence.

## Install

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt          # Windows; .venv/bin/pip on *nix
.venv/Scripts/python -m playwright install chromium

python tools/bootstrap.py                              # runtime dirs + clean ledger
python tools/install_tools.py --with-codeql            # gitleaks, osv-scanner, CodeQL
```

Needs Python 3.10+ and git. Node/npm only for JS/TS targets.

## Run

```bash
python intel/repo_intel.py     # ranked candidate targets
/hunt <owner/repo>             # inside Claude Code — the full hunt
python hunt.py --help          # the 17 subcommands, if driving it by hand
```

## Tools

Full detail in **[TOOLS.md](TOOLS.md)**.

| | Tool | Used for |
|---|---|---|
| **Static** | semgrep | multi-language SAST |
| | bandit | Python SAST |
| | CodeQL | dataflow / taint |
| | gitleaks | secrets |
| | pip-audit, osv-scanner | dependency CVEs |
| **Dynamic** | Playwright | headless Chromium — SPA render, DOM XSS |
| | requests, PyJWT | HTTP probes, JWT forgery |
| | hypothesis | fuzzing |
| **Optional** | nmap, ffuf, nuclei, sqlmap, mitmproxy, jwt_tool, httpx, subfinder | not installed or invoked by any script — an agent fetches one on demand if a job needs it |

## Agents

| Agent | Finds |
|---|---|
| `sec-orchestrator` | plans the hunt, routes leads, holds the gates |
| `web-recon-hunter` | attack surface of a live site — crawl, JS/sourcemaps, API specs |
| `authz-logic-hunter` | IDOR, BOLA, privilege escalation, mass assignment |
| `injection-hunter` | RCE, SSRF, SSTI, SQLi, traversal, deserialization |
| `authn-crypto-hunter` | auth bypass, JWT, secrets exposure, CORS, weak crypto |
| `client-side-hunter` | DOM XSS, prototype pollution, CSRF, clickjacking |
| `report-writer` | evidence → report with CWE, CVSS 3.1, dup-check |
| `report-auditor` | cold fact-check — opens every cited line |
| `report-editor` | structure, voice, rendering |

The two report auditors read the finished report cold and each returns PASS or BLOCK. Nothing is
delivered without both, plus a PoC that actually ran. Skills in `.claude/skills/` are the
methodology each agent follows.

## Rules

- **Authorized targets only** — a target you booted yourself, or a live host a validated `scope.yml`
  places inside a published bug-bounty scope. `hunt scope` is the gate.
- **Private disclosure only** — never a public issue before a fix and embargo.
- **Novel bugs only** — anything covered by a published advisory, or an incomplete-fix of one, is
  dropped.
- **Nothing is `CLEAR` until you sent the attack and watched it get rejected.** A clean scan is not
  a verdict.

## What a clone contains

The pipeline, not the research. Cloned targets, evidence, reports, PoCs and the ledger are excluded
by `.gitignore` — findings stay embargoed until the vendor ships a fix. `tools/bootstrap.py`
recreates those directories empty.

## More

`docs/methodology.md` · `docs/disclosure.md` · `scope.example.yml` · `.claude/skills/`

> **Known gap:** the fixture apps under `work/_selftest/` are not built, so 8 of 38 tests fail on a
> missing flask fixture. The rest pass.
