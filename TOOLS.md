# Tools

Every tool this pipeline uses, and what invokes it. Check what you have installed:

```bash
python tools/install_tools.py --check
```

## Prerequisites

| Tool | Required | Why |
|---|---|---|
| Python 3.10+ | yes | the pipeline |
| git | yes | clones targets, pins the commit cited in evidence |
| Node.js + npm | JS/TS targets only | `npm audit`, and booting JS targets |
| GitHub CLI (`gh`) | no | stars/activity/advisory counts for target ranking |

## Installed by `tools/install_tools.py`

Downloaded from the vendors' official GitHub releases into `tools/bin/`. Never system-wide.

| Tool | Used for | Invoked from |
|---|---|---|
| **gitleaks** | secrets scanning | `static/run_secrets.py` |
| **osv-scanner** | dependency CVEs from any lockfile | `static/run_depaudit.py` |
| **CodeQL CLI** | dataflow / taint, Python + JS packs | `static/run_codeql.py` |

```bash
python tools/install_tools.py                # gitleaks + osv-scanner
python tools/install_tools.py --with-codeql  # also CodeQL (~500 MB)
```

Set `GITHUB_TOKEN` if you hit the releases-API rate limit.

## Installed by `requirements.txt`

**Static analysis**

| Package | Used for | Invoked from |
|---|---|---|
| semgrep | multi-language SAST + the rules in `rules/` | `static/run_semgrep.py` |
| bandit | Python SAST → SARIF | `static/run_bandit.py` |
| pip-audit | Python dependency CVEs | `static/run_depaudit.py` |

**Reading code**

| Package | Used for | Invoked from |
|---|---|---|
| tree-sitter + tree-sitter-languages | AST endpoint extraction, cross-language de-dupe | `intel/ast_scan.py`, `correlate/merge.py` |
| libcst | richer Python CST | `intel/ast_scan.py` |

> Keep the pin `tree-sitter==0.21.3` + `tree-sitter-languages==1.10.2`. Version 0.22 changed the API
> and breaks the prebuilt grammars.

**Dynamic testing**

| Package | Used for | Invoked from |
|---|---|---|
| requests | every crafted HTTP probe, scope-gated | `dynamic/scope.py`, `dynamic/probe.py` |
| PyJWT | JWT forgery — `alg:none`, hardcoded secret, algorithm confusion | `dynamic/primitives/authn.py` |
| cryptography | RS256/ES256 JWT probes | `dynamic/primitives/authn.py` |
| dnspython | DNS rebinding, SSRF-guard bypass | `dynamic/primitives/authn.py` |
| websockets | WebSocket probes | `dynamic/primitives/apis.py` |
| hypothesis | property-based fuzzing | `dynamic/fuzz.py` |
| watchdog | filesystem-delta — proves a write or traversal landed | `dynamic/instrument.py` |

**Live websites**

| Package | Used for | Invoked from |
|---|---|---|
| beautifulsoup4 | HTML parsing during crawl | `web/recon.py` |
| playwright | headless Chromium — SPA render, DOM XSS execution, real cookie behaviour | `web/browser.py` |

Playwright needs its browser too:

```bash
.venv/Scripts/python -m playwright install chromium
```

**Plumbing:** PyYAML · GitPython · packaging · rich · flask + pytest (test fixtures)

## Offensive web tools — `--with-offensive`

For **authorized targets only**: a host you booted yourself, or one a validated `scope.yml` places
inside a published bug-bounty scope.

```bash
python tools/install_tools.py --with-offensive
```

| Tool | Used for | Installed as |
|---|---|---|
| **ffuf** | content and parameter fuzzing | `tools/bin/ffuf` |
| **nuclei** | templated vulnerability checks | `tools/bin/nuclei` |
| **httpx** | fast HTTP probing across many hosts | `tools/bin/httpx` |
| **subfinder** | subdomain enumeration | `tools/bin/subfinder` |
| **mitmproxy** | scriptable intercepting proxy | project venv |
| **sqlmap** | SQL injection exploitation | project venv |
| **jwt_tool** | JWT attack toolkit | `tools/bin/jwt_tool/` |
| **nmap** | host / port / service discovery | **detected, not installed** |

Notes:

- **nmap is not auto-installed.** Windows needs an MSI, admin rights and Npcap. Install it from
  <https://nmap.org/download> if a job needs it; `--check` will then find it on PATH.
- **Burp Suite is not drivable from an agent** — Community has no REST API. mitmproxy replaces it.
- Everything lands in `tools/bin/` or the project venv, never on your system PATH.

## What the agents use

The agents in `.claude/agents/` are Markdown, not scripts. Their tools are Claude Code's own; through
`Bash` they reach everything above.

| Agent | Tools | Model |
|---|---|---|
| `sec-orchestrator` | Read, Grep, Glob, Bash, Write, WebFetch, WebSearch | opus |
| `web-recon-hunter` | Read, Grep, Glob, Bash, Write, WebFetch | opus |
| `report-writer` | Read, Grep, Glob, Bash, Write, WebFetch, WebSearch | opus |
| `authz-logic-hunter` | Read, Grep, Glob, Bash, Write | opus |
| `injection-hunter` | Read, Grep, Glob, Bash, Write | opus |
| `authn-crypto-hunter` | Read, Grep, Glob, Bash, Write | opus |
| `client-side-hunter` | Read, Grep, Glob, Bash, Write | opus |
| `report-auditor` | Read, Grep, Glob, Bash, Write | opus |
| `report-editor` | Read, Grep, Glob, Bash, Write | sonnet |

Taken from each agent's `tools:` frontmatter. `python hunt.py agents` prints the live roster.

### The orchestrator

`sec-orchestrator` runs the hunt but tests nothing itself — it plans, routes work to the specialists,
checks what they return, and holds the gates. It works through `hunt.py`:

| Command | Role |
|---|---|
| `hunt scope --lint` / `--check <url>` | authorization gate, before any packet reaches a host it doesn't own |
| `hunt dup <owner/repo> --query` | prior-art check, run early — to exclude, not to copy |
| `hunt scan <src>` | scan → merge → exploit_score → ranked `findings.json` |
| `hunt web <target>` | live-site recon and coverage |
| `hunt sweep <target>` | boots once, then probe + authz differential + fuzz |
| `hunt probe` | one primitive against one endpoint |
| `hunt authz-scaffold` / `hunt authz` | authorization differential |
| `hunt cvss <vector>` | CVSS 3.1 score |
| `hunt poc-run <id> --cmd` | runs the PoC for real, records `runlog.json` |
| `hunt evidence <id>` | builds the evidence bundle |
| `hunt validate-report <id>` | delivery gate — issues the receipt |
| `hunt report <id>` | report scaffold |
| `hunt ledger` / `hunt metrics` | investigation state, so work is never repeated |
| `hunt board` | the live run board |
| `hunt agents` | the roster |

Skills it loads: `guardrails` · `run-board` · `variant-analysis` · `vuln-playbooks` ·
`web-playbooks` · `dynamic-hunt` · `deep-trace` · `cwe-map` · `report-craft` · `report-standards` ·
`disclosure-ethics` · `env`.

> `Task` and `TodoWrite` appear in the orchestrator's instructions (routing to hunters, mirroring the
> board) but not in its `tools:` frontmatter. If that field is a strict allowlist, add them.

## If a tool is missing

It is reported as missing and skipped. A stage that could not run is never a `CLEAR` verdict.
