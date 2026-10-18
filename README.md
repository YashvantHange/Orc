# Orc — AI/ML Security Research Pipeline

Find unknown vulnerabilities in open-source AI/ML software (Python and JS/TypeScript), prove them
at runtime, and disclose them responsibly through a private GitHub Security Advisory or
[huntr](https://huntr.com/guidelines).

Seventeen agents in `.claude/` do the reasoning — ten hunters, run in waves, plus the orchestrator,
the report lane, and the two store keepers (`memory`, `mistake`). The Python in this repo is the muscle that runs
scanners, boots targets, sends probes and records evidence.

## Agents

| Agent | Finds |
|---|---|
| `sec-orchestrator` | plans the hunt, routes leads, holds the gates |
| `web-recon-hunter` | attack surface of a live site — crawl, JS/sourcemaps, API specs |
| `authz-logic-hunter` | IDOR, BOLA, privilege escalation, mass assignment |
| `rce-exec-hunter` | code execution, argument & env injection, deserialization, expression languages |
| `server-side-hunter` | SSRF, XXE, traversal, arbitrary write, uploads, host-header, cache, smuggling |
| `datastore-hunter` | SQL / NoSQL / Cypher / ORM / search injection, ORDER BY & identifier injection |
| `xss-hunter` | reflected, stored, DOM and mutation XSS; sanitizer, encoder and CSP bypass |
| `resource-dos-hunter` | ReDoS, expansion bombs, event-loop stalls, stored cycles, OOB index math |
| `authn-crypto-hunter` | auth bypass, JWT, secrets exposure, CORS, weak crypto |
| `client-side-hunter` | prototype pollution, postMessage, CSRF, clickjacking, CSP, cookies |
| `injection-hunter` | prompt injection, insecure output handling, model supply chain, unclaimed sinks |
| `report-writer` | evidence → report with CWE, CVSS 3.1, dup-check |
| `report-auditor` | cold fact-check — opens every cited line |
| `report-editor` | structure, voice, rendering |

The two report auditors read the finished report cold and each returns PASS or BLOCK. Nothing is
delivered without both, plus a PoC that actually ran. Skills in `.claude/skills/` are the
methodology each agent follows.

Coverage runs on two axes. `vuln-playbooks` and `web-playbooks` sweep class-first; `stack-playbooks`
sweeps stack-first (Next.js, Node, Spring Boot, Laravel, ASP.NET, Django/Rails, gRPC, Kubernetes,
CI/CD), because a class sweep never thinks to ask for `/actuator/heapdump`. `api-inventory` finds the
API versions nobody retired and the SPA route groups nobody guarded, and `chain-craft` runs on every
confirmation before the report is written, so a Low that was really step one of a Critical is caught
before triage rather than after.

Parts of `stack-playbooks`, `api-inventory` and `chain-craft` are adapted from
[Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) by Sachin Sharma, whose skill
content is CC-BY-4.0.

## Install

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt          # Windows; .venv/bin/pip on *nix
.venv/Scripts/python -m playwright install chromium

python tools/bootstrap.py                              # runtime dirs + clean ledger
python tools/install_tools.py --with-codeql            # gitleaks, osv-scanner, CodeQL
python tools/install_tools.py --with-offensive         # ffuf, nuclei, httpx, subfinder,
                                                       # mitmproxy, sqlmap, jwt_tool
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
| **Offensive** | ffuf, gobuster, dirsearch, arjun | content, path and parameter fuzzing |
| | nuclei, dalfox, sqlmap, commix, nikto | templated checks, XSS, SQLi, command injection |
| | httpx, katana, subfinder, amass, dnsx, naabu | probing, crawling, subdomains, DNS, ports |
| | mitmproxy, jwt_tool, testssl.sh, trufflehog | proxy, JWT, TLS, secrets |
| **Manual** | Burp Suite, OWASP ZAP, nmap, Wireshark | detected on PATH, not auto-installed — see TOOLS.md |


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
