# Tooling inventory

Every external tool this pipeline drives, what invokes it, and how to get it. Nothing here is
hidden behind an agent — each entry names the file that shells out to it, so you can verify the
list against the source.

Run `python tools/install_tools.py --check` at any time to see what is actually present.

---

## 1. System prerequisites

Install these yourself; the pipeline does not fetch them.

| Tool | Why | Required? | Invoked from |
|---|---|---|---|
| **Python 3.10+** | the whole pipeline | **required** | — |
| **git** | shallow-clones targets, resolves the commit pinned in evidence | **required** | `intel/repo_intel.py`, `evidence/collect.py` |
| **Node.js + npm** | `npm audit` on JS/TS targets, and booting JS targets for dynamic runs | optional (needed for JS/TS targets) | `static/run_depaudit.py` |
| **GitHub CLI (`gh`)** | pulls stars/activity/advisory counts for target ranking | optional (ranking degrades without it) | `intel/repo_intel.py` |

---

## 2. Python packages — `requirements.txt`

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt     # Windows
# .venv/bin/pip install -r requirements.txt       # Linux/macOS
```

### Static analysis
| Package | Role | Invoked from |
|---|---|---|
| `semgrep` | multi-language SAST (Python + JS/TS), plus the custom rules in `rules/` | `static/run_semgrep.py` |
| `bandit[sarif]` | Python-specific SAST → SARIF | `static/run_bandit.py` |
| `pip-audit` | Python dependency CVE audit | `static/run_depaudit.py` |

### Code understanding
| Package | Role | Invoked from |
|---|---|---|
| `tree-sitter==0.21.3` + `tree-sitter-languages==1.10.2` | prebuilt Python/JS/TS grammars for AST endpoint extraction and cross-language de-duplication (pinned pair — `tree-sitter>=0.22` changes the API and breaks the prebuilt grammars) | `intel/ast_scan.py`, `correlate/merge.py` |
| `libcst` | richer Python CST when tree-sitter is too coarse | `intel/ast_scan.py` |

### Dynamic testing
| Package | Role | Invoked from |
|---|---|---|
| `hypothesis` | property-based fuzzing of parsers/loaders | `dynamic/fuzz.py` |
| `requests` | every crafted HTTP probe, and the scope-gated request wrapper | `dynamic/scope.py`, `dynamic/probe.py`, `evidence/collect.py` |
| `PyJWT` | JWT forgery probes (`alg:none`, hardcoded-secret, algorithm confusion) | `dynamic/probe.py`, `dynamic/primitives/authn.py` |
| `cryptography` | asymmetric JWT probes (RS256/ES256 key handling) | `dynamic/primitives/authn.py` |
| `dnspython` | DNS-rebinding and SSRF-guard probes | `dynamic/primitives/authn.py` |
| `websockets` | WebSocket endpoint probing | `dynamic/primitives/apis.py` |
| `watchdog` | filesystem-delta instrumentation (proves a write/traversal actually landed) | `dynamic/instrument.py` |

### Live-website recon
| Package | Role | Invoked from |
|---|---|---|
| `beautifulsoup4` | HTML parsing during crawl//link extraction | `web/recon.py` |
| `playwright` | headless Chromium — renders SPAs, confirms DOM XSS by real execution, tests cookie/CHIPS behaviour a `requests` client cannot | `web/browser.py`, `web/sweep.py` |

Playwright needs its browser binary in addition to the pip package:

```bash
.venv/Scripts/python -m playwright install chromium
```

Without it, browser-dependent steps report themselves blocked rather than silently passing.

### Plumbing
`PyYAML` (scope files, target lists, OpenAPI specs) · `GitPython` · `packaging` (version comparison
for affected/patched ranges) · `rich` (CLI tables).

---

## 3. Binary tools — `tools/install_tools.py`

Downloaded from the vendors' official GitHub releases into `tools/bin/` (gitignored, never
system-wide). Re-running is idempotent.

```bash
python tools/install_tools.py                # gitleaks + osv-scanner
python tools/install_tools.py --with-codeql  # also the CodeQL bundle (~500 MB)
python tools/install_tools.py --check        # report what is installed
```

| Tool | Role | Invoked from | Flag |
|---|---|---|---|
| **gitleaks** | secrets scanning, driven by `rules/gitleaks.toml` | `static/run_secrets.py` | default |
| **osv-scanner** | dependency vulnerabilities from any lockfile (npm and beyond) | `static/run_depaudit.py` | default |
| **CodeQL CLI** | dataflow/taint engine with the Python + JavaScript packs; runs the custom queries in `rules/codeql/` | `static/run_codeql.py` | `--with-codeql` |

Set `GITHUB_TOKEN` if you hit the releases-API rate limit.

---

## 4. What the agents themselves use

The agents in `.claude/agents/` are Markdown, not scripts. Their tools are Claude Code's own —
`Read`, `Grep`, `Glob`, `Bash`, `Write` (plus `WebFetch`/`WebSearch` for `report-writer`,
`sec-orchestrator`, and `web-recon-hunter`). Through `Bash` they reach everything above, normally
via the `hunt.py` front door:

```bash
python hunt.py --help        # every subcommand
python hunt.py agents        # the roster: each agent, its model, tools and skills
```

The detection knowledge lives in `.claude/skills/` and does not depend on the Python layer — the
scripts are optional muscle, and every subcommand has a manual equivalent.

---

## 5. Optional tools the pipeline does *not* bundle

Nothing below is required, referenced by any script, or installed for you. They are listed because
an agent may fetch one mid-hunt when a specific job calls for it — from the vendor's own release
page, into the project venv or a directory under `work/`, never onto your PATH:

`ffuf` · `nuclei` · `sqlmap` · `mitmproxy` · `jwt_tool` · ProjectDiscovery's `httpx`/`subfinder`

**There is no port scanner in this pipeline — no `nmap`, `masscan`, or `naabu`, anywhere.** That is
deliberate. Targets are either source you cloned and booted yourself on localhost, or a live host
inside a published bug-bounty scope, where host/port enumeration is usually out of scope and always
noisy. Discovery here is crawling, JS-bundle mining, and API-spec parsing (`web/recon.py`,
`web/jsintel.py`, `web/apispec.py`) — not network sweeping.

Burp Suite is worth naming for the same reason: it is a GUI proxy with no REST API in the Community
edition, so it is not drivable from an agent loop. `mitmproxy` is the CLI substitute.

---

## 6. Verifying the install

```bash
python tools/install_tools.py --check
python intel/repo_intel.py --self-test
python static/run_all.py work/_selftest/py_app   --lang python
python static/run_all.py work/_selftest/node_app --lang javascript
python -m pytest tests/ -q
```

Any tool that is missing is reported as missing and skipped — the pipeline degrades loudly rather
than pretending a class was checked. A stage that could not run is never a `CLEAR` verdict.
