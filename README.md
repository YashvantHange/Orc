# Orca — AI/ML Security Research Pipeline

**Find previously-unknown vulnerabilities in open-source AI/ML software, prove them at runtime, and
disclose them responsibly.**

Targets Python **and** JS/TypeScript projects. Findings go out as private GitHub Security Advisories
or [huntr](https://huntr.com/guidelines) reports — the path by which CVEs get assigned and credited.

```
/hunt <owner/repo>        →     one command, nine agents, a submittable report
```

---

## The idea in one paragraph

**The Markdown is the product.** The agents and skills in `.claude/` are the brain: they read source,
reason about logic and authorization bugs that no scanner encodes, confirm them by sending a real
request, and write the disclosure. The Python in `intel/ static/ correlate/ dynamic/ evidence/ web/`
is deterministic **muscle** — it runs scanners, boots targets, sends probes, records evidence.
The muscle is replaceable; every one of its commands has a manual equivalent. The reasoning is not.

---

## Quickstart

**Needs:** Python 3.10+, git. Node/npm only for JS/TS targets.
Full tool inventory → **[TOOLS.md](TOOLS.md)**

```bash
# 1 · python muscle
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt          # Windows; .venv/bin/pip on *nix
.venv/Scripts/python -m playwright install chromium    # headless browser, for web targets

# 2 · runtime dirs + a clean ledger  (research output is never tracked in git)
python tools/bootstrap.py

# 3 · binary tools
python tools/install_tools.py --with-codeql            # gitleaks, osv-scanner, CodeQL
python tools/install_tools.py --check

# 4 · verify
python hunt.py --help
python hunt.py agents                                  # roster: 9 agents, 18 skills
python -m pytest tests/ -q
```

Then hunt:

```bash
python intel/repo_intel.py     # ranked candidate table → pick a target
/hunt <owner/repo>             # inside Claude Code — the full agent-driven hunt
```

> [!NOTE]
> **Known gap:** the deliberately-vulnerable fixture apps under `work/_selftest/` are not built yet,
> so 7 acceptance tests and 1 gate test fail with `SKIP: no interpreter with flask available for the
> fixture`. The other 30 pass. A missing fixture, not a broken pipeline.

---

## Guardrails — these outrank everything else

| Rule | What it means |
|---|---|
| **No Assumption** | You don't know it until you checked it *this session*. `CLEAR` requires reading the guard **and** sending the attack and watching it get rejected. A clean scan is not a verdict. |
| **No Hallucination** | Never write a specific you didn't obtain — `file:line`, versions, CVSS vectors, command output, gate receipts. Paste from recorded runs; never retype from memory. |
| **No bypass** | A guardrail is not a step you may decide is already satisfied. `.claude/settings.json`, `tools/hooks/**`, `reports/gate.py` and `evidence/runlog.py` are deny-listed on purpose. |

**Authorized targets only.** Either a target you cloned and booted yourself on localhost, or a live
host that a validated `scope.yml` places inside a published bug-bounty/VDP scope — inside its window,
at its stated rate. `hunt scope` is the gate; `dynamic/scope.py` enforces it on every request and
transcribes what it sent. Exit code 3 means a request was refused as out of scope.

**Responsible disclosure only.** Private GHSA or huntr. Never a public issue before a fix and embargo.
Exposed secrets get a private report plus a rotation advisory — never a post.

**Novel zero-days only.** A candidate covered by a published advisory, or that is merely an
incomplete-fix or patch-bypass of one, is marked `OUT_OF_SCOPE` and dropped. Volume is not the metric;
accepted-over-submitted is (`hunt metrics`).

---

## How a hunt runs

```
                        ┌──────────────────────────────────────────┐
   /hunt <target>  ───▶ │            sec-orchestrator              │
                        │  plans · routes · gates · owns the board │
                        └───────────────────┬──────────────────────┘
                                            │
     ┌──────────────┬──────────────┬────────┴────────┬──────────────┐
     ▼              ▼              ▼                 ▼              ▼
 web-recon      authz-logic    injection       authn-crypto    client-side
  (first,       IDOR · BFLA    RCE · SSRF      JWT · secrets   DOM XSS · CSRF
   alone)       priv-esc       SSTI · SQLi     CORS · crypto   proto-pollution
     │              │              │                 │              │
     └──────────────┴──────────────┴────────┬────────┴──────────────┘
                                            │  a confirmation INTERRUPTS the hunt
                                            ▼
                    report-writer ─▶ report-auditor ─▶ report-editor ─▶ delivery gate
                                     (cold, hostile)   (voice, form)    state/gate/<id>.json
```

**Stages the muscle provides:**

| Stage | Directory | What it does |
|---|---|---|
| Repository intelligence | `intel/` | ranks candidates by maturity, complexity, attack + auth surface |
| Static analysis | `static/` | semgrep · bandit · CodeQL (py+js) · dep-audit · secrets |
| Correlation | `correlate/` | multi-language AST de-dupe → `findings.sarif` / `findings.json` |
| Exploitability scoring | `correlate/` | gates which leads earn dynamic testing |
| Dynamic validation | `dynamic/` | instrumented boot + probes + authz differential + fuzz |
| Live-site recon | `web/` | crawl · render · JS/sourcemap mining · OpenAPI/GraphQL · baselines |
| Evidence | `evidence/` | per-finding bundle with a recorded runlog |
| Report | `reports/` | GHSA/huntr report + CVSS + dup-check + patch-verify |

---

## What the orchestrator uses

`sec-orchestrator` is the lead agent. It never scans or exploits anything itself — it plans, routes,
verifies and gates. Three kinds of tool are available to it.

### 1 · Claude Code tools

| Tool | Used for |
|---|---|
| `Read` | opening source at the pinned commit, evidence bundles, gate receipts |
| `Grep` | deriving the route table on `src` targets; locating guards and sinks |
| `Glob` | mapping the target's layout before any scan |
| `Bash` | every `hunt.py` subcommand below, plus `git`, target boots, `curl` probes |
| `Write` | `work/<slug>/profile.json`, scope files, coverage tables |
| `WebFetch` · `WebSearch` | published advisories for the novelty exclusion map, `SECURITY.md`, program policy |
| `Task` \* | spawning the five specialist hunters and the three report agents |
| `TodoWrite` \* | mirroring the run board so progress shows in the UI, not just the text |

The first seven are its `tools:` frontmatter verbatim. \* `Task` and `TodoWrite` are used by the
orchestrator's instructions but are not listed there — see the note in [TOOLS.md](TOOLS.md#4a-the-orchestrator-specifically).

### 2 · The `hunt.py` front door

One call per stage, so tokens go to reasoning instead of shelling out a dozen scripts.

| Command | What the orchestrator does with it |
|---|---|
| `hunt scope --file <f> --lint / --check <url>` | **hard gate** before any packet reaches a host it doesn't own |
| `hunt dup <owner/repo> --query "<class>"` | prior-art check — run *early*, to exclude, not to emulate |
| `hunt web <target>` | live-site recon and coverage; derives the request budget spent |
| `hunt scan <src>` | chains scan → merge → exploit_score → ranked `findings.json` |
| `hunt sweep <target>` | boots **once**, then probe + authz differential + fuzz on that instance |
| `hunt probe --url --primitive --endpoint` | a single primitive against one real endpoint |
| `hunt authz-scaffold <src>` · `hunt authz` | derives an `authz.json` skeleton, then runs the differential |
| `hunt cvss <vector>` | CVSS 3.1 score for the report |
| `hunt poc-run <target> <id> --cmd` | **executes** the PoC for real and records `runlog.json` |
| `hunt evidence <target> <id>` | assembles the `evidence.json` bundle |
| `hunt validate-report <id>` | the delivery gate — verifies the chain, issues the receipt |
| `hunt report <id> [--layout github\|hackerone]` | the report section scaffold |
| `hunt ledger add/update` · `hunt metrics` | investigation state, so work is never repeated |
| `hunt board init/start/done/set/tally/lane/show` | the live run board, reprinted at every boundary |
| `hunt agents [--skills]` | the roster — each agent, its model, tools and skills |

### 3 · Skills it loads

The twelve it names by name: `guardrails` (first, and again before any report) · `run-board` ·
`variant-analysis` (the novelty gate) · `vuln-playbooks` (the coverage matrix — ~55 classes in seven
groups) · `web-playbooks` for live targets · `dynamic-hunt` before any class is called `CLEAR` ·
`deep-trace` when a surface read comes up clean · `cwe-map` · `report-craft` and `report-standards`
the moment a lead confirms · `disclosure-ethics` for anything it doesn't own · `env`.

> The orchestrator delegates every actual test. It reads `guardrails` first, verifies scope, builds
> the exclusion map, keeps one booted instance alive for the whole hunt, requires each hunter to cite
> **the request it actually sent**, and treats a hunter's `CONFIRMED` as a lead until it opens the
> evidence itself.

---

## Target kinds

| Kind | Input | Surface from | Verdicts qualified by | Report anchored on |
|---|---|---|---|---|
| `src` | `owner/repo` or a local path | `Grep` over the routes | **hops** (`deep-trace`) | `file:line` at a pinned commit |
| `url` | `https://host` + a `scope.yml` | web-recon-hunter's inventory | **enumeration tuple** | transcript `T#####` ids |
| `grey` | both | both, fused | both | both — **the strongest mode** |

Always try to reach `grey`. If a live target ships JS sourcemaps carrying `sourcesContent`,
web-recon-hunter recovers the front-end source and `hunt scan` restores real `file:line` evidence.
That upgrade takes ten minutes and improves everything downstream.

---

## The agent team

| Agent | Owns |
|---|---|
| `sec-orchestrator` | plans the hunt, routes leads, enforces guardrails, owns the ledger and run board |
| `web-recon-hunter` | runs **first and alone** on live targets: scope check, crawl, JS/sourcemap mining, API specs, identities, baselines |
| `authz-logic-hunter` | broken access control · IDOR/BOLA · BFLA · priv-esc · mass assignment · race/TOCTOU |
| `injection-hunter` | RCE · SSRF · SSTI · command/SQL injection · traversal · deserialization · ReDoS · prompt injection |
| `authn-crypto-hunter` | auth-by-default · JWT · session lifecycle · secrets exposure · CORS · weak crypto |
| `client-side-hunter` | DOM XSS · prototype pollution · postMessage · CSRF · clickjacking · CSP · cookies |
| `report-writer` | evidence → GHSA/huntr report with CWE, CVSS 3.1, dup-check and a remediation diff |
| `report-auditor` | cold hostile fact-check; opens every cited line and byte-compares it |
| `report-editor` | title, structure, voice, rendering |

**Why two auditors.** Both read the finished report **cold** — never the hunt's reasoning — and each
emits a PASS/BLOCK bound to the report's sha256. `reports/gate.py` releases nothing without both
verdicts on the exact bytes on disk, on top of a PoC that `hunt poc-run` actually executed. The hooks
in `.claude/settings.json` make that unskippable: a `Stop` hook holds the turn open while a touched
report has no receipt, and a `PreToolUse` hook refuses to transmit one.

Skills in `.claude/skills/` are the executable methodology each agent performs.

---

## How the novel bugs get found

Five mechanisms, wired across the stages:

- **Dataflow/taint** — CodeQL with the custom queries in `rules/codeql/`
- **Semantic agent review** — logic and authorization bugs no rule encodes; the largest source
- **Multi-user differential testing** — the authz harness that makes IDOR and priv-esc visible
- **Fuzzing** — property-based, over parsers and loaders
- **Variant analysis** — used as a **novelty gate**: build the product's advisory exclusion map, then
  reject anything that lands inside it

Scanners give up exactly where the remaining bugs live — dynamic dispatch, registries, subclass
overrides, DI, config-named handlers, queue boundaries, cross-language calls. That's why a clean scan
closes nothing, and why `deep-trace` exists.

---

## What a clone contains

**You get** the whole pipeline: agents and skills (`.claude/`), the `hunt.py` front door, every stage,
the rules, report templates and tests.

**You don't get** anyone's research output. Cloned targets, scan databases, evidence bundles,
disclosure drafts, PoCs, submission packets and the investigation ledger are excluded by
`.gitignore` — findings stay embargoed until the vendor ships a fix. `tools/bootstrap.py` recreates
those directories empty so a fresh clone runs immediately.

---

## Further reading

| Document | Contents |
|---|---|
| **[TOOLS.md](TOOLS.md)** | every tool, what invokes it, how to install it |
| `docs/methodology.md` | per-class hunting playbooks |
| `docs/disclosure.md` | huntr + GHSA submission steps, ethics checklist |
| `scope.example.yml` | the authorization record required for any live target |
| `.claude/skills/` | the 18 skills — the methodology itself |
