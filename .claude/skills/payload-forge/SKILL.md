---
name: payload-forge
description: >
  The payload corpus and mutation matrix — one source of truth for the dialects, encodings,
  contexts and oracles that turn a single probe into real coverage. Load when a lead needs
  exercising and you are about to send more than one request: SQLi/NoSQLi dialects, SSTI engine
  syntax, command and argument-injection separators, traversal encodings, SSRF guard bypasses, XSS
  contexts, XXE, LDAP/XPath/Cypher/search filters, deserialization, open redirect, header
  injection, mass assignment and prompt injection. Generation only — this skill never sends;
  execution stays on the scope-gated path so every request keeps its transcript entry.
---

# Payload forge (build the set, then send it through the gate)

One payload is not a test. A class called `CLEAR` after a single `'` is a class that was never
exercised — the guard you failed to beat may only be a WAF signature, a single encoding, or a
dialect the target does not speak. This skill is the shared corpus that replaces per-hunter
guesswork, and the rules that keep a big payload set from becoming a big pile of noise.

**The split that matters:** *you* generate, *the pipeline* sends. Payload generation belongs to the
hunter that read the code, because only that hunter knows which builder is concatenating and which
column is an identifier. Execution belongs to `dynamic/probe.py`, `dynamic/fuzz.py` and
`web/sweep.py`, because they go through `dynamic/scope.py` — the host/rate/budget check and the
`T#####` transcript entry that a black-box report cites instead of `file:line`. A hand-rolled
request against a host you do not own skips both and is a `guardrails` violation, not a shortcut.

## 1. Build the set

```sh
.venv/Scripts/python.exe hunt.py payload --list
.venv/Scripts/python.exe hunt.py payload --class sqli --dialect postgres --encodings raw,url,double-url
.venv/Scripts/python.exe hunt.py payload --class ssti --encodings all --out work/<slug>/dynamic/ssti-plan.txt
.venv/Scripts/python.exe hunt.py payload --class ssrf --dialect callback --port 9001 --json
```

`--class` picks the class, `--dialect` narrows it (repeatable; default is every dialect),
`--encodings all` applies every encoding that makes sense for that class, `--marker` sets the proof
string, `--port` fills the callback templates for SSRF/XXE. `--json` gives you records carrying the
oracle and the control alongside each payload; `--out` writes the plan into the target's workdir so
the next session (and the report) can see exactly what was enumerated.

The corpus lives in [`dynamic/payloads.py`](../../../dynamic/payloads.py). Add a dialect there once
and every hunter gets it — never re-type a payload list into an agent file.

| Class | Dialects covered |
|---|---|
| `sqli` | generic · mysql · postgres · mssql · sqlite · oracle · **identifier** · **second-order** |
| `nosqli` | operator · form · `$where` · js |
| `ssti` | jinja · twig/smarty · el-spel-ognl · erb/jsp/asp · razor · handlebars · freemarker/velocity |
| `cmdi` / `arginj` | posix · windows · quoted ‖ generic · curl · git · tar-zip · `--` separator |
| `path` | posix · windows · absolute · planted sentinel |
| `ssrf` | callback · loopback-alt (decimal/octal/hex/IPv6) · metadata · scheme · guard-bypass |
| `xss` | html · attribute · js-string · url · markdown · svg-upload · mutation |
| `xxe` · `ldap` · `xpath` · `cypher` · `searchq` | file/oob/svg ‖ filter ‖ node ‖ neo4j ‖ lucene/elastic |
| `deser` · `redirect` · `headerinj` · `massassign` · `promptinj` | see `--list` |

Encodings: `raw`, `url`, `double-url`, `unicode`, `mixed-case`, `null-byte`, `html-entity`,
`overlong-utf8` — each class only accepts the ones that mean something for it, so `--encodings all`
gives coverage, not noise.

## 2. The four rules that make a set evidence

1. **Every positive needs its negative control.** The `--json` output carries the control for the
   class; send it in the same run, from the same identity, against the same endpoint. A `500` with
   no control is a bug report about the app's error handling, not a finding.
2. **Name the tuple, not the payload count.** Report *endpoints × parameters × methods × identities
   × dialects × encodings*, the transcript id range, **and the defense you observed**. `hunt payload`
   prints the dialect × encoding half of that tuple for you; `hunt web coverage` derives the rest
   from the transcript.
3. **Find out who answered.** A block page on the payload and the app on a benign request means you
   tested the WAF, not the target: `BLOCKED`, never `CLEAR`.
4. **Generation is not confirmation.** A plan file is a plan. The verdict rules in `dynamic-hunt`
   are unchanged — `CLEAR` still requires that you read the guard **and** sent the attack and
   watched it be rejected, and a set that was built but never fired is `BLOCKED (untested)`.

## 3. What this corpus will not build

`mutating SQL` · `destructive shell` · `availability/exhaustion` · `bulk exfiltration`. Every
payload here is a benign read-only marker, and the ceiling on a time-based oracle is
`SLEEP_CEILING_S` (5s). If you think you need something outside that, you need `disclosure-ethics`
and probably a different oracle — not a bigger payload. The deserialization entries are deliberately
build-it-yourself: a copy-pasted gadget blob proves nothing about *this* target's classpath.

## 4. Where it plugs in

- Class playbooks and the sink lists: `vuln-playbooks`, `web-playbooks`. This skill supplies the
  payloads those playbooks tell you to send.
- Oracles and marker strings: `marker-conventions` is still the canonical oracle list; the corpus
  carries the same markers so the two cannot drift.
- Runtime procedure, verdicts and progress reporting: `dynamic-hunt`.
- CWE ids: `cwe-map`. Escalating a confirmed fire: `chain-craft`. Standing rules: `guardrails`.
- Invocation and exit codes (`3` = scope refusal, never worked around): `env`.
