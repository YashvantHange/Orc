# Methodology — per-bug-class hunting, grounded in real AI-tool advisories

The detection knowledge lives here and in the `.claude/skills/`. **You can find every class below
with only code-reading + curl** — the `static/`+`dynamic/` scripts just accelerate it. This catalog
is mapped from published HKUDS/LightRAG (Python) and n8n-io/n8n (TypeScript) advisories to the exact
detection + confirmation.

## How to hunt (the loop)
1. **Recon** — entrypoints, auth model, roles/tenants, untrusted-input surfaces, language.
2. **Read for red flags** — `Grep` the sinks/routes/checks below, then `Read` and reason.
3. **Confirm at runtime** — launch locally, build a minimal benign PoC (script or curl), observe.
4. **Novelty gate** — variant-analysis as the *exclusion* map: sweep for the same pattern elsewhere, but
   drop anything a published CVE covers or that is an incomplete-fix/patch-bypass of one (zero-days only).
5. **Dedup → report → track** in the ledger.

## Catalog: real advisory → class → detect → confirm

| Real advisory (source) | Class / CWE | Detect by reading | Confirm |
|---|---|---|---|
| n8n: unauth test-webhook cancel; member runs others' MCP workflows; viewer→owner via run_node_tool | Broken access control / IDOR / priv-esc — CWE-639/862/269 | route handler uses request id with no ownership/role check; endpoint missing the auth its siblings have | replay resource as another/anon identity → 200 + owner data (`authz_diff.py` or curl with two tokens) |
| n8n: SSO instance-role provisioning; public-API key over-scope | Privilege escalation — CWE-269 | role/scope assigned from client-influenced input; exchanged token widened | authenticate as low role, hit high-role function |
| n8n: legacy expression evaluator sanitizer bypass | Code/expression injection — CWE-94/95 | `eval`/`new Function`/`vm`/custom evaluator on user expression; denylist sanitizer | `?expr=7*7` → 49; sandbox-escape payloads |
| n8n: computer-use shell sandbox not enforced | Sandbox escape — CWE-693 | platform-conditional sandbox; shell exec reachable | run a benign marker command, observe execution |
| n8n: stored DOM XSS via cachedResultUrl | XSS — CWE-79 | user value into `innerHTML`/`v-html`/`dangerouslySetInnerHTML` / unescaped interpolation | inject marker, load view, see unescaped reflection |
| n8n: authenticated SSRF via dynamic node params | SSRF — CWE-918 | request URL into `fetch`/`axios`/`requests` w/o allow-list | callback listener + bypass variants (NAT64/decimal/redirect) |
| n8n: header creds leaked into LLM node execution data | Sensitive data in logs — CWE-532 | credential value flows into prompt/execution record/log | run a credentialed node, inspect execution data/logs |
| LightRAG: hardcoded DEFAULT_TOKEN_SECRET; hardcoded JWT signing secret | Hardcoded secret — CWE-798 | `Grep` SECRET/JWT/TOKEN/DEFAULT_* = literal | sign a token with the secret → accepted |
| LightRAG: JWT algorithm confusion | JWT verify — CWE-347 | `algorithms` includes none / HS↔RS; `verify=False`; `jwt.decode()` (JS never verifies) | forge alg:none token → accepted (`jwt_forgery`/curl) |
| LightRAG: missing auth for critical API in default config | Missing auth — CWE-306 | endpoint w/o auth dependency; auth opt-in default off | hit sensitive endpoint with no token → 200 |
| LightRAG: CORS wildcard + credentials | CORS — CWE-942 | reflected/`*` ACAO with `allow_credentials=True` | evil Origin → reflected + `ACAC: true` |
| LightRAG: plaintext password non-constant-time compare | Timing — CWE-208 | secret/password compared with `==` | (code-level; note for report) |
| LightRAG: no rate limit on /login | Brute force — CWE-307 | `/login` handler with no limiter | burst logins → no 429/lockout |
| LightRAG: raw exception messages | Info disclosure — CWE-209 | `str(e)`/`err.stack`/`debug=True` returned to client | malformed input → stack/exception in body |
| classic ML | Unsafe deserialization — CWE-502 | `pickle/torch/joblib.load`, `yaml.load` no SafeLoader, on untrusted/model data | benign marker payload → execution/error |
| classic ML | Path traversal / zip-slip — CWE-22 | `open`/`send_file`/`fs.readFile`/`extractall` with request path | `../` sentinel / `/etc/passwd` / `win.ini` |

## Sink & route grep starters
- Python routes: `@app\.(get|post|put|delete|patch)`, `@router\.`, `@app\.route`
- JS/TS routes: `(app|router)\.(get|post|put|delete|patch)\(`
- RCE sinks: `pickle\.load|joblib\.load|torch\.load|yaml\.load\(|eval\(|exec\(|new Function|vm\.run|child_process|subprocess|os\.system`
- command/argv: `shell\s*=\s*True|os\.popen|execSync|spawnSync|check_output` — then ask whether the value
  can start with `-` (argument injection) or is passed as an env var the child interprets
- SSRF: `requests\.(get|post)|urllib|httpx|fetch\(|axios`
- path (read): `open\(|send_file|send_from_directory|FileResponse|StaticFiles|readFile|sendFile|extractall`
- path (write): `open\([^)]*['\"][wa]|write_text|write_bytes|\.save\(|writeFile|createWriteStream|shutil\.(copy|move)|os\.symlink`
- upload: `request\.files|UploadFile|multer|formidable|\.filename|content_type|mimetype|guess_type`
- template: `render_template_string|Template\(|from_string|handlebars\.compile|_\.template|ejs\.render|\.format\(`
- agent tool dispatch: `handle_tool_call|execute_tool|tool_registry|call_tool|available_tools|allowed_tools|@tool`
- secrets in responses: `api_key|apiKey|client_secret|password|token` inside a serializer/`to_dict`/
  `model_dump`/`toJSON`/`SELECT \*` — check the **list** route as well as the detail route
- race/TOCTOU: a check-then-act pair around a counter/flag/one-time code, and module-level mutable state
  (`^[A-Z_]+ *= *(\{|\[)`) or a cached `current_user`/tenant shared across requests
- authn/secrets: `jwt\.(decode|verify|sign)|SECRET|DEFAULT_|allow_credentials|Access-Control-Allow`

The full 13-class required-coverage list (and the `HIT`/`CLEAR`/`N/A` verdict each hunt owes) is in
`.claude/skills/vuln-playbooks` § "Required coverage".

See `.claude/skills/vuln-playbooks` for the full source→sink→bypass→confirm per class, and the
specialist agents for the manual curl recipes.
