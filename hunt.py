#!/usr/bin/env python3
"""
hunt.py — one-call orchestration over the pipeline's muscle, so agents spend tokens on
REASONING, not on shelling out a dozen scripts. Every subcommand reuses the existing tools
(static/ correlate/ dynamic/ evidence/ reports/) and threads a per-target profile so recon
is derived once and reused across agents/sessions.

  hunt.py scope --file scope.yml [--lint|--check <url>|--selftest]   authorization gate for a live host
  hunt.py scan <src>                       static -> merge -> exploit_score (ranked findings.json)
  hunt.py sweep <target> [--authz a.json] [--fuzz ep:param]   boot ONCE, probe+authz+fuzz
  hunt.py probe --url <base> --primitive <p> --endpoint <ep> [--param x]   one primitive, real endpoint
  hunt.py authz-scaffold <src>             derive an authz.json skeleton from AST endpoints
  hunt.py authz --url <base> --config a.json                  authorization differential
  hunt.py cvss <vector | --metrics AV=N ...>                  CVSS 3.1 score
  hunt.py evidence <target> <id> --poc "<cmd>" [--url U] [--root-cause file]   evidence.json bundle
  hunt.py poc-run <target> <id> --cmd "<cmd>"   EXECUTE the PoC and record it (runlog.json)
  hunt.py validate-report <id>             delivery gate — verifies the evidence chain
  hunt.py report <id> [--layout github|hackerone]   section scaffold (default: github/GHSA)
  hunt.py dup <owner/repo> --query "..."   duplicate check
  hunt.py ledger add|update --id F0.. ...  update state/ledger.json
  hunt.py metrics                          KPI snapshot from the ledger
  hunt.py board init|start|done|set|tally|lane|show <target>   the live run board (state-backed)
  hunt.py agents [--skills]                the roster — every agent, its model, tools and skills

The skills are the product; this is optional muscle. Anything here has a manual equivalent.

AUTHORIZED TARGETS ONLY. Point dynamic subcommands at a target you launched yourself, or at a live
host that a validated scope.yml places inside a published bug-bounty/VDP scope — inside its window,
at its stated rate. `hunt scope` is the gate; dynamic/scope.py enforces it on every request and
transcribes what it sent. Exit code 3 means a request was refused as out of scope.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for sub in ("static", "dynamic", "intel", "reports", "evidence", "web", "tools"):
    sys.path.insert(0, str(ROOT / sub))
import board as B                                                            # noqa: E402
PY = sys.executable
PROFILE_SCHEMA = 2          # 2 adds target-kind + live-website recon keys


# ------------------------------------------------------------------------ profile.json ---
def _workdir(target: str) -> Path:
    import _common as C
    return C.workdir(target)


def profile_path(target: str) -> Path:
    return _workdir(target) / "profile.json"


def _migrate(prof: dict, target: str) -> dict:
    """Bring an older profile forward. Everything written before schema 2 was a source target."""
    if prof.get("schema", 0) < 2:
        prof.setdefault("kind", "src")
    return prof


def load_profile(target: str) -> dict:
    p = profile_path(target)
    if p.exists():
        try:
            return _migrate(json.loads(p.read_text(encoding="utf-8")), target)
        except json.JSONDecodeError:
            print(f"warn: corrupt {p}, recomputing", file=sys.stderr)
    import _common as C
    return {"schema": PROFILE_SCHEMA, "target": str(target),
            "slug": C.web_slug(target) if C.is_url(target) else C.slug(target),
            "kind": C.target_kind(target)}


def save_profile(target: str, **updates) -> dict:
    prof = load_profile(target)
    prof.update(updates)
    prof["schema"] = PROFILE_SCHEMA
    prof["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    # Values lifted straight out of a scope.yml can carry non-JSON types: PyYAML resolves an
    # unquoted 2026-08-06T00:00:00Z into a datetime, which sank every url-target recon whose
    # scope declared a test_window. Stringify rather than reject — a profile is a cache, and
    # losing it to a serialization error is worse than an approximate value.
    profile_path(target).write_text(json.dumps(prof, indent=2, default=str), encoding="utf-8")
    return prof


def _run(cmd: list[str], env: dict | None = None) -> int:
    print(f"$ {' '.join(str(c) for c in cmd)}")
    return subprocess.run(cmd, env=env).returncode


# ------------------------------------------------------------------------ target kinds ---
class TargetSpec:
    """What a subcommand is pointed at: a live origin, a local source tree, or both.

    Grey-box (both) deliberately keeps the SOURCE slug as its workdir id, so findings.json,
    evidence bundles and every file:line path a source hunt already produced keep working; the
    origin is recorded in the profile alongside them.
    """

    def __init__(self, url: str | None = None, src: str | None = None,
                 scope_path: str | None = None):
        import _common as C
        self.url = url or None
        self.src = src or None
        self.origin = C.normalize_origin(self.url) if self.url else None
        self.kind = C.target_kind(self.url, self.src)
        self.scope_path = scope_path
        self.key = self.src if self.src else self.origin        # the workdir/profile id
        self.slug = C.slug(self.src) if self.src else C.web_slug(self.url)
        self.workdir = C.workdir(self.key)
        self.scope = None

    def __repr__(self) -> str:
        return f"<TargetSpec {self.kind} slug={self.slug} url={self.origin} src={self.src}>"

    def child_env(self, identity: str = "anon", primitive: str = "") -> dict | None:
        """Environment for a subprocess (authz_diff.py / fuzz.py) so the scope survives the
        process boundary — dynamic/scope.py picks these up at import time."""
        if not self.scope_path:
            return None
        env = dict(os.environ)
        env["HUNT_SCOPE_FILE"] = str(Path(self.scope_path).resolve())
        env["HUNT_SLUG"] = self.key or self.slug
        env["HUNT_IDENTITY"] = identity
        if primitive:
            env["HUNT_PRIMITIVE"] = primitive
        return env


def _resolve_target(url: str | None = None, src: str | None = None,
                    scope_path: str | None = None, require_scope: bool = True) -> TargetSpec:
    """Build the TargetSpec and activate the scope guard for this process.

    A live host that isn't loopback REQUIRES a scope file. That refusal is the whole point of the
    feature — it is not a warning.
    """
    import _common as C
    import scope as S

    spec = TargetSpec(url=url, src=src, scope_path=scope_path)
    if not spec.url:
        return spec

    host = C.normalize_origin(spec.url).split("://", 1)[1].split(":")[0]
    is_local = host in ("127.0.0.1", "localhost", "::1", "0.0.0.0")

    if scope_path:
        try:
            spec.scope = S.Scope.load(scope_path)
        except S.ScopeError as e:
            raise SystemExit(f"scope error: {e}")
    elif is_local:
        spec.scope = S.Scope.local(host)          # implicit permissive scope, still transcribed
    elif require_scope:
        raise S.ScopeViolation(
            f"no scope file for {spec.origin} — a live host needs a scope.yml naming the program "
            f"that authorizes it. Start from scope.example.yml, then: hunt scope --file <f> --lint",
            rule="--scope")

    if spec.scope is not None:
        S.activate(spec.scope, spec.key or spec.slug)
        save_profile(spec.key, kind=spec.kind, origin=spec.origin,
                     scope_file=str(scope_path) if scope_path else "",
                     scope_digest=spec.scope.digest(),
                     program=spec.scope.program,
                     test_window=spec.scope.raw.get("test_window") or {})
    return spec


# --------------------------------------------------------------------------- scope ----
def cmd_scope(a) -> int:
    import scope as S
    argv = []
    if a.file:
        argv += ["--file", a.file]
    if a.check:
        argv += ["--check", a.check, "--method", a.method]
    if a.lint:
        argv.append("--lint")
    if a.selftest:
        argv.append("--selftest")
    return S.main(argv)


# ---------------------------------------------------------------------------- scan ----
def cmd_scan(a) -> int:
    src = a.src
    extra = ["--lang", a.lang] if a.lang else []
    if a.with_codeql:
        extra.append("--with-codeql")
    rc = _run([PY, str(ROOT / "static" / "run_all.py"), src, *extra])
    if rc != 0:
        print("static/run_all.py reported issues; continuing to correlate", file=sys.stderr)
    _run([PY, str(ROOT / "correlate" / "merge.py"), src])
    _run([PY, str(ROOT / "correlate" / "exploit_score.py"), src,
          "--threshold", str(a.threshold)])
    findings = _workdir(src) / "findings.json"
    save_profile(src, findings=str(findings))
    print(f"\nranked leads -> {findings}")
    return 0


# --------------------------------------------------------------------------- sweep ----
def cmd_sweep(a) -> int:
    """Boot the target ONCE, then run probe + authz + fuzz against that single instance."""
    import probe
    from instrument import TargetProcess
    summary: dict = {"target": a.target, "probe": [], "authz": None, "fuzz": None}
    with TargetProcess(a.target, entry=a.entry) as t:
        base = t.base_url
        print(f"booted {base} (kind={t.kind}, log={t.log_path})")
        save_profile(a.target, base_url=base, kind=t.kind)
        time.sleep(1.0)

        # 1) probe primitives (fixture plan by default; --primitive for a real endpoint)
        if a.primitive:
            results = [probe.run_primitive(base, a.primitive, a.endpoint, a.param, a.secret)]
        else:
            results = probe.selftest_plan(base)
        probe._write(a.target, results)
        summary["probe"] = [{"name": r.name, "confirmed": r.confirmed,
                             "endpoint": r.endpoint, "detail": r.detail} for r in results]
        ok = sum(r.confirmed for r in results)
        print(f"probe: {ok}/{len(results)} confirmed")

        # 2) authorization differential (reuses the SAME running instance — no re-boot)
        if a.authz:
            cmd = [PY, str(ROOT / "dynamic" / "authz_diff.py"), "--url", base,
                   "--slug", a.target]
            cmd += ["--selftest"] if a.authz == "selftest" else ["--config", a.authz]
            summary["authz"] = {"exit": _run(cmd)}

        # 3) fuzz one endpoint:param (same instance)
        if a.fuzz:
            ep, _, param = a.fuzz.partition(":")
            summary["fuzz"] = {"exit": _run([PY, str(ROOT / "dynamic" / "fuzz.py"),
                                             "--url", base, "--slug", a.target,
                                             "--endpoint", ep, "--param", param or "q",
                                             "--iterations", str(a.iterations)])}

        # capture the server log (stack traces) while the instance is still up
        (_workdir(a.target) / "dynamic").mkdir(parents=True, exist_ok=True)
        (_workdir(a.target) / "dynamic" / "server.log").write_text(
            t.read_log(), encoding="utf-8")

    out = _workdir(a.target) / "dynamic" / "sweep.json"
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nsweep summary -> {out}  (one boot; reused for all stages)")
    return 0


# --------------------------------------------------------------------------- probe ----
def cmd_probe(a) -> int:
    env = None
    if a.url:
        spec = _resolve_target(url=a.url, scope_path=getattr(a, "scope", None))
        env = spec.child_env(primitive=a.primitive)
    cmd = [PY, str(ROOT / "dynamic" / "probe.py"), "--primitive", a.primitive,
           "--endpoint", a.endpoint]
    cmd += ["--url", a.url] if a.url else ["--launch", a.launch]
    if a.param:
        cmd += ["--param", a.param]
    if a.secret:
        cmd += ["--secret", a.secret]
    return _run(cmd, env=env)


# --------------------------------------------------------------------------- web ----
def cmd_web(a) -> int:
    if a.web_cmd == "recon":
        spec = _resolve_target(url=a.url, src=getattr(a, "src", None), scope_path=a.scope)
        import recon
        argv = [a.url, "--slug", spec.key or spec.slug,
                "--depth", str(a.depth), "--max-pages", str(a.max_pages),
                "--posture-path", a.posture_path]
        if a.scope:
            argv += ["--scope", a.scope]
        if a.auth_cookie:
            argv += ["--auth-cookie", a.auth_cookie]
        rc = recon.main(argv)
        wd = _workdir(spec.key)
        eps = wd / "web" / "endpoints.json"
        if eps.exists():
            save_profile(spec.key, kind=spec.kind, origin=spec.origin,
                         web={"endpoints": str(eps),
                              "baselines": str(wd / "web" / "baselines.json"),
                              "js_src": str(wd / "web" / "js" / "src"),
                              "transcript": str(wd / "web" / "transcript.jsonl")})
        return rc
    if a.web_cmd == "probe":
        spec = _resolve_target(url=a.url, scope_path=a.scope)
        import sweep
        argv = [a.url, "--slug", spec.key or spec.slug, "--marker", a.marker]
        if a.scope:
            argv += ["--scope", a.scope]
        for i in a.identity:
            argv += ["--identity", i]
        for o in a.opt:
            argv += ["--opt", o]
        for p in a.primitive:
            argv += ["--primitive", p]
        if a.fast:
            argv.append("--fast")
        if a.no_browser:
            argv.append("--no-browser")
        return sweep.main(argv)
    if a.web_cmd == "coverage":
        return _web_coverage(a)
    print(f"error: unknown web subcommand {a.web_cmd!r}", file=sys.stderr)
    return 2


def _web_coverage(a) -> int:
    """Derive the enumeration tuple every url-kind CLEAR verdict must cite, straight from the
    transcript — so a hunter cannot invent the numbers it claims to have covered."""
    wd = _workdir(a.target)
    tp = wd / "web" / "transcript.jsonl"
    if not tp.exists():
        print(f"no transcript at {tp} — run `hunt web recon` first", file=sys.stderr)
        return 2
    recs = []
    for line in tp.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            recs.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    sent = [r for r in recs if not r.get("refused") and r.get("status")]
    refused = [r for r in recs if r.get("refused")]
    from urllib.parse import urlsplit
    paths = {urlsplit(r.get("url", "")).path for r in sent}
    methods = {r.get("method") for r in sent}
    identities = {r.get("identity") or "anon" for r in sent}
    by_primitive: dict[str, list] = {}
    for r in sent:
        by_primitive.setdefault(r.get("primitive") or "(none)", []).append(r.get("id"))

    print(f"coverage for {a.target}  ({tp})")
    print(f"  requests sent   : {len(sent)}   refused: {len(refused)}")
    print(f"  distinct paths  : {len(paths)}")
    print(f"  methods         : {sorted(m for m in methods if m)}")
    print(f"  identities      : {sorted(identities)}")
    ids = [r.get("id") for r in sent if r.get("id")]
    if ids:
        print(f"  transcript range: {min(ids)}–{max(ids)}")
    print("\n  by primitive:")
    for name, tids in sorted(by_primitive.items(), key=lambda kv: -len(kv[1])):
        print(f"    {name:22} {len(tids):5}  {tids[0]}–{tids[-1]}")
    print("\n  Paste the tuple into each CLEAR verdict — and add the defense you OBSERVED.")
    print("  A tuple without a defense clause describes your traffic, not the target (vuln-playbooks).")
    if refused:
        print(f"\n  {len(refused)} request(s) were refused as out of scope:")
        for r in refused[:5]:
            print(f"    {r.get('id')} {r.get('method')} {r.get('url')} — {r.get('reason')}")
    return 0


# ------------------------------------------------------------------- authz-scaffold ---
def _authz_skeleton(endpoints: list[dict]) -> dict:
    """The authz.json shape both target kinds fill: identities + resources to replay across them.

    `endpoints` is a list of {path, method} — from AST signals for a source target, or from
    web/endpoints.json for a live one. Same skeleton either way.
    """
    resources = []
    for e in endpoints[:12]:
        path = e.get("path") or f"/TODO{len(resources) + 1}"
        method = (e.get("method") or "GET").upper()[:6] or "GET"
        # a templated id is exactly the IDOR candidate — give it a concrete value to replay
        resources.append({"path": path.replace("{id}", str(e.get("example_id", "1"))),
                          "method": method, "owner": "owner",
                          "marker": "<owner-only string>"})
    return {
        "_note": "Fill login bodies + per-resource owner/marker. anon:true = unauthenticated. "
                 "The marker must be a string that appears ONLY in the owner's response — on a live "
                 "SPA a 200 proves nothing (see web-recon baselines).",
        "identities": [
            {"name": "owner", "login": {"endpoint": "/login",
                                        "body": {"username": "owner", "password": "TODO"},
                                        "token_field": "token"}},
            {"name": "other", "login": {"endpoint": "/login",
                                        "body": {"username": "other", "password": "TODO"},
                                        "token_field": "token"}},
            {"name": "anon", "anon": True},
        ],
        "resources": resources or [{"path": "/items/1", "method": "GET", "owner": "owner",
                                    "marker": "<owner-only string>"}],
    }


def cmd_authz_scaffold(a) -> int:
    """Derive an authz.json skeleton — from AST endpoint signals (src) or web/endpoints.json (url)."""
    if getattr(a, "url", None):
        spec = _resolve_target(url=a.url, scope_path=getattr(a, "scope", None))
        eps_file = _workdir(spec.key) / "web" / "endpoints.json"
        if not eps_file.exists():
            print(f"error: {eps_file} not found — run `hunt web recon {a.url}` first",
                  file=sys.stderr)
            return 2
        eps = json.loads(eps_file.read_text(encoding="utf-8"))
        # the templated paths that carry an observed id are the IDOR candidates; lead with those
        eps.sort(key=lambda e: (0 if "{id}" in e.get("path", "") else 1, e.get("path", "")))
        endpoints = [{"path": e.get("path"), "method": e.get("method"),
                      "example_id": (e.get("observed_values") or ["1"])[0]} for e in eps]
        out = _workdir(spec.key) / "authz.json"
        out.write_text(json.dumps(_authz_skeleton(endpoints), indent=2), encoding="utf-8")
        print(f"authz.json skeleton -> {out}  ({len(endpoints)} endpoints from recon; fill TODOs)")
        return 0

    import ast_scan
    sig = ast_scan.scan(a.src) if hasattr(ast_scan, "scan") else None
    endpoints = []
    if sig and isinstance(sig, dict):
        endpoints = [s for s in sig.get("signals", []) if s.get("category") == "endpoint"]
    else:  # fall back to the module's CLI JSON
        rc = subprocess.run([PY, str(ROOT / "intel" / "ast_scan.py"), a.src, "--json"],
                            capture_output=True, text=True)
        try:
            endpoints = [s for s in json.loads(rc.stdout).get("signals", [])
                         if s.get("category") == "endpoint"]
        except (json.JSONDecodeError, AttributeError):
            endpoints = []
    skeleton = {
        "_note": "Fill login bodies + per-resource owner/marker. anon:true = unauthenticated.",
        "identities": [
            {"name": "owner", "login": {"endpoint": "/login",
                                        "body": {"username": "owner", "password": "TODO"},
                                        "token_field": "token"}},
            {"name": "other", "login": {"endpoint": "/login",
                                        "body": {"username": "other", "password": "TODO"},
                                        "token_field": "token"}},
            {"name": "anon", "anon": True},
        ],
        "resources": [
            {"path": f"/TODO{i}", "method": (e.get("name") or "GET").upper()[:6] or "GET",
             "owner": "owner", "marker": "<owner-only string>"}
            for i, e in enumerate(endpoints[:8], 1)
        ] or [{"path": "/items/1", "method": "GET", "owner": "owner",
               "marker": "<owner-only string>"}],
    }
    out = _workdir(a.src) / "authz.json"
    out.write_text(json.dumps(skeleton, indent=2), encoding="utf-8")
    print(f"authz.json skeleton -> {out}  ({len(endpoints)} endpoints seen; fill TODOs)")
    return 0


def cmd_authz(a) -> int:
    spec = _resolve_target(url=a.url, scope_path=getattr(a, "scope", None))
    cmd = [PY, str(ROOT / "dynamic" / "authz_diff.py"), "--url", a.url, "--slug", spec.key]
    cmd += ["--selftest"] if a.config == "selftest" else ["--config", a.config]
    return _run(cmd, env=spec.child_env())


# ---------------------------------------------------------------------------- cvss ----
def cmd_cvss(a) -> int:
    import cvss
    vec = "/".join(m.replace("=", ":") for m in a.metrics) if a.metrics else a.vector
    if not vec:
        print("error: pass a vector or --metrics", file=sys.stderr)
        return 2
    try:
        score, sev, canon = cvss.score_vector(vec)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"{score} {sev}\n{canon}")
    return 0


# ------------------------------------------------------------------------- evidence ---
def cmd_evidence(a) -> int:
    import collect
    collect.collect(a.target, a.id, a.poc, request=a.request, response=a.response,
                    url=a.url, log=a.log, root_cause=a.root_cause,
                    transcript_ids=getattr(a, "transcript_ids", ""),
                    screenshot=getattr(a, "screenshot", ""), har=getattr(a, "har", ""))
    return 0


def cmd_poc_run(a) -> int:
    """Run the PoC for real and record it. `collect` writes down the command you SAY you ran;
    this writes down what actually happened, which is what the report is then checked against."""
    sys.path.insert(0, str(ROOT / "evidence"))
    import runlog
    e = runlog.record(a.target, a.id, a.cmd, cwd=a.cwd, python=a.python,
                      volatile=a.volatile, timeout=a.timeout, shell=not a.no_shell)
    doc = runlog.load(a.target, a.id)
    print(f"recorded run #{len(doc.get('runs', []))} - exit {e['exit_code']} in {e['duration_s']}s")
    print(f"  {runlog.runlog_path(a.target, a.id)}")
    for ln in (e["stdout"].strip().splitlines()[:8] if e["stdout"] else []):
        print(f"    {ln}")
    ok, problems = runlog.verify(doc)
    if not ok:
        print("\n  not yet gate-ready:")
        for p in problems:
            print(f"    - {p}")
    return 0


# ------------------------------------------------------------------ validate-report ---
_CHECKS_SRC = ["PoC", "PoC reproducible", "Root cause", "file:line", "Impact", "Remediation", "CWE",
               "CVSS", "Duplicate check", "Patch tested"]
# A live host has no commit and no file:line, so the anchors move rather than soften. The transcript
# check is STRICTER than the source one: today's `file:line` gate is satisfied by the literal string
# "app.py:1", while a transcript id has to exist AND its response hash has to match the bundle.
_CHECKS_URL = ["PoC", "PoC reproducible", "Root cause", "Evidence transcript", "Impact",
               "Remediation", "CWE", "CVSS", "Duplicate check", "Scope authorization"]
# Grey-box is the union — that is exactly what makes it the strongest mode.
_CHECKS_GREY = _CHECKS_SRC + ["Evidence transcript", "Scope authorization"]
_CHECKS = _CHECKS_SRC          # kept for anything importing the old name


def _checks_for(kind: str) -> list:
    return {"url": _CHECKS_URL, "grey": _CHECKS_GREY}.get(kind, _CHECKS_SRC)


def _transcript_ok(rec: dict, report_txt: str) -> tuple[bool, str]:
    """Cited T##### ids must exist in the transcript, and their response hashes must match the
    evidence bundle's copy. A stale or invented id fails exactly like a stale line number."""
    import re
    ids = [i.strip() for i in str(rec.get("transcript_ids", "")).split(",") if i.strip()]
    ids += [m for m in re.findall(r"\bT\d{5}\b", report_txt) if m not in ids]
    if not ids:
        return False, "no transcript ids cited (ledger transcript_ids, or T##### in the report)"

    target = rec.get("target_url") or rec.get("repo") or ""
    try:
        tp = _workdir(target) / "web" / "transcript.jsonl"
    except Exception:                                   # noqa: BLE001
        return False, "could not resolve the target's workdir"
    if not tp.exists():
        return False, f"transcript not found at {tp}"

    found: dict = {}
    for line in tp.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("id") in ids:
            found[r["id"]] = r
    missing = [i for i in ids if i not in found]
    if missing:
        return False, f"cited ids absent from the transcript: {', '.join(missing)}"

    # cross-check against the bundle's sliced copy, when one was collected
    ep = rec.get("evidence_path")
    if ep:
        bundle = ROOT / ep / "transcript.jsonl"
        if bundle.exists():
            for line in bundle.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    b = json.loads(line)
                except json.JSONDecodeError:
                    continue
                src = found.get(b.get("id"))
                if src and b.get("resp_body_sha256") and \
                        b["resp_body_sha256"] != src.get("resp_body_sha256"):
                    return False, (f"{b['id']}: evidence-bundle response hash does not match the "
                                   f"transcript — the bundle was edited or the target changed")
    return True, f"{len(ids)} transcript id(s) verified"


def _scope_auth_ok(rec: dict, report_txt: str) -> tuple[bool, str]:
    """The report must name the program that authorized the test, and the scope digest it ran under
    must still match the file on disk."""
    low = report_txt.lower()
    digest = rec.get("scope_digest", "")
    prof = {}
    try:
        prof = load_profile(rec.get("target_url") or rec.get("repo") or "")
    except Exception:                                   # noqa: BLE001
        pass
    digest = digest or prof.get("scope_digest", "")
    program = rec.get("program") or prof.get("program") or {}
    if not digest:
        return False, "no scope_digest recorded — the report cannot show what authorized the test"
    if digest not in report_txt and digest.split(":")[-1][:16] not in report_txt:
        return False, "the scope digest is not quoted in the report"
    if not (program or "program" in low):
        return False, "the report does not name the bug-bounty program"
    if not (rec.get("test_window") or prof.get("test_window") or "test window" in low):
        return False, "no test window recorded"

    sf = prof.get("scope_file")
    if sf and Path(sf).exists():
        import hashlib
        live = "sha256:" + hashlib.sha256(Path(sf).read_bytes()).hexdigest()
        if live != digest:
            return False, (f"{sf} has changed since the test (digest mismatch) — re-verify which "
                           f"scope actually authorized this traffic")
    return True, "program, digest and window present"

# Advisory-only prose scan for the production-quality bar (report-standards): AI-tells, padding
# phrases, and unfilled placeholders. High-precision by design — it never blocks disclosure; the
# agent/human is the judge. Code fences (PoC payloads) and the scaffold comment are skipped.
_AI_TELLS = [
    ("filler", r"\b(in today'?s (?:landscape|world|fast[- ]paced\w*)|it (?:is|'s) worth noting that|"
               r"it (?:is|'s) important to (?:note|understand|remember|realize)|in conclusion|"
               r"to summari[sz]e|overall,|needless to say|at the end of the day|"
               r"first(?:ly)?,.*second(?:ly)?,)\b"),
    ("adjective", r"\b(robust|seamless(?:ly)?|powerful|comprehensive|cutting[- ]edge|"
                  r"state[- ]of[- ]the[- ]art|crucial(?:ly)?|significantly|plethora|delve|"
                  r"leverag(?:e|es|ing)|utiliz(?:e|es|ing|ation)|facilitate)\b"),
    ("hedging", r"\b(may potentially|potentially possibly|could perhaps|might possibly|"
                r"in some cases,? it (?:may|might))\b"),
    ("signpost", r"(?m)^\s*(?:[-*]\s*)?(?:\*\*)?(additionally|furthermore|moreover|notably|"
                 r"importantly|consequently|subsequently)\b,?"),
    ("antithesis", r"\b(not only\b[^.\n]{0,60}\bbut also|is ?n[o']t just\b[^.\n]{0,40}\bit'?s|"
                   r"not (?:merely|simply)\b[^.\n]{0,40}\bbut\b)"),
    ("boilerplate", r"\b(this (?:report|document|advisory) (?:details|outlines|describes|presents)|"
                    r"serves as a|plays a (?:key|critical|vital|significant) role|a testament to|"
                    r"underscores the|highlights the importance)\b"),
    ("self-ref", r"\b(as an ai|as a language model|i (?:have )?generated|i'?m just an?)\b"),
    ("placeholder", r"(<[^>\n]*\b(?:your|name|handle|owner|repo|version|commit|path|line|impact|"
                    r"component|method|route|vuln|cwe|score|vector|xxx|todo)\b[^>\n]*>|"
                    r"\bTODO\b|\bFIXME\b|Lorem ipsum|<\.\.\.>|_{3,})"),
]


_TITLE_MAX_WORDS = 10          # report-standards "Title rule"; 12 is the hard ceiling

# report-standards "Title rule": the first half must name the security failure, not the mechanism.
# A title with none of these reads like a refactor-PR subject ("Quadratic image regex in the parser").
# Advisory only, and deliberately wide - a miss costs nothing, a false flag costs an audit round.
_TITLE_SECURITY_TERMS = (
    r"xss|csrf|ssrf|xxe|rce|redos|dos\b|denial of service|idor|bola|bfla|ssti|csti|sqli|"
    r"injection|traversal|deserializ|prototype pollution|smuggl|poisoning|takeover|hijack|"
    r"spoof|forgery|clickjack|rebinding|open redirect|"
    r"bypass|unauthenticated|unauthorized|unauth\b|missing (?:auth|permission|access|validation)|"
    r"broken access|privilege|priv[- ]esc|escalat|impersonat|mass assignment|superuser|"
    r"leak|leaks|exposure|exposes|disclos|exfiltrat|read of|arbitrary|"
    r"tamper|overwrite|corrupt|forge|"
    r"crash|crashes|hang|hangs|stall|freeze|exhaust|starv|unbounded memory|oom\b|take[ -]?down|"
    r"out[ -]?of[ -]?bounds|oob\b|overflow|underflow|replay|bomb|race condition|toctou|"
    r"secret|credential|token theft|fixation|enumerat|weak (?:crypto|random)|timing attack"
)


def _title_advisory(report_txt: str) -> list[str]:
    """Flag a title that breaks the Title rule (report-standards): short, plain, one clause.

    Reads the first level-1 heading outside code fences. Advisory only, like the rest of the scan.
    """
    import re
    # Collect every H1 outside code fences, with the lines that follow it. The `github` layout opens
    # with a banner H1 ("GitHub Security Advisory draft - owner/repo") and carries the real title
    # further down, inside the paste region - so "first H1" is the wrong line to grade.
    lines, in_fence, h1s = report_txt.splitlines(), False, []
    for i, ln in enumerate(lines):
        if ln.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence and re.match(r"^#\s+\S", ln):
            h1s.append((i, ln.lstrip("# ").strip()))
    if not h1s:
        return ["title: no level-1 heading found"]

    # The real title is the H1 that introduces the description body: the one followed shortly by
    # Summary / Details / Steps To Reproduce. Fall back to the first H1.
    title = h1s[0][1]
    for i, t in h1s:
        nxt = "\n".join(lines[i + 1:i + 12])
        if re.search(r"(?im)^##+\s+(summary|details|steps to reproduce)\b", nxt):
            title = t
            break
    else:
        # Older drafts carry the title as a `## Title` section instead of an H1.
        for i, ln in enumerate(lines):
            if re.match(r"(?i)^##+\s+title\s*$", ln):
                body = [x.strip(" `") for x in lines[i + 1:i + 6]
                        if x.strip(" `") and not x.lstrip().startswith(("```", "#", "|"))]
                if body:
                    title = body[0]
                break

    words = re.sub(r"[`*_\[\]]", "", title).split()
    hits = []
    if len(words) > _TITLE_MAX_WORDS:
        hits.append(f"title: {len(words)} words (max {_TITLE_MAX_WORDS}) - \"{title[:70]}\"")
    if ":" in title and not re.search(r"https?://|\w+:\d", title):
        hits.append("title: colon framing - say it in one clause")
    if re.search(r"\b(CVE|GHSA)[-‑]", title, re.IGNORECASE):
        hits.append("title: drop the CVE/GHSA id - the report body carries it")
    if re.search(r"\(", title):
        hits.append("title: parenthetical qualifier - move it to Summary")
    if re.search(r"(?i)\ballows?\b[^.\n]*\bvia\b|\bvia\b[^.\n]*\ballows?\b|\bleading to\b", title):
        hits.append("title: chained allows/via clause - keep one idea")
    if re.search(r"(?i)\b(critical|severe|high[- ]severity|dangerous)\b", title):
        hits.append("title: severity word - the CVSS field says that")
    if not re.search(_TITLE_SECURITY_TERMS, title, re.IGNORECASE):
        hits.append("title: names a mechanism, not a vulnerability - would this look normal on a "
                    "refactor PR? say the security failure and move the mechanism to Summary")
    return hits


def _quality_advisory(report_txt: str) -> list[str]:
    """Flag AI-tells / padding / placeholders in report PROSE only. Advisory; never blocks."""
    import re
    prose, in_fence = [], False
    for ln in report_txt.splitlines():
        s = ln.strip()
        if s.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence or s.startswith("<!--") or s.startswith(">"):  # PoC payload / scaffold / note
            continue
        prose.append(ln)
    text = "\n".join(prose)
    hits: list[str] = []
    for label, pat in _AI_TELLS:
        seen: dict[str, int] = {}
        for m in re.finditer(pat, text, re.IGNORECASE):
            snip = " ".join(m.group(0).split())
            seen[snip.lower()] = seen.get(snip.lower(), 0) + 1
        for snip, n in seen.items():
            hits.append(f"{label}: \"{snip}\"" + (f" (x{n})" if n > 1 else ""))
    return hits


def _poc_reproducible(report_txt: str) -> bool:
    """True if the PoC section is owner-verifiable: a concrete runnable trigger AND a verbatim
    outcome, both present (report-standards rule 5). A PoC that only *describes* what would happen —
    no command/script, or no expected/observed result — fails the gate. Best-effort heuristic.

    The section runs from the PoC heading to the next level-1/2 heading, but headings are only
    honored OUTSIDE code fences, so `# comment` lines inside a bash/python block don't cut it short.
    """
    import re
    lines = report_txt.splitlines()
    start = next((i for i, ln in enumerate(lines)
                  if re.match(r"(?i)^#{1,3}\s*(?:proof of concept|poc)\b", ln)), None)
    if start is None:
        return False
    body, in_fence = [], False
    for ln in lines[start + 1:]:
        if ln.lstrip().startswith("```"):
            in_fence = not in_fence
            body.append(ln)
            continue
        if not in_fence and re.match(r"^#{1,2}\s", ln):   # next real section heading ends the PoC
            break
        body.append(ln)
    section = "\n".join(body)
    if "```" not in section:                              # needs at least one runnable code block
        return False
    has_command = bool(re.search(
        r"(?im)\b(curl|python|pip install|uv pip|git clone|git fetch|vllm serve|requests\.|"
        r"http://127|https://127|POST /|GET /|\.py\b|import\s+\w|"
        # live-target findings are not always HTTP: a DNS-only proof is still runnable
        r"dig\s|nslookup|host\s+-t|openssl s_client|dnsrecon)", section))
    has_outcome = bool(re.search(
        r"(?im)\b(observed|expected|output|traceback|status[_ ]?code|illegal memory|"
        r"result|returns)\b|->", section))
    # a described-only PoC full of unfilled trigger placeholders is not runnable
    placeholder = bool(re.search(r"(?im)<[^>\n]*\b(your|placeholder|crafted-?input|todo|xxx)\b", section))
    return has_command and has_outcome and not placeholder


def _ledger() -> list[dict]:
    p = ROOT / "state" / "ledger.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")).get("findings", [])
    except (OSError, json.JSONDecodeError):
        return []


def cmd_validate_report(a) -> int:
    """The delivery gate. Thin caller - every check lives in reports/gate.py.

    What changed and why: this used to be ten substring tests (`"impact" in low`, `"fix" in low`).
    An unfilled TEMPLATE.md passed nine of them. Worse, the checks that mattered most - is the prose
    human, is this file:line real, is the CVSS vector the right one - are judgement calls a regex
    gets wrong in both directions, so they were only ever printed as advice nobody had to take.

    Those judgements now belong to two agents that actually read the report (report-auditor,
    report-editor). What is left here is the part a script can be trusted with: verifying that the
    judging happened, against these exact bytes, on top of a PoC that really ran.
    """
    sys.path.insert(0, str(ROOT / "reports"))
    import gate
    code = gate.main([a.id] + (["--json"] if getattr(a, "json", False) else []))
    if code != 0 and not getattr(a, "json", False):
        _print_editor_hints(a.id)
    return code


def _print_editor_hints(finding_id: str) -> None:
    """Print the old regex scan as HINTS FOR THE EDITOR AGENT - never as a pass/fail signal.

    These patterns are kept because they are a cheap first pass over obvious tells, and thrown away
    as a gate because they were wrong too often in both directions: they flag "comprehensive" in a
    sentence where it belongs, and they sail past a page of generated prose whose tells are
    structural. Treat every line below as "go look at this", not "this is broken".
    """
    rec = next((f for f in _ledger() if f.get("finding_id") == finding_id), {})
    rp = rec.get("report_path")
    if not (rp and (ROOT / rp).exists()):
        return
    txt = (ROOT / rp).read_text(encoding="utf-8", errors="replace")
    hints = _title_advisory(txt) + _quality_advisory(txt)
    if not hints:
        return
    print("\nhints for report-editor (NOT gate results - a regex guessing at prose):")
    for h in hints[:15]:
        print(f"  ? {h}")
    if len(hints) > 15:
        print(f"  ... +{len(hints) - 15} more")


# ---------------------------------------------------------------- report / dup / ledger ---
# Templates live in templates/, not reports/ - everything *.md under reports/ is a disclosure as far
# as the delivery-gate hooks are concerned, and a template has no finding id to gate.
LAYOUTS = {
    "github": "report-github.md",      # default - private GHSA draft / huntr on-platform form
    "hackerone": "report-hackerone.md",
}


def cmd_report(a) -> int:
    rec = next((f for f in _ledger() if f.get("finding_id") == a.id), None)
    if not rec:
        print(f"error: {a.id} not in ledger; add it first (hunt ledger add)", file=sys.stderr)
        return 2
    layout = getattr(a, "layout", "github")
    tmpl_name = LAYOUTS.get(layout)
    if not tmpl_name:
        print(f"error: unknown layout {layout!r}; pick one of {', '.join(LAYOUTS)}", file=sys.stderr)
        return 2
    tmpl = (ROOT / "templates" / tmpl_name).read_text(encoding="utf-8")
    slug = rec.get("repo", "target").replace("/", "__")
    cwe = (rec.get("cwe") or "CWE").replace(" ", "")
    suffix = "" if layout == "github" else f"-{layout}"
    out = ROOT / "reports" / f"{slug}-{cwe}-{a.id}{suffix}.md"
    header = (f"<!-- scaffolded by hunt report; layout={layout}. ledger={a.id} -->\n"
              f"<!-- the scaffold is a section checklist, NOT the report: report-writer writes the\n"
              f"     prose from the evidence bundle. Delete any line you did not fill. -->\n"
              f"<!-- repo={rec.get('repo')} commit={rec.get('commit')} "
              f"cwe={rec.get('cwe')} cvss={rec.get('cvss')} file={rec.get('file')}:"
              f"{rec.get('line')} evidence={rec.get('evidence_path')} -->\n\n")
    out.write_text(header + tmpl, encoding="utf-8")
    print(f"report scaffold ({layout}) -> {out}")
    print(f"  write it, clean-room verify the PoC, run both auditors, then: hunt validate-report {a.id}")
    return 0


def cmd_dup(a) -> int:
    return _run([PY, str(ROOT / "reports" / "dup_check.py"), a.repo, "--query", a.query])


def cmd_ledger(a) -> int:
    p = ROOT / "state" / "ledger.json"
    doc = json.loads(p.read_text(encoding="utf-8"))
    fields = dict(kv.split("=", 1) for kv in a.set) if a.set else {}
    findings = doc.setdefault("findings", [])
    rec = next((f for f in findings if f.get("finding_id") == a.id), None)
    if a.action == "add":
        if rec:
            print(f"error: {a.id} already exists (use update)", file=sys.stderr)
            return 2
        rec = {"finding_id": a.id, "status": "NEW"}
        findings.append(rec)
    elif not rec:
        print(f"error: {a.id} not found (use add)", file=sys.stderr)
        return 2
    rec.update(fields)
    rec["updated_at"] = time.strftime("%Y-%m-%d")
    p.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"ledger {a.action} {a.id}: {fields}")
    return 0


def cmd_metrics(a) -> int:
    f = _ledger()
    by_status: dict[str, int] = {}
    for r in f:
        by_status[r.get("status", "?")] = by_status.get(r.get("status", "?"), 0) + 1
    dupes = sum(1 for r in f if r.get("status") == "DUPLICATE")
    out_of_scope = sum(1 for r in f if r.get("status") == "OUT_OF_SCOPE")
    # policy: variants/incomplete-fixes are EXCLUDED, not reported — this counts what we dropped.
    variants_excluded = sum(1 for r in f if "variant" in (r.get("notes", "") + r.get("class", "")).lower()
                            or "incomplete-fix" in (r.get("dup_verdict", "")).lower())
    print("pipeline KPIs (from ledger):")
    print(f"  total findings          : {len(f)}")
    print(f"  by status               : {by_status}")
    print(f"  duplicates caught       : {dupes}")
    print(f"  out-of-scope (non-novel): {out_of_scope}")
    print(f"  variants excluded       : {variants_excluded}  (patch-bypass/incomplete-fix - not reported)")
    return 0


def cmd_board(a) -> int:
    return a.board_fn(a)


# ---------------------------------------------------------------------------- main ----
def main() -> int:
    ap = argparse.ArgumentParser(prog="hunt", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scope", help="authorization gate for a live-website target")
    p.add_argument("--file", help="scope.yml")
    p.add_argument("--check", help="URL to test against the scope")
    p.add_argument("--method", default="GET")
    p.add_argument("--lint", action="store_true")
    p.add_argument("--selftest", action="store_true")
    p.set_defaults(fn=cmd_scope)

    p = sub.add_parser("scan"); p.add_argument("src"); p.add_argument("--lang")
    p.add_argument("--with-codeql", action="store_true"); p.add_argument("--threshold", type=float, default=4.0)
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("sweep"); p.add_argument("target"); p.add_argument("--entry")
    p.add_argument("--authz", help="authz.json path, or 'selftest'")
    p.add_argument("--fuzz", help="endpoint:param, e.g. /calc:expr")
    p.add_argument("--iterations", type=int, default=300)
    p.add_argument("--primitive", help="run one probe primitive instead of the fixture plan")
    p.add_argument("--endpoint"); p.add_argument("--param"); p.add_argument("--secret")
    p.set_defaults(fn=cmd_sweep)

    p = sub.add_parser("probe"); p.add_argument("--url"); p.add_argument("--launch")
    p.add_argument("--primitive", required=True); p.add_argument("--endpoint", required=True)
    p.add_argument("--param"); p.add_argument("--secret")
    p.add_argument("--scope", help="scope.yml — required for a non-loopback --url")
    p.set_defaults(fn=cmd_probe)

    p = sub.add_parser("web", help="live-website recon and coverage")
    wsub = p.add_subparsers(dest="web_cmd", required=True)
    w = wsub.add_parser("recon", help="crawl, mine bundles/sourcemaps, discover specs, baseline")
    w.add_argument("url"); w.add_argument("--scope")
    w.add_argument("--src", help="also have the source? that makes this grey-box")
    w.add_argument("--depth", type=int, default=2)
    w.add_argument("--max-pages", type=int, default=150, dest="max_pages")
    w.add_argument("--auth-cookie", default="", dest="auth_cookie",
                   help="Cookie header for the authenticated baselines")
    w.add_argument("--posture-path", default="/", dest="posture_path",
                   help="the SENSITIVE authenticated path to read headers from (not the root)")
    w = wsub.add_parser("probe", help="sweep every applicable primitive; per-class verdicts")
    w.add_argument("url"); w.add_argument("--scope")
    w.add_argument("--all", action="store_true", help="every primitive (the default)")
    w.add_argument("--primitive", action="append", default=[], help="run only these (repeatable)")
    w.add_argument("--identity", action="append", default=[],
                   help="name=<Cookie header or 'Bearer x'>, repeatable — without at least two, "
                        "every authorization row reports BLOCKED")
    w.add_argument("--opt", action="append", default=[], help="k=v passed to primitives")
    w.add_argument("--marker", default="probe-9c2f")
    w.add_argument("--fast", action="store_true", help="skip the timing/volume probes")
    w.add_argument("--no-browser", action="store_true", dest="no_browser",
                   help="skip the browser checks (they report NEEDS-BROWSER, never clear)")

    w = wsub.add_parser("coverage", help="derive the enumeration tuple from the transcript")
    w.add_argument("target", help="workdir slug, origin, or source path")
    p.set_defaults(fn=cmd_web)

    p = sub.add_parser("authz-scaffold")
    p.add_argument("src", nargs="?", help="local source tree (omit when using --url)")
    p.add_argument("--url", help="derive from work/<slug>/web/endpoints.json instead")
    p.add_argument("--scope")
    p.set_defaults(fn=cmd_authz_scaffold)
    p = sub.add_parser("authz"); p.add_argument("--url", required=True)
    p.add_argument("--config", required=True, help="authz.json path, or 'selftest'")
    p.add_argument("--scope", help="scope.yml — required for a non-loopback --url")
    p.set_defaults(fn=cmd_authz)

    p = sub.add_parser("cvss"); p.add_argument("vector", nargs="?"); p.add_argument("--metrics", nargs="+")
    p.set_defaults(fn=cmd_cvss)

    p = sub.add_parser("evidence"); p.add_argument("target"); p.add_argument("id")
    p.add_argument("--poc", required=True); p.add_argument("--request", default="")
    p.add_argument("--response", default=""); p.add_argument("--url", default="")
    p.add_argument("--log", default=""); p.add_argument("--root-cause", default="", dest="root_cause")
    p.add_argument("--transcript-ids", default="", dest="transcript_ids",
                   help="T00203,T00287 — the exchanges that prove a live-website finding")
    p.add_argument("--screenshot", default=""); p.add_argument("--har", default="")
    p.set_defaults(fn=cmd_evidence)

    p = sub.add_parser("poc-run", help="execute the PoC for real and record it (runlog.json)")
    p.add_argument("target"); p.add_argument("id")
    p.add_argument("--cmd", required=True,
                   help="the exact command the report tells a maintainer to run")
    p.add_argument("--cwd", default="")
    p.add_argument("--python", default="",
                   help="the interpreter the PoC uses — pip freeze is captured from it")
    p.add_argument("--volatile", action="append", default=[],
                   help="regex for a value that legitimately changes between runs (repeatable)")
    p.add_argument("--timeout", type=int, default=600)
    p.add_argument("--no-shell", action="store_true", dest="no_shell")
    p.set_defaults(fn=cmd_poc_run)

    p = sub.add_parser("validate-report"); p.add_argument("id"); p.set_defaults(fn=cmd_validate_report)
    p = sub.add_parser("report"); p.add_argument("id")
    p.add_argument("--layout", choices=sorted(LAYOUTS), default="github",
                   help="destination layout (default: github = private GHSA draft / huntr form)")
    p.set_defaults(fn=cmd_report)
    p = sub.add_parser("dup"); p.add_argument("repo"); p.add_argument("--query", required=True)
    p.set_defaults(fn=cmd_dup)

    p = sub.add_parser("ledger"); p.add_argument("action", choices=["add", "update"])
    p.add_argument("--id", required=True); p.add_argument("--set", nargs="*", default=[],
                                                          help="key=value pairs")
    p.set_defaults(fn=cmd_ledger)

    p = sub.add_parser("metrics"); p.set_defaults(fn=cmd_metrics)

    # ---- the run board: state, so a reprint can't disagree with what actually happened ----
    p = sub.add_parser("board", help="the live run board (state-backed; see the run-board skill)")
    bsub = p.add_subparsers(dest="board_cmd", required=True)

    b = bsub.add_parser("init", help="open the board with the WHOLE roster")
    b.add_argument("target"); b.add_argument("--kind", default="src")
    b.add_argument("--step", default="1/9")
    b.add_argument("--row", action="append", default=[], help="'agent:scope', repeatable")
    b.set_defaults(board_fn=lambda a: B.cmd_init(a))

    b = bsub.add_parser("add", help="append rows (never renumbers existing ones)")
    b.add_argument("target"); b.add_argument("--row", action="append", default=[], required=True)
    b.set_defaults(board_fn=lambda a: B.cmd_add(a))

    for name, status in (("start", "running"), ("done", "done"),
                         ("block", "blocked"), ("na", "na")):
        b = bsub.add_parser(name, help=f"mark a row {status}")
        b.add_argument("target"); b.add_argument("n", type=int)
        b.add_argument("--result", default=""); b.add_argument("--scope", default="")
        b.set_defaults(board_fn=(lambda s: lambda a: B.cmd_status(a, s))(status))

    b = bsub.add_parser("set", help="update a row's result/scope without changing its status")
    b.add_argument("target"); b.add_argument("n", type=int)
    b.add_argument("--result", default=""); b.add_argument("--scope", default="")
    b.add_argument("--status", choices=sorted(B.STATUSES))
    b.add_argument("--show", action="store_true", help="reprint the board after the update")
    b.set_defaults(board_fn=lambda a: B.cmd_set(a))

    b = bsub.add_parser("tally", help="advance the cumulative counters (forward only)")
    b.add_argument("target"); b.add_argument("--covered"); b.add_argument("--step")
    b.add_argument("--hit", type=int); b.add_argument("--clear", type=int)
    b.add_argument("--blocked", type=int)
    b.add_argument("--confirmed", action="append", default=[], help="finding id, repeatable")
    b.set_defaults(board_fn=lambda a: B.cmd_tally(a))

    b = bsub.add_parser("lane", help="open a report lane for a confirmed finding (4 new rows)")
    b.add_argument("target"); b.add_argument("id")
    b.add_argument("--layout", choices=sorted(LAYOUTS), default="github")
    b.set_defaults(board_fn=lambda a: B.cmd_lane(a))

    b = bsub.add_parser("show", help="render the board")
    b.add_argument("target"); b.add_argument("--watch", action="store_true")
    b.add_argument("--interval", type=float, default=2.0)
    b.set_defaults(board_fn=lambda a: B.cmd_show(a))

    p.set_defaults(fn=cmd_board)

    p = sub.add_parser("agents", help="the roster — every agent, its model, tools and skills")
    p.add_argument("--skills", action="store_true", help="list skills and who loads them instead")
    p.add_argument("--width", type=int, default=92)
    p.set_defaults(fn=lambda a: B.cmd_agents(a))

    a = ap.parse_args()
    try:
        return a.fn(a)
    except SystemExit:
        raise
    except Exception as e:                                  # noqa: BLE001
        import scope as S
        if isinstance(e, S.ScopeViolation):
            print(f"\nSCOPE REFUSAL: {e}", file=sys.stderr)
            print("  nothing was sent. Fix the scope file, or stop — the host is not authorized.",
                  file=sys.stderr)
            return S.EXIT_SCOPE_REFUSAL
        raise


if __name__ == "__main__":
    sys.exit(main())
