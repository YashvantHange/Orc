#!/usr/bin/env python3
"""
exttool.py - run an external security tool inside the scope guard.

    from exttool import TargetSpec, run
    res = run("sqlmap", TargetSpec(url="https://app.example.com/api/x", parameter="id"),
              scope_file="work/<slug>/scope.yml", slug="app.example.com",
              opts={"technique": "B"})

WHAT THIS IS FOR: `guardrails` Known gap #1 - a hand-rolled request skips dynamic/scope.py, so it
gets no host/window/rate check and leaves no T##### transcript entry. sqlmap, ffuf, nuclei, dalfox
and commix are all hand-rolled requests by that definition. This module starts a mitmdump carrying
dynamic/mitm_gate.py, points the tool's proxy flag at it, and tears it down afterwards - so the
tool's traffic is scope-checked, rate-limited against the same shared budget as the in-house
primitives, and citable as evidence.

TWO RULES THE INTERFACE ENFORCES, rather than describing:

1. THE CALLER NEVER SUPPLIES A RAW FLAG. Options arrive as `key=value` against a per-tool allowlist,
   and each value must match that option's pattern. A passthrough (`-- <tool args>`) would turn this
   into "run arbitrary offensive software through my proxy", and would let a caller re-specify a
   flag the wrapper already computed - argv order decides the winner for most of these tools.

2. SECURITY-CRITICAL ARGUMENTS ARE THE WRAPPER'S. The proxy, the batch/non-interactive flag and the
   rate ceiling are forced. Destructive modes are refused by name so the error says what was wrong
   rather than silently dropping it. `sqlmap --dump` is the one to keep in mind: it exfiltrates real
   user data, which `disclosure-ethics` forbids independently of scope. Confirming injection needs a
   differential, never a dump.

An allowlist, not a denylist, because a denylist loses to flag aliases (-T for --dump, --os-pwn for
--os-shell), to `--config`-style files that reintroduce banned options, and to any flag a future
release adds.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dynamic"))
sys.path.insert(0, str(ROOT / "static"))

import scope as S  # noqa: E402

EXE = ".exe" if os.name == "nt" else ""


class ToolError(Exception):
    """Bad invocation: unknown tool, unknown option, forbidden option, missing binary."""


# --------------------------------------------------------------------------- the target ---
@dataclass
class TargetSpec:
    """What a tool is pointed at.

    Not a bare URL, because these tools are not uniformly URL-shaped: sqlmap takes a saved raw
    request or a URL plus a parameter name, ffuf needs a FUZZ marker position, nuclei takes a list on
    stdin. Modelling the target once and letting each adapter render it keeps the next tool from
    forcing a redesign. Built from web-recon's endpoints.json entries, so the inventory that already
    exists is the input format.
    """

    url: str = ""
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body: str = ""
    parameter: str = ""
    input_file: str = ""

    def origin_url(self) -> str:
        if not self.url:
            raise ToolError("TargetSpec needs a url for the pre-flight scope check")
        return self.url

    def as_raw_request(self, path: Path) -> Path:
        """Write the target as an HTTP request file (sqlmap -r, and a readable artifact)."""
        u = urlsplit(self.url)
        target = (u.path or "/") + (("?" + u.query) if u.query else "")
        lines = ["{} {} HTTP/1.1".format(self.method.upper(), target), "Host: " + u.netloc]
        lines += ["{}: {}".format(k, v) for k, v in self.headers.items()]
        lines += ["", self.body or ""]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\r\n".join(lines), encoding="utf-8")
        return path


# -------------------------------------------------------------------------- the policies ---
@dataclass
class Opt:
    """One caller-settable option: how it renders, and what values are legal."""

    flag: str
    pattern: str = r"^[A-Za-z0-9_.,:/-]{1,200}$"
    joiner: str = "="

    def render(self, value) -> list:
        v = str(value)
        if not re.fullmatch(self.pattern, v):
            raise ToolError(
                "value {!r} is not allowed for this option (must match {}). Values are "
                "pattern-checked because a permissive value is a flag injection: 'B --dump' would "
                "otherwise smuggle in a second argument.".format(v, self.pattern))
        return [self.flag + "=" + v] if self.joiner == "=" else [self.flag, v]


@dataclass
class ToolPolicy:
    binary: str
    forced: object                  # callable(ctx) -> list
    target: object                  # callable(spec, ctx) -> list
    opts: dict = field(default_factory=dict)
    forbidden: tuple = ()
    note: str = ""


def _rate(ctx) -> float:
    return float(ctx["limits"]["rps"])


def _proxy(ctx) -> str:
    return "http://127.0.0.1:{}".format(ctx["proxy_port"])


# Forbidden entries are spellings refused BY NAME so the error is specific. They are belt to the
# allowlist's braces: a caller cannot reach them anyway, since raw flags are never accepted.
POLICIES = {
    "sqlmap": ToolPolicy(
        binary="sqlmap",
        forced=lambda c: ["--proxy=" + _proxy(c), "--batch", "--risk=1", "--level=2",
                          "--threads=1", "--disable-coloring",
                          "--output-dir=" + str(c["outdir"])],
        target=lambda s, c: ["-r", str(s.as_raw_request(Path(c["outdir"]) / "request.txt"))]
        + (["-p", s.parameter] if s.parameter else []),
        opts={"technique": Opt("--technique", r"^[BEUSTQ]{1,6}$"),
              "dbms": Opt("--dbms", r"^[A-Za-z0-9 ]{1,30}$"),
              "time_sec": Opt("--time-sec", r"^[1-5]$")},
        forbidden=("--dump", "--dump-all", "-D", "-T", "-C", "--os-shell", "--os-pwn", "--os-cmd",
                   "--file-read", "--file-write", "--sql-shell", "--eval", "--tamper",
                   "--configfile", "--crawl"),
        note="confirm with a differential; dumping real rows is a disclosure-ethics violation "
             "independent of scope"),

    "commix": ToolPolicy(
        binary="commix",
        forced=lambda c: ["--proxy=" + _proxy(c), "--batch", "--skip-waf",
                          "--output-dir=" + str(c["outdir"])],
        target=lambda s, c: ["--url", s.origin_url()] + (["-p", s.parameter] if s.parameter else []),
        opts={"technique": Opt("--technique", r"^[ctfeb]{1,5}$"),
              "os_cmd": Opt("--os-cmd", r"^echo [A-Za-z0-9-]{1,40}$")},
        forbidden=("--os-pwn", "--reverse-tcp", "--file-write", "--file-upload", "--shellshock"),
        note="marker command only - `echo <marker>` proves execution without doing anything"),

    "ffuf": ToolPolicy(
        binary="ffuf",
        forced=lambda c: ["-x", _proxy(c), "-rate", str(int(max(_rate(c), 1))), "-s",
                          "-of", "json", "-o", str(Path(c["outdir"]) / "ffuf.json")],
        target=lambda s, c: ["-u", s.origin_url()],
        opts={"wordlist": Opt("-w", r"^[A-Za-z0-9_.:/-]{1,300}$", joiner=" "),
              "match_codes": Opt("-mc", r"^[0-9,]{1,40}$", joiner=" "),
              "filter_size": Opt("-fs", r"^[0-9,]{1,40}$", joiner=" ")},
        forbidden=("-recursion", "-recursion-depth"),
        note="the soft-404 baseline from web-recon is what makes a hit meaningful"),

    "nuclei": ToolPolicy(
        binary="nuclei",
        forced=lambda c: ["-proxy", _proxy(c), "-rl", str(int(max(_rate(c), 1))),
                          "-silent", "-jsonl", "-o", str(Path(c["outdir"]) / "nuclei.jsonl")],
        target=lambda s, c: ["-u", s.origin_url()],
        opts={"tags": Opt("-tags", r"^[a-z0-9,_-]{1,100}$", joiner=" "),
              "severity": Opt(
                  "-severity",
                  r"^(low|medium|high|critical)(,(low|medium|high|critical))*$", joiner=" ")},
        forbidden=("-headless", "-interactsh-server", "-templates", "-t"),
        note="template matches are triage input, not findings"),

    "dalfox": ToolPolicy(
        binary="dalfox",
        forced=lambda c: ["--proxy", _proxy(c), "--delay", str(int(1000 / max(_rate(c), 1))),
                          "--format", "json", "--output", str(Path(c["outdir"]) / "dalfox.json")],
        target=lambda s, c: ["url", s.origin_url()],
        opts={"param": Opt("--param", r"^[A-Za-z0-9_-]{1,60}$", joiner=" ")},
        forbidden=("--blind", "-b", "--remote-payloads", "--custom-payload"),
        note="candidate generator only - xss-hunter's browser assertion is the verdict"),

    "arjun": ToolPolicy(
        binary="arjun",
        forced=lambda c: ["--proxy", _proxy(c), "-t", "1",
                          "-oJ", str(Path(c["outdir"]) / "arjun.json")],
        target=lambda s, c: ["-u", s.origin_url()],
        opts={"method": Opt("-m", r"^(GET|POST|JSON|XML)$", joiner=" ")},
        forbidden=("-w",),
        note="parameter discovery; feeds TargetSpec.parameter for the other tools"),

    "httpx": ToolPolicy(
        binary="httpx",
        forced=lambda c: ["-http-proxy", _proxy(c), "-rl", str(int(max(_rate(c), 1))),
                          "-silent", "-json", "-o", str(Path(c["outdir"]) / "httpx.jsonl")],
        target=lambda s, c: ["-u", s.origin_url()],
        opts={},
        forbidden=(),
        note="probe and fingerprint only"),
}


# ------------------------------------------------------------------------- binary lookup ---
def _venv_python() -> str:
    p = ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin") / ("python" + EXE)
    return str(p) if p.exists() else sys.executable


# Several of these tools are NOT executables. sqlmap ships no console script and no __main__ (so
# `python -m sqlmap` fails too); commix, jwt_tool, nikto and testssl.sh are source trees cloned by
# tools/install_tools.py. Each needs an interpreter in front of a script path, so tool resolution
# returns a COMMAND PREFIX rather than a single binary.
SCRIPT_ENTRIES = {
    "sqlmap": (".venv/lib/site-packages/sqlmap/sqlmap.py", "python"),
    "commix": ("tools/bin/commix/commix.py", "python"),
    "jwt_tool": ("tools/bin/jwt_tool/jwt_tool.py", "python"),
    "nikto": ("tools/bin/nikto/program/nikto.pl", "perl"),
    "testssl.sh": ("tools/bin/testssl.sh/testssl.sh", "bash"),
}


def resolve_command(name: str) -> list | None:
    """The argv prefix that runs this tool, or None if it is not installed.

    tools/bin, then the venv's console scripts, then a known script entry point, then PATH.
    Never a bare shell lookup.
    """
    cand = ROOT / "tools" / "bin" / (name + EXE)
    if cand.exists():
        return [str(cand)]
    venv = ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin") / (name + EXE)
    if venv.exists():
        return [str(venv)]

    entry = SCRIPT_ENTRIES.get(name)
    if entry:
        script, interp = entry
        path = ROOT / script
        if path.exists():
            if interp == "python":
                return [_venv_python(), str(path)]
            found = shutil.which(interp)
            if found:
                return [found, str(path)]

    found = shutil.which(name)
    return [found] if found else None


def resolve_binary(name: str) -> Path | None:
    """First element of the command prefix, for callers that only need a presence check."""
    cmd = resolve_command(name)
    return Path(cmd[0]) if cmd else None


def available() -> dict:
    return {n: resolve_command(p.binary) for n, p in POLICIES.items()}


def _policy(tool: str) -> ToolPolicy:
    if tool not in POLICIES:
        raise ToolError("unknown tool {!r}; known: {}".format(tool, ", ".join(sorted(POLICIES))))
    return POLICIES[tool]


def explain(tool: str) -> str:
    """Print the policy the wrapper actually enforces.

    Exists so an agent reads the real rules instead of inferring them from the skill text - a drift
    between what the docs say and what the wrapper does is what sends someone looking for a
    workaround.
    """
    p = _policy(tool)
    b = resolve_command(p.binary)
    ctx = {"proxy_port": "PORT", "outdir": "<outdir>", "limits": {"rps": 1}}
    lines = ["{}  ({})".format(tool, "installed: " + " ".join(b) if b else "NOT INSTALLED"),
             "  binary        " + p.binary,
             "  forced        " + " ".join(str(x) for x in p.forced(ctx)),
             "  options       " + (", ".join(sorted(p.opts)) or "(none)"),
             "  refused       " + (", ".join(p.forbidden) or "(none)")]
    if p.note:
        lines.append("  note          " + p.note)
    return "\n".join(lines)


def build_argv(tool: str, spec: TargetSpec, ctx: dict, opts: dict | None = None) -> list:
    """Render the full argv. Raises rather than dropping anything it does not recognise."""
    p = _policy(tool)
    cmd = ctx.get("cmd") or [str(ctx["binary"])]
    argv = [str(x) for x in cmd] + list(p.forced(ctx)) + list(p.target(spec, ctx))
    for key, value in (opts or {}).items():
        if key not in p.opts:
            allowed = ", ".join(sorted(p.opts)) or "none"
            bare = str(key).lstrip("-").lower()
            if any(bare == f.lstrip("-").lower() for f in p.forbidden):
                raise ToolError(
                    "{}: {!r} is refused by policy. Allowed: {}. {}".format(
                        tool, key, allowed,
                        p.note or "it is destructive or out of scope for confirmation"))
            raise ToolError(
                "{}: unknown option {!r}. Allowed: {}. Options are an allowlist - raw flags are "
                "never accepted, so a new one must be added to POLICIES.".format(tool, key, allowed))
        argv += p.opts[key].render(value)
    return argv


# ------------------------------------------------------------------------------ the run ---
def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_port(port: int, timeout: float = 45.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def run(tool: str, spec: TargetSpec, scope_file: str, slug: str,
        opts: dict | None = None, workdir: Path | None = None, timeout: int = 900) -> dict:
    """Start the gate, run the tool through it, tear it down. Returns a result record."""
    p = _policy(tool)
    cmd = resolve_command(p.binary)
    if not cmd:
        raise ToolError(
            "{}: {} is not installed. Run `.venv/Scripts/python.exe tools/install_tools.py "
            "--with-offensive`. A missing tool is BLOCKED (untested) - never CLEAR."
            .format(tool, p.binary))

    sc = S.Scope.load(scope_file)

    # PRE-FLIGHT, before anything is spawned: an out-of-scope target costs zero processes.
    decision = sc.explain(spec.method or "GET", spec.origin_url())
    if not decision["allowed"]:
        raise S.ScopeViolation(decision["reason"], spec.method, spec.origin_url(), decision["rule"])

    if workdir is None:
        import _common as C
        workdir = Path(C.workdir(slug))
    workdir = Path(workdir)
    outdir = workdir / "dynamic" / "ext" / tool
    outdir.mkdir(parents=True, exist_ok=True)

    mitm = resolve_command("mitmdump")
    if not mitm:
        raise ToolError("mitmdump is not installed, so no external tool can be run inside the "
                        "scope guard. Run tools/install_tools.py --with-offensive.")

    transcript = workdir / "web" / "transcript.jsonl"
    before = _last_id(transcript)

    port = _free_port()
    env = {**os.environ,
           "HUNT_SCOPE_FILE": str(scope_file), "HUNT_SLUG": slug,
           "HUNT_EXT_TOOL": tool, "HUNT_WORKDIR": str(workdir),
           "PYTHONPATH": os.pathsep.join([str(ROOT / "dynamic"), str(ROOT / "static")]),
           "PYTHONUTF8": "1"}
    gate = subprocess.Popen(
        [str(mitm[0]), "-q", "--listen-host", "127.0.0.1", "-p", str(port),
         "-s", str(ROOT / "dynamic" / "mitm_gate.py"),
         "--set", "confdir=" + str(outdir / "mitm")],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    started = time.time()
    argv: list = []
    stdout_path = outdir / "stdout.txt"
    try:
        if not _wait_port(port):
            gate.kill()
            raise ToolError("the scope gate did not start, so the tool was not run. Check "
                            "`mitmdump --version` - a broken pyOpenSSL pin is the usual cause.")

        ctx = {"proxy_port": port, "outdir": str(outdir), "cmd": cmd,
               "binary": cmd[0], "limits": sc.limits}
        argv = build_argv(tool, spec, ctx, opts)

        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              cwd=str(outdir))
        stdout_path.write_text((proc.stdout or "") + (proc.stderr or ""), encoding="utf-8")
        code = proc.returncode
    except subprocess.TimeoutExpired:
        stdout_path.write_text("timed out after {}s".format(timeout), encoding="utf-8")
        code = -1
    finally:
        gate.terminate()
        try:
            gate.wait(timeout=10)
        except subprocess.TimeoutExpired:
            gate.kill()

    after = _last_id(transcript)
    rec = {"tool": tool, "argv": [str(a) for a in argv], "exit": code,
           "stdout_path": str(stdout_path), "outdir": str(outdir),
           "transcript_ids": (["T{:05d}".format(before + 1), "T{:05d}".format(after)]
                              if after > before else []),
           "requests": max(0, after - before),
           "duration_s": round(time.time() - started, 1),
           "scope_digest": sc.digest()}
    _append(workdir / "dynamic" / "exttools.json", rec)
    return rec


def _last_id(transcript: Path) -> int:
    if not transcript.exists():
        return 0
    ids = re.findall(r'"id":\s*"T(\d+)"',
                     transcript.read_text(encoding="utf-8", errors="replace"))
    return max((int(i) for i in ids), default=0)


def _append(path: Path, rec: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(doc, list):
            doc = []
    except (OSError, ValueError):
        doc = []
    doc.append(rec)
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
