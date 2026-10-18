#!/usr/bin/env python3
"""
scope.py — the authorization choke point for live-website targets.

Every HTTP request the pipeline sends at a host it does not own goes through here. The scope file
(scope.yml) states which hosts/paths/methods a bug-bounty program authorizes, how fast, and for how
long; this module refuses anything outside that and writes an auditable transcript of everything it
did send.

Two ways to use it:

  explicit   sess = ScopedSession(Scope.load("scope.yml"), slug="app.example.com")
             sess.get(url)

  ambient    activate(scope, slug)            # or set HUNT_SCOPE_FILE in the environment
             from scope import http as requests
             requests.get(url)                # guarded, rate-limited, transcribed

The ambient form is what lets probe.py / authz_diff.py / fuzz.py be retrofitted by changing one
import line each. With no scope active the facade delegates straight to real `requests`, so every
existing local-target flow behaves byte-for-byte as before.

AUTHORIZED TARGETS ONLY: a local instance you launched yourself, or a live host that a validated
scope.yml places inside a published bug-bounty/VDP scope, inside its window, at its stated rate.
The guard is a safety net, not permission — see the disclosure-ethics skill.
"""
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import requests as _requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from limits import BudgetExhausted, SharedLimiter, _FileLock  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

EXIT_SCOPE_REFUSAL = 3          # distinct from 1 (not confirmed) and 2 (usage)
_MAX_REQ_BODY = 4096
_MAX_RESP_BODY = 8192

DEFAULT_LIMITS = {"rps": 2.0, "burst": 5, "concurrency": 2, "max_requests": 5000,
                  "timeout_s": 15, "max_redirects": 3}
DEFAULT_METHODS = {"allow": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"],
                   "deny": ["DELETE", "TRACE", "CONNECT"]}
# Verbs that change state, paired with paths that sound irreversible. The combination is refused;
# either alone is fine (a POST to /login is normal; a GET of /account/delete is a read).
_DESTRUCTIVE_VERBS = {"POST", "PUT", "PATCH", "DELETE"}


class ScopeViolation(Exception):
    """A request the scope file does not authorize. Never caught-and-continued inside this module."""

    def __init__(self, reason: str, method: str = "", url: str = "", rule: str = ""):
        super().__init__(reason)
        self.reason, self.method, self.url, self.rule = reason, method, url, rule

    def __str__(self) -> str:
        where = f" [{self.method} {self.url}]" if self.url else ""
        return f"{self.reason}{where}" + (f" (rule: {self.rule})" if self.rule else "")


class ScopeError(Exception):
    """A malformed or unreadable scope file. Fail closed — never degrade to 'no scope'."""


# ------------------------------------------------------------------------ rate limiting ---
class _TokenBucket:
    """Monotonic token bucket. acquire() blocks until a token is available."""

    def __init__(self, rps: float, burst: int):
        self.rps = max(float(rps), 0.01)
        self.capacity = max(int(burst), 1)
        self._tokens = float(self.capacity)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """Consume one token, sleeping if necessary. Returns seconds waited."""
        waited = 0.0
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rps)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return waited
                need = (1.0 - self._tokens) / self.rps
            time.sleep(need)
            waited += need


# -------------------------------------------------------------------------- the scope ---
@dataclass
class Scope:
    raw: dict
    path: Path | None = None
    _digest: str = ""
    _bucket: _TokenBucket | None = field(default=None, repr=False)
    _sem: threading.Semaphore | None = field(default=None, repr=False)
    _sent: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    # Set by attach_shared() once a workdir is known. While it is None the in-memory counters above
    # are the authority (loopback targets we launched); once set, the file is, and the in-memory
    # counters are bypassed entirely rather than kept in parallel — two authorities is the bug.
    _shared: SharedLimiter | None = field(default=None, repr=False)

    # ---------------------------------------------------------------------- loading ---
    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        p = Path(path)
        if not p.exists():
            raise ScopeError(f"scope file not found: {p}")
        try:
            import yaml
        except ImportError as e:                       # PyYAML is in requirements.txt
            raise ScopeError(f"PyYAML required to read a scope file: {e}") from e
        blob = p.read_bytes()
        try:
            doc = yaml.safe_load(blob.decode("utf-8")) or {}
        except Exception as e:                          # noqa: BLE001 - yaml raises many types
            raise ScopeError(f"{p}: not valid YAML: {e}") from e
        if not isinstance(doc, dict):
            raise ScopeError(f"{p}: top level must be a mapping")
        sc = cls(raw=doc, path=p, _digest="sha256:" + hashlib.sha256(blob).hexdigest())
        sc._validate()
        lim = sc.limits
        sc._bucket = _TokenBucket(lim["rps"], lim["burst"])
        sc._sem = threading.Semaphore(max(int(lim["concurrency"]), 1))
        return sc

    @classmethod
    def local(cls, host: str = "127.0.0.1") -> "Scope":
        """An implicit permissive scope for a target we launched ourselves. Used by --launch flows
        so local self-tests are transcribed without needing a scope file on disk."""
        doc = {"schema": 1, "program": {"name": "local", "authorized_by": "self-hosted"},
               "in_scope": {"schemes": ["http", "https"], "hosts": [host], "allow_private": True},
               "limits": {"rps": 50, "burst": 50, "concurrency": 8, "max_requests": 100000}}
        sc = cls(raw=doc, path=None, _digest="local")
        lim = sc.limits
        sc._bucket = _TokenBucket(lim["rps"], lim["burst"])
        sc._sem = threading.Semaphore(int(lim["concurrency"]))
        return sc

    def _validate(self) -> None:
        ins = self.raw.get("in_scope")
        if not isinstance(ins, dict) or not ins.get("hosts"):
            raise ScopeError(f"{self.path}: in_scope.hosts is required and must be non-empty")
        if not isinstance(ins["hosts"], list):
            raise ScopeError(f"{self.path}: in_scope.hosts must be a list")
        for key in ("in_scope", "out_of_scope"):
            for sub in ("paths",):
                pats = ((self.raw.get(key) or {}).get(sub) or [])
                for pat in pats:
                    try:
                        re.compile(pat)
                    except re.error as e:
                        raise ScopeError(f"{self.path}: {key}.{sub}: bad regex {pat!r}: {e}") from e
        for pat in (self.safety.get("destructive_paths") or []):
            try:
                re.compile(pat)
            except re.error as e:
                raise ScopeError(f"{self.path}: safety.destructive_paths: bad regex {pat!r}") from e
        for k in ("start", "end"):
            v = (self.raw.get("test_window") or {}).get(k)
            if v is not None and _parse_ts(v) is None:
                raise ScopeError(f"{self.path}: test_window.{k}={v!r} is not an ISO-8601 timestamp")
        prox = self.raw.get("proxy")
        if prox is not None:
            if not isinstance(prox, dict):
                raise ScopeError(f"{self.path}: proxy must be a mapping of {{http, https, verify}}")
            for k in ("http", "https"):
                v = prox.get(k)
                if v is not None and (not isinstance(v, str) or not urlsplit(v).scheme):
                    raise ScopeError(f"{self.path}: proxy.{k}={v!r} must be a URL like "
                                     f"http://127.0.0.1:8081")
            ver = prox.get("verify")
            if ver is not None and not isinstance(ver, (bool, str)):
                raise ScopeError(f"{self.path}: proxy.verify must be a CA bundle path or a boolean")

        rh = self.safety.get("required_headers")
        if rh is not None:
            if not isinstance(rh, dict):
                raise ScopeError(f"{self.path}: safety.required_headers must be a mapping of "
                                 f"header-name -> value")
            for k, v in rh.items():
                s = "" if v is None else str(v).strip()
                # A policy-mandated attribution header sent with the template text still in it is
                # worse than not testing: the traffic is unattributable AND looks like an attack.
                if not s or _PLACEHOLDER_RE.search(s):
                    raise ScopeError(
                        f"{self.path}: safety.required_headers[{k!r}] is unfilled ({v!r}) — the "
                        f"program mandates this header, so substitute the real value before testing")

    # -------------------------------------------------------------------- accessors ---
    @property
    def limits(self) -> dict:
        return {**DEFAULT_LIMITS, **(self.raw.get("limits") or {})}

    @property
    def methods(self) -> dict:
        m = self.raw.get("methods") or {}
        return {"allow": [x.upper() for x in (m.get("allow") or DEFAULT_METHODS["allow"])],
                "deny": [x.upper() for x in (m.get("deny") or DEFAULT_METHODS["deny"])]}

    @property
    def safety(self) -> dict:
        return self.raw.get("safety") or {}

    @property
    def program(self) -> dict:
        return self.raw.get("program") or {}

    @property
    def user_agent(self) -> str:
        return self.safety.get("user_agent") or "sec-research/1.0 (authorized scope testing)"

    @property
    def proxy(self) -> dict:
        """Optional upstream proxy: {http, https, verify}.

        Present so the whole in-house path can be recorded through mitmproxy alongside the external
        tools, or watched live through a Burp/ZAP listener. Absent by default — an unset key must
        leave requests' own behaviour untouched, including its trust_env handling.

        `verify` is normally the path to the intercepting proxy's CA certificate. It may be set to
        false, which is why lint() warns about it: TLS verification off against a live target means a
        third party on the path can read and rewrite the traffic, and the transcript would record the
        rewritten version as if the target had sent it.
        """
        p = self.raw.get("proxy") or {}
        return {str(k): v for k, v in p.items()} if isinstance(p, dict) else {}

    @property
    def required_headers(self) -> dict:
        """Headers the program's policy *requires* on every request (attribution headers such as
        HackerOne's X-HackerOne-Research). ScopedSession applies these to the whole session, so a
        primitive cannot forget one. Untestable by us — the policy is the authority."""
        h = self.safety.get("required_headers") or {}
        return {str(k): str(v) for k, v in h.items()}

    def digest(self) -> str:
        return self._digest

    # ----------------------------------------------------------------- the decision ---
    def explain(self, method: str, url: str) -> dict:
        # A malformed URL used to escape as a raw urllib ValueError from deep inside the parser
        # ("Port could not be cast to integer value as '8099C:'"), which reads like a pipeline crash
        # rather than what it is. The usual cause on Windows is MSYS rewriting a leading-slash
        # argument (--endpoint /api/x) into C:/Program Files/Git/api/x, and the message must say so
        # or the operator debugs the wrong layer - it cost two wrong diagnoses to learn that once.
        try:
            _probe = urlsplit(url)
            _ = _probe.port
        except ValueError as e:
            return {"allowed": False, "rule": "url.malformed",
                    "reason": (f"{url!r} is not a parseable URL ({e}). On Windows this is usually "
                               f"MSYS path conversion rewriting a leading-slash argument into a "
                               f"C:\... path - set MSYS_NO_PATHCONV=1 for that argument, or pass "
                               f"the endpoint without a leading slash.")}

        """Pure, network-free scope decision. Returns {allowed, reason, rule}. The one function
        the tests drive — check() is just this plus side effects."""
        method = (method or "GET").upper()
        try:
            u = urlsplit(url)
        except ValueError:
            return _deny("unparseable URL", "url")
        if not u.scheme or not u.hostname:
            return _deny(f"not an absolute URL: {url!r}", "url")

        ins = self.raw.get("in_scope") or {}
        oos = self.raw.get("out_of_scope") or {}

        schemes = [s.lower() for s in (ins.get("schemes") or ["https", "http"])]
        if u.scheme.lower() not in schemes:
            return _deny(f"scheme {u.scheme!r} not in in_scope.schemes {schemes}", "in_scope.schemes")

        host = u.hostname.lower()
        port = u.port or (443 if u.scheme.lower() == "https" else 80)

        # deny wins, always, and is evaluated first
        for pat in (oos.get("hosts") or []):
            if _host_match(host, pat):
                return _deny(f"host {host} matches out_of_scope.hosts {pat!r}", "out_of_scope.hosts")
        if not any(_host_match(host, pat) for pat in (ins.get("hosts") or [])):
            return _deny(f"host {host} not in in_scope.hosts", "in_scope.hosts")

        ports = ins.get("ports")
        if ports and port not in [int(x) for x in ports]:
            return _deny(f"port {port} not in in_scope.ports {ports}", "in_scope.ports")

        path = u.path or "/"
        for pat in (oos.get("paths") or []):
            if re.search(pat, path):
                return _deny(f"path {path} matches out_of_scope.paths {pat!r}", "out_of_scope.paths")
        in_paths = ins.get("paths") or []
        if in_paths and not any(re.search(pat, path) for pat in in_paths):
            return _deny(f"path {path} not in in_scope.paths", "in_scope.paths")

        meths = self.methods
        if method in meths["deny"]:
            return _deny(f"method {method} in methods.deny", "methods.deny")
        if method not in meths["allow"]:
            return _deny(f"method {method} not in methods.allow", "methods.allow")

        if method in _DESTRUCTIVE_VERBS:
            for pat in (self.safety.get("destructive_paths") or []):
                if re.search(pat, path):
                    return _deny(f"{method} {path} matches safety.destructive_paths {pat!r}",
                                 "safety.destructive_paths")

        win = self.raw.get("test_window") or {}
        now = datetime.now(timezone.utc)
        start, end = _parse_ts(win.get("start")), _parse_ts(win.get("end"))
        if start and now < start:
            return _deny(f"test window has not opened (starts {win['start']})", "test_window.start")
        if end and now > end:
            return _deny(f"test window closed at {win['end']}", "test_window.end")

        return {"allowed": True, "reason": "in scope", "rule": ""}

    def check(self, method: str, url: str) -> None:
        """Raise ScopeViolation unless this request is authorized. Includes the checks that need
        the network (DNS -> private-IP refusal) and the request budget."""
        verdict = self.explain(method, url)
        if not verdict["allowed"]:
            raise ScopeViolation(verdict["reason"], method, url, verdict["rule"])

        ins = self.raw.get("in_scope") or {}
        if not ins.get("allow_private"):
            host = urlsplit(url).hostname or ""
            for ip in _resolve(host):
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    raise ScopeViolation(
                        f"host {host} resolves to non-public {ip} — set in_scope.allow_private only "
                        f"for a target you launched yourself", method, url, "in_scope.allow_private")

        # With a shared limiter attached the budget is spent in acquire(), against the file every
        # participating process locks. Counting here too would double-charge each request.
        if self._shared is not None:
            return

        budget = int(self.limits["max_requests"])
        with self._lock:
            if self._sent >= budget:
                raise ScopeViolation(f"request budget exhausted ({budget}); raise limits.max_requests "
                                     f"only if the program's policy allows it", method, url,
                                     "limits.max_requests")
            self._sent += 1

    # ------------------------------------------------------------- rate & budget spending ---
    def attach_shared(self, path: str | Path) -> None:
        """Route rate and budget through a file every process testing this target locks.

        Called by ScopedSession once the workdir is known, and by the mitmproxy gate with the same
        path, so an external tool and the in-house primitives draw down ONE budget. Without this the
        two processes each get a full max_requests — see limits.py for why that is an authorization
        defect and not merely an inconsistency.

        ALWAYS attached when there is a scope FILE, including a loopback one. It is tempting to skip
        it for a target we launched ourselves - it costs a measured 52 ms per request, two lock
        cycles each opening, locking, reading and rewriting the state file, which is ~10 minutes
        across a full sweep's ~11k requests. That skip was tried and REVERTED: the shared budget is
        also what makes a proxied external tool's traffic accountable, and
        tests/test_exttool_live.py asserts exactly that on a loopback target. limits.py's "cheap
        path" reasoning applies to Scope.local() - the IMPLICIT scope with no file - because writing
        a scope file is opting into this accounting.

        The cost is real and the honest fix is to make this cheaper (one lock cycle for rate, budget
        and slot instead of two), not to stop sharing.
        """
        lim = self.limits
        # concurrency moves to the file for the same reason the budget did. It was the one limit
        # left in process memory: N agent processes each got their own semaphore, so a scope
        # authorising 2 in flight permitted 2*N. requests' timeout is per-read rather than total,
        # so the TTL is a crash backstop sized well above any single exchange - liveness, not the
        # clock, is what actually frees a slot.
        self._shared = SharedLimiter(path, rps=lim["rps"], burst=lim["burst"],
                                     max_requests=int(lim["max_requests"]),
                                     concurrency=int(lim["concurrency"]),
                                     lease_ttl=max(60.0, float(lim["timeout_s"]) * 4))

    def slot(self):
        """One of the target's concurrency slots, as a context manager.

        The shared limiter is the authority whenever it is attached, exactly as it is for rate and
        budget - keeping two authorities apart is the whole point of the _shared field. Loopback
        targets we launched ourselves keep the in-process semaphore.
        """
        if self._shared is not None:
            return self._shared.lease()
        return self._sem

    def acquire_slot(self) -> str:
        """Take a concurrency slot without a `with` block, for hook-driven callers (the proxy gate).

        Returns "" when no shared limiter is attached: a loopback target we launched has no program
        policy to honour, and the in-process semaphore cannot span the proxy's separate hooks.
        """
        return self._shared.acquire_lease() if self._shared is not None else ""

    def release_slot(self, token: str) -> None:
        if token and self._shared is not None:
            self._shared.release_lease(token)

    def acquire(self, method: str = "", url: str = "") -> float:
        """Spend one token of rate and one unit of budget. Returns seconds waited.

        The single place either is spent, so the shared and in-memory paths cannot drift. Budget
        exhaustion surfaces as a ScopeViolation whichever path produced it, keeping ScopeViolation
        the one exception callers need to handle.
        """
        if self._shared is not None:
            try:
                return self._shared.acquire()
            except BudgetExhausted as e:
                raise ScopeViolation(
                    f"request budget exhausted ({e.sent}/{e.budget}); raise limits.max_requests only "
                    f"if the program's policy allows it", method, url, "limits.max_requests") from e
        return self._bucket.acquire()

    def lint(self) -> list[str]:
        """Advisory warnings about a scope file that parses but is weak. Never blocks."""
        warn: list[str] = []
        prog = self.program
        if not prog.get("policy_sha256"):
            warn.append("program.policy_sha256 is empty — pin the hash of the policy text you read")
        if not prog.get("authorized_by"):
            warn.append("program.authorized_by is empty — this should be typed by a human, not "
                        "generated; it is the field carrying legal weight")
        if not prog.get("url"):
            warn.append("program.url is empty — the report needs the program it was tested under")
        if not (self.raw.get("test_window") or {}).get("end"):
            warn.append("test_window.end is unset — testing will never self-expire")
        if (self.raw.get("in_scope") or {}).get("allow_private"):
            warn.append("in_scope.allow_private is true — correct ONLY for a locally-launched "
                        "instance; never for a third-party host")
        if prog.get("platform") in ("hackerone", "bugcrowd", "intigriti") and not self.required_headers:
            warn.append(f"safety.required_headers is empty — most {prog['platform']} programs ask "
                        f"for an attribution header (e.g. X-HackerOne-Research); check the policy")
        if self.limits["rps"] > 10:
            warn.append(f"limits.rps={self.limits['rps']} is high — confirm the program permits it")
        for pat in ((self.raw.get("in_scope") or {}).get("hosts") or []):
            if pat.strip() in ("*", ".", ".*"):
                warn.append(f"in_scope.hosts contains {pat!r} — that authorizes the entire internet")
        return warn


# Placeholder text left in a field that must carry a real value: "[H1 username]", "<your-handle>",
# "TODO", "CHANGEME". Cheap, and it catches the one mistake that makes traffic unattributable.
_PLACEHOLDER_RE = re.compile(
    r"[<\[\{]|\b(todo|changeme|fixme|your[-_ ]?handle|h1[-_ ]?username)\b", re.I)


def _deny(reason: str, rule: str) -> dict:
    return {"allowed": False, "reason": reason, "rule": rule}


def _host_match(host: str, pattern: str) -> bool:
    """Exact host, or a leading-dot wildcard (.example.com matches any subdomain AND the apex).
    Deliberately not a regex — a typo'd regex that over-matches is how you test the wrong company."""
    p = (pattern or "").strip().lower()
    if not p:
        return False
    if p.startswith("."):
        base = p[1:]
        return host == base or host.endswith(p)
    if "*" in p:
        return fnmatch.fnmatch(host, p)
    return host == p


def _resolve(host: str) -> list:
    try:
        ipaddress.ip_address(host)
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    out = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    return out


def _parse_ts(v) -> datetime | None:
    if not v:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ------------------------------------------------------------------------- transcript ---
class _Transcript:
    """Append-only JSONL of every request sent and every request refused. The T##### ids are what
    a report cites in place of file:line for a black-box target, so they must be stable and the
    bodies must be hashed."""

    def __init__(self, path: Path, shared: bool = False):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._n = self._resume()
        # `shared` is for processes that write CONCURRENTLY - the in-house primitives and an
        # external tool's traffic arriving through the mitmproxy gate at the same moment.
        # _resume() runs once at construction, which is enough for hunt.py's SEQUENTIAL
        # subprocesses but not for two live writers: both would hold the same _n and mint
        # duplicate ids. A duplicate T##### makes a report's evidence citation ambiguous, so in
        # shared mode the id is allocated from the file itself, under a lock every writer respects.
        self._shared = bool(shared)
        self._flock = _FileLock(Path(str(path) + ".ids")) if shared else None
        self._counter = Path(str(path) + ".ids")

    def _counter_on_disk(self) -> int:
        """Highest id handed out, including ids reserved but not yet written."""
        try:
            return int(json.loads(self._counter.read_text(encoding="utf-8"))["n"])
        except (OSError, ValueError, KeyError, TypeError):
            return 0

    def _last_id_on_disk(self) -> int:
        """Highest id already written. Reads the tail rather than the whole file - an engagement's
        transcript gets large and this runs once per request."""
        try:
            size = self.path.stat().st_size
        except OSError:
            return 0
        if not size:
            return 0
        try:
            with self.path.open("rb") as fh:
                fh.seek(max(0, size - 8192))
                tail = fh.read().decode("utf-8", "replace")
        except OSError:
            return 0
        ids = re.findall(r'"id":\s*"T(\d+)"', tail)
        # max(), NOT ids[-1]: records interleave. Process A reserves T00005, B reserves
        # T00006, then A appends its real T00005 record last - so the final line in the file
        # is T00005 and the next allocator would hand out T00006 a second time.
        return max((int(i) for i in ids), default=self._n)

    def _resume(self) -> int:
        """Continue the id sequence across processes — hunt.py launches authz_diff/fuzz as
        subprocesses, and restarting at T00001 would collide with existing evidence."""
        if not self.path.exists():
            return 0
        n = 0
        try:
            with self.path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = re.search(r'"id":\s*"T(\d+)"', line)
                    if m:
                        n = max(n, int(m.group(1)))
        except OSError:
            return 0
        return n

    def next_id(self) -> str:
        if self._shared:
            # The id is reserved in a sidecar counter, NOT by writing a placeholder line into the
            # transcript. An early version did the latter, and it meant every request left two
            # lines carrying the same T##### - which is precisely the ambiguity shared mode exists
            # to remove, since `hunt evidence --transcript-ids` selects by id.
            with self._flock:
                n = max(self._n, self._counter_on_disk(), self._last_id_on_disk()) + 1
                self._n = n
                try:
                    self._counter.write_text(json.dumps({"n": n}), encoding="utf-8")
                except OSError:
                    pass       # the tail scan below is the fallback authority
                return f"T{n:05d}"
        with self._lock:
            self._n += 1
            return f"T{self._n:05d}"

    def write(self, rec: dict) -> None:
        if self._shared:
            with self._flock:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            return
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


_REDACT_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
                   "proxy-authorization"}
_REDACT_BODY = re.compile(
    r'(?i)("(?:password|passwd|secret|token|api_?key|access_?token|refresh_?token|client_?secret)"'
    r'\s*:\s*)"[^"]*"')


def _redact_headers(h: dict) -> dict:
    return {k: ("<REDACTED>" if k.lower() in _REDACT_HEADERS else v) for k, v in (h or {}).items()}


def _redact_body(s: str) -> str:
    return _REDACT_BODY.sub(r'\1"<REDACTED>"', s or "")


def _sha(s) -> str:
    if s is None:
        return ""
    b = s.encode("utf-8", "replace") if isinstance(s, str) else bytes(s)
    return hashlib.sha256(b).hexdigest()


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + f"\n...[truncated {len(s) - n} chars]"


# --------------------------------------------------------------------- scoped session ---
class ScopedSession:
    """The only object in the pipeline allowed to put bytes on the wire at a scoped target."""

    def __init__(self, scope: Scope, slug: str, identity: str = "anon",
                 workdir: Path | None = None, primitive: str = ""):
        self.scope = scope
        self.slug = slug
        self.identity = identity
        self.primitive = primitive
        if workdir is None:
            sys.path.insert(0, str(ROOT / "static"))
            import _common as C
            workdir = C.workdir(slug)
        self.workdir = Path(workdir)
        # A real scope file means a live target, which is where an external tool may be
        # writing to this same transcript concurrently through the mitmproxy gate.
        self.transcript = _Transcript(self.workdir / "web" / "transcript.jsonl",
                                      shared=scope.path is not None)
        self._sess = _requests.Session()
        self._sess.headers.update({"User-Agent": scope.user_agent})
        # Policy-mandated attribution headers ride on the session so no primitive can omit one.
        self._sess.headers.update(scope.required_headers)

        # Route through the recording proxy when the scope asks for one, so in-house traffic and
        # external-tool traffic land in the same transcript in the same order.
        prox = scope.proxy
        if prox:
            self._sess.proxies = {k: v for k, v in prox.items()
                                  if k in ("http", "https") and v}
            if "verify" in prox:
                self._sess.verify = prox["verify"]

        # One budget per target, shared with every other process testing it. Only for a real scope
        # file — a loopback instance we launched has no program policy to honour, so it keeps the
        # cheap in-memory counters rather than locking a file on every request.
        if scope.path is not None:
            scope.attach_shared(self.workdir / "web" / "limits.json")

        self.finding = ""          # set to an Fxxx id to tag the requests that prove it

    # ------------------------------------------------------------------------ api ---
    def request(self, method: str, url: str, **kw):
        method = (method or "GET").upper()
        # Redirects are followed by hand so every hop is re-checked. requests' own redirect
        # following would happily walk an in-scope 302 out to a CDN or SSO host.
        follow = kw.pop("allow_redirects", False)
        kw.setdefault("timeout", self.scope.limits["timeout_s"])
        max_hops = int(self.scope.limits["max_redirects"])

        hops = 0
        while True:
            resp = self._send(method, url, **kw)
            if not follow or resp.status_code not in (301, 302, 303, 307, 308):
                return resp
            loc = resp.headers.get("Location")
            if not loc:
                return resp
            if hops >= max_hops:
                return resp
            url = _requests.compat.urljoin(url, loc)
            if resp.status_code in (301, 302, 303) and method not in ("GET", "HEAD"):
                method, kw = "GET", {k: v for k, v in kw.items() if k not in ("data", "json", "files")}
            hops += 1

    def _send(self, method: str, url: str, **kw):
        tid = self.transcript.next_id()
        try:
            self.scope.check(method, url)
        except ScopeViolation as v:
            self.transcript.write({
                "id": tid, "ts": _now(), "refused": True, "identity": self.identity,
                "primitive": self.primitive, "method": method, "url": url,
                "reason": v.reason, "rule": v.rule, "scope_digest": self.scope.digest()})
            raise

        if self.scope.safety.get("dry_run"):
            self.transcript.write({"id": tid, "ts": _now(), "dry_run": True, "method": method,
                                   "url": url, "identity": self.identity,
                                   "scope_digest": self.scope.digest()})
            raise ScopeViolation("safety.dry_run is set — no request sent", method, url, "safety.dry_run")

        try:
            waited = self.scope.acquire(method, url)
        except ScopeViolation as v:
            self.transcript.write({
                "id": tid, "ts": _now(), "refused": True, "identity": self.identity,
                "primitive": self.primitive, "method": method, "url": url,
                "reason": v.reason, "rule": v.rule, "scope_digest": self.scope.digest()})
            raise
        started = time.monotonic()
        with self.scope.slot():
            try:
                resp = self._sess.request(method, url, allow_redirects=False, **kw)
            except _requests.RequestException as e:
                self.transcript.write({"id": tid, "ts": _now(), "identity": self.identity,
                                       "primitive": self.primitive, "method": method, "url": url,
                                       "error": f"{type(e).__name__}: {e}",
                                       "scope_digest": self.scope.digest()})
                raise
        elapsed = (time.monotonic() - started) * 1000.0

        body = kw.get("data") or kw.get("json") or ""
        if not isinstance(body, str):
            try:
                body = json.dumps(body)
            except (TypeError, ValueError):
                body = str(body)
        text = resp.text or ""
        self.transcript.write({
            "id": tid, "ts": _now(), "identity": self.identity, "primitive": self.primitive,
            "finding": self.finding, "method": method, "url": url,
            "req_headers": _redact_headers(dict(self._sess.headers, **(kw.get("headers") or {}))),
            "req_body": _truncate(_redact_body(body), _MAX_REQ_BODY),
            "req_body_sha256": _sha(body),
            "status": resp.status_code,
            "resp_headers": _redact_headers(dict(resp.headers)),
            "resp_body": _truncate(text, _MAX_RESP_BODY),
            "resp_body_sha256": _sha(text),
            "elapsed_ms": round(elapsed, 1), "rate_wait_ms": round(waited * 1000, 1),
            "scope_digest": self.scope.digest()})
        return resp

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def put(self, url, **kw):
        return self.request("PUT", url, **kw)

    def patch(self, url, **kw):
        return self.request("PATCH", url, **kw)

    def delete(self, url, **kw):
        return self.request("DELETE", url, **kw)

    def head(self, url, **kw):
        return self.request("HEAD", url, **kw)

    def options(self, url, **kw):
        return self.request("OPTIONS", url, **kw)

    @property
    def transcript_path(self) -> Path:
        return self.transcript.path


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ------------------------------------------------------------------- ambient activation ---
_active: ScopedSession | None = None


def activate(scope: Scope, slug: str, identity: str = "anon", primitive: str = "") -> ScopedSession:
    """Install the process-wide scoped session that the `http` facade delegates to."""
    global _active
    _active = ScopedSession(scope, slug, identity=identity, primitive=primitive)
    return _active


def deactivate() -> None:
    global _active
    _active = None


def active() -> ScopedSession | None:
    return _active


def _bootstrap_from_env() -> None:
    """Pick up an ambient scope from the environment. hunt.py runs authz_diff.py and fuzz.py as
    subprocesses, so the guard has to survive a process boundary without rewiring their argparse.

    Fail closed: HUNT_SCOPE_FILE set but unreadable must make every request raise, never fall
    through to unguarded requests."""
    f = os.environ.get("HUNT_SCOPE_FILE")
    if not f:
        return
    slug = os.environ.get("HUNT_SLUG") or "url-target"
    identity = os.environ.get("HUNT_IDENTITY") or "anon"
    try:
        activate(Scope.load(f), slug, identity=identity,
                 primitive=os.environ.get("HUNT_PRIMITIVE", ""))
    except (ScopeError, OSError) as e:
        global _broken
        _broken = f"HUNT_SCOPE_FILE={f} could not be loaded: {e}"


_broken: str = ""
_bootstrap_from_env()


# ------------------------------------------------------------------------ http facade ---
class _HttpFacade:
    """Mirrors the slice of the `requests` API the pipeline uses.

    Scope active   -> guarded, rate-limited, transcribed.
    No scope       -> real `requests`, unchanged. This is what keeps every local-target flow
                      (work/_selftest, hunt sweep, all existing skills) byte-identical.
    """

    # re-exported so `except requests.RequestException` keeps working after the import swap
    RequestException = _requests.RequestException
    Timeout = _requests.Timeout
    ConnectionError = _requests.ConnectionError
    HTTPError = _requests.HTTPError
    TooManyRedirects = _requests.TooManyRedirects
    exceptions = _requests.exceptions
    Session = _requests.Session
    compat = _requests.compat

    def _target(self):
        if _broken:
            raise ScopeViolation(_broken, rule="HUNT_SCOPE_FILE")
        return _active or _requests

    def request(self, method, url, **kw):
        return self._target().request(method, url, **kw)

    def get(self, url, **kw):
        return self._target().get(url, **kw)

    def post(self, url, **kw):
        return self._target().post(url, **kw)

    def put(self, url, **kw):
        return self._target().put(url, **kw)

    def patch(self, url, **kw):
        return self._target().patch(url, **kw)

    def delete(self, url, **kw):
        return self._target().delete(url, **kw)

    def head(self, url, **kw):
        return self._target().head(url, **kw)

    def options(self, url, **kw):
        return self._target().options(url, **kw)


http = _HttpFacade()


# -------------------------------------------------------------------------- self-test ---
_SELFTEST_SCOPE = {
    "schema": 1,
    "program": {"name": "selftest", "url": "https://example.com/program",
                "policy_sha256": "0" * 64, "authorized_by": "pipeline self-test"},
    "in_scope": {"schemes": ["https"], "hosts": ["app.example.com", ".api.example.com"],
                 "ports": [443], "paths": ["^/api/", "^/app/"], "allow_private": False},
    "out_of_scope": {"hosts": ["blog.example.com"], "paths": ["^/api/v1/payments/"]},
    "methods": {"allow": ["GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"], "deny": ["DELETE"]},
    "safety": {"destructive_paths": ["(?i)/(delete|purge|deactivate)"]},
}

# (method, url, expected_allowed, what it proves)
_SELFTEST_CASES = [
    ("GET", "https://app.example.com/api/items/1", True, "exact in-scope host + path"),
    ("GET", "https://v2.api.example.com/api/x", True, "leading-dot wildcard matches a subdomain"),
    ("GET", "https://api.example.com/api/x", True, "leading-dot wildcard matches the apex too"),
    ("GET", "https://blog.example.com/api/x", False, "out_of_scope host beats in_scope"),
    ("GET", "https://evil.example.org/api/x", False, "unlisted host refused"),
    ("GET", "https://app.example.com/internal/x", False, "path outside in_scope.paths"),
    ("GET", "https://app.example.com/api/v1/payments/9", False, "out_of_scope path"),
    ("DELETE", "https://app.example.com/api/items/1", False, "denied method"),
    ("POST", "https://app.example.com/api/items/delete", False, "destructive verb x path"),
    ("GET", "https://app.example.com/api/items/delete", True, "reading a scary path is fine"),
    ("GET", "http://app.example.com/api/x", False, "scheme not in in_scope.schemes"),
    ("GET", "https://app.example.com:8443/api/x", False, "port not in in_scope.ports"),
    ("GET", "/api/relative", False, "relative URL is not an authorized absolute target"),
]


def selftest() -> int:
    sc = Scope(raw=_SELFTEST_SCOPE, path=None, _digest="selftest")
    sc._validate()
    failed = 0
    print("scope selftest (pure decisions, no network):")
    for method, url, want, why in _SELFTEST_CASES:
        got = sc.explain(method, url)
        ok = got["allowed"] == want
        failed += not ok
        verdict = "ALLOW" if got["allowed"] else "REFUSE"
        print(f"  [{'x' if ok else ' '}] {verdict:6} {method:7} {url}")
        print(f"        {why}" + ("" if got["allowed"] else f" -> {got['reason']}"))
    # the rate limiter actually limits
    b = _TokenBucket(rps=10, burst=1)
    b.acquire()
    t0 = time.monotonic()
    b.acquire()
    dt = time.monotonic() - t0
    ok = dt >= 0.05
    failed += not ok
    print(f"  [{'x' if ok else ' '}] token bucket throttled the 2nd call by {dt * 1000:.0f}ms")
    print(f"\n{len(_SELFTEST_CASES) + 1 - failed}/{len(_SELFTEST_CASES) + 1} passed")
    return 1 if failed else 0


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="scope", description="scope-file lint / decision check")
    ap.add_argument("--file", help="scope.yml")
    ap.add_argument("--check", help="URL to test against the scope")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--lint", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)

    if a.selftest and not a.file:
        return selftest()
    if not a.file:
        ap.error("--file is required (or use --selftest)")
    try:
        sc = Scope.load(a.file)
    except ScopeError as e:
        print(f"scope error: {e}", file=sys.stderr)
        return 2

    if a.selftest:
        return selftest()

    if a.lint or not a.check:
        print(f"scope: {a.file}")
        print(f"  digest   : {sc.digest()}")
        print(f"  program  : {sc.program.get('name', '?')} — {sc.program.get('url', 'no url')}")
        print(f"  hosts    : {(sc.raw.get('in_scope') or {}).get('hosts')}")
        print(f"  limits   : {sc.limits}")
        print(f"  methods  : {sc.methods}")
        warn = sc.lint()
        if warn:
            print("\nadvisory:")
            for w in warn:
                print(f"  ! {w}")
        else:
            print("\nno advisories.")
        if not a.check:
            return 0

    got = sc.explain(a.method, a.check)
    if got["allowed"]:
        print(f"ALLOW  {a.method} {a.check}")
        return 0
    print(f"REFUSE {a.method} {a.check}\n  {got['reason']}  (rule: {got['rule']})", file=sys.stderr)
    return EXIT_SCOPE_REFUSAL


if __name__ == "__main__":
    sys.exit(main())
