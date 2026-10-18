#!/usr/bin/env python3
"""
limits.py — one rate budget and one request budget per target, shared across processes.

WHY THIS EXISTS (it is a bug fix, not a refactor):

`scope._TokenBucket` keeps its tokens in a float behind a threading.Lock, and `Scope._sent` is an
in-memory int. Both are per-process. That was correct while every request came from one Python
process. The moment an external tool sends through a mitmdump child, there are two processes, two
buckets and — the part that matters — TWO INDEPENDENT max_requests BUDGETS. A scope authorizing 500
requests would silently permit 1000, and a bug-bounty program's stated rate limit would be doubled
without anyone seeing it happen. Python object state does not cross a process boundary.

So the counters move to a file that every participating process locks, mutates and releases:

    work/<slug>/web/limits.json     next to the transcript, same lifetime, readable after a run

TIME IS THE SUBTLE PART. time.monotonic() is only comparable within one process — its zero point is
arbitrary and differs per process. A shared bucket must therefore refill against the wall clock
(time.time()), which can step backwards under NTP; `_refill` clamps a negative delta to zero so a
clock adjustment can never mint tokens.

Loopback targets we launched ourselves keep the cheap in-memory path: there is no program policy to
honour and no budget worth protecting, so `Scope.local()` does not pay for file locking per request.
"""
from __future__ import annotations

import contextlib
import json
import os
import secrets
import socket
import threading
import time
from pathlib import Path

if os.name == "nt":
    import msvcrt
else:
    import fcntl


def _pid_alive(pid: int) -> bool:
    """Is the process that took a lease still running?

    A lease TTL alone cannot be trusted as proof the holder is gone: requests' `timeout` is per-read,
    not total, so a slow-drip response legitimately outlives any fixed TTL. Reclaiming such a lease
    would hand its concurrency slot to a second process while the first is still on the wire - the
    exact over-concurrency this file exists to prevent. So expiry only ARMS a reclaim; liveness
    decides it.

    Unknown (a pid we cannot query, or a lease from another host) is treated as ALIVE, because the
    cost of a wrongly-held slot is a slower hunt and the cost of a wrongly-freed one is exceeding a
    program's authorized concurrency.
    """
    if pid <= 0:
        return True
    try:
        if os.name == "nt":
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION, STILL_ACTIVE = 0x1000, 259
            k32 = ctypes.windll.kernel32
            h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
            if not h:
                return False          # no such process (or no rights to it) - treat as gone
            try:
                code = ctypes.c_ulong()
                if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
                    return True       # could not tell - assume alive
                return code.value == STILL_ACTIVE
            finally:
                k32.CloseHandle(h)
        os.kill(int(pid), 0)
        return True
    except PermissionError:
        return True                   # exists, owned by someone else
    except (OSError, ValueError, AttributeError):
        return False


# A live holder gets its window extended rather than stolen (see _pid_alive), but not forever: a
# hook-driven caller that never reaches its release path would otherwise hold a slot permanently.
#
# This is a DEFAULT, not a law, because the two things that take leases have very different natural
# durations. An HTTP lease covers one exchange - seconds - so ten extensions of a 60s window is an
# enormous margin. An AGENT slot (tools/fleet.py) is held for a member's entire run, which is
# minutes to hours, and the same numbers would reclaim a slot from a member that is still working.
# Per-instance, so each caller sets a backstop that matches what it is actually holding.
MAX_EXTENSIONS = 10


class BudgetExhausted(Exception):
    """The scope's max_requests is spent.

    Raised rather than returned so it cannot be ignored by a caller that forgot to check. scope.py
    translates it into a ScopeViolation, keeping ScopeViolation the single exception the rest of the
    pipeline has to know about.
    """

    def __init__(self, sent: int, budget: int):
        self.sent, self.budget = sent, budget
        super().__init__(f"request budget exhausted ({sent}/{budget})")


class _FileLock:
    """Exclusive lock over the state file, on a separate .lock path.

    Locking a sidecar rather than the state file itself means the writer can freely truncate and
    rewrite the state without touching the locked byte range — on Windows, msvcrt locks byte ranges
    of a specific handle, and rewriting the file underneath one is asking for trouble.
    """

    def __init__(self, path: Path):
        self.path = Path(str(path) + ".lock")
        self._fh = None
        # A file lock separates PROCESSES and nothing else. Two threads here would each open their
        # own handle - msvcrt locks per handle, and fcntl.flock per open file description - so both
        # would be admitted, and worse, they would stomp self._fh on the way out. That was latent
        # while only one thread per process ever took the lock; lease() is called from many.
        self._tlock = threading.Lock()

    def __enter__(self):
        self._tlock.acquire()
        try:
            return self._enter()
        except BaseException:
            self._tlock.release()
            raise

    def _enter(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a+b")
        if os.name == "nt":
            # msvcrt has no blocking-with-wait mode that survives contention politely; retry.
            deadline = time.time() + 10.0
            while True:
                try:
                    self._fh.seek(0)
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    if time.time() > deadline:
                        raise
                    time.sleep(0.01)
        else:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        try:
            try:
                if os.name == "nt":
                    self._fh.seek(0)
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            finally:
                self._fh.close()
                self._fh = None
        finally:
            self._tlock.release()
        return False


class SharedLimiter:
    """A token bucket and a request budget that several processes share honestly.

    Every process testing one target constructs one of these against the same path. The file is the
    authority; the object holds no counter state of its own, because any state it held would be the
    bug this class exists to fix.
    """

    def __init__(self, path: str | Path, rps: float, burst: int, max_requests: int,
                 concurrency: int = 1, lease_ttl: float = 60.0,
                 max_extensions: int = MAX_EXTENSIONS):
        self.path = Path(path)
        self.rps = max(float(rps), 0.01)
        self.capacity = max(int(burst), 1)
        self.max_requests = int(max_requests)
        self.concurrency = max(int(concurrency), 1)
        self.lease_ttl = max(float(lease_ttl), 1.0)
        self.max_extensions = max(int(max_extensions), 0)
        self._host = socket.gethostname()
        self._lock = _FileLock(self.path)

    # ----------------------------------------------------------------------- state io ---
    def _read(self) -> dict:
        """Read the shared state.

        FAILURE POLICY IS SPLIT BY FIELD, deliberately.

        Rate and budget fail OPEN on a corrupt file, unchanged: the budget is what actually bounds a
        run, and a corrupt file must not wedge a hunt.

        The lease map cannot use that policy. Failing open there means every process reads
        `leases = {}`, concludes it has capacity, and 30 agents go to the wire at once - which
        defeats the entire mechanism rather than merely degrading it. Failing CLOSED is no better:
        it wedges the hunt, the thing fail-open exists to prevent. So a lost lease map degrades to
        `concurrency = 1` and sets `degraded`, which is serial and loud: the run continues, the
        board says LIMITER_DEGRADED, and `hunt swarm plan` refuses to size a swarm until someone
        clears it deliberately.
        """
        blank = {"tokens": float(self.capacity), "last": time.time(), "sent": 0,
                 "leases": {}, "degraded": False}
        try:
            st = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(st, dict):
                raise ValueError
        except FileNotFoundError:
            return blank                      # a fresh run is not a degraded one
        except (OSError, ValueError, json.JSONDecodeError):
            blank["degraded"] = True          # we HAD state and lost it - the lease map is unknown
            return blank
        st.setdefault("tokens", float(self.capacity))
        st.setdefault("last", time.time())
        st.setdefault("sent", 0)
        st.setdefault("degraded", False)
        leases = st.get("leases")
        if not isinstance(leases, dict):
            st["leases"], st["degraded"] = {}, True
        return st

    def _write(self, st: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(st), encoding="utf-8")

    def _refill(self, st: dict, now: float) -> None:
        # Wall clock can step backwards (NTP). A negative delta must mint nothing.
        elapsed = max(0.0, now - float(st["last"]))
        st["tokens"] = min(float(self.capacity), float(st["tokens"]) + elapsed * self.rps)
        st["last"] = now

    # --------------------------------------------------------------------------- api ---
    def acquire(self) -> float:
        """Consume one token and one unit of budget. Returns seconds waited.

        Blocks on rate; raises BudgetExhausted on budget. The sleep happens OUTSIDE the lock — a
        process that slept while holding it would serialize every other process behind its own rate
        limit and turn a 2 rps scope into 2 rps shared by nobody.
        """
        waited = 0.0
        while True:
            with self._lock:
                st = self._read()

                if self.max_requests and st["sent"] >= self.max_requests:
                    raise BudgetExhausted(st["sent"], self.max_requests)

                now = time.time()
                self._refill(st, now)

                if st["tokens"] >= 1.0:
                    st["tokens"] -= 1.0
                    st["sent"] = int(st["sent"]) + 1
                    self._write(st)
                    return waited

                need = (1.0 - float(st["tokens"])) / self.rps
                self._write(st)          # persist the refill so the wait isn't recomputed from stale
            time.sleep(need)
            waited += need

    # ---------------------------------------------------------------- concurrency ---
    def _reap(self, st: dict, now: float) -> bool:
        """Drop leases whose holder is gone. Returns True if anything changed.

        Expiry ARMS a reclaim; it never completes one on its own. A holder that is still alive gets
        its window extended instead, because the only way a live process holds a lease past the TTL
        is a slow response - and stealing its slot would put two requests on the wire against a
        program that authorized one.
        """
        changed, dead = False, []
        for tok, rec in list(st["leases"].items()):
            if not isinstance(rec, dict):
                dead.append(tok)
                continue
            try:
                expiry = float(rec.get("expiry") or 0.0)
            except (TypeError, ValueError):
                dead.append(tok)
                continue
            if now < expiry:
                continue
            host = rec.get("host")
            if host and host != self._host:
                dead.append(tok)          # another machine: TTL is the only signal we have
                continue
            try:
                pid = int(rec.get("pid") or 0)
            except (TypeError, ValueError):
                pid = 0
            if _pid_alive(pid) and int(rec.get("renewals") or 0) < self.max_extensions:
                rec["expiry"] = now + self.lease_ttl
                rec["renewals"] = int(rec.get("renewals") or 0) + 1
                changed = True
                continue
            # Either the holder is gone, or it is alive and has held one slot for
            # max_extensions * lease_ttl without finishing. The second case is a leak, not a slow
            # request: no single exchange on these programs runs that long, and a live process
            # that never reaches its release path would otherwise pin the slot for the whole run.
            dead.append(tok)
        for tok in dead:
            st["leases"].pop(tok, None)
            changed = True
        return changed

    def effective_concurrency(self, st: dict | None = None) -> int:
        """The cap actually in force. A degraded limiter serialises rather than guessing."""
        if st is None:
            with self._lock:
                st = self._read()
        return 1 if st.get("degraded") else self.concurrency

    def degraded(self) -> bool:
        with self._lock:
            return bool(self._read().get("degraded"))

    def acquire_lease(self) -> str:
        """Take a slot and return its token. Prefer lease(); this is for hook-driven callers.

        mitmproxy hands control back between its request and response hooks, so the proxy gate
        cannot hold a `with` block across one exchange. It must release explicitly on BOTH the
        response and the error hook - and max_extensions is the backstop for when neither fires.
        """
        token = secrets.token_hex(8)
        while True:
            with self._lock:
                st = self._read()
                now = time.time()
                changed = self._reap(st, now)
                if len(st["leases"]) < self.effective_concurrency(st):
                    st["leases"][token] = {"expiry": now + self.lease_ttl, "renewals": 0,
                                           "pid": os.getpid(), "host": self._host}
                    self._write(st)
                    return token
                soonest = min((float(r.get("expiry") or 0.0)
                               for r in st["leases"].values() if isinstance(r, dict)), default=now)
                if changed:
                    self._write(st)       # persist extensions so they are not recomputed from stale
            # Poll at least once a second: a holder can die at any moment, and only _reap notices.
            time.sleep(min(max(soonest - now, 0.05), 1.0))

    def release_lease(self, token: str) -> None:
        if not token:
            return
        with self._lock:
            st = self._read()
            if st["leases"].pop(token, None) is not None:
                self._write(st)

    @contextlib.contextmanager
    def lease(self):
        """Hold one of the target's concurrency slots for the duration of one request.

        Shares the file with every other process testing this target, so N agent processes draw down
        ONE ceiling instead of N. The sleep is outside the lock for the same reason acquire()'s is:
        a process waiting for a slot while holding the file lock would serialise everyone behind it.
        """
        token = self.acquire_lease()
        try:
            yield token
        finally:
            self.release_lease(token)

    def recover(self) -> dict:
        """Clear a degraded lease map. Budget and rate are deliberately left alone.

        Resetting `sent` here would turn recovery into a way past a budget refusal, which is exactly
        what reset()'s docstring forbids. This clears only what was lost.
        """
        with self._lock:
            st = self._read()
            st["leases"], st["degraded"] = {}, False
            self._write(st)
            return {"sent": int(st["sent"]), "concurrency": self.concurrency}

    def spent(self) -> int:
        with self._lock:
            return int(self._read()["sent"])

    def remaining(self) -> int:
        if not self.max_requests:
            return -1
        return max(0, self.max_requests - self.spent())

    def reset(self) -> None:
        """Start a fresh budget. Only for a new engagement or a test — never to get past a refusal."""
        with self._lock:
            self._write({"tokens": float(self.capacity), "last": time.time(), "sent": 0,
                         "leases": {}, "degraded": False})
