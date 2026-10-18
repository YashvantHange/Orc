#!/usr/bin/env python3
"""
Concurrency is a shared limit or it is not a limit.

rps, burst and max_requests already moved into work/<slug>/web/limits.json because per-process
counters silently doubled a program's authorized budget. `concurrency` was left behind as a
threading.Semaphore on the in-process Scope object - harmless while one process sent every request,
and an authorization defect the moment a swarm runs N agent processes: each gets its own semaphore,
so a scope authorizing 2 in flight permits 2*N.

Every test here is written to prove the NEGATIVE case fires, because the failure mode of a limiter
is looking correct while being structurally unable to refuse.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dynamic"))

import limits as L  # noqa: E402


def mk(tmp_path, concurrency=2, rps=1000.0, burst=1000, budget=100000, ttl=60.0):
    return L.SharedLimiter(tmp_path / "limits.json", rps=rps, burst=burst,
                           max_requests=budget, concurrency=concurrency, lease_ttl=ttl)


def state(tmp_path) -> dict:
    return json.loads((tmp_path / "limits.json").read_text(encoding="utf-8"))


def hammer(lim, n, hold=0.05):
    """Run n concurrent leaseholders; return the highest number ever live at once."""
    live, peak, guard = 0, 0, threading.Lock()

    def worker():
        nonlocal live, peak
        with lim.lease():
            with guard:
                live += 1
                peak = max(peak, live)
            time.sleep(hold)
            with guard:
                live -= 1

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    return peak


# ======================================================== the ceiling actually holds ===
@pytest.mark.parametrize("cap", [1, 2, 3])
def test_never_more_than_cap_in_flight(tmp_path, cap):
    """`peak <= cap` is the safety property; `peak == cap` only proves the test contended.

    The second one is load-sensitive: on a busy machine the threads can finish without ever
    overlapping, which fails the test for a reason that says nothing about the ceiling. So the
    safety property is asserted on every attempt and never retried, while the did-it-contend check
    gets a few tries with a longer hold.
    """
    lim = mk(tmp_path, concurrency=cap)
    peak = 0
    for attempt in range(4):
        peak = max(peak, hammer(lim, cap * 4, hold=0.1 * (attempt + 1)))
        assert peak <= cap, f"{peak} leases were live at once against a ceiling of {cap}"
        if peak == cap:
            return
    pytest.fail(f"peak was {peak}, never reached the ceiling of {cap} in 4 attempts - the test "
                f"never contended, so it proves nothing either way")


def test_the_ceiling_can_be_exceeded_without_the_shared_lease():
    """Negative control: prove the per-process semaphore is what the fix replaces.

    Two independent Semaphore(2) objects - what two agent processes used to get - admit 4 at once.
    If this ever stops being true, the test above is no longer measuring anything.
    """
    a, b = threading.Semaphore(2), threading.Semaphore(2)
    assert all(s.acquire(blocking=False) for s in (a, a, b, b)), \
        "two per-process semaphores did not admit 2*N - the premise of the fix is wrong"


# ============================================== expiry arms a reclaim, liveness decides ===
def test_expired_lease_of_a_live_holder_is_not_stolen(tmp_path):
    """requests' timeout is per-read, not total, so a slow response outlives any fixed TTL.

    Reclaiming it would put two requests on the wire against a program that authorized one.
    """
    lim = mk(tmp_path, concurrency=1, ttl=1.0)
    admitted = threading.Event()

    def contender():
        with lim.lease():
            admitted.set()

    with lim.lease():
        time.sleep(1.3)                      # past the TTL; holder (this process) still alive
        assert len(state(tmp_path)["leases"]) == 1
        t = threading.Thread(target=contender, daemon=True)
        t.start()
        assert not admitted.wait(timeout=2.0), "an expired-but-live lease was stolen"
    t.join(timeout=30)
    assert admitted.is_set(), "the slot was never released after the holder finished"


def test_expired_lease_of_a_dead_holder_is_reclaimed(tmp_path):
    lim = mk(tmp_path, concurrency=1, ttl=0.2)
    gone = subprocess.Popen([sys.executable, "-c", "pass"])         # exits immediately
    gone.wait(timeout=30)
    dead_pid = gone.pid
    (tmp_path / "limits.json").write_text(json.dumps({
        "tokens": 1000.0, "last": time.time(), "sent": 5, "degraded": False,
        "leases": {"stale": {"expiry": time.time() - 10, "pid": dead_pid,
                             "host": lim._host}}}), encoding="utf-8")

    start = time.time()
    with lim.lease():
        pass
    assert time.time() - start < 15, "a dead holder's slot was never reclaimed"
    assert state(tmp_path)["sent"] == 5, "reclaiming a lease must not touch the budget"


def test_a_lease_from_another_host_falls_back_to_ttl(tmp_path):
    lim = mk(tmp_path, concurrency=1, ttl=0.2)
    (tmp_path / "limits.json").write_text(json.dumps({
        "tokens": 1000.0, "last": time.time(), "sent": 0, "degraded": False,
        "leases": {"elsewhere": {"expiry": time.time() - 5, "pid": os.getpid(),
                                 "host": "some-other-box"}}}), encoding="utf-8")
    with lim.lease():
        pass      # must not hang: our pid is alive, but that lease is not ours to keep


# ================================================ a lost lease map degrades, loudly ===
def test_corrupt_state_degrades_to_serial_rather_than_unlimited(tmp_path):
    (tmp_path / "limits.json").write_text("{not json at all", encoding="utf-8")
    lim = mk(tmp_path, concurrency=8)
    assert lim.degraded() is True
    assert lim.effective_concurrency() == 1, (
        "a lost lease map must serialise; failing open here lets every process believe it has "
        "capacity, which is worse than having no limiter at all")


def test_corrupt_leases_key_alone_degrades(tmp_path):
    (tmp_path / "limits.json").write_text(json.dumps({
        "tokens": 3.0, "last": time.time(), "sent": 42, "leases": "not-a-map"}), encoding="utf-8")
    lim = mk(tmp_path, concurrency=8)
    assert lim.degraded() is True
    assert lim.spent() == 42, "budget accounting must survive a lost lease map"


def test_a_missing_file_is_not_degraded(tmp_path):
    """A fresh run has no state yet. Calling that degraded would refuse every new hunt."""
    assert mk(tmp_path, concurrency=4).degraded() is False


def test_degraded_ceiling_is_enforced_not_just_reported(tmp_path):
    (tmp_path / "limits.json").write_text("garbage", encoding="utf-8")
    assert hammer(mk(tmp_path, concurrency=8), 4) == 1, \
        "a degraded limiter must serialise, not merely announce itself"


def test_recover_clears_degraded_but_never_the_budget(tmp_path):
    (tmp_path / "limits.json").write_text(json.dumps({
        "tokens": 1.0, "last": time.time(), "sent": 77, "leases": 5}), encoding="utf-8")
    lim = mk(tmp_path, concurrency=4)
    assert lim.degraded() is True
    lim.recover()
    assert lim.degraded() is False
    assert lim.effective_concurrency() == 4
    assert lim.spent() == 77, (
        "recover() must not reset the budget - that would make it a way past a refusal, which is "
        "exactly what reset()'s docstring forbids")


# ============================================================= the cross-process claim ===
CHILD = """
import json, sys, time
sys.path.insert(0, {dyn!r})
import limits as L
lim = L.SharedLimiter({path!r}, rps=1000.0, burst=1000, max_requests=100000,
                      concurrency={cap}, lease_ttl=60.0)
with lim.lease():
    time.sleep({hold})
"""


def test_two_processes_share_one_ceiling(tmp_path):
    """The defect this file exists for: two processes, two semaphores, twice the concurrency."""
    path = tmp_path / "limits.json"
    src = CHILD.format(dyn=str(ROOT / "dynamic"), path=str(path), cap=1, hold=2.0)
    def wait_for_leases(n, deadline=30.0):
        """Poll rather than sleep a fixed interval.

        A fixed sleep is a race on a loaded machine: the child had not yet written the state file,
        so the read raised FileNotFoundError and the test failed for reasons that had nothing to do
        with the ceiling it exists to measure.
        """
        end = time.time() + deadline
        while time.time() < end:
            try:
                if len(state(tmp_path)["leases"]) >= n:
                    return True
            except (OSError, ValueError):
                pass
            time.sleep(0.05)
        return False

    a = subprocess.Popen([sys.executable, "-c", src])
    assert wait_for_leases(1), "child A never took the only slot"

    b = subprocess.Popen([sys.executable, "-c", src])
    time.sleep(1.0)                                   # give B a chance to wrongly take a second
    held = len(state(tmp_path)["leases"])
    for p in (a, b):
        p.wait(timeout=60)
    assert held == 1, (
        f"{held} leases held across 2 processes against concurrency 1 - the ceiling is still "
        f"per-process")


# ============================== the backstop must fit what is being held ===
def test_max_extensions_is_per_instance_not_global(tmp_path):
    """An HTTP lease covers one exchange; an agent slot covers a member's whole run.

    One module constant cannot serve both: the value that is a huge margin for a 60s HTTP lease
    reclaims a slot from an agent that is still working. So it is a default, not a law.
    """
    quick = L.SharedLimiter(tmp_path / "a.json", rps=1000.0, burst=1000, max_requests=0,
                            concurrency=1, lease_ttl=1.0, max_extensions=0)
    patient = L.SharedLimiter(tmp_path / "b.json", rps=1000.0, burst=1000, max_requests=0,
                              concurrency=1, lease_ttl=1.0, max_extensions=50)
    assert quick.max_extensions == 0 and patient.max_extensions == 50
    assert L.SharedLimiter(tmp_path / "c.json", rps=1.0, burst=1,
                           max_requests=0).max_extensions == L.MAX_EXTENSIONS


def test_a_zero_extension_limiter_reclaims_on_the_first_expiry(tmp_path):
    """max_extensions=0 means expiry alone decides - the pre-liveness behaviour, on demand."""
    path = tmp_path / "limits.json"
    lim = L.SharedLimiter(path, rps=1000.0, burst=1000, max_requests=0, concurrency=1,
                          lease_ttl=1.0, max_extensions=0)
    lim.acquire_lease()                       # never released, this process stays alive
    time.sleep(1.2)
    start = time.time()
    assert lim.acquire_lease()
    assert time.time() - start < 5, "a zero-extension lease was still being extended"


def test_a_generous_extension_limiter_protects_a_long_holder(tmp_path):
    """The fleet case: a member working for minutes must not have its slot taken."""
    path = tmp_path / "limits.json"
    lim = L.SharedLimiter(path, rps=1000.0, burst=1000, max_requests=0, concurrency=1,
                          lease_ttl=1.0, max_extensions=50)
    lim.acquire_lease()
    time.sleep(1.2)

    admitted = threading.Event()

    def contender():
        lim.acquire_lease()
        admitted.set()

    threading.Thread(target=contender, daemon=True).start()
    assert not admitted.wait(timeout=3.0), (
        "a long-running holder lost its slot despite a generous extension budget")


# ================= a scope FILE means shared accounting, loopback or not ===
LOOPBACK_SCOPE = """
schema: 1
program: {name: selftest, authorized_by: self-hosted fixture}
in_scope: {schemes: [http], hosts: ["127.0.0.1", "localhost"], allow_private: true}
limits: {rps: 200, burst: 200, concurrency: 4, max_requests: 20000, timeout_s: 10, max_redirects: 3}
"""
REAL_SCOPE = """
schema: 1
program: {name: acme, authorized_by: alice@acme.example}
in_scope: {schemes: [https], hosts: ["api.acme.example"], allow_private: false}
limits: {rps: 2, burst: 5, concurrency: 2, max_requests: 500, timeout_s: 15, max_redirects: 3}
"""


def _scope(tmp_path, body, name="scope.yml"):
    sys.path.insert(0, str(ROOT / "dynamic"))
    import scope as S
    (tmp_path / name).write_text(body, encoding="utf-8")
    return S.Scope.load(tmp_path / name)


def test_a_loopback_scope_file_still_shares_the_budget(tmp_path):
    """Skipping this for loopback was tried, and it broke a real guarantee.

    The shared file is not only about a third party's rate limit - it is what makes a PROXIED
    EXTERNAL TOOL's traffic accountable, and tests/test_exttool_live.py asserts that against a
    loopback target. Skipping it there made `spent()` read 0 after ffuf had sent three requests.
    limits.py's cheap-path reasoning covers Scope.local(), the implicit scope with NO file; writing
    a scope file is opting into this accounting.
    """
    sc = _scope(tmp_path, LOOPBACK_SCOPE)
    sc.attach_shared(tmp_path / "limits.json")
    assert sc._shared is not None, (
        "a loopback scope FILE skipped the shared budget - an external tool's traffic would then "
        "draw down nothing and the transcript would under-report what was sent")
    assert sc._shared.concurrency == 4


def test_a_real_program_shares_the_budget(tmp_path):
    sc = _scope(tmp_path, REAL_SCOPE)
    sc.attach_shared(tmp_path / "limits.json")
    assert sc._shared is not None
    assert sc._shared.concurrency == 2
    assert sc._shared.max_requests == 500


def test_the_implicit_local_scope_keeps_the_cheap_path(tmp_path):
    """Scope.local() has no file and no program policy, so it pays nothing - that part stands."""
    sys.path.insert(0, str(ROOT / "dynamic"))
    import scope as S
    loc = S.Scope.local()
    assert loc.path is None
    assert loc._shared is None
    assert loc.slot() is loc._sem, "the in-process semaphore is the local path's slot"
