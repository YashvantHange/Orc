#!/usr/bin/env python3
"""
An external tool proxied through the gate must draw on the SAME concurrency slot as everything else.

This is the half of the shared-limiter fix that was missed the first time, and it is the half
limits.py's own docstring is about: the moment an external tool sends through a mitmdump child there
are two processes. rps and max_requests were already shared through work/<slug>/web/limits.json. The
concurrency SLOT was not - so sqlmap and ffuf, both threaded by default, were rate-limited and
budget-limited while opening as many simultaneous connections as they liked.

mitmproxy hands control back between its request and response hooks, so the gate cannot hold a `with`
block across one exchange. It takes the slot explicitly and must release it on BOTH the response and
the error hook. MAX_EXTENSIONS is the backstop for the case where neither fires - without it, a
leaked lease inside a still-live process would be extended forever by the pid-liveness check and pin
the slot for the whole run.
"""
from __future__ import annotations

import json
import os
import sys
import time
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dynamic"))

import limits as L  # noqa: E402
import mitm_gate as MG  # noqa: E402
import scope as S  # noqa: E402

SCOPE_YML = """
schema: 1
program: {name: selfcheck, authorized_by: self}
in_scope: {schemes: [http, https], hosts: [example.test], allow_private: false}
limits: {rps: 1000, burst: 1000, concurrency: 1, max_requests: 500, timeout_s: 15, max_redirects: 3}
"""


def fake_flow(method="GET", url="http://example.test/a"):
    req = types.SimpleNamespace(method=method, pretty_url=url, headers={}, content=b"")
    return types.SimpleNamespace(metadata={}, request=req, response=None, error=None)


@pytest.fixture
def gate(tmp_path, monkeypatch):
    (tmp_path / "scope.yml").write_text(SCOPE_YML, encoding="utf-8")
    monkeypatch.setenv("HUNT_SCOPE_FILE", str(tmp_path / "scope.yml"))
    monkeypatch.setenv("HUNT_SLUG", "selfcheck")
    monkeypatch.setattr(MG, "_workdir", lambda slug: tmp_path)
    g = MG.ScopeGate()
    assert not g.broken, g.broken
    return g, tmp_path


def leases(tmp_path) -> dict:
    p = tmp_path / "web" / "limits.json"
    return json.loads(p.read_text(encoding="utf-8")).get("leases", {}) if p.exists() else {}


# ================================================ the slot is taken and given back ===
def test_the_proxy_takes_a_slot_for_the_duration_of_the_exchange(gate):
    g, tmp = gate
    flow = fake_flow()
    g.request(flow)
    assert flow.metadata.get("hunt_lease"), "the proxy sent a request without taking a slot"
    assert len(leases(tmp)) == 1, "the slot was not recorded in the shared file"

    flow.response = types.SimpleNamespace(status_code=200, headers={}, content=b"ok")
    g.response(flow)
    assert leases(tmp) == {}, "the slot was never released on the response hook"


def test_the_slot_is_released_when_the_flow_errors(gate):
    """Without this a failed connection pins a slot until MAX_EXTENSIONS finally expires it."""
    g, tmp = gate
    flow = fake_flow()
    g.request(flow)
    assert len(leases(tmp)) == 1
    flow.error = "connection refused"
    g.error(flow)
    assert leases(tmp) == {}, "an errored flow kept its slot"


def test_a_refused_request_never_takes_a_slot(gate):
    # The refusal path builds a real mitmproxy response object, so this one needs the package.
    pytest.importorskip("mitmproxy", reason="the gate's refusal path constructs a mitmproxy response")
    g, tmp = gate
    flow = fake_flow(url="http://not-in-scope.test/a")
    g.request(flow)
    assert not flow.metadata.get("hunt_lease")
    assert leases(tmp) == {}, "a refused request consumed concurrency it never used"


def test_the_gate_and_the_in_house_path_share_one_ceiling(gate):
    """The whole point: concurrency 1 means ONE in flight, whichever door it comes through."""
    g, tmp = gate
    flow = fake_flow()
    g.request(flow)                                  # proxy holds the only slot

    sc = S.Scope.load(tmp / "scope.yml")
    sc.attach_shared(tmp / "web" / "limits.json")
    tok = None
    try:
        # The in-house path must NOT be admitted while the proxy holds it.
        import threading
        got = threading.Event()

        def contend():
            nonlocal tok
            tok = sc.acquire_slot()
            got.set()

        t = threading.Thread(target=contend, daemon=True)
        t.start()
        assert not got.wait(timeout=2.0), (
            "the in-house path was admitted while the proxy held the only slot - the two doors are "
            "still drawing on separate ceilings")

        flow.response = types.SimpleNamespace(status_code=200, headers={}, content=b"ok")
        g.response(flow)
        assert got.wait(timeout=30), "the slot was not handed over after the proxy released it"
    finally:
        if tok:
            sc.release_slot(tok)


# ===================================================== the leak backstop is bounded ===
def test_a_live_holder_that_never_releases_is_eventually_reclaimed(tmp_path):
    """pid-liveness stops a slow request being stolen; MAX_EXTENSIONS stops that becoming forever.

    A hook-driven caller that reaches neither of its release paths would otherwise hold a slot for
    the entire run, because its process is alive and every reap would extend it.
    """
    path = tmp_path / "limits.json"
    lim = L.SharedLimiter(path, rps=1000.0, burst=1000, max_requests=10 ** 6,
                          concurrency=1, lease_ttl=1.0)   # 1.0 is the enforced floor
    lim.acquire_lease()                      # taken and deliberately never released
    assert len(json.loads(path.read_text(encoding="utf-8"))["leases"]) == 1

    start = time.time()
    tok = lim.acquire_lease()                # must eventually win the slot back
    assert tok
    assert time.time() - start < 30, "the leaked slot was never reclaimed"

    st = json.loads(path.read_text(encoding="utf-8"))
    assert len(st["leases"]) == 1, "the leaked lease survived alongside the new one"


def test_extensions_are_counted_so_the_backstop_can_fire(tmp_path):
    path = tmp_path / "limits.json"
    lim = L.SharedLimiter(path, rps=1000.0, burst=1000, max_requests=10 ** 6,
                          concurrency=2, lease_ttl=1.0)   # 1.0 is the enforced floor
    lim.acquire_lease()
    time.sleep(1.2)
    with lim.lease():                        # this reap extends the stale one rather than killing it
        pass
    rec = next(iter(json.loads(path.read_text(encoding="utf-8"))["leases"].values()))
    assert rec["renewals"] >= 1, "a live holder's extension was not counted, so it can never expire"
    assert L.MAX_EXTENSIONS > 0


def test_releasing_an_unknown_or_empty_token_is_harmless(tmp_path):
    lim = L.SharedLimiter(tmp_path / "limits.json", rps=1000.0, burst=1000, max_requests=100,
                          concurrency=1)
    lim.release_lease("")
    lim.release_lease("never-existed")       # must not raise, must not corrupt state
    with lim.lease():
        pass
