#!/usr/bin/env python3
"""
Tests for the two shared contracts: the result state machine and the cross-process limiter.

Both were written to fix a specific defect, so each has at least one test that fails on the old
behaviour rather than merely describing the new one:

  * CLEAR used to be the fallthrough of web/sweep.py:verdict(), so a blind probe that did not fire
    was recorded as "checked, defended".
  * Rate and budget lived in per-process memory, so two processes testing one target each got a
    full max_requests.
"""
from __future__ import annotations

import multiprocessing
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dynamic"))
sys.path.insert(0, str(ROOT / "static"))

import limits as L          # noqa: E402
import verdict as V         # noqa: E402


# ============================================================ 0a. the state machine ===
def test_clear_requires_a_guard_and_an_attack():
    """The rule the whole module exists for: CLEAR is a claim about a guard, not a shrug."""
    v = V.cleared(guard="realpath() + prefix check", attack="../../etc/passwd, 6 encodings")
    assert v.state is V.State.CLEAR
    assert "realpath" in v.one_line()

    # Neither half may be omitted.
    with pytest.raises(ValueError, match="CLEAR requires"):
        V.Verdict(V.State.CLEAR, V.Evidence.RUNTIME)
    with pytest.raises(ValueError, match="CLEAR requires"):
        V.Verdict(V.State.CLEAR, V.Evidence.RUNTIME, guard="a guard")


def test_a_probe_that_does_not_fire_is_not_clear():
    """The regression this replaces. A blank result is NOT_CONFIRMED, and it renders distinctly."""
    v = V.not_confirmed("no timing differential over 5 samples")
    assert v.state is V.State.NOT_CONFIRMED
    assert v.render() == "NOT-CONFIRMED"
    assert v.render() != "CLEAR"
    # and it keeps the row open
    assert v.state.needs_followup()
    assert not v.state.is_terminal_negative()


def test_confirmed_must_say_what_proves_it():
    with pytest.raises(ValueError, match="No-Hallucination"):
        V.Verdict(V.State.CONFIRMED, V.Evidence.NONE, "trust me")

    assert V.confirmed("49 in body, 3x", V.Evidence.RUNTIME).render() == "HIT"
    assert V.confirmed("sink read, unreachable at runtime", V.Evidence.CODE).render() \
        == "code-confirmed"


def test_states_that_sent_nothing_cannot_claim_runtime_evidence():
    """BLOCKED means no request was made; claiming a recorded response contradicts that."""
    for st in (V.State.UNTESTED, V.State.N_A, V.State.BLOCKED, V.State.NEEDS_EXTERNAL_SIGNAL):
        with pytest.raises(ValueError, match="nothing was sent"):
            V.Verdict(st, V.Evidence.RUNTIME, "x")


def test_oob_three_outcomes_stay_distinct():
    """Plan verification 4b: no-channel, timeout and callback must be three different answers."""
    no_channel = V.needs_external("target cannot reach 127.0.0.1", channel=V.Evidence.OOB)
    timeout = V.not_confirmed("no callback in 30s; egress filtering not ruled out")
    hit = V.confirmed("callback carried oob-9c2f", V.Evidence.OOB)

    assert len({no_channel.state, timeout.state, hit.state}) == 3
    for v in (no_channel, timeout, hit):
        assert v.render() != "CLEAR"


def test_legacy_words_round_trip():
    """The shim must be invisible: the words the skills and run board use keep rendering."""
    for word in ("HIT", "BLOCKED", "NEEDS-BROWSER", "code-confirmed", "N/A"):
        assert V.from_legacy(word).render() == word

    # A legacy CLEAR has no recorded guard. It is admitted, but it says so rather than inventing one.
    old = V.from_legacy("CLEAR")
    assert old.state is V.State.CLEAR
    assert "not recorded" in old.guard

    with pytest.raises(ValueError, match="unknown legacy verdict"):
        V.from_legacy("PROBABLY-FINE")


# ================================================== 0b. the cross-process limiter ===
def test_budget_is_spent_not_reset(tmp_path):
    lim = L.SharedLimiter(tmp_path / "limits.json", rps=1000, burst=1000, max_requests=5)
    for _ in range(5):
        lim.acquire()
    assert lim.spent() == 5
    assert lim.remaining() == 0
    with pytest.raises(L.BudgetExhausted):
        lim.acquire()


def test_a_second_limiter_object_sees_the_same_budget(tmp_path):
    """Two objects, one file. This is the single-process shape of the cross-process bug."""
    path = tmp_path / "limits.json"
    a = L.SharedLimiter(path, rps=1000, burst=1000, max_requests=4)
    b = L.SharedLimiter(path, rps=1000, burst=1000, max_requests=4)

    a.acquire(); a.acquire()
    b.acquire(); b.acquire()

    # Four total, not four each — the assertion that fails against per-process counters.
    assert b.spent() == 4
    with pytest.raises(L.BudgetExhausted):
        b.acquire()
    with pytest.raises(L.BudgetExhausted):
        a.acquire()


def _burn(path: str, n: int, out):
    """Child process: spend up to n units and report how many it actually got."""
    sys.path.insert(0, str(ROOT / "dynamic"))
    import limits as _L
    lim = _L.SharedLimiter(path, rps=1000, burst=1000, max_requests=20)
    got = 0
    for _ in range(n):
        try:
            lim.acquire()
            got += 1
        except _L.BudgetExhausted:
            break
    out.put(got)


def test_budget_is_shared_across_processes(tmp_path):
    """Plan verification 1c, the real thing: two processes, one max_requests=20 budget.

    Against the old in-memory counters each process would happily spend 20, for 40 total.
    """
    path = str(tmp_path / "limits.json")
    q = multiprocessing.Queue()
    procs = [multiprocessing.Process(target=_burn, args=(path, 15, q)) for _ in range(2)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)

    total = sum(q.get() for _ in procs)
    assert total == 20, f"two processes spent {total} of a 20-request budget"

    lim = L.SharedLimiter(path, rps=1000, burst=1000, max_requests=20)
    assert lim.spent() == 20


def test_rate_throttles_across_objects(tmp_path):
    path = tmp_path / "limits.json"
    a = L.SharedLimiter(path, rps=10, burst=1, max_requests=0)
    b = L.SharedLimiter(path, rps=10, burst=1, max_requests=0)
    a.acquire()
    t0 = time.time()
    b.acquire()              # b must wait on the token a just took
    assert time.time() - t0 >= 0.05


def test_clock_going_backwards_mints_no_tokens(tmp_path):
    """Wall clock is shared state's only option across processes, and NTP can step it back."""
    path = tmp_path / "limits.json"
    lim = L.SharedLimiter(path, rps=10, burst=5, max_requests=0)
    lim.acquire()
    with lim._lock:
        st = lim._read()
        st["last"] = time.time() + 3600      # pretend the clock jumped forward, then came back
        before = st["tokens"]
        lim._write(st)
    with lim._lock:
        st = lim._read()
        lim._refill(st, time.time())
        assert st["tokens"] <= before + 1e-9


def test_corrupt_state_file_does_not_wedge_a_hunt(tmp_path):
    path = tmp_path / "limits.json"
    path.write_text("{not json", encoding="utf-8")
    lim = L.SharedLimiter(path, rps=1000, burst=5, max_requests=3)
    lim.acquire()
    assert lim.spent() == 1


# ================================================== 1a. the proxy block on a scope ===
def _scope_with(tmp_path, body: str):
    import scope as S
    p = tmp_path / "scope.yml"
    p.write_text(body, encoding="utf-8")
    return S.Scope.load(p)


_BASE = """
schema: 1
program:
  name: test
  authorized_by: test
in_scope:
  schemes: [https]
  hosts: [app.example.com]
"""


def test_proxy_absent_leaves_the_session_alone(tmp_path):
    sc = _scope_with(tmp_path, _BASE)
    assert sc.proxy == {}


def test_proxy_present_is_applied(tmp_path):
    sc = _scope_with(tmp_path, _BASE + """
proxy:
  http: http://127.0.0.1:8081
  https: http://127.0.0.1:8081
  verify: false
""")
    assert sc.proxy["https"] == "http://127.0.0.1:8081"
    assert sc.proxy["verify"] is False


def test_malformed_proxy_is_refused_at_load(tmp_path):
    import scope as S
    with pytest.raises(S.ScopeError, match="must be a URL"):
        _scope_with(tmp_path, _BASE + "\nproxy:\n  http: 8081\n")
    with pytest.raises(S.ScopeError, match="must be a mapping"):
        _scope_with(tmp_path, _BASE + "\nproxy: yes\n")


# ===================================== the defect itself, at the call site ===
def _mk(**ev):
    """A ProbeResult shaped like what a primitive returns."""
    import primitives as P
    return P.ProbeResult("x", ev.pop("confirmed", False), "/e", evidence=ev)


def test_sweep_verdict_no_longer_clears_by_fallthrough():
    """The regression, at the function that had it.

    A probe that returned nothing used to come back CLEAR from web/sweep.py:verdict(). Every
    timing-based primitive on a target that simply did not respond was therefore filed as
    "surface exists, checked, defended".
    """
    sys.path.insert(0, str(ROOT / "web"))
    import sweep

    assert sweep.verdict(_mk()) == "NOT-CONFIRMED"
    assert sweep.verdict(_mk(blocked=True)) == "BLOCKED"
    assert sweep.verdict(_mk(needs_browser=True)) == "NEEDS-BROWSER"
    assert sweep.verdict(_mk(needs_oob=True)) == "NEEDS-OOB"
    assert sweep.verdict(_mk(confirmed=True)) == "HIT"

    # CLEAR is now reachable only by saying what defended the target.
    import primitives as P
    ok = P.cleared("x", "/e", guard="400 + realpath prefix check", attack="../../etc/passwd x6")
    assert sweep.verdict(ok) == "CLEAR"
    assert ok.evidence["guard"] and ok.evidence["attack"]


def test_primitive_constructors_agree_with_the_state_machine():
    """primitives.* and verdict.* are two views of one vocabulary; they must not drift."""
    sys.path.insert(0, str(ROOT / "web"))
    import primitives as P
    import sweep

    pairs = [
        (P.blocked("x", "/e", "no token"), V.blocked("no token")),
        (P.not_confirmed("x", "/e", "no delay"), V.not_confirmed("no delay")),
        (P.cleared("x", "/e", guard="g", attack="a"), V.cleared(guard="g", attack="a")),
    ]
    for probe_result, verdict_obj in pairs:
        assert sweep.verdict(probe_result) == verdict_obj.render()


# ============================== concurrent writers must not reuse a T##### id ===
def _append(path: str, n: int, out):
    """Child process: allocate n transcript ids the way the mitm gate will."""
    sys.path.insert(0, str(ROOT / "dynamic"))
    sys.path.insert(0, str(ROOT / "static"))
    import scope as S
    t = S._Transcript(Path(path), shared=True)
    got = []
    for _ in range(n):
        tid = t.next_id()
        t.write({"id": tid, "ts": "x", "method": "GET", "url": "http://127.0.0.1/"})
        got.append(tid)
    out.put(got)


def test_concurrent_processes_do_not_reuse_transcript_ids(tmp_path):
    """A duplicate T##### makes a report's evidence citation ambiguous.

    _resume() runs once at construction, so two processes writing at the same time (the in-house
    primitives and an external tool's traffic through the mitmproxy gate) would each hold the same
    counter. Shared mode allocates from the file instead.
    """
    path = str(tmp_path / "transcript.jsonl")
    q = multiprocessing.Queue()
    procs = [multiprocessing.Process(target=_append, args=(path, 25, q)) for _ in range(3)]
    for p in procs:
        p.start()
    got = []
    for _ in procs:
        got += q.get()
    for p in procs:
        p.join(timeout=60)

    assert len(got) == 75
    assert len(set(got)) == 75, f"{75 - len(set(got))} duplicate transcript ids across processes"


def test_unshared_transcript_keeps_its_fast_path(tmp_path):
    """Local targets must not pay for file locking on every request."""
    import scope as S
    t = S._Transcript(tmp_path / "t.jsonl")
    assert t._flock is None
    assert [t.next_id() for _ in range(3)] == ["T00001", "T00002", "T00003"]


# ================================ write-evidence chain and the ledger mapping ===
def test_write_confirmed_needs_a_write_not_just_a_readback():
    """A read-back alone is a traversal READ bug - a different finding, a different owner."""
    assert not V.write_confirmed({V.READBACK_CONFIRMED: True})
    assert not V.write_confirmed({V.WRITE_ATTEMPTED: True})
    assert V.write_confirmed({V.WRITE_ATTEMPTED: True, V.WRITE_CONFIRMED: True})


def test_execution_is_never_tested():
    """disclosure-ethics forbids persistence; reaching the location is already the finding."""
    with pytest.raises(ValueError, match="never be set"):
        V.write_confirmed({V.WRITE_ATTEMPTED: True, V.WRITE_CONFIRMED: True,
                           V.EXECUTION_TESTED: True})


def test_the_report_line_says_how_the_write_was_established():
    """The whole point of splitting the steps: a reader can see which primitive carries the claim."""
    direct = V.describe_write_evidence({V.WRITE_ATTEMPTED: True, V.WRITE_CONFIRMED: True})
    via_read = V.describe_write_evidence({V.WRITE_ATTEMPTED: True, V.WRITE_CONFIRMED: True,
                                          V.READBACK_CONFIRMED: True})
    assert "observed directly" in direct
    assert "separate read path" in via_read
    assert direct != via_read

    scored = V.describe_write_evidence({V.WRITE_ATTEMPTED: True, V.WRITE_CONFIRMED: True,
                                        V.EXECUTION_POSSIBLE: "site-packages"})
    assert "scored, not tested" in scored
    assert "site-packages" in scored

    assert "not established" in V.describe_write_evidence({V.WRITE_ATTEMPTED: True})


def test_every_probe_state_maps_to_a_real_ledger_status():
    """Without a mapping the two machines drift by hand, and a CONFIRMED probe gets filed stale."""
    import json
    schema = json.loads((ROOT / "state" / "ledger.example.json").read_text(encoding="utf-8"))
    allowed = set(schema["_schema"]["status_values"])

    for state in V.State:
        v = V.Verdict(state, V.Evidence.NONE) if state in (
            V.State.UNTESTED, V.State.N_A, V.State.BLOCKED, V.State.NEEDS_EXTERNAL_SIGNAL) else None
        if v is None:
            v = (V.cleared(guard="g", attack="a") if state is V.State.CLEAR
                 else V.Verdict(state, V.Evidence.RUNTIME, "x"))
        status = V.ledger_status(v)
        assert status in allowed, f"{state} maps to {status!r}, absent from the ledger schema"


def test_scope_refusal_is_distinct_from_blocked():
    """A boundary we respected is not a capability we lacked, and the ledger separates them."""
    v = V.blocked("rate limited")
    assert V.ledger_status(v) == "BLOCKED"
    assert V.ledger_status(v, scope_refused=True) == "SCOPE_REFUSED"


def test_a_clear_is_not_filed_as_a_finding():
    assert V.ledger_status(V.cleared(guard="realpath containment", attack="../ x6")) \
        == "FALSE_POSITIVE"
    assert V.ledger_status(V.not_confirmed("no signal")) == "TRIAGED"


def test_a_malformed_url_is_a_clean_refusal_not_a_traceback():
    """MSYS rewrites --endpoint /api/x into C:/Program Files/Git/api/x on Windows.

    That used to escape as a raw urllib ValueError from inside the parser, which reads like a
    pipeline crash and sends the operator debugging the wrong layer. It cost two wrong diagnoses
    before the cause was spotted, so the message now names it.
    """
    import scope as S
    sc = S.Scope.local("127.0.0.1")
    v = sc.explain("GET", "http://127.0.0.1:8099C:/Program Files/Git/api/read")
    assert v["allowed"] is False
    assert v["rule"] == "url.malformed"
    assert "MSYS_NO_PATHCONV" in v["reason"]
    # and a normal URL is unaffected
    assert sc.explain("GET", "http://127.0.0.1:8099/api/read")["allowed"] is True


def test_check_raises_scopeviolation_for_a_malformed_url():
    """It must refuse, not crash - a caller catching ScopeViolation should catch this too."""
    import scope as S
    sc = S.Scope.local("127.0.0.1")
    with pytest.raises(S.ScopeViolation):
        sc.check("GET", "http://127.0.0.1:8099C:/bad")
