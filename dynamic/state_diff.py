#!/usr/bin/env python3
"""
state_diff.py — the cross-request state-reuse differential (`state-integrity` § S2).

Proves, or fails to prove, that state belonging to one identity is served to another because a
process-scoped holder (module global, pooled object, thread-local, async context) was never reset
when the request ended. This is CVE-2026-109619's shape, and in a managed language it presents as
one user's data or AUTHORIZATION CONTEXT reaching the next caller.

WHY IT IS ITS OWN MODULE. authz_diff.py asks "can identity B reach A's *resource*" — a question
about a missing check. This asks "does identity B receive A's *state*" — a question about a missing
reset. The second needs things the first has no notion of: two requests in a fixed order, both on
the SAME pooled worker, a repeat count, and a control where they are deliberately on different
workers.

THE TRAP THIS MODULE EXISTS TO AVOID. Raising the worker count is not a negative control. Measured
on win32 with node v24.20.0: 4 workers, no connection reuse, 5 trials - every trial still put both
requests on one worker and still reproduced the leak. 12 sequential requests reached 1 of 4 workers
under the platform default, and 4 of 4 under cluster.SCHED_RR. A rate measured while the platform
was pinning everything to one process is not a rate, it is an artefact of the harness. So the policy
is always stated, never inherited, and the control forces distribution.

LOCAL BY CONSTRUCTION for --launch. A live host is reached only with --url plus a scope.yml, and on
a live target read `state-integrity` § "When the target is a live website" FIRST: two accounts the
operator owns, a marker unmistakably ours, and stop/minimise/purge/report the instant anything that
is not our marker comes back.

  python dynamic/state_diff.py --selftest
  python dynamic/state_diff.py --launch work/_selftest/pool_app --probe /whoami \\
         --identity-a alice --marker-field identity --attempts 10
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class StateDiffResult:
    """One S2 verdict, carrying the seven fields `state-integrity` requires.

    The seventh (distribution_mechanism) is here because the other six can all look healthy while
    the platform quietly pins every request to one worker.
    """
    probe: str
    verdict: str                      # CONFIRMED / NOT_CONFIRMED / BLOCKED / NEEDS_EXTERNAL_SIGNAL
    reason: str = ""
    # --- the seven recorded fields ---
    worker_identification: str = ""
    connection_reuse: bool = False
    distribution_mechanism: str = ""
    attempts: int = 0
    observations: int = 0
    rate: str = ""
    control: str = ""
    # --- supporting ---
    same_worker_attempts: int = 0
    leaked_values: list = field(default_factory=list)
    marker: str = ""


def _get(base: str, path: str, headers: dict, session) -> dict:
    r = session.get(base + path, headers=headers, timeout=10)
    try:
        return {"status": r.status_code, "json": r.json()}
    except ValueError:
        return {"status": r.status_code, "text": r.text[:400]}


def _http():
    """The scope-gated requests facade — never bare `requests`.

    `dynamic/scope.py` is the single choke point: it refuses a host outside the authorized scope and
    writes every request that is sent OR refused into the transcript with a T##### id. Importing
    `requests` directly here would route the --url path around both, which is precisely what
    tests/test_orchestration.py::test_no_bare_requests_import_outside_scope exists to stop. It
    caught this module doing exactly that.
    """
    from scope import http as scoped
    return scoped


def differential(base: str, probe: str, identity_a: str, marker_field: str,
                 attempts: int, keep_alive: bool, policy_label: str,
                 worker_path: str = "/worker", worker_field: str = "pid") -> StateDiffResult:
    """Run A-then-B `attempts` times and report how often B saw A's state, on the same worker."""
    requests = _http()

    res = StateDiffResult(probe=probe, verdict="NOT_CONFIRMED",
                          connection_reuse=keep_alive,
                          distribution_mechanism=policy_label,
                          attempts=attempts, marker=identity_a)

    # Worker identification is a recorded field, not an assumption. If the target cannot tell us
    # which worker served a request, say so - the whole finding rests on "the same worker".
    probe_session = requests.Session()
    try:
        w = _get(base, worker_path, {}, probe_session)
        if isinstance(w.get("json"), dict) and worker_field in w["json"]:
            res.worker_identification = f"{worker_path} -> {worker_field}"
        else:
            res.worker_identification = "none"
    except requests.RequestException:
        res.worker_identification = "none"
    finally:
        probe_session.close()

    if res.worker_identification == "none":
        res.verdict = "BLOCKED"
        res.reason = (f"no worker identification: {worker_path} does not return {worker_field!r}. "
                      "Same-worker service is a precondition of this class and cannot be assumed; "
                      "find a pid-revealing response, header or error first.")
        return res

    for _ in range(attempts):
        session = requests.Session()
        if not keep_alive:
            session.headers["connection"] = "close"
        try:
            a = _get(base, probe, {"authorization": f"Bearer {identity_a}"}, session)
            b = _get(base, probe, {}, session)          # identity B: NO credentials at all
        except requests.RequestException as e:          # noqa: BLE001
            res.verdict = "BLOCKED"
            res.reason = f"request failed: {e}"
            session.close()
            return res

        ja, jb = a.get("json") or {}, b.get("json") or {}
        if not isinstance(ja, dict) or not isinstance(jb, dict):
            session.close()
            continue
        same_worker = ja.get(worker_field) is not None and ja.get(worker_field) == jb.get(worker_field)
        if same_worker:
            res.same_worker_attempts += 1
        if same_worker and jb.get(marker_field) == identity_a:
            res.observations += 1
            if identity_a not in res.leaked_values:
                res.leaked_values.append(identity_a)
        session.close()

    res.rate = f"{res.observations}/{res.attempts}"
    if res.observations:
        res.verdict = "CONFIRMED"
        res.reason = (f"an unauthenticated request to {probe} received identity {identity_a!r} "
                      f"written by the previous request on the same worker "
                      f"({res.observations}/{res.attempts} attempts, "
                      f"{res.same_worker_attempts}/{res.attempts} landed on one worker; "
                      f"distribution={policy_label})")
    else:
        res.reason = (f"attack sent {attempts}x and nothing came back. NOT the same as defended: "
                      f"{res.same_worker_attempts}/{attempts} attempts even landed on one worker "
                      f"(distribution={policy_label}).")
    return res


def write(slug_dir: Path, payload: dict) -> Path:
    out = slug_dir / "dynamic"
    out.mkdir(parents=True, exist_ok=True)
    p = out / "state_diff.json"
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return p


def selftest() -> int:
    """Positive case and the control that must stay quiet, against the seeded fixture."""
    from instrument import PoolUnavailable, TargetProcess
    target = ROOT / "work" / "_selftest" / "pool_app"
    if not target.exists():
        print(f"fixture missing: {target}", file=sys.stderr)
        return 2

    results = []
    print("== S2 differential selftest ==\n")

    # --- positive: one worker, platform default policy. The leak must be detected.
    try:
        with TargetProcess(str(target), pool=1, policy="none") as t:
            r = differential(t.base_url, "/whoami", "alice", "identity",
                             attempts=6, keep_alive=True, policy_label="1 worker, platform default")
            r.control = "see the forced-distribution run below"
            results.append(("positive /whoami", r))
            # the fixture's own negative control: correctly isolated, same shape
            c = differential(t.base_url, "/note", "alice", "note",
                             attempts=6, keep_alive=True, policy_label="1 worker, platform default")
            results.append(("isolated-cache control /note", c))
    except PoolUnavailable as e:
        print(f"NEEDS_EXTERNAL_SIGNAL: {e}", file=sys.stderr)
        return 1

    # --- the real negative control: FORCE distribution. Merely adding workers is not a control.
    try:
        with TargetProcess(str(target), pool=4, policy="rr") as t:
            d = differential(t.base_url, "/whoami", "alice", "identity",
                             attempts=8, keep_alive=False,
                             policy_label="4 workers, cluster.SCHED_RR (forced round-robin)")
            results.append(("forced-distribution control /whoami", d))
    except PoolUnavailable as e:
        print(f"control BLOCKED: {e}", file=sys.stderr)

    ok = True
    for label, r in results:
        print(f"  {label}")
        print(f"    verdict  : {r.verdict}")
        print(f"    worker id: {r.worker_identification}   keep-alive: {r.connection_reuse}")
        print(f"    distrib  : {r.distribution_mechanism}")
        print(f"    rate     : {r.rate}  (same-worker {r.same_worker_attempts}/{r.attempts})")
        print(f"    reason   : {r.reason}\n")

    verdicts = {label: r.verdict for label, r in results}
    if verdicts.get("positive /whoami") != "CONFIRMED":
        print("FAIL: the seeded leak was not detected — the differential does not work", file=sys.stderr)
        ok = False
    if verdicts.get("isolated-cache control /note") == "CONFIRMED":
        print("FAIL: reported a correctly-isolated cache — false positive", file=sys.stderr)
        ok = False
    payload = {"results": [dict(label=l, **asdict(r)) for l, r in results]}
    print(f"wrote {write(target, payload)}")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--launch", help="local target directory to boot under a worker pool")
    ap.add_argument("--url", help="already-running base url (needs --scope for a live host)")
    ap.add_argument("--scope", help="scope.yml authorizing --url (see dynamic/scope.py)")
    ap.add_argument("--probe", default="/whoami", help="path whose response may carry A's state")
    ap.add_argument("--identity-a", default="alice", help="identity A's bearer token / marker")
    ap.add_argument("--marker-field", default="identity",
                    help="JSON field in the probe response expected to carry A's marker")
    ap.add_argument("--worker-path", default="/worker")
    ap.add_argument("--worker-field", default="pid")
    ap.add_argument("--attempts", type=int, default=10)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--policy", choices=("rr", "none"), default="none",
                    help="'rr' forces round-robin (use for the CONTROL); 'none' = platform default")
    ap.add_argument("--no-keep-alive", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if not (a.launch or a.url):
        ap.error("pass --selftest, --launch <dir>, or --url <base>")
    if a.url and not a.scope:
        ap.error("--url needs --scope: a live host is only reached through the scope gate")

    policy_label = ("forced round-robin (SCHED_RR)" if a.policy == "rr"
                    else "platform default — NOT a control")
    if a.launch:
        from instrument import PoolUnavailable, TargetProcess
        try:
            with TargetProcess(a.launch, pool=a.workers, policy=a.policy) as t:
                r = differential(t.base_url, a.probe, a.identity_a, a.marker_field,
                                 a.attempts, not a.no_keep_alive,
                                 f"{a.workers} worker(s), {policy_label}",
                                 a.worker_path, a.worker_field)
        except PoolUnavailable as e:
            print(f"NEEDS_EXTERNAL_SIGNAL — {e}", file=sys.stderr)
            return 1
        out = write(Path(a.launch), {"results": [asdict(r)]})
    else:
        r = differential(a.url.rstrip("/"), a.probe, a.identity_a, a.marker_field,
                         a.attempts, not a.no_keep_alive,
                         f"live target, {policy_label}", a.worker_path, a.worker_field)
        out = write(ROOT / "work" / "_live", {"results": [asdict(r)]})

    print(json.dumps(asdict(r), indent=2))
    print(f"\n{out}")
    if r.verdict == "CONFIRMED" and a.policy != "rr":
        print("\nNOTE: this ran under the platform default. Re-run with --policy rr as the control "
              "before reporting a rate — adding workers alone does not distribute requests.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
