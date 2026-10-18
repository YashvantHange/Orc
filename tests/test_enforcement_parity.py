#!/usr/bin/env python3
"""
The two enforcement paths must give the same answer.

ScopedSession (in-house primitives) and mitm_gate (external tools) both put bytes on the wire at a
scoped target. If either implemented its own copy of the rules they would drift, and a drift here is
a security hole rather than a cosmetic inconsistency - traffic authorized on one path and refused on
the other, or worse, the reverse.

So: one corpus of request tuples, both paths, identical verdicts. The test is deliberately blunt.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dynamic"))
sys.path.insert(0, str(ROOT / "static"))

import scope as S  # noqa: E402

SCOPE_YML = """
schema: 1
program:
  name: parity-test
  authorized_by: test
in_scope:
  schemes: [https]
  hosts: [app.example.com, "*.api.example.com"]
  paths: ["^/api/", "^/public"]
out_of_scope:
  paths: ["^/api/internal"]
methods:
  allow: [GET, HEAD, OPTIONS, POST]
  deny: [DELETE, TRACE]
safety:
  destructive_paths: ["/account/delete", "/purge"]
limits:
  rps: 1000
  burst: 1000
  max_requests: 100000
"""

# (method, url) - the answer is whatever Scope says; the point is that BOTH paths say it.
CORPUS = [
    ("GET", "https://app.example.com/api/users"),
    ("GET", "https://app.example.com/public/x"),
    ("GET", "https://app.example.com/api/internal/secrets"),   # out_of_scope wins
    ("GET", "https://evil.example.net/api/users"),             # host not in scope
    ("GET", "http://app.example.com/api/users"),               # scheme not in scope
    ("GET", "https://v2.api.example.com/api/x"),               # wildcard host
    ("GET", "https://app.example.com/admin"),                  # path not in scope
    ("DELETE", "https://app.example.com/api/users/1"),         # denied method
    ("TRACE", "https://app.example.com/api/x"),
    ("POST", "https://app.example.com/api/account/delete"),    # destructive verb + path
    ("GET", "https://app.example.com/api/account/delete"),     # same path, safe verb
    ("HEAD", "https://app.example.com/api/x"),
    ("OPTIONS", "https://app.example.com/api/x"),
    ("POST", "https://app.example.com/api/purge"),
    ("PUT", "https://app.example.com/api/x"),                  # not in allow list
]


@pytest.fixture()
def sc(tmp_path):
    p = tmp_path / "scope.yml"
    p.write_text(SCOPE_YML, encoding="utf-8")
    return S.Scope.load(p)


def test_corpus_exercises_both_outcomes(sc):
    """A parity test where everything is refused would pass while proving nothing."""
    verdicts = [sc.explain(m, u)["allowed"] for m, u in CORPUS]
    assert any(verdicts), "corpus authorizes nothing - it cannot detect an over-permissive path"
    assert not all(verdicts), "corpus refuses nothing - it cannot detect an over-permissive path"


def test_both_paths_reach_the_same_decision(sc):
    """The parity assertion itself.

    Both paths call Scope.explain(); this test is what keeps that true. If someone later gives
    mitm_gate its own host matching or its own method list, these stop agreeing.
    """
    import mitm_gate

    gate = mitm_gate.ScopeGate.__new__(mitm_gate.ScopeGate)   # no env, no mitmproxy import
    gate.scope = sc

    for method, url in CORPUS:
        session_view = sc.explain(method, url)
        gate_view = gate.scope.explain(method, url)
        assert session_view == gate_view, (
            f"{method} {url}: ScopedSession says {session_view}, gate says {gate_view}")


def test_the_gate_holds_no_authorization_logic_of_its_own():
    """The review rule from the module docstring, enforced.

    mitm_gate is meant to be a translator. If it grows its own host/scheme/method/path matching, the
    two paths can diverge without any test noticing - so catch the regression at the source.
    """
    src = (ROOT / "dynamic" / "mitm_gate.py").read_text(encoding="utf-8")
    banned = ["fnmatch", "urlsplit", "in_scope", "out_of_scope",
              "destructive", "ipaddress", "test_window"]
    found = [b for b in banned if b in src]
    assert not found, (
        f"mitm_gate.py references {found} - that is policy, and policy belongs in scope.py. "
        f"Delegate to Scope.explain()/check() instead of reimplementing the rule.")


def test_budget_is_shared_between_the_two_paths(tmp_path):
    """An external tool and the in-house primitives draw down ONE max_requests, not one each."""
    p = tmp_path / "scope.yml"
    p.write_text(SCOPE_YML.replace("max_requests: 100000", "max_requests: 6"), encoding="utf-8")

    session_scope = S.Scope.load(p)
    gate_scope = S.Scope.load(p)
    shared = tmp_path / "limits.json"
    session_scope.attach_shared(shared)
    gate_scope.attach_shared(shared)

    url = "https://app.example.com/api/x"
    for _ in range(3):
        session_scope.acquire("GET", url)
    for _ in range(3):
        gate_scope.acquire("GET", url)

    for who in (session_scope, gate_scope):
        with pytest.raises(S.ScopeViolation, match="budget exhausted"):
            who.acquire("GET", url)
