#!/usr/bin/env python3
"""
The agent aims, the script shoots, the scope gate still decides.

These tests pin the contract in both directions: an agent's judgement must actually override the
hardcoded guesses (or the agent is decoration), and a malformed or unjustified plan must be rejected
loudly (or the plan becomes a way to launder unreasoned targeting).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for sub in ("web", "dynamic", "static"):
    sys.path.insert(0, str(ROOT / sub))

import primitives as P      # noqa: E402
import probe                # noqa: E402
import sweep                # noqa: E402
import targeting_plan as TP  # noqa: E402

FOREIGN = [
    {"path": "/v2/dossier/{id}", "method": "GET", "params": [{"name": "ref"}]},
    {"path": "/v2/kontakt", "method": "GET", "params": [{"name": "suchbegriff"}]},
]


def _write(tmp_path: Path, doc: dict) -> Path:
    (tmp_path / "web").mkdir(parents=True, exist_ok=True)
    (tmp_path / "web" / "targeting.json").write_text(json.dumps(doc), encoding="utf-8")
    return tmp_path


def _plan(**targets) -> dict:
    return {"version": 1, "targets": targets}


# ------------------------------------------------------------------ the override works ---
def test_an_aimed_target_outranks_the_hardcoded_hints():
    """Without this the agent is decoration."""
    plan = _plan(sqli_error=[{"path": "/v2/kontakt", "param": "suchbegriff",
                              "why": "observed values are product names - free-text search"}])
    first = sweep.pick_targets("sqli_error", FOREIGN, plan=plan)[0]
    assert first == ("/v2/kontakt", "suchbegriff"), (
        "the agent's chosen target must be tried before /search and the other invented fallbacks")


def test_the_fallbacks_are_still_there_after_the_aimed_targets():
    """Aiming narrows the order, it does not throw away coverage."""
    plan = _plan(sqli_error=[{"path": "/v2/kontakt", "param": "suchbegriff", "why": "search"}])
    targets = sweep.pick_targets("sqli_error", FOREIGN, plan=plan)
    assert len(targets) > 1


def test_aiming_works_for_fixed_path_primitives_too():
    plan = _plan(graphql_introspection=[{"path": "/api/v2/gql", "param": "",
                                         "why": "sourcemap shows the client posts queries here"}])
    assert sweep.pick_targets("graphql_introspection", FOREIGN, plan=plan)[0] == ("/api/v2/gql", "")


def test_no_plan_is_not_an_error():
    assert sweep.pick_targets("sqli_error", FOREIGN, plan={}) == \
        sweep.pick_targets("sqli_error", FOREIGN)


# ------------------------------------------------------- the plan cannot launder guesswork ---
def test_a_target_without_a_why_is_rejected(tmp_path):
    """`why` is what separates reasoning from shuffling, and it is quoted in the evidence."""
    _write(tmp_path, _plan(sqli_error=[{"path": "/v2/kontakt", "param": "suchbegriff"}]))
    with pytest.raises(TP.PlanError, match="no 'why'"):
        TP.load(tmp_path)


def test_a_blank_why_is_rejected(tmp_path):
    _write(tmp_path, _plan(sqli_error=[{"path": "/x", "param": "y", "why": "   "}]))
    with pytest.raises(TP.PlanError, match="no 'why'"):
        TP.load(tmp_path)


def test_not_applicable_without_a_reason_is_rejected(tmp_path):
    """'The surface does not exist' is a claim about the target, not a way to skip a class."""
    _write(tmp_path, {"version": 1, "targets": {}, "not_applicable": {"xxe": ""}})
    with pytest.raises(TP.PlanError, match="no reason"):
        TP.load(tmp_path)


def test_malformed_plan_raises_rather_than_silently_falling_back(tmp_path):
    (tmp_path / "web").mkdir(parents=True)
    (tmp_path / "web" / "targeting.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(TP.PlanError):
        TP.load(tmp_path)


# ------------------------------------------------------------------------ staleness ---
def test_a_stale_plan_is_ignored_not_obeyed(tmp_path):
    """A plan aimed at last week's recon names paths that may no longer exist."""
    _write(tmp_path, {"version": 1, "aimed_at": "sha256:stale",
                      "targets": {"sqli_error": [{"path": "/gone", "why": "was here once"}]}})
    plan = TP.load(tmp_path, FOREIGN)
    assert plan["_stale"] is True
    assert TP.targets_for(plan, "sqli_error") == []
    assert "STALE" in TP.summary(plan)


def test_a_current_plan_is_not_stale(tmp_path):
    digest = TP.endpoints_digest(FOREIGN)
    _write(tmp_path, {"version": 1, "aimed_at": digest,
                      "targets": {"sqli_error": [{"path": "/v2/kontakt", "why": "search"}]}})
    plan = TP.load(tmp_path, FOREIGN)
    assert plan["_stale"] is False
    assert TP.targets_for(plan, "sqli_error") == [("/v2/kontakt", "")]


# -------------------------------------------------------------- what the sweep does with it ---
def test_agent_marked_na_becomes_the_verdict_with_its_reason(tmp_path, monkeypatch):
    """Only an agent can justify N/A; the sweep can only fail to find something."""
    _write(tmp_path, {"version": 1, "targets": {},
                      "not_applicable": {"xxe": "no endpoint declares an XML content type"}})
    monkeypatch.setattr(sweep, "load_endpoints", lambda wd: FOREIGN)

    out = sweep.run("http://127.0.0.1:1", tmp_path, P.Ctx(), only=["xxe"])
    r = out["results"][0]
    assert r.evidence.get("not_applicable") is True
    assert "XML content type" in r.detail
    assert not r.confirmed


def test_the_why_is_carried_into_the_evidence(tmp_path, monkeypatch):
    """A reviewer must be able to check the reasoning against what was actually sent."""
    why = "observed values INV-2291/INV-2310 - sequential object reference"
    _write(tmp_path, {"version": 1,
                      "targets": {"idor_enum": [{"path": "/v2/dossier/{id}", "param": "ref",
                                                 "why": why}]}})
    monkeypatch.setattr(sweep, "load_endpoints", lambda wd: FOREIGN)
    monkeypatch.setattr(probe, "run_primitive",
                        lambda base, name, endpoint, param=None, ctx=None:
                        P.not_confirmed(name, endpoint, "nothing came back"))

    out = sweep.run("http://127.0.0.1:1", tmp_path, P.Ctx(), only=["idor_enum"])
    r = out["results"][0]
    assert r.evidence.get("aimed_by") == "agent"
    assert r.evidence.get("why_this_target") == why


def test_a_rejected_plan_does_not_stop_the_sweep(tmp_path, monkeypatch, capsys):
    """Fail loud, but an unaimed sweep is still better than no sweep."""
    (tmp_path / "web").mkdir(parents=True)
    (tmp_path / "web" / "targeting.json").write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(sweep, "load_endpoints", lambda wd: FOREIGN)
    monkeypatch.setattr(probe, "run_primitive",
                        lambda base, name, endpoint, param=None, ctx=None:
                        P.not_confirmed(name, endpoint, "nothing came back"))

    out = sweep.run("http://127.0.0.1:1", tmp_path, P.Ctx(), only=["sqli_error"])
    assert out["results"], "the sweep must still run without a usable plan"
    assert "targeting plan rejected" in capsys.readouterr().out


# ------------------------------------------------------------------------ the agent file ---
def test_the_target_aimer_agent_is_registered():
    f = ROOT / ".claude" / "agents" / "target-aimer.md"
    assert f.exists()
    text = f.read_text(encoding="utf-8")
    assert text.startswith("---"), "agent files need frontmatter"
    for field in ("name: target-aimer", "tools:", "model:"):
        assert field in text
    # it must not claim it sends requests - the scope gate owns that
    assert "targeting.json" in text
