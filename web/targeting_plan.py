#!/usr/bin/env python3
"""
targeting_plan.py - the contract that lets an agent aim the probes.

THE PROBLEM THIS SOLVES. `sweep.TARGETING` guesses which parameter belongs to which class from a
hardcoded English vocabulary (`q`, `search`, `file`, `next`). Measured against a target named
otherwise - `/v2/kontakt?suchbegriff=`, `/v2/ledger?payload=` - 52 of 54 primitives touched no real
endpoint and no real parameter was attacked at all, while the sweep still printed a verdict for every
class. A catch-all tier now attacks every discovered parameter, which stops the silent miss, but it
is brute force: it cannot tell that `suchbegriff` is a search box and `menge` is a quantity.

An agent can. `endpoints.json` carries `observed_values` (real examples seen in traffic), `source`
(crawl / openapi / jsbundle / sourcemap), `auth_declared` and `content_type`. A parameter named
`ref` whose observed values are `INV-2291` and `INV-2310` is an object reference worth an IDOR probe;
one named `menge` whose values are `1` and `3` is a quantity worth a business-logic look and no SQL
payloads at all. No word list reaches that conclusion.

SO: THE AGENT DECIDES WHERE, THE SCRIPT DECIDES HOW, AND THE SCOPE GATE STILL DECIDES WHETHER.
The plan is data, not code - it selects among probes that already exist and cannot introduce a new
request path, so an aimed sweep is exactly as scope-bound as an unaimed one.

    work/<slug>/web/targeting.json
    {
      "version": 1,
      "aimed_at": "sha256:...",            # digest of the endpoints.json this was written against
      "targets": {
        "sqli_error": [
          {"path": "/v2/kontakt", "param": "suchbegriff",
           "why": "observed values are product names - free-text search, likely a LIKE query"}
        ]
      },
      "not_applicable": {"xxe": "no endpoint accepts XML or any document content type"}
    }

`why` is mandatory on every target. It is the difference between an agent that reasoned and one that
shuffled the list, it lands in the evidence bundle beside the request, and a reviewer can check it.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

PLAN_NAME = "targeting.json"


class PlanError(Exception):
    """A malformed plan. Raised rather than ignored: silently falling back to the hardcoded hints
    would reproduce the exact under-testing the plan exists to fix, with no sign it happened."""


def endpoints_digest(endpoints: list) -> str:
    """Identity of the surface a plan was written against.

    A plan aimed at last week's recon can name paths that no longer exist, which would put the sweep
    back to attacking a site that is not there.
    """
    blob = json.dumps([(e.get("path"), e.get("method")) for e in endpoints], sort_keys=True)
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()


def load(workdir: Path, endpoints: list | None = None) -> dict:
    """Read and validate the plan. Returns {} when there is none - an unaimed sweep still runs."""
    path = Path(workdir) / "web" / PLAN_NAME
    if not path.exists():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise PlanError(f"{path}: not readable as JSON: {e}") from e
    if not isinstance(doc, dict):
        raise PlanError(f"{path}: top level must be an object")

    targets = doc.get("targets") or {}
    if not isinstance(targets, dict):
        raise PlanError(f"{path}: 'targets' must be an object keyed by primitive name")

    for name, entries in targets.items():
        if not isinstance(entries, list):
            raise PlanError(f"{path}: targets[{name!r}] must be a list")
        for i, t in enumerate(entries):
            if not isinstance(t, dict) or not t.get("path"):
                raise PlanError(f"{path}: targets[{name!r}][{i}] needs at least a 'path'")
            if not (t.get("why") or "").strip():
                raise PlanError(
                    f"{path}: targets[{name!r}][{i}] has no 'why'. Every aimed target must say why "
                    f"it was chosen - that sentence is what distinguishes reasoning from shuffling, "
                    f"and it is quoted in the evidence bundle.")

    na = doc.get("not_applicable") or {}
    if not isinstance(na, dict):
        raise PlanError(f"{path}: 'not_applicable' must be an object of primitive -> reason")
    for name, reason in na.items():
        if not (reason or "").strip():
            raise PlanError(
                f"{path}: not_applicable[{name!r}] has no reason. 'The surface does not exist' is a "
                f"claim about the target and needs saying out loud, or it is indistinguishable from "
                f"skipping the class.")

    doc["_stale"] = bool(
        endpoints is not None and doc.get("aimed_at")
        and doc["aimed_at"] != endpoints_digest(endpoints))
    return doc


def targets_for(plan: dict, name: str) -> list:
    """(path, param) pairs the agent chose for this primitive, in its order."""
    if not plan or plan.get("_stale"):
        return []
    return [(t["path"], t.get("param") or "") for t in (plan.get("targets") or {}).get(name, [])]


def why_for(plan: dict, name: str, path: str, param: str) -> str:
    for t in (plan.get("targets") or {}).get(name, []):
        if t.get("path") == path and (t.get("param") or "") == (param or ""):
            return t.get("why", "")
    return ""


def not_applicable(plan: dict, name: str) -> str:
    """The agent's reason this class does not apply, or "" if it made no such claim."""
    if not plan or plan.get("_stale"):
        return ""
    return ((plan.get("not_applicable") or {}).get(name) or "").strip()


def summary(plan: dict) -> str:
    if not plan:
        return "no targeting plan - the sweep will use hardcoded hints and the catch-all tier"
    if plan.get("_stale"):
        return ("targeting plan is STALE (written against a different endpoint set) - ignoring it "
                "and falling back to hints; re-run recon and re-aim")
    t = plan.get("targets") or {}
    return (f"targeting plan: {sum(len(v) for v in t.values())} aimed targets across {len(t)} "
            f"primitives, {len(plan.get('not_applicable') or {})} classes marked N/A")
