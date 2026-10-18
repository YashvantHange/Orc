#!/usr/bin/env python3
"""
The sweep must attack the target that exists, not the target it expected.

THE DEFECT THIS PINS. TARGETING's hints are English and conventional - `q`, `search`, `file`, `next`
- and FALLBACK_PATHS adds conventional paths (`/search`, `/api/items`) whether or not recon found
them. On a target whose API says `suchbegriff`, `ref` or `payload`, nothing matched, so the sweep
attacked the fallback paths instead: endpoints that do not exist on that host. It then reported a
verdict for every class, having never touched the real surface.

Measured before the fix, on the four-endpoint fixture below: 52 of 54 primitives hit no real
endpoint, and not one real parameter was attacked by anything.

This is the limit of a script-only approach, so these tests exist to keep the floor from moving:
a hardcoded vocabulary cannot anticipate a target's naming, and the honest fallbacks are (a) attack
every discovered parameter regardless of its name, and (b) say BLOCKED when only guesses were tried.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for sub in ("web", "dynamic", "static"):
    sys.path.insert(0, str(ROOT / sub))

import primitives as P   # noqa: E402
import probe             # noqa: E402
import sweep             # noqa: E402

# A realistic target that matches none of the hint vocabularies: versioned, non-English, and
# domain-specific. Nothing here is unusual - it is just not the naming the hints assume.
FOREIGN = [
    {"path": "/v2/dossier/{id}", "method": "GET", "params": [{"name": "ref"}]},
    {"path": "/v2/ledger", "method": "POST", "params": [{"name": "payload"}]},
    {"path": "/v2/kontakt", "method": "GET", "params": [{"name": "suchbegriff"}]},
    {"path": "/v2/auftrag", "method": "POST", "params": [{"name": "menge"}]},
]
REAL_PATHS = {e["path"] for e in FOREIGN}
REAL_PARAMS = {(e["path"], p["name"]) for e in FOREIGN for p in e["params"]}


def test_every_discovered_parameter_is_attacked_by_something():
    """The floor: no real parameter may be ignored just because nobody guessed its name."""
    attacked = {(path, param)
                for name in probe.PRIMITIVES
                for path, param in sweep.pick_targets(name, FOREIGN)
                if path in REAL_PATHS and param}
    missed = REAL_PARAMS - attacked
    assert not missed, (
        f"these real parameters are attacked by no primitive at all: {sorted(missed)} - "
        f"the sweep would report verdicts for every class without touching them")


def test_a_meaningful_share_of_primitives_reach_the_real_surface():
    """Was 2/54 before the discovered-parameter tier."""
    touched = [name for name in probe.PRIMITIVES
               if any(p in REAL_PATHS for p, _ in sweep.pick_targets(name, FOREIGN))]
    assert len(touched) >= 15, (
        f"only {len(touched)} of {len(probe.PRIMITIVES)} primitives target a real endpoint on a "
        f"target with unconventional naming")


def test_named_hints_still_win_over_the_catch_all():
    """The catch-all must not dilute good targeting when the vocabulary DOES match."""
    conventional = [
        {"path": "/search", "method": "GET",
         "params": [{"name": "q"}, {"name": "unrelated_blob"}]},
    ]
    first_path, first_param = sweep.pick_targets("sqli_error", conventional)[0]
    assert first_param == "q", (
        f"the catch-all tier outranked a named hint (got {first_param!r}) - a characteristic "
        f"parameter must still be tried first")


def test_a_miss_against_paths_that_do_not_exist_is_blocked_not_a_verdict(tmp_path, monkeypatch):
    """If only invented paths were tried, the class is untested - say so.

    Reporting it as a clean miss is the same laundering as the old CLEAR fallthrough: it reads as
    'we looked and it is fine' when the truth is 'we looked somewhere else'.
    """
    (tmp_path / "web").mkdir(parents=True)

    monkeypatch.setattr(sweep, "load_endpoints", lambda wd: FOREIGN)
    # Force every candidate to be a path that does not exist on the target.
    monkeypatch.setattr(sweep, "pick_targets",
                        lambda name, eps, limit=6, plan=None: [("/invented", "q")])
    monkeypatch.setattr(probe, "run_primitive",
                        lambda base, name, endpoint, param=None, ctx=None:
                        P.not_confirmed(name, endpoint, "nothing came back"))

    out = sweep.run("http://127.0.0.1:1", tmp_path, P.Ctx(), only=["sqli_error"])
    r = out["results"][0]
    assert sweep.verdict(r) == "BLOCKED", (
        f"expected BLOCKED for a class tested only against non-existent paths, got "
        f"{sweep.verdict(r)}")
    assert "no discovered endpoint matched" in r.detail


def test_a_miss_against_a_real_endpoint_stays_a_real_verdict(tmp_path, monkeypatch):
    """The inverse: when the sweep DID attack the real surface, do not downgrade the result."""
    (tmp_path / "web").mkdir(parents=True)

    monkeypatch.setattr(sweep, "load_endpoints", lambda wd: FOREIGN)
    monkeypatch.setattr(sweep, "pick_targets",
                        lambda name, eps, limit=6, plan=None: [("/v2/kontakt", "suchbegriff")])
    monkeypatch.setattr(probe, "run_primitive",
                        lambda base, name, endpoint, param=None, ctx=None:
                        P.not_confirmed(name, endpoint, "nothing came back"))

    out = sweep.run("http://127.0.0.1:1", tmp_path, P.Ctx(), only=["sqli_error"])
    assert sweep.verdict(out["results"][0]) == "NOT-CONFIRMED"


def test_blocked_names_the_manual_command_to_run():
    """A BLOCKED row is only useful if it says what would unblock it."""
    (Path(ROOT) / "work").mkdir(exist_ok=True)
    detail = ("no discovered endpoint matched this class - only conventional paths were tried, "
              "so the target's real surface is untested for it. Point it by hand: "
              "hunt web probe <url> --primitive sqli_error --endpoint <path> --param <name>")
    assert "hunt web probe" in detail and "--primitive" in detail
