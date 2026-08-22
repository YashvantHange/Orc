#!/usr/bin/env python3
"""
cvss.py — CVSS 3.1 base-score calculator (pure computation, no network).

Turns a vector string into a score+severity, or a set of metric flags into a vector.
Used by `hunt cvss` and the report-craft skill so the CVSS in a report is never hand-math.

  python reports/cvss.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   -> 9.8 Critical
  python reports/cvss.py AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N              -> 6.5 Medium
  python reports/cvss.py --metrics AV=N AC=L PR=N UI=N S=U C=H I=H A=H    -> builds + scores

Importable: score_vector(vector) -> (score: float, severity: str, vector: str)
"""
from __future__ import annotations

import argparse
import math
import sys

# metric weight tables (CVSS 3.1 spec section 7)
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}    # scope changed
_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
_ALLOWED = {"AV": set("NALP"), "AC": set("LH"), "PR": set("NLH"), "UI": set("NR"),
            "S": set("UC"), "C": set("HLN"), "I": set("HLN"), "A": set("HLN")}


def _roundup(x: float) -> float:
    """CVSS 3.1 roundUp: smallest 1-decimal number >= x (spec appendix A)."""
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def severity(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS vector (with or without the `CVSS:3.1/` prefix) into {metric: value}."""
    parts = [p for p in vector.strip().split("/") if p]
    metrics: dict[str, str] = {}
    for p in parts:
        if p.upper().startswith("CVSS:"):
            continue
        if ":" not in p:
            raise ValueError(f"bad metric segment {p!r} (expected e.g. AV:N)")
        k, v = p.split(":", 1)
        k, v = k.upper(), v.upper()
        if k in _ALLOWED:
            if v not in _ALLOWED[k]:
                raise ValueError(f"bad value {v!r} for {k} (allowed: {sorted(_ALLOWED[k])})")
            metrics[k] = v
    missing = [m for m in _ORDER if m not in metrics]
    if missing:
        raise ValueError(f"missing base metrics: {', '.join(missing)}")
    return metrics


def canonical_vector(metrics: dict[str, str]) -> str:
    return "CVSS:3.1/" + "/".join(f"{m}:{metrics[m]}" for m in _ORDER)


def base_score(metrics: dict[str, str]) -> float:
    scope_changed = metrics["S"] == "C"
    pr = (_PR_C if scope_changed else _PR_U)[metrics["PR"]]
    iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    expl = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    if impact <= 0:
        return 0.0
    raw = (1.08 * (impact + expl)) if scope_changed else (impact + expl)
    return _roundup(min(raw, 10.0))


def score_vector(vector: str) -> tuple[float, str, str]:
    metrics = parse_vector(vector)
    score = base_score(metrics)
    return score, severity(score), canonical_vector(metrics)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("vector", nargs="?", help="CVSS 3.1 vector string")
    ap.add_argument("--metrics", nargs="+", help="metric flags e.g. AV=N AC=L PR=N ...")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    if a.metrics:
        vec = "/".join(m.replace("=", ":") for m in a.metrics)
    elif a.vector:
        vec = a.vector
    else:
        ap.error("pass a vector string or --metrics AV=N AC=L ...")
    try:
        score, sev, canon = score_vector(vec)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.json:
        import json
        print(json.dumps({"score": score, "severity": sev, "vector": canon}))
    else:
        print(f"{score} {sev}\n{canon}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
