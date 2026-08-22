#!/usr/bin/env python3
"""
run_depaudit.py — dependency vulnerability audit -> normalized JSON.

  * Python:  pip-audit (requirements*.txt / pyproject / lockfiles)
  * JS/TS:   npm audit  (package-lock.json)  and/or osv-scanner (any lockfile)

NOTE: dependency vulns are usually *already-known CVEs* — valuable to report to the
project (bump the pin) and for scoring, but they will not mint a NEW CVE credited to you.

  python static/run_depaudit.py <target>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402


def _pip_audit(target: Path) -> list[C.Finding]:
    tool = C.find_tool("pip-audit")
    reqs = list(target.rglob("requirements*.txt")) + list(target.glob("pyproject.toml"))
    if not tool or not reqs:
        return []
    findings: list[C.Finding] = []
    for req in reqs[:6]:
        if any(p in req.parts for p in ("node_modules", ".venv", "venv")):
            continue
        args = ["-r", str(req)] if req.name.startswith("requirements") else []
        code, out, _ = C.run([tool, *args, "-f", "json"] if args
                             else [tool, "-f", "json"], cwd=str(req.parent), timeout=600)
        try:
            doc = json.loads(out or "{}")
        except json.JSONDecodeError:
            continue
        for dep in doc.get("dependencies", []):
            for v in dep.get("vulns", []):
                findings.append(C.Finding(
                    tool="pip-audit", rule_id=v.get("id", ""), severity="WARNING",
                    message=f"{dep.get('name')} {dep.get('version')}: {v.get('description','')[:160]}",
                    file=str(req.relative_to(target)), line=0, family="dependency",
                    extra={"fix": v.get("fix_versions")}))
    return findings


def _npm_audit(target: Path) -> list[C.Finding]:
    npm = C.find_tool("npm")
    locks = [p for p in target.rglob("package-lock.json")
             if "node_modules" not in p.parts]
    if not npm or not locks:
        return []
    findings: list[C.Finding] = []
    for lock in locks[:4]:
        code, out, _ = C.run([npm, "audit", "--json"], cwd=str(lock.parent), timeout=600)
        try:
            doc = json.loads(out or "{}")
        except json.JSONDecodeError:
            continue
        for name, adv in (doc.get("vulnerabilities", {}) or {}).items():
            via = adv.get("via", [])
            title = next((v.get("title") for v in via if isinstance(v, dict)), adv.get("severity", ""))
            findings.append(C.Finding(
                tool="npm-audit", rule_id=name, severity=_npm_sev(adv.get("severity")),
                message=f"{name}: {title} (severity {adv.get('severity')})",
                file=str(lock.relative_to(target)), line=0, family="dependency"))
    return findings


def _npm_sev(s: str | None) -> str:
    return {"critical": "ERROR", "high": "ERROR", "moderate": "WARNING",
            "low": "INFO"}.get((s or "").lower(), "WARNING")


def run_depaudit(target: str) -> Path:
    src = Path(target)
    print("  dep-audit: pip-audit + npm audit")
    findings = _pip_audit(src) + _npm_audit(src)
    out = C.scandir(target) / "depaudit.json"
    C.write_json(out, findings)
    print(f"  dep-audit: {len(findings)} known-vuln dependencies "
          f"(context — usually already CVE'd)")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    args = ap.parse_args()
    run_depaudit(args.target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
