#!/usr/bin/env python3
"""
repo_intel.py — Repository Intelligence: score & rank candidate repos for hunting.

Combines three signals into a hunt_score:
  * attack/auth surface  (from candidates.yml tags, or real AST counts with --deep)
  * security maturity     (SECURITY.md, Dependabot, CodeQL workflow, activity — via `gh`)
  * audit saturation      (published GHSA advisory count — picked-over repos yield less)
  * bug-density = surface / complexity   (--deep only; needs a shallow clone)

The pick is a *recommendation* — a human confirms it. `--deep <repo>` clones and runs
the real multi-language AST surface/complexity analysis.

CLI:
  python intel/repo_intel.py                      # rank all candidates (metadata mode)
  python intel/repo_intel.py --deep HKUDS/LightRAG  # clone + real AST surface/bug-density
  python intel/repo_intel.py --self-test          # prove ast_scan on the self-test apps
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import ast_scan  # noqa: E402  (local module)

# scoring weights (documented + tunable)
W_SURFACE = 1.0      # more attack surface -> more to hunt
W_TRIAGE = 4.0       # SECURITY.md + active maintainers -> reports get triaged (CVE odds)
W_SATURATION = -0.5  # each prior advisory -> a bit more picked-over
W_DENSITY = 6.0      # bug-density (deep only) -> effort efficiency


@dataclass
class RepoScore:
    repo: str
    lang: str
    category: str
    surface_tags: list[str] = field(default_factory=list)
    stars: int = 0
    days_since_push: int = 9999
    has_security_md: bool = False
    has_dependabot: bool = False
    has_codeql: bool = False
    advisory_count: int = 0
    ast_surface: int = 0          # deep only
    loc: int = 0                  # deep only
    bug_density: float = 0.0      # deep only
    hunt_score: float = 0.0
    notes: str = ""

    def compute(self) -> None:
        surface = self.ast_surface or (len(self.surface_tags) * 3)
        triage = (1.0 if self.has_security_md else 0.0)
        # recent activity boosts triage-readiness (active = responsive)
        if self.days_since_push < 30:
            triage += 0.75
        elif self.days_since_push < 120:
            triage += 0.35
        self.hunt_score = (
            W_SURFACE * surface
            + W_TRIAGE * triage
            + W_SATURATION * self.advisory_count
            + W_DENSITY * self.bug_density
        )


def _gh_json(args: list[str]) -> dict | list | None:
    """Call `gh api` and parse JSON; None on any failure (unauthenticated/rate-limit)."""
    gh = shutil.which("gh")
    if not gh:
        return None
    try:
        out = subprocess.run([gh, *args], capture_output=True, text=True, timeout=45)
        if out.returncode != 0:
            return None
        return json.loads(out.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None


def _days_since(iso: str | None) -> int:
    if not iso:
        return 9999
    from datetime import datetime, timezone
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except ValueError:
        return 9999


def enrich_metadata(rs: RepoScore) -> None:
    meta = _gh_json(["api", f"repos/{rs.repo}"])
    if isinstance(meta, dict):
        rs.stars = meta.get("stargazers_count", 0)
        rs.days_since_push = _days_since(meta.get("pushed_at"))
    # file presence checks (200 vs 404)
    for label, attr, path in [
        ("security", "has_security_md", "SECURITY.md"),
        ("dependabot", "has_dependabot", ".github/dependabot.yml"),
    ]:
        got = _gh_json(["api", f"repos/{rs.repo}/contents/{path}"])
        setattr(rs, attr, isinstance(got, dict))
    # codeql workflow presence
    wf = _gh_json(["api", f"repos/{rs.repo}/contents/.github/workflows"])
    if isinstance(wf, list):
        rs.has_codeql = any("codeql" in (f.get("name", "").lower()) for f in wf)
    # published advisory count
    adv = _gh_json(["api", f"repos/{rs.repo}/security-advisories?per_page=100"])
    if isinstance(adv, list):
        rs.advisory_count = len(adv)


def deep_analyze(rs: RepoScore) -> None:
    """Shallow-clone and run real AST surface + complexity."""
    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "src"
        git = shutil.which("git")
        r = subprocess.run(
            [git, "clone", "--depth", "1", f"https://github.com/{rs.repo}.git", str(dest)],
            capture_output=True, text=True, timeout=600,
        )
        if r.returncode != 0:
            rs.notes = f"clone failed: {r.stderr.strip()[:80]}"
            return
        langs = None if rs.lang in ("mixed", "auto") else {rs.lang}
        result = ast_scan.scan_repo(dest, langs)
        rs.ast_surface = result["n_signals"]
        rs.loc = result["loc"]
        rs.bug_density = round(rs.ast_surface / max(rs.loc / 1000, 1), 3)


def load_candidates() -> list[RepoScore]:
    data = yaml.safe_load((ROOT / "targets" / "candidates.yml").read_text(encoding="utf-8"))
    out = []
    for c in data["candidates"]:
        out.append(RepoScore(
            repo=c["repo"], lang=c.get("lang", "auto"),
            category=c.get("category", ""), surface_tags=c.get("surface", []),
            notes=c.get("note", ""),
        ))
    return out


def print_table(rows: list[RepoScore], deep: bool) -> None:
    rows = sorted(rows, key=lambda r: -r.hunt_score)
    try:
        from rich.console import Console
        from rich.table import Table
        t = Table(title="Candidate hunt ranking (higher = hunt first)")
        cols = ["#", "repo", "lang", "★", "pushed", "SEC", "adv", "surface"]
        if deep:
            cols += ["LOC", "density"]
        cols += ["score", "note"]
        for c in cols:
            t.add_column(c)
        for i, r in enumerate(rows, 1):
            cells = [str(i), r.repo, r.lang, f"{r.stars:,}",
                     f"{r.days_since_push}d", "Y" if r.has_security_md else "-",
                     str(r.advisory_count),
                     str(r.ast_surface or len(r.surface_tags) * 3)]
            if deep:
                cells += [f"{r.loc:,}", f"{r.bug_density}"]
            cells += [f"{r.hunt_score:.1f}", (r.notes or "")[:42]]
            t.add_row(*cells)
        Console().print(t)
    except ImportError:
        print(f"{'#':>2} {'repo':32} {'lang':11} {'★':>7} {'adv':>3} {'surf':>4} {'score':>6}")
        for i, r in enumerate(rows, 1):
            surf = r.ast_surface or len(r.surface_tags) * 3
            print(f"{i:>2} {r.repo:32} {r.lang:11} {r.stars:>7} "
                  f"{r.advisory_count:>3} {surf:>4} {r.hunt_score:>6.1f}")
    print("\nRecommended top-2 to hunt:")
    for r in rows[:2]:
        print(f"  • {r.repo}  (score {r.hunt_score:.1f}) — {r.notes or r.category}")
    print("\n(Confirm the pick yourself. Then: python intel/repo_intel.py --deep <repo>, "
          "or /hunt <repo> to let the agent team drive it.)")


def self_test() -> int:
    print("== ast_scan self-test on bundled fixtures ==")
    ok = True
    for name, path, lang, want in [
        ("py_app", ROOT / "work/_selftest/py_app", {"python"},
         {"deserialize", "exec", "path", "endpoint", "jwt", "auth"}),
        ("node_app", ROOT / "work/_selftest/node_app", {"javascript"},
         {"exec", "cmd", "path", "endpoint", "jwt", "xss"}),
    ]:
        res = ast_scan.scan_repo(path, lang)
        found = set(res["counts"])
        missing = want - found
        status = "OK" if not missing else f"MISSING {missing}"
        if missing:
            ok = False
        if lang == {"javascript"} and not res["tree_sitter_available"]:
            status = "SKIP (tree-sitter-languages not installed)"
        print(f"  {name:9} categories={sorted(found)}  -> {status}")
    print("self-test", "PASSED" if ok else "had gaps (see above)")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--deep", metavar="OWNER/REPO",
                    help="clone one repo and run real AST surface/complexity")
    ap.add_argument("--no-gh", action="store_true", help="skip gh metadata (offline)")
    ap.add_argument("--self-test", action="store_true", help="verify ast_scan on fixtures")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    rows = load_candidates()
    if args.deep:
        rows = [r for r in rows if r.repo.lower() == args.deep.lower()] or rows
    for r in rows:
        if not args.no_gh:
            enrich_metadata(r)
        if args.deep and r.repo.lower() == args.deep.lower():
            print(f"cloning + analyzing {r.repo} …")
            deep_analyze(r)
        r.compute()
    print_table(rows, deep=bool(args.deep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
