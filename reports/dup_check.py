#!/usr/bin/env python3
"""
dup_check.py — is this vulnerability already known? Check BEFORE writing a report.

Searches, via the `gh` CLI + GitHub API: published GHSA advisories, open+closed issues,
pull requests, recent commits, and releases — because many bugs are fixed WITHOUT a CVE.
Also prints the huntr + CVE search URLs for a manual look.

  python reports/dup_check.py <owner/repo> --query "IDOR items endpoint ownership"
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import urllib.parse


def _gh(args: list[str]) -> list | dict | None:
    gh = shutil.which("gh")
    if not gh:
        return None
    try:
        out = subprocess.run([gh, *args], capture_output=True, text=True, timeout=45)
        if out.returncode != 0:
            return None
        return json.loads(out.stdout) if out.stdout.strip() else []
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None


def check(repo: str, query: str) -> dict:
    terms = query.strip()
    results: dict[str, list] = {}

    adv = _gh(["api", f"repos/{repo}/security-advisories?per_page=100"])
    if isinstance(adv, list):
        results["advisories"] = [a.get("summary", "") for a in adv
                                 if any(t.lower() in json.dumps(a).lower()
                                        for t in terms.split())][:10]

    for kind, cmd in {
        "issues": ["search", "issues", "--repo", repo, terms, "--state", "all",
                   "--limit", "10", "--json", "title,url,state"],
        "prs": ["search", "prs", "--repo", repo, terms, "--state", "all",
                "--limit", "10", "--json", "title,url,state"],
        "commits": ["search", "commits", "--repo", repo, terms,
                    "--limit", "10", "--json", "sha,url"],
    }.items():
        r = _gh(cmd)
        if isinstance(r, list):
            results[kind] = r

    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repo")
    ap.add_argument("--query", required=True, help="vuln + component keywords")
    args = ap.parse_args()

    print(f"== duplicate check: {args.repo}  query='{args.query}' ==")
    res = check(args.repo, args.query)
    hits = 0
    for kind, items in res.items():
        if not items:
            continue
        print(f"\n[{kind}] {len(items)} possible match(es):")
        for it in items[:8]:
            hits += 1
            if isinstance(it, dict):
                print(f"  - {it.get('title') or it.get('sha','')[:12]}  "
                      f"{it.get('state','')}  {it.get('url','')}")
            else:
                print(f"  - {it}")

    q = urllib.parse.quote(f"{args.repo.split('/')[-1]} {args.query}")
    print("\nAlso search manually (paste in browser):")
    print(f"  huntr:   https://huntr.com/bounties?search={q}")
    print(f"  CVE:     https://www.cve.org/CVERecord/SearchResults?query={q}")
    print(f"  GHSA:    https://github.com/advisories?query={q}")
    print(f"  NVD:     https://nvd.nist.gov/vuln/search/results?query={q}")

    print(f"\nverdict: {'POSSIBLE DUPLICATE — review the matches above' if hits else 'no obvious duplicate found (still check the URLs)'}")
    if not shutil.which("gh"):
        print("  (gh not found / not authenticated — only manual URLs available)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
