#!/usr/bin/env python3
"""
run_all.py — run the whole static layer for a target, by language.

  python static/run_all.py <target> [--lang python|javascript|typescript|auto]
                                     [--with-codeql] [--local-only]

Runs: semgrep (always), bandit (python), dep-audit, secrets (gitleaks), and CodeQL
(opt-in). Each writes SARIF/JSON into work/<slug>/scan/. Then run correlate/merge.py.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402
import run_semgrep, run_bandit, run_secrets, run_depaudit, run_codeql  # noqa: E402


def detect_lang(target: str) -> str:
    p = Path(target)
    has_py = any(p.rglob("*.py"))
    has_js = any(p.rglob("*.js")) or any(p.rglob("*.ts"))
    if has_py and has_js:
        return "auto"
    return "python" if has_py else ("javascript" if has_js else "auto")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    ap.add_argument("--lang", default="auto")
    ap.add_argument("--with-codeql", action="store_true")
    ap.add_argument("--local-only", action="store_true", help="semgrep custom rules only (offline)")
    args = ap.parse_args()

    lang = detect_lang(args.target) if args.lang == "auto" else args.lang
    print(f"== static scan: {args.target}  (lang={lang}) ==")
    print(f"   outputs -> {C.scandir(args.target)}")

    run_semgrep.run_semgrep(args.target, lang, args.local_only)
    if lang in ("python", "auto"):
        run_bandit.run_bandit(args.target)
    run_depaudit.run_depaudit(args.target)
    run_secrets.run_secrets(args.target)
    if args.with_codeql:
        for lg in (["python", "javascript"] if lang == "auto" else [lang]):
            run_codeql.run_codeql(args.target, lg)

    print(f"\nDone. Next: python correlate/merge.py {args.target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
