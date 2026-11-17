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
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402
import run_semgrep, run_bandit, run_secrets, run_depaudit, run_codeql  # noqa: E402


#: extension -> language label, for languages NO scanner in this layer supports. semgrep's PACKS
#: has python/javascript/typescript only and CodeQL is driven with those two, so a tree in any of
#: these gets scanned to zero findings. Zero findings from a scanner that cannot read the language
#: is not a clean result, and reporting it as one is the silence `guardrails` forbids.
UNSUPPORTED_EXT = {
    ".c": "c", ".h": "c", ".cc": "c++", ".cpp": "c++", ".cxx": "c++", ".hpp": "c++",
    ".rs": "rust", ".go": "go", ".java": "java", ".kt": "kotlin", ".cs": "c#",
    ".rb": "ruby", ".php": "php", ".swift": "swift", ".m": "objective-c", ".scala": "scala",
}
SUPPORTED = ("python", "javascript", "typescript")


def survey(target: str) -> dict:
    """Count source files per language so the scan can say what it could NOT read.

    Skips C.EXCLUDE_DIRS. That matters more than it looks: `detect_lang` now picks the dominant
    language from this census, and a target's own `.dynvenv` holds hundreds of .py files - measured
    528 in work/_selftest/py_app after one instrumented boot. Counting vendored trees would let
    node_modules or a venv decide what language a project is written in.
    """
    skip = set(C.EXCLUDE_DIRS)
    counts: dict = {}
    for f in Path(target).rglob("*"):
        if not f.is_file():
            continue
        if skip.intersection(f.parts):
            continue
        ext = f.suffix.lower()
        if ext == ".py":
            counts["python"] = counts.get("python", 0) + 1
        elif ext in (".js", ".jsx", ".mjs", ".cjs"):
            counts["javascript"] = counts.get("javascript", 0) + 1
        elif ext in (".ts", ".tsx"):
            counts["typescript"] = counts.get("typescript", 0) + 1
        elif ext in UNSUPPORTED_EXT:
            lang = UNSUPPORTED_EXT[ext]
            counts[lang] = counts.get(lang, 0) + 1
    return counts


def detect_lang(target: str) -> str:
    """The tree's dominant language, from `survey`'s census rather than a second set of walks.

    It used to test only .py/.js/.ts and return "auto" for everything else - and "auto" is the most
    EXPANSIVE mode, not the most cautious: run_semgrep iterates every pack in PACKS and this file
    builds two CodeQL databases. So a pure C or PHP tree drew the whole Python+JS toolchain against
    source none of it parses: maximum cost, guaranteed zero findings, and a "0 findings" line that
    reads as clean.

    Naming the real language costs nothing and skips that. It does NOT add coverage for the named
    language - there is no scanner here that reads C - which is what the UNSUPPORTED banner below
    exists to say. Do not read a language name in this output as a language that was analysed.
    """
    counts = survey(target)
    if not counts:
        return "auto"
    py = counts.get("python", 0)
    js = counts.get("javascript", 0) + counts.get("typescript", 0)
    top, n = max(counts.items(), key=lambda kv: kv[1])
    # a genuinely mixed python+js tree keeps the historical "auto" meaning: scan both
    if py and js and max(py, js) >= n * 0.5:
        return "auto"
    # survey's labels are human ("c++", "c#"); the scanners want identifiers
    return {"c++": "cpp", "c#": "csharp", "objective-c": "objc"}.get(top, top)


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

    # Say out loud what this layer cannot read. A C/C++ tree used to scan to zero findings and
    # print nothing about it, so "0 findings" read as "clean" for a language no scanner here parses.
    counts = survey(args.target)
    unreadable = {k: v for k, v in counts.items() if k not in SUPPORTED}
    readable = {k: v for k, v in counts.items() if k in SUPPORTED}
    coverage = {"target": args.target, "lang": lang, "file_counts": counts,
                "unsupported_languages": sorted(unreadable),
                "static_coverage": "none" if unreadable and not readable
                                   else ("partial" if unreadable else "full")}
    if unreadable:
        top = ", ".join(f"{k} ({v} files)" for k, v in
                        sorted(unreadable.items(), key=lambda kv: -kv[1])[:4])
        print("")
        # ASCII only: this banner must survive a cp1252 console, which mangles an em dash.
        print("   !! UNSUPPORTED LANGUAGE - scanners contribute nothing; this is NOT a clean result")
        print(f"      unreadable here: {top}")
        print(f"      supported: {', '.join(SUPPORTED)} (semgrep PACKS + CodeQL)")
        if not readable:
            print("      every static verdict for this target is BLOCKED (no static coverage).")
        else:
            print(f"      readable: {', '.join(f'{k} ({v})' for k, v in readable.items())}"
                  " — the rest of the tree was not analysed by any engine.")
        print("      Read it by hand, and do not record CLEAR on the strength of a quiet scan.")
        print("")
    # Not C.write_json: that helper serialises a list of Finding dataclasses, not a plain dict.
    (C.scandir(args.target) / "language-coverage.json").write_text(
        json.dumps(coverage, indent=2), encoding="utf-8")

    run_semgrep.run_semgrep(args.target, lang, args.local_only)
    if lang in ("python", "auto"):
        run_bandit.run_bandit(args.target)
    run_depaudit.run_depaudit(args.target)
    run_secrets.run_secrets(args.target)
    if args.with_codeql:
        # Only the languages run_codeql has a query suite for. Its SUITES.get(lang, SUITES["python"])
        # would otherwise run the PYTHON suite against, say, a C database - a silently wrong answer,
        # and one detect_lang can now reach for the first time since it names real languages.
        wanted = ["python", "javascript"] if lang == "auto" else [lang]
        for lg in wanted:
            if lg in SUPPORTED:
                run_codeql.run_codeql(args.target, lg)
            else:
                print(f"  codeql: no query suite for {lg!r} - skipped (not a clean result)")

    print(f"\nDone. Next: python correlate/merge.py {args.target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
