#!/usr/bin/env python3
"""
run_codeql.py — CodeQL dataflow/taint scan -> SARIF (opt-in; the deepest engine).

This is the primary engine for the n8n-class logic/authz bugs: CodeQL models taint from
request params to dangerous sinks and (with custom queries) "param -> query without authz
guard" — paths that pattern rules cannot express. Heavy: builds a DB per language.

  python static/run_codeql.py <target> --lang python
  python static/run_codeql.py <target> --lang javascript   # covers TS too
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402

SUITES = {
    "python": "python-security-and-quality.qls",
    "javascript": "javascript-security-and-quality.qls",
    "typescript": "javascript-security-and-quality.qls",
}


def run_codeql(target: str, lang: str) -> Path:
    out = C.scandir(target) / f"codeql-{lang}.sarif"
    tool = C.find_tool("codeql")
    if not tool:
        print("  codeql not found — run: python tools/install_tools.py --with-codeql")
        out.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8"); return out

    db = C.workdir(target) / f"codeql-db-{lang}"
    if db.exists():
        shutil.rmtree(db, ignore_errors=True)
    cq_lang = "javascript" if lang in ("javascript", "typescript") else lang

    print(f"  codeql: building {cq_lang} database (slow) …")
    code, _, err = C.run([tool, "database", "create", str(db),
                          f"--language={cq_lang}", f"--source-root={target}",
                          "--overwrite"], timeout=3600)
    if code != 0 or not db.exists():
        print(f"  codeql db build failed: {err.strip()[:200]}")
        out.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8"); return out

    # include our custom queries dir if any exist
    queries = [SUITES.get(lang, SUITES["python"])]
    custom = C.ROOT / "rules" / "codeql"
    if any(custom.glob("*.ql")):
        queries.append(str(custom))

    print("  codeql: analyzing …")
    C.run([tool, "database", "analyze", str(db), *queries,
           "--format=sarif-latest", f"--output={out}", "--rerun"], timeout=3600)
    if not out.exists():
        out.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
    findings = C.load_sarif(out, "codeql")
    C.write_json(C.scandir(target) / f"codeql-{lang}.json", findings)
    print(f"  codeql: {len(findings)} findings")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    ap.add_argument("--lang", default="python", choices=["python", "javascript", "typescript"])
    args = ap.parse_args()
    run_codeql(args.target, args.lang)
    return 0


if __name__ == "__main__":
    sys.exit(main())
