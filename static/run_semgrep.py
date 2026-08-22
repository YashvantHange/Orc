#!/usr/bin/env python3
"""
run_semgrep.py — multi-language Semgrep scan -> SARIF + normalized JSON.

Registry packs (need network) selected by language, PLUS our custom rules/ai-tools.yml.
Lesson baked in: custom multi-language rules only declare languages whose *syntax* they use,
else Semgrep silently drops the rule.

  python static/run_semgrep.py <target> [--lang python|javascript|typescript|auto]
                                          [--local-only]   # skip registry packs (offline)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402

PACKS = {
    "python": ["p/python", "p/security-audit", "p/flask", "p/django",
               "p/command-injection", "p/jwt", "p/secrets"],
    "javascript": ["p/javascript", "p/nodejs", "p/react", "p/xss"],
    "typescript": ["p/typescript", "p/javascript", "p/nodejs", "p/react", "p/xss"],
}
CUSTOM = C.ROOT / "rules" / "ai-tools.yml"


def run_semgrep(target: str, lang: str = "auto", local_only: bool = False) -> Path:
    tool = C.find_tool("semgrep")
    out = C.scandir(target) / "semgrep.sarif"
    if not tool:
        print("  semgrep not found (pip install -r requirements.txt)"); _empty_sarif(out); return out

    configs = ["--config", str(CUSTOM)]
    if not local_only:
        langs = PACKS.keys() if lang == "auto" else [lang]
        for lg in langs:
            for pack in PACKS.get(lg, []):
                configs += ["--config", pack]

    excludes = []
    for d in C.EXCLUDE_DIRS:
        excludes += ["--exclude", d]
    cmd = [tool, "scan", *configs, *excludes, "--sarif", "--output", str(out),
           "--metrics", "off", "--quiet", "--no-git-ignore", str(target)]
    print(f"  semgrep: {len(configs)//2} configs -> {out.name}")
    code, _, err = C.run(cmd, timeout=1800)
    if not out.exists():
        print(f"  semgrep failed (exit {code}): {err.strip()[:200]}")
        _empty_sarif(out)
    findings = C.load_sarif(out, "semgrep")
    C.write_json(C.scandir(target) / "semgrep.json", findings)
    print(f"  semgrep: {len(findings)} findings")
    return out


def _empty_sarif(path: Path) -> None:
    path.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    ap.add_argument("--lang", default="auto")
    ap.add_argument("--local-only", action="store_true")
    args = ap.parse_args()
    run_semgrep(args.target, args.lang, args.local_only)
    return 0


if __name__ == "__main__":
    sys.exit(main())
