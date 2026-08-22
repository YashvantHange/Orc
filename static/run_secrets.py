#!/usr/bin/env python3
"""
run_secrets.py — gitleaks secrets scan over the full git history -> SARIF.

Exposed secrets need PRIVATE disclosure + rotation — never post them publicly.

  python static/run_secrets.py <target>   # target is a local dir (a git clone ideally)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402


def run_secrets(target: str) -> Path:
    tool = C.find_tool("gitleaks")
    out = C.scandir(target) / "gitleaks.sarif"
    if not tool:
        print("  gitleaks not found (python tools/install_tools.py)")
        out.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8"); return out
    src = Path(target)
    is_git = (src / ".git").exists()
    # `dir` scans the working tree; `git` walks history. Prefer history when available.
    mode = "git" if is_git else "dir"
    cfg = C.ROOT / "rules" / "gitleaks.toml"
    cmd = [tool, mode, str(src), "--report-format", "sarif",
           "--report-path", str(out), "--no-banner", "--exit-code", "0"]
    if cfg.exists():
        cmd += ["--config", str(cfg)]
    print(f"  gitleaks ({mode}) -> {out.name}")
    C.run(cmd, timeout=900)
    if not out.exists():
        out.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
    findings = C.load_sarif(out, "gitleaks")
    for f in findings:
        f.family = "secrets"
    C.write_json(C.scandir(target) / "gitleaks.json", findings)
    print(f"  gitleaks: {len(findings)} findings (verify + advise rotation; do not post)")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    args = ap.parse_args()
    run_secrets(args.target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
