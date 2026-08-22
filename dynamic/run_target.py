#!/usr/bin/env python3
"""
run_target.py — launch a target locally and hold it up for interactive probing.

Writes the live base URL to work/<slug>/dynamic/target.json so probe.py / authz_diff.py
can attach with --url. Holds until --seconds elapses or you Ctrl-C.

LOCAL BY CONSTRUCTION: launches software you cloned yourself on 127.0.0.1. A live authorized host is
reached with `--url` + a scope.yml instead (dynamic/scope.py), never launched.

  python dynamic/run_target.py work/_selftest/py_app --seconds 120
  # then, in the agent / another shell:
  python dynamic/probe.py --url <printed-url> --selftest
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "static"))
from instrument import TargetProcess  # noqa: E402
import _common as C  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    ap.add_argument("--entry", help="entrypoint (app.py / server.js / npm start auto-detected)")
    ap.add_argument("--port", type=int)
    ap.add_argument("--seconds", type=int, default=300, help="how long to hold the target up")
    args = ap.parse_args()

    with TargetProcess(args.target, args.port, args.entry) as t:
        d = C.workdir(args.target) / "dynamic"
        d.mkdir(parents=True, exist_ok=True)
        state = {"base_url": t.base_url, "kind": t.kind, "pid": t.proc.pid,
                 "log": str(t.log_path)}
        (d / "target.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
        print(f"UP  {t.base_url}  (kind={t.kind}, pid={t.proc.pid})")
        print(f"    log: {t.log_path}")
        print(f"    attach: python dynamic/probe.py --url {t.base_url} --selftest")
        print(f"    holding for {args.seconds}s (Ctrl-C to stop early) …")
        try:
            time.sleep(args.seconds)
        except KeyboardInterrupt:
            print("\nstopping …")
    print("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
