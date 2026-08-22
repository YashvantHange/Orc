#!/usr/bin/env python3
"""
install_tools.py - fetch the binary "muscle" SAST tools the pip layer can't provide.

Downloads Windows (or Linux, if run under WSL) builds of:
  - gitleaks       (secrets scanning)
  - osv-scanner    (dependency vulnerability scanning, npm + more)
  - CodeQL CLI     (dataflow/taint engine, python + javascript packs)  [--with-codeql]

Binaries land in tools/bin/ (gitignored). Re-running is idempotent (skips present tools).

Usage:
  python tools/install_tools.py              # gitleaks + osv-scanner
  python tools/install_tools.py --with-codeql  # also the (large ~500MB) CodeQL bundle
  python tools/install_tools.py --check      # just report what's installed

Note: uses the public GitHub releases API. If you hit rate limits, set GITHUB_TOKEN.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

BIN = Path(__file__).resolve().parent / "bin"
BIN.mkdir(parents=True, exist_ok=True)

IS_WINDOWS = platform.system().lower().startswith("win")
EXE = ".exe" if IS_WINDOWS else ""


def _api(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "sec-pipeline-installer"})
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())


def _download(url: str, dest: Path) -> Path:
    print(f"  v {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "sec-pipeline-installer"})
    with urllib.request.urlopen(req, timeout=300) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)
    return dest


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _pick_asset(assets: list[dict], must_include: list[str], any_of: list[str]) -> dict | None:
    for a in assets:
        name = a["name"].lower()
        if all(m in name for m in must_include) and any(o in name for o in any_of):
            return a
    return None


def _extract(archive: Path, want_basename: str, out: Path) -> bool:
    """Extract the first member whose basename starts with want_basename into out."""
    def _match(member_name: str) -> bool:
        base = os.path.basename(member_name).lower()
        return base.startswith(want_basename.lower())

    if archive.suffix == ".zip" or zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            for m in z.namelist():
                if _match(m):
                    with z.open(m) as src, open(out, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    return True
    else:  # tar.gz
        with tarfile.open(archive) as t:
            for m in t.getmembers():
                if m.isfile() and _match(m.name):
                    src = t.extractfile(m)
                    with open(out, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    return True
    return False


def _mark_executable(p: Path) -> None:
    if not IS_WINDOWS:
        p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def install_gitleaks() -> None:
    target = BIN / f"gitleaks{EXE}"
    if target.exists():
        print("gitleaks: already installed"); return
    print("gitleaks: fetching latest release ...")
    rel = _api("https://api.github.com/repos/gitleaks/gitleaks/releases/latest")
    plat = "windows" if IS_WINDOWS else "linux"
    asset = _pick_asset(rel["assets"], [plat], ["x64", "amd64"])
    if not asset:
        print("  !! no matching gitleaks asset found"); return
    tmp = BIN / asset["name"]
    _download(asset["browser_download_url"], tmp)
    print(f"  sha256={_sha256(tmp)[:16]}...")
    if _extract(tmp, "gitleaks", target):
        _mark_executable(target); print(f"  installed -> {target}")
    tmp.unlink(missing_ok=True)


def install_osv_scanner() -> None:
    target = BIN / f"osv-scanner{EXE}"
    if target.exists():
        print("osv-scanner: already installed"); return
    print("osv-scanner: fetching latest release ...")
    rel = _api("https://api.github.com/repos/google/osv-scanner/releases/latest")
    plat = "windows" if IS_WINDOWS else "linux"
    # osv-scanner ships bare executables named e.g. osv-scanner_windows_amd64.exe
    asset = _pick_asset(rel["assets"], [plat], ["amd64", "x86_64"])
    if not asset:
        print("  !! no matching osv-scanner asset found"); return
    tmp = BIN / asset["name"]
    _download(asset["browser_download_url"], tmp)
    print(f"  sha256={_sha256(tmp)[:16]}...")
    if tmp.suffix in (".zip", ".gz") or zipfile.is_zipfile(tmp):
        _extract(tmp, "osv-scanner", target); tmp.unlink(missing_ok=True)
    else:  # bare exe
        tmp.rename(target)
    _mark_executable(target)
    print(f"  installed -> {target}")


def install_codeql() -> None:
    target = BIN / "codeql" / f"codeql{EXE}"
    if target.exists():
        print("codeql: already installed"); return
    print("codeql: fetching latest bundle (large, ~500MB) ...")
    rel = _api("https://api.github.com/repos/github/codeql-action/releases/latest")
    plat = "win64" if IS_WINDOWS else "linux64"
    asset = _pick_asset(rel["assets"], ["codeql-bundle", plat], [".tar.gz", ".zip"])
    if not asset:
        asset = _pick_asset(rel["assets"], ["codeql-bundle"], [".tar.gz"])  # generic bundle
    if not asset:
        print("  !! no codeql bundle asset found"); return
    tmp = BIN / asset["name"]
    _download(asset["browser_download_url"], tmp)
    print("  extracting bundle ...")
    with tarfile.open(tmp) as t:
        t.extractall(BIN)  # unpacks to tools/bin/codeql/
    tmp.unlink(missing_ok=True)
    if target.exists():
        _mark_executable(target)
        print(f"  installed -> {target}")
    else:
        print("  !! codeql binary not found after extraction - check tools/bin/codeql/")


def check() -> None:
    print("Installed binary tools (tools/bin/):")
    for name in ("gitleaks", "osv-scanner"):
        p = BIN / f"{name}{EXE}"
        print(f"  {name:14} {'OK ' + str(p) if p.exists() else 'MISSING'}")
    cq = BIN / "codeql" / f"codeql{EXE}"
    print(f"  {'codeql':14} {'OK ' + str(cq) if cq.exists() else 'MISSING (run --with-codeql)'}")
    # npm/gh are expected on PATH already
    for name in ("npm", "gh", "git"):
        print(f"  {name:14} {'OK (PATH)' if shutil.which(name) else 'MISSING on PATH'}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--with-codeql", action="store_true", help="also install the CodeQL bundle")
    ap.add_argument("--check", action="store_true", help="report installed tools and exit")
    args = ap.parse_args()

    if args.check:
        check(); return 0

    try:
        install_gitleaks()
        install_osv_scanner()
        if args.with_codeql:
            install_codeql()
    except Exception as e:  # noqa: BLE001 - installer should fail loud but readable
        print(f"\n!! install error: {e}", file=sys.stderr)
        print("   (public GitHub API rate limit? set GITHUB_TOKEN and retry.)", file=sys.stderr)
        return 1
    print("\nDone.")
    check()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
