#!/usr/bin/env python3
"""
install_tools.py - fetch the binary "muscle" SAST tools the pip layer can't provide.

Downloads Windows (or Linux, if run under WSL) builds of:
  - gitleaks       (secrets scanning)
  - osv-scanner    (dependency vulnerability scanning, npm + more)
  - CodeQL CLI     (dataflow/taint engine, python + javascript packs)  [--with-codeql]

  [--with-offensive] the web attack toolkit, for AUTHORIZED targets only:
  - ffuf           (content + parameter fuzzing)
  - nuclei         (templated vulnerability checks)
  - httpx          (fast HTTP probing)
  - subfinder      (subdomain enumeration)
  - mitmproxy      (scriptable intercepting proxy - the CLI answer to Burp)
  - sqlmap         (SQL injection exploitation)
  - jwt_tool       (JWT attack toolkit)
  nmap is detected, not installed: Windows needs an MSI + admin rights + Npcap.

Binaries land in tools/bin/ (gitignored). Re-running is idempotent (skips present tools).

Usage:
  python tools/install_tools.py                  # gitleaks + osv-scanner
  python tools/install_tools.py --with-codeql    # also the (large ~500MB) CodeQL bundle
  python tools/install_tools.py --with-offensive # also the web attack toolkit
  python tools/install_tools.py --check          # just report what's installed

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
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
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


# --------------------------------------------------------------------------------------
# Offensive web tooling (--with-offensive)
#
# These are for AUTHORIZED targets only - a host you booted yourself, or one a validated
# scope.yml places inside a published bug-bounty scope. Several are noisy by default; read
# the disclosure-ethics skill before pointing any of them at something you don't own.
# --------------------------------------------------------------------------------------

# name -> (github repo, binary basename inside the archive)
GH_RELEASE_TOOLS = {
    "ffuf":       ("ffuf/ffuf",                    "ffuf"),        # content/param fuzzing
    "nuclei":     ("projectdiscovery/nuclei",      "nuclei"),      # templated checks
    "httpx":      ("projectdiscovery/httpx",       "httpx"),       # fast HTTP probing
    "subfinder":  ("projectdiscovery/subfinder",   "subfinder"),   # subdomains
    "katana":     ("projectdiscovery/katana",      "katana"),      # crawler
    "dnsx":       ("projectdiscovery/dnsx",        "dnsx"),        # DNS toolkit (rebinding checks)
    "naabu":      ("projectdiscovery/naabu",       "naabu"),       # port scan - the installable nmap alternative
    "gobuster":   ("OJ/gobuster",                  "gobuster"),    # dir/dns/vhost brute force
    "amass":      ("owasp-amass/amass",            "amass"),       # attack-surface mapping
    "dalfox":     ("hahwul/dalfox",                "dalfox"),      # XSS scanner
    "trufflehog": ("trufflesecurity/trufflehog",   "trufflehog"),  # secrets, verified
}

# pip-installable, into the project venv (never system-wide).
# name -> (pip spec, console script to probe for).
#
# The probe is a CONSOLE SCRIPT, not `python -m <name>`. mitmproxy ships no __main__, so the old
# `python -m mitmproxy --version` probe always failed and the installer reinstalled it on every run
# - which mattered because that reinstall DOWNGRADES pyOpenSSL back to mitmproxy 11.0.2's declared
# pin (<=24.3.0), and 24.3.0 cannot import against cryptography 50 ("module 'lib' has no attribute
# 'GEN_EMAIL'"). The net effect was an installer that silently broke its own proxy each time it ran.
PIP_TOOLS = {
    "mitmproxy": ("mitmproxy", "mitmdump"),  # scriptable intercepting proxy - the CLI answer to Burp
    "sqlmap":    ("sqlmap", "sqlmap"),       # SQL injection exploitation
    "arjun":     ("arjun", "arjun"),         # HTTP parameter discovery
    "dirsearch": ("dirsearch", "dirsearch"), # path brute force
}

# How to ask a tool "are you alive". Not every tool answers --version: arjun exits 2 on it, and
# sqlmap ships NO console script and no __main__ at all (so both `sqlmap.exe` and `python -m sqlmap`
# fail) - it is a script under site-packages that has to be run with an interpreter. Probing every
# tool the same way produced two confident false MISSINGs.
PIP_PROBES = {
    "arjun": ["-h"],
}
PIP_SCRIPTS = {
    "sqlmap": (".venv/lib/site-packages/sqlmap/sqlmap.py", ["--batch", "--version"]),
}

# Upper pins a package declares that are wrong in practice, and what to force afterwards.
# Only for the case where the declared pin is itself the broken thing.
PIP_PIN_REPAIRS = {
    "mitmproxy": ["pyOpenSSL>=25.1.0"],
}

# repo -> entrypoint. Tools that ship as a source tree, not a release artifact.
GIT_TOOLS = {
    "jwt_tool":   ("https://github.com/ticarpi/jwt_tool.git",    "jwt_tool.py"),
    "commix":     ("https://github.com/commixproject/commix.git", "commix.py"),
    "nikto":      ("https://github.com/sullo/nikto.git",          "program/nikto.pl"),
    "testssl.sh": ("https://github.com/drwetter/testssl.sh.git",  "testssl.sh"),
}

# GUI or installer-based: detected, never fetched. Auto-installing these needs an MSI,
# admin rights, a JRE or a licence, none of which belong in an unattended script.
MANUAL_TOOLS = {
    "nmap": (
        ["nmap"],
        "https://nmap.org/download",
        "windows needs the MSI + admin + Npcap; linux: apt install nmap",
    ),
    "burpsuite": (
        ["burpsuite", "BurpSuiteCommunity", "BurpSuitePro"],
        "https://portswigger.net/burp/releases",
        "GUI proxy. Community has NO REST API and cannot be driven from an agent loop - "
        "only Professional/Enterprise expose one. Use mitmproxy or ZAP for automation.",
    ),
    "zap": (
        ["zap", "zap.sh", "zap.bat", "owasp-zap"],
        "https://www.zaproxy.org/download/",
        "needs a JRE. Unlike Burp Community it has a REST API and a headless daemon "
        "(-daemon -config api.key=...), so it IS drivable from an agent.",
    ),
    "wireshark": (
        ["tshark", "wireshark"],
        "https://www.wireshark.org/download.html",
        "tshark is the CLI half - use it, not the GUI, for capture in a hunt.",
    ),
}


def _venv_python() -> str:
    """The project venv interpreter if there is one, else whatever is running us."""
    cand = ROOT / ".venv" / ("Scripts" if IS_WINDOWS else "bin") / ("python.exe" if IS_WINDOWS else "python")
    return str(cand) if cand.exists() else sys.executable


def install_gh_release(name: str, repo: str, binary: str) -> None:
    """Install a single-binary tool from its GitHub releases page."""
    target = BIN / f"{binary}{EXE}"
    if target.exists():
        print(f"{name}: already installed"); return
    print(f"{name}: fetching latest release ...")
    rel = _api(f"https://api.github.com/repos/{repo}/releases/latest")
    plat = "windows" if IS_WINDOWS else "linux"
    asset = _pick_asset(rel["assets"], [plat], ["amd64", "x86_64", "x64"])
    if not asset:
        print(f"  !! no matching {name} asset found"); return
    tmp = BIN / asset["name"]
    _download(asset["browser_download_url"], tmp)
    print(f"  sha256={_sha256(tmp)[:16]}...")
    if _extract(tmp, binary, target):
        _mark_executable(target); print(f"  installed -> {target}")
    else:
        print(f"  !! {binary} not found inside {asset['name']}")
    tmp.unlink(missing_ok=True)


def _venv_script(binary: str) -> Path:
    """Path to a console script inside the project venv."""
    d = ROOT / ".venv" / ("Scripts" if IS_WINDOWS else "bin")
    return d / f"{binary}{EXE}"


def _pip_tool_ok(binary: str) -> bool:
    """Installed AND able to start. A tool whose entry point dies on import is not installed."""
    script = PIP_SCRIPTS.get(binary)
    if script:
        path, args = script
        full = ROOT / path
        if not full.exists():
            return False
        try:
            r = subprocess.run([_venv_python(), str(full)] + args,
                               capture_output=True, text=True, timeout=180)
            # sqlmap prints its version and then exits non-zero from its own teardown, so the
            # output is the signal here, not the return code.
            return bool((r.stdout or "").strip())
        except (OSError, subprocess.SubprocessError):
            return False

    exe = _venv_script(binary)
    if not exe.exists():
        return False
    try:
        return subprocess.run([str(exe)] + PIP_PROBES.get(binary, ["--version"]),
                              capture_output=True, text=True, timeout=120).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def install_pip_tool(name: str, spec: str, binary: str) -> None:
    """Install a python-based tool into the project venv, then repair any pin it got wrong."""
    py = _venv_python()
    if _pip_tool_ok(binary):
        print(f"{name}: already installed"); return
    print(f"{name}: pip install {spec} ...")
    r = subprocess.run([py, "-m", "pip", "install", "-q", spec], capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  !! pip install {spec} failed: {(r.stderr or '').strip().splitlines()[-1:]}")
        return

    for pin in PIP_PIN_REPAIRS.get(name, []):
        # pip prints a dependency-conflict warning here, and that warning is correct-but-wrong:
        # the DECLARED pin is the broken half. Resolving it by downgrading restores the crash.
        print(f"  repairing pin: {pin}")
        subprocess.run([py, "-m", "pip", "install", "-q", "--upgrade", pin],
                       capture_output=True, text=True)

    if _pip_tool_ok(binary):
        print(f"  installed -> {_venv_script(binary)}")
    else:
        print(f"  !! {name} installed but {binary} will not start - run it by hand to see why")


def install_git_tool(name: str, url: str, entry: str) -> None:
    """Some tools ship as a source tree, not a release artifact."""
    dest = BIN / name
    if (dest / entry).exists():
        print(f"{name}: already installed"); return
    git = shutil.which("git")
    if not git:
        print(f"{name}: !! git not on PATH"); return
    print(f"{name}: cloning ...")
    r = subprocess.run([git, "clone", "--depth", "1", url, str(dest)],
                       capture_output=True, text=True)
    if r.returncode == 0:
        print(f"  installed -> {dest / entry}")
    else:
        print(f"  !! clone failed: {(r.stderr or '').strip().splitlines()[-1:]}")


def report_manual(name: str, binaries: list[str], url: str, note: str) -> None:
    """Detect an installer- or GUI-based tool. Never fetch it."""
    found = next((shutil.which(b) for b in binaries if shutil.which(b)), None)
    if found:
        print(f"{name}: OK (PATH) {found}")
    else:
        print(f"{name}: not installed - {url}")
    print(f"      {note}")


def install_offensive() -> None:
    for name, (repo, binary) in GH_RELEASE_TOOLS.items():
        install_gh_release(name, repo, binary)
    for name, (spec, binary) in PIP_TOOLS.items():
        install_pip_tool(name, spec, binary)
    for name, (url, entry) in GIT_TOOLS.items():
        install_git_tool(name, url, entry)
    print("\nInstaller/GUI tools - detected only, install these yourself:")
    for name, (binaries, url, note) in MANUAL_TOOLS.items():
        report_manual(name, binaries, url, note)


def check() -> None:
    print("Installed binary tools (tools/bin/):")
    for name in ("gitleaks", "osv-scanner"):
        p = BIN / f"{name}{EXE}"
        print(f"  {name:14} {'OK ' + str(p) if p.exists() else 'MISSING'}")
    cq = BIN / "codeql" / f"codeql{EXE}"
    print(f"  {'codeql':14} {'OK ' + str(cq) if cq.exists() else 'MISSING (run --with-codeql)'}")

    print("Offensive web tools (--with-offensive):")
    for name, (_repo, binary) in GH_RELEASE_TOOLS.items():
        p = BIN / f"{binary}{EXE}"
        print(f"  {name:14} {'OK ' + str(p) if p.exists() else 'MISSING'}")
    py = _venv_python()
    for name, (_spec, binary) in PIP_TOOLS.items():
        ok = _pip_tool_ok(binary)
        where = (str(ROOT / PIP_SCRIPTS[binary][0]) if binary in PIP_SCRIPTS
                 else str(_venv_script(binary)))
        print(f"  {name:14} {'OK (venv) ' + where if ok else 'MISSING'}")
    for name, (_url, entry) in GIT_TOOLS.items():
        p = BIN / name / entry
        print(f"  {name:14} {'OK ' + str(p) if p.exists() else 'MISSING'}")

    print("Installer/GUI tools (install yourself):")
    for name, (binaries, url, _note) in MANUAL_TOOLS.items():
        found = next((shutil.which(b) for b in binaries if shutil.which(b)), None)
        print(f"  {name:14} {'OK (PATH) ' + found if found else 'MISSING - ' + url}")

    # npm/gh are expected on PATH already
    print("Expected on PATH:")
    for name in ("npm", "gh", "git"):
        print(f"  {name:14} {'OK (PATH)' if shutil.which(name) else 'MISSING on PATH'}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--with-codeql", action="store_true", help="also install the CodeQL bundle")
    ap.add_argument("--with-offensive", action="store_true",
                    help="also install ffuf, nuclei, httpx, subfinder, mitmproxy, sqlmap, jwt_tool")
    ap.add_argument("--check", action="store_true", help="report installed tools and exit")
    args = ap.parse_args()

    if args.check:
        check(); return 0

    try:
        install_gitleaks()
        install_osv_scanner()
        if args.with_codeql:
            install_codeql()
        if args.with_offensive:
            install_offensive()
    except Exception as e:  # noqa: BLE001 - installer should fail loud but readable
        print(f"\n!! install error: {e}", file=sys.stderr)
        print("   (public GitHub API rate limit? set GITHUB_TOKEN and retry.)", file=sys.stderr)
        return 1
    print("\nDone.")
    check()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
