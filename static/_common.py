"""
_common.py — shared plumbing for the static-analysis runners.

Conventions:
  * every target (a local dir OR an owner/repo slug) gets a workdir:  work/<slug>/
  * scan outputs land in                                              work/<slug>/scan/
  * each tool writes SARIF where possible; findings are normalized to a common schema.

This is deterministic muscle — it *locates leads*, it does not decide what is a real bug.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
from dataclasses import dataclass, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "work"
BIN = ROOT / "tools" / "bin"

# dirs every scanner must skip — vendored deps / venvs / build output, not target source.
# (Scanning these swamps results with third-party findings.)
EXCLUDE_DIRS = [".dynvenv", ".venv", "venv", "env", "node_modules", ".git", "__pycache__",
                "site-packages", "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
                "vendor", "third_party"]
IS_WINDOWS = platform.system().lower().startswith("win")
EXE = ".exe" if IS_WINDOWS else ""
VENV_SCRIPTS = ROOT / ".venv" / ("Scripts" if IS_WINDOWS else "bin")


# Leaf directory names that identify a layout role, not a target. `work/lightrag/src` and
# `work/mlflow/src` both end in "src", so naming the workdir after the leaf silently merges every
# target's state into one bucket — including its evidence bundles.
_GENERIC_LEAF = {"src", "source", "sources", "web", "app", "dist", "build", "out", "repo",
                 "code", "js", "target", "main"}


def _distinguishing_name(t: str) -> str:
    """Walk up from a generic leaf to the nearest component that actually names a target.

    `work/lightrag/src` and `work/mlflow/src` both end in "src"; naming the workdir after the leaf
    merges every target's scan output, findings and evidence into one `work/src/` bucket. Only the
    generic-leaf case walks up, so a real target directory keeps its own name.
    """
    parts = [p for p in re.split(r"[\\/]+", t) if p not in ("", ".", "..")]
    for name in reversed(parts):
        if name.lower() not in _GENERIC_LEAF:
            return name
    return ""


def slug(target: str) -> str:
    """A filesystem-safe id for a target dir, owner/repo, or URL."""
    t = str(target).rstrip("/\\")
    if "/" in t and not Path(t).exists():        # looks like owner/repo or a URL
        s = t.replace("/", "__")
    else:
        s = Path(t).name or "target"
        if s.lower() in _GENERIC_LEAF:
            s = _distinguishing_name(str(Path(t).resolve())) or s
    # strip chars that are illegal in Windows paths (e.g. ':' from a URL hint)
    return re.sub(r'[:*?"<>|\s]', "_", s) or "target"


def is_url(target: str) -> bool:
    return bool(re.match(r"^https?://", str(target or ""), re.IGNORECASE))


def normalize_origin(url: str) -> str:
    """scheme://host[:port] — lowercased host, default port dropped, everything else discarded.

    Live-website state is keyed on the ORIGIN, never the full URL. Slugging a full URL would give
    /api/users and /api/items separate workdirs, fragmenting one host's profile, transcript and
    evidence across dozens of directories.
    """
    from urllib.parse import urlsplit
    u = urlsplit(str(url).strip())
    if not u.scheme or not u.hostname:
        raise ValueError(f"not an absolute http(s) URL: {url!r}")
    scheme = u.scheme.lower()
    host = u.hostname.lower()
    port = u.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def web_slug(url: str) -> str:
    """The workdir id for a live-website target. One host = one workdir."""
    return slug(normalize_origin(url))


def target_kind(target: str | None, src: str | None = None) -> str:
    """url (live host only) | src (local tree only) | grey (both — a host we can also read)."""
    has_url = bool(target and is_url(target))
    has_src = bool(src) or bool(target and not has_url)
    if has_url and has_src:
        return "grey"
    return "url" if has_url else "src"


def workdir(target: str) -> Path:
    d = WORK / (web_slug(target) if is_url(target) else slug(target))
    d.mkdir(parents=True, exist_ok=True)
    return d


def scandir(target: str) -> Path:
    d = workdir(target) / "scan"
    d.mkdir(parents=True, exist_ok=True)
    return d


def find_tool(name: str) -> str | None:
    """Locate a tool: venv Scripts first, then tools/bin, then PATH."""
    for cand in (VENV_SCRIPTS / f"{name}{EXE}", VENV_SCRIPTS / name,
                 BIN / f"{name}{EXE}", BIN / "codeql" / f"{name}{EXE}"):
        if cand.exists():
            return str(cand)
    return shutil.which(name)


# ---------------------------------------------------------------- normalized findings ---
@dataclass
class Finding:
    tool: str
    rule_id: str
    severity: str          # ERROR | WARNING | INFO
    message: str
    file: str
    line: int
    cwe: str = ""
    family: str = ""
    extra: dict | None = None

    def key(self) -> tuple:
        return (os.path.normpath(self.file).lower(), self.line, self.rule_id)


def _sev(level: str) -> str:
    return {"error": "ERROR", "warning": "WARNING", "note": "INFO",
            "high": "ERROR", "medium": "WARNING", "low": "INFO"}.get(
        (level or "").lower(), "WARNING")


def load_sarif(path: Path, tool: str) -> list[Finding]:
    """Parse a SARIF file into normalized Findings."""
    if not path.exists():
        return []
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    out: list[Finding] = []
    for run in doc.get("runs", []):
        # rule metadata (cwe/tags) indexed by ruleId
        rule_meta = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            tags = rule.get("properties", {}).get("tags", []) or []
            cwe = next((t for t in tags if "cwe" in t.lower()), "")
            rule_meta[rule.get("id", "")] = cwe
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            msg = (res.get("message", {}) or {}).get("text", "")
            level = res.get("level") or res.get("properties", {}).get("severity", "warning")
            for loc in res.get("locations", []) or [{}]:
                phys = (loc.get("physicalLocation", {}) or {})
                art = (phys.get("artifactLocation", {}) or {})
                region = (phys.get("region", {}) or {})
                cwe = rule_meta.get(rid, "")
                m = re.search(r"CWE[-_ ]?(\d+)", msg + " " + cwe)
                out.append(Finding(
                    tool=tool, rule_id=rid, severity=_sev(level), message=msg,
                    file=art.get("uri", ""), line=region.get("startLine", 0),
                    cwe=f"CWE-{m.group(1)}" if m else cwe,
                ))
    return out


def write_json(path: Path, findings: list[Finding]) -> None:
    path.write_text(json.dumps([asdict(f) for f in findings], indent=2), encoding="utf-8")


def run(cmd: list[str], **kw) -> tuple[int, str, str]:
    import subprocess
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    kw.setdefault("timeout", 1800)
    try:
        p = subprocess.run(cmd, **kw)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)
