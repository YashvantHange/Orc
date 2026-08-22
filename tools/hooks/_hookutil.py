#!/usr/bin/env python3
"""
_hookutil.py — shared plumbing for the delivery-gate hooks.

The hooks are the layer that makes the gate mandatory rather than advisory. Everything they do is
mechanical: read the hook payload, map a report file back to its finding, ask reports/gate.py whether
a valid receipt exists for the bytes on disk right now. No judgement here either.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def project_root() -> Path:
    """tools/hooks/_hookutil.py -> the repo root, without trusting cwd or an env var."""
    return Path(__file__).resolve().parent.parent.parent


ROOT = project_root()
for _s in (ROOT, ROOT / "reports", ROOT / "static", ROOT / "evidence"):
    sys.path.insert(0, str(_s))


def norm(path: str) -> Path:
    """Resolve a path that may have come from either shell on this machine.

    Git Bash reports MSYS paths (/c/Users/...), PowerShell reports C:\\Users\\... . Python resolves
    only the second, so an unnormalized MSYS path silently fails every relative_to() and the hook
    quietly decides it has nothing to check - a gate that fails open, which is the worst kind.
    """
    p = str(path or "").strip().strip('"')
    m = re.match(r"^/([A-Za-z])/(.*)$", p)
    if m:
        p = f"{m.group(1).upper()}:/{m.group(2)}"
    try:
        return Path(p).resolve()
    except OSError:
        return Path(p)


def rel_to_root(path: str) -> str:
    """Repo-relative, forward-slashed - the form used as a key everywhere in this package."""
    p = norm(path)
    try:
        return str(p.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(p).replace("\\", "/")


def read_payload() -> dict:
    try:
        raw = sys.stdin.read()
        return json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, OSError):
        return {}


def ledger() -> list:
    try:
        return json.loads((ROOT / "state" / "ledger.json").read_text(encoding="utf-8")
                          ).get("findings", [])
    except (OSError, json.JSONDecodeError):
        return []


def finding_for_report(path: str) -> str:
    """Map a report file back to its finding id via the ledger, falling back to the filename.

    The fallback matters: a report drafted before `hunt ledger add` has no record yet, and a hook
    that silently found nothing would wave it through.
    """
    rel = rel_to_root(path)
    for f in ledger():
        rp = str(f.get("report_path", "")).replace("\\", "/")
        if rp and (rp == rel or rel.endswith(rp)):
            return f.get("finding_id", "")
    import re
    m = re.search(r"\b((?:F|W|A|OHC|QD|JHUB)[-_]?\d{2,4})\b", Path(path).name, re.IGNORECASE)
    return m.group(1).upper().replace("_", "-") if m else ""


def is_report(path: str) -> bool:
    """A disclosure report under reports/, not the template and not a helper script."""
    if not path:
        return False
    np = norm(path)
    if np.suffix.lower() != ".md":
        return False
    try:
        rel = np.relative_to(ROOT)
    except ValueError:
        return "/reports/" in str(np).replace("\\", "/")
    parts = rel.parts
    return len(parts) >= 2 and parts[0] == "reports" and rel.name != "TEMPLATE.md"


def waiver_path(fid: str) -> Path:
    return ROOT / "state" / "gate" / f"{fid}.waived.json"


def is_waived(fid: str, report_sha: str) -> bool:
    """A waiver says 'this draft is NOT being delivered'. It is bound to the report's bytes, so it
    lapses the moment the draft is edited again, and it never authorizes a submission."""
    p = waiver_path(fid)
    if not p.exists():
        return False
    try:
        w = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    return bool(w.get("reason")) and w.get("report_sha256") == report_sha


def session_file(session_id: str) -> Path:
    d = ROOT / "state" / "session"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{(session_id or 'unknown')[:64]}.json"


def touch_report(session_id: str, path: str) -> None:
    p = session_file(session_id)
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        doc = {"reports": []}
    rel = rel_to_root(path)
    if rel not in doc["reports"]:
        doc["reports"].append(rel)
        p.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def touched_reports(session_id: str) -> list:
    try:
        return json.loads(session_file(session_id).read_text(encoding="utf-8")).get("reports", [])
    except (OSError, json.JSONDecodeError):
        return []


def emit(obj: dict, code: int = 0) -> int:
    print(json.dumps(obj))
    return code
