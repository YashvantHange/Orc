#!/usr/bin/env python3
"""
jsintel.py — mine a site's own front-end build for its attack surface.

The highest-value ten minutes of a black-box hunt. A shipped `.map` with `sourcesContent` hands you
the original front-end sources, which turns a `url` target into `grey`: write them to
work/<slug>/web/js/src/ and the pipeline's existing static chain (`hunt scan`) produces real
`file:line` evidence for a target you never cloned.

Without a sourcemap the bundle is still the best endpoint inventory available — it lists routes the
UI never calls, role names, and every DOM-XSS source->sink pair worth testing.

Read-only. No payloads.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import urljoin, urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dynamic"))
sys.path.insert(0, str(ROOT / "static"))

# API call sites and route strings the build embedded
RE_ENDPOINT = re.compile(r"""["'`](/(?:api|graphql|v\d|admin|internal|_next/data)[A-Za-z0-9_\-/.{}$:]*)["'`]""")
RE_FETCH = re.compile(r"""(?:fetch|axios(?:\.\w+)?|\$\.(?:get|post|ajax)|request)\s*\(\s*["'`]([^"'`]+)""")
RE_METHOD_HINT = re.compile(r"""method\s*:\s*["'](\w+)["']""", re.I)

# client-side authorization checks — each is a server-side test to run as a lower role
RE_ROLE = re.compile(
    r"""(?:isAdmin|is_admin|isSuperuser|hasRole|hasPermission|can[A-Z]\w+|"""
    r"""role\s*===?\s*["'][\w.-]+["']|permissions?\s*\.\s*(?:includes|has|indexOf)\s*\(\s*["'][\w.:-]+["'])""")

# DOM XSS: sources and sinks. Pairing them per-file is enough to queue a browser check.
RE_DOM_SOURCE = re.compile(
    r"""location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer|baseURI)|"""
    r"""window\.name|localStorage\.getItem|sessionStorage\.getItem|(?:^|\W)event\.data""")
RE_DOM_SINK = re.compile(
    r"""\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(|"""
    r"""\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*["'`]|setInterval\s*\(\s*["'`]|"""
    r"""dangerouslySetInnerHTML|v-html|bypassSecurityTrust\w+|\$\(\s*[\w.]+\s*\)\.html\s*\(""")

RE_PM_LISTENER = re.compile(r"""addEventListener\s*\(\s*["']message["']""")
RE_PM_SEND = re.compile(r"""postMessage\s*\([^)]*,\s*["']\*["']""")
RE_PROTO_MERGE = re.compile(r"""\b(?:deepMerge|deepExtend|mergeDeep|extend|merge|set)\s*\(""")

# credential shapes worth flagging. gitleaks does the thorough pass over web/js/src/; this is the
# in-bundle triage so a live key isn't missed when no sourcemap exists.
SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("stripe-key", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("generic-assignment", re.compile(
        r"""(?i)\b(?:api[_-]?key|apikey|secret|password|passwd|token|client[_-]?secret)"""
        r"""["']?\s*[:=]\s*["']([A-Za-z0-9_\-!@#$%^&*+/=]{12,})["']""")),
]
# things that look like secrets but are meant to be public — flagging them wastes a reviewer's time
SECRET_FALSE_POSITIVES = re.compile(
    r"(?i)^(?:process\.env|import\.meta|undefined|null|true|false|xxx+|your[_-]?|example|placeholder|"
    r"changeme|<[^>]+>|\$\{)")


@dataclass
class BundleIntel:
    url: str
    local: str = ""
    size: int = 0
    sourcemap_url: str = ""
    sourcemap_local: str = ""
    sources_recovered: int = 0
    endpoints: list = field(default_factory=list)
    role_checks: list = field(default_factory=list)
    dom_pairs: list = field(default_factory=list)
    postmessage: list = field(default_factory=list)
    proto_merges: list = field(default_factory=list)
    secrets: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _ctx(text: str, pos: int, width: int = 90) -> str:
    """A single-line window around a match — bundles are minified into one enormous line, so slicing
    by character offset is the only way to show context."""
    lo, hi = max(0, pos - width // 2), min(len(text), pos + width // 2)
    return text[lo:hi].replace("\n", " ").strip()


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def analyze_source(text: str, name: str = "") -> dict:
    """Signals from one JS file (bundle or a recovered original)."""
    out: dict = {"endpoints": [], "role_checks": [], "dom_pairs": [], "postmessage": [],
                 "proto_merges": [], "secrets": []}

    seen = set()
    for rx in (RE_ENDPOINT, RE_FETCH):
        for m in rx.finditer(text):
            path = m.group(1)
            if not path.startswith("/") or path in seen or len(path) > 200:
                continue
            seen.add(path)
            window = text[m.end():m.end() + 120]
            mh = RE_METHOD_HINT.search(window)
            out["endpoints"].append({"path": path, "method": (mh.group(1).upper() if mh else "GET"),
                                     "file": name, "line": _line_of(text, m.start()),
                                     "source": "jsbundle"})

    for m in RE_ROLE.finditer(text):
        out["role_checks"].append({"check": m.group(0)[:80], "file": name,
                                   "line": _line_of(text, m.start()), "context": _ctx(text, m.start())})

    # A source and a sink in the same file is the queue entry; proving the flow is the browser's job.
    sources = [(m.group(0), m.start()) for m in RE_DOM_SOURCE.finditer(text)]
    sinks = [(m.group(0), m.start()) for m in RE_DOM_SINK.finditer(text)]
    if sources and sinks:
        for s_name, s_pos in sources[:20]:
            near = min(sinks, key=lambda k: abs(k[1] - s_pos))
            out["dom_pairs"].append({
                "source": s_name.strip(), "sink": near[0].strip(), "file": name,
                "line": _line_of(text, s_pos), "distance_chars": abs(near[1] - s_pos),
                "context": _ctx(text, s_pos, 140)})

    for m in RE_PM_LISTENER.finditer(text):
        # the origin check, if any, is within the first few hundred chars of the handler
        body = text[m.end():m.end() + 400]
        checked = bool(re.search(r"\.origin\s*(?:===?|!==?|\.(?:startsWith|includes|match|indexOf))", body))
        out["postmessage"].append({"kind": "listener", "origin_checked": checked, "file": name,
                                   "line": _line_of(text, m.start()), "context": _ctx(text, m.end(), 200)})
    for m in RE_PM_SEND.finditer(text):
        out["postmessage"].append({"kind": "send-wildcard-target", "origin_checked": False,
                                   "file": name, "line": _line_of(text, m.start()),
                                   "context": _ctx(text, m.start(), 140)})

    if "__proto__" in text or "constructor.prototype" in text:
        for m in RE_PROTO_MERGE.finditer(text):
            out["proto_merges"].append({"fn": m.group(0), "file": name,
                                        "line": _line_of(text, m.start()),
                                        "context": _ctx(text, m.start())})

    for label, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            val = m.group(1) if m.groups() else m.group(0)
            if SECRET_FALSE_POSITIVES.match(val or ""):
                continue
            out["secrets"].append({
                "type": label, "file": name, "line": _line_of(text, m.start()),
                # never write the full value to disk — the report quotes a prefix and redacts the rest
                "value_prefix": (val or "")[:4] + "<REDACTED>", "length": len(val or ""),
                "context": _ctx(text, m.start())})

    return out


def _safe_join(base: Path, rel: str) -> Path | None:
    """Sourcemap `sources` entries are attacker-adjacent data (whoever built the bundle chose them),
    and they routinely contain ../ and webpack:// prefixes. Resolve and confine."""
    rel = re.sub(r"^(?:webpack|rollup|vite)://+", "", rel or "")
    rel = rel.replace("\\", "/").lstrip("/")
    rel = re.sub(r"^(?:\.\./)+", "", rel)
    if not rel or rel in (".", ".."):
        return None
    p = (base / rel).resolve()
    try:
        p.relative_to(base.resolve())
    except ValueError:
        return None
    return p


def fetch_sourcemap(sess, bundle_url: str, text: str, out_dir: Path) -> tuple[str, str, int]:
    """Return (sourcemap_url, local_path, sources_recovered). Writes originals under out_dir/src/."""
    m = re.search(r"//[#@]\s*sourceMappingURL=([^\s*]+)", text[-2000:] or text)
    if not m:
        return "", "", 0
    ref = m.group(1).strip()
    if ref.startswith("data:"):
        return "data:", "", 0
    map_url = urljoin(bundle_url, ref)
    try:
        r = sess.get(map_url)
    except Exception:                                     # noqa: BLE001 - network/scope, either way no map
        return map_url, "", 0
    if r.status_code != 200:
        return map_url, "", 0
    try:
        doc = json.loads(r.text)
    except json.JSONDecodeError:
        return map_url, "", 0

    map_local = out_dir / (Path(urlsplit(map_url).path).name or "bundle.js.map")
    map_local.parent.mkdir(parents=True, exist_ok=True)
    map_local.write_text(r.text, encoding="utf-8")

    contents = doc.get("sourcesContent") or []
    names = doc.get("sources") or []
    src_root = out_dir / "src"
    n = 0
    for name, content in zip(names, contents):
        if not content:
            continue
        dest = _safe_join(src_root, name)
        if dest is None:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        n += 1
    return map_url, str(map_local), n


def analyze_bundle(sess, url: str, out_dir: Path) -> BundleIntel:
    intel = BundleIntel(url=url)
    try:
        r = sess.get(url)
    except Exception as e:                                # noqa: BLE001
        intel.endpoints = []
        return intel
    if r.status_code != 200 or not r.text:
        return intel
    text = r.text
    intel.size = len(text)

    out_dir.mkdir(parents=True, exist_ok=True)
    local = out_dir / (Path(urlsplit(url).path).name or "bundle.js")
    local.write_text(text, encoding="utf-8")
    intel.local = str(local)

    intel.sourcemap_url, intel.sourcemap_local, intel.sources_recovered = fetch_sourcemap(
        sess, url, text, out_dir)

    sig = analyze_source(text, name=local.name)
    # Recovered originals are far more readable than the minified bundle — re-run over them so the
    # reported file:line points at real source, which is the whole reason to pull the map.
    if intel.sources_recovered:
        for f in sorted((out_dir / "src").rglob("*")):
            if f.is_file() and f.suffix in (".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte"):
                try:
                    sub = analyze_source(f.read_text(encoding="utf-8", errors="replace"),
                                         name=str(f.relative_to(out_dir / "src")))
                except OSError:
                    continue
                for k in sig:
                    sig[k].extend(sub[k])

    for k, v in sig.items():
        setattr(intel, k, v)
    return intel


def summarize(bundles: list) -> dict:
    """Accepts BundleIntel objects or their dicts — recon.py has already serialized them."""
    total = {"bundles": len(bundles), "sources_recovered": 0, "endpoints": 0, "role_checks": 0,
             "dom_pairs": 0, "postmessage_unchecked": 0, "secrets": 0}
    for b in bundles:
        d = b if isinstance(b, dict) else b.to_dict()
        total["sources_recovered"] += d.get("sources_recovered", 0)
        for k in ("endpoints", "role_checks", "dom_pairs", "secrets"):
            total[k] += len(d.get(k) or [])
        total["postmessage_unchecked"] += sum(
            1 for p in (d.get("postmessage") or []) if not p.get("origin_checked"))
    return total
