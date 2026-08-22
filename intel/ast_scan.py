#!/usr/bin/env python3
"""
ast_scan.py — accurate, multi-language attack-surface extraction (NOT grep).

Python is parsed with the stdlib `ast`; JS/TS with Tree-sitter (prebuilt wheels via
`tree-sitter-languages`, no native build). Emits located "signals" — (file, line,
category, name) — that both intel scoring and the hunting agents consume as leads.

Categories: endpoint, auth, deserialize, exec, cmd, path, http, template, jwt, xss,
parser, plugin. Grep would match `pickle.load` inside a string or comment; AST won't.

CLI:
  python intel/ast_scan.py <path> [--lang python|javascript|typescript|auto] [--json]
  python intel/ast_scan.py <path> --summary        # just the category counts
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
import warnings
from collections import Counter

# tree-sitter-languages 1.10.2 uses the deprecated Language(path, name) ctor -> noisy warning
warnings.filterwarnings("ignore", category=FutureWarning, module="tree_sitter")
from dataclasses import dataclass, asdict
from pathlib import Path

# ---- callee name -> category (shared across languages) --------------------------------
SINK_CATEGORY = {
    # deserialization / RCE
    "pickle.load": "deserialize", "pickle.loads": "deserialize",
    "joblib.load": "deserialize", "torch.load": "deserialize",
    "marshal.loads": "deserialize", "yaml.load": "deserialize",
    "dill.load": "deserialize", "dill.loads": "deserialize",
    # code exec
    "eval": "exec", "exec": "exec", "compile": "exec",
    "Function": "exec", "vm.runInContext": "exec", "vm.runInNewContext": "exec",
    # command exec
    "os.system": "cmd", "os.popen": "cmd",
    "subprocess.run": "cmd", "subprocess.call": "cmd", "subprocess.Popen": "cmd",
    "subprocess.check_output": "cmd", "subprocess.check_call": "cmd",
    "execSync": "cmd", "exec": "cmd", "spawn": "cmd", "spawnSync": "cmd", "execFile": "cmd",
    # path handling
    "open": "path", "send_file": "path", "send_from_directory": "path",
    "readFile": "path", "readFileSync": "path", "createReadStream": "path",
    "tarfile.open": "path", "extractall": "path",
    # http clients (SSRF surface)
    "requests.get": "http", "requests.post": "http", "requests.request": "http",
    "urllib.request.urlopen": "http", "httpx.get": "http", "httpx.post": "http",
    "fetch": "http", "axios.get": "http", "axios.post": "http",
    # templates (SSTI)
    "render_template_string": "template", "Template": "template",
    # jwt
    "jwt.decode": "jwt", "jwt.encode": "jwt", "jwt.sign": "jwt", "jwt.verify": "jwt",
}
# member/attribute names that indicate XSS sinks in JS/TS
XSS_MEMBERS = {"innerHTML", "outerHTML", "dangerouslySetInnerHTML"}
# route-registration methods
ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "route", "options", "head"}
AUTH_HINTS = ("login", "auth", "token", "jwt", "session", "cors", "password",
              "credential", "permission", "role", "rbac", "authorize", "authenticate")


@dataclass
class Signal:
    file: str
    line: int
    category: str
    name: str
    lang: str


# ---------------------------------------------------------------------------- python ---
def _py_callee(node: ast.AST) -> str | None:
    """Dotted callee name for a Call node's func, e.g. pickle.loads / app.get / open."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    if not parts:
        return None
    return ".".join(reversed(parts))


def scan_python(path: Path, root: Path) -> list[Signal]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except (SyntaxError, ValueError):
        return []
    rel = str(path.relative_to(root))
    out: list[Signal] = []

    for node in ast.walk(tree):
        # route decorators: @app.route / @app.get / @router.post ...
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                callee = _py_callee(target) if isinstance(target, (ast.Attribute, ast.Name)) else None
                if callee and callee.split(".")[-1] in ROUTE_METHODS:
                    out.append(Signal(rel, node.lineno, "endpoint", callee, "python"))
                if any(h in node.name.lower() for h in AUTH_HINTS):
                    out.append(Signal(rel, node.lineno, "auth", node.name, "python"))
        # calls to known sinks
        if isinstance(node, ast.Call):
            callee = _py_callee(node.func)
            if not callee:
                continue
            last = callee.split(".")[-1]
            cat = SINK_CATEGORY.get(callee) or SINK_CATEGORY.get(last)
            # yaml.load is only dangerous without SafeLoader
            if callee == "yaml.load":
                kws = {k.arg for k in node.keywords}
                if "Loader" in kws:
                    cat = None
            if cat:
                out.append(Signal(rel, node.lineno, cat, callee, "python"))
    return out


# ------------------------------------------------------------------------- js / ts -----
_TS_PARSERS: dict = {}


def _get_ts_parser(lang: str):
    if lang in _TS_PARSERS:
        return _TS_PARSERS[lang]
    try:
        from tree_sitter_languages import get_parser
        p = get_parser(lang)
    except Exception:  # noqa: BLE001 — tree-sitter optional; caller warns once
        p = None
    _TS_PARSERS[lang] = p
    return p


def _node_text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def scan_js(path: Path, root: Path, lang: str = "javascript") -> list[Signal]:
    parser = _get_ts_parser(lang)
    if parser is None:
        return []
    src = path.read_bytes()
    tree = parser.parse(src)
    rel = str(path.relative_to(root))
    out: list[Signal] = []

    def _has_interpolation(node) -> bool:
        # true if the subtree contains a template literal with `${...}` substitution
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "template_substitution":
                return True
            stack.extend(n.children)
        return False

    def walk(node):
        t = node.type
        if t == "call_expression":
            fn = node.child_by_field_name("function")
            if fn is not None:
                callee = _node_text(fn, src)
                last = callee.split(".")[-1].split("(")[0]
                # route registration: app.get( / router.post(
                if last in ROUTE_METHODS and "." in callee:
                    out.append(Signal(rel, fn.start_point[0] + 1, "endpoint", callee, lang))
                cat = SINK_CATEGORY.get(callee) or SINK_CATEGORY.get(last)
                if cat:
                    out.append(Signal(rel, fn.start_point[0] + 1, cat, callee, lang))
                if any(h in callee.lower() for h in AUTH_HINTS):
                    out.append(Signal(rel, fn.start_point[0] + 1, "auth", callee, lang))
                # reflected XSS: interpolated template literal into a response writer
                if last in ("send", "write", "end"):
                    args = node.child_by_field_name("arguments")
                    if args is not None and _has_interpolation(args):
                        out.append(Signal(rel, fn.start_point[0] + 1, "xss", f"{callee}(``)", lang))
        elif t in ("member_expression", "assignment_expression"):
            txt = _node_text(node, src)
            for member in XSS_MEMBERS:
                if txt.split(".")[-1].startswith(member) or member in txt.split("=")[0]:
                    out.append(Signal(rel, node.start_point[0] + 1, "xss", member, lang))
                    break
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    # de-dup identical (line, category, name)
    seen, uniq = set(), []
    for s in out:
        key = (s.line, s.category, s.name)
        if key not in seen:
            seen.add(key); uniq.append(s)
    return uniq


# --------------------------------------------------------------------------- driver ----
PY_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".mjs", ".cjs"}
TS_EXT = {".ts", ".tsx"}
SKIP_DIRS = {"node_modules", ".git", ".venv", ".dynvenv", "venv", "env", "dist", "build",
             "__pycache__", "site-packages", ".tox", "vendor", "third_party",
             "test", "tests", "__tests__"}


def scan_repo(root: Path, langs: set[str] | None = None) -> dict:
    root = root.resolve()
    signals: list[Signal] = []
    loc = 0
    ts_missing = False
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        ext = path.suffix.lower()
        try:
            if ext in PY_EXT and (not langs or "python" in langs):
                loc += _count_lines(path)
                signals += scan_python(path, root)
            elif ext in JS_EXT and (not langs or {"javascript"} & (langs or {"javascript"})):
                loc += _count_lines(path)
                s = scan_js(path, root, "javascript")
                if not s and _get_ts_parser("javascript") is None:
                    ts_missing = True
                signals += s
            elif ext in TS_EXT and (not langs or {"typescript", "javascript"} & (langs or {"typescript"})):
                loc += _count_lines(path)
                s = scan_js(path, root, "typescript")
                if not s and _get_ts_parser("typescript") is None:
                    ts_missing = True
                signals += s
        except Exception:  # noqa: BLE001 — one bad file shouldn't kill the scan
            continue

    counts = Counter(s.category for s in signals)
    return {
        "root": str(root),
        "loc": loc,
        "counts": dict(counts),
        "n_signals": len(signals),
        "signals": [asdict(s) for s in signals],
        "tree_sitter_available": not ts_missing,
    }


def _count_lines(path: Path) -> int:
    try:
        return sum(1 for _ in path.open("r", encoding="utf-8", errors="replace"))
    except OSError:
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path")
    ap.add_argument("--lang", default="auto",
                    help="python | javascript | typescript | auto (default)")
    ap.add_argument("--json", action="store_true", help="emit full signal list as JSON")
    ap.add_argument("--summary", action="store_true", help="just category counts")
    args = ap.parse_args()

    langs = None if args.lang == "auto" else {args.lang}
    result = scan_repo(Path(args.path), langs)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    print(f"root: {result['root']}")
    print(f"LOC: {result['loc']:,}   signals: {result['n_signals']}")
    if not result["tree_sitter_available"]:
        print("  (note: tree-sitter-languages not installed — JS/TS not parsed; "
              "run: pip install tree-sitter tree-sitter-languages)")
    print("attack-surface signals by category:")
    for cat, n in sorted(result["counts"].items(), key=lambda kv: -kv[1]):
        print(f"  {cat:12} {n}")
    if not args.summary and result["n_signals"]:
        print("\nsample locations:")
        for s in result["signals"][:25]:
            print(f"  {s['category']:11} {s['name']:28} {s['file']}:{s['line']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
