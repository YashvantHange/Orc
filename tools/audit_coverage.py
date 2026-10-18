#!/usr/bin/env python3
"""
audit_coverage.py - find matrix rows that no verdict can ever reach.

`vuln-playbooks` says "didn't look" is not an allowed state: every applicable row must come back
HIT / CLEAR / N/A / BLOCKED. That rule assumes every row is REACHABLE by something - a primitive the
sweep targets, or an entry in MANUAL_ROWS that prints it as outstanding.

A row in neither is worse than a missing row. It never appears in `hunt web coverage` in any state,
so a hunt can report full coverage having never mentioned it, and the silence reads as safety. Same
defect shape as the old CLEAR fallthrough in web/sweep.py:verdict().

WHY THIS FILE IS A TABLE AND NOT A MATCHER. The first version scored row names against primitive
names by word similarity. It was wrong in both directions at every threshold tried: it called
`idor_enum` missing because the row says "Authorization flaws (IDOR/BOLA)", and it called
"MCP-surface auth" covered because `missing_auth` also contains the word "auth" - a false negative
on the exact row that motivated writing the tool. A coverage claim resting on string similarity is
the "plausible but unverified" thing `guardrails` forbids, so coverage is now asserted explicitly,
one row at a time, and each entry is checkable by opening the primitive it names.

    .venv/Scripts/python.exe tools/audit_coverage.py
    .venv/Scripts/python.exe tools/audit_coverage.py --strict   # exit 1 if any row is uncovered

Exit codes: 0 ok · 1 uncovered rows (--strict) · 2 could not parse.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MATRIX = ROOT / ".claude" / "skills" / "vuln-playbooks" / "SKILL.md"

# Non-probe stages that settle a row. Named so the exemption is a decision on the record.
RECON = "web-recon stage"
BROWSER = "browser stage"
STATIC = "static read (src)"
STRUCTURAL = "structural (own procedure)"

# Matrix row -> what settles it. A primitive name, a MANUAL_ROWS key, or one of the stages above.
# "" means NOTHING settles it: the row is in the matrix and unreachable.
COVERS = {
    # A. Access control & identity
    "Authorization flaws (IDOR/BOLA)": "idor_enum",
    "Missing function-level authz (BFLA)": "bfla_matrix",
    "Privilege escalation / role tampering": "bfla_matrix",
    "Cross-tenant access": "idor_enum",
    "Mass assignment / unsafe field binding": "mass_assignment",
    "HTTP method override": "method_override",
    "Authentication bypass": "missing_auth",
    "Trusted-header / local-gate bypass": "host_header",
    "Session fixation & lifecycle": "session_fixation",
    "Password reset flaws": "pwreset_token",
    "MFA bypass": "MFA bypass",
    "OAuth / OIDC flaws": "oauth_redirect",
    "SAML assertion handling": "SAML",
    "JWT (alg confusion, kid, jku, none)": "jwt_alg_confusion",
    "Missing rate limit / anti-automation": "rate_limit",
    "Race conditions (multi-user)": "Race conditions (multi-user)",
    "Business logic & workflow abuse": "Business logic & workflow abuse",
    "Unguarded API route group behind an SPA": "Unguarded API route group behind an SPA",

    # B. Injection & execution
    "Command injection": "cmdi_blind",                       # expr_injection is expressions, not commands
    "Argument injection on a shell-free argv call": "arg_injection",
    "Env-var injection into a child process": "env_injection",
    "Code / expression injection": "expr_injection",
    "Unsafe deserialization": "deserial_cookie",
    "Untrusted model / checkpoint / dataset load": "",
    "Loader-by-name (registry, plugin, `_target_`)": "",
    "Template injection (SSTI)": "ssti",
    "Client-side template injection (CSTI)": "CSTI",
    "SQL injection": "sqli_error",
    "SQL identifier / ORDER BY injection": "sqli_error",
    "NoSQL / Cypher injection": "nosqli",
    "ORM filter / escape-hatch injection": "nosqli",
    "Search / vector-store filter injection": "nosqli",
    "LDAP / XPath injection": "",
    "Expression-language injection (SpEL/OGNL/MVEL)": "expr_injection",
    "Second-order injection": "second_order",
    "XXE": "xxe",
    "Prototype pollution (server)": "proto_pollution_server",

    # C. Untrusted fetch & files
    "SSRF (incl. guard bypass)": "ssrf",
    "SSRF via renderers (PDF/screenshot/webhook)": "ssrf",
    "DNS rebinding against an allowlist": "",
    "Path traversal / LFI → file READ": "path_traversal",
    "Arbitrary file WRITE": "arbitrary_file_write",
    "Write-then-execute chain (write reaches an executed path)": "arbitrary_file_write",
    "File upload validation bypass": "upload_bypass",
    "Uploaded `.svg`/`.html` served inline from the app origin": "upload_bypass",
    "Open redirect": "open_redirect",
    "Signed-URL / presigned-upload abuse": "signed_url_abuse",
    "Decompression bomb / expansion bomb": "",     # deliberate: availability is not reportable
    "Unbounded allocation from a declared size/count": "",

    # D. Client-side
    "Reflected XSS": "xss",
    "Stored XSS": "xss",
    "Sanitizer bypass / mXSS": "xss",
    "DOM XSS": "xss",
    "Prototype pollution (client)": BROWSER,
    "CSRF": "csrf",
    "Clickjacking / UI redress": "clickjacking_header",
    "postMessage origin confusion": BROWSER,
    "CORS misconfiguration": "cors",
    "Cookie flags & scope": RECON,
    "CSP weakness": RECON,
    "Client-side path traversal / DOM open redirect": "Client-side traversal / DOM redirect",
    "JS bundle & sourcemap exposure": RECON,

    # E. API & protocol
    "GraphQL (introspection, batching, depth, field authz)": "graphql_introspection",
    "WebSocket auth & origin": "ws_auth",
    "Host-header injection": "host_header",
    "Response splitting (CRLF into a header)": "",
    "Web cache poisoning": "cache_poison",
    "Web cache deception": "cache_deception",
    "Request smuggling (detection only)": "smuggling_detect",
    "MCP-surface auth": "mcp_surface_auth",
    "Shadow / zombie API versions": "Shadow / zombie API versions",

    # F. Infrastructure & config
    "Secrets exposure through APIs": "",
    "Info disclosure / secrets in logs & errors": "error_disclosure",
    "Verbose error / fail-open on malformed input": "error_disclosure",
    "Stack-specific surface (framework/platform)": "Stack-specific surface (framework/platform)",
    "Security-header posture": RECON,
    "Subdomain takeover (detection only)": "subdomain_takeover",
    "Weak crypto / weak randomness": STATIC,
    "ReDoS": "",                                   # deliberate: availability is not reportable
    "Quadratic / exponential algorithm on request input": "",
    "Sync CPU work blocking an async event loop": "",
    "Unbounded recursion / stored cycle (never terminates)": "",
    "OOB index / length math into native or GPU code": STATIC,
    "Vulnerable & outdated components": STRUCTURAL,

    # G. AI / LLM-native
    "Prompt injection → insecure output handling": "prompt_inject_direct",
    "Prompt-to-tool privilege escalation": "tool_authz_diff",
    "Excessive agency / unbounded tool scope": "excessive_agency",
    "Secrets leaking into LLM execution data": "",
    "Model / training-data supply chain": STATIC,
    "Vector & embedding weaknesses (RAG store)": "Vector & embedding weaknesses (RAG)",
}

STAGES = {RECON, BROWSER, STATIC, STRUCTURAL}

# Rows deliberately left unreachable, with the reason. Availability findings score C:N/I:N and do
# not qualify on the programs this pipeline targets, so a probe for them would generate work that
# cannot be reported. Listed rather than silently skipped.
DELIBERATE = {
    "Decompression bomb / expansion bomb": "availability - not reportable",
    "Unbounded allocation from a declared size/count": "availability - not reportable",
    "ReDoS": "availability - not reportable",
    "Quadratic / exponential algorithm on request input": "availability - not reportable",
    "Sync CPU work blocking an async event loop": "availability - not reportable",
    "Unbounded recursion / stored cycle (never terminates)": "availability - not reportable",
}


def matrix_rows(path: Path = MATRIX) -> list:
    """Parse the coverage matrix into (section, class, playbook, kind, owner)."""
    rows, section = [], ""
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^### ([A-Z])\. (.+)$", line)
        if m:
            section = m.group(1)
            continue
        if not section or not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 4 or cells[0] in ("Class", "") or set(cells[0]) <= set("-: "):
            continue
        rows.append((section, cells[0], cells[1], cells[2], cells[3]))
    return rows


def reachable_labels() -> set:
    sys.path.insert(0, str(ROOT / "web"))
    sys.path.insert(0, str(ROOT / "dynamic"))
    sys.path.insert(0, str(ROOT / "static"))
    import probe
    import sweep
    return set(probe.PRIMITIVES) | set(sweep.MANUAL_ROWS) | STAGES


def audit() -> dict:
    """Three buckets: uncovered, deliberate, and entries whose target no longer exists."""
    labels = reachable_labels()
    uncovered, deliberate, stale, unmapped = [], [], [], []

    for section, cls, playbook, kind, owner in matrix_rows():
        row = {"section": section, "class": cls, "owner": owner, "kind": kind}
        if cls not in COVERS:
            unmapped.append(row)
            continue
        target = COVERS[cls]
        if not target:
            (deliberate if cls in DELIBERATE else uncovered).append(
                {**row, "why": DELIBERATE.get(cls, "")})
        elif target not in labels:
            stale.append({**row, "target": target})
    return {"uncovered": uncovered, "deliberate": deliberate,
            "stale": stale, "unmapped": unmapped}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="audit matrix coverage")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any row is uncovered")
    a = ap.parse_args(argv)

    try:
        rows = matrix_rows()
    except OSError as e:
        print(f"cannot read the matrix: {e}", file=sys.stderr)
        return 2
    if not rows:
        print("parsed 0 matrix rows - the matrix format changed", file=sys.stderr)
        return 2

    r = audit()
    print(f"coverage audit - {len(rows)} matrix rows")
    print(f"  {len(r['uncovered'])} UNCOVERED (no primitive, no manual row, no stage)")
    print(f"  {len(r['deliberate'])} deliberately unreachable")
    print(f"  {len(r['stale'])} stale map entries (named target no longer exists)")
    print(f"  {len(r['unmapped'])} rows missing from COVERS")
    print()

    if r["stale"]:
        print("STALE - COVERS names something that is gone. Fix the map or restore the probe:")
        for f in r["stale"]:
            print(f"   {f['class']:56} -> {f['target']!r}")
        print()

    if r["unmapped"]:
        print("UNMAPPED - a row was added to the matrix without deciding what settles it:")
        for f in r["unmapped"]:
            print(f"   {f['section']}. {f['class']:54} owner={f['owner']}")
        print()

    if r["uncovered"]:
        print("UNCOVERED - in the matrix, reportable in no state, not even BLOCKED.")
        print("A hunt can report full coverage without ever mentioning these:")
        for f in sorted(r["uncovered"], key=lambda x: (x["section"], x["class"])):
            print(f"   {f['section']}. {f['class']:54} owner={f['owner']:14} kind={f['kind']}")
        print()

    if r["deliberate"]:
        print("Deliberately unreachable (recorded, not forgotten):")
        for f in r["deliberate"]:
            print(f"   {f['class']:56} {f['why']}")

    bad = r["uncovered"] or r["stale"] or r["unmapped"]
    return 1 if (bad and a.strict) else 0


if __name__ == "__main__":
    sys.exit(main())
