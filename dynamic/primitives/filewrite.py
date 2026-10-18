#!/usr/bin/env python3
r"""
filewrite.py - arbitrary file WRITE, and the write-then-execute chain it enables.

THE INVARIANT (this is the whole definition; everything below is machinery for it):

    Attacker-controlled path material reaches a filesystem write sink without a reliable
    containment guarantee that the resolved destination cannot escape the intended writable root.

CONTAINMENT IS A PROPERTY, NOT A FUNCTION NAME. Any of these satisfy it, and a playbook that says
"no realpath() means vulnerable" is overfitted to a mechanism:

  * basename reduction - the name is stripped to its last component before use
  * canonical containment - realpath()/resolve() AND the check applied to the SAME path later written
  * directory-FD operations - openat() relative to a held descriptor, so the root cannot move
  * an allowlist of destinations, or a generated name the caller never influences
  * a platform-safe path API that refuses escapes outright

And a present realpath() does NOT imply containment. Two failure modes stay visible:

  * check-then-write races - validating one resolution and writing another is not containment
  * link following - resolving the NAME but not the TARGET (CWE-59)

SAFETY - the constraint that makes this runnable against someone else's host.

A real attacker writes to ~/.ssh/authorized_keys, .bashrc, /etc/cron.d/*, or a .pth on the import
path. Those are exactly what we must never touch. This probe:

  * writes only a benign marker, with a name unique to THIS run (ctx.fresh_marker)
  * reads before it writes, and aborts if anything is already there - it never overwrites
  * refuses any destination whose basename matches a known-sensitive name, even if asked
  * scores execution reachability from the path alone and never executes anything

Reaching a writable location outside the intended root IS the finding. The gadget belongs in the
report as reasoning, labelled `not tested`.

## Seen in the wild
Examples of the invariant, never its definition: a `Content-Disposition` filename on a response the
target fetched; a step object's `target` field; a `user_id` used as a path component; a multipart
`filename`; an archive entry (zip-slip). The list grows by adding SOURCES, never by adding products.
"""
from __future__ import annotations

import posixpath

from . import (TIMEOUT, Ctx, ProbeResult, blocked, not_confirmed, primitive, requests, send)

# Kept out of reach regardless of what a caller asks for. Writing to any of these on a host we do
# not own is an attack, not a test - and the finding does not require it.
FORBIDDEN_BASENAMES = frozenset({
    "authorized_keys", "known_hosts", "id_rsa", "id_ed25519",
    ".bashrc", ".bash_profile", ".profile", ".zshrc", ".netrc", ".npmrc", ".pgpass",
    "crontab", "passwd", "shadow", "sudoers", "hosts",
    "settings.py", "wp-config.php", ".env", "web.config", ".htaccess",
})

FORBIDDEN_FRAGMENTS = ("/etc/cron", "/etc/init", "/var/spool/cron", "site-packages", ".ssh/")

# Directories whose contents get executed or imported. Presence here raises severity; it is SCORED
# from the destination path alone and never exercised.
EXECUTION_HINTS = {
    "site-packages": "python import path (.pth files are executed at interpreter start)",
    "dist-packages": "python import path",
    "node_modules": "node module resolution",
    "/cgi-bin/": "CGI execution",
    "/etc/cron": "scheduled execution",
    "/wp-content/": "PHP execution under a web root",
    "webapps": "servlet container auto-deploy",
    "/public/": "served web root",
    "/static/": "served web root",
    "/uploads/": "served web root",
}

# Traversal encodings. The point is coverage of ENCODINGS, not of products.
_PREFIXES = (
    "../../../",
    "..\\..\\..\\",
    "....//....//....//",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
    "..%2f..%2f..%2f",
    "%252e%252e%252f",
    "/",
)


def _is_forbidden(path: str) -> bool:
    """Refuse a destination we must not touch, whatever the caller passed."""
    low = (path or "").replace("\\", "/").lower()
    if posixpath.basename(low) in FORBIDDEN_BASENAMES:
        return True
    return any(frag in low for frag in FORBIDDEN_FRAGMENTS)


def _execution_hint(path: str) -> str:
    low = (path or "").replace("\\", "/").lower()
    for frag, why in EXECUTION_HINTS.items():
        if frag in low:
            return why
    return ""


def _already_there(base: str, readback: str, dest: str, ctx: Ctx) -> bool:
    """Read before writing. A probe that overwrites a real file is an incident, not a test.

    `readback` is a READ ENDPOINT taking a `file` parameter - the same shape the confirmation oracle
    uses. An earlier version treated it as a directory prefix here and as a query endpoint there,
    so this check requested a nonsense URL, always 404ed, and the guard never actually guarded.
    One meaning for one option.
    """
    if not readback:
        return False
    try:
        r = send("GET", base + readback, ctx=ctx, params={"file": dest}, timeout=TIMEOUT)
    except requests.RequestException:
        return False        # cannot see: fall through to the forbidden-name check below
    return r.status_code == 200 and bool((r.text or "").strip())


def _artifacts(written: list, occupied: list, refused: list, control: str) -> dict:
    """What this probe left behind, and what it declined to touch.

    We cannot guarantee cleanup on a host we do not own: HTTP write APIs rarely expose a delete, and
    guessing one would mean sending destructive verbs at someone else's service. So the guarantee is
    DISCLOSURE instead - every destination is named, so the operator can remove them and the report
    can state plainly what the test created. `disclosure-ethics` forbids persistence; an undisclosed
    file is persistence, a disclosed and removable one is a documented test artifact.
    """
    return {
        "artifacts_written": written,
        "artifact_note": (
            "this probe created the paths above and cannot delete them remotely - remove them "
            "after testing and list them in the report's impact section" if written else
            "no artifacts created"),
        "skipped_occupied": occupied,      # never overwritten
        "skipped_forbidden": refused,      # never touched, by name
        "control_root": control,
    }


def _control_root(base: str, endpoint: str, param: str, marker: str, ctx: Ctx) -> str:
    """Where does a NORMAL name land? That directory is the intended writable root.

    Without this the probe cannot tell containment from escape: an endpoint that reduces our payload
    to a basename stores it safely inside its own root, and a probe checking a fixed list of served
    paths reads that as a successful write outside the root. Establish the root, then differential
    against it.
    """
    name = "control-" + marker + ".txt"
    try:
        send("POST", base + endpoint, ctx=ctx,
             json={param: name, "content": "hunt-control " + marker}, timeout=TIMEOUT)
    except requests.RequestException:
        return ""
    for candidate in ("/uploads/", "/static/", "/tmp/", "/"):
        try:
            r = send("GET", base + candidate + name, ctx=ctx, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code == 200 and marker in (r.text or ""):
            return candidate.rstrip("/")
    return ""


@primitive("arbitrary_file_write", default_param="filename", group="C", cwe="CWE-22",
           needs="a parameter naming a write destination; --opt readback=/path makes it decisive")
def arbitrary_file_write(base: str, endpoint: str, param: str = "filename",
                         ctx: Ctx | None = None) -> ProbeResult:
    """Does attacker-controlled path material escape the intended writable root?

    Three oracles, strongest first, because a write succeeds silently:

      1. write-then-read-back - plant a marker, retrieve it through a read path
      2. write-then-serve     - write into a served directory, then request it
      3. differential error   - LEAD ONLY. A 500 is not a write.
    """
    ctx = ctx or Ctx()
    marker = ctx.fresh_marker("fw")          # unique per attempt; a fixed name makes re-runs lie
    body = "hunt-write-probe " + marker
    readback = ctx.opts.get("readback", "")

    ev: dict = {}
    attempts = 0
    lead: ProbeResult | None = None
    written: list = []        # every destination this probe may have created
    occupied: list = []       # destinations skipped because something was already there
    refused: list = []        # destinations refused by the forbidden-name guard

    # Establish the intended root with a benign, traversal-free name. Everything after this is a
    # differential against it: a payload that lands where the control landed was contained.
    control_dir = _control_root(base, endpoint, param, marker, ctx)

    # A caller can aim the probe at a directory recon actually found; default stays /tmp. The
    # forbidden check gates THAT, which is what makes it more than decoration - with a hardcoded
    # /tmp/<random> destination it could never fire, since nothing sensitive is ever named.
    dest_dir = (ctx.opts.get("dest_dir") or "tmp").strip("/")

    for prefix in _PREFIXES:
        dest = prefix + dest_dir + "/" + marker + ".txt"
        if _is_forbidden(dest):
            refused.append(dest)
            continue

        # Never overwrite. If anything is visible at the destination, abandon this candidate.
        if _already_there(base, readback, dest, ctx):
            occupied.append(dest)
            continue

        try:
            r = send("POST", base + endpoint, ctx=ctx,
                     json={param: dest, "content": body}, timeout=TIMEOUT)
        except requests.RequestException:
            continue

        attempts += 1
        ev["write_attempted"] = True      # the payload went out; on its own this proves nothing
        written.append(dest)

        text = r.text or ""

        # --- oracle 1: read the marker back through a separate read path -------------------
        if readback:
            try:
                rb = send("GET", base + readback, ctx=ctx,
                          params={"file": dest}, timeout=TIMEOUT)
            except requests.RequestException:
                rb = None
            if rb is not None and marker in (rb.text or ""):
                ev["write_confirmed"] = True
                ev["readback_confirmed"] = True
                ev["destination_resolved"] = dest
                hint = _execution_hint(dest)
                if hint:
                    ev["execution_possible"] = hint
                return ProbeResult(
                    "arbitrary_file_write", True, endpoint, dest, r.status_code,
                    "marker written outside the intended root and read back from " + readback +
                    (" - destination is on an executed path: " + hint if hint else ""),
                    {**ev, "marker": marker,
                     "how": "read back through a separate read path (that path is a dependency of "
                            "this evidence, not part of the finding)",
                     **_artifacts(written, occupied, refused, control_dir)})

        # --- oracle 2: the app serves what it stored, AT A PATH THE CONTROL DID NOT --------
        #
        # Landing somewhere is not escaping. A basename-reducing endpoint stores our traversal
        # payload safely inside its own root - and an early version of this probe called that a
        # confirmed write, because it checked a fixed list of served paths that included the root.
        # The probe cannot know the intended root, so it establishes one: write a benign control
        # name first, see where THAT lands, and confirm only when the traversal payload lands
        # somewhere else.
        for served in ("/" + marker + ".txt", "/tmp/" + marker + ".txt",
                       "/static/" + marker + ".txt", "/uploads/" + marker + ".txt"):
            if control_dir and posixpath.dirname(served).rstrip("/") == control_dir:
                continue          # inside the intended root: containment worked
            try:
                s = send("GET", base + served, ctx=ctx, timeout=TIMEOUT)
            except requests.RequestException:
                continue
            if s.status_code == 200 and marker in (s.text or ""):
                ev["write_confirmed"] = True
                ev["destination_resolved"] = served
                hint = _execution_hint(served)
                if hint:
                    ev["execution_possible"] = hint
                return ProbeResult(
                    "arbitrary_file_write", True, endpoint, dest, r.status_code,
                    "marker written outside the intended root and served from " + served +
                    (" - destination is on an executed path: " + hint if hint else ""),
                    {**ev, "marker": marker, "how": "observed directly at the destination",
                     **_artifacts(written, occupied, refused, control_dir)})

        # --- oracle 3: a differential, which is a LEAD and never a confirmation -------------
        if lead is None and r.status_code >= 500 and marker not in text:
            lead = ProbeResult(
                "arbitrary_file_write", False, endpoint, dest, r.status_code,
                "LEAD: a traversal-shaped destination produced " + str(r.status_code) +
                " where a normal name does not. A 500 is not a write - point a read-back at it "
                "with --opt readback=/path to settle this.",
                {"lead": True, "write_attempted": True, "status": r.status_code,
                 **_artifacts(written, occupied, refused, control_dir)})

    disclosure = _artifacts(written, occupied, refused, control_dir)

    # EVERY terminal path carries the disclosure, including the ones that found nothing. A probe
    # that only reports what it left when it succeeds is the worst version: the runs that leave
    # artifacts without a finding are exactly the ones nobody goes back to clean up.
    if not attempts:
        why = "the endpoint did not accept a write request - is this a write sink?"
        if refused and not written:
            why = ("every candidate destination was refused by the sensitive-path guard "
                   "(" + ", ".join(refused[:3]) + ") - aim it somewhere testable with "
                   "--opt dest_dir=<a writable directory recon found>")
        elif occupied and not written:
            why = ("every candidate destination already had content, so nothing was written - "
                   "this probe never overwrites. Re-run with a different --opt dest_dir=")
        r = blocked("arbitrary_file_write", endpoint, why)
        r.evidence.update(disclosure)
        return r

    if lead is not None:
        lead.evidence.update(disclosure)
        return lead

    if not readback:
        r = blocked(
            "arbitrary_file_write", endpoint,
            "wrote nothing observable and no read-back path was given. A write succeeds silently, "
            "so without --opt readback=/path this class cannot be settled here - that is untested, "
            "not defended.")
        r.evidence.update(disclosure)
        return r

    r = not_confirmed(
        "arbitrary_file_write", endpoint,
        "no marker appeared outside the intended root across " + str(len(_PREFIXES)) +
        " encodings; containment may be present, or the sink may not be reached by this parameter")
    r.evidence.update(disclosure)
    return r
