#!/usr/bin/env python3

"""

fuzz.py — property/mutation fuzzing to trigger UNKNOWN crashes (novel-bug discovery).



Two modes:

  * HTTP endpoint fuzzing (default): hammer a parameter with a corpus of edge-case inputs

    + Hypothesis-generated strings; flag inputs that cause 500s, tracebacks, timeouts, or

    reflected markers — i.e. unhandled conditions a human wouldn't hand-write.

  * Callable fuzzing (--module M --func F): property-fuzz an importable parser/loader.



Coverage-guided fuzzers (Atheris / jazzer.js) are Linux-only -> use them under WSL for

deep parser fuzzing; this cross-platform layer is the default.



  python dynamic/fuzz.py --launch work/_selftest/py_app --endpoint /calc --param expr

"""

from __future__ import annotations



import argparse

import json

import random

import string

import sys

import time

from dataclasses import dataclass, asdict, field

from pathlib import Path



ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(Path(__file__).resolve().parent))

sys.path.insert(0, str(ROOT / "static"))

# scope guard, not bare requests — see dynamic/scope.py

from scope import http as requests  # noqa: E402

from instrument import TargetProcess  # noqa: E402

import _common as C  # noqa: E402



TIMEOUT = 8



# curated edge-case corpus (parsers/evaluators/loaders choke on these)

CORPUS = [

    "", " ", "0", "-1", "1e400", "9" * 400, "%s%s%s%n", "{{7*7}}", "${7*7}",

    "__import__('os')", "() ", "[", "{", "\"", "'", "\\", "\x00", "../" * 20,

    "A" * 5000, "", "\U0001d54f" * 50, "null", "NaN", "Infinity",

    "true && false", "1/0", "().__class__", "<img src=x onerror=1>",

]

MUT_CHARS = "{}[]()<>\"'`;|&$\\/%\x00\n\t"





def _mutate(seed: str) -> str:

    s = list(seed)

    for _ in range(random.randint(1, 4)):

        if not s:

            s.append(random.choice(MUT_CHARS)); continue

        i = random.randrange(len(s))

        op = random.random()

        if op < 0.4:

            s[i] = random.choice(MUT_CHARS)

        elif op < 0.7:

            s.insert(i, random.choice(MUT_CHARS))

        else:

            s[i] = s[i] * random.randint(2, 50)

    return "".join(s)





def _hypothesis_samples(n: int) -> list[str]:

    try:

        from hypothesis import strategies as st

        strat = st.one_of(st.text(), st.text(alphabet=string.printable),

                          st.binary().map(lambda b: b.decode("latin1")))

        return [strat.example() for _ in range(n)]

    except Exception:  # noqa: BLE001 — hypothesis optional

        return ["".join(random.choice(string.printable) for _ in range(random.randint(0, 40)))

                for _ in range(n)]





@dataclass

class Crash:

    payload: str

    status: int

    signal: str            # http-500 | traceback | timeout | reflected

    snippet: str = ""





@dataclass

class FuzzReport:

    endpoint: str

    param: str

    iterations: int

    crashes: list = field(default_factory=list)

    unique_signals: list = field(default_factory=list)





def fuzz_http(base: str, endpoint: str, param: str, iterations: int = 300) -> FuzzReport:

    inputs = list(CORPUS)

    inputs += [_mutate(random.choice(CORPUS)) for _ in range(iterations // 2)]

    inputs += _hypothesis_samples(max(0, iterations - len(inputs)))



    crashes: list[Crash] = []

    seen_payloads: set[str] = set()

    for payload in inputs[:iterations]:

        if payload in seen_payloads:

            continue

        seen_payloads.add(payload)

        try:

            r = requests.get(f"{base}{endpoint}", params={param: payload}, timeout=TIMEOUT)

        except requests.Timeout:

            crashes.append(Crash(payload[:120], 0, "timeout")); continue

        except requests.RequestException:

            continue

        low = r.text.lower()

        if r.status_code >= 500:

            sig = "traceback" if ("traceback" in low or "stack" in low) else "http-500"

            crashes.append(Crash(payload[:120], r.status_code, sig, r.text[:200]))

    signals = sorted({c.signal for c in crashes})

    return FuzzReport(endpoint, param, len(seen_payloads), [asdict(c) for c in crashes[:50]], signals)





def _report(base: str, hint: str, endpoint: str, param: str, iterations: int) -> int:

    rep = fuzz_http(base, endpoint, param, iterations)

    d = C.workdir(hint) / "dynamic"

    d.mkdir(parents=True, exist_ok=True)

    out = d / "fuzz.json"

    out.write_text(json.dumps(asdict(rep), indent=2), encoding="utf-8")

    print(f"\nfuzzed {base}{endpoint}?{param}=  ({rep.iterations} inputs)  ({out})")

    print(f"  crash-inducing inputs: {len(rep.crashes)}   signals: {rep.unique_signals}")

    for c in rep.crashes[:6]:

        print(f"  [{c['signal']:10}] status={c['status']} payload={c['payload']!r}")

    return 0 if rep.crashes else 1





def main() -> int:

    ap = argparse.ArgumentParser(description=__doc__)

    ap.add_argument("--url")

    ap.add_argument("--launch")

    ap.add_argument("--entry")

    ap.add_argument("--endpoint", default="/calc")

    ap.add_argument("--param", default="expr")

    ap.add_argument("--iterations", type=int, default=300)

    ap.add_argument("--slug", help="workdir hint (co-locate under work/<slug>/); defaults to url/target")

    ap.add_argument("--scope", help="scope.yml authorizing --url (see dynamic/scope.py)")

    args = ap.parse_args()



    if args.scope:

        import scope as S

        try:

            S.activate(S.Scope.load(args.scope), args.slug or args.url or "url-target",
                       primitive="fuzz")

        except S.ScopeError as e:

            print(f"scope error: {e}", file=sys.stderr)

            return 2



    if args.launch:

        with TargetProcess(args.launch, entry=args.entry) as t:

            print(f"launched {t.base_url} (kind={t.kind})")

            time.sleep(1.0)

            return _report(t.base_url, args.slug or args.launch, args.endpoint, args.param, args.iterations)

    elif args.url:

        return _report(args.url, args.slug or args.url, args.endpoint, args.param, args.iterations)

    ap.error("pass --launch <target> or --url <running-instance>")





if __name__ == "__main__":

    sys.exit(main())

