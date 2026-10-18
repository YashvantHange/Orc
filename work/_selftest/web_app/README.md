# web_app — a deliberately vulnerable Flask fixture

**DO NOT FIX THE BUGS HERE.** `tests/test_web_acceptance.py` asserts the live sweep still finds them.

This is the black-box counterpart to `../src_app` (which is read, not probed). It exists because the
six `test_web_acceptance.py` tests had no fixture at all and raised `RuntimeError: fixture did not
come up` on every run — the directory was never committed, because `.gitignore`'s `!work/_selftest/`
negations were inert until `work/` became `work/*` (git cannot re-include anything inside an excluded
directory).

## Running it by hand

```
PORT=8031 .venv/Scripts/python.exe work/_selftest/web_app/app.py
python hunt.py web recon http://127.0.0.1:8031 --scope work/_selftest/web_app/scope.yml
```

Binds to 127.0.0.1 only. Two identities: `alice/alice-pw`, `bob/bob-pw`.

## Design rule: routes are named for the sweep's aim

Every seeded route is named to match a `web/sweep.py` TARGETING hint (`q`, `tpl`, `next`, `username`,
`/admin/`, `/profile`, `/reset`, `/graphql`, …). A bug on a path no primitive aims at proves nothing —
that is the 52-of-54 targeting failure this pipeline already recorded once.

`/api/safe/*` routes are correctly defended. A HIT on any of them is a false positive, and
`test_no_false_positives_on_defended_routes` fails the build for it.
