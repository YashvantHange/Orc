# py_app / node_app — the dynamic self-test fixtures

**DO NOT FIX THE BUGS IN THIS DIRECTORY.** They are seeded on purpose. `seeds.json` is the
machine-readable list and covers both fixtures.

These two are the targets the dynamic entrypoints name in their own usage lines:

```
python dynamic/probe.py      --launch work/_selftest/py_app --selftest
python dynamic/authz_diff.py --launch work/_selftest/py_app --selftest
python dynamic/fuzz.py       --launch work/_selftest/py_app --endpoint /calc --param expr
python dynamic/run_target.py work/_selftest/py_app --seconds 120
```

They were missing. Four modules documented `work/_selftest/py_app`, `dynamic/probe.py`'s
`selftest_plan` was written against routes nothing served, its docstring said "py_app + node_app
share routes", and `tests/test_orchestration.py` asserted the directory existed — while
`work/_selftest/` held only `src_app` (read, never run), `web_app` (driven through the live-website
sweep, on different routes) and `pool_app` (the worker-pool S2 case). So `--selftest` could not run
at all, and the slug test failed because `_common.slug()` branches on whether the path exists.

## The two runtimes serve the same routes, deliberately

`py_app/app.py` is Python, `node_app/server.js` is Node, and they answer identically. An identical
defect reached through a different runtime is the cheapest check that a primitive confirms the
**bug** rather than one framework's error strings — several primitives match on response text
(`error_disclosure` looks for a traceback, `xss` for a content type), and a plan tuned to exactly
one server is a plan that only works there.

## Stdlib only, and why

`dynamic/instrument.py` boots a python target in a fresh `.dynvenv` and pip-installs only when the
target has a `requirements.txt`. A fixture needing Flask would need a network install before the
self-test could run. So `py_app` uses `http.server` and mints its own HS256 tokens with `hmac`, and
`node_app` uses Node core with no dependencies — `npm install` has nothing to fetch and both boot
offline. `../web_app` imports Flask because it is launched by hand from the repo venv, never
through `instrument.py`.

## Routes

| route | seed | primitive / harness |
|---|---|---|
| `GET /` | reflects `Origin` **and** `Allow-Credentials: true` | `cors` |
| `POST /login` | — (identity provisioning: alice/pw-alice, bob/pw-bob, viewer/pw-viewer) | `authz_diff` |
| `GET /me` | HS256 key is a source constant | `jwt_forgery` |
| `GET /items/<id>` | ownership never compared against the caller | `authz_diff` |
| `GET /read?path=` | no containment check — **and** returns the raw exception | `path_traversal`, `error_disclosure` |
| `GET /admin/secret` | no authentication at all | `missing_auth` |
| `GET /greet?name=` | unescaped into `text/html` | `xss` |
| `GET /calc?expr=` | `eval()` on a request parameter | `expr_injection` |

`/read` carries two independent seeds, which is why both `path_traversal` and `error_disclosure`
aim at it. The traversal payload is deterministic because `selftest_plan` writes
`../_TRAVERSAL_SENTINEL.txt` one level up before probing, rather than relying on `/etc/passwd`
existing.

## The `/safe/*` routes are negative controls

`/safe/items/<id>`, `/safe/read`, `/safe/greet` and `/safe/calc` are the same shapes, correctly
defended. **A run that reports one of them is producing false positives**, which is the only reason
they are here.

Two of them are traps on purpose: `/safe/greet` still reflects the marker (it is escaped, not
dropped) and `/safe/calc` still answers `7*7` with `49` (it is parsed, not evaluated). A primitive
that confirms on reflection alone, or on the arithmetic result alone, reports both. That is the
distinction the controls exist to force.

## The identity that matters for the signature seed

The signing key is leaked but the signature **is** verified, and `alg: none` is rejected. So
`jwt_forgery` must confirm on its `hardcoded_secret` variant and **not** on `alg_none` against
these fixtures. A run reporting `alg_none` here is reporting something that did not happen.
