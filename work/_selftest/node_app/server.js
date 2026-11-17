// node_app — a deliberately vulnerable Node fixture. DO NOT FIX THE BUGS HERE.
//
// The JS twin of ../py_app: the SAME routes, the same seeds, the same negative controls, so the
// one self-test plan in dynamic/probe.py runs unchanged against either runtime. `selftest_plan`'s
// own docstring says "py_app + node_app share routes" — this file is the half that makes that true.
//
//   python dynamic/probe.py      --launch work/_selftest/node_app --selftest
//   python dynamic/authz_diff.py --launch work/_selftest/node_app --selftest
//
// Why it exists separately: an identical defect reached through a different runtime is the cheapest
// check that a primitive confirms the BUG and not one framework's error strings. Several of the
// primitives match on response text (`error_disclosure` looks for a traceback, `xss` for a content
// type), and a plan tuned to exactly one server is a plan that only works there.
//
// Node core only — no dependencies, so `npm install` has nothing to fetch and the fixture boots
// offline. Binds 127.0.0.1 only, on $PORT.
'use strict';
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');

const PORT = parseInt(process.env.PORT || '8012', 10);
const HERE = __dirname;

// ---- seed: authn-hardcoded-secret ---------------------------------------------------------
// Same constant py_app carries, and the same one dynamic/probe.py's selftest_plan hands to the
// jwt_forgery primitive. In the source means in everyone's hands.
const JWT_SECRET = 'hardcoded-self-test-secret-do-not-use';

const USERS = { alice: 'pw-alice', bob: 'pw-bob', viewer: 'pw-viewer' };

// The marker must really be in the owner's record: the authorization differential confirms an
// IDOR by seeing the OWNER's marker in some OTHER identity's response.
const ITEMS = {
  1: { id: 1, owner: 'alice', note: 'alice-private-note' },
  2: { id: 2, owner: 'bob', note: 'bob-private-note' },
};

// ------------------------------------------------------------------------------ JWT (manual) ---
const b64u = (buf) => Buffer.from(buf).toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64uDec = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

function jwtEncode(payload) {
  const head = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64u(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${head}.${body}`).digest();
  return `${head}.${body}.${b64u(sig)}`;
}

// Verifies HS256 against JWT_SECRET. `alg: none` is rejected — the seed here is the leaked key,
// not a skipped signature check, so the forgery that lands is the one using the constant above.
function jwtDecode(token) {
  try {
    const [head, body, sig] = String(token).split('.');
    if (!head || !body || !sig) return null;
    if (JSON.parse(b64uDec(head).toString()).alg !== 'HS256') return null;
    const want = b64u(crypto.createHmac('sha256', JWT_SECRET)
      .update(`${head}.${body}`).digest());
    const a = Buffer.from(want);
    const b = Buffer.from(sig);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    return JSON.parse(b64uDec(body).toString());
  } catch (e) {
    return null;
  }
}

const send = (res, code, body, ctype, headers) => {
  res.writeHead(code, Object.assign({ 'content-type': ctype || 'application/json' },
    headers || {}));
  res.end(body);
};
const json = (res, code, obj) => send(res, code, JSON.stringify(obj));

function identity(req) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) return null;
  const claims = jwtDecode(auth.slice(7));
  return claims ? claims.sub : null;
}

function readBody(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => resolve(raw));
  });
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const p = u.pathname;
  const q = (k, d) => (u.searchParams.get(k) === null ? d : u.searchParams.get(k));

  if (req.method === 'POST' && p === '/login') {
    let body = {};
    try {
      body = JSON.parse((await readBody(req)) || '{}');
    } catch (e) {
      return json(res, 400, { error: 'bad json' });
    }
    if (USERS[body.user] && USERS[body.user] === body.password) {
      return json(res, 200, { token: jwtEncode({ sub: body.user }) });
    }
    return json(res, 401, { error: 'bad credentials' });
  }

  if (req.method !== 'GET') return json(res, 404, { error: 'no such route' });

  // ---- seed: cors-reflected-origin-with-credentials ---------------------------------------
  // Reflects whatever Origin arrives AND allows credentials, so any site can read the
  // authenticated response. The pair is the bug; either alone is not.
  if (p === '/') {
    const origin = req.headers.origin || '';
    const hdrs = origin
      ? { 'access-control-allow-origin': origin, 'access-control-allow-credentials': 'true' }
      : {};
    return send(res, 200, JSON.stringify({ app: 'node_app', ok: true }), null, hdrs);
  }

  // ---- seed: missing-auth-admin-endpoint ---------------------------------------------------
  // An administrative route with no authentication check at all.
  if (p === '/admin/secret') {
    return json(res, 200, {
      api_key: 'AKIA-FIXTURE-0000-NOT-REAL', admin: true,
      note: 'no authentication required',
    });
  }

  if (p === '/me') {
    const who = identity(req);
    if (!who) return json(res, 401, { error: 'no valid token' });
    return json(res, 200, { sub: who, authenticated: true });
  }

  // ---- seed: idor-missing-ownership-check --------------------------------------------------
  // The item id is trusted straight from the path. Ownership is recorded on the record and never
  // compared against the caller, so every identity — anonymous included — reads every item.
  if (p.startsWith('/items/')) {
    const item = ITEMS[p.slice('/items/'.length)];
    if (!item) return json(res, 404, { error: 'no such item' });
    return json(res, 200, item);
  }

  // ---- negative control: same shape, ownership enforced ------------------------------------
  if (p.startsWith('/safe/items/')) {
    const who = identity(req);
    const item = ITEMS[p.slice('/safe/items/'.length)];
    if (!item) return json(res, 404, { error: 'no such item' });
    if (item.owner !== who) return json(res, 403, { error: 'not your item' });
    return json(res, 200, item);
  }

  // ---- seed: path-traversal + error-disclosure ---------------------------------------------
  // The parameter is joined onto a base directory with no containment check, so `../` walks out
  // of it. Returning the raw exception is a SECOND, separate seed: probe.py's error_disclosure
  // primitive aims at this same route and matches on the internals in the body.
  if (p === '/read') {
    const rel = q('path', 'README.md');
    try {
      return send(res, 200, fs.readFileSync(path.join(HERE, rel), 'utf8'), 'text/plain');
    } catch (e) {
      return json(res, 500, { error: String(e.message), traceback: String(e.stack) });
    }
  }

  // ---- negative control: resolved-path containment -----------------------------------------
  if (p === '/safe/read') {
    const rel = q('path', 'README.md');
    try {
      const target = path.resolve(HERE, rel);
      if (target !== HERE && !target.startsWith(HERE + path.sep)) throw new Error('escaped');
      return send(res, 200, fs.readFileSync(target, 'utf8'), 'text/plain');
    } catch (e) {
      return json(res, 400, { error: 'bad path' });   // no internals in the response
    }
  }

  // ---- seed: reflected-xss ------------------------------------------------------------------
  // Interpolated into an HTML response with no escaping. The content type matters: the primitive
  // only confirms when the reflection lands in a document a browser parses.
  if (p === '/greet') {
    return send(res, 200, `<html><body><h1>hello ${q('name', 'world')}</h1></body></html>`,
      'text/html; charset=utf-8');
  }

  // ---- negative control: escaped on output --------------------------------------------------
  if (p === '/safe/greet') {
    const name = String(q('name', 'world')).replace(/[&<>"']/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    return send(res, 200, `<html><body><h1>hello ${name}</h1></body></html>`,
      'text/html; charset=utf-8');
  }

  // ---- seed: expression-injection -----------------------------------------------------------
  // eval() on a request parameter. 7*7 -> 49 is the benign marker the primitive uses; the same
  // sink takes require('child_process'), which is why this is code execution, not a calculator.
  if (p === '/calc') {
    const expr = q('expr', '1+1');
    try {
      // eslint-disable-next-line no-eval
      return json(res, 200, { expr, result: eval(expr) });
    } catch (e) {
      return json(res, 400, { expr, error: e.name });
    }
  }

  // ---- negative control: parsed, not evaluated ----------------------------------------------
  if (p === '/safe/calc') {
    const expr = q('expr', '1+1');
    if (!/^[0-9]+(\s*[-+*/]\s*[0-9]+)*$/.test(expr)) {
      return json(res, 400, { expr, error: 'not an arithmetic literal' });
    }
    let acc = null;
    let op = '+';
    for (const tok of expr.match(/[0-9]+|[-+*/]/g)) {
      if ('+-*/'.includes(tok)) { op = tok; continue; }
      const n = parseInt(tok, 10);
      if (acc === null) { acc = n; continue; }
      acc = op === '+' ? acc + n : op === '-' ? acc - n : op === '*' ? acc * n : acc / n;
    }
    return json(res, 200, { expr, result: acc });
  }

  return json(res, 404, { error: 'no such route' });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`node_app fixture listening on http://127.0.0.1:${PORT}`);
});
