// pool_app — a deliberately vulnerable worker-pool fixture. DO NOT FIX THE BUGS HERE.
//
// Seeds the cross-request state-reuse class (`state-integrity` § S2, the CVE-2026-109619 shape)
// so the two-identity differential has a known-positive to detect and a known-negative to stay
// quiet on. Honours the env that dynamic/instrument.py's `pool` shape sets:
//
//   WORKERS=N               how many workers to fork
//   CLUSTER_SCHED_POLICY    "rr" => cluster.SCHED_RR (forced round-robin), else platform default
//
// The policy matters: on win32 the platform default routes EVERY connection to ONE worker, so a
// control built by merely raising WORKERS reproduces the leak and proves nothing.
'use strict';
const cluster = require('cluster');
const http = require('http');

const WORKERS = parseInt(process.env.WORKERS || '1', 10);
const PORT = parseInt(process.env.PORT || '8711', 10);

if (cluster.isPrimary) {
  if ((process.env.CLUSTER_SCHED_POLICY || '') === 'rr') {
    cluster.schedulingPolicy = cluster.SCHED_RR;
  }
  for (let i = 0; i < WORKERS; i++) cluster.fork();
  cluster.on('exit', () => cluster.fork());
} else {
  // ---- seed: s2-identity-bleed -------------------------------------------------------------
  // Module scope, so it has WORKER lifetime, not request lifetime. It is set from the caller's
  // credentials and never cleared when the request ends, so the next request on this worker —
  // including an unauthenticated one — reads the previous caller's identity.
  let lastIdentity = null;

  // ---- negative control: correctly isolated, same shape ------------------------------------
  // Shaped like the seed but keyed per identity and read only with that identity's own key, so
  // nothing crosses. A run that reports this one is producing false positives.
  const perIdentity = new Map();

  const json = (res, body) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(body));
  };

  http.createServer((req, res) => {
    const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
    const auth = req.headers['authorization'] || '';
    const identity = auth.startsWith('Bearer ') ? auth.slice(7) : null;

    if (identity) {
      lastIdentity = identity;                               // the defect: no reset on request end
      if (url.searchParams.has('note')) {
        perIdentity.set(identity, url.searchParams.get('note'));
      }
    }

    switch (url.pathname) {
      case '/whoami':
        // VULNERABLE: serves module-scope state that belonged to whoever called last.
        return json(res, { pid: process.pid, identity: lastIdentity });

      case '/note':
        // CONTROL: reads only this caller's own key; an unauthenticated caller gets nothing.
        return json(res, { pid: process.pid,
                           note: identity ? (perIdentity.get(identity) || null) : null });

      case '/worker':
        // Worker identification, so a probe can state WHICH worker served it rather than guess.
        return json(res, { pid: process.pid, workers: WORKERS,
                           policy: process.env.CLUSTER_SCHED_POLICY || 'default' });

      default:
        res.statusCode = 404;
        return json(res, { error: 'not found' });
    }
  }).listen(PORT);
}
