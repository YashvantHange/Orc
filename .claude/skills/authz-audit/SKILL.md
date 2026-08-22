---
name: authz-audit
description: >
  Step-by-step access-control audit performed by reading route + permission code, then proving
  violations with the multi-user authorization-differential harness. Load when auditing a target
  for IDOR / missing authorization / privilege escalation (bugs SAST cannot find).
---

# Authorization audit procedure (perform against the real repo)

Access control is the richest vein (n8n class) and invisible to SAST — it's a *reasoning* task you
finish with a *behavioral* proof. Use the harness when you have a candidate to confirm; a bug that's
airtight by inspection can be reported on the trace alone.

1. **Build the identity/role model.** Read the auth middleware and user model. List every principal
   type (owner, admin, member, viewer, anon) and every scope/tenant boundary. Note how a request
   proves who it is (session, JWT, API key) and which claim carries the role. Cache this in
   `work/<slug>/profile.json` so later sessions don't re-derive it.

2. **Inventory protected routes.** With source, `Grep` route registrations:
   - Python: `@app\.(get|post|put|delete|patch)`, `@router\.`, `@app\.route`.
   - JS/TS: `(app|router)\.(get|post|put|delete|patch)\(`.
   For each: method, path, the resource/object it acts on, and the **intended** authorized principal.

   **Black-box (`url` targets) — read the inventory instead of grepping for it.**
   `work/<slug>/web/endpoints.json`, produced by `web-recon` / web-recon-hunter, is the route table:
   templated paths (`/items/{id}` with observed values), methods, parameters, and auth as *declared*
   (OpenAPI `security`) versus as *observed* (does it actually 401?). Any endpoint whose declared
   security you can ignore in practice is handed to you by the target's own spec. Three additions
   specific to black-box, each a common finding:
   - **Every client-side permission check is a server-side test.** The bundle's `isAdmin`,
     `role ===`, `permissions.includes` comparisons name the endpoints to request as a lower role. A
     greyed-out button is a hypothesis, not a control.
   - **Old versions stay mounted.** `/api/v2` got the ownership filter; `/api/v1` is often still routed.
   - **The GraphQL schema is a route table** — every query and mutation is an endpoint, its arguments
     are parameters, and the object-level check passing tells you nothing about the nested field
     resolvers (`web-playbooks` → GraphQL).

3. **Classify each route's authorization check** (find the code that verifies the caller may act on
   *this specific object*):
   - **OK**: verifies ownership/role against the acting principal.
   - **IDOR / BOLA** (CWE-639): a request-supplied id indexes the resource with no ownership filter.
   - **Missing authz / BFLA** (CWE-862/306): no auth dependency/decorator/middleware vs. authenticated
     siblings — *or* the route is guarded but reachable by a role that should never call it. Replay every
     privileged verb (admin, settings, user-management, execute, export) as **each lower role**, not just
     as anon; role-level gaps are the half most audits miss.
   - **Wrong-subject** (CWE-284): checks "authenticated" but not "authorized for this object", or trusts
     a client-supplied role/tenant.
   - **Scope creep** (CWE-269): a token/key valid for one scope honored for a broader one.
   (CWE ids: `cwe-map`.)

3b. **Extend the route inventory past HTTP — the non-route principals.** Three surfaces where the check is
   usually absent because nobody thinks of them as routes:
   - **Agent tool calls.** Find the dispatcher (`handle_tool_call`/`execute_tool`/`tool_registry[name]`/
     MCP `call_tool`) and answer: *whose permissions does the tool run with?* If the schema/name is
     validated but no user or tenant id reaches the resource access, every prompt is an authz bypass
     (prompt-to-tool priv-esc — see `vuln-playbooks`). Check whether `allowed_tools`/scopes come from the
     request body, and whether the principal survives into a worker/queue/background task.
   - **Background jobs, webhooks, WS/SSE handlers, GraphQL resolvers** — authenticated at the edge, then
     acting as the service.
   - **Concurrency.** A check-then-act window is a *missing* check for the duration of the window; treat
     redeem-once/first-user-admin/quota/parallel-role-change as authz surfaces and prove them with the
     concurrent harness (`dynamic-hunt`).

4. **Build the differential config** (or scaffold it): `hunt authz-scaffold work/<slug>/src` writes a
   `work/<slug>/authz.json` skeleton from the discovered endpoints — fill the login bodies and, per
   resource, the `owner` + an owner-only `marker` string. Manual schema:
   ```json
   {"identities":[{"name":"owner","login":{"endpoint":"/login","body":{...},"token_field":"token"}},
                  {"name":"other","login":{...}}, {"name":"anon","anon":true}],
    "resources":[{"path":"/api/items/1","method":"GET","owner":"owner","marker":"<owner-only string>"}]}
   ```

5. **Run the harness and confirm:**
   `hunt authz --url <base> --config work/<slug>/authz.json` (or as part of `hunt sweep`; or the manual
   two-token curl replay in the authz-logic-hunter agent). A reported violation — a non-owner/anon
   reads or mutates the owner's resource (status < 400 + the marker) — is a **confirmed** bug. Save the
   command + output as evidence.

6. **Instance sweep + novelty gate + remediation.** Grep for sibling routes missing the same guard —
   more instances of *your* bug. If the target has access-control advisories, load `variant-analysis`
   as the exclusion map (**zero-days only**): a missing check a published CVE already covers, or a
   sibling route a patch didn't reach, is an incomplete-fix — **out of scope**, drop it. Recommend the
   fix at the exact boundary: an ownership/role check keyed to the authenticated principal (never a
   client-supplied field).

Finish with the **reasoning-checklist**.
