# Escape SSO

**Owner:** Antoine Carossio · **Deadline:** 2026-11-11 (24 h after planning) · **Repo:** `~/Work/escape-sso` (new, `github.com/Escape-Technologies/escape-sso`, public) and `~/Work/escape-designs` (`github.com/Escape-Technologies/escape-designs`) · **Default branch:** main

## Goal
Put a Google sign-in in front of the internal website `design.escape.dev` (repo `escape-designs`, static Vite build on Vercel, public today) so that only active, verified `@escape.tech` Google Workspace accounts can see it. Build the gate as a standalone, platform-neutral package in its own repo, installed as a git dependency, so any other internal site (on Vercel or elsewhere) is protected the same way: install the package, add a few-line middleware, set 4 env vars. No new infrastructure.

## Expectations and KPIs
Owner's words (intake, 2026-11-10): "add a google sso login in front of the website. we just need to validate the email address is an active valid escape.tech email address. Build a system generic enough so that we can port it the same way on other similar interal websites like this later." KPIs picked by the owner: K1, K2, K3; for K4: "maybe what we could do is create a separate repo and use it inside this repo? so that the SSO is just a package and maintained apart". "do something super generic". Deadline: "I think it's doable in 24h no?".

| # | KPI | Target | How measured (command / query / count) | Owner |
|---|---|---|---|---|
| K1 | Zero public paths | Every built path of `design.escape.dev` and `designs.escape.dev` (hub, `/assets/*`, every file under every project) answers, without a session, only 302 to `accounts.google.com` or `/auth/login`, or 401; any other status or a network error is a failure; with a valid session `/`, a nested project page and an asset answer 200 | `node scripts/sso-sweep.mjs <url> --dist dist [--cookie <session>]` in escape-designs -> exit 0, "0 open, 0 unexpected" | autopilot (preview), owner (production after merge) |
| K2 | Only escape.tech | An active, verified `@escape.tech` Workspace account gets in; a gmail.com account, an account of another Workspace domain, an unverified email, and a token with `hd=escape.tech` but another email domain get no session (403 from the package, or Google's `org_internal` error for accounts outside the Workspace) | `npm test` in escape-sso: the K2 test matrix (fake Google issuer) passes, 0 skipped; plus one manual login with an escape.tech account (gets in) and one with a gmail.com account (Google error or 403, no session) on the preview and on production | autopilot (tests), owner (manual) |
| K3 | Access lost within 8 h | The session issued by the callback lives ≤ 8 h and traffic never extends it, after which Google is asked again; a suspended or deleted account cannot get a new session. Not covered: bytes a browser already downloaded during a valid session | Fake-issuer test on the callback-issued `Set-Cookie` (`Max-Age` ≤ 28800, `exp - iat` ≤ 28800, unchanged after later requests, rejected at `exp`); `node scripts/sso-sweep.mjs <preview> --session-check --cookie <owner session>` decodes the real session (no secret needed) and checks `exp - iat` ≤ 28800 | autopilot |
| K4 | Port as a package | escape-designs is protected only by adding the git dependency, a `middleware.ts` of ≤ 10 non-blank lines and 4 env vars, following the escape-sso README; the package lives in its own repo with a tagged release | `git diff --stat main...autopilot/escape-sso` in escape-designs touches only `package.json`, `package-lock.json`, `middleware.ts`, `vercel.json` (asset cache header only), `scripts/sso-sweep.mjs`, `scripts/sso-sweep.test.mjs`, README; `grep -cv '^\s*$' middleware.ts` ≤ 10; tag `v1.0.0` exists on escape-sso | autopilot |

## Non-goals
- One login shared across sites (a central auth service or a cookie on `.escape.dev`). Each site has its own session; with an active Google session the re-login is one redirect.
- Roles, groups or per-user permissions. Any active `@escape.tech` account sees everything.
- A reverse proxy for sites not written in JS (Python, Go). Only JS runtimes: Vercel middleware, Node, and Web-fetch runtimes (Cloudflare Workers, Deno, Bun).
- Protecting local development (`npm run dev` in escape-designs stays open on localhost).
- Publishing to the npm registry or GitHub Packages.

## Constraints
- Owner decides open questions: Antoine Carossio.
- Git: the autopilot may create the public GitHub repo `Escape-Technologies/escape-sso`, push `autopilot/*` branches in both repos, push the `v1.0.0` tag on escape-sso, and open draft PRs. Owner's answer: "Create repo + push + draft PR". Merging escape-designs to `main` deploys production: owner only.
- Package install: git dependency (owner: "git dependency"), public repo (owner: "Public (Recommended)"). No token needed to install.
- Hosts: "not necessarily" Vercel only -> the core uses only Web standard APIs (`Request`, `Response`, `crypto.subtle`, `fetch`).
- Google OAuth client: created by the owner in the Google Cloud console (owner: "me I guess?"). No Workspace admin token is used by the autopilot: there is no public Google API to create a standard OAuth web client, and an admin credential in an unattended run is out of proportion.
- Secrets live only in each site's env vars; nothing secret in either repo. Budget: subscriptions and free tiers only.
- escape-designs keeps its stack (Vite 8, TypeScript 7, Node ≥ 20, Vercel project `escape-designs`, team `escape-tech`, `framework: null`). Its preview deployments stay behind Vercel Authentication (`ssoProtection: all_except_custom_domains`).

## Architecture and key decisions
- **Package `escape-sso`, repo `Escape-Technologies/escape-sso`, TypeScript, ESM, Node 24 LTS for development, runtime target: any Web-standard runtime.** Built to `dist/` by a `prepare` script, so `npm install github:Escape-Technologies/escape-sso#v1.0.0` builds it on install. Rejected: committing `dist/` (drift between source and build), npm registry (owner chose git dependency).
- **Dependencies verified on 2026-11-10 (Node v24.21.0):** `jose@6.2.17` (session JWT), `oauth4webapi@3.8.8` (OIDC code flow, PKCE, ID token validation), `@vercel/functions@3.11.1` (optional peer, Vercel adapter only), dev: `typescript@7.0.2` (as escape-designs), `vitest@5.1.0`. Pinned exactly. Fallback for the whole project if one fails: the previous minor of the failing package.
- **Core API:** `createSSO(config)` returns `{ handle(request: Request): Promise<{ response: Response } | { user: { email, name } } | { pass: true }> }`. A `response` (redirect to Google, callback result, 403, logout) is returned as is; a `user` means pass through with that identity; `pass` means an exact `publicPaths` entry that needs no session. Routes under `basePath` (default `/auth`): `/auth/login`, `/auth/callback`, `/auth/logout`. Every other path needs a valid session.
- **Login:** OIDC authorization code flow with PKCE, `state` and `nonce`, against Google discovery (`https://accounts.google.com`), `hd=<first allowed domain>` as a hint only. The pending login (state, nonce, verifier, return path) is a signed, 10-minute, HttpOnly cookie.
- **Who gets in (K2):** the ID token passes issuer, audience, expiry and nonce checks, `email_verified === true`, the `hd` claim is in `allowedDomains`, and the email's domain equals `hd`. `hd` is authoritative: only Google Workspace accounts of that domain carry it; a gmail.com account never does. "Active" means Google issued the token: Google refuses sign-in to suspended or deleted accounts. Rejected: Admin SDK Directory API lookup per login (needs a service account with domain-wide delegation, i.e. infra and an admin credential, for no gain over `hd` plus short sessions).
- **Session (K3):** a JWT (HS256, `jose`) in an HttpOnly, Secure, SameSite=Lax cookie, `exp` and `Max-Age` = `sessionTtl`, default and maximum 8 h. After expiry the user goes back through Google, which re-checks the account. Rejected: refresh tokens (state to store, nothing gained at 8 h).
- **Fail closed:** missing or short config (`sessionSecret` < 32 bytes, no client id/secret, empty `allowedDomains`) makes every request answer 500 "SSO misconfigured", never pass through. Any error in the flow answers 403 or a redirect to login, never the content.
- **Return path:** parsed with `new URL(value, requestOrigin)`; kept only when the value has no control character and the resolved origin equals the request origin; only `pathname + search` of the result is used; anything else returns to `/`. No open redirect.
- **Adapters:** `escape-sso/vercel` (Vercel Routing Middleware for any framework, including static `framework: null` sites; `export default vercelSSO(config)` plus `config.matcher`; identity forwarded upstream with `next({ request: { headers } })`, any incoming `x-escape-sso-email` stripped), `escape-sso/node` (Connect/Express middleware and a wrapper for `http.createServer` handlers), `escape-sso/fetch` (`withSSO(handler, config)` for Cloudflare Workers, Deno, Bun: the handler keeps its native arguments, identity via `getUser(request)`). Tested in CI on Node 20 and 24, Vercel's `next()` contract, and the core plus the fetch adapter in the `edge-runtime` VM (`@edge-runtime/vm@5.0.0`); Workers, Deno and Bun are not run in CI (README says so). `configFromEnv(env)` reads `SSO_GOOGLE_CLIENT_ID`, `SSO_GOOGLE_CLIENT_SECRET`, `SSO_SESSION_SECRET`, `SSO_ALLOWED_DOMAINS` in every adapter.
- **One Google OAuth client for all internal sites** (type Internal, escape.tech Workspace), one redirect URI per site added to it. Rejected: one client per site (more console work, same security since the domain check is in the package).
- **Previews of escape-designs:** Google refuses wildcard redirect URIs, so an arbitrary preview URL cannot complete a Google login. Previews already sit behind Vercel Authentication. The 4 env vars are set for Production, and for Preview scoped to the branch `autopilot/escape-sso` only, whose stable alias `escape-designs-git-autopilot-escape-sso-escape-tech.vercel.app` is a registered redirect URI: that preview runs the full gate before production (ticket `preview-e2e`). The Vercel adapter passes through only when `process.env.VERCEL_ENV === 'preview'` AND `SSO_GOOGLE_CLIENT_ID` is unset AND the site sets `skipOnVercelPreview: true`; production never skips, and any other missing config fails closed.
- **Caching:** every response of the gate (302, 401, 403, login, callback, logout) carries `Cache-Control: no-store`. escape-designs changes its `/assets/*` header from `public` to `private, max-age=31536000, immutable`, so no shared cache keeps protected assets. Middleware runs before Vercel's CDN cache.
- Rejected platform options: Vercel Authentication on custom domains (requires a Vercel team seat per viewer), Cloudflare Access or Google IAP (new infra, ruled out by the owner's question "will I need a separate infra?").

## Milestones and tickets

### M1 Core package
The `escape-sso` repo exists on GitHub with the core: config, session, Google OIDC flow, domain checks, and the K2/K3 test matrix against a fake Google issuer.

| # | KPI / acceptance | Target | How measured |
|---|---|---|---|
| M1-K1 | K2 matrix green | every K2 case passes, 0 skipped | `npm run check` (tsc + vitest) -> exit 0 |
| M1-K2 | Fail closed | missing/short config answers 500 for every path | tests `config.*` pass |

| slug | title | size | blocked by | checks | guardrails |
|---|---|---|---|---|---|
| scaffold | Create the escape-sso repo: TS, vitest, CI, exports, prepare build, public GitHub repo | S | - | `npm ci && npm run check` ; `npm pack --dry-run` | PM-7 |
| config-session | Config validation (fail closed) and signed session cookie | M | scaffold | `npm run check` | |
| fake-idp | Fake Google issuer for tests: discovery, JWKS, token endpoint, signed ID tokens with chosen claims | S | scaffold | `npm run check` | |
| oidc-flow | Core handler: login, callback, logout, domain checks, return path, K2 matrix | L | config-session, fake-idp | `npm run check` | PM-4, PM-5, PM-6, PM-9 |

### M2 Adapters and porting guide
Any JS site can use the package: Vercel middleware, Node, and Web-fetch runtimes, each tested, with a README that a developer follows to protect a new site, and release `v1.0.0`.

| # | KPI / acceptance | Target | How measured |
|---|---|---|---|
| M2-K1 | Each adapter protects a running server | one integration test per adapter: no cookie -> 302 Google, valid session -> 200 | `npm run check` |
| M2-K2 | Installable from git | a clean directory installs `github:Escape-Technologies/escape-sso#v1.0.0` and imports the 3 entry points | `scripts/install-smoke.sh v1.0.0` -> exit 0 |

| slug | title | size | blocked by | checks | guardrails |
|---|---|---|---|---|---|
| adapter-vercel | `escape-sso/vercel`: Routing Middleware adapter and example | S | oidc-flow | `npm run check` | PM-3, PM-10 |
| adapter-node-fetch | `escape-sso/node` and `escape-sso/fetch` adapters with real-server tests | M | oidc-flow | `npm run check` | PM-6, PM-7 |
| docs-release | README porting guide, Google client setup, env vars; tag and push `v1.0.0`; install smoke | S | adapter-vercel, adapter-node-fetch | `npm run check` ; `scripts/install-smoke.sh v1.0.0` | |

### M3 design.escape.dev behind SSO
escape-designs installs `escape-sso@v1.0.0`, the branch preview passes the full gate with a real Google login, and after the owner merges, production answers only to escape.tech accounts. A draft PR alone does not complete M3.

| # | KPI / acceptance | Target | How measured |
|---|---|---|---|
| M3-K0 | Gate on the branch preview | 0 open, 0 unexpected without session; 200 on `/`, a project page and an asset with the owner's session | `preview-e2e` sweep commands |
| M3-K1 | K1 on production | 0 open paths | `node scripts/sso-sweep.mjs https://design.escape.dev` and `https://designs.escape.dev` -> exit 0 |
| M3-K2 | K4 diff | only the files listed in K4, `middleware.ts` ≤ 10 non-blank lines | `git diff --stat`, `grep -cv` |

| slug | title | size | blocked by | checks | guardrails |
|---|---|---|---|---|---|
| google-client | (owner) Google OAuth client, 3 redirect URIs, env vars for Production and the branch preview, Vercel bypass token | S | - | owner confirms; `vercel env ls` shows the 4 names in Production and Preview (autopilot/escape-sso) | PM-1, PM-3 |
| integrate-designs | escape-designs: dependency, `middleware.ts`, asset cache header, strict sweep script with its tests; draft PR | M | docs-release | `npm ci && npm run build` ; `node --test scripts/` ; `node scripts/sso-sweep.mjs --local dist` | PM-2, PM-4, PM-5 |
| preview-e2e | Full gate on the branch preview: sweep without session, owner login, sweep with session, K3 decode | S | integrate-designs, google-client | `node scripts/sso-sweep.mjs https://escape-designs-git-autopilot-escape-sso-escape-tech.vercel.app --dist dist --bypass-file ~/.config/linear-autopilot/escape-designs.bypass` | PM-3, PM-5, PM-8 |
| owner-merge | (owner) Merge the escape-sso PR (no squash) and the escape-designs PR by 2026-11-11 12:00 | S | preview-e2e | production deployment READY | PM-1 |
| verify-production | Final QA: sweep production with and without session, manual logins, KPI table | S | owner-merge | `node scripts/sso-sweep.mjs https://design.escape.dev --dist dist` ; same for `https://designs.escape.dev` | PM-1, PM-2, PM-8 |

## Pre-mortem: most probable failure reasons and their guardrails
Reviewed by codex-sol-b (OpenAI, Tier 1), both passes, 2026-11-10. Full outputs: `.autopilot/plan/premortem-codex-sol-b-{1,2}.md`. A first run (codex-sol-c) was discarded because the planner edited PLAN.md during it.

| # | Failure reason | P | Impact | Guardrail | Where it lives |
|---|---|---|---|---|---|
| PM-1 | Package ships; production stays public past deadline | 0.85 | fatal | `google-client` starts with `scaffold`; owner ticket `owner-merge` with a deadline; M3 not done on a draft PR | tickets `google-client`, `owner-merge`; M3 text (D-2) |
| PM-2 | Broken deployment reports 0 open | 0.8 | severe | strict sweep: only 302-to-login or 401 is closed, anything else fails; empty inventory fails; authenticated 200 checks; fixture tests of the sweep | K1; ticket `integrate-designs` (D-3) |
| PM-3 | Production receives the first deployed gate test | 0.75 | severe | full gate on the branch preview with a registered redirect URI and a bypass token before merge. Rejected part: deploy-author restriction (local `git config user.email` = antoine.carossio@me.com, the accepted author) | ticket `preview-e2e`; architecture "Previews" (D-4) |
| PM-4 | Browser cache outlives the SSO session | 0.7 | severe | gate responses `no-store`; `/assets/*` `private`; K3 excludes already downloaded bytes | architecture "Caching"; K3, K4; rule (D-5) |
| PM-5 | K3 evidence measures the pending cookie | 0.7 | severe | K3 on the callback-issued session (test + decoded real session); suspended-account test as open decision | K3; tickets `oidc-flow`, `preview-e2e` (D-6) |
| PM-6 | Ticket contracts still contradict the approved union | 0.65 | severe | every ticket uses `response \| user \| pass`; only `user` carries identity | tickets `oidc-flow`, adapters (D-7) |
| PM-7 | Node tests certify runtimes they never execute | 0.6 | severe | native handler args kept; CI Node 20 + 24; core and fetch adapter in `edge-runtime` VM. Rejected: per-runtime CI for Workers, Deno, Bun (24 h budget), stated in README | tickets `scaffold`, `adapter-node-fetch`, `docs-release` (D-8) |
| PM-8 | Correct Gmail denial fails the stated manual criterion | 0.9 | moderate | K2 manual accepts Google's `org_internal` error or the 403, no session either way | K2 (D-9) |
| PM-9 | Specified return-path check permits an external redirect | 0.8 | moderate | URL-parsed same-origin check, control characters rejected, tests with `%09`, `%0a`, backslash | architecture "Return path"; ticket `oidc-flow` (D-10) |
| PM-10 | Vercel adapter sends identity in the wrong direction | 0.65 | moderate | `next({ request: { headers } })`, spoofed header stripped and tested | ticket `adapter-vercel` (D-11) |

**Watch for:** at `scaffold` done, owner has not started `google-client`; `--session-check` passing without a session cookie; a sweep run with 0 paths; tests reading `response.headers` for the identity header; any `return=` test list without encoded characters.

## Rules for implementers and reviewers
- Fail closed. Any missing config, thrown error, invalid or expired cookie, or failed check ends in a redirect to login or a 403, never in the protected content. A reviewer rejects any `catch` that lets the request through.
- Every rejection path of K2 has its own test against the fake issuer: no `hd`, other `hd`, `email_verified` false or missing, email domain different from `hd`, wrong audience, wrong issuer, expired token, nonce mismatch, state mismatch, tampered session cookie, expired session. No test is skipped or marked todo.
- The core imports nothing from Node (`node:*`) or Vercel: only Web standard APIs. Adapters import only their own platform. A test imports the core in an environment without Node globals (vitest `environment: 'edge-runtime'` or a check that `src/core` has no `node:` import).
- Never log or return tokens, cookies, codes or secrets, including in error messages.
- No new runtime dependency beyond `jose`, `oauth4webapi` and the optional peer `@vercel/functions`, pinned exactly.
- Cookies: HttpOnly, Secure (except `http://localhost` in tests), SameSite=Lax, Path=/.
- No change in escape-designs outside the files listed in K4.
- Every response produced by the gate carries `Cache-Control: no-store` (PM-4).
- Identity reaches the site only from a verified session: an incoming `x-escape-sso-email` header is always removed first (PM-10).
- A check script fails on anything it does not expect: unknown status, network error, empty input (PM-2).

## Open human decisions
- Google OAuth client: owner creates it (ticket `google-client`). Default meanwhile: everything else is built and tested against the fake issuer; the run waits only on that ticket.
- Merge of the escape-designs draft PR to `main` (deploys production): owner. Default: PR stays draft, production unchanged.
- Session length: 8 h (K3). Default 8 h; a site may set less, never more.
- Suspended-account test (PM-5): needs a test escape.tech account the owner can suspend. Default: not run; K3 notes the suspended-account guarantee as Google's, unverified here.
- Owner deadlines (PM-1): Google client, env vars and bypass token before M2 ends; both merges by 2026-11-11 12:00. Default: if missed, the run stops at `preview-e2e` and reports production still public.

## Decision log
Every change of plan after the first draft, with its source: an answer of the user, a pre-mortem reason, a plan or code
review finding, a re-plan signal, a quota limit, a safe default for an open human decision. Written with `bin/decision add`
before the change is acted on, then mirrored in Linear. A change of plan without a row here is a defect.

| # | Date | Change (before -> after) | Why | Source | Decided by | Affects | Linear |
|---|---|---|---|---|---|---|---|
| D-1 | 2026-11-10 | core handle() returns response \| user -> response \| user \| pass (exact publicPaths need no session) | publicPaths in the config had no result shape; a third one keeps the type honest instead of a null user | coordinator:.autopilot/plan/build_tickets.py oidc-flow ticket, publicPaths routing | claude-opus | oidc-flow, adapter-vercel, adapter-node-fetch | pre-linear |
| D-2 | 2026-11-10 | google-client blocked by docs-release -> blocked by nothing (starts with scaffold); new owner ticket owner-merge before verify-production; owner deadlines: Google client + env vars before M2 ends, merge by 2026-11-11 12:00 | owner work was last on the critical path and the merge had no ticket | premortem:PM-1 | claude-opus | K1, google-client, owner-merge, verify-production | pre-linear |
| D-3 | 2026-11-10 | sweep: open = 2xx or foreign 3xx -> closed only = 302 to accounts.google.com or /auth/login, or 401; any other status, network error, empty inventory or missing dist fails; --cookie mode requires authenticated 200 on /, a nested project page and an asset; sweep has its own fixture tests (leaky, all-404, all-500, correct) | an all-500 server passed the old sweep | premortem:PM-2 | claude-opus | K1, integrate-designs | pre-linear |
| D-4 | 2026-11-10 | no deployed test before production -> new ticket preview-e2e: branch alias escape-designs-git-autopilot-escape-sso-escape-tech.vercel.app registered as redirect URI, 4 env vars on Preview scoped to branch autopilot/escape-sso, sweep with a Vercel protection bypass token plus one owner login; skipOnVercelPreview skips only when SSO_GOOGLE_CLIENT_ID is unset on a preview. Deploy-author part rejected: escape-designs local git user.email is antoine.carossio@me.com, the author Vercel accepts | the Vercel middleware was first exercised on production | premortem:PM-3 | claude-opus | K1, K2, adapter-vercel, google-client, preview-e2e | pre-linear |
| D-5 | 2026-11-10 | vercel.json untouched, /assets public immutable -> /assets Cache-Control private, max-age=31536000, immutable; every gate response no-store; K4 file list adds vercel.json; K3 states it does not revoke bytes already downloaded | public 1-year asset caching outlives the session in shared caches | premortem:PM-4 | claude-opus | K3, K4, integrate-designs, oidc-flow | pre-linear |
| D-6 | 2026-11-10 | K3 measured on the pending cookie -> on the callback-issued session cookie (fake-issuer test, and the owner's preview session decoded by sweep --session-check: exp - iat <= 28800); suspended-account test is an open human decision, default unverified and documented as Google's guarantee | the old check never saw a session cookie | premortem:PM-5 | claude-opus | K3, integrate-designs, preview-e2e, verify-production | pre-linear |
| D-7 | 2026-11-10 | ticket texts with response\|user -> exhaustive response\|user\|pass in every ticket; only user carries identity | tickets contradicted D-1 | premortem:PM-6 | claude-opus | oidc-flow, adapter-vercel, adapter-node-fetch | pre-linear |
| D-8 | 2026-11-10 | fetch adapter replaces the 2nd argument with ctx -> native args kept, identity via getUser(request); env bindings of any type; CI on Node 20 and 24; core and fetch tests also run in vitest edge-runtime (@edge-runtime/vm 5.0.0). Rejected: per-runtime smoke in Workers, Deno and Bun (out of the 24 h budget); README says they are not run in CI | the claimed runtimes were never executed | premortem:PM-7 | claude-opus | scaffold, adapter-node-fetch, docs-release | pre-linear |
| D-9 | 2026-11-10 | K2 manual: gmail.com gets the app 403 -> gets Google's org_internal error or the app 403, and no session either way | an Internal OAuth client stops external accounts at Google | premortem:PM-8 | claude-opus | K2, verify-production | pre-linear |
| D-10 | 2026-11-10 | return path: starts with / not // -> parsed against the request origin, same origin required, control characters rejected, only pathname+search kept; tests for %09, %0a, backslash, protocol-relative | return=/%09/evil.com resolves to evil.com | premortem:PM-9 | claude-opus | oidc-flow | pre-linear |
| D-11 | 2026-11-10 | next({ headers }) -> next({ request: { headers } }); incoming x-escape-sso-email always stripped, set only from a verified user; test a spoofed header | headers set the response, not the upstream request | premortem:PM-10 | claude-opus | adapter-vercel | pre-linear |
| D-12 | 2026-11-10 | preview-e2e check --bypass $VERCEL_BYPASS -> --bypass-file ~/.config/linear-autopilot/escape-designs.bypass | the plan table and the ticket named different flags; the file keeps the secret out of shell history | coordinator:PLAN.md M3 table vs tickets.json preview-e2e CHECKS line | claude-opus | preview-e2e | pre-linear |

## Approval
- Pre-mortem reviewed by: codex-sol-b (OpenAI gpt-6.1-sol) on 2026-11-10
- Plan approved by: Antoine Carossio on 2026-11-10 ("yes, put the plan in pla but assign it to me")
