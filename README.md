# escape-sso

Put Google Workspace sign-in in front of internal sites. Only active, verified accounts from your allowed Google Workspace domains get in; Google handles suspended and deleted accounts. Sessions last at most 8 hours, and every request checks the session. The gate fails closed when configuration or a check fails.

## Install

```sh
npm install github:Escape-Technologies/escape-sso#v1.0.0
```

Pin consumers to the release tag. Do not install from a moving branch.

## Protect a site in 3 steps

**1. Vercel:** Copy [`examples/vercel-static/middleware.ts`](examples/vercel-static/middleware.ts) into the site root as `middleware.ts`. Keep the matcher literal because Vercel reads it statically:

```ts
import { vercelSSO } from 'escape-sso/vercel';

export default vercelSSO();

export const config = { matcher: ['/((?!_vercel).*)'] };
```

**2. Node/Express:** Copy [`examples/node/server.mjs`](examples/node/server.mjs) into the project. Use `expressSSO(config?)` as Express middleware or wrap a Node handler with `nodeSSO(handler, config?)`.

**3. Cloudflare Workers, Deno, or Bun:** Copy [`examples/cloudflare/worker.ts`](examples/cloudflare/worker.ts) into the project. Wrap the handler with `withSSO(handler, config?)`; call `getUser(request)` inside it to read the verified identity. The wrapped handler keeps its runtime's native arguments.

Set the environment variables below in each site's deployment settings. Every site has its own session cookie and login; users with an active Google session usually pass through Google without entering credentials again.

## Environment variables

Required:

| Variable | Value |
| --- | --- |
| `SSO_GOOGLE_CLIENT_ID` | OAuth client ID from Google Cloud. |
| `SSO_GOOGLE_CLIENT_SECRET` | OAuth client secret from Google Cloud. |
| `SSO_SESSION_SECRET` | Random secret of at least 32 UTF-8 bytes. Generate one with `openssl rand -base64 48`. |
| `SSO_ALLOWED_DOMAINS` | Comma-separated Workspace domains, for example `escape.tech`. |

Optional:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SSO_SESSION_TTL_SECONDS` | `28800` | Session lifetime in seconds. Minimum `60`; maximum `28800` (8 hours). |
| `SSO_PUBLIC_PATHS` | empty | Comma-separated exact paths that do not need a session. Wildcards are not supported. |

## Google OAuth client setup

Create one OAuth client for the Workspace and add each site's callback URI to it.

1. Open [Google Cloud console](https://console.cloud.google.com/).
2. Open **APIs & Services > OAuth consent screen**.
3. Set User type to **Internal**. Set app name to `Escape internal sites` and add a support email. Complete the required consent-screen fields and save.
4. Open **Credentials > Create credentials > OAuth client ID**.
5. Select **Web application**.
6. Under **Authorized redirect URIs**, add `https://<site>/auth/callback` for every site. Add each site's exact domain; Google does not accept wildcard redirect URIs. If you test previews, add a stable preview branch alias too.
7. Create the client. Copy its client ID and client secret into each site's `SSO_GOOGLE_CLIENT_ID` and `SSO_GOOGLE_CLIENT_SECRET` environment variables.

An Internal client stops external accounts at Google with an `org_internal` error. Those accounts do not reach the site's callback.

### Adding a site to the existing client

Add one Authorized redirect URI: `https://<new-site>/auth/callback`. Then set the existing client ID and secret in that site's environment variables. Do not create another client.

## Security notes

- Google sends `hd` as an account-domain claim. The package requires `hd` to match an allowed domain and the email domain to match `hd`; a sign-in hint alone does not grant access. Google issues tokens only for accounts it accepts, including its active-account check.
- Sessions last no more than 8 hours and do not slide forward with traffic. Expired sessions require another Google check.
- The gate cannot revoke bytes a browser already downloaded during a valid session.
- Sites do not share login cookies or sessions. Each site has its own session.
- Google does not allow wildcard redirect URIs. Preview login works only for a preview URL or stable branch alias registered in the OAuth client.
- Vercel middleware strips incoming `x-escape-sso-email` and forwards that header only for a verified user.
- Every gate response uses `Cache-Control: no-store`. Protect static assets with private caching too; a shared cache must not serve protected files without running the gate.

## Supported runtimes

CI tests Node 20 and Node 24, the Vercel middleware contract, and the core and fetch adapter in an edge-runtime VM. Cloudflare Workers, Deno, and Bun use the same Web APIs in the fetch adapter, but CI does not run those runtimes.

## Releasing

Tag releases as `vX.Y.Z`; consumers pin the tag in their Git dependency. Merge the escape-sso PR with a merge commit or fast-forward, never squash or rebase, so the tagged commit stays in `main`'s history.
