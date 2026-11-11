# vercel-static example

Protects a static site (`framework: null`) with escape-sso. Copy `middleware.ts` to the site root.

1. Install `escape-sso` as a git dependency and `@vercel/functions` as its peer.
2. Set `SSO_GOOGLE_CLIENT_ID`, `SSO_GOOGLE_CLIENT_SECRET`, `SSO_SESSION_SECRET` (32+ bytes) and `SSO_ALLOWED_DOMAINS=escape.tech`.
3. Keep the matcher literal in `middleware.ts`: Vercel reads it statically.
```ts
export const config = { matcher: ['/((?!_vercel).*)'] };
```
