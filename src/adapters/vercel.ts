import { next } from '@vercel/functions/middleware';
import { configFromEnv, createSSO, type SSOConfig } from '../core/index.js';

// Vercel reads `config.matcher` statically, so sites must write the literal array
// in middleware.ts (see examples/vercel-static/middleware.ts); an imported identifier is rejected.
export const vercelMatcher = '/((?!_vercel).*)';

const EMAIL_HEADER = 'x-escape-sso-email';
const NO_STORE = { 'Cache-Control': 'no-store' };

export type VercelSSOConfig = Partial<SSOConfig> & { skipOnVercelPreview?: boolean };

// `options.fetch` is undocumented: tests inject the fake Google issuer through it.
export function vercelSSO(
  config: VercelSSOConfig = {},
  options: { fetch?: typeof fetch } = {},
): (request: Request) => Promise<Response | undefined> {
  const { skipOnVercelPreview = false, ...overrides } = config;
  const merged: Record<string, unknown> = { ...configFromEnv(process.env) };
  Object.assign(merged, overrides);
  // One instance per vercelSSO call, created on the first request.
  let instance: ReturnType<typeof createSSO> | undefined;

  return async function sso(request: Request): Promise<Response | undefined> {
    try {
      if (skipOnVercelPreview && process.env.VERCEL_ENV === 'preview' && process.env.SSO_GOOGLE_CLIENT_ID === undefined) {
        return next({ request: { headers: withoutEmail(request.headers) } });
      }
      instance ??= createSSO(merged, { fetch: options.fetch });
      const result = await instance.handle(request);
      if ('response' in result) return result.response;
      if ('user' in result) {
        const headers = withoutEmail(request.headers);
        headers.set(EMAIL_HEADER, result.user.email);
        return next({ request: { headers } });
      }
      return next({ request: { headers: withoutEmail(request.headers) } });
    } catch {
      return new Response('SSO failed', { status: 500, headers: { ...NO_STORE, 'Content-Type': 'text/plain; charset=utf-8' } });
    }
  };
}

function withoutEmail(incoming: Headers): Headers {
  const headers = new Headers(incoming);
  headers.delete(EMAIL_HEADER);
  return headers;
}
