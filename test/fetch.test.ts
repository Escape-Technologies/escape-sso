import { afterEach, describe, expect, it, vi } from 'vitest';
import { withSSO, getUser } from '../src/adapters/fetch.js';
import { createFakeGoogle } from './helpers/fake-google.js';

const config = { clientId: 'fetch-client', clientSecret: 'fetch-secret', sessionSecret: 'a fetch adapter session secret long enough', allowedDomains: ['escape.tech'], issuer: 'https://accounts.google.com' };
const env = { SSO_GOOGLE_CLIENT_ID: config.clientId, SSO_GOOGLE_CLIENT_SECRET: config.clientSecret, SSO_SESSION_SECRET: config.sessionSecret, SSO_ALLOWED_DOMAINS: 'escape.tech', IGNORED_BINDING: 42 };
const restoreFetch: Array<() => void> = [];
afterEach(() => { while (restoreFetch.length) restoreFetch.pop()!(); });

async function fakeFetch() {
  const fake = await createFakeGoogle(config);
  const original = globalThis.fetch;
  vi.stubGlobal('fetch', fake.fetch);
  restoreFetch.push(() => vi.stubGlobal('fetch', original));
  return fake;
}

async function authorize(fetchHandler: (request: Request, ...args: any[]) => Response | Promise<Response>) {
  const fake = await fakeFetch();
  fake.issueCode();
  const handler = withSSO(fetchHandler, config);
  const login = await handler(new Request('https://fetch.example/auth/login'));
  const google = await fake.fetch(new URL(login.headers.get('Location')!));
  const callbackUrl = new URL(google.headers.get('Location')!);
  const pending = login.headers.get('Set-Cookie')!.split(';', 1)[0]!;
  const callback = await handler(new Request(callbackUrl, { headers: { Cookie: pending } }));
  return { handler, callback };
}

describe('fetch adapter', () => {
  it('redirects HTML and rejects assets without session', async () => {
    const handler = withSSO(() => new Response('app'), config);
    const login = await handler(new Request('https://fetch.example/private', { headers: { Accept: 'text/html' } }));
    expect(login.status).toBe(302);
    expect(new URL(login.headers.get('Location')!, 'https://fetch.example').pathname).toBe('/auth/login');
    const asset = await handler(new Request('https://fetch.example/assets/a.js', { headers: { Accept: '*/*', 'x-escape-sso-email': 'attacker@example.com' } }));
    expect(asset.status).toBe(401);
    expect(asset.headers.get('Cache-Control')).toBe('no-store');
  });

  it('returns undefined identity for public pass-through paths', async () => {
    let identity: ReturnType<typeof getUser> = { email: 'stale@example.com' };
    const handler = withSSO((request) => { identity = getUser(request); return new Response('public'); }, { ...config, publicPaths: ['/open'] });
    const response = await handler(new Request('https://fetch.example/open'));
    expect(await response.text()).toBe('public');
    expect(identity).toBeUndefined();
  });

  it('completes login, preserves two cookies, native args, and request identity', async () => {
    let received: Request | undefined;
    let receivedEnv: unknown;
    let receivedCtx: unknown;
    const userEnv = { ...env };
    const ctx = { waitUntil() {} };
    const nativeHandler = (request: Request, actualEnv: typeof userEnv, actualCtx: typeof ctx) => {
      received = request;
      receivedEnv = actualEnv;
      receivedCtx = actualCtx;
      return new Response(getUser(request)?.email ?? 'missing');
    };
    const { handler, callback } = await authorize(nativeHandler);
    expect(callback.status).toBe(302);
    expect(callback.headers.getSetCookie()).toHaveLength(2);
    const session = callback.headers.getSetCookie().find((cookie) => cookie.startsWith('escape_sso='))!.split(';', 1)[0]!;
    const request = new Request('https://fetch.example/private', { headers: { Cookie: session, 'x-escape-sso-email': 'attacker@example.com' } });
    const response = await handler(request, userEnv, ctx);
    expect(await response.text()).toBe('user@escape.tech');
    expect(receivedEnv).toBe(userEnv);
    expect(receivedCtx).toBe(ctx);
    expect(received).toBe(request);
    expect(received?.headers.has('x-escape-sso-email')).toBe(false);
    expect(getUser(received!)).toEqual({ email: 'user@escape.tech' });
  });

  it('uses Workers env only for Workers-shaped calls and process env for Bun and Deno shapes', async () => {
    const handler = withSSO(() => new Response('app'));
    const request = new Request('https://fetch.example/private', { headers: { Accept: '*/*' } });
    const missing = await handler(request, { ...env, SSO_SESSION_SECRET: 7 }, { waitUntil() {} });
    expect(missing.status).toBe(500);
    const original = process.env;
    process.env = { ...original, SSO_GOOGLE_CLIENT_ID: config.clientId, SSO_GOOGLE_CLIENT_SECRET: config.clientSecret, SSO_SESSION_SECRET: config.sessionSecret, SSO_ALLOWED_DOMAINS: 'escape.tech' };
    try {
      expect((await handler(request, { waitUntil() {} })).status).toBe(401);
      expect((await handler(request, { server: true })).status).toBe(401);
    } finally { process.env = original; }
  });

  it('returns a no-store 500 for missing config and does not call app', async () => {
    const app = vi.fn(() => new Response('secret app'));
    const response = await withSSO(app)(new Request('https://fetch.example/private'));
    expect(response.status).toBe(500);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(app).not.toHaveBeenCalled();
  }, 10000);

  it('returns a generic no-store 500 when gate throws, without calling app', async () => {
    const app = vi.fn(() => new Response('protected content'));
    const request = { url: 'http://[', headers: new Headers() } as Request;
    const response = await withSSO(app, config)(request);
    expect(response.status).toBe(500);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(await response.text()).not.toContain('protected content');
    expect(app).not.toHaveBeenCalled();
  }, 10000);
});
