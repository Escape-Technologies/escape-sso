import { describe, expect, it, vi } from 'vitest';
import { getUser, withSSO } from '../../src/adapters/fetch.js';
import { createFakeGoogle } from '../helpers/fake-google.js';

const config = { clientId: 'edge-fetch-client', clientSecret: 'edge-fetch-secret', sessionSecret: 'edge fetch session secret long enough', allowedDomains: ['escape.tech'], issuer: 'https://accounts.google.com' };

describe('fetch adapter in edge runtime', () => {
  it('runs login and passes Workers arguments unchanged with verified identity', async () => {
    const fake = await createFakeGoogle(config);
    const originalFetch = globalThis.fetch;
    vi.stubGlobal('fetch', fake.fetch);
    try {
      fake.issueCode();
      const env = { SSO_GOOGLE_CLIENT_ID: config.clientId, SSO_GOOGLE_CLIENT_SECRET: config.clientSecret, SSO_SESSION_SECRET: config.sessionSecret, SSO_ALLOWED_DOMAINS: 'escape.tech', OTHER: false };
      const ctx = { waitUntil() {} };
      let args: unknown[] = [];
      const wrapped = withSSO((...received: [Request, typeof env, typeof ctx]) => {
        args = received;
        return new Response(getUser(received[0])?.email ?? 'missing');
      });
      const noSession = await wrapped(new Request('https://edge-fetch.example/private', { headers: { Accept: 'text/html' } }), env, ctx);
      expect(noSession.status).toBe(302);
      const asset = await wrapped(new Request('https://edge-fetch.example/assets/a.js', { headers: { Accept: '*/*' } }), env, ctx);
      expect(asset.status).toBe(401);
      const login = await wrapped(new Request('https://edge-fetch.example/auth/login'), env, ctx);
      const google = await fake.fetch(new URL(login.headers.get('Location')!));
      const callbackUrl = new URL(google.headers.get('Location')!);
      const callback = await wrapped(new Request(callbackUrl, { headers: { Cookie: login.headers.get('Set-Cookie')!.split(';', 1)[0]! } }), env, ctx);
      expect(callback.headers.getSetCookie()).toHaveLength(2);
      const session = callback.headers.getSetCookie().find((cookie) => cookie.startsWith('escape_sso='))!.split(';', 1)[0]!;
      const appRequest = new Request('https://edge-fetch.example/private', { headers: { Cookie: session, 'x-escape-sso-email': 'spoof@example.com' } });
      const response = await wrapped(appRequest, env, ctx);
      expect(await response.text()).toBe('user@escape.tech');
      expect(args[1]).toBe(env);
      expect(args[2]).toBe(ctx);
      expect((args[0] as Request).headers.has('x-escape-sso-email')).toBe(false);
      expect(getUser(args[0] as Request)).toEqual({ email: 'user@escape.tech' });
    } finally { vi.stubGlobal('fetch', originalFetch); }
  }, 10000);
});
