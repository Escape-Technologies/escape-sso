import { describe, expect, it } from 'vitest';
import { createSSO, type SSOOptions } from '../src/core/index.js';
import { createFakeGoogle, type FakeGoogle } from './helpers/fake-google.js';

const clientId = 'test-client-id';
const clientSecret = 'test-client-secret';
const sessionSecret = 'a sufficiently long session secret for tests';
const baseConfig = {
  clientId,
  clientSecret,
  sessionSecret,
  allowedDomains: ['escape.tech'],
};

async function setup(claims: Record<string, unknown> = {}, options: SSOOptions = {}, fakeOptions: { fetch?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> } = {}) {
  const fake = await createFakeGoogle({ clientId, clientSecret });
  const fetcher = fakeOptions.fetch ?? fake.fetch;
  const sso = createSSO({ ...baseConfig, issuer: 'https://accounts.google.com' }, { fetch: fetcher, ...options });
  return { fake, sso, claims };
}

async function loginAndCallback(fake: FakeGoogle, sso: ReturnType<typeof createSSO>, claims: Record<string, unknown> = {}, returnTo?: string, requestHost = 'app.example') {
  fake.issueCode(claims);
  const query = returnTo === undefined ? '' : `?return=${returnTo}`;
  const login = await sso.handle(new Request(`https://${requestHost}/auth/login${query}`));
  expect('response' in login).toBe(true);
  const loginResponse = (login as { response: Response }).response;
  expectNoStore(loginResponse);
  const authorization = new URL(loginResponse.headers.get('Location')!);
  const google = await fake.fetch(authorization);
  const callbackUrl = new URL(google.headers.get('Location')!);
  const pending = loginResponse.headers.get('Set-Cookie')!.split(';', 1)[0];
  const callback = await sso.handle(new Request(callbackUrl, { headers: { Cookie: pending } }));
  expect('response' in callback).toBe(true);
  return { loginResponse, callback: (callback as { response: Response }).response, callbackUrl, pending };
}

function expectNoStore(response: Response): void {
  expect(response.headers.get('Cache-Control')).toBe('no-store');
}

function sessionCookie(response: Response): string | null {
  const setCookie = response.headers.get('Set-Cookie');
  return setCookie?.split(/, (?=[^;,]+=)/).find((part) => part.startsWith('escape_sso='))?.split(';', 1)[0] ?? null;
}

describe('createSSO flow', () => {
  it('accepts verified escape.tech account and session', async () => {
    const { fake, sso } = await setup();
    const { callback } = await loginAndCallback(fake, sso, {}, '/inside?x=1');
    expectNoStore(callback);
    expect(callback.status).toBe(302);
    expect(new URL(callback.headers.get('Location')!).pathname + new URL(callback.headers.get('Location')!).search).toBe('/inside?x=1');
    const cookie = sessionCookie(callback);
    expect(cookie).toContain('escape_sso=');
    const next = await sso.handle(new Request('https://app.example/inside', { headers: { Cookie: cookie! } }));
    expect(next).toEqual({ user: { email: 'user@escape.tech' } });
  });

  it('rejects gmail account without hosted domain', async () => {
    const { fake, sso } = await setup();
    const { callback } = await loginAndCallback(fake, sso, { hd: undefined, email: 'user@gmail.com' });
    expectNoStore(callback);
    expect(callback.status).toBe(403);
    expect(await callback.clone().text()).toContain('Access restricted to escape.tech Google accounts');
    expect(await callback.clone().text()).toContain('/auth/login?switch=1');
    expect(sessionCookie(callback)).toBeNull();
  });

  it('rejects other hosted domain', async () => {
    const { fake, sso } = await setup();
    const { callback } = await loginAndCallback(fake, sso, { hd: 'other.com', email: 'user@other.com' });
    expectNoStore(callback);
    expect(callback.status).toBe(403);
    expect(sessionCookie(callback)).toBeNull();
  });

  it('rejects unverified email', async () => {
    const { fake, sso } = await setup();
    const { callback } = await loginAndCallback(fake, sso, { email_verified: false });
    expectNoStore(callback);
    expect(callback.status).toBe(403);
    expect(sessionCookie(callback)).toBeNull();
  });

  it('rejects missing email_verified', async () => {
    const { fake, sso } = await setup();
    const { callback } = await loginAndCallback(fake, sso, { email_verified: undefined });
    expectNoStore(callback);
    expect(callback.status).toBe(403);
    expect(sessionCookie(callback)).toBeNull();
  });

  it('rejects email domain different from hd', async () => {
    const { fake, sso } = await setup();
    const { callback } = await loginAndCallback(fake, sso, { email: 'x@other.com' });
    expectNoStore(callback);
    expect(callback.status).toBe(403);
    expect(sessionCookie(callback)).toBeNull();
  });

  it('rejects wrong audience', async () => {
    const { fake, sso } = await setup();
    const { callback } = await loginAndCallback(fake, sso, { aud: 'wrong-client' });
    expectNoStore(callback);
    expect(callback.status).toBe(403);
    expect(sessionCookie(callback)).toBeNull();
  });

  it('rejects wrong issuer', async () => {
    const { fake, sso } = await setup();
    const { callback } = await loginAndCallback(fake, sso, { iss: 'https://wrong.example' });
    expectNoStore(callback);
    expect(callback.status).toBe(403);
    expect(sessionCookie(callback)).toBeNull();
  });

  it('rejects expired ID token', async () => {
    const { fake, sso } = await setup();
    const { callback } = await loginAndCallback(fake, sso, { exp: Math.floor(Date.now() / 1000) - 10 });
    expectNoStore(callback);
    expect(callback.status).toBe(403);
    expect(sessionCookie(callback)).toBeNull();
  });

  it('rejects nonce mismatch', async () => {
    const { fake, sso } = await setup();
    const { callback } = await loginAndCallback(fake, sso, { nonce: 'wrong' });
    expectNoStore(callback);
    expect(callback.status).toBe(403);
    expect(sessionCookie(callback)).toBeNull();
  });

  it('rejects state mismatch', async () => {
    const { fake, sso } = await setup();
    fake.issueCode();
    const login = await sso.handle(new Request('https://app.example/auth/login'));
    const loginResponse = (login as { response: Response }).response;
    const google = await fake.fetch(new URL(loginResponse.headers.get('Location')!));
    const callbackUrl = new URL(google.headers.get('Location')!);
    callbackUrl.searchParams.set('state', 'wrong');
    const response = (await sso.handle(new Request(callbackUrl, { headers: { Cookie: loginResponse.headers.get('Set-Cookie')!.split(';', 1)[0] } }))) as { response: Response };
    expectNoStore(response.response);
    expect(response.response.status).toBe(403);
    expect(sessionCookie(response.response)).toBeNull();
  });

  it('rejects ID token signed by foreign key', async () => {
    const { fake, sso } = await setup();
    const { callback } = await loginAndCallback(fake, sso, { signWithForeignKey: true });
    expectNoStore(callback);
    expect(callback.status).toBe(403);
    expect(sessionCookie(callback)).toBeNull();
  });

  it('rejects tampered session cookie', async () => {
    const { sso } = await setup();
    const result = await sso.handle(new Request('https://app.example/private', { headers: { Accept: 'text/html', Cookie: 'escape_sso=not-a-token' } }));
    expectNoStore((result as { response: Response }).response);
    expect((result as { response: Response }).response.status).toBe(302);
  });

  it('rejects expired session', async () => {
    const { fake, sso } = await setup();
    const { callback } = await loginAndCallback(fake, sso);
    const cookie = sessionCookie(callback)!;
    const session = cookie.slice(cookie.indexOf('=') + 1);
    const exp = JSON.parse(atob(session.split('.')[1].replaceAll('-', '+').replaceAll('_', '/'))).exp;
    const expired = createSSO({ ...baseConfig, issuer: 'https://accounts.google.com' }, { now: () => exp + 1 });
    const result = await expired.handle(new Request('https://app.example/private', { headers: { Accept: 'text/html', Cookie: cookie } }));
    expectNoStore((result as { response: Response }).response);
    expect((result as { response: Response }).response.status).toBe(302);
  });

  it('rejects unsafe return paths and keeps safe path', async () => {
    const bad = ['/.//evil.com/x', 'https://app.example//evil.com/x', '//evil.com', 'https://evil.com', '/%09/evil.com', '/%0a/evil.com', '/\\evil.com', '%2F%2Fevil.com'];
    for (const value of bad) {
      const { fake, sso } = await setup();
      const { callback } = await loginAndCallback(fake, sso, {}, value);
      expectNoStore(callback);
      expect(callback.status).toBe(302);
      expect(new URL(callback.headers.get('Location')!).origin).toBe('https://app.example');
      expect(new URL(callback.headers.get('Location')!).pathname).toBe('/');
    }
    const { fake, sso } = await setup();
    const safe = await loginAndCallback(fake, sso, {}, '/a/b?x=1');
    expect(new URL(safe.callback.headers.get('Location')!).pathname + new URL(safe.callback.headers.get('Location')!).search).toBe('/a/b?x=1');
  });

  it('returns 401 for asset request without session', async () => {
    const { sso } = await setup();
    const result = await sso.handle(new Request('https://app.example/assets/x.js', { headers: { Accept: '*/*' } }));
    expectNoStore((result as { response: Response }).response);
    expect((result as { response: Response }).response.status).toBe(401);
    expect(await (result as { response: Response }).response.text()).toBe('');
  });

  it('returns 500 on every path when misconfigured', async () => {
    const sso = createSSO({ ...baseConfig, sessionSecret: 'short' });
    for (const path of ['/auth/login', '/auth/callback', '/auth/logout', '/private']) {
      const result = await sso.handle(new Request(`https://app.example${path}`));
      const response = (result as { response: Response }).response;
      expectNoStore(response);
      expect(response.status).toBe(500);
      expect(await response.text()).toBe('SSO misconfigured: sessionSecret');
    }
  });

  it('accepts uppercase hosted domain and email', async () => {
    const { fake, sso } = await setup();
    const { callback } = await loginAndCallback(fake, sso, { email: 'X@Escape.Tech', hd: 'Escape.Tech' });
    expectNoStore(callback);
    expect(callback.status).toBe(302);
    expect(sessionCookie(callback)).toContain('escape_sso=');
  });

  it('shows terminal page when pending cookie is missing or tampered', async () => {
    const { sso } = await setup();
    for (const cookie of [undefined, 'escape_sso_pending=bad']) {
      const result = await sso.handle(new Request('https://app.example/auth/callback?code=abc&state=abc', { headers: cookie ? { Cookie: cookie } : {} }));
      const response = (result as { response: Response }).response;
      expectNoStore(response);
      expect(response.status).toBe(403);
      expect(response.headers.get('Location')).toBeNull();
      expect(await response.text()).toContain('/auth/login');
      expect(sessionCookie(response)).toBeNull();
    }
  });

  it('matches public paths exactly', async () => {
    const sso = createSSO({ ...baseConfig, publicPaths: ['/public'] });
    expect(await sso.handle(new Request('https://app.example/public'))).toEqual({ pass: true });
    const subpath = await sso.handle(new Request('https://app.example/public/x', { headers: { Accept: '*/*' } }));
    expectNoStore((subpath as { response: Response }).response);
    expect((subpath as { response: Response }).response.status).toBe(401);
  });

  it('logs out with a clearing cookie and requires login next', async () => {
    const { fake, sso } = await setup();
    const { callback } = await loginAndCallback(fake, sso);
    const logout = (await sso.handle(new Request('https://app.example/auth/logout', { headers: { Cookie: sessionCookie(callback)! } }))) as { response: Response };
    expectNoStore(logout.response);
    expect(logout.response.status).toBe(200);
    const logoutBody = await logout.response.text();
    expect(logoutBody).toContain('Signed out');
    expect(logoutBody).toContain('/auth/login');
    expect(logout.response.headers.get('Set-Cookie')).toContain('escape_sso=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax');
    const next = (await sso.handle(new Request('https://app.example/private', { headers: { Accept: 'text/html' } }))) as { response: Response };
    expectNoStore(next.response);
    expect(next.response.status).toBe(302);
  });

  it('fails closed on discovery, token, and JWKS operational errors', async () => {
    const discoveryFailure = await setup({}, {}, { fetch: async () => { throw new Error('secret token cookie code'); } });
    const discovery = (await discoveryFailure.sso.handle(new Request('https://app.example/auth/login'))) as { response: Response };
    expectNoStore(discovery.response);
    expect([500, 503]).toContain(discovery.response.status);
    expect(await discovery.response.text()).not.toMatch(/token|cookie|code|secret/i);

    for (const endpoint of ['/token', '/.well-known/jwks.json']) {
      const fake = await createFakeGoogle({ clientId, clientSecret });
      const fetcher: typeof fetch = async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        if (new URL(request.url).pathname === endpoint) return new Response('unavailable', { status: 500 });
        return fake.fetch(request);
      };
      const sso = createSSO({ ...baseConfig, issuer: 'https://accounts.google.com' }, { fetch: fetcher });
      const { callback } = await loginAndCallback(fake, sso);
      expectNoStore(callback);
      expect(callback.status).toBe(403);
      expect(sessionCookie(callback)).toBeNull();
      expect(await callback.text()).not.toMatch(/token|cookie|code|secret/i);
    }
  });

  it('retries discovery after a transient failure', async () => {
    const fake = await createFakeGoogle({ clientId, clientSecret });
    let discoveryAttempts = 0;
    const fetcher: typeof fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (new URL(request.url).pathname === '/.well-known/openid-configuration' && discoveryAttempts++ === 0) {
        throw new Error('temporary discovery failure');
      }
      return fake.fetch(request);
    };
    const sso = createSSO({ ...baseConfig, issuer: 'https://accounts.google.com' }, { fetch: fetcher });
    const first = (await sso.handle(new Request('https://app.example/auth/login'))) as { response: Response };
    expectNoStore(first.response);
    expect(first.response.status).toBe(503);

    const second = (await sso.handle(new Request('https://app.example/auth/login'))) as { response: Response };
    expectNoStore(second.response);
    expect(second.response.status).toBe(302);
    expect(discoveryAttempts).toBe(2);
  });

  it('issues sessions capped at eight hours without sliding expiry', async () => {
    let now = Math.floor(Date.now() / 1000);
    const { fake } = await setup();
    const sso = createSSO({ ...baseConfig, issuer: 'https://accounts.google.com' }, { fetch: fake.fetch, now: () => now });
    const { callback } = await loginAndCallback(fake, sso);
    const rawCookie = sessionCookie(callback)!;
    const jwt = rawCookie.slice(rawCookie.indexOf('=') + 1);
    const payload = JSON.parse(atob(jwt.split('.')[1].replaceAll('-', '+').replaceAll('_', '/')));
    expect(Number(callback.headers.get('Set-Cookie')!.match(/Max-Age=(\d+)/)?.[1])).toBeLessThanOrEqual(28800);
    expect(payload.exp - payload.iat).toBeLessThanOrEqual(28800);
    now += 3600;
    const later = await sso.handle(new Request('https://app.example/private', { headers: { Cookie: rawCookie } }));
    expect(later).toHaveProperty('user');
    expect('response' in later && later.response.headers.has('Set-Cookie')).toBe(false);
    now = payload.exp + 1;
    const expired = (await sso.handle(new Request('https://app.example/private', { headers: { Accept: 'text/html', Cookie: rawCookie } }))) as { response: Response };
    expectNoStore(expired.response);
    expect(expired.response.status).toBe(302);
  });

  it('sets no-store on gate responses', async () => {
    const { sso } = await setup();
    for (const request of [
      new Request('https://app.example/auth/logout'),
      new Request('https://app.example/missing', { headers: { Accept: '*/*' } }),
      new Request('https://app.example/missing', { headers: { Accept: 'text/html' } }),
    ]) {
      const result = (await sso.handle(request)) as { response: Response };
      expectNoStore(result.response);
    }
  });
});
