import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { vercelSSO } from '../src/adapters/vercel.js';
import { createFakeGoogle, type FakeGoogle } from './helpers/fake-google.js';

const clientId = 'test-client-id';
const clientSecret = 'test-client-secret';
const sessionSecret = 'a sufficiently long session secret for tests';
const otherSessionSecret = 'another sufficiently long session secret for tests';
const baseConfig = {
  clientId,
  clientSecret,
  sessionSecret,
  allowedDomains: ['escape.tech'],
  issuer: 'https://accounts.google.com',
};
const origin = 'https://app.example';
const emailHeader = 'x-middleware-request-x-escape-sso-email';
const overrideHeader = 'x-middleware-override-headers';

type Middleware = ReturnType<typeof vercelSSO>;

// Keep SSO_* and VERCEL_* of the developer's shell out of the tests.
const savedEnv: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const key of Object.keys(process.env)) {
    if (key.startsWith('SSO_') || key.startsWith('VERCEL_')) {
      savedEnv[key] = process.env[key];
      delete process.env[key];
    }
  }
});
afterEach(() => {
  for (const key of Object.keys(process.env)) {
    if (key.startsWith('SSO_') || key.startsWith('VERCEL_')) delete process.env[key];
  }
  Object.assign(process.env, savedEnv);
  for (const key of Object.keys(savedEnv)) delete savedEnv[key];
});

function overriddenHeaders(response: Response | undefined): string[] {
  expect(response?.headers.get('x-middleware-next')).toBe('1');
  return (response!.headers.get(overrideHeader) ?? '').split(',').filter(Boolean);
}

// Logs in through the middleware itself and returns the session cookie from the callback.
async function sessionCookieFor(fake: FakeGoogle, middleware: Middleware, claims: Record<string, unknown> = { email: 'a@escape.tech' }): Promise<string> {
  fake.issueCode(claims);
  const login = (await middleware(new Request(`${origin}/auth/login`)))!;
  expect(login.status).toBe(302);
  const google = await fake.fetch(new URL(login.headers.get('Location')!));
  const pending = login.headers.getSetCookie()[0].split(';', 1)[0];
  const callback = (await middleware(new Request(new URL(google.headers.get('Location')!), { headers: { Cookie: pending } })))!;
  expect(callback.status).toBe(302);
  const session = callback.headers.getSetCookie().find((cookie) => cookie.startsWith('escape_sso='));
  return session!.split(';', 1)[0];
}

describe('vercelSSO', () => {
  it('answers no-store 302 to login without a cookie', async () => {
    const fake = await createFakeGoogle({ clientId, clientSecret });
    const middleware = vercelSSO(baseConfig, { fetch: fake.fetch });
    const response = (await middleware(new Request(`${origin}/inside`)))!;
    expect(response.status).toBe(302);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(response.headers.get('Location')).toBe('/auth/login?return=%2Finside');
  });

  it('forwards the verified email upstream with a request override, not a response header', async () => {
    const fake = await createFakeGoogle({ clientId, clientSecret });
    const middleware = vercelSSO(baseConfig, { fetch: fake.fetch });
    const cookie = await sessionCookieFor(fake, middleware);
    const response = await middleware(new Request(`${origin}/inside`, { headers: { Cookie: cookie } }));
    expect(overriddenHeaders(response)).toContain('x-escape-sso-email');
    expect(response!.headers.get(emailHeader)).toBe('a@escape.tech');
    expect(response!.headers.get('x-escape-sso-email')).toBeNull();
  });

  it('gates a spoofed email header without a session', async () => {
    const fake = await createFakeGoogle({ clientId, clientSecret });
    const middleware = vercelSSO(baseConfig, { fetch: fake.fetch });
    const response = (await middleware(new Request(`${origin}/inside`, { headers: { 'x-escape-sso-email': 'evil@escape.tech' } })))!;
    expect(response.status).toBe(302);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(response.headers.get('x-middleware-next')).toBeNull();
  });

  it('replaces a spoofed email header with the session email', async () => {
    const fake = await createFakeGoogle({ clientId, clientSecret });
    const middleware = vercelSSO(baseConfig, { fetch: fake.fetch });
    const cookie = await sessionCookieFor(fake, middleware);
    const response = await middleware(new Request(`${origin}/inside`, {
      headers: { Cookie: cookie, 'x-escape-sso-email': 'evil@escape.tech' },
    }));
    expect(response!.headers.get(emailHeader)).toBe('a@escape.tech');
    expect(overriddenHeaders(response)).toContain('x-escape-sso-email');
  });

  it('pass on a public path strips the spoofed header and keeps unrelated headers', async () => {
    const fake = await createFakeGoogle({ clientId, clientSecret });
    const middleware = vercelSSO({ ...baseConfig, publicPaths: ['/public'] }, { fetch: fake.fetch });
    const response = await middleware(new Request(`${origin}/public`, {
      headers: { 'x-escape-sso-email': 'evil@escape.tech', 'x-unrelated': 'kept' },
    }));
    const overridden = overriddenHeaders(response);
    expect(overridden).not.toContain('x-escape-sso-email');
    expect(response!.headers.get(emailHeader)).toBeNull();
    expect(overridden).toContain('x-unrelated');
    expect(response!.headers.get('x-middleware-request-x-unrelated')).toBe('kept');
  });

  it('skips on a preview with the flag and no client id, with the spoofed header removed', async () => {
    process.env.VERCEL_ENV = 'preview';
    const middleware = vercelSSO({ skipOnVercelPreview: true, sessionSecret, allowedDomains: ['escape.tech'] });
    const response = await middleware(new Request(`${origin}/inside`, { headers: { 'x-escape-sso-email': 'evil@escape.tech' } }));
    expect(overriddenHeaders(response)).not.toContain('x-escape-sso-email');
    expect(response!.headers.get(emailHeader)).toBeNull();
  });

  it('runs the gate on a preview with the flag when a client id is set', async () => {
    process.env.VERCEL_ENV = 'preview';
    process.env.SSO_GOOGLE_CLIENT_ID = clientId;
    const middleware = vercelSSO({ skipOnVercelPreview: true, clientSecret, sessionSecret, allowedDomains: ['escape.tech'] });
    const response = (await middleware(new Request(`${origin}/inside`)))!;
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('/auth/login?return=%2Finside');
  });

  it('skips on a preview when only the argument carries a client id, since the skip reads SSO_GOOGLE_CLIENT_ID', async () => {
    process.env.VERCEL_ENV = 'preview';
    const middleware = vercelSSO({ skipOnVercelPreview: true, ...baseConfig });
    const response = await middleware(new Request(`${origin}/inside`, { headers: { 'x-escape-sso-email': 'evil@escape.tech' } }));
    expect(overriddenHeaders(response)).not.toContain('x-escape-sso-email');
    expect(response!.headers.get(emailHeader)).toBeNull();
  });

  it('never skips in production, even with the flag and no config', async () => {
    process.env.VERCEL_ENV = 'production';
    const middleware = vercelSSO({ skipOnVercelPreview: true });
    const response = (await middleware(new Request(`${origin}/inside`)))!;
    expect(response.status).toBe(500);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(response.headers.get('x-middleware-next')).toBeNull();
  });

  it('fails closed with 500 when config is missing outside a preview', async () => {
    const middleware = vercelSSO({ allowedDomains: ['escape.tech'] });
    const response = (await middleware(new Request(`${origin}/inside`)))!;
    expect(response.status).toBe(500);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
  });

  it('reads config from the environment and lets the argument win', async () => {
    process.env.SSO_GOOGLE_CLIENT_ID = 'env-client-id';
    process.env.SSO_GOOGLE_CLIENT_SECRET = clientSecret;
    process.env.SSO_SESSION_SECRET = sessionSecret;
    process.env.SSO_ALLOWED_DOMAINS = 'escape.tech';
    const fake = await createFakeGoogle({ clientId: 'env-client-id', clientSecret });
    const fromEnv = vercelSSO({}, { fetch: fake.fetch });
    const fromArgument = vercelSSO({ clientId: 'other-client-id' }, { fetch: fake.fetch });
    const cookie = await sessionCookieFor(fake, fromEnv);
    const withEnv = await fromEnv(new Request(`${origin}/inside`, { headers: { Cookie: cookie } }));
    expect(withEnv!.headers.get(emailHeader)).toBe('a@escape.tech');
    const login = (await fromArgument(new Request(`${origin}/auth/login`)))!;
    expect(new URL(login.headers.get('Location')!).searchParams.get('client_id')).toBe('other-client-id');
  });

  it('keeps explicit undefined overrides instead of falling back to the environment', async () => {
    process.env.SSO_GOOGLE_CLIENT_ID = clientId;
    process.env.SSO_GOOGLE_CLIENT_SECRET = clientSecret;
    process.env.SSO_SESSION_SECRET = sessionSecret;
    process.env.SSO_ALLOWED_DOMAINS = 'escape.tech';
    const middleware = vercelSSO({ clientId: undefined });
    const response = (await middleware(new Request(`${origin}/inside`)))!;
    expect(response.status).toBe(500);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
  });

  describe('two middlewares with different configs', () => {
    type Name = 'one' | 'two';
    const configs: Record<Name, Parameters<typeof vercelSSO>[0]> = {
      one: { ...baseConfig, publicPaths: ['/one'] },
      two: { ...baseConfig, sessionSecret: otherSessionSecret, publicPaths: ['/two'] },
    };
    const other = (name: Name): Name => (name === 'one' ? 'two' : 'one');

    it.each<[Name, Name]>([
      ['one', 'one'],
      ['one', 'two'],
      ['two', 'one'],
      ['two', 'two'],
    ])('keeps them isolated when built %s first and called %s first', async (buildFirst, callFirst) => {
      const fake = await createFakeGoogle({ clientId, clientSecret });
      const built = {} as Record<Name, Middleware>;
      for (const name of [buildFirst, other(buildFirst)]) built[name] = vercelSSO(configs[name], { fetch: fake.fetch });

      for (const name of [callFirst, other(callFirst)]) {
        const publicResponse = await built[name](new Request(`${origin}/${name}`));
        expect(publicResponse!.headers.get('x-middleware-next')).toBe('1');
        const gated = (await built[other(name)](new Request(`${origin}/${name}`)))!;
        expect(gated.status).toBe(302);
      }

      const cookie = await sessionCookieFor(fake, built[callFirst]);
      const accepted = await built[callFirst](new Request(`${origin}/inside`, { headers: { Cookie: cookie } }));
      expect(accepted!.headers.get(emailHeader)).toBe('a@escape.tech');
      const rejected = (await built[other(callFirst)](new Request(`${origin}/inside`, { headers: { Cookie: cookie } })))!;
      expect(rejected.status).toBe(302);
    });
  });
});
