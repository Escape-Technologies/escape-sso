import { describe, expect, it } from 'vitest';
import { createSSO } from '../../src/core/index.js';
import { createFakeGoogle } from '../helpers/fake-google.js';

const config = {
  clientId: 'edge-client-id',
  clientSecret: 'edge-client-secret',
  sessionSecret: 'edge test session secret with enough bytes',
  allowedDomains: ['escape.tech'],
  issuer: 'https://accounts.google.com',
};

async function flow(claims: Record<string, unknown> = {}, returnTo?: string) {
  const fake = await createFakeGoogle(config);
  const sso = createSSO(config, { fetch: fake.fetch });
  fake.issueCode(claims);
  const suffix = returnTo === undefined ? '' : `?return=${returnTo}`;
  const login = (await sso.handle(new Request(`https://edge.example/auth/login${suffix}`))) as { response: Response };
  const google = await fake.fetch(new URL(login.response.headers.get('Location')!));
  const callbackUrl = new URL(google.headers.get('Location')!);
  const callback = (await sso.handle(new Request(callbackUrl, {
    headers: { Cookie: login.response.headers.get('Set-Cookie')!.split(';', 1)[0] },
  }))) as { response: Response };
  return callback.response;
}

describe('edge runtime SSO flow', () => {
  it('accepts verified escape.tech account', async () => {
    const response = await flow({}, '/edge/ok');
    expect(response.status).toBe(302);
    expect(new URL(response.headers.get('Location')!).pathname).toBe('/edge/ok');
    expect(response.headers.get('Set-Cookie')).toContain('escape_sso=');
  });

  it('rejects account without hosted domain', async () => {
    const response = await flow({ hd: undefined, email: 'user@gmail.com' });
    expect(response.status).toBe(403);
    expect(response.headers.get('Set-Cookie')).not.toContain('escape_sso=');
  });

  it('rejects unsafe return paths and keeps safe return path', async () => {
    for (const value of ['/.//evil.com/x', 'https://edge.example//evil.com/x', '//evil.com', 'https://evil.com', '/%09/evil.com', '/%0a/evil.com', '/\\evil.com', '%2F%2Fevil.com']) {
      const response = await flow({}, value);
      expect(new URL(response.headers.get('Location')!).origin).toBe('https://edge.example');
      expect(new URL(response.headers.get('Location')!).pathname).toBe('/');
    }
    const safe = await flow({}, '/a/b?x=1');
    expect(new URL(safe.headers.get('Location')!).pathname + new URL(safe.headers.get('Location')!).search).toBe('/a/b?x=1');
  });
});
