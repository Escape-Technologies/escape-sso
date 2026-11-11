import { describe, expect, it } from 'vitest';
import { createFakeGoogle } from './helpers/fake-google.js';

const clientId = 'test-client-id';
const clientSecret = 'test-client-secret';

async function challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  let binary = '';
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

describe('fake Google issuer', () => {
  it('serves discovery and a JWKS', async () => {
    const fake = await createFakeGoogle({ clientId, clientSecret });

    const discoveryResponse = await fake.fetch('https://accounts.google.com/.well-known/openid-configuration');
    const discovery = await discoveryResponse.json();
    expect(discovery).toMatchObject({
      issuer: 'https://accounts.google.com',
      authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
      token_endpoint: 'https://accounts.google.com/token',
      jwks_uri: 'https://accounts.google.com/.well-known/jwks.json',
      userinfo_endpoint: 'https://accounts.google.com/userinfo',
    });

    const jwksResponse = await fake.fetch(discovery.jwks_uri);
    const jwks = await jwksResponse.json();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({ kid: 'fake-google-key', use: 'sig', alg: 'RS256' });
    expect(jwks.keys[0].kty).toBe('RSA');
  });

  it('rejects a wrong verifier and a reused authorization code', async () => {
    const fake = await createFakeGoogle({ clientId, clientSecret });
    const code = fake.issueCode();
    const verifier = 'a sufficiently long test verifier value';
    const authorizationUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    authorizationUrl.searchParams.set('client_id', clientId);
    authorizationUrl.searchParams.set('redirect_uri', 'https://app.example/auth/callback');
    authorizationUrl.searchParams.set('response_type', 'code');
    authorizationUrl.searchParams.set('state', 'test-state');
    authorizationUrl.searchParams.set('nonce', 'test-nonce');
    authorizationUrl.searchParams.set('code_challenge', await challenge(verifier));
    authorizationUrl.searchParams.set('code_challenge_method', 'S256');
    const authorizationResponse = await fake.fetch(authorizationUrl);
    expect(authorizationResponse.status).toBe(302);
    expect(new URL(authorizationResponse.headers.get('Location')!).searchParams.get('code')).toBe(code);

    const exchange = async (codeVerifier: string) => fake.fetch('https://accounts.google.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: 'https://app.example/auth/callback',
        code_verifier: codeVerifier,
      }),
    });

    expect((await exchange('wrong verifier')).status).toBe(400);
    expect((await exchange(verifier)).status).toBe(200);
    expect((await exchange(verifier)).status).toBe(400);
  });

  it('throws on URLs outside the fake issuer', async () => {
    const fake = await createFakeGoogle({ clientId, clientSecret });
    await expect(fake.fetch('https://example.com/')).rejects.toThrow('Unexpected fake Google URL');
  });
});
