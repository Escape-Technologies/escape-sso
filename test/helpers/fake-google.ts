import { exportJWK, generateKeyPair, SignJWT } from 'jose';

const issuer = 'https://accounts.google.com';
const authorizationEndpoint = `${issuer}/o/oauth2/v2/auth`;
const tokenEndpoint = `${issuer}/token`;
const jwksUri = `${issuer}/.well-known/jwks.json`;
const userinfoEndpoint = `${issuer}/userinfo`;

export interface FakeGoogleOptions {
  clientId: string;
  clientSecret: string;
}

export interface FakeGoogle {
  fetch: typeof fetch;
  issueCode(claims?: Record<string, unknown>): string;
}

interface CodeRecord {
  claims: Record<string, unknown>;
  nonce?: string;
  codeChallenge?: string;
  redirectUri?: string;
  used: boolean;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function oauthError(error: string): Response {
  return json({ error }, 400);
}

async function sha256(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
}

function encodeBase64Url(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

export async function createFakeGoogle(options: FakeGoogleOptions): Promise<FakeGoogle> {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const { privateKey: foreignPrivateKey } = await generateKeyPair('RS256');
  const jwk = await exportJWK(publicKey);
  const codes = new Map<string, CodeRecord>();
  const unassignedCodes: string[] = [];

  const fetcher: typeof fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    if (url.origin !== issuer) throw new Error(`Unexpected fake Google URL: ${url.href}`);

    if (request.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
      return json({
        issuer,
        authorization_endpoint: authorizationEndpoint,
        token_endpoint: tokenEndpoint,
        jwks_uri: jwksUri,
        userinfo_endpoint: userinfoEndpoint,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
      });
    }

    if (request.method === 'GET' && url.pathname === '/.well-known/jwks.json') {
      return json({ keys: [{ ...jwk, kid: 'fake-google-key', use: 'sig', alg: 'RS256' }] });
    }

    if (request.method === 'GET' && url.pathname === '/o/oauth2/v2/auth') {
      const code = unassignedCodes.shift();
      if (!code) return oauthError('invalid_request');
      const record = codes.get(code);
      if (!record) return oauthError('invalid_request');
      record.nonce = url.searchParams.get('nonce') ?? undefined;
      record.codeChallenge = url.searchParams.get('code_challenge') ?? undefined;
      record.redirectUri = url.searchParams.get('redirect_uri') ?? undefined;
      const callback = new URL(record.redirectUri ?? 'https://invalid.example/');
      callback.searchParams.set('code', code);
      const state = url.searchParams.get('state');
      if (state) callback.searchParams.set('state', state);
      return new Response(null, { status: 302, headers: { Location: callback.href } });
    }

    if (request.method === 'POST' && url.pathname === '/token') {
      const form = new URLSearchParams(await request.text());
      const code = form.get('code') ?? '';
      const record = codes.get(code);
      if (
        form.get('client_id') !== options.clientId ||
        form.get('client_secret') !== options.clientSecret ||
        form.get('grant_type') !== 'authorization_code' ||
        !record ||
        record.used ||
        !record.codeChallenge ||
        !record.redirectUri ||
        form.get('redirect_uri') !== record.redirectUri
      ) return oauthError('invalid_grant');

      const verifier = form.get('code_verifier') ?? '';
      if (encodeBase64Url(await sha256(verifier)) !== record.codeChallenge) {
        return oauthError('invalid_grant');
      }

      record.used = true;
      const now = Math.floor(Date.now() / 1000);
      const signWithForeignKey = record.claims.signWithForeignKey === true;
      const claims = {
        iss: issuer,
        aud: options.clientId,
        sub: 'fake-google-user',
        email: 'user@escape.tech',
        email_verified: true,
        hd: 'escape.tech',
        iat: now,
        exp: now + 3600,
        ...(record.nonce ? { nonce: record.nonce } : {}),
        ...record.claims,
      };
      const signingKey = signWithForeignKey ? foreignPrivateKey : privateKey;
      delete (claims as Record<string, unknown>).signWithForeignKey;
      const idToken = await new SignJWT(claims)
        .setProtectedHeader({ alg: 'RS256', kid: signWithForeignKey ? 'foreign-key' : 'fake-google-key' })
        .sign(signingKey);
      return json({
        access_token: `fake-access-${crypto.randomUUID()}`,
        id_token: idToken,
        token_type: 'Bearer',
        expires_in: 3600,
      });
    }

    if (request.method === 'GET' && url.pathname === '/userinfo') {
      return json({ sub: 'fake-google-user', email: 'user@escape.tech', email_verified: true });
    }

    throw new Error(`Unexpected fake Google URL: ${url.href}`);
  };

  return {
    fetch: fetcher,
    issueCode(claims = {}) {
      const code = `fake-code-${crypto.randomUUID()}`;
      codes.set(code, { claims: { ...claims }, used: false });
      unassignedCodes.push(code);
      return code;
    },
  };
}
