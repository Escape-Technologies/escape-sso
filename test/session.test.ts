import { decodeJwt, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import type { SSOConfig } from '../src/core/config.js';
import { clearCookie, parseCookies, requiresSecureCookie, serializeCookie } from '../src/core/cookies.js';
import { readPending, readSession, signPending, signSession } from '../src/core/session.js';

const NOW = 1_800_000_000;
const USER = { email: 'ana@escape.tech', name: 'Ana Example' };

const config: SSOConfig = {
  clientId: 'client-id.apps.googleusercontent.com',
  clientSecret: 'client-secret-value',
  sessionSecret: 'a'.repeat(32),
  allowedDomains: ['escape.tech'],
};

const otherConfig: SSOConfig = { ...config, sessionSecret: 'b'.repeat(32) };

const PENDING = {
  state: 'state-value',
  nonce: 'nonce-value',
  verifier: 'verifier-value-with-enough-entropy',
  returnTo: '/projects/alpha',
};

function encodeSegment(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function replaceSignature(token: string): string {
  const signature = token.split('.')[2];
  const last = signature.slice(-1);
  return `${token.slice(0, -1)}${last === 'A' ? 'B' : 'A'}`;
}

describe('session tokens', () => {
  it('round-trips a session to the same user', async () => {
    const token = await signSession(USER, config, NOW);
    expect(await readSession(token, config, NOW)).toEqual(USER);
  });

  it('sets iat, exp = iat + ttl, sub, name, iss and aud', async () => {
    const token = await signSession(USER, config, NOW);
    expect(decodeJwt(token)).toMatchObject({
      iat: NOW,
      exp: NOW + 28800,
      sub: USER.email,
      name: USER.name,
      iss: 'escape-sso',
      aud: 'escape-sso-session',
    });
  });

  it('keeps a fresh session within 8 hours (K3)', async () => {
    const token = await signSession(USER, config, NOW);
    const claims = decodeJwt(token);
    expect((claims.exp as number) - (claims.iat as number)).toBeLessThanOrEqual(28800);

    const cookie = serializeCookie('escape_sso', token, {
      maxAge: config.sessionTtlSeconds ?? 28800,
    });
    const maxAge = Number(/Max-Age=(\d+)/.exec(cookie)?.[1]);
    expect(maxAge).toBeLessThanOrEqual(28800);
  });

  it('uses a shorter configured ttl', async () => {
    const token = await signSession(USER, { ...config, sessionTtlSeconds: 3600 }, NOW);
    expect(decodeJwt(token).exp).toBe(NOW + 3600);
  });

  it('rejects a session at exp and accepts one second before', async () => {
    const token = await signSession(USER, config, NOW);
    expect(await readSession(token, config, NOW + 28799)).toEqual(USER);
    expect(await readSession(token, config, NOW + 28800)).toBeNull();
    expect(await readSession(token, config, NOW + 90000)).toBeNull();
  });

  it('rejects a tampered signature', async () => {
    const token = await signSession(USER, config, NOW);
    expect(await readSession(replaceSignature(token), config, NOW)).toBeNull();
  });

  it('rejects a tampered payload', async () => {
    const token = await signSession(USER, config, NOW);
    const [header, , signature] = token.split('.');
    const forged = encodeSegment({ ...decodeJwt(token), sub: 'mallory@escape.tech' });
    expect(await readSession(`${header}.${forged}.${signature}`, config, NOW)).toBeNull();
  });

  it('rejects a session signed with another secret', async () => {
    const token = await signSession(USER, otherConfig, NOW);
    expect(await readSession(token, config, NOW)).toBeNull();
  });

  it('rejects an alg none token', async () => {
    const token = await signSession(USER, config, NOW);
    const payload = token.split('.')[1];
    const unsigned = `${encodeSegment({ alg: 'none', typ: 'JWT' })}.${payload}.`;
    expect(await readSession(unsigned, config, NOW)).toBeNull();
  });

  it('rejects a token with the wrong issuer or audience', async () => {
    const key = new TextEncoder().encode(config.sessionSecret);
    const base = { sub: USER.email, name: USER.name };
    const wrongIssuer = await new SignJWT(base)
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt(NOW)
      .setExpirationTime(NOW + 600)
      .setIssuer('someone-else')
      .setAudience('escape-sso-session')
      .sign(key);
    const wrongAudience = await new SignJWT(base)
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt(NOW)
      .setExpirationTime(NOW + 600)
      .setIssuer('escape-sso')
      .setAudience('other-audience')
      .sign(key);
    expect(await readSession(wrongIssuer, config, NOW)).toBeNull();
    expect(await readSession(wrongAudience, config, NOW)).toBeNull();
  });

  it('rejects a session without a name claim', async () => {
    const key = new TextEncoder().encode(config.sessionSecret);
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject(USER.email)
      .setIssuedAt(NOW)
      .setExpirationTime(NOW + 600)
      .setIssuer('escape-sso')
      .setAudience('escape-sso-session')
      .sign(key);
    expect(await readSession(token, config, NOW)).toBeNull();
  });

  it('returns null for garbage and for an invalid config, without throwing', async () => {
    const token = await signSession(USER, config, NOW);
    expect(await readSession('not-a-jwt', config, NOW)).toBeNull();
    expect(await readSession('', config, NOW)).toBeNull();
    expect(await readSession(token, { ...config, sessionSecret: 'short' }, NOW)).toBeNull();
  });

  it('refuses to sign with an invalid config', async () => {
    await expect(signSession(USER, { ...config, sessionSecret: 'short' }, NOW)).rejects.toThrow('sessionSecret');
  });
});

describe('pending login tokens', () => {
  it('round-trips the pending values', async () => {
    const token = await signPending(PENDING, config, NOW);
    expect(await readPending(token, config, NOW)).toEqual(PENDING);
  });

  it('lives 600 seconds with the pending audience', async () => {
    const token = await signPending(PENDING, config, NOW);
    expect(decodeJwt(token)).toMatchObject({ iat: NOW, exp: NOW + 600, aud: 'escape-sso-pending' });
    expect(await readPending(token, config, NOW + 599)).toEqual(PENDING);
    expect(await readPending(token, config, NOW + 600)).toBeNull();
  });

  it('rejects a pending token tampered or signed with another secret', async () => {
    const token = await signPending(PENDING, config, NOW);
    expect(await readPending(replaceSignature(token), config, NOW)).toBeNull();
    expect(await readPending(await signPending(PENDING, otherConfig, NOW), config, NOW)).toBeNull();
  });

  it('never accepts a pending token as a session', async () => {
    const token = await signPending(PENDING, config, NOW);
    expect(await readSession(token, config, NOW)).toBeNull();
  });

  it('never accepts a session token as a pending login', async () => {
    const token = await signSession(USER, config, NOW);
    expect(await readPending(token, config, NOW)).toBeNull();
  });
});

describe('cookies', () => {
  const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln';

  it('serializes HttpOnly, SameSite=Lax, Path=/, Max-Age and Secure by default', () => {
    const header = serializeCookie('escape_sso', token, { maxAge: 28800 });
    expect(header).toBe(`escape_sso=${token}; Max-Age=28800; Path=/; HttpOnly; SameSite=Lax; Secure`);
  });

  it('omits Secure only when the caller says so', () => {
    const header = serializeCookie('escape_sso', token, { maxAge: 600, secure: false });
    expect(header).toContain('Max-Age=600');
    expect(header).not.toContain('Secure');
    expect(header).toContain('HttpOnly');
  });

  it('refuses a name or value that would break the header', () => {
    expect(() => serializeCookie('bad name', token, { maxAge: 1 })).toThrow('cookie name');
    expect(() => serializeCookie('ok', 'a; Domain=evil.com', { maxAge: 1 })).toThrow('cookie value');
    expect(() => serializeCookie('ok', token, { maxAge: -1 })).toThrow('maxAge');
  });

  it('clears a cookie with Max-Age=0 and the same attributes', () => {
    expect(clearCookie('escape_sso')).toBe('escape_sso=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure');
    expect(clearCookie('escape_sso', { secure: false })).not.toContain('Secure');
  });

  it('parses a Cookie header and keeps the first of duplicate names', () => {
    const cookies = parseCookies(`other=1; escape_sso=${token}; escape_sso=second; "quoted"=x; =bare`);
    expect(cookies).toEqual({ other: '1', escape_sso: token, '"quoted"': 'x' });
    expect(parseCookies(null)).toEqual({});
  });

  it('requires Secure except on plain-http localhost and 127.0.0.1', () => {
    expect(requiresSecureCookie('https://design.escape.dev/auth/callback')).toBe(true);
    expect(requiresSecureCookie('http://localhost:3000/auth/login')).toBe(false);
    expect(requiresSecureCookie('http://127.0.0.1:8080/')).toBe(false);
    expect(requiresSecureCookie('https://localhost/')).toBe(true);
    expect(requiresSecureCookie('http://example.com/')).toBe(true);
    expect(requiresSecureCookie('not a url')).toBe(true);
  });

  it('sets the session cookie with Max-Age at most 28800 on https', async () => {
    const session = await signSession(USER, config, NOW);
    const header = serializeCookie('escape_sso', session, {
      maxAge: 28800,
      secure: requiresSecureCookie('https://design.escape.dev/auth/callback'),
    });
    expect(header).toContain('Max-Age=28800');
    expect(header).toContain('HttpOnly');
    expect(header).toContain('SameSite=Lax');
    expect(header).toContain('Path=/');
    expect(header).toContain('Secure');
  });
});
