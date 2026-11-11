import { describe, expect, it } from 'vitest';
import { configFromEnv, validateConfig } from '../src/core/config.js';

const SECRET = 's'.repeat(32);

function validInput(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    clientId: 'client-id.apps.googleusercontent.com',
    clientSecret: 'client-secret-value',
    sessionSecret: SECRET,
    allowedDomains: ['escape.tech'],
    ...overrides,
  };
}

function expectRejected(input: unknown, field: string): void {
  const result = validateConfig(input);
  expect(result.ok).toBe(false);
  if (!result.ok) {
    expect(result.error).toContain(field);
    // The error names the field, never the value.
    expect(result.error).not.toContain(SECRET);
    expect(result.error).not.toContain('client-secret-value');
  }
}

describe('validateConfig', () => {
  it('accepts a minimal config and fills the defaults', () => {
    const result = validateConfig(validInput());
    expect(result).toEqual({
      ok: true,
      config: {
        clientId: 'client-id.apps.googleusercontent.com',
        clientSecret: 'client-secret-value',
        sessionSecret: SECRET,
        allowedDomains: ['escape.tech'],
        sessionTtlSeconds: 28800,
        basePath: '/auth',
        cookieName: 'escape_sso',
        issuer: 'https://accounts.google.com',
        publicPaths: [],
      },
    });
  });

  it('rejects a non-object input', () => {
    expectRejected(null, 'config');
    expectRejected('config', 'config');
    expectRejected([], 'config');
  });

  it.each(['', '   ', 42])('rejects clientId %j', (clientId) => {
    expectRejected(validInput({ clientId }), 'clientId');
  });

  it.each(['', '   ', undefined])('rejects clientSecret %j', (clientSecret) => {
    expectRejected(validInput({ clientSecret }), 'clientSecret');
  });

  it('rejects a sessionSecret shorter than 32 bytes', () => {
    expectRejected(validInput({ sessionSecret: 's'.repeat(31) }), 'sessionSecret');
    expectRejected(validInput({ sessionSecret: '' }), 'sessionSecret');
    expectRejected(validInput({ sessionSecret: undefined }), 'sessionSecret');
  });

  it('counts the sessionSecret in UTF-8 bytes, not characters', () => {
    // 15 characters of 2 bytes each are 30 bytes, below the 32-byte minimum.
    expectRejected(validInput({ sessionSecret: 'é'.repeat(15) }), 'sessionSecret');
    expect(validateConfig(validInput({ sessionSecret: 'é'.repeat(16) })).ok).toBe(true);
  });

  it.each([
    [[]],
    [undefined],
    ['escape.tech'],
    [['*.escape.tech']],
    [['https://escape.tech']],
    [['escape.tech/']],
    [['escape tech']],
    [['localhost']],
    [[' escape.tech']],
    [['es cape.tech']],
    [['éscape.tech']],
    [['escape..tech']],
    [['-escape.tech']],
    [[42]],
    [[null]],
  ])('rejects allowedDomains %j', (allowedDomains) => {
    expectRejected(validInput({ allowedDomains }), 'allowedDomains');
  });

  it('lower-cases allowedDomains before the check', () => {
    const result = validateConfig(validInput({ allowedDomains: ['ESCAPE.TECH', 'Partner.Example.com'] }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.config.allowedDomains).toEqual(['escape.tech', 'partner.example.com']);
    }
  });

  it.each([59, 28801, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '3600', null])(
    'rejects sessionTtlSeconds %j',
    (sessionTtlSeconds) => {
      expectRejected(validInput({ sessionTtlSeconds }), 'sessionTtlSeconds');
    },
  );

  it.each([60, 3600, 28800])('accepts sessionTtlSeconds %j', (sessionTtlSeconds) => {
    const result = validateConfig(validInput({ sessionTtlSeconds }));
    expect(result.ok && result.config.sessionTtlSeconds).toBe(sessionTtlSeconds);
  });

  it.each(['auth', '', 'https://example.com/auth'])('rejects basePath %j', (basePath) => {
    expectRejected(validInput({ basePath }), 'basePath');
  });

  it('accepts a basePath that starts with /', () => {
    const result = validateConfig(validInput({ basePath: '/sso' }));
    expect(result.ok && result.config.basePath).toBe('/sso');
  });

  it.each(['bad name;', '', 'näme'])('rejects cookieName %j', (cookieName) => {
    expectRejected(validInput({ cookieName }), 'cookieName');
  });

  it.each(['', 42])('rejects issuer %j', (issuer) => {
    expectRejected(validInput({ issuer }), 'issuer');
  });

  it.each([
    ['/assets/*'],
    ['favicon.svg'],
    [['/favicon.svg', '/robots/*']],
    [['/ok', 'relative']],
    [[42]],
  ])('rejects publicPaths %j', (publicPaths) => {
    expectRejected(validInput({ publicPaths }), 'publicPaths');
  });

  it('accepts exact publicPaths', () => {
    const result = validateConfig(validInput({ publicPaths: ['/favicon.svg', '/robots.txt'] }));
    expect(result.ok && result.config.publicPaths).toEqual(['/favicon.svg', '/robots.txt']);
  });
});

describe('configFromEnv', () => {
  const env = {
    SSO_GOOGLE_CLIENT_ID: 'client-id.apps.googleusercontent.com',
    SSO_GOOGLE_CLIENT_SECRET: 'client-secret-value',
    SSO_SESSION_SECRET: SECRET,
    SSO_ALLOWED_DOMAINS: ' escape.tech , Partner.example.com ,',
    SSO_SESSION_TTL_SECONDS: '3600',
    SSO_PUBLIC_PATHS: '/favicon.svg, /robots.txt',
  };

  it('reads every variable and trims the comma-separated lists', () => {
    const result = validateConfig(configFromEnv(env));
    expect(result).toEqual({
      ok: true,
      config: {
        clientId: 'client-id.apps.googleusercontent.com',
        clientSecret: 'client-secret-value',
        sessionSecret: SECRET,
        allowedDomains: ['escape.tech', 'partner.example.com'],
        sessionTtlSeconds: 3600,
        basePath: '/auth',
        cookieName: 'escape_sso',
        issuer: 'https://accounts.google.com',
        publicPaths: ['/favicon.svg', '/robots.txt'],
      },
    });
  });

  it('uses the defaults for the optional variables when they are unset or empty', () => {
    const result = validateConfig(
      configFromEnv({ ...env, SSO_SESSION_TTL_SECONDS: '', SSO_PUBLIC_PATHS: undefined }),
    );
    expect(result.ok && result.config.sessionTtlSeconds).toBe(28800);
    expect(result.ok && result.config.publicPaths).toEqual([]);
  });

  it('fails validation when SSO_ALLOWED_DOMAINS is unset', () => {
    expectRejected(configFromEnv({ ...env, SSO_ALLOWED_DOMAINS: undefined }), 'allowedDomains');
  });

  it('fails validation when SSO_ALLOWED_DOMAINS has no entries', () => {
    expectRejected(configFromEnv({ ...env, SSO_ALLOWED_DOMAINS: ' , ' }), 'allowedDomains');
  });

  it('fails validation when a required variable is missing', () => {
    expectRejected(configFromEnv({ ...env, SSO_GOOGLE_CLIENT_ID: undefined }), 'clientId');
    expectRejected(configFromEnv({ ...env, SSO_GOOGLE_CLIENT_SECRET: '' }), 'clientSecret');
    expectRejected(configFromEnv({ ...env, SSO_SESSION_SECRET: 'short' }), 'sessionSecret');
  });

  it('rejects a non-numeric SSO_SESSION_TTL_SECONDS', () => {
    expectRejected(configFromEnv({ ...env, SSO_SESSION_TTL_SECONDS: '8h' }), 'sessionTtlSeconds');
  });
});
