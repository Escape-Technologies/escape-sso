export interface SSOConfig {
  clientId: string;
  clientSecret: string;
  sessionSecret: string;
  allowedDomains: string[];
  sessionTtlSeconds?: number;
  basePath?: string;
  cookieName?: string;
  issuer?: string;
  publicPaths?: string[];
}

export type ConfigResult = { ok: true; config: SSOConfig } | { ok: false; error: string };

export const DEFAULT_SESSION_TTL_SECONDS = 28800;

const MIN_SESSION_TTL_SECONDS = 60;
const MIN_SESSION_SECRET_BYTES = 32;
const DEFAULT_BASE_PATH = '/auth';
const DEFAULT_COOKIE_NAME = 'escape_sso';
const DEFAULT_ISSUER = 'https://accounts.google.com';

const HOSTNAME_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const COOKIE_NAME_PATTERN = /^[A-Za-z0-9_-]+$/;

export function validateConfig(input: unknown): ConfigResult {
  if (!isRecord(input)) {
    return fail('config must be an object');
  }

  const { clientId, clientSecret, sessionSecret } = input;
  if (!isNonEmptyString(clientId)) {
    return fail('clientId must be a non-empty string');
  }
  if (!isNonEmptyString(clientSecret)) {
    return fail('clientSecret must be a non-empty string');
  }
  if (typeof sessionSecret !== 'string' || new TextEncoder().encode(sessionSecret).length < MIN_SESSION_SECRET_BYTES) {
    return fail(`sessionSecret must be at least ${MIN_SESSION_SECRET_BYTES} bytes (UTF-8)`);
  }

  const allowedDomains = input.allowedDomains;
  if (!Array.isArray(allowedDomains) || allowedDomains.length === 0) {
    return fail('allowedDomains must be a non-empty array of hostnames');
  }
  const domains: string[] = [];
  for (const domain of allowedDomains) {
    const lowered = typeof domain === 'string' ? domain.toLowerCase() : '';
    if (!HOSTNAME_PATTERN.test(lowered)) {
      return fail('allowedDomains must contain only lowercase hostnames, such as escape.tech');
    }
    domains.push(lowered);
  }

  const sessionTtlSeconds = withDefault(input.sessionTtlSeconds, DEFAULT_SESSION_TTL_SECONDS);
  if (
    typeof sessionTtlSeconds !== 'number' ||
    !Number.isInteger(sessionTtlSeconds) ||
    sessionTtlSeconds < MIN_SESSION_TTL_SECONDS ||
    sessionTtlSeconds > DEFAULT_SESSION_TTL_SECONDS
  ) {
    return fail(`sessionTtlSeconds must be an integer from ${MIN_SESSION_TTL_SECONDS} to ${DEFAULT_SESSION_TTL_SECONDS}`);
  }

  const basePath = withDefault(input.basePath, DEFAULT_BASE_PATH);
  if (typeof basePath !== 'string' || !basePath.startsWith('/')) {
    return fail('basePath must start with /');
  }

  const cookieName = withDefault(input.cookieName, DEFAULT_COOKIE_NAME);
  if (typeof cookieName !== 'string' || !COOKIE_NAME_PATTERN.test(cookieName)) {
    return fail('cookieName must contain only letters, digits, _ or -');
  }

  const issuer = withDefault(input.issuer, DEFAULT_ISSUER);
  if (!isNonEmptyString(issuer)) {
    return fail('issuer must be a non-empty string');
  }

  const publicPaths = withDefault(input.publicPaths, []);
  if (
    !Array.isArray(publicPaths) ||
    !publicPaths.every((path) => typeof path === 'string' && path.startsWith('/') && !path.includes('*'))
  ) {
    return fail('publicPaths must be an array of exact paths starting with /, without globs');
  }

  return {
    ok: true,
    config: {
      clientId,
      clientSecret,
      sessionSecret,
      allowedDomains: domains,
      sessionTtlSeconds,
      basePath,
      cookieName,
      issuer,
      publicPaths: [...publicPaths],
    },
  };
}

export function configFromEnv(env: Record<string, string | undefined>): Record<string, unknown> {
  const input: Record<string, unknown> = {
    clientId: env.SSO_GOOGLE_CLIENT_ID,
    clientSecret: env.SSO_GOOGLE_CLIENT_SECRET,
    sessionSecret: env.SSO_SESSION_SECRET,
    allowedDomains: splitList(env.SSO_ALLOWED_DOMAINS),
  };

  const ttl = env.SSO_SESSION_TTL_SECONDS?.trim();
  if (ttl) {
    // A non-numeric value is passed on as a string so validateConfig rejects it.
    input.sessionTtlSeconds = /^\d+$/.test(ttl) ? Number(ttl) : ttl;
  }

  input.publicPaths = splitList(env.SSO_PUBLIC_PATHS);
  return input;
}

function splitList(value: string | undefined): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  return value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item !== '');
}

// Only a missing key takes the default; null or a wrong type is an error.
function withDefault(value: unknown, fallback: unknown): unknown {
  return value === undefined ? fallback : value;
}

function fail(error: string): { ok: false; error: string } {
  return { ok: false, error };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim() !== '';
}
