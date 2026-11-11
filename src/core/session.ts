import { jwtVerify, SignJWT, type JWTPayload } from 'jose';
import { DEFAULT_SESSION_TTL_SECONDS, validateConfig, type SSOConfig } from './config.js';

export interface SessionUser {
  email: string;
  name: string;
}

export interface PendingLogin {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
}

const ISSUER = 'escape-sso';
const SESSION_AUDIENCE = 'escape-sso-session';
const PENDING_AUDIENCE = 'escape-sso-pending';
const ALGORITHM = 'HS256';
const PENDING_TTL_SECONDS = 600;

// Times are Unix seconds, as in the iat and exp claims. Tests inject `now`.
export function unixNow(): number {
  return Math.floor(Date.now() / 1000);
}

export async function signSession(user: SessionUser, config: SSOConfig, now: number = unixNow()): Promise<string> {
  if (typeof user.email !== 'string' || user.email === '' || typeof user.name !== 'string') {
    throw new Error('session user must have an email and a name');
  }
  const ttl = sessionTtlSeconds(config);
  return new SignJWT({ name: user.name })
    .setProtectedHeader({ alg: ALGORITHM })
    .setSubject(user.email)
    .setIssuedAt(now)
    .setExpirationTime(now + ttl)
    .setIssuer(ISSUER)
    .setAudience(SESSION_AUDIENCE)
    .sign(signingKey(config));
}

// Returns null for any failure, including a malformed config: a bad token never throws.
export async function readSession(token: string, config: SSOConfig, now: number = unixNow()): Promise<SessionUser | null> {
  const payload = await verifyToken(token, config, SESSION_AUDIENCE, now);
  if (!payload || typeof payload.sub !== 'string' || typeof payload.name !== 'string') {
    return null;
  }
  return { email: payload.sub, name: payload.name };
}

export async function signPending(pending: PendingLogin, config: SSOConfig, now: number = unixNow()): Promise<string> {
  return new SignJWT({
    state: pending.state,
    nonce: pending.nonce,
    verifier: pending.verifier,
    returnTo: pending.returnTo,
  })
    .setProtectedHeader({ alg: ALGORITHM })
    .setIssuedAt(now)
    .setExpirationTime(now + PENDING_TTL_SECONDS)
    .setIssuer(ISSUER)
    .setAudience(PENDING_AUDIENCE)
    .sign(signingKey(config));
}

export async function readPending(token: string, config: SSOConfig, now: number = unixNow()): Promise<PendingLogin | null> {
  const payload = await verifyToken(token, config, PENDING_AUDIENCE, now);
  if (
    !payload ||
    typeof payload.state !== 'string' ||
    typeof payload.nonce !== 'string' ||
    typeof payload.verifier !== 'string' ||
    typeof payload.returnTo !== 'string'
  ) {
    return null;
  }
  return {
    state: payload.state,
    nonce: payload.nonce,
    verifier: payload.verifier,
    returnTo: payload.returnTo,
  };
}

function sessionTtlSeconds(config: SSOConfig): number {
  const checked = validateConfig(config);
  if (!checked.ok) {
    throw new Error(checked.error);
  }
  return checked.config.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS;
}

function signingKey(config: SSOConfig): Uint8Array {
  // Throws on an invalid config, so a token is never signed with a weak or missing secret.
  sessionTtlSeconds(config);
  return new TextEncoder().encode(config.sessionSecret);
}

async function verifyToken(
  token: string,
  config: SSOConfig,
  audience: string,
  now: number,
): Promise<JWTPayload | null> {
  try {
    if (typeof token !== 'string' || !validateConfig(config).ok) {
      return null;
    }
    const { payload } = await jwtVerify(token, new TextEncoder().encode(config.sessionSecret), {
      algorithms: [ALGORITHM],
      issuer: ISSUER,
      audience,
      currentDate: new Date(now * 1000),
    });
    return payload;
  } catch {
    return null;
  }
}
