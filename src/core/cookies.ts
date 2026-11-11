const COOKIE_NAME_PATTERN = /^[A-Za-z0-9_-]+$/;
// RFC 6265 cookie-octet: no controls, whitespace, DQUOTE, comma, semicolon or backslash.
const COOKIE_VALUE_PATTERN = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/;

export interface CookieOptions {
  maxAge: number;
  secure?: boolean;
}

export function parseCookies(header: string | null | undefined): Record<string, string> {
  const cookies: Record<string, string> = Object.create(null);
  if (!header) {
    return cookies;
  }
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator === -1) {
      continue;
    }
    const name = part.slice(0, separator).trim();
    // The first occurrence wins, so a later duplicate cannot replace the cookie.
    if (name === '' || name in cookies) {
      continue;
    }
    cookies[name] = stripQuotes(part.slice(separator + 1).trim());
  }
  return cookies;
}

// Secure is the default. Only the caller can turn it off, for plain-http local development.
export function serializeCookie(name: string, value: string, options: CookieOptions): string {
  if (!COOKIE_NAME_PATTERN.test(name)) {
    throw new Error('cookie name must contain only letters, digits, _ or -');
  }
  if (!COOKIE_VALUE_PATTERN.test(value)) {
    throw new Error('cookie value contains characters that are not allowed');
  }
  if (!Number.isInteger(options.maxAge) || options.maxAge < 0) {
    throw new Error('maxAge must be a non-negative integer');
  }
  const parts = [`${name}=${value}`, `Max-Age=${options.maxAge}`, 'Path=/', 'HttpOnly', 'SameSite=Lax'];
  if (options.secure ?? true) {
    parts.push('Secure');
  }
  return parts.join('; ');
}

export function clearCookie(name: string, options: { secure?: boolean } = {}): string {
  return serializeCookie(name, '', { maxAge: 0, secure: options.secure });
}

// False only for plain http on localhost or 127.0.0.1. Anything unparseable is treated as secure.
export function requiresSecureCookie(requestUrl: string): boolean {
  try {
    const url = new URL(requestUrl);
    const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
    return !(url.protocol === 'http:' && local);
  } catch {
    return true;
  }
}

function stripQuotes(value: string): string {
  return value.length >= 2 && value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value;
}
