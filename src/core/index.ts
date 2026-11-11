import * as oauth from 'oauth4webapi';
import { validateConfig, type SSOConfig } from './config.js';
import { clearCookie, parseCookies, requiresSecureCookie, serializeCookie } from './cookies.js';
import { readPending, readSession, signPending, signSession, unixNow, type PendingLogin } from './session.js';

export type { SSOConfig, ConfigResult } from './config.js';
export { configFromEnv, validateConfig } from './config.js';

export interface SSOOptions {
  fetch?: typeof fetch;
  now?: () => number;
}

export type SSOResult =
  | { response: Response }
  | { user: { email: string; name?: string } }
  | { pass: true };

const NO_STORE = { 'Cache-Control': 'no-store' };
const ACCEPTED_REDIRECT = 302;

export function createSSO(input: unknown, options: SSOOptions = {}): { handle(request: Request): Promise<SSOResult> } {
  const checked = validateConfig(input);
  const config = checked.ok ? checked.config : null;
  const fetcher = options.fetch ?? fetch;
  const now = options.now ?? unixNow;
  let discovery: Promise<oauth.AuthorizationServer> | undefined;

  async function authorizationServer(): Promise<oauth.AuthorizationServer> {
    if (!discovery) {
      const pending = (async () => {
        const issuer = new URL(config!.issuer!);
        const response = await oauth.discoveryRequest(issuer, { [oauth.customFetch]: fetcher });
        return oauth.processDiscoveryResponse(issuer, response);
      })();
      discovery = pending;
      void pending.catch(() => {
        if (discovery === pending) discovery = undefined;
      });
    }
    return discovery;
  }

  function client(): oauth.Client {
    return { client_id: config!.clientId };
  }

  function response(body: BodyInit | null, status: number, headers: HeadersInit = {}): Response {
    const result = new Response(body, { status, headers: { ...NO_STORE, ...headers } });
    return result;
  }

  function page(title: string, href: string, linkText: string, status: number, headers: HeadersInit = {}): Response {
    const safeHref = escapeHtml(href);
    return response(`<!doctype html><html><head><title>${escapeHtml(title)}</title></head><body><p>${escapeHtml(title)}</p><a href="${safeHref}">${escapeHtml(linkText)}</a></body></html>`, status, {
      'Content-Type': 'text/html; charset=utf-8',
      ...headers,
    });
  }

  function accessDenied(clearPending: string): Response {
    return page(
      `Access restricted to ${config!.allowedDomains.join(', ')} Google accounts`,
      `${config!.basePath}/login?switch=1`,
      'Choose another account',
      403,
      { 'Set-Cookie': clearPending },
    );
  }

  function configFailure(): Response {
    const message = checked.ok ? 'config' : checked.error;
    const field = /^([A-Za-z][A-Za-z0-9]*)/.exec(message)?.[1] ?? 'config';
    return response(`SSO misconfigured: ${field}`, 500, { 'Content-Type': 'text/plain; charset=utf-8' });
  }

  function cookieHeader(request: Request, name: string, value: string, maxAge: number): string {
    return serializeCookie(name, value, { maxAge, secure: requiresSecureCookie(request.url) });
  }

  function clearHeader(request: Request, name: string): string {
    return clearCookie(name, { secure: requiresSecureCookie(request.url) });
  }

  function redirect(location: string, headers: HeadersInit = {}): Response {
    return response(null, ACCEPTED_REDIRECT, { Location: location, ...headers });
  }

  function checkedReturnTo(value: string, origin: string): string {
    if ([...value].some((character) => {
      const code = character.codePointAt(0)!;
      return code < 0x20 || code === 0x7f;
    })) return '/';
    try {
      const url = new URL(value, origin);
      const candidate = url.pathname + url.search;
      if (url.origin !== origin || !/^\/(?!\/|\\)/.test(candidate)) return '/';
      if (new URL(candidate, origin).origin !== origin) return '/';
      return candidate;
    } catch {
      return '/';
    }
  }

  async function login(request: Request, url: URL): Promise<Response> {
    try {
      const as = await authorizationServer();
      const state = oauth.generateRandomState();
      const nonce = oauth.generateRandomNonce();
      const verifier = oauth.generateRandomCodeVerifier();
      const challenge = await oauth.calculatePKCECodeChallenge(verifier);
      const callback = `${url.origin}${config!.basePath}/callback`;
      const returnTo = checkedReturnTo(url.searchParams.get('return') ?? '/', url.origin);
      const params: Record<string, string> = {
        response_type: 'code',
        client_id: config!.clientId,
        redirect_uri: callback,
        scope: 'openid email profile',
        state,
        nonce,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        hd: config!.allowedDomains[0],
      };
      if (url.searchParams.get('switch') === '1') params.prompt = 'select_account';
      const authorizationUrl = new URL(as.authorization_endpoint!);
      for (const [key, value] of Object.entries(params)) authorizationUrl.searchParams.set(key, value);
      const pending: PendingLogin = { state, nonce, verifier, returnTo };
      const pendingToken = await signPending(pending, config!, now());
      return redirect(authorizationUrl.href, {
        'Set-Cookie': cookieHeader(request, `${config!.cookieName}_pending`, pendingToken, 600),
      });
    } catch {
      return response('Unable to start sign-in', 503, { 'Content-Type': 'text/plain; charset=utf-8' });
    }
  }

  async function callback(request: Request, url: URL): Promise<Response> {
    const pendingName = `${config!.cookieName}_pending`;
    const clearPending = clearHeader(request, pendingName);
    const pendingToken = parseCookies(request.headers.get('Cookie'))[pendingName];
    const pending = pendingToken ? await readPending(pendingToken, config!, now()) : null;
    if (!pending) {
      return page('Sign-in expired or blocked, try again', `${config!.basePath}/login`, 'Sign in', 403, { 'Set-Cookie': clearPending });
    }
    try {
      const as = await authorizationServer();
      const callbackParameters = oauth.validateAuthResponse(as, client(), url, pending.state);
      const tokenResponse = await oauth.authorizationCodeGrantRequest(
        as,
        client(),
        oauth.ClientSecretPost(config!.clientSecret),
        callbackParameters,
        `${url.origin}${config!.basePath}/callback`,
        pending.verifier,
        { [oauth.customFetch]: fetcher },
      );
      const tokens = await oauth.processAuthorizationCodeResponse(as, client(), tokenResponse, {
        expectedNonce: pending.nonce,
        requireIdToken: true,
      });
      await oauth.validateApplicationLevelSignature(as, tokenResponse, { [oauth.customFetch]: fetcher });
      const idToken = tokens.id_token;
      if (typeof idToken !== 'string') throw new Error('invalid identity token');
      const claims = oauth.getValidatedIdTokenClaims(tokens);
      if (!claims) throw new Error('invalid identity token');
      const email = claims.email;
      const hd = claims.hd;
      const verified = claims.email_verified;
      if (typeof claims.exp !== 'number' || claims.exp <= now()) throw new Error('expired identity token');
      const lowerHd = typeof hd === 'string' ? hd.toLowerCase() : '';
      const emailDomain = typeof email === 'string' ? email.toLowerCase().split('@')[1] : undefined;
      if (verified !== true || !lowerHd || !config!.allowedDomains.includes(lowerHd) || emailDomain !== lowerHd) {
        return accessDenied(clearPending);
      }
      const user = typeof claims.name === 'string' ? { email: email as string, name: claims.name } : { email: email as string };
      const session = await signSession(user, config!, now());
      const returnTo = checkedReturnTo(pending.returnTo, url.origin);
      const headers = new Headers(NO_STORE);
      headers.set('Location', new URL(returnTo, url.origin).href);
      headers.append('Set-Cookie', cookieHeader(request, config!.cookieName!, session, config!.sessionTtlSeconds!));
      headers.append('Set-Cookie', clearPending);
      return new Response(null, { status: ACCEPTED_REDIRECT, headers });
    } catch {
      return accessDenied(clearPending);
    }
  }

  async function handle(request: Request): Promise<SSOResult> {
    if (!config) return { response: configFailure() };
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === `${config.basePath}/login`) return { response: await login(request, url) };
    if (path === `${config.basePath}/callback`) return { response: await callback(request, url) };
    if (path === `${config.basePath}/logout`) {
      return { response: page('Signed out', `${config.basePath}/login`, 'Sign in', 200, { 'Set-Cookie': clearHeader(request, config.cookieName!) }) };
    }
    if (config.publicPaths!.includes(path)) return { pass: true };
    const token = parseCookies(request.headers.get('Cookie'))[config.cookieName!];
    if (token) {
      const user = await readSession(token, config, now());
      if (user) return { user };
    }
    const accept = request.headers.get('Accept');
    if ((request.method === 'GET' || request.method === 'HEAD') && (accept === null || accept.toLowerCase().includes('text/html'))) {
      const returnTo = path + url.search;
      return { response: redirect(`${config.basePath}/login?return=${encodeURIComponent(returnTo)}`) };
    }
    return { response: response(null, 401) };
  }

  return { handle };
}

function escapeHtml(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll("'", '&#39;');
}
