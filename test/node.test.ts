import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from 'node:http';
import { once } from 'node:events';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { expressSSO, nodeSSO, type NodeHandler, type NodeRequest } from '../src/adapters/node.js';
import { createFakeGoogle } from './helpers/fake-google.js';

const config = { clientId: 'node-client', clientSecret: 'node-secret', sessionSecret: 'a node adapter session secret long enough', allowedDomains: ['escape.tech'], issuer: 'https://accounts.google.com' };
const restoreFetch: Array<() => void> = [];
afterEach(() => { while (restoreFetch.length) restoreFetch.pop()!(); });

async function fakeIssuer() {
  const fake = await createFakeGoogle(config);
  const original = globalThis.fetch;
  vi.stubGlobal('fetch', fake.fetch);
  restoreFetch.push(() => vi.stubGlobal('fetch', original));
  return fake;
}

async function serve(handler: NodeHandler) {
  const server = createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Server did not bind TCP port');
  return { server, origin: `http://127.0.0.1:${address.port}` };
}

async function send(url: string, headers: Record<string, string> = {}, method = 'GET', body?: string) {
  return new Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }>((resolve, reject) => {
    const request = httpRequest(url, { method, headers }, (response) => {
      let text = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { text += chunk; });
      response.on('end', () => resolve({ status: response.statusCode ?? 0, headers: response.headers, body: text }));
    });
    request.on('error', reject);
    if (body !== undefined) request.write(body);
    request.end();
  });
}

async function sendTarget(origin: string, path: string) {
  const url = new URL(origin);
  return new Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }>((resolve, reject) => {
    const request = httpRequest({ hostname: url.hostname, port: url.port, path, headers: { Accept: 'text/html' } }, (response) => {
      let text = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { text += chunk; });
      response.on('end', () => resolve({ status: response.statusCode ?? 0, headers: response.headers, body: text }));
    });
    request.on('error', reject);
    request.end();
  });
}

async function authenticated(fake: Awaited<ReturnType<typeof fakeIssuer>>, origin: string, route: NodeHandler) {
  fake.issueCode();
  const initial = await send(`${origin}/auth/login`);
  const google = await fake.fetch(new URL(headerText(initial.headers.location), origin));
  const callbackUrl = new URL(google.headers.get('Location')!);
  const pending = (initial.headers['set-cookie'] as string[])[0]!.split(';', 1)[0]!;
  const callback = await send(`${origin}${callbackUrl.pathname}${callbackUrl.search}`, { Cookie: pending });
  return { callback, route };
}

function headerText(value: string | string[] | undefined): string {
  if (typeof value !== 'string') throw new Error('Missing response header');
  return value;
}

describe('Node adapter', () => {
  it('protects real HTTP server and preserves multi-cookie gate responses', async () => {
    const fake = await fakeIssuer();
    const app = vi.fn((_request: IncomingMessage, response: ServerResponse) => { response.end('app'); });
    const { server, origin } = await serve(nodeSSO(app, config));
    try {
      const unauthenticated = await send(`${origin}/`, { Accept: 'text/html' });
      expect(unauthenticated.status).toBe(302);
      expect(new URL(headerText(unauthenticated.headers.location), origin).pathname).toBe('/auth/login');
      const { callback } = await authenticated(fake, origin, app);
      expect(callback.status).toBe(302);
      expect(callback.headers['set-cookie']).toHaveLength(2);
      const cookies = callback.headers['set-cookie'] as string[];
      const session = cookies.find((cookie) => cookie.startsWith('escape_sso='))!.split(';', 1)[0]!;
      const accepted = await send(`${origin}/private`, { Cookie: session, 'x-escape-sso-email': 'attacker@example.com' });
      expect(accepted.status).toBe(200);
      expect(app).toHaveBeenCalledOnce();
      expect(app.mock.calls[0]![0].headers['x-escape-sso-email']).toBeUndefined();
      expect((app.mock.calls[0]![0] as NodeRequest).ssoUser).toEqual({ email: 'user@escape.tech' });
      const asset = await send(`${origin}/assets/a.js`, { Accept: '*/*', 'x-escape-sso-email': 'attacker@example.com' });
      expect(asset.status).toBe(401);
      expect(app).toHaveBeenCalledOnce();
    } finally { server.close(); await once(server, 'close'); }
  });

  it('preserves original POST body for the protected Node handler', async () => {
    const fake = await fakeIssuer();
    const received: string[] = [];
    const app = (_request: IncomingMessage, response: ServerResponse) => {
      let body = '';
      _request.setEncoding('utf8');
      _request.on('data', (chunk) => { body += chunk; });
      _request.on('end', () => { received.push(body); response.end(body); });
    };
    fake.issueCode();
    const { server, origin } = await serve(nodeSSO(app, config));
    try {
      const login = await send(`${origin}/auth/login`);
      const google = await fake.fetch(new URL(headerText(login.headers.location), origin));
      const callbackUrl = new URL(google.headers.get('Location')!);
      const done = await send(`${origin}${callbackUrl.pathname}${callbackUrl.search}`, { Cookie: (login.headers['set-cookie'] as string[])[0]!.split(';', 1)[0]! });
      const session = (done.headers['set-cookie'] as string[]).find((cookie) => cookie.startsWith('escape_sso='))!.split(';', 1)[0]!;
      const post = await send(`${origin}/submit`, { Cookie: session, 'Content-Type': 'text/plain' }, 'POST', 'full request body');
      expect(post.body).toBe('full request body');
      expect(received).toEqual(['full request body']);
    } finally { server.close(); await once(server, 'close'); }
  });

  it('runs Express-like middleware in a real connect stack', async () => {
    const fake = await fakeIssuer();
    fake.issueCode();
    const middleware = expressSSO(config);
    const stack = [(req: any, res: ServerResponse, next: (error?: unknown) => void) => middleware(req, res, next), (req: any, res: ServerResponse) => { res.end(req.ssoUser?.email ?? 'missing'); }];
    const runner = (req: IncomingMessage, res: ServerResponse) => {
      let index = 0;
      const next = (error?: unknown) => { if (error) { res.writeHead(500); res.end(); return; } stack[index++]!(req, res, next); };
      next();
    };
    const { server, origin } = await serve(runner);
    try {
      const login = await send(`${origin}/auth/login`);
      const google = await fake.fetch(new URL(headerText(login.headers.location), origin));
      const callbackUrl = new URL(google.headers.get('Location')!);
      const callback = await send(`${origin}${callbackUrl.pathname}${callbackUrl.search}`, { Cookie: (login.headers['set-cookie'] as string[])[0]!.split(';', 1)[0]! });
      expect(callback.status).toBe(302);
      expect(callback.headers['set-cookie']).toHaveLength(2);
      const session = (callback.headers['set-cookie'] as string[]).find((cookie) => cookie.startsWith('escape_sso='))!.split(';', 1)[0]!;
      expect((await send(`${origin}/`, { Cookie: session, 'x-escape-sso-email': 'spoof@example.com' })).body).toBe('user@escape.tech');
    } finally { server.close(); await once(server, 'close'); }
  });

  it('uses forwarded origin only when trustProxy is enabled', async () => {
    await fakeIssuer();
    const { server, origin } = await serve(nodeSSO((_req, res) => res.end(), { ...config, trustProxy: true }));
    try {
      const response = await send(`${origin}/auth/login`, { 'x-forwarded-proto': 'https', 'x-forwarded-host': 'public.example' });
      const redirectUri = new URL(headerText(response.headers.location), origin).searchParams.get('redirect_uri');
      expect(redirectUri).toBe('https://public.example/auth/callback');
    } finally { server.close(); await once(server, 'close'); }
    const untrusted = await serve(nodeSSO((_req, res) => res.end(), config));
    try {
      const response = await send(`${untrusted.origin}/auth/login`, { 'x-forwarded-proto': 'https', 'x-forwarded-host': 'public.example' });
      const redirectUri = new URL(headerText(response.headers.location), untrusted.origin).searchParams.get('redirect_uri');
      expect(redirectUri).toBe(`${untrusted.origin}/auth/callback`);
    } finally { untrusted.server.close(); await once(untrusted.server, 'close'); }
  }, 10000);

  it('rejects protocol-relative request targets before the app', async () => {
    const app = vi.fn((_req: IncomingMessage, res: ServerResponse) => res.end('app'));
    const { server, origin } = await serve(nodeSSO(app, config));
    try {
      for (const path of ['//evil.example/auth/login', '/\\evil.example/auth/login', 'http://evil.example/auth/login']) {
        const malformed = await sendTarget(origin, path);
        expect(malformed.status).toBe(400);
        expect(malformed.headers['cache-control']).toBe('no-store');
      }
      expect(app).not.toHaveBeenCalled();
    } finally { server.close(); await once(server, 'close'); }
  }, 10000);

  it('fails closed for malformed URLs, missing config, and gate errors', async () => {
    const app = vi.fn((_req: IncomingMessage, res: ServerResponse) => res.end('app'));
    const { server, origin } = await serve(nodeSSO(app, config));
    try {
      const malformed = await send(`${origin}/`, { Host: '[' });
      expect([400, 403]).toContain(malformed.status);
      expect(app).not.toHaveBeenCalled();
    } finally { server.close(); await once(server, 'close'); }
    const misconfigured = await serve(nodeSSO(app, { ...config, sessionSecret: 'short' }));
    try {
      const response = await send(`${misconfigured.origin}/`);
      expect(response.status).toBe(500);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(app).not.toHaveBeenCalled();
    }
    finally { misconfigured.server.close(); await once(misconfigured.server, 'close'); }
  }, 10000);
});
