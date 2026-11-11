import type { IncomingMessage, OutgoingHttpHeaders, ServerResponse } from 'node:http';
import type { TLSSocket } from 'node:tls';
import { configFromEnv, createSSO, type SSOConfig } from '../core/index.js';

export interface NodeSSOConfig extends SSOConfig {
  trustProxy?: boolean;
}

export type NodeRequest = IncomingMessage & { ssoUser?: { email: string; name?: string } };
export type NodeHandler = (request: NodeRequest, response: ServerResponse) => unknown | Promise<unknown>;

export function expressSSO(config?: unknown): (request: IncomingMessage & { ssoUser?: { email: string; name?: string } }, response: ServerResponse, next: (error?: unknown) => void) => void {
  const gate = createSSO(config === undefined ? processConfig() : config);
  return (request, response, next) => {
    delete request.ssoUser;
    delete request.headers['x-escape-sso-email'];
    void (async () => {
      let webRequest: Request;
      try {
        webRequest = toRequest(request, configTrustProxy(config));
      } catch {
        sendFailure(response, 400);
        return;
      }
      let result;
      try { result = await gate.handle(webRequest); }
      catch { sendFailure(response, 500); return; }
      if ('response' in result) await writeResponse(result.response, response);
      else {
        delete request.headers['x-escape-sso-email'];
        if ('user' in result) request.ssoUser = result.user;
        next();
      }
    })();
  };
}

export function nodeSSO(handler: NodeHandler, config?: unknown): NodeHandler {
  const gate = createSSO(config === undefined ? processConfig() : config);
  return async (request, response) => {
    delete (request as NodeRequest).ssoUser;
    delete request.headers['x-escape-sso-email'];
    let webRequest: Request;
    try {
      webRequest = toRequest(request, configTrustProxy(config));
    } catch {
      sendFailure(response, 400);
      return;
    }
    let result;
    try { result = await gate.handle(webRequest); }
    catch { sendFailure(response, 500); return; }
    if ('response' in result) { await writeResponse(result.response, response); return; }
    delete request.headers['x-escape-sso-email'];
    if ('user' in result) (request as NodeRequest).ssoUser = result.user;
    try { await handler(request, response); }
    catch { if (!response.headersSent) sendFailure(response, 500); else response.destroy(); }
  };
}

function sendFailure(response: ServerResponse, status: number): void {
  if (response.headersSent) { response.destroy(); return; }
  response.writeHead(status, { 'Cache-Control': 'no-store' });
  response.end();
}

function processConfig(): Record<string, unknown> {
  return configFromEnv(process.env);
}

function configTrustProxy(config: unknown): boolean {
  return typeof config === 'object' && config !== null && (config as NodeSSOConfig).trustProxy === true;
}

function toRequest(request: IncomingMessage, trustProxy: boolean): Request {
  const headers = new Headers();
  for (const [name, value] of Object.entries(request.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) headers.set(name, value.join(', '));
    else headers.set(name, value);
  }
  headers.delete('x-escape-sso-email');
  const host = trustProxy
    ? firstHeader(request.headers['x-forwarded-host']) ?? firstHeader(request.headers.host)
    : firstHeader(request.headers.host);
  if (!host) throw new TypeError('Missing host');
  const protocol = trustProxy
    ? (firstHeader(request.headers['x-forwarded-proto']) ?? 'http').split(',')[0]!.trim()
    : (request.socket as TLSSocket).encrypted ? 'https' : 'http';
  if (protocol !== 'http' && protocol !== 'https') throw new TypeError('Invalid protocol');
  const path = request.url;
  if (typeof path !== 'string' || !/^\/(?![\\/])/.test(path)) throw new TypeError('Invalid request target');
  const url = new URL(path, `${protocol}://${host}`);
  return new Request(url, { method: request.method ?? 'GET', headers });
}

function firstHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

async function writeResponse(response: Response, target: ServerResponse): Promise<void> {
  const headers: OutgoingHttpHeaders = {};
  const cookies = response.headers.getSetCookie();
  response.headers.forEach((value, name) => {
    if (name !== 'set-cookie') headers[name] = value;
  });
  if (cookies.length) headers['Set-Cookie'] = cookies;
  target.writeHead(response.status, headers);
  if (response.body) {
    const body = new Uint8Array(await response.arrayBuffer());
    target.end(body);
  } else target.end();
}
