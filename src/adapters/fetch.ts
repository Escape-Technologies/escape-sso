import { configFromEnv, createSSO } from '../core/index.js';

type Handler<Args extends [Request, ...unknown[]]> = (...args: Args) => Response | Promise<Response>;

const users = new WeakMap<Request, { email: string; name?: string }>();

export function getUser(request: Request): { email: string; name?: string } | undefined {
  return users.get(request);
}

export function withSSO<Args extends [Request, ...unknown[]]>(handler: Handler<Args>, config?: unknown): (...args: Args) => Promise<Response> {
  return async (...args) => {
    const [incoming] = args;
    try {
      let request = incoming;
      users.delete(incoming);
      try {
        incoming.headers.delete('x-escape-sso-email');
      } catch {
        const headers = new Headers(incoming.headers);
        headers.delete('x-escape-sso-email');
        request = new Request(incoming, { headers });
      }
      const workerCall = args.length === 3 && typeof args[2] === 'object' && args[2] !== null && 'waitUntil' in args[2] && typeof (args[2] as { waitUntil?: unknown }).waitUntil === 'function';
      const source = config === undefined
        ? workerCall && typeof args[1] === 'object' && args[1] !== null
          ? configFromEnv(stringBindings(args[1]))
          : configFromEnv(stringBindings(globalThis.process?.env))
        : config;
      const result = await createSSO(source).handle(request);
      if ('response' in result) return result.response;
      if ('user' in result) users.set(request, result.user);
      args[0] = request;
      return await handler(...args);
    } catch {
      return new Response('SSO unavailable', { status: 500, headers: { 'Cache-Control': 'no-store' } });
    }
  };
}

function stringBindings(value: unknown): Record<string, string | undefined> {
  if (typeof value !== 'object' || value === null) return {};
  const result: Record<string, string | undefined> = {};
  for (const [key, item] of Object.entries(value)) {
    if (typeof item === 'string') result[key] = item;
  }
  return result;
}
