import { expect, it } from 'vitest';
import type { SSOConfig } from '../../src/core/config.js';
import { readPending, readSession, signPending, signSession } from '../../src/core/session.js';

const NOW = 1_800_000_000;
const config: SSOConfig = {
  clientId: 'client-id.apps.googleusercontent.com',
  clientSecret: 'client-secret-value',
  sessionSecret: 'a'.repeat(32),
  allowedDomains: ['escape.tech'],
};

it('signs and reads sessions and pending logins without Node globals', async () => {
  const token = await signSession({ email: 'ana@escape.tech', name: 'Ana' }, config, NOW);
  expect(await readSession(token, config, NOW)).toEqual({ email: 'ana@escape.tech', name: 'Ana' });

  const pending = { state: 's', nonce: 'n', verifier: 'v', returnTo: '/' };
  const pendingToken = await signPending(pending, config, NOW);
  expect(await readPending(pendingToken, config, NOW)).toEqual(pending);
  expect(await readSession(pendingToken, config, NOW)).toBeNull();
});
