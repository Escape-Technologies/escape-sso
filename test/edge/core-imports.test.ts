import { expect, it } from 'vitest';
import { createSSO } from '../../src/core/index.js';

it('imports core without Node globals', () => {
  expect(createSSO).toBeTypeOf('function');
  expect(typeof (globalThis as { EdgeRuntime?: unknown }).EdgeRuntime).toBe('string');
});
