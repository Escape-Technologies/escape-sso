import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const coreDirectory = fileURLToPath(new URL('../src/core/', import.meta.url));
const forbiddenPatterns = [/from\s+['"]node:/, /require\s*\(/, /@vercel\//];

function containsForbiddenImport(source: string): boolean {
  return forbiddenPatterns.some((pattern) => pattern.test(source));
}

async function scanDirectory(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const matches: string[] = [];

  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      matches.push(...await scanDirectory(path));
    } else if (entry.isFile()) {
      const contents = await readFile(path, 'utf8');
      if (containsForbiddenImport(contents)) {
        matches.push(path);
      }
    }
  }

  return matches;
}

describe('core runtime boundaries', () => {
  it('contains no Node or Vercel imports', async () => {
    expect(await scanDirectory(coreDirectory)).toEqual([]);
  });

  it('flags a Node import in source text', () => {
    expect(containsForbiddenImport("import { randomUUID } from 'node:crypto';")).toBe(true);
  });
});
