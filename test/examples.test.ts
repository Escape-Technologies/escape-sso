import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const exampleDirectory = fileURLToPath(new URL('../examples/vercel-static/', import.meta.url));
const exampleFiles = ['middleware.ts', 'public/index.html', 'vercel.json', 'README.md'];
const literalStatement = "export const config = { matcher: ['/((?!_vercel).*)'] };";

// Source with comments removed, so a commented-out statement cannot pass for the real one.
function codeOf(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
}

describe('vercel-static example', () => {
  it('has its four files', () => {
    for (const file of exampleFiles) {
      expect(existsSync(exampleDirectory + file), file).toBe(true);
    }
  });

  it('keeps middleware.ts within 10 non-blank lines', () => {
    const lines = readFileSync(exampleDirectory + 'middleware.ts', 'utf8').split('\n').filter((line) => line.trim() !== '');
    expect(lines.length).toBeGreaterThanOrEqual(1);
    expect(lines.length).toBeLessThanOrEqual(10);
  });

  it('exports config as the literal matcher, with no imported identifier', () => {
    const code = codeOf(readFileSync(exampleDirectory + 'middleware.ts', 'utf8'));
    const statements = code.split('\n').map((line) => line.trim()).filter((line) => line !== '');
    expect(statements).toContain(literalStatement);
    expect(code.match(/\bconfig\b/g)).toHaveLength(1);
  });

  it('declares a static framework', () => {
    expect(JSON.parse(readFileSync(exampleDirectory + 'vercel.json', 'utf8'))).toEqual({ framework: null });
  });

  it('includes middleware.ts verbatim in the README', () => {
    const middleware = readFileSync(exampleDirectory + 'middleware.ts', 'utf8');
    const readme = readFileSync(fileURLToPath(new URL('../README.md', import.meta.url)), 'utf8');
    expect(readme).toContain(middleware);
  });
});
