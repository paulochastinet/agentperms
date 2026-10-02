import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const FIXTURES = path.join(ROOT, 'test', 'fixtures');
export const CLI = path.join(ROOT, 'dist', 'cli.js');

/** A throwaway directory with an empty `home/` and `proj/` (optionally seeded from fixtures). */
export function sandbox(opts: { home?: boolean; project?: boolean } = {}) {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'agentperms-test-'));
  const home = path.join(dir, 'home');
  const proj = path.join(dir, 'proj');
  if (opts.home) cpSync(path.join(FIXTURES, 'home'), home, { recursive: true });
  else mkdirSync(home);
  if (opts.project) cpSync(path.join(FIXTURES, 'project'), proj, { recursive: true });
  else mkdirSync(proj);
  return {
    dir,
    home,
    proj,
    ctx: { cwd: proj, home },
    write(rel: string, content: string) {
      const p = path.join(proj, rel);
      mkdirSync(path.dirname(p), { recursive: true });
      writeFileSync(p, content);
      return p;
    },
    read(rel: string) {
      return readFileSync(path.join(proj, rel), 'utf8');
    },
    cleanup() {
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

export const referencePolicyText = () => readFileSync(path.join(FIXTURES, 'policy', 'agentperms.yaml'), 'utf8');
