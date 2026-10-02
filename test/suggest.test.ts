import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { parsePolicy } from '../src/policy/load.js';
import { maskCommand } from '../src/secrets.js';
import { aggregate, allowCandidates, derivePattern, mine, mineClaude, mineCodex, mineGemini, parseSince } from '../src/suggest.js';
import { FIXTURES } from './helpers.js';

const home = path.join(FIXTURES, 'home');
const since = 0;

describe('history miners', () => {
  it('Claude Code transcripts: Bash tool_use + approval outcome', async () => {
    const r = await mineClaude({ home, sinceMs: since });
    expect(r.found).toBe(true);
    expect(r.files).toBe(2);
    expect(r.obs.length).toBe(38);
    const rm = r.obs.find((o) => o.command === 'rm -rf dist')!;
    expect(rm.outcome).toBe('rejected');
    expect(r.obs.find((o) => o.command === 'git status')!.outcome).toBe('approved');
    expect(r.obs.every((o) => o.source === 'claude')).toBe(true);
  });

  it('Claude Code: --project restricts to sessions under the cwd', async () => {
    const r = await mineClaude({ home, sinceMs: since, projectDir: '/work/other' });
    expect(r.obs.map((o) => o.command)).toEqual(['git log --oneline -5', 'git status']);
  });

  it('Codex rollouts: exec_command, shell argv, shell_command, local_shell_call', async () => {
    const r = await mineCodex({ home, sinceMs: since });
    expect(r.obs.map((o) => o.command)).toEqual([
      'git status',
      'git log -3',
      'git status && npm test',
      'ls -la',
      'git status',
      'export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD && curl https://api.openai.com',
      'git push --force',
      'npm test',
      'git diff',
      'git diff --stat',
    ]);
    expect(r.obs.find((o) => o.command === 'git push --force')!.outcome).toBe('rejected');
    expect(r.obs[0]!.session).toBe('codex-1');
  });

  it('Gemini CLI chats', async () => {
    const r = await mineGemini({ home, sinceMs: since });
    expect(r.obs.map((o) => [o.command, o.outcome])).toEqual([
      ['git status', 'approved'],
      ['rm -rf /tmp/x', 'rejected'],
    ]);
  });

  it('respects --since', async () => {
    const r = await mineClaude({ home, sinceMs: Date.parse('2026-09-21T00:00:00Z') });
    expect(r.obs.every((o) => o.time >= Date.parse('2026-09-21T00:00:00Z'))).toBe(true);
    expect(r.obs.length).toBeLessThan(38);
  });
});

describe('aggregation and safety', () => {
  it('ranks patterns, splits compound commands and classifies them', async () => {
    const report = await mine({ home, sinceMs: since }, null);
    const by = (p: string) => report.patterns.find((x) => x.pattern === p);
    expect(by('git status *')).toMatchObject({ cls: 'safe', sources: ['claude', 'codex', 'gemini'] });
    expect(by('git status *')!.count).toBe(8);
    expect(by('npm test *')).toMatchObject({ cls: 'safe' }); // timeout/NODE_ENV wrappers stripped
    expect(by('cat *')).toMatchObject({ cls: 'safe' });
    expect(by('curl *')).toMatchObject({ cls: 'never' });
    expect(by('sh *')).toMatchObject({ cls: 'never' });
    expect(by('rm -rf *') ?? by('rm *')).toBeDefined();
    expect(by('git push *')).toMatchObject({ cls: 'never' });
    expect(by('git commit *')).toMatchObject({ cls: 'ask' });
    expect(by('gh pr *') ?? by('gh pr list *')).toMatchObject({ cls: 'ask' });

    const allow = allowCandidates(report, 3).map((p) => p.pattern);
    expect(allow).toEqual(expect.arrayContaining(['git status *', 'git diff *', 'ls *', 'npm run test *', 'npm test *']));
    expect(allow).not.toContain('rg *'); // rejected once
    for (const bad of ['curl *', 'rm *', 'git push *', 'git commit *', 'sh *']) expect(allow).not.toContain(bad);
  });

  it('never prints secrets: examples and patterns are masked', async () => {
    const report = await mine({ home, sinceMs: since }, null);
    const dump = JSON.stringify(report);
    expect(dump).not.toContain('ghp_abcdefghijklmnopqrstuvwxyz0123456789AB');
    expect(dump).not.toContain('ghp_ZZZZabcdefghijklmnopqrstuvwxyz0123456789');
    expect(dump).not.toContain('sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD');
    expect(dump).toContain('GITHUB_TOKEN=****');
  });

  it('skips patterns already covered by the policy', async () => {
    const { policy } = parsePolicy('version: 1\nshell:\n  allow: ["git *"]\n  deny: ["curl *"]\n');
    const report = await mine({ home, sinceMs: since }, policy);
    expect(report.patterns.find((p) => p.pattern === 'git status *')!.policy).toBe('allowed');
    expect(report.patterns.find((p) => p.pattern === 'curl *')!.policy).toBe('denied');
    expect(allowCandidates(report, 1).map((p) => p.pattern)).not.toContain('git status *');
  });

  it('aggregate counts sessions and approvals', () => {
    const { patterns } = aggregate(
      [
        { source: 'claude', command: 'ls -la', time: 1, outcome: 'approved', session: 'a' },
        { source: 'claude', command: 'ls', time: 2, outcome: 'approved', session: 'b' },
        { source: 'codex', command: 'ls src | wc -l', time: 3, outcome: 'unknown', session: 'b' },
      ],
      null,
    );
    expect(patterns.find((p) => p.pattern === 'ls *')).toMatchObject({ count: 3, sessions: 2, approved: 2, sources: ['claude', 'codex'] });
    expect(patterns.find((p) => p.pattern === 'wc *')!.count).toBe(1);
  });
});

describe('derivePattern', () => {
  const d = (cmd: string) => derivePattern(cmd.split(' '));
  it('generalizes to a stable prefix', () => {
    expect(d('git status --short')).toBe('git status *');
    expect(d('npm run test -- --run')).toBe('npm run test *');
    expect(d('npm test')).toBe('npm test *');
    expect(d('pnpm run lint')).toBe('pnpm run lint *');
    expect(d('python3 -m pytest -q')).toBe('python3 -m pytest *');
    expect(d('docker compose up -d')).toBe('docker compose up *');
    expect(d('gh pr view 12')).toBe('gh pr view *');
    expect(d('ls -la src')).toBe('ls *');
    expect(d('node --version')).toBe('node --version');
    expect(d('timeout 30 npm test')).toBe('npm test *');
    expect(d('FOO=1 BAR=2 cargo test')).toBe('cargo test *');
  });
  it('refuses to generalize what it cannot read safely', () => {
    expect(d('git -C /x status')).toBeNull();
    expect(d('cd src')).toBeNull();
    expect(d('npm run')).toBeNull();
    expect(d('git ghp_abcdefghijklmnopqrstuvwxyz0123456789AB')).toBeNull();
  });
});

describe('maskCommand', () => {
  it('masks tokens, env values, auth headers, URL credentials and flags', () => {
    const m = maskCommand(
      `API_TOKEN=abc123 curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" https://user:hunter2@example.com --password s3cret -p'pw' AKIAIOSFODNN7EXAMPL3 sk-ant-api03-${'a1B2'.repeat(10)}`,
    );
    for (const s of ['abc123', 'eyJhbGci', 'hunter2', 's3cret', 'IOSFODNN7EXAMPL3', 'a1B2a1B2']) expect(m).not.toContain(s);
    expect(m).toContain('API_TOKEN=****');
    expect(m).toContain('https://user:****@example.com');
  });
  it('keeps ordinary commands readable', () => {
    expect(maskCommand('git log --oneline -5 src/components/Button.tsx')).toBe('git log --oneline -5 src/components/Button.tsx');
  });
});

describe('parseSince', () => {
  it('parses durations and dates', () => {
    const now = Date.now();
    expect(Math.abs(parseSince('30d') - (now - 30 * 86400e3))).toBeLessThan(5000);
    expect(Math.abs(parseSince('12h') - (now - 12 * 3600e3))).toBeLessThan(5000);
    expect(parseSince('2026-01-01')).toBe(Date.parse('2026-01-01'));
    expect(() => parseSince('soon')).toThrow(/duration/);
  });
});
