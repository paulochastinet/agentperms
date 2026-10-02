import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { CLI, ROOT, referencePolicyText, sandbox } from './helpers.js';

function run(args: string[], opts: { cwd?: string; env?: Record<string, string> } = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    cwd: opts.cwd ?? ROOT,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '', ...opts.env },
  });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

beforeAll(() => {
  if (!existsSync(CLI)) {
    const b = spawnSync('npm', ['run', 'build'], { cwd: ROOT, encoding: 'utf8', shell: process.platform === 'win32' });
    if (b.status !== 0) throw new Error(`build failed: ${b.stderr}`);
  }
}, 120_000);

let sb: ReturnType<typeof sandbox>;
afterEach(() => sb?.cleanup());

describe('cli basics', () => {
  it('--version / --help', () => {
    const pkg = JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8')) as { version: string };
    expect(run(['--version']).out.trim()).toBe(pkg.version);
    const h = run(['--help']);
    expect(h.code).toBe(0);
    expect(h.out).toMatch(/one permission policy for every AI coding agent/);
  });

  it('usage errors exit 2', () => {
    expect(run([]).code).toBe(2);
    expect(run(['frobnicate']).code).toBe(2);
    expect(run(['audit', '--bogus']).code).toBe(2);
    expect(run(['audit', '--format', 'xml']).code).toBe(2);
    expect(run(['init', '--dry-run']).err).toMatch(/not an option of "init"/);
    expect(run(['suggest', '--since', 'soon']).code).toBe(2);
  });
});

describe('init → apply → diff', () => {
  it('full flow is idempotent and reports drift', () => {
    sb = sandbox();
    sb.write('package.json', '{}');
    const base = ['--cwd', sb.proj, '--home', sb.home];
    const init = run(['init', ...base]);
    expect(init.code).toBe(0);
    expect(init.out).toMatch(/preset: node, auto-detected/);
    expect(run(['init', ...base]).code).toBe(2); // exists

    const dry = run(['apply', '--dry-run', ...base]);
    expect(dry.code).toBe(0);
    expect(dry.out).toContain('+++ b/.claude/settings.json');
    expect(existsSync(path.join(sb.proj, '.claude'))).toBe(false);

    expect(run(['diff', ...base]).code).toBe(1); // nothing applied yet: drift

    const apply = run(['apply', ...base]);
    expect(apply.code).toBe(0);
    expect(apply.out).toMatch(/created \.claude\/settings\.json/);
    expect(apply.out).toMatch(/created \.cursor\/cli\.json/);

    const again = run(['apply', ...base]);
    expect(again.out).toMatch(/Nothing to do/);
    const diff = run(['diff', ...base]);
    expect(diff.code).toBe(0);
    expect(diff.out).toMatch(/In sync/);

    // hand-edit a native file: drift is detected, user entries are preserved on re-apply
    const settings = path.join(sb.proj, '.claude/settings.json');
    const j = JSON.parse(readFileSync(settings, 'utf8'));
    j.permissions.allow = j.permissions.allow.filter((x: string) => x !== 'Bash(git status *)');
    j.permissions.allow.push('Bash(make *)');
    writeFileSync(settings, JSON.stringify(j, null, 2));
    const drift = run(['diff', ...base]);
    expect(drift.code).toBe(1);
    expect(drift.out).toContain('+      "Bash(git status *)"');
    expect(run(['apply', ...base]).code).toBe(0);
    const after = JSON.parse(readFileSync(settings, 'utf8'));
    expect(after.permissions.allow).toContain('Bash(make *)');
    expect(after.permissions.allow).toContain('Bash(git status *)');
    expect(run(['diff', '--format', 'json', ...base]).out).toMatch(/"drift": \[\]/);
  });

  it('--target and --scope user', () => {
    sb = sandbox();
    sb.write('agentperms.yaml', referencePolicyText());
    const r = run(['apply', '--target', 'claude,cursor', '--scope', 'user', '--cwd', sb.proj, '--home', sb.home]);
    expect(r.code).toBe(0);
    expect(existsSync(path.join(sb.home, '.claude/settings.json'))).toBe(true);
    expect(existsSync(path.join(sb.home, '.cursor/cli-config.json'))).toBe(true);
    expect(existsSync(path.join(sb.home, '.codex'))).toBe(false);
    expect(r.err).toMatch(/contains shell operators/);
  });

  it('invalid policy exits 2 with file:line', () => {
    sb = sandbox();
    sb.write('agentperms.yaml', 'version: 1\nshell:\n  allow: ["ls && rm"]\n');
    const r = run(['apply', '--cwd', sb.proj, '--home', sb.home]);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/agentperms\.yaml: invalid policy\n {2}3:\d+ shell\.allow\[0\]/);
  });

  it('missing policy exits 2 with a hint', () => {
    sb = sandbox();
    const r = run(['apply', '--cwd', sb.proj, '--home', sb.home]);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/agentperms init/);
  });
});

describe('audit', () => {
  it('text, json, markdown and --fail-on', () => {
    sb = sandbox({ home: true, project: true });
    const base = ['--cwd', sb.proj, '--home', sb.home];
    const t = run(['audit', ...base]);
    expect(t.code).toBe(0);
    expect(t.out).toMatch(/Claude Code/);
    expect(t.out).toMatch(/HIGH/);
    expect(t.out).not.toMatch(/\x1b\[/); // NO_COLOR
    const j = JSON.parse(run(['audit', '--format', 'json', ...base]).out);
    expect(j.schemaVersion).toBe(1);
    expect(j.summary.high).toBeGreaterThan(0);
    expect(JSON.stringify(j)).not.toContain(sb.home); // paths are shown relative to ~
    expect(run(['audit', '--format', 'markdown', ...base]).out).toMatch(/^## agentperms audit/);
    expect(run(['audit', '--fail-on', 'high', ...base]).code).toBe(1);
    expect(run(['audit', '--fail-on', 'high', '--scope', 'project', ...base]).code).toBe(0);
    expect(run(['audit', '--home', '--cwd', sb.proj]).code).toBe(0); // bare --home is accepted
  });
});

describe('suggest', () => {
  it('mines fixtures without leaking secrets, and --write merges into the policy', () => {
    sb = sandbox({ home: true });
    const base = ['--cwd', sb.proj, '--home', sb.home, '--since', '3650d'];
    const t = run(['suggest', ...base, '--verbose']);
    expect(t.code).toBe(0);
    expect(t.out).toMatch(/Suggested allow/);
    expect(t.out).toMatch(/git status \*/);
    expect(t.out).not.toMatch(/ghp_[A-Za-z0-9]{20}/);
    expect(t.out).not.toContain('sk-proj-abcdefghij');
    const j = JSON.parse(run(['suggest', '--format', 'json', ...base]).out);
    expect(j.suggestions.allow.map((p: { pattern: string }) => p.pattern)).toContain('git diff *');
    expect(JSON.stringify(j)).not.toMatch(/ghp_[A-Za-z0-9]{20}/);

    expect(run(['suggest', '--write', ...base]).code).toBe(2); // no policy yet
    sb.write('agentperms.yaml', '# mine\nversion: 1\nshell:\n  allow: ["git status *"]\n');
    const w = run(['suggest', '--write', ...base]);
    expect(w.code).toBe(0);
    expect(w.err).toMatch(/added \d+ patterns?/);
    const pol = sb.read('agentperms.yaml');
    expect(pol).toMatch(/^# mine/);
    expect(pol).toContain('"git diff *"');
    expect(pol).not.toContain('curl');
    // transcripts are never modified
    expect(readFileSync(path.join(sb.home, '.claude/projects/-work-app/sess-a.jsonl'), 'utf8')).toContain('ghp_abcdefghij');
  });

  it('handles an empty home', () => {
    sb = sandbox();
    const r = run(['suggest', '--cwd', sb.proj, '--home', sb.home]);
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/No shell commands found/);
  });
});
