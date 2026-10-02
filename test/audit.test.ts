import { afterEach, describe, expect, it } from 'vitest';
import { executePlan, planApply } from '../src/apply.js';
import { audit, worstSeverity } from '../src/audit.js';
import { parsePolicy } from '../src/policy/load.js';
import { renderPreset } from '../src/policy/presets.js';
import { parseCodexRules } from '../src/targets/codex.js';
import { normalizeClaudeRule } from '../src/targets/claude.js';
import { normalizeCursorRule } from '../src/targets/cursor.js';
import { sandbox } from './helpers.js';

let sb: ReturnType<typeof sandbox>;
afterEach(() => sb?.cleanup());

describe('native rule normalization', () => {
  it('Claude', () => {
    expect(normalizeClaudeRule('Bash(git status:*)')).toEqual({ category: 'shell', pattern: 'git status *' });
    expect(normalizeClaudeRule('Bash')).toEqual({ category: 'shell', pattern: '*' });
    expect(normalizeClaudeRule('Bash(*)')).toEqual({ category: 'shell', pattern: '*' });
    expect(normalizeClaudeRule('Read(//etc/passwd)')).toEqual({ category: 'read', pattern: '/etc/passwd' });
    expect(normalizeClaudeRule('Edit(src/**)')).toEqual({ category: 'write', pattern: 'src/**' });
    expect(normalizeClaudeRule('WebFetch(domain:*.github.com)')).toEqual({ category: 'web', pattern: '*.github.com' });
    expect(normalizeClaudeRule('mcp__github__create_issue')).toEqual({ category: 'mcp', pattern: 'github:create_issue' });
    expect(normalizeClaudeRule('mcp__github')).toEqual({ category: 'mcp', pattern: 'github:*' });
    expect(normalizeClaudeRule('WebSearch')).toEqual({ category: 'tool', pattern: 'WebSearch' });
  });

  it('Cursor', () => {
    expect(normalizeCursorRule('Shell(git)')).toEqual({ category: 'shell', pattern: 'git *' });
    expect(normalizeCursorRule('Shell(curl:*)')).toEqual({ category: 'shell', pattern: 'curl *' });
    expect(normalizeCursorRule('Shell(git:status)')).toEqual({ category: 'shell', pattern: 'git status' });
    expect(normalizeCursorRule('Mcp(datadog:*)')).toEqual({ category: 'mcp', pattern: 'datadog:*' });
  });

  it('Codex rules (Starlark subset with alternatives)', () => {
    const rules = parseCodexRules(`
# comment with prefix_rule(pattern=["nope"])
prefix_rule(pattern = ["gh", ["pr", "issue"], "view"], decision = "prompt", justification = "a, b (c)")
prefix_rule(pattern=['ls'])
`);
    expect(rules).toEqual([
      { patterns: [['gh', 'pr', 'view'], ['gh', 'issue', 'view']], decision: 'prompt' },
      { patterns: [['ls']], decision: 'allow' },
    ]);
  });
});

describe('audit', () => {
  it('detects dangerous grants in every agent', () => {
    sb = sandbox({ home: true, project: true });
    const r = audit({ ctx: sb.ctx, scopes: ['project', 'user'] });
    expect(r.agents.map((a) => [a.agent, a.detected])).toEqual([
      ['claude', true],
      ['codex', true],
      ['gemini', true],
      ['cursor', true],
    ]);
    const has = (id: string, agent: string, re: RegExp) => r.findings.some((f) => f.id === id && f.agent === agent && re.test(f.message));
    // Claude
    expect(has('bypass-mode', 'claude', /bypassPermissions/)).toBe(true);
    expect(has('dangerous-allow', 'claude', /"curl \*".*network/)).toBe(true);
    expect(has('secrets-read-allowed', 'claude', /"\*\*"/)).toBe(true);
    expect(has('web-any', 'claude', /any URL/)).toBe(true);
    // Codex
    expect(has('bypass-mode', 'codex', /danger-full-access/)).toBe(true);
    expect(has('never-ask', 'codex', /never asks/)).toBe(true);
    expect(has('network-on', 'codex', /network access/)).toBe(true);
    expect(has('dangerous-allow', 'codex', /"npm \*"/)).toBe(true);
    // Gemini
    expect(has('bypass-mode', 'gemini', /YOLO/)).toBe(true);
    expect(has('dangerous-allow', 'gemini', /"git push \*"/)).toBe(true);
    expect(has('mcp-trusted', 'gemini', /"fs"/)).toBe(true);
    // Cursor
    expect(has('dangerous-allow', 'cursor', /"git \*"/)).toBe(true);
    expect(has('git-write-allowed', 'cursor', /\.git/)).toBe(true);
    // missing protections and inconsistencies
    expect(has('secrets-unprotected', 'cursor', /\.env/)).toBe(true);
    expect(has('secrets-unprotected', 'claude', /\.env/)).toBe(false); // Read(./.env) is denied
    expect(has('inconsistent', 'gemini', /"git push \*" is denied in Codex CLI but auto-approved in Gemini CLI/)).toBe(true);
    expect(has('inconsistent', 'cursor', /"git push \*" is denied in Codex CLI but auto-approved in Cursor CLI by "git \*"/)).toBe(true);
    expect(worstSeverity(r.findings)).toBe('high');
    // findings are sorted by severity
    const ranks = r.findings.map((f) => ({ high: 3, medium: 2, low: 1 })[f.severity]);
    expect([...ranks].sort((a, b) => b - a)).toEqual(ranks);
  });

  it('reads Codex rules files and Gemini legacy allowlists', () => {
    sb = sandbox({ home: true });
    const r = audit({ ctx: sb.ctx, scopes: ['user'] });
    const codex = r.agents.find((a) => a.agent === 'codex')!;
    expect(codex.rules.filter((x) => x.category === 'shell').map((x) => `${x.decision} ${x.pattern}`)).toEqual([
      'allow git status *',
      'allow git log *',
      'deny git push *',
      'allow npm *',
    ]);
    expect(codex.settings.find((s) => s.key === 'projects.trusted')?.value).toBe('1');
    const gem = r.agents.find((a) => a.agent === 'gemini')!;
    expect(gem.rules.filter((x) => x.category === 'shell').map((x) => x.pattern)).toEqual(['git status *', 'git push *']);
  });

  it('project scope only reads project files', () => {
    sb = sandbox({ home: true, project: true });
    const r = audit({ ctx: sb.ctx, scopes: ['project'] });
    expect(r.agents.flatMap((a) => a.files).every((f) => f.scope === 'project')).toBe(true);
    expect(r.findings.some((f) => f.id === 'bypass-mode')).toBe(false);
  });

  it('a project configured from a preset has no high findings', () => {
    sb = sandbox();
    const { policy } = parsePolicy(renderPreset('node'));
    executePlan(planApply(policy, { scope: 'project', targets: ['claude', 'codex', 'gemini', 'cursor'], ctx: sb.ctx }));
    const r = audit({ ctx: sb.ctx, scopes: ['project'] });
    expect(r.findings.filter((f) => f.severity === 'high')).toEqual([]);
    expect(r.findings.filter((f) => f.id === 'secrets-unprotected')).toEqual([]);
  });

  it('reports nothing when no agent is configured', () => {
    sb = sandbox();
    const r = audit({ ctx: sb.ctx, scopes: ['project', 'user'] });
    expect(r.agents.every((a) => !a.detected)).toBe(true);
    expect(r.findings).toEqual([]);
  });
});
