import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { parse as parseToml } from 'smol-toml';
import { describe, expect, it } from 'vitest';
import { mergeJsonLists } from '../src/apply.js';
import { parsePolicy } from '../src/policy/load.js';
import { claude } from '../src/targets/claude.js';
import { codex, codexPrefix, parseCodexRules } from '../src/targets/codex.js';
import type { FilePlan } from '../src/targets/common.js';
import { cursor, cursorShell } from '../src/targets/cursor.js';
import { gemini, geminiShell } from '../src/targets/gemini.js';
import type { Ctx, Policy } from '../src/types.js';
import { FIXTURES, referencePolicyText } from './helpers.js';

const ctx: Ctx = { cwd: '/work/app', home: '/home/dev' };
const GOLDEN = path.join(FIXTURES, 'golden');
const policy = parsePolicy(referencePolicyText()).policy;

function golden(name: string, actual: string) {
  const file = path.join(GOLDEN, name);
  if (process.env.UPDATE_GOLDEN || !existsSync(file)) {
    mkdirSync(GOLDEN, { recursive: true });
    writeFileSync(file, actual);
  }
  expect(actual).toBe(readFileSync(file, 'utf8'));
}

function render(fp: FilePlan): string {
  if (fp.kind === 'json-lists') return mergeJsonLists(null, fp.lists, {}).text;
  if (fp.kind === 'owned') return fp.content ?? '';
  return (fp.block ?? '') + '\n';
}

const pol = (yaml: string): Policy => parsePolicy(`version: 1\n${yaml}`).policy;

describe('golden files for the reference policy', () => {
  it('Claude Code: .claude/settings.json', () => {
    const out = claude.generate(policy, 'project', ctx);
    expect(out.files[0]!.file).toBe('/work/app/.claude/settings.json');
    const text = render(out.files[0]!);
    golden('claude.settings.json', text);
    const json = JSON.parse(text);
    expect(json.permissions.allow).toContain('Bash(git status)');
    expect(json.permissions.ask).toEqual(['Bash(git push *)']);
    expect(json.permissions.deny).toEqual(expect.arrayContaining(['Bash(curl *)', 'Bash(sh)', 'Read(.env)', 'Edit(.git/**)', 'mcp__*__delete_*']));
  });

  it('Codex CLI: rules file + permission profile block', () => {
    const out = codex.generate(policy, 'user', ctx);
    expect(out.files.map((f) => f.file)).toEqual(['/home/dev/.codex/rules/agentperms.rules', '/home/dev/.codex/config.toml']);
    const rules = render(out.files[0]!);
    golden('codex.agentperms.rules', rules);
    const block = render(out.files[1]!);
    golden('codex.config.toml', block);
    expect(() => parseToml(block)).not.toThrow();
    // parse our own output back
    const parsed = parseCodexRules(rules);
    expect(parsed).toContainEqual({ patterns: [['git', 'push']], decision: 'prompt' });
    expect(parsed).toContainEqual({ patterns: [['rm', '-rf']], decision: 'forbidden' });
    expect(parsed).toContainEqual({ patterns: [['npm', 'run', 'test']], decision: 'allow' });
    // exact "git status" must NOT become a prefix allow
    expect(parsed.some((r) => r.decision === 'allow' && r.patterns[0]!.join(' ') === 'git status')).toBe(false);
  });

  it('Gemini CLI: policy TOML', () => {
    const out = gemini.generate(policy, 'user', ctx);
    const text = render(out.files[0]!);
    golden('gemini.agentperms.toml', text);
    const doc = parseToml(text) as { rule: Record<string, unknown>[] };
    expect(doc.rule.length).toBeGreaterThan(8);
    for (const r of doc.rule) {
      expect(['allow', 'deny', 'ask_user']).toContain(r.decision);
      for (const k of ['commandRegex', 'argsPattern']) if (typeof r[k] === 'string') expect(() => new RegExp(r[k] as string)).not.toThrow();
    }
  });

  it('Cursor CLI: .cursor/cli.json', () => {
    const out = cursor.generate(policy, 'project', ctx);
    expect(out.files[0]!.file).toBe('/work/app/.cursor/cli.json');
    const text = render(out.files[0]!);
    golden('cursor.cli.json', text);
    const json = JSON.parse(text);
    expect(json.permissions.allow).toEqual(
      expect.arrayContaining(['Shell(git:status)', 'Shell(git:diff)', 'Shell(git:diff *)', 'Shell(ls)', 'WebFetch(*.npmjs.com)', 'Mcp(github:*)']),
    );
    expect(json.permissions.deny).toEqual(expect.arrayContaining(['Shell(rm:-rf)', 'Read(.env)', 'Read(**/.env)', 'Write(.git/**)', 'Mcp(*:delete_*)']));
  });
});

/** Emulates how Gemini CLI evaluates commandPrefix / commandRegex against JSON args. */
function geminiMatches(fields: Record<string, unknown>, command: string): boolean {
  const json = JSON.stringify({ command, description: 'x' });
  if (typeof fields.commandPrefix === 'string') {
    const enc = JSON.stringify(fields.commandPrefix).slice(0, -1);
    const re = new RegExp(`${`"command":${enc}`.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:[\\s"]|\\\\")`);
    return re.test(json);
  }
  if (typeof fields.commandRegex === 'string') return new RegExp(`"command":"${fields.commandRegex}`).test(json);
  return true;
}

describe('conservative mapping', () => {
  it('Gemini: exact rules stay exact, prefixes are word-bounded', () => {
    const exact = geminiShell('git status', 'allow').fields!;
    expect(geminiMatches(exact, 'git status')).toBe(true);
    expect(geminiMatches(exact, 'git status --short')).toBe(false);
    const pre = geminiShell('git diff *', 'allow').fields!;
    expect(geminiMatches(pre, 'git diff')).toBe(true);
    expect(geminiMatches(pre, 'git diff HEAD')).toBe(true);
    expect(geminiMatches(pre, 'git difftool')).toBe(false);
    const inner = geminiShell('git log * main', 'allow').fields!;
    expect(geminiMatches(inner, 'git log --oneline main')).toBe(true);
    expect(geminiMatches(inner, 'git log main; echo "x" main')).toBe(false);
    expect(geminiMatches(inner, 'git log ; rm -rf x ; main')).toBe(false);
    expect(geminiMatches(geminiShell('git log * main', 'deny').fields!, 'git log ; rm -rf x ; main')).toBe(true);
  });

  it('Codex: exact allow and middle wildcards in allow are not mapped; deny is broadened instead', () => {
    expect(codexPrefix('git status', 'allow').tokens).toBeNull();
    expect(codexPrefix('git log * main', 'allow').tokens).toBeNull();
    expect(codexPrefix('git status', 'deny').tokens).toEqual(['git', 'status']);
    expect(codexPrefix('git push * main', 'deny').tokens).toEqual(['git', 'push']);
    expect(codexPrefix('npm run test *', 'allow').tokens).toEqual(['npm', 'run', 'test']);
    const w = codex.generate(pol('shell: { allow: ["git status"], deny: ["*"] }'), 'user', ctx).warnings;
    expect(w.map((x) => x.message).join('\n')).toMatch(/not mapped/);
    expect(w.some((x) => x.level === 'warn' && /NOT enforced/.test(x.message))).toBe(true);
  });

  it('Cursor: "ask" shadowed by an allow becomes deny; otherwise it is left out', () => {
    const out = cursor.generate(pol('shell: { allow: ["git *"], ask: ["git push *", "npm publish *"] }'), 'project', ctx);
    const json = JSON.parse(render(out.files[0]!));
    expect(json.permissions.allow).toContain('Shell(git)');
    expect(json.permissions.deny).toEqual(['Shell(git:push)', 'Shell(git:push *)']);
    const msgs = out.warnings.map((w) => `${w.level} ${w.message}`).join('\n');
    expect(msgs).toMatch(/warn shell\.ask "git push \*".*mapped to deny/);
    expect(msgs).toMatch(/info Cursor has no "ask"; 1 ask rule left out.*npm publish/);
  });

  it('Cursor: a bare exact allow is not widened to any arguments', () => {
    expect(cursorShell('pwd', 'allow').rules).toEqual([]);
    expect(cursorShell('pwd', 'deny').rules).toEqual(['Shell(pwd)']);
    expect(cursorShell('*', 'allow').rules).toEqual(['Shell(*)']);
  });

  it('Claude: wildcard-server MCP allow rules are skipped with a note', () => {
    const out = claude.generate(pol('mcp: { allow: ["*:search", "linear:*"], ask: ["*:create_*"] }'), 'project', ctx);
    const json = JSON.parse(render(out.files[0]!));
    expect(json.permissions.allow).toEqual(['mcp__linear__*']);
    expect(json.permissions.ask).toEqual(['mcp__*__create_*']);
    expect(out.warnings[0]!.message).toMatch(/named server/);
  });

  it('Claude: absolute and home paths use Claude syntax', () => {
    const out = claude.generate(pol('files: { read: { deny: ["/etc/shadow", "~/.ssh/**"] } }'), 'project', ctx);
    const json = JSON.parse(render(out.files[0]!));
    expect(json.permissions.deny).toEqual(['Read(//etc/shadow)', 'Read(~/.ssh/**)']);
  });

  it('Gemini: project scope warns that workspace policies are not loaded; web.allow is not mapped', () => {
    const out = gemini.generate(policy, 'project', ctx);
    expect(out.warnings.some((w) => w.level === 'warn' && /does not load project policies/.test(w.message))).toBe(true);
    expect(out.warnings.some((w) => /web\.allow not mapped.*docs\.github\.com/.test(w.message))).toBe(true);
  });

  it('Codex: file rules go to an inactive profile, with a warning', () => {
    const out = codex.generate(policy, 'user', ctx);
    expect(out.warnings.some((w) => w.level === 'warn' && /inactive until you set default_permissions/.test(w.message))).toBe(true);
    expect(out.warnings.some((w) => w.level === 'warn' && /mcp\.deny: NOT enforced in Codex/.test(w.message))).toBe(true);
  });

  it('no target ever turns a deny into an allow', () => {
    const p = pol('shell: { deny: ["git push *", "rm *", "git * main"] }\nweb: { deny: ["evil.example.com"] }\nmcp: { deny: ["fs:write_file"] }');
    for (const t of [claude, cursor, gemini]) {
      const fp = t.generate(p, 'user', ctx).files[0]!;
      const text = render(fp);
      if (fp.kind === 'json-lists') expect(JSON.parse(text).permissions.allow ?? []).toEqual([]);
      else expect(text).not.toMatch(/decision = "allow"/);
    }
    expect(codex.generate(p, 'user', ctx).files[0]!.kind === 'owned' && (codex.generate(p, 'user', ctx).files[0] as { content: string }).content).not.toMatch(/"allow"/);
  });
});
