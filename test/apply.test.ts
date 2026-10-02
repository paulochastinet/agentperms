import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { parse as parseJsonc, type ParseError } from 'jsonc-parser';
import { parse as parseToml } from 'smol-toml';
import { afterEach, describe, expect, it } from 'vitest';
import { executePlan, mergeJsonLists, planApply, planDiffs, replaceTomlBlock } from '../src/apply.js';
import { parsePolicy } from '../src/policy/load.js';
import { BLOCK_BEGIN, BLOCK_END } from '../src/targets/common.js';
import type { Policy, TargetId } from '../src/types.js';
import { referencePolicyText, sandbox } from './helpers.js';

const pol = (yaml: string): Policy => parsePolicy(`version: 1\n${yaml}`).policy;
const ref = () => parsePolicy(referencePolicyText()).policy;
const ALL: TargetId[] = ['claude', 'codex', 'gemini', 'cursor'];

let sb: ReturnType<typeof sandbox>;
afterEach(() => sb?.cleanup());

describe('mergeJsonLists', () => {
  const lists = (allow: string[], deny: string[] = []) => [
    { key: 'permissions.allow', path: ['permissions', 'allow'], entries: allow },
    { key: 'permissions.deny', path: ['permissions', 'deny'], entries: deny },
  ];

  it('preserves comments, foreign keys, user entries and indentation', () => {
    const src = `{
    // my settings
    "model": "opus", /* inline */
    "permissions": {
        "allow": [
            "Bash(make *)" // hand-written
        ],
        "defaultMode": "default"
    },
    "hooks": {}
}
`;
    const r = mergeJsonLists(src, lists(['Bash(ls *)', 'Bash(make *)'], ['Read(.env)']), {});
    expect(r.added).toEqual(['Bash(ls *)', 'Read(.env)']);
    expect(r.text).toContain('// my settings');
    expect(r.text).toContain('/* inline */');
    expect(r.text).toContain('// hand-written');
    expect(r.text).toContain('"hooks": {}');
    expect(r.text).toMatch(/\n {12}"Bash\(ls \*\)"/); // 4-space indentation kept
    const json = parseJsonc(r.text);
    expect(json.permissions.allow).toEqual(['Bash(make *)', 'Bash(ls *)']);
    expect(json.permissions.deny).toEqual(['Read(.env)']);
    expect(json.permissions.defaultMode).toBe('default');
    // "Bash(make *)" was already there: not claimed as managed
    expect(r.managed).toEqual({ 'permissions.allow': ['Bash(ls *)'], 'permissions.deny': ['Read(.env)'] });
  });

  it('removes only entries it added before, never hand-written ones', () => {
    const src = '{"permissions":{"allow":["Bash(make *)","Bash(ls *)","Bash(old *)"]}}';
    const r = mergeJsonLists(src, lists(['Bash(ls *)']), { 'permissions.allow': ['Bash(ls *)', 'Bash(old *)'], 'permissions.deny': [] });
    expect(r.removed).toEqual(['Bash(old *)']);
    expect(JSON.parse(r.text).permissions.allow).toEqual(['Bash(make *)', 'Bash(ls *)']);
  });

  it('is idempotent', () => {
    const first = mergeJsonLists('{"a":1}\n', lists(['Bash(ls *)'], ['Read(.env)']), {});
    const second = mergeJsonLists(first.text, lists(['Bash(ls *)'], ['Read(.env)']), first.managed);
    expect(second.text).toBe(first.text);
    expect(second.added).toEqual([]);
    expect(second.managed).toEqual(first.managed);
  });

  it('refuses invalid JSON and non-array targets', () => {
    expect(() => mergeJsonLists('{"permissions": ', lists(['x']), {})).toThrow(/invalid JSON/);
    expect(() => mergeJsonLists('{"permissions": {"allow": "x"}}', lists(['x']), {})).toThrow(/not an array/);
    expect(() => mergeJsonLists('[]', lists(['x']), {})).toThrow(/JSON object/);
  });
});

describe('replaceTomlBlock', () => {
  const block = `${BLOCK_BEGIN}\n[permissions.agentperms]\nextends = ":workspace"\n${BLOCK_END}`;
  it('appends, replaces and removes the managed block without touching the rest', () => {
    const src = '# keep me\nmodel = "gpt-5"\n\n[mcp_servers.x]\ncommand = "x" # inline\n';
    const added = replaceTomlBlock(src, block)!;
    expect(added.startsWith(src.trimEnd())).toBe(true);
    expect(parseToml(added)).toMatchObject({ model: 'gpt-5', permissions: { agentperms: { extends: ':workspace' } } });
    const replaced = replaceTomlBlock(added, block.replace(':workspace', ':read-only'))!;
    expect(replaced).toContain('":read-only"');
    expect(replaced.match(/agentperms managed block:/g)).toHaveLength(1);
    expect(replaceTomlBlock(replaced, null)).toBe(src);
  });
});

describe('planApply / executePlan', () => {
  it('writes every target, then a second run is a no-op (idempotent)', () => {
    sb = sandbox();
    const p = ref();
    const plan = planApply(p, { scope: 'project', targets: ALL, ctx: sb.ctx });
    expect(plan.errors).toEqual([]);
    expect(plan.changes.map((c) => c.display).sort()).toEqual([
      '.claude/settings.json',
      '.codex/config.toml',
      '.codex/rules/agentperms.rules',
      '.cursor/cli.json',
      '.gemini/policies/agentperms.toml',
    ]);
    const res = executePlan(plan);
    expect(res.backupDir).toBeNull(); // nothing existed before
    expect(existsSync(path.join(sb.proj, '.agentperms-backup', 'state.json'))).toBe(true);

    const again = planApply(p, { scope: 'project', targets: ALL, ctx: sb.ctx });
    expect(again.changes).toEqual([]);
    expect(again.stateChanged).toBe(false);
    expect(again.unchanged).toHaveLength(5);
  });

  it('merges into existing configs, preserving foreign keys, and backs up the originals', () => {
    sb = sandbox({ project: true });
    const before = sb.read('.claude/settings.json');
    sb.write('.codex/config.toml', '# project codex config\nmodel = "o4"\n');
    const plan = planApply(ref(), { scope: 'project', targets: ['claude', 'codex'], ctx: sb.ctx });
    const diff = planDiffs(plan);
    expect(diff).toContain('--- a/.claude/settings.json');
    expect(diff).toContain('+      "Bash(git status)",');
    const res = executePlan(plan, new Date('2026-10-02T12:00:00Z'));
    const settings = JSON.parse(sb.read('.claude/settings.json'));
    expect(settings.$schema).toBeDefined();
    expect(settings.env).toEqual({ FOO: 'bar' });
    expect(settings.permissions.allow).toEqual(expect.arrayContaining(['Bash(npm test *)', 'Bash(git status)']));
    expect(settings.permissions.ask).toEqual(['Bash(git push *)']); // already present, not duplicated
    expect(sb.read('.codex/config.toml')).toMatch(/^# project codex config\nmodel = "o4"\n/);
    expect(res.backupDir).toBe(path.join(sb.proj, '.agentperms-backup', '2026-10-02T12-00-00-000Z'));
    expect(readFileSync(path.join(res.backupDir!, '.claude', 'settings.json'), 'utf8')).toBe(before);
    expect(existsSync(path.join(res.backupDir!, '.codex', 'config.toml'))).toBe(true);
  });

  it('removes rules that were dropped from the policy, keeps hand-written ones', () => {
    sb = sandbox();
    sb.write('.claude/settings.json', '{"permissions":{"allow":["Bash(make *)"]}}\n');
    executePlan(planApply(pol('shell: { allow: ["ls *", "pwd"] }'), { scope: 'project', targets: ['claude'], ctx: sb.ctx }));
    expect(JSON.parse(sb.read('.claude/settings.json')).permissions.allow).toEqual(['Bash(make *)', 'Bash(ls *)', 'Bash(pwd)']);
    const plan = planApply(pol('shell: { allow: ["ls *"] }'), { scope: 'project', targets: ['claude'], ctx: sb.ctx });
    expect(plan.changes[0]!.removed).toEqual(['Bash(pwd)']);
    executePlan(plan);
    expect(JSON.parse(sb.read('.claude/settings.json')).permissions.allow).toEqual(['Bash(make *)', 'Bash(ls *)']);
  });

  it('removes owned files when the policy no longer needs them', () => {
    sb = sandbox();
    executePlan(planApply(pol('shell: { allow: ["ls *"] }'), { scope: 'project', targets: ['codex'], ctx: sb.ctx }));
    expect(existsSync(path.join(sb.proj, '.codex/rules/agentperms.rules'))).toBe(true);
    const plan = planApply(pol('web: { allow: ["example.com"] }'), { scope: 'project', targets: ['codex'], ctx: sb.ctx });
    expect(plan.changes.map((c) => [c.display, c.after])).toEqual([['.codex/rules/agentperms.rules', null]]);
    executePlan(plan);
    expect(existsSync(path.join(sb.proj, '.codex/rules/agentperms.rules'))).toBe(false);
  });

  it('refuses to overwrite a file it does not own, unless --force', () => {
    sb = sandbox();
    sb.write('.codex/rules/agentperms.rules', 'prefix_rule(pattern = ["ls"])\n');
    const plan = planApply(pol('shell: { allow: ["ls *"] }'), { scope: 'project', targets: ['codex'], ctx: sb.ctx });
    expect(plan.errors[0]!.message).toMatch(/not created by agentperms/);
    expect(plan.changes).toEqual([]);
    const forced = planApply(pol('shell: { allow: ["ls *"] }'), { scope: 'project', targets: ['codex'], ctx: sb.ctx, force: true });
    expect(forced.errors).toEqual([]);
    expect(forced.changes).toHaveLength(1);
  });

  it('does not touch invalid JSON or TOML', () => {
    sb = sandbox();
    sb.write('.cursor/cli.json', '{ "permissions": ');
    sb.write('.codex/config.toml', 'model = \n');
    const plan = planApply(ref(), { scope: 'project', targets: ['cursor', 'codex'], ctx: sb.ctx });
    expect(plan.errors.map((e) => e.file).sort()).toEqual(['.codex/config.toml', '.cursor/cli.json']);
    executePlan(plan);
    expect(sb.read('.cursor/cli.json')).toBe('{ "permissions": ');
  });

  it('user scope writes under --home and keeps its state there', () => {
    sb = sandbox();
    const plan = planApply(ref(), { scope: 'user', targets: ['claude', 'gemini'], ctx: sb.ctx });
    executePlan(plan);
    expect(existsSync(path.join(sb.home, '.claude', 'settings.json'))).toBe(true);
    expect(existsSync(path.join(sb.home, '.gemini', 'policies', 'agentperms.toml'))).toBe(true);
    expect(existsSync(path.join(sb.home, '.agentperms-backup', 'state.json'))).toBe(true);
    expect(readdirSync(sb.proj)).toEqual([]);
  });

  it('dry-run planning never writes', () => {
    sb = sandbox({ project: true });
    const m = statSync(path.join(sb.proj, '.claude/settings.json')).mtimeMs;
    const plan = planApply(ref(), { scope: 'project', targets: ALL, ctx: sb.ctx });
    expect(plan.changes.length).toBeGreaterThan(0);
    expect(statSync(path.join(sb.proj, '.claude/settings.json')).mtimeMs).toBe(m);
    expect(existsSync(path.join(sb.proj, '.agentperms-backup'))).toBe(false);
    void writeFileSync;
  });
});

describe('removeArrayItem', () => {
  const cases: [string, string[]][] = [
    ['{"a":["x","y","z"]}', ['x', 'y']],
    ['{"a":["x"]}', []],
    ['{\n  "a": [\n    "x", // keep?\n    "y",\n    "z", // trailing comma\n  ]\n}', ['x', 'y']],
    ['{\n  "a": [\n    "x",\n    /* c */ "z"\n  ]\n}', ['x']],
  ];
  for (const [src, expected] of cases) {
    it(`removes "z" from ${JSON.stringify(src)}`, () => {
      const r = mergeJsonLists(src, [{ key: 'a', path: ['a'], entries: expected }], { a: ['x', 'y', 'z'].filter((v) => !expected.includes(v)).concat(expected) });
      const errors: ParseError[] = [];
      const parsed = parseJsonc(r.text, errors, { allowTrailingComma: false });
      expect(errors).toEqual([]);
      expect(parsed.a).toEqual(expected);
      if (!src.includes(',\n  ]')) expect(() => JSON.parse(r.text.replace(/\/\/.*$/gm, '').replace(/\/\*.*?\*\//g, ''))).not.toThrow();
    });
  }

  it('appends to a minified file without breaking it', () => {
    const r = mergeJsonLists('{"permissions":{"allow":["a"]},"x":1}', [{ key: 'k', path: ['permissions', 'allow'], entries: ['a', 'b'] }], {});
    expect(JSON.parse(r.text)).toEqual({ permissions: { allow: ['a', 'b'] }, x: 1 });
  });
});
