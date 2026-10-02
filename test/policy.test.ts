import { describe, expect, it } from 'vitest';
import { parsePolicy, PolicyError } from '../src/policy/load.js';
import { PRESETS, renderPreset } from '../src/policy/presets.js';
import { addShellPatterns } from '../src/policy/write.js';
import { classifyPattern } from '../src/safety.js';
import { referencePolicyText } from './helpers.js';

function issues(text: string) {
  try {
    parsePolicy(text);
  } catch (e) {
    expect(e).toBeInstanceOf(PolicyError);
    return (e as PolicyError).issues;
  }
  throw new Error('expected the policy to be invalid');
}

describe('policy validation', () => {
  it('parses the reference policy', () => {
    const { policy, notes } = parsePolicy(referencePolicyText());
    expect(policy.shell.allow).toEqual(['git status', 'git diff *', 'npm run test *', 'ls *']);
    expect(policy.files.read.deny).toEqual(['.env', '.env.*', 'secrets/**']);
    expect(policy.web.allow).toEqual(['docs.github.com', '*.npmjs.com']);
    expect(policy.mcp).toEqual({ allow: ['github:*'], ask: [], deny: ['*:delete_*'] });
    expect(policy.targets).toEqual(['claude', 'codex', 'gemini', 'cursor']);
    // compound deny patterns are split into their sub-commands (stricter) with a note
    expect(policy.shell.deny).toEqual(['rm -rf *', 'curl *', 'sh']);
    expect(notes.join('\n')).toMatch(/"curl \* \| sh" contains shell operators/);
  });

  it('defaults everything that is omitted', () => {
    const { policy } = parsePolicy('version: 1\n');
    expect(policy.shell).toEqual({ allow: [], ask: [], deny: [] });
    expect(policy.targets).toEqual(['claude', 'codex', 'gemini', 'cursor']);
  });

  it('normalizes the legacy :* suffix and whitespace', () => {
    const { policy } = parsePolicy('version: 1\nshell:\n  allow: ["git  log:*", "  npm test  "]\n');
    expect(policy.shell.allow).toEqual(['git log *', 'npm test']);
  });

  it('reports unknown keys with a suggestion and a line number', () => {
    const is = issues('version: 1\nshel:\n  allow: []\n');
    expect(is[0]).toMatchObject({ path: 'shel', line: 2 });
    expect(is[0]!.message).toMatch(/did you mean "shell"/);
  });

  it('reports a wrong decision key', () => {
    const is = issues('version: 1\nshell:\n  alow: ["ls"]\n');
    expect(is[0]!.message).toMatch(/did you mean "allow"/);
    expect(is[0]!.line).toBe(3);
  });

  it('requires version 1', () => {
    expect(issues('shell: {}\n')[0]!.message).toMatch(/missing "version: 1"/);
    expect(issues('version: 2\n')[0]!.message).toMatch(/unsupported version 2/);
  });

  it('rejects shell operators in allow rules', () => {
    const is = issues('version: 1\nshell:\n  allow:\n    - "ls && rm -rf /"\n');
    expect(is[0]).toMatchObject({ path: 'shell.allow[0]', line: 4 });
    expect(is[0]!.message).toMatch(/cannot contain shell operators/);
  });

  it('rejects non-string items, bad domains, bad mcp patterns and unknown targets', () => {
    const is = issues(
      [
        'version: 1',
        'shell: { allow: [42] }',
        'web: { allow: ["https://ok.example.com/path", "exa mple.com", "foo.*.com"] }',
        'mcp: { deny: ["a:b:c"] }',
        'targets: [claude, vscode]',
      ].join('\n'),
    );
    const msgs = is.map((i) => `${i.path} ${i.message}`).join('\n');
    expect(msgs).toMatch(/shell\.allow\[0\] expected a non-empty string/);
    expect(msgs).toMatch(/web\.allow\[1\] "exa mple\.com" is not a domain pattern/);
    expect(msgs).toMatch(/web\.allow\[2\].*only a leading/);
    expect(msgs).toMatch(/mcp\.deny\[0\]/);
    expect(msgs).toMatch(/targets\[1\] unknown target "vscode"/);
    expect(msgs).not.toMatch(/web\.allow\[0\]/); // URLs are reduced to their host
  });

  it('rejects contradictory rules', () => {
    const is = issues('version: 1\nshell:\n  allow: ["ls *"]\n  deny: ["ls *"]\n');
    expect(is[0]!.message).toMatch(/both allow and deny/);
  });

  it('reports YAML syntax errors with a position', () => {
    const is = issues('version: 1\nshell:\n  allow: [unclosed\n');
    expect(is[0]!.line).toBeGreaterThan(0);
  });
});

describe('presets', () => {
  for (const p of PRESETS) {
    it(`${p} is a valid policy whose allow list is entirely "safe"`, () => {
      const { policy } = parsePolicy(renderPreset(p));
      expect(policy.shell.allow.length).toBeGreaterThan(10);
      for (const a of policy.shell.allow) expect([a, classifyPattern(a).cls]).toEqual([a, 'safe']);
      for (const d of policy.shell.deny) expect([d, classifyPattern(d).cls]).toEqual([d, 'never']);
      expect(policy.files.read.deny).toContain('.env');
      expect(policy.files.write.deny).toContain('.git/**');
    });
  }
});

describe('addShellPatterns (suggest --write)', () => {
  it('appends to an existing list, keeping comments and quoting', () => {
    const src = renderPreset('node');
    const { text, added } = addShellPatterns(src, 'allow', ['git status *', 'jq *', 'du *']);
    expect(added).toEqual(['jq *', 'du *']);
    expect(text).toContain('# Run without asking.');
    expect(text).toContain('    - "jq *"');
    expect(parsePolicy(text).policy.shell.allow).toContain('du *');
  });

  it('creates the list when it does not exist', () => {
    const { text, added } = addShellPatterns('# my policy\nversion: 1\n', 'allow', ['ls *']);
    expect(added).toEqual(['ls *']);
    expect(text.startsWith('# my policy')).toBe(true);
    expect(parsePolicy(text).policy.shell.allow).toEqual(['ls *']);
  });

  it('turns an empty flow list into a block list', () => {
    const { text } = addShellPatterns('version: 1\nshell:\n  allow: []\n', 'allow', ['ls *']);
    expect(parsePolicy(text).policy.shell.allow).toEqual(['ls *']);
    expect(text).not.toContain('[]');
  });
});
