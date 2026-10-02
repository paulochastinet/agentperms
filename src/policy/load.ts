import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { LineCounter, isMap, parseDocument, type Node as YamlNode } from 'yaml';
import { hasOperator, normalizeShellPattern, parseShellPattern, splitPatternOnOperators } from '../shell.js';
import { DECISIONS, TARGET_IDS, type Decision, type Policy, type RuleLists, type TargetId } from '../types.js';

export const POLICY_FILENAMES = ['agentperms.yaml', 'agentperms.yml'];

export interface PolicyIssue {
  /** Dotted path in the document, e.g. `shell.allow[2]`. */
  path: string;
  message: string;
  line?: number;
  col?: number;
}

export class PolicyError extends Error {
  constructor(
    public file: string,
    public issues: PolicyIssue[],
  ) {
    issues.sort((a, b) => (a.line ?? 0) - (b.line ?? 0) || (a.col ?? 0) - (b.col ?? 0));
    super(
      `${file}: invalid policy\n` +
        issues.map((i) => `  ${i.line ? `${i.line}:${i.col ?? 1} ` : ''}${i.path ? `${i.path}: ` : ''}${i.message}`).join('\n'),
    );
  }
}

export interface LoadedPolicy {
  file: string;
  policy: Policy;
  /** Non-fatal notes (e.g. compound deny patterns that were split). */
  notes: string[];
}

export function findPolicyFile(cwd: string, explicit?: string): string | null {
  if (explicit) return path.resolve(cwd, explicit);
  for (const f of POLICY_FILENAMES) {
    const p = path.join(cwd, f);
    if (existsSync(p)) return p;
  }
  return null;
}

const TOP_KEYS = ['version', 'shell', 'files', 'web', 'mcp', 'targets'];
const TARGET_ALIASES: Record<string, TargetId> = {
  claude: 'claude',
  'claude-code': 'claude',
  codex: 'codex',
  'codex-cli': 'codex',
  gemini: 'gemini',
  'gemini-cli': 'gemini',
  cursor: 'cursor',
  'cursor-cli': 'cursor',
};

export function parseTargetName(name: string): TargetId | undefined {
  return TARGET_ALIASES[name.trim().toLowerCase()];
}

function closest(word: string, options: string[]): string | undefined {
  let best: string | undefined;
  let bestD = 3;
  for (const o of options) {
    const d = lev(word, o);
    if (d < bestD) {
      bestD = d;
      best = o;
    }
  }
  return best;
}

function lev(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array<number>(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0]![j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i]![j] = Math.min(dp[i - 1]![j]! + 1, dp[i]![j - 1]! + 1, dp[i - 1]![j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
  return dp[a.length]![b.length]!;
}

function emptyLists(): RuleLists {
  return { allow: [], ask: [], deny: [] };
}

/** Parse + validate policy text. Throws PolicyError with line numbers. */
export function parsePolicy(text: string, file = 'agentperms.yaml'): LoadedPolicy {
  const lc = new LineCounter();
  const doc = parseDocument(text, { lineCounter: lc, prettyErrors: false, uniqueKeys: true });
  const issues: PolicyIssue[] = [];
  const notes: string[] = [];

  for (const e of doc.errors) {
    const pos = e.linePos?.[0] ?? lc.linePos(e.pos[0]);
    issues.push({ path: '', message: e.message.split('\n')[0]!, line: pos?.line, col: pos?.col });
  }
  if (issues.length) throw new PolicyError(file, issues);

  const at = (p: (string | number)[]): { line?: number; col?: number } => {
    const node = doc.getIn(p, true) as YamlNode | undefined;
    const range = (node as { range?: [number, number, number] } | undefined)?.range;
    if (!range) return {};
    const pos = lc.linePos(range[0]);
    return { line: pos.line, col: pos.col };
  };
  const keyAt = (p: (string | number)[], key: string): { line?: number; col?: number } => {
    const parent = p.length ? doc.getIn(p, true) : doc.contents;
    if (isMap(parent)) {
      const pair = parent.items.find((it) => (it.key as { value?: unknown })?.value === key);
      const range = (pair?.key as { range?: [number, number, number] } | undefined)?.range;
      if (range) {
        const pos = lc.linePos(range[0]);
        return { line: pos.line, col: pos.col };
      }
    }
    return at(p);
  };
  const fmt = (p: (string | number)[]) =>
    p.map((s, i) => (typeof s === 'number' ? `[${s}]` : i === 0 ? s : `.${s}`)).join('');
  const issue = (p: (string | number)[], message: string, keyPos = false) => {
    issues.push({ path: fmt(p), message, ...(keyPos ? keyAt(p.slice(0, -1), String(p[p.length - 1])) : at(p)) });
  };

  const data: unknown = doc.toJS();
  if (data === null || data === undefined) throw new PolicyError(file, [{ path: '', message: 'the policy file is empty' }]);
  if (typeof data !== 'object' || Array.isArray(data)) throw new PolicyError(file, [{ path: '', message: 'expected a mapping at the top level', line: 1, col: 1 }]);
  const root = data as Record<string, unknown>;

  for (const k of Object.keys(root)) {
    if (!TOP_KEYS.includes(k)) {
      const hint = closest(k, TOP_KEYS);
      issue([k], `unknown key "${k}"${hint ? ` (did you mean "${hint}"?)` : ''}. Allowed: ${TOP_KEYS.join(', ')}`, true);
    }
  }
  if (root.version === undefined) issues.push({ path: 'version', message: 'missing "version: 1"', line: 1, col: 1 });
  else if (root.version !== 1) issue(['version'], `unsupported version ${JSON.stringify(root.version)}; this agentperms understands version 1`);

  const readLists = (p: string[], v: unknown, check: (s: string, p: (string | number)[], d: Decision) => string | void): RuleLists => {
    const out = emptyLists();
    if (v === undefined || v === null) return out;
    if (typeof v !== 'object' || Array.isArray(v)) {
      issue(p, `expected a mapping with allow / ask / deny lists, got ${Array.isArray(v) ? 'a list' : typeof v}`);
      return out;
    }
    for (const [k, list] of Object.entries(v as Record<string, unknown>)) {
      if (!(DECISIONS as string[]).includes(k)) {
        const hint = closest(k, DECISIONS);
        issue([...p, k], `unknown key "${k}"${hint ? ` (did you mean "${hint}"?)` : ''}. Allowed: allow, ask, deny`, true);
        continue;
      }
      if (list === null || list === undefined) continue;
      if (!Array.isArray(list)) {
        issue([...p, k], `expected a list of strings`);
        continue;
      }
      const seen = new Set<string>();
      list.forEach((item, i) => {
        if (typeof item !== 'string' || !item.trim()) {
          issue([...p, k, i], `expected a non-empty string, got ${item === null ? 'null' : typeof item}`);
          return;
        }
        const r = check(item, [...p, k, i], k as Decision);
        if (typeof r === 'string' && r) {
          if (!seen.has(r)) out[k as Decision].push(r);
          seen.add(r);
        }
      });
    }
    return out;
  };

  const extra: RuleLists = emptyLists();
  const shell = readLists(['shell'], root.shell, (s, p, d) => {
    const t = normalizeShellPattern(s);
    if (t === '') return void issue(p, 'empty pattern');
    if (hasOperator(t)) {
      if (d === 'allow') {
        issue(p, `allow patterns cannot contain shell operators (&&, ||, ;, |, &, $(...), backticks): agents check each sub-command separately. List each command on its own instead`);
        return;
      }
      const parts = splitPatternOnOperators(t);
      if (!parts.length) return void issue(p, 'pattern has no command once operators are removed');
      notes.push(
        `shell.${d}: "${t}" contains shell operators; agents check each sub-command separately, so it is enforced as ${parts.map((x) => `"${x}"`).join(' + ')} (stricter than written)`,
      );
      // extra parts are appended below
      extra[d].push(...parts.slice(1));
      return parts[0];
    }
    if (/^\s*\*\s*$/.test(t) && d === 'allow') {
      notes.push('shell.allow: "*" allows every shell command without a prompt');
    }
    const parsed = parseShellPattern(t);
    if (!parsed.tokens.length) return void issue(p, 'empty pattern');
    return parsed.text;
  });
  for (const d of DECISIONS) for (const e of extra[d]) if (!shell[d].includes(e)) shell[d].push(e);

  const pathCheck = (s: string, p: (string | number)[]) => {
    const t = s.trim();
    if (/[\r\n]/.test(t)) return void issue(p, 'paths cannot contain newlines');
    if (t.includes('(') || t.includes(')')) return void issue(p, 'paths cannot contain parentheses (they would break native rule syntax)');
    if (/^[A-Za-z]:\\/.test(t)) return void issue(p, 'Windows drive paths are not supported; use forward slashes');
    return t;
  };
  const files = { read: emptyLists(), write: emptyLists() };
  if (root.files !== undefined && root.files !== null) {
    if (typeof root.files !== 'object' || Array.isArray(root.files)) issue(['files'], 'expected a mapping with "read" and/or "write"');
    else {
      for (const [k, v] of Object.entries(root.files as Record<string, unknown>)) {
        if (k !== 'read' && k !== 'write') {
          const hint = closest(k, ['read', 'write']);
          issue(['files', k], `unknown key "${k}"${hint ? ` (did you mean "${hint}"?)` : ''}. Allowed: read, write`, true);
          continue;
        }
        files[k] = readLists(['files', k], v, pathCheck);
      }
    }
  }

  const web = readLists(['web'], root.web, (s, p) => {
    const t = s.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (t.includes('*') && !/^\*\.[^*]+$/.test(t) && t !== '*') return void issue(p, `"${s}": only a leading "*." wildcard is supported`);
    if (t !== '*' && !/^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*\.?$/.test(t))
      return void issue(p, `"${s}" is not a domain pattern (use "example.com", "*.example.com" or "*")`);
    return t;
  });

  const mcp = readLists(['mcp'], root.mcp, (s, p) => {
    const t = s.trim();
    if (!/^[^:\s]+(:[^:\s]+)?$/.test(t)) return void issue(p, `"${s}" is not an MCP pattern (use "server:tool", "server:*" or "*:tool")`);
    return t.includes(':') ? t : `${t}:*`;
  });

  let targets: TargetId[] = [...TARGET_IDS];
  if (root.targets !== undefined) {
    if (!Array.isArray(root.targets)) issue(['targets'], `expected a list, e.g. [${TARGET_IDS.join(', ')}]`);
    else {
      targets = [];
      root.targets.forEach((t, i) => {
        const id = typeof t === 'string' ? parseTargetName(t) : undefined;
        if (!id) issue(['targets', i], `unknown target ${JSON.stringify(t)}. Allowed: ${TARGET_IDS.join(', ')}`);
        else if (!targets.includes(id)) targets.push(id);
      });
      if (!targets.length && !issues.length) issue(['targets'], 'at least one target is required');
    }
  }

  // contradictions: same pattern in two lists
  const contradictions = (p: string, lists: RuleLists) => {
    for (const a of DECISIONS)
      for (const b of DECISIONS) {
        if (a >= b) continue;
        for (const x of lists[a]) if (lists[b].includes(x)) issues.push({ path: p, message: `"${x}" is listed in both ${a} and ${b}` });
      }
  };
  contradictions('shell', shell);
  contradictions('files.read', files.read);
  contradictions('files.write', files.write);
  contradictions('web', web);
  contradictions('mcp', mcp);

  if (issues.length) throw new PolicyError(file, issues);
  return { file, policy: { version: 1, shell, files, web, mcp, targets }, notes };
}

export function loadPolicy(file: string): LoadedPolicy {
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch (e) {
    throw new PolicyError(file, [{ path: '', message: `cannot read file (${(e as NodeJS.ErrnoException).code ?? (e as Error).message})` }]);
  }
  return parsePolicy(text, file);
}

