import path from 'node:path';
import { parse as parseJsonc, type ParseError } from 'jsonc-parser';
import { isAnyDepth, splitMcp } from '../glob.js';
import { normalizeShellPattern, parseShellPattern } from '../shell.js';
import { DECISIONS, type Ctx, type Decision, type MappingWarning, type Policy, type Scope } from '../types.js';
import {
  askShadowedBy,
  dirExists,
  readText,
  warn,
  type AgentSnapshot,
  type Category,
  type NativeRule,
  type SourceFile,
  type Target,
  type TargetOutput,
} from './common.js';

function configFile(scope: Scope, ctx: Ctx): string {
  return scope === 'project' ? path.join(ctx.cwd, '.cursor', 'cli.json') : path.join(ctx.home, '.cursor', 'cli-config.json');
}

/**
 * Policy shell pattern -> Cursor `Shell(...)` tokens. Cursor matches `Shell(base)` on the first
 * token (any arguments) and `Shell(base:args)` with a glob over the arguments.
 */
export function cursorShell(pattern: string, d: Decision): { rules: string[]; note?: string } {
  const p = parseShellPattern(pattern);
  const [base, ...rest] = p.tokens;
  if (!base) return { rules: [] };
  if (base.includes('*')) {
    if (p.text === '*') return { rules: ['Shell(*)'] };
    return d === 'allow'
      ? { rules: [], note: `wildcard in the program name cannot be expressed safely; not allowed` }
      : { rules: ['Shell(*)'], note: `wildcard in the program name; denied as Shell(*) (every command)` };
  }
  if (!rest.length) {
    // exact bare command, e.g. "pwd"
    if (d === 'allow')
      return { rules: [], note: `Cursor cannot allow "${base}" without also allowing "${base} <any args>"; not mapped (write "${base} *" if any arguments are fine)` };
    return { rules: [`Shell(${base})`] };
  }
  if (p.trailing && rest.length === 1) return { rules: [`Shell(${base})`] }; // "ls *"
  const args = rest.join(' ');
  if (p.trailing) {
    const fixed = args.slice(0, -2);
    return { rules: [`Shell(${base}:${fixed})`, `Shell(${base}:${fixed} *)`] };
  }
  return { rules: [`Shell(${base}:${args})`] };
}

/** Cursor path globs are workspace-relative; gitignore-style "any depth" patterns get a `** /` twin. */
function cursorPaths(p: string): string[] {
  if (p.startsWith('./')) return [p.slice(2)];
  if (p.startsWith('/') || p.startsWith('~')) return [p];
  if (isAnyDepth(p) && !p.startsWith('**/')) return [p, `**/${p}`];
  return [p];
}

export function cursorRules(policy: Policy, warnings: MappingWarning[]): { allow: string[]; deny: string[] } {
  const out = { allow: [] as string[], deny: [] as string[] };
  const add = (list: 'allow' | 'deny', rules: string[]) => {
    for (const r of rules) if (!out[list].includes(r)) out[list].push(r);
  };
  const W = (level: 'info' | 'warn', m: string) => warnings.push(warn('cursor', level, m));

  // shell
  for (const d of DECISIONS) {
    for (const s of policy.shell[d]) {
      if (d === 'ask') continue;
      const { rules, note } = cursorShell(s, d);
      if (note) W(d === 'allow' && rules.length ? 'warn' : 'info', `shell.${d} "${s}": ${note}`);
      add(d, rules);
    }
  }
  const askToDeny = (cat: 'shell' | 'read' | 'write' | 'web' | 'mcp', rule: string, allows: string[], toNative: () => string[]) => {
    const by = askShadowedBy(cat, rule, allows);
    if (by) {
      W('warn', `${cat === 'read' || cat === 'write' ? `files.${cat}` : cat}.ask "${rule}": Cursor has no "ask"; it is covered by allow "${by}", so it is mapped to deny`);
      add('deny', toNative());
    } else {
      leftOut.push(`${cat === 'read' || cat === 'write' ? `files.${cat}` : cat}.ask "${rule}"`);
    }
  };
  const leftOut: string[] = [];
  for (const s of policy.shell.ask) askToDeny('shell', s, policy.shell.allow, () => cursorShell(s, 'deny').rules);

  // files
  for (const [kind, Tool] of [['read', 'Read'], ['write', 'Write']] as const) {
    const lists = policy.files[kind];
    for (const p of lists.allow) add('allow', cursorPaths(p).map((x) => `${Tool}(${x})`));
    for (const p of lists.deny) add('deny', cursorPaths(p).map((x) => `${Tool}(${x})`));
    for (const p of lists.ask) askToDeny(kind, p, lists.allow, () => cursorPaths(p).map((x) => `${Tool}(${x})`));
    for (const p of [...lists.allow, ...lists.deny, ...lists.ask])
      if (p.startsWith('~')) W('info', `files.${kind} "${p}": Cursor documents absolute paths; "~" expansion is not documented`);
  }

  // web
  for (const p of policy.web.allow) add('allow', [`WebFetch(${p})`]);
  for (const p of policy.web.deny) add('deny', [`WebFetch(${p})`]);
  for (const p of policy.web.ask) askToDeny('web', p, policy.web.allow, () => [`WebFetch(${p})`]);

  // mcp
  const mcpTok = (p: string) => {
    const [s, t] = splitMcp(p);
    return `Mcp(${s}:${t})`;
  };
  for (const p of policy.mcp.allow) add('allow', [mcpTok(p)]);
  for (const p of policy.mcp.deny) add('deny', [mcpTok(p)]);
  for (const p of policy.mcp.ask) askToDeny('mcp', p, policy.mcp.allow, () => [mcpTok(p)]);
  if (leftOut.length)
    W('info', `Cursor has no "ask"; ${leftOut.length} ask rule${leftOut.length === 1 ? '' : 's'} left out so Cursor keeps its default prompt: ${leftOut.join(', ')}`);
  return out;
}

export function normalizeCursorRule(raw: string): { category: Category; pattern: string } {
  const m = /^(Shell|Read|Write|WebFetch|Mcp)\((.*)\)$/s.exec(raw.trim());
  if (!m) return { category: 'tool', pattern: raw };
  const [, tool, spec = ''] = m;
  switch (tool) {
    case 'Shell': {
      if (spec === '*' || spec === '') return { category: 'shell', pattern: '*' };
      const i = spec.indexOf(':');
      if (i === -1) return { category: 'shell', pattern: `${spec} *` };
      const args = spec.slice(i + 1);
      return { category: 'shell', pattern: normalizeShellPattern(args === '*' ? `${spec.slice(0, i)} *` : `${spec.slice(0, i)} ${args}`) };
    }
    case 'Read':
      return { category: 'read', pattern: spec };
    case 'Write':
      return { category: 'write', pattern: spec };
    case 'WebFetch':
      return { category: 'web', pattern: spec };
    default: {
      return { category: 'mcp', pattern: spec.includes(':') ? spec : `${spec}:*` };
    }
  }
}

function readConfig(file: string, scope: Scope, snap: AgentSnapshot) {
  if (snap.files.some((f) => f.path === file)) return;
  const { text, error } = readText(file);
  const src: SourceFile = { path: file, scope, exists: text !== null };
  if (error) src.error = error;
  snap.files.push(src);
  if (text === null) return;
  const errors: ParseError[] = [];
  const json = parseJsonc(text, errors, { allowTrailingComma: true }) as Record<string, unknown> | undefined;
  if (errors.length || !json || typeof json !== 'object') {
    src.error = 'invalid JSON';
    return;
  }
  const perms = json.permissions as Record<string, unknown> | undefined;
  for (const d of ['allow', 'deny'] as const) {
    const list = perms?.[d];
    if (!Array.isArray(list)) continue;
    for (const item of list) {
      if (typeof item !== 'string') continue;
      snap.rules.push({ agent: 'cursor', scope, file, decision: d, native: item, ...normalizeCursorRule(item) } satisfies NativeRule);
    }
  }
  for (const key of ['approvalMode', 'sandbox', 'force', 'yolo']) {
    const v = json[key];
    if (v !== undefined && v !== null && typeof v !== 'object') snap.settings.push({ agent: 'cursor', scope, file, key, value: String(v) });
  }
}

export const cursor: Target = {
  id: 'cursor',
  name: 'Cursor CLI',
  files: (scope, ctx) => [configFile(scope, ctx)],
  generate(policy, scope, ctx): TargetOutput {
    const warnings: MappingWarning[] = [];
    const rules = cursorRules(policy, warnings);
    return {
      target: 'cursor',
      scope,
      warnings,
      files: [
        {
          kind: 'json-lists',
          file: configFile(scope, ctx),
          lists: [
            { key: 'permissions.allow', path: ['permissions', 'allow'], entries: rules.allow },
            { key: 'permissions.deny', path: ['permissions', 'deny'], entries: rules.deny },
          ],
        },
      ],
    };
  },
  read(ctx, scopes): AgentSnapshot {
    const snap: AgentSnapshot = { agent: 'cursor', detected: false, files: [], rules: [], settings: [] };
    if (scopes.includes('user')) readConfig(path.join(ctx.home, '.cursor', 'cli-config.json'), 'user', snap);
    if (scopes.includes('project')) readConfig(path.join(ctx.cwd, '.cursor', 'cli.json'), 'project', snap);
    snap.detected =
      snap.files.some((f) => f.exists) ||
      (scopes.includes('user') && dirExists(path.join(ctx.home, '.cursor'))) ||
      (scopes.includes('project') && dirExists(path.join(ctx.cwd, '.cursor')));
    return snap;
  },
};
