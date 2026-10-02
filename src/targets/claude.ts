import path from 'node:path';
import { parse as parseJsonc, type ParseError } from 'jsonc-parser';
import { splitMcp } from '../glob.js';
import { normalizeShellPattern } from '../shell.js';
import { DECISIONS, type Ctx, type Decision, type MappingWarning, type Policy, type Scope } from '../types.js';
import {
  dirExists,
  readText,
  warn,
  type AgentSnapshot,
  type Category,
  type NativeRule,
  type NativeSetting,
  type SourceFile,
  type Target,
  type TargetOutput,
} from './common.js';

/** Policy path -> Claude Code path specifier (`/abs` must be written `//abs`). */
export function claudePath(p: string): string {
  if (p.startsWith('/')) return '/' + p;
  return p;
}

function mcpRule(pattern: string): string {
  const [server, tool] = splitMcp(pattern);
  return tool === '*' ? `mcp__${server}__*` : `mcp__${server}__${tool}`;
}

export function claudeRules(policy: Policy, warnings: MappingWarning[]): Record<Decision, string[]> {
  const out: Record<Decision, string[]> = { allow: [], ask: [], deny: [] };
  for (const d of DECISIONS) {
    for (const p of policy.shell[d]) out[d].push(`Bash(${p})`);
    for (const p of policy.files.read[d]) out[d].push(`Read(${claudePath(p)})`);
    for (const p of policy.files.write[d]) out[d].push(`Edit(${claudePath(p)})`);
    for (const p of policy.web[d]) out[d].push(p === '*' ? 'WebFetch' : `WebFetch(domain:${p})`);
    for (const p of policy.mcp[d]) {
      const [server] = splitMcp(p);
      if (d === 'allow' && server.includes('*')) {
        warnings.push(
          warn('claude', 'info', `mcp.allow "${p}": Claude Code only accepts allow rules for a named server (mcp__<server>__...); not mapped, those tools keep prompting`),
        );
        continue;
      }
      out[d].push(mcpRule(p));
    }
  }
  return out;
}

function settingsFile(scope: Scope, ctx: Ctx): string {
  return scope === 'project' ? path.join(ctx.cwd, '.claude', 'settings.json') : path.join(ctx.home, '.claude', 'settings.json');
}

/** Native Claude rule -> normalized rule. */
export function normalizeClaudeRule(raw: string): { category: Category; pattern: string } {
  const r = raw.trim();
  const m = /^([A-Za-z_][\w*-]*)(?:\((.*)\))?$/s.exec(r);
  if (!m) return { category: 'tool', pattern: r };
  const tool = m[1]!;
  const spec = m[2];
  if (tool === 'Bash') {
    if (spec === undefined || spec.trim() === '' || spec.trim() === '*' || spec.trim() === ':*') return { category: 'shell', pattern: '*' };
    return { category: 'shell', pattern: normalizeShellPattern(spec) };
  }
  if (tool === 'Read' || tool === 'Edit' || tool === 'Write' || tool === 'MultiEdit' || tool === 'NotebookEdit') {
    const cat: Category = tool === 'Read' ? 'read' : 'write';
    if (spec === undefined || spec === '' || spec === '*' || spec === '**') return { category: cat, pattern: '**' };
    return { category: cat, pattern: spec.startsWith('//') ? spec.slice(1) : spec };
  }
  if (tool === 'WebFetch') {
    if (spec === undefined) return { category: 'web', pattern: '*' };
    return { category: 'web', pattern: spec.replace(/^domain:/, '') };
  }
  if (tool.startsWith('mcp__') || tool === 'mcp') {
    const parts = tool.split('__');
    const server = parts[1] ?? '*';
    const name = parts.slice(2).join('__') || '*';
    return { category: 'mcp', pattern: `${server || '*'}:${name}` };
  }
  return { category: 'tool', pattern: r };
}

function readSettings(file: string, scope: Scope, snap: AgentSnapshot) {
  if (snap.files.some((f) => f.path === file)) return; // cwd == home
  const { text, error } = readText(file);
  const src: SourceFile = { path: file, scope, exists: text !== null };
  snap.files.push(src);
  if (error) src.error = error;
  if (text === null) return;
  const errors: ParseError[] = [];
  const json = parseJsonc(text, errors, { allowTrailingComma: true });
  if (errors.length || !json || typeof json !== 'object') {
    src.error = 'invalid JSON';
    return;
  }
  const perms = (json as Record<string, unknown>).permissions as Record<string, unknown> | undefined;
  for (const d of DECISIONS) {
    const list = perms?.[d];
    if (!Array.isArray(list)) continue;
    for (const item of list) {
      if (typeof item !== 'string') continue;
      const n = normalizeClaudeRule(item);
      snap.rules.push({ agent: 'claude', scope, file, decision: d, native: item, ...n } satisfies NativeRule);
    }
  }
  const set = (key: string, value: unknown) => {
    if (value === undefined || value === null) return;
    snap.settings.push({ agent: 'claude', scope, file, key, value: String(value) } satisfies NativeSetting);
  };
  const j = json as Record<string, unknown>;
  set('defaultMode', perms?.defaultMode ?? j.defaultMode);
  set('skipDangerousModePermissionPrompt', j.skipDangerousModePermissionPrompt);
  set('enableAllProjectMcpServers', j.enableAllProjectMcpServers);
  set('disableBypassPermissionsMode', perms?.disableBypassPermissionsMode);
  if (Array.isArray(perms?.additionalDirectories)) set('additionalDirectories', (perms.additionalDirectories as unknown[]).join(', '));
  const sandbox = j.sandbox as Record<string, unknown> | undefined;
  if (sandbox && typeof sandbox === 'object') set('sandbox.enabled', sandbox.enabled);
}

export const claude: Target = {
  id: 'claude',
  name: 'Claude Code',
  files: (scope, ctx) => [settingsFile(scope, ctx)],
  generate(policy, scope, ctx): TargetOutput {
    const warnings: MappingWarning[] = [];
    const rules = claudeRules(policy, warnings);
    return {
      target: 'claude',
      scope,
      warnings,
      files: [
        {
          kind: 'json-lists',
          file: settingsFile(scope, ctx),
          lists: DECISIONS.map((d) => ({ key: `permissions.${d}`, path: ['permissions', d], entries: rules[d] })),
        },
      ],
    };
  },
  read(ctx, scopes): AgentSnapshot {
    const snap: AgentSnapshot = { agent: 'claude', detected: false, files: [], rules: [], settings: [] };
    if (scopes.includes('user')) {
      readSettings(path.join(ctx.home, '.claude', 'settings.json'), 'user', snap);
      readSettings(path.join(ctx.home, '.claude', 'settings.local.json'), 'user', snap);
    }
    if (scopes.includes('project')) {
      readSettings(path.join(ctx.cwd, '.claude', 'settings.json'), 'project', snap);
      readSettings(path.join(ctx.cwd, '.claude', 'settings.local.json'), 'project', snap);
    }
    snap.detected =
      snap.files.some((f) => f.exists) ||
      (scopes.includes('user') && dirExists(path.join(ctx.home, '.claude'))) ||
      (scopes.includes('project') && dirExists(path.join(ctx.cwd, '.claude')));
    return snap;
  },
};
