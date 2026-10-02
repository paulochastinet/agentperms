import { readdirSync } from 'node:fs';
import path from 'node:path';
import { parse as parseJsonc, type ParseError } from 'jsonc-parser';
import { parse as parseToml } from 'smol-toml';
import { globToRegexSource, splitMcp } from '../glob.js';
import { normalizeShellPattern, parseShellPattern } from '../shell.js';
import type { Ctx, Decision, MappingWarning, Policy, Scope } from '../types.js';
import {
  MANAGED_HEADER,
  dirExists,
  escapeRegex,
  readText,
  tomlString,
  warn,
  type AgentSnapshot,
  type NativeRule,
  type SourceFile,
  type Target,
  type TargetOutput,
} from './common.js';

const DECISION: Record<Decision, string> = { allow: 'allow', ask: 'ask_user', deny: 'deny' };
/** Higher wins inside the user tier: deny > ask > allow. */
const PRIORITY: Record<Decision, number> = { deny: 900, ask: 500, allow: 100 };
const READ_TOOLS = ['read_file', 'read_many_files'];
const WRITE_TOOLS = ['write_file', 'replace'];

export function geminiPolicyFile(scope: Scope, ctx: Ctx): string {
  return scope === 'project'
    ? path.join(ctx.cwd, '.gemini', 'policies', 'agentperms.toml')
    : path.join(ctx.home, '.gemini', 'policies', 'agentperms.toml');
}

/** Escape text the way it appears inside the JSON-encoded tool arguments, then regex-escape it. */
function jsonRe(s: string): string {
  return escapeRegex(JSON.stringify(s).slice(1, -1));
}

type Rule = Record<string, string | number | string[]>;

/** Policy shell pattern -> Gemini rule fields (commandPrefix is word-bounded by Gemini). */
export function geminiShell(pattern: string, d: Decision): { fields: Rule | null; note?: string; level?: 'info' | 'warn' } {
  const p = parseShellPattern(pattern);
  if (p.text === '*') return { fields: { toolName: 'run_shell_command' } };
  if (p.trailing) return { fields: { toolName: 'run_shell_command', commandPrefix: p.text.slice(0, -2) } };
  if (p.exact) return { fields: { toolName: 'run_shell_command', commandRegex: `${jsonRe(p.text)}"` } };
  // inner wildcard: allow -> wildcard can't leave the command string; deny/ask -> anything
  // allow: the wildcard may not cross quotes, backslashes or shell operators (no smuggled sub-commands)
  const star = d === 'allow' ? '[^"\\\\&|;`$<>()]*' : '.*';
  const parts = p.text.split('*').map(jsonRe);
  const re = parts.join(star) + (p.text.endsWith('*') ? '' : '"');
  return { fields: { toolName: 'run_shell_command', commandRegex: re } };
}

/** Path glob -> regex matched against a JSON string value in the tool args (absolute paths). */
export function geminiPathRegex(p: string, home: string): string {
  let g = p.startsWith('./') ? p.slice(2) : p;
  if (g.endsWith('/')) g += '**';
  const body = (x: string) => globToRegexSource(x, '[^"/]').replace(/\.\*/g, '[^"]*');
  if (g.startsWith('~/')) return `"${escapeRegex(home)}/${body(g.slice(2))}"`;
  if (g.startsWith('/')) return `"${body(g)}"`;
  if (g.startsWith('**/')) g = g.slice(3);
  // workspace-relative or any-depth: match the path suffix (paths are absolute in tool args)
  return `"(?:[^"]*/)?${body(g)}"`;
}

function domainRegex(d: string): string {
  if (d.startsWith('*.')) return `https?://(?:[^/"\\s]*\\.)?${escapeRegex(d.slice(2))}(?:[/:?#"\\s\\\\]|$)`;
  return `https?://${escapeRegex(d)}(?:[/:?#"\\s\\\\]|$)`;
}

function renderRule(fields: Rule, d: Decision, why: string): string {
  const lines = ['[[rule]]', `# agentperms: ${why.replace(/\n/g, ' ')}`];
  for (const [k, v] of Object.entries(fields)) {
    lines.push(`${k} = ${Array.isArray(v) ? `[${v.map(tomlString).join(', ')}]` : typeof v === 'number' ? v : tomlString(v)}`);
  }
  lines.push(`decision = ${tomlString(DECISION[d])}`, `priority = ${PRIORITY[d]}`);
  if (d === 'deny') lines.push(`denyMessage = ${tomlString(`Blocked by agentperms policy (${why.replace(/\n/g, ' ')})`)}`);
  return lines.join('\n');
}

export function geminiPolicyContent(policy: Policy, ctx: Ctx, warnings: MappingWarning[]): string | null {
  const W = (level: 'info' | 'warn', m: string) => warnings.push(warn('gemini', level, m));
  const rules: string[] = [];
  const webSkipped: string[] = [];
  for (const d of ['deny', 'ask', 'allow'] as Decision[]) {
    for (const s of policy.shell[d]) {
      const r = geminiShell(s, d);
      if (r.note) W(r.level ?? 'info', `shell.${d} "${s}": ${r.note}`);
      if (r.fields) rules.push(renderRule(r.fields, d, `shell.${d} "${s}"`));
    }
    for (const [kind, tools] of [['read', READ_TOOLS], ['write', WRITE_TOOLS]] as const) {
      for (const p of policy.files[kind][d]) {
        if (d === 'allow') {
          W('info', `files.${kind}.allow "${p}": not mapped for Gemini (a path regex over absolute paths could match outside the project)`);
          continue;
        }
        rules.push(renderRule({ toolName: tools, argsPattern: geminiPathRegex(p, ctx.home) }, d, `files.${kind}.${d} "${p}"`));
      }
    }
    for (const p of policy.web[d]) {
      if (d === 'allow') {
        webSkipped.push(p);
        continue;
      }
      rules.push(renderRule(p === '*' ? { toolName: 'web_fetch' } : { toolName: 'web_fetch', argsPattern: domainRegex(p) }, d, `web.${d} "${p}"`));
    }
    for (const p of policy.mcp[d]) {
      const [server, tool] = splitMcp(p);
      if (server.includes('*') && d === 'allow') {
        W('info', `mcp.allow "${p}": allow rules need a named server; not mapped`);
        continue;
      }
      let fields: Rule;
      if (!server.includes('*') && !tool.includes('*')) fields = { mcpName: server, toolName: tool };
      else if (!server.includes('*') && tool === '*') fields = { mcpName: server };
      else fields = { toolName: `mcp_${server}_${tool}` };
      if (server.includes('*') || (tool.includes('*') && tool !== '*'))
        W('info', `mcp.${d} "${p}": mapped to toolName "mcp_${server}_${tool}" (Gemini tool-name wildcards)`);
      rules.push(renderRule(fields, d, `mcp.${d} "${p}"`));
    }
  }
  if (webSkipped.length)
    W('info', `web.allow not mapped for Gemini (web_fetch takes a free-form prompt that can mention several URLs, so a domain allow could approve others); fetches keep prompting: ${webSkipped.join(', ')}`);
  if (!rules.length) return null;
  return (
    [
      `# ${MANAGED_HEADER} (https://github.com/paulochastinet/agentperms).`,
      '# Do not edit: this file is regenerated by `agentperms apply`. Edit agentperms.yaml instead.',
      '# Gemini CLI policy engine: the highest-priority matching rule wins (deny 900 > ask 500 > allow 100).',
      '',
      rules.join('\n\n'),
    ].join('\n') + '\n'
  );
}

// ───────────────────────────── reading (audit) ─────────────────────────────

const D_FROM_GEMINI: Record<string, Decision> = { allow: 'allow', ask_user: 'ask', deny: 'deny' };

function readSettings(file: string, scope: Scope, snap: AgentSnapshot) {
  if (snap.files.some((f) => f.path === file)) return;
  const { text, error } = readText(file);
  const src: SourceFile = { path: file, scope, exists: text !== null };
  if (error) src.error = error;
  snap.files.push(src);
  if (text === null) return;
  const errors: ParseError[] = [];
  const j = parseJsonc(text, errors, { allowTrailingComma: true }) as Record<string, unknown> | undefined;
  if (errors.length || !j || typeof j !== 'object') {
    src.error = 'invalid JSON';
    return;
  }
  const tools = (j.tools as Record<string, unknown> | undefined) ?? {};
  const general = (j.general as Record<string, unknown> | undefined) ?? {};
  const security = (j.security as Record<string, unknown> | undefined) ?? {};
  const pushTool = (item: string, decision: Decision, key: string) => {
    const m = /^(run_shell_command|ShellTool|shell)\((.*)\)$/s.exec(item);
    if (m) {
      snap.rules.push({ agent: 'gemini', scope, file, category: 'shell', decision, pattern: `${normalizeShellPattern(m[2]!)} *`, native: `${key}: ${item}` });
    } else if (item === 'run_shell_command' || item === 'ShellTool') {
      snap.rules.push({ agent: 'gemini', scope, file, category: 'shell', decision, pattern: '*', native: `${key}: ${item}` });
    } else if (['write_file', 'replace', 'WriteFileTool', 'EditTool'].includes(item)) {
      snap.rules.push({ agent: 'gemini', scope, file, category: 'write', decision, pattern: '**', native: `${key}: ${item}` });
    } else if (item === 'web_fetch' || item === 'WebFetchTool') {
      snap.rules.push({ agent: 'gemini', scope, file, category: 'web', decision, pattern: '*', native: `${key}: ${item}` });
    } else {
      snap.rules.push({ agent: 'gemini', scope, file, category: 'tool', decision, pattern: item, native: `${key}: ${item}` });
    }
  };
  for (const [key, decision] of [
    ['tools.allowed', 'allow'],
    ['allowedTools', 'allow'],
    ['tools.exclude', 'deny'],
    ['excludeTools', 'deny'],
  ] as const) {
    const list = key.startsWith('tools.') ? tools[key.slice(6)] : j[key];
    if (Array.isArray(list)) for (const it of list) if (typeof it === 'string') pushTool(it, decision, key);
  }
  const set = (key: string, value: unknown) => {
    if (value === undefined || value === null || typeof value === 'object') return;
    snap.settings.push({ agent: 'gemini', scope, file, key, value: String(value) });
  };
  set('general.defaultApprovalMode', general.defaultApprovalMode);
  set('tools.autoAccept', tools.autoAccept);
  set('autoAccept', j.autoAccept);
  set('security.disableYoloMode', security.disableYoloMode);
  const ft = security.folderTrust as Record<string, unknown> | undefined;
  if (ft) set('security.folderTrust.enabled', ft.enabled);
  if (Array.isArray(tools.core)) set('tools.core', (tools.core as unknown[]).join(', '));
  const servers = j.mcpServers as Record<string, Record<string, unknown>> | undefined;
  for (const [name, conf] of Object.entries(servers ?? {})) {
    if (conf?.trust === true)
      snap.rules.push({ agent: 'gemini', scope, file, category: 'mcp', decision: 'allow', pattern: `${name}:*`, native: `mcpServers.${name}.trust = true` });
    for (const t of Array.isArray(conf?.excludeTools) ? (conf.excludeTools as unknown[]) : [])
      if (typeof t === 'string') snap.rules.push({ agent: 'gemini', scope, file, category: 'mcp', decision: 'deny', pattern: `${name}:${t}`, native: `mcpServers.${name}.excludeTools ${t}` });
  }
}

function readPolicies(dir: string, scope: Scope, snap: AgentSnapshot) {
  let files: string[] = [];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith('.toml')).sort().map((f) => path.join(dir, f));
  } catch {
    return;
  }
  for (const file of files) {
    if (snap.files.some((f) => f.path === file)) continue;
    const { text, error } = readText(file);
    const src: SourceFile = { path: file, scope, exists: text !== null };
    if (error) src.error = error;
    snap.files.push(src);
    if (text === null) continue;
    let doc: Record<string, unknown>;
    try {
      doc = parseToml(text) as Record<string, unknown>;
    } catch {
      src.error = 'invalid TOML';
      continue;
    }
    const rules = Array.isArray(doc.rule) ? (doc.rule as Record<string, unknown>[]) : [];
    for (const r of rules) {
      const decision = D_FROM_GEMINI[String(r.decision)];
      if (!decision) continue;
      const toolNames = Array.isArray(r.toolName) ? (r.toolName as string[]) : typeof r.toolName === 'string' ? [r.toolName] : [];
      const prefixes = Array.isArray(r.commandPrefix) ? (r.commandPrefix as string[]) : typeof r.commandPrefix === 'string' ? [r.commandPrefix] : [];
      const native = `[[rule]] ${Object.entries(r)
        .filter(([k]) => !['priority', 'denyMessage'].includes(k))
        .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
        .join(' ')}`;
      const modes = Array.isArray(r.modes) ? ` (modes: ${(r.modes as string[]).join(', ')})` : '';
      const push = (category: NativeRule['category'], pattern: string, approximate = false) =>
        snap.rules.push({ agent: 'gemini', scope, file, category, decision, pattern, native: native + modes, ...(approximate ? { approximate } : {}) });
      if (prefixes.length) {
        for (const p of prefixes) push('shell', `${normalizeShellPattern(p)} *`);
        continue;
      }
      if (typeof r.commandRegex === 'string') {
        const exact = /^((?:[^\\.*+?^${}()|[\]]|\\[^dDwWsSbB])*)"$/.exec(r.commandRegex);
        if (exact) push('shell', exact[1]!.replace(/\\(.)/g, '$1'));
        else push('shell', `re:${r.commandRegex}`, true);
        continue;
      }
      if (typeof r.mcpName === 'string') {
        push('mcp', `${r.mcpName}:${toolNames[0] ?? '*'}`);
        continue;
      }
      for (const t of toolNames.length ? toolNames : ['*']) {
        const args = typeof r.argsPattern === 'string' ? r.argsPattern : undefined;
        if (t === 'run_shell_command') push('shell', args ? `re:${args}` : '*', !!args);
        else if (READ_TOOLS.includes(t)) push('read', args ? `re:${args}` : '**', !!args);
        else if (WRITE_TOOLS.includes(t)) push('write', args ? `re:${args}` : '**', !!args);
        else if (t === 'web_fetch') push('web', args ? `re:${args}` : '*', !!args);
        else if (t.startsWith('mcp_')) push('mcp', t.slice(4).replace('_', ':'), true);
        else push('tool', t);
      }
    }
  }
}

export const gemini: Target = {
  id: 'gemini',
  name: 'Gemini CLI',
  files: (scope, ctx) => [geminiPolicyFile(scope, ctx)],
  generate(policy, scope, ctx): TargetOutput {
    const warnings: MappingWarning[] = [];
    const content = geminiPolicyContent(policy, ctx, warnings);
    if (scope === 'project' && content)
      warnings.push(
        warn(
          'gemini',
          'warn',
          'Gemini CLI does not load project policies yet (the workspace policy tier is disabled, and workspace settings cannot set policyPaths). .gemini/policies/agentperms.toml is written for the future; run `agentperms apply --scope user --target gemini` to enforce it today',
        ),
      );
    return { target: 'gemini', scope, warnings, files: [{ kind: 'owned', file: geminiPolicyFile(scope, ctx), content, comment: '#' }] };
  },
  read(ctx, scopes): AgentSnapshot {
    const snap: AgentSnapshot = { agent: 'gemini', detected: false, files: [], rules: [], settings: [] };
    for (const scope of ['user', 'project'] as const) {
      if (!scopes.includes(scope)) continue;
      const dir = path.join(scope === 'user' ? ctx.home : ctx.cwd, '.gemini');
      readSettings(path.join(dir, 'settings.json'), scope, snap);
      readPolicies(path.join(dir, 'policies'), scope, snap);
    }
    snap.detected =
      snap.files.some((f) => f.exists) ||
      (scopes.includes('user') && dirExists(path.join(ctx.home, '.gemini'))) ||
      (scopes.includes('project') && dirExists(path.join(ctx.cwd, '.gemini')));
    return snap;
  },
};
