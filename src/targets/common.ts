import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { domainMatches, mcpRegex, pathPatternCovers } from '../glob.js';
import { shellPatternCovers } from '../shell.js';
import type { Ctx, Decision, MappingWarning, Policy, Scope, TargetId } from '../types.js';

export const MANAGED_HEADER = 'Managed by agentperms';
export const BLOCK_BEGIN = '# >>> agentperms managed block: edit agentperms.yaml, not this block >>>';
export const BLOCK_END = '# <<< agentperms managed block <<<';

export interface JsonListPlan {
  /** Stable key used in the state file, e.g. `permissions.allow`. */
  key: string;
  path: string[];
  entries: string[];
}

export type FilePlan =
  | { kind: 'json-lists'; file: string; lists: JsonListPlan[] }
  /** A file fully owned by agentperms. `content: null` removes it (only if we own it). */
  | { kind: 'owned'; file: string; content: string | null; comment: string }
  /** A delimited block inside a TOML file. `block: null` removes the block. */
  | { kind: 'toml-block'; file: string; block: string | null };

export interface TargetOutput {
  target: TargetId;
  scope: Scope;
  files: FilePlan[];
  warnings: MappingWarning[];
}

export type Category = 'shell' | 'read' | 'write' | 'web' | 'mcp' | 'tool';

/** One native rule normalized into agentperms vocabulary (audit / diff). */
export interface NativeRule {
  agent: TargetId;
  scope: Scope;
  file: string;
  category: Category;
  decision: Decision;
  /** agentperms-style pattern (`git status *`, `.env`, `docs.github.com`, `github:*`). */
  pattern: string;
  /** The rule as written in the native file. */
  native: string;
  /** Pattern is a regex / something we could not normalize exactly. */
  approximate?: boolean;
}

export interface NativeSetting {
  agent: TargetId;
  scope: Scope;
  file: string;
  key: string;
  value: string;
}

export interface SourceFile {
  path: string;
  scope: Scope;
  exists: boolean;
  error?: string;
}

export interface AgentSnapshot {
  agent: TargetId;
  /** At least one config or data directory of the agent exists. */
  detected: boolean;
  files: SourceFile[];
  rules: NativeRule[];
  settings: NativeSetting[];
}

export interface Target {
  id: TargetId;
  name: string;
  /** Files written for a scope (for messages). */
  files(scope: Scope, ctx: Ctx): string[];
  generate(policy: Policy, scope: Scope, ctx: Ctx): TargetOutput;
  read(ctx: Ctx, scopes: Scope[]): AgentSnapshot;
}

export function scopeRoot(scope: Scope, ctx: Ctx): string {
  return scope === 'project' ? ctx.cwd : ctx.home;
}

export function readText(file: string): { text: string | null; error?: string } {
  try {
    if (!statSync(file).isFile()) return { text: null, error: 'not a file' };
    return { text: readFileSync(file, 'utf8') };
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return { text: null };
    return { text: null, error: code ?? (e as Error).message };
  }
}

export function dirExists(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

export function warn(target: TargetId, level: 'info' | 'warn', message: string): MappingWarning {
  return { target, level, message };
}

/** Is a policy `ask` rule shadowed by one of the policy's `allow` rules (same category)? */
export function askShadowedBy(category: 'shell' | 'read' | 'write' | 'web' | 'mcp', rule: string, allows: string[]): string | undefined {
  return allows.find((a) => {
    switch (category) {
      case 'shell':
        return shellPatternCovers(a, rule);
      case 'read':
      case 'write':
        return pathPatternCovers(a, rule);
      case 'web':
        return a === rule || domainMatches(a, rule.replace(/^\*\./, 'x.'));
      case 'mcp':
        return mcpRegex(a).test(rule.replace(/\*/g, 'x'));
    }
    return false;
  });
}

export function rel(ctx: Ctx, p: string): string {
  if (p.startsWith(ctx.cwd + path.sep)) return path.relative(ctx.cwd, p);
  if (ctx.home && p.startsWith(ctx.home + path.sep)) return '~/' + path.relative(ctx.home, p);
  return p;
}

export function tomlString(s: string): string {
  // TOML basic strings accept the same escapes JSON produces (\" \\ \n \t \uXXXX)
  return JSON.stringify(s);
}

export function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}
