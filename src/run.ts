import { existsSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import pc from 'picocolors';
import { BACKUP_DIR, executePlan, planApply } from './apply.js';
import { audit, worstSeverity } from './audit.js';
import { findPolicyFile, loadPolicy, parseTargetName, PolicyError, type LoadedPolicy } from './policy/load.js';
import { detectPreset, PRESETS, renderPreset, type Preset } from './policy/presets.js';
import { addShellPatterns } from './policy/write.js';
import { auditJson, renderAuditMarkdown, renderAuditText, renderPlan, renderSuggestText, show, type Colors } from './render.js';
import { allowCandidates, askCandidates, HISTORY_SOURCES, mine, parseSince, type HistorySource } from './suggest.js';
import { readText } from './targets/common.js';
import { SEVERITY_RANK, TARGET_IDS, type Ctx, type Scope, type Severity, type TargetId } from './types.js';
import { VERSION } from './version.js';

export class UsageError extends Error {}

const COMMANDS = ['init', 'apply', 'audit', 'suggest', 'diff'] as const;
type Command = (typeof COMMANDS)[number];

export const HELP = `agentperms ${VERSION}: one permission policy for every AI coding agent

Usage
  agentperms <command> [options]

Commands
  init      Write a commented agentperms.yaml   [--preset safe-readonly|node|python|go|rust] [--force]
  apply     Generate native configs              [--target <list>] [--scope project|user] [--dry-run] [--force]
  audit     What is allowed today, everywhere    [--scope project|user|all] [--format text|json|markdown] [--fail-on high|medium|low]
  suggest   Mine local history for an allowlist  [--since 30d] [--min-count 3] [--source claude,codex,gemini] [--write] [--include-ask]
  diff      Drift between policy and native configs (exit 1 on drift)  [--target <list>] [--scope project|user]

Global options
  --cwd <dir>         Project directory (default: .)
  --home <dir>        Home directory for user-level configs and history (default: ~)
  --policy <file>     Policy file (default: agentperms.yaml in --cwd)
  -v, --verbose       Show every rule, note and example
  --no-color          Disable colors (NO_COLOR is respected)
  -h, --help          Show help
  -V, --version       Show version

Targets: claude, codex, gemini, cursor.   Exit codes: 0 ok · 1 findings/drift · 2 usage or policy error.
Docs: https://github.com/paulochastinet/agentperms
`;

interface Out {
  out: (s: string) => void;
  err: (s: string) => void;
}

function useColor(flag: boolean | undefined, stream: NodeJS.WriteStream): boolean {
  if (flag !== undefined) return flag;
  if ('NO_COLOR' in process.env && process.env.NO_COLOR !== '') return false;
  if (process.env.FORCE_COLOR && process.env.FORCE_COLOR !== '0') return true;
  return !!stream.isTTY && process.env.TERM !== 'dumb';
}

function list(v: string[] | undefined): string[] {
  return (v ?? []).flatMap((x) => x.split(',')).map((s) => s.trim()).filter(Boolean);
}

function parseTargets(v: string[] | undefined, fallback: TargetId[]): TargetId[] {
  const names = list(v);
  if (!names.length) return fallback;
  return names.map((n) => {
    const id = parseTargetName(n);
    if (!id) throw new UsageError(`unknown target "${n}" (expected: ${TARGET_IDS.join(', ')})`);
    return id;
  });
}

function oneOf<T extends string>(flag: string, v: string | undefined, allowed: readonly T[], def: T): T {
  if (v === undefined) return def;
  if (!(allowed as readonly string[]).includes(v)) throw new UsageError(`--${flag} must be one of ${allowed.join(', ')} (got "${v}")`);
  return v as T;
}

function posInt(flag: string, v: string | undefined, def: number): number {
  if (v === undefined) return def;
  if (!/^\d+$/.test(v) || Number(v) < 1) throw new UsageError(`--${flag} expects a positive integer, got "${v}"`);
  return Number(v);
}

/** `--home` alone (no directory) means "include user-level config" for `audit`; otherwise it takes a path. */
function preprocess(argv: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--home') {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('-')) {
        out.push('--include-home');
        continue;
      }
    }
    out.push(a);
  }
  return out;
}

const OPTIONS = {
  cwd: { type: 'string' },
  home: { type: 'string' },
  'include-home': { type: 'boolean' },
  policy: { type: 'string' },
  preset: { type: 'string' },
  force: { type: 'boolean' },
  target: { type: 'string', multiple: true, short: 't' },
  agent: { type: 'string', multiple: true, short: 'a' },
  scope: { type: 'string' },
  'dry-run': { type: 'boolean', short: 'n' },
  format: { type: 'string', short: 'f' },
  json: { type: 'boolean' },
  'fail-on': { type: 'string' },
  since: { type: 'string' },
  'min-count': { type: 'string' },
  source: { type: 'string', multiple: true },
  project: { type: 'boolean' },
  write: { type: 'boolean', short: 'w' },
  'include-ask': { type: 'boolean' },
  limit: { type: 'string' },
  verbose: { type: 'boolean', short: 'v' },
  color: { type: 'boolean' },
  'no-color': { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean', short: 'V' },
} as const;

const ALLOWED: Record<Command, string[]> = {
  init: ['preset', 'force'],
  apply: ['target', 'scope', 'dry-run', 'force'],
  audit: ['scope', 'agent', 'target', 'format', 'json', 'fail-on', 'include-home'],
  suggest: ['since', 'min-count', 'source', 'project', 'write', 'include-ask', 'limit', 'format', 'json'],
  diff: ['target', 'scope', 'format', 'json'],
};
const GLOBAL = ['cwd', 'home', 'policy', 'verbose', 'color', 'no-color', 'help', 'version'];

export async function run(argv: string[], io: Out, env: { stdout: NodeJS.WriteStream; stderr: NodeJS.WriteStream }): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({ args: preprocess(argv), allowPositionals: true, strict: true, options: OPTIONS });
  } catch (e) {
    io.err(`agentperms: ${(e as Error).message}\nRun "agentperms --help" for usage.\n`);
    return 2;
  }
  const v = parsed.values;
  if (v.version) {
    io.out(`${VERSION}\n`);
    return 0;
  }
  const cmd = parsed.positionals[0];
  if (v.help || !cmd) {
    io.out(HELP);
    return cmd || v.help ? 0 : 2;
  }
  if (!(COMMANDS as readonly string[]).includes(cmd)) {
    io.err(`agentperms: unknown command "${cmd}"\nRun "agentperms --help" for usage.\n`);
    return 2;
  }
  const command = cmd as Command;
  const colorFlag = v['no-color'] ? false : v.color ? true : undefined;
  const c = pc.createColors(useColor(colorFlag, env.stdout));
  const ce = pc.createColors(useColor(colorFlag, env.stderr));

  try {
    if (parsed.positionals.length > 1) throw new UsageError(`unexpected argument "${parsed.positionals[1]}"`);
    for (const k of Object.keys(v)) {
      if (!GLOBAL.includes(k) && !ALLOWED[command].includes(k)) throw new UsageError(`--${k} is not an option of "${command}"`);
    }
    const ctx: Ctx = {
      cwd: path.resolve(v.cwd ?? process.cwd()),
      home: path.resolve(v.home ?? os.homedir()),
    };
    if (!existsSync(ctx.cwd)) throw new UsageError(`--cwd directory does not exist: ${ctx.cwd}`);
    const verbose = !!v.verbose;
    switch (command) {
      case 'init':
        return cmdInit(v, ctx, io, c);
      case 'apply':
        return cmdApply(v, ctx, io, c, ce, verbose, 'apply');
      case 'diff':
        return cmdApply(v, ctx, io, c, ce, verbose, 'diff');
      case 'audit':
        return cmdAudit(v, ctx, io, c, verbose);
      case 'suggest':
        return await cmdSuggest(v, ctx, io, c, ce, verbose);
    }
  } catch (e) {
    if (e instanceof UsageError) {
      io.err(`agentperms: ${e.message}\nRun "agentperms --help" for usage.\n`);
      return 2;
    }
    if (e instanceof PolicyError) {
      io.err(`${ce.red('✗')} ${e.message.replace(e.file, show(e.file, { cwd: v.cwd ? path.resolve(v.cwd) : process.cwd(), home: v.home ?? os.homedir() }))}\n`);
      return 2;
    }
    throw e;
  }
}

type Values = Record<string, string | boolean | string[] | undefined>;

function requirePolicy(v: Values, ctx: Ctx): LoadedPolicy {
  const file = findPolicyFile(ctx.cwd, v.policy as string | undefined);
  if (!file || !existsSync(file)) {
    throw new UsageError(`no policy found (${v.policy ? String(v.policy) : 'agentperms.yaml'} in ${show(ctx.cwd, ctx) || '.'}). Create one with "agentperms init"`);
  }
  return loadPolicy(file);
}

function cmdInit(v: Values, ctx: Ctx, io: Out, c: Colors): number {
  const file = path.resolve(ctx.cwd, (v.policy as string | undefined) ?? 'agentperms.yaml');
  const preset = v.preset === undefined ? detectPreset(ctx.cwd) : oneOf('preset', v.preset as string, PRESETS, 'safe-readonly');
  if (existsSync(file) && !v.force) throw new UsageError(`${show(file, ctx)} already exists (use --force to overwrite)`);
  writeFileSync(file, renderPreset(preset as Preset));
  io.out(
    `${c.green('✓')} wrote ${c.bold(show(file, ctx))} ${c.dim(`(preset: ${preset}${v.preset === undefined ? ', auto-detected' : ''})`)}\n` +
      `  next: ${c.bold('agentperms apply --dry-run')} to preview, ${c.bold('agentperms apply')} to write the native configs\n`,
  );
  return 0;
}

function cmdApply(v: Values, ctx: Ctx, io: Out, c: Colors, ce: Colors, verbose: boolean, mode: 'apply' | 'diff'): number {
  const loaded = requirePolicy(v, ctx);
  const scope = oneOf<Scope>('scope', v.scope as string | undefined, ['project', 'user'], 'project');
  const targets = parseTargets(v.target as string[] | undefined, loaded.policy.targets);
  const dryRun = !!v['dry-run'];
  const fmt = mode === 'diff' ? formatOf(v, ['text', 'json'] as const) : 'text';

  for (const n of loaded.notes) io.err(`${ce.yellow('!')} ${n}\n`);
  const plan = planApply(loaded.policy, { scope, targets, ctx, force: !!v.force });

  if (mode === 'diff') {
    if (fmt === 'json') {
      io.out(
        JSON.stringify(
          {
            schemaVersion: 1,
            scope,
            drift: plan.changes.map((ch) => ({ target: ch.target, file: show(ch.file, ctx), missing: ch.added, stale: ch.removed, create: ch.before === null, delete: ch.after === null })),
            inSync: plan.unchanged.map((u) => ({ target: u.target, file: u.display })),
            errors: plan.errors,
            warnings: plan.warnings,
          },
          null,
          2,
        ) + '\n',
      );
    } else {
      io.out(`\n  ${c.bold('agentperms diff')} ${c.dim(`· ${show(loaded.file, ctx)} vs native configs (${scope})`)}\n\n`);
      io.out(renderPlan(plan, c, { dryRun: true, verbose, ctx, mode: 'diff' }));
      if (plan.changes.length) io.out(`\n  ${c.yellow(`${plan.changes.length} file(s) drifted.`)} Run ${c.bold(`agentperms apply${scope === 'user' ? ' --scope user' : ''}`)} to sync.\n`);
    }
    if (plan.errors.length) return 2;
    return plan.changes.length ? 1 : 0;
  }

  io.out(`\n  ${c.bold(`agentperms apply${dryRun ? ' --dry-run' : ''}`)} ${c.dim(`· ${show(loaded.file, ctx)} → ${targets.join(', ')} (${scope})`)}\n\n`);
  if (dryRun) {
    io.out(renderPlan(plan, c, { dryRun: true, verbose, ctx, mode: 'apply' }));
    return plan.errors.length ? 2 : 0;
  }
  const res = executePlan(plan);
  io.out(renderPlan(plan, c, { dryRun: false, verbose, ctx, mode: 'apply' }));
  if (res.backupDir) {
    io.out(`\n  ${c.dim(`Originals backed up to ${show(res.backupDir, ctx)}/`)}\n`);
    if (scope === 'project') io.out(`  ${c.dim(`Tip: add ${BACKUP_DIR}/ to .gitignore.`)}\n`);
  }
  return plan.errors.length ? 2 : 0;
}

function formatOf<T extends string>(v: Values, allowed: readonly T[]): T {
  if (v.json) return 'json' as T;
  return oneOf('format', v.format as string | undefined, allowed, allowed[0]!);
}

function cmdAudit(v: Values, ctx: Ctx, io: Out, c: Colors, verbose: boolean): number {
  const fmt = formatOf(v, ['text', 'json', 'markdown'] as const);
  const scopeArg = oneOf('scope', v.scope as string | undefined, ['project', 'user', 'all'], 'all');
  const scopes: Scope[] = scopeArg === 'all' ? ['project', 'user'] : [scopeArg as Scope];
  const failOn = v['fail-on'] === undefined ? null : oneOf<Severity>('fail-on', v['fail-on'] as string, ['high', 'medium', 'low'], 'high');
  const agents = parseTargets([...((v.agent as string[]) ?? []), ...((v.target as string[]) ?? [])], TARGET_IDS);
  const report = audit({ ctx, scopes, agents });
  if (fmt === 'json') io.out(JSON.stringify(auditJson(report, ctx, VERSION), null, 2) + '\n');
  else if (fmt === 'markdown') io.out(renderAuditMarkdown(report, { ctx, version: VERSION }));
  else io.out(renderAuditText(report, c, { ctx, verbose, version: VERSION, scopes: scopes.map((s) => (s === 'user' ? 'user (~)' : 'project')) }));
  if (failOn) {
    const w = worstSeverity(report.findings);
    if (w && SEVERITY_RANK[w] >= SEVERITY_RANK[failOn]) {
      if (fmt === 'text') io.err(`agentperms: findings at or above "${failOn}" severity\n`);
      return 1;
    }
  }
  return 0;
}

async function cmdSuggest(v: Values, ctx: Ctx, io: Out, c: Colors, ce: Colors, verbose: boolean): Promise<number> {
  const fmt = formatOf(v, ['text', 'json'] as const);
  const sinceRaw = (v.since as string | undefined) ?? '30d';
  let sinceMs: number;
  try {
    sinceMs = parseSince(sinceRaw);
  } catch (e) {
    throw new UsageError((e as Error).message);
  }
  const minCount = posInt('min-count', v['min-count'] as string | undefined, 3);
  const limit = posInt('limit', v.limit as string | undefined, 25);
  const sources = list(v.source as string[] | undefined).map((s) => {
    const n = s.toLowerCase().replace(/-cli$|-code$/, '') as HistorySource;
    if (!HISTORY_SOURCES.includes(n)) throw new UsageError(`unknown --source "${s}" (expected: ${HISTORY_SOURCES.join(', ')})`);
    return n;
  });
  const policyFile = findPolicyFile(ctx.cwd, v.policy as string | undefined);
  const loaded = policyFile && existsSync(policyFile) ? loadPolicy(policyFile) : null;
  if (v.write && !loaded) throw new UsageError('--write needs a policy file; create one with "agentperms init" first');

  const report = await mine({ home: ctx.home, sinceMs, sources, projectDir: v.project ? ctx.cwd : undefined }, loaded?.policy ?? null);
  const allow = allowCandidates(report, minCount);
  const ask = askCandidates(report, minCount);

  if (fmt === 'json') {
    io.out(
      JSON.stringify(
        {
          schemaVersion: 1,
          since: report.since,
          sources: report.sources,
          commands: report.commands,
          minCount,
          suggestions: { allow: allow.slice(0, limit), ask: ask.slice(0, limit) },
          patterns: report.patterns.filter((p) => p.count >= minCount).map((p) => (verbose ? p : { ...p, example: undefined })),
        },
        null,
        2,
      ) + '\n',
    );
  } else {
    io.out(renderSuggestText(report, allow, ask, c, { minCount, limit, verbose, sinceLabel: sinceRaw, hasPolicy: !!loaded }));
  }

  if (v.write && loaded) {
    const { text } = readText(loaded.file);
    if (text === null) throw new UsageError(`cannot read ${loaded.file}`);
    let t = text;
    const res1 = addShellPatterns(t, 'allow', allow.slice(0, limit).map((p) => p.pattern), loaded.file);
    t = res1.text;
    let added = res1.added.length;
    if (v['include-ask']) {
      const res2 = addShellPatterns(t, 'ask', ask.slice(0, limit).map((p) => p.pattern), loaded.file);
      t = res2.text;
      added += res2.added.length;
    }
    if (added) {
      writeFileSync(loaded.file, t);
      io.err(`${ce.green('✓')} added ${added} pattern${added === 1 ? '' : 's'} to ${show(loaded.file, ctx)}. Review it, then run ${ce.bold('agentperms apply')}.\n`);
    } else io.err(`${ce.dim('Nothing to add to the policy.')}\n`);
  }
  return 0;
}
