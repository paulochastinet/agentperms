import pc from 'picocolors';
import type { AuditReport } from './audit.js';
import type { Plan } from './apply.js';
import { displayPath, planDiffs } from './apply.js';
import { redactPath } from './secrets.js';
import type { PatternStat, SuggestReport } from './suggest.js';
import type { AgentSnapshot, NativeRule } from './targets/index.js';
import { TARGET_NAMES, type Ctx, type Decision, type MappingWarning, type Severity, type TargetId } from './types.js';

export type Colors = ReturnType<typeof pc.createColors>;

const SEV_LABEL: Record<Severity, string> = { high: 'HIGH', medium: 'MED ', low: 'LOW ' };

function sevColor(c: Colors, s: Severity, text: string): string {
  return s === 'high' ? c.red(c.bold(text)) : s === 'medium' ? c.yellow(text) : c.dim(text);
}

function pad(s: string, n: number): string {
  // pad by visible length (strip ANSI)
  // eslint-disable-next-line no-control-regex
  const len = s.replace(/\x1b\[[0-9;]*m/g, '').length;
  return len >= n ? s : s + ' '.repeat(n - len);
}

function trunc(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n - 1) + '…';
}

export function show(p: string, ctx: Ctx): string {
  return redactPath(displayPath(p, ctx), ctx.home);
}

// ───────────────────────────── warnings ─────────────────────────────

export function renderWarnings(ws: MappingWarning[], c: Colors, verbose: boolean): string {
  const shown = ws.filter((w) => verbose || w.level === 'warn');
  const hidden = ws.length - shown.length;
  const lines = shown.map((w) => `  ${w.level === 'warn' ? c.yellow('!') : c.dim('i')} ${c.bold(TARGET_NAMES[w.target])}: ${w.message}`);
  if (hidden) lines.push(c.dim(`  i ${hidden} mapping note${hidden === 1 ? '' : 's'} (exact matches, stricter fallbacks...). Use --verbose to see them.`));
  return lines.length ? lines.join('\n') + '\n' : '';
}

// ───────────────────────────── apply / diff ─────────────────────────────

export function renderPlan(plan: Plan, c: Colors, opts: { dryRun: boolean; verbose: boolean; ctx: Ctx; mode: 'apply' | 'diff' }): string {
  const out: string[] = [];
  const where = plan.scope === 'project' ? 'project' : 'user (~)';
  if (opts.dryRun || opts.mode === 'diff') {
    const diff = planDiffs(plan);
    if (diff) {
      out.push(
        diff
          .split('\n')
          .map((l) => (l.startsWith('+++') || l.startsWith('---') ? c.bold(l) : l.startsWith('+') ? c.green(l) : l.startsWith('-') ? c.red(l) : l.startsWith('@@') ? c.cyan(l) : l))
          .join('\n'),
      );
    }
  }
  for (const ch of plan.changes) {
    const verb = ch.before === null ? 'create' : ch.after === null ? 'delete' : 'update';
    const detail = ch.added.length || ch.removed.length ? ` (${[ch.added.length ? `+${ch.added.length}` : '', ch.removed.length ? `-${ch.removed.length}` : ''].filter(Boolean).join(' ')} rules)` : '';
    const label = opts.mode === 'diff' ? 'drift ' : opts.dryRun ? `would ${verb}` : `${verb}d`;
    out.push(`  ${c.green('●')} ${pad(TARGET_NAMES[ch.target], 12)} ${label} ${c.bold(ch.display)}${detail}`);
  }
  for (const u of plan.unchanged) out.push(`  ${c.dim('○')} ${pad(TARGET_NAMES[u.target], 12)} ${c.dim(`up to date ${u.display}`)}`);
  for (const e of plan.errors) out.push(`  ${c.red('✗')} ${pad(TARGET_NAMES[e.target], 12)} ${e.file}: ${e.message}`);
  if (!plan.changes.length && !plan.errors.length) out.push(c.dim(opts.mode === 'diff' ? `  In sync: native configs (${where}) match the policy.` : `  Nothing to do: native configs (${where}) already match the policy.`));
  const w = renderWarnings(plan.warnings, c, opts.verbose);
  if (w) out.push('', w.trimEnd());
  return out.join('\n') + '\n';
}

// ───────────────────────────── audit ─────────────────────────────

const MARK: Record<Decision, string> = { allow: '✓', ask: '?', deny: '✗' };

function counts(rules: NativeRule[], cat: NativeRule['category'] | NativeRule['category'][]): string {
  const cats = Array.isArray(cat) ? cat : [cat];
  const r = rules.filter((x) => cats.includes(x.category));
  if (!r.length) return '—';
  const a = r.filter((x) => x.decision === 'allow').length;
  const q = r.filter((x) => x.decision === 'ask').length;
  const d = r.filter((x) => x.decision === 'deny').length;
  return `${a}/${q}/${d}`;
}

function modeOf(s: AgentSnapshot): string {
  const pick = (k: string) => s.settings.filter((x) => x.key === k).map((x) => x.value).pop();
  switch (s.agent) {
    case 'claude':
      return pick('defaultMode') ?? 'default';
    case 'codex': {
      const a = pick('approval_policy');
      const b = pick('default_permissions') ?? pick('sandbox_mode');
      return a || b ? [a, b].filter(Boolean).join(' · ') : 'default';
    }
    case 'gemini':
      return pick('general.defaultApprovalMode') ?? 'default';
    case 'cursor':
      return pick('approvalMode') ?? 'default';
  }
}

export function auditJson(r: AuditReport, ctx: Ctx, version: string) {
  const sum = { high: 0, medium: 0, low: 0 } as Record<Severity, number>;
  for (const f of r.findings) sum[f.severity]++;
  const p = (x: string) => show(x, ctx);
  return {
    schemaVersion: 1,
    tool: { name: 'agentperms', version },
    generatedAt: new Date().toISOString(),
    agents: r.agents.map((a) => ({
      id: a.agent,
      name: TARGET_NAMES[a.agent],
      detected: a.detected,
      mode: modeOf(a),
      files: a.files.filter((f) => f.exists || f.error).map((f) => ({ path: p(f.path), scope: f.scope, ...(f.error ? { error: f.error } : {}) })),
      rules: a.rules.map((x) => ({ ...x, file: p(x.file) })),
      settings: a.settings.map((x) => ({ ...x, file: p(x.file) })),
    })),
    findings: r.findings.map((f) => ({ ...f, ...(f.file ? { file: p(f.file) } : {}) })),
    summary: sum,
  };
}

function matrixRows(r: AuditReport, agents: AgentSnapshot[], limit: number): { label: string; cells: Record<TargetId, string> }[] {
  const keyed = new Map<string, { label: string; cells: Partial<Record<TargetId, Decision>>; score: number }>();
  const rank: Record<Decision, number> = { allow: 1, ask: 2, deny: 3 };
  for (const a of agents)
    for (const rule of a.rules) {
      if (rule.category === 'tool') continue;
      const label = `${rule.category === 'read' || rule.category === 'write' ? `${rule.category}` : rule.category} ${rule.pattern}`;
      let e = keyed.get(label);
      if (!e) keyed.set(label, (e = { label, cells: {}, score: 0 }));
      const prev = e.cells[a.agent];
      if (!prev || rank[rule.decision] > rank[prev]) e.cells[a.agent] = rule.decision;
    }
  const risky = new Set(r.findings.map((f) => f.rule).filter(Boolean));
  const rows = [...keyed.values()].map((e) => {
    const n = Object.keys(e.cells).length;
    const decs = new Set(Object.values(e.cells));
    e.score = n * 10 + (decs.size > 1 ? 100 : 0) + (agents.some((a) => a.rules.some((x) => risky.has(x.native) && `${x.category} ${x.pattern}` === e.label)) ? 50 : 0);
    return e;
  });
  rows.sort((x, y) => y.score - x.score || x.label.localeCompare(y.label));
  return rows.slice(0, limit).map((e) => ({
    label: e.label,
    cells: Object.fromEntries(agents.map((a) => [a.agent, e.cells[a.agent] ? MARK[e.cells[a.agent]!] : '·'])) as Record<TargetId, string>,
  }));
}

export function renderAuditText(r: AuditReport, c: Colors, opts: { ctx: Ctx; verbose: boolean; version: string; scopes: string[] }): string {
  const out: string[] = [];
  out.push('', `  ${c.bold('agentperms audit')} ${c.dim(`v${opts.version}  ·  ${opts.scopes.join(' + ')}  ·  ${show(opts.ctx.cwd, opts.ctx)}`)}`, '');
  const det = r.agents.filter((a) => a.detected);
  const missing = r.agents.filter((a) => !a.detected);
  if (!det.length) {
    out.push(c.dim('  No agent configuration found.'), '');
  } else {
    out.push(c.dim(`  ${pad('', 13)}${pad('mode', 26)}${pad('shell', 11)}${pad('read', 9)}${pad('write', 9)}${pad('web', 9)}${pad('mcp', 9)}`));
    for (const a of det) {
      out.push(
        `  ${pad(c.bold(TARGET_NAMES[a.agent]), 13)}${pad(trunc(modeOf(a), 24), 26)}${pad(counts(a.rules, 'shell'), 11)}${pad(counts(a.rules, 'read'), 9)}${pad(counts(a.rules, 'write'), 9)}${pad(counts(a.rules, 'web'), 9)}${pad(counts(a.rules, 'mcp'), 9)}`,
      );
    }
    out.push(c.dim(`  ${pad('', 13)}counts are allow/ask/deny rules`));
    const files = det.flatMap((a) => a.files.filter((f) => f.exists || f.error).map((f) => `${show(f.path, opts.ctx)}${f.error ? c.red(` (${f.error})`) : ''}`));
    if (files.length) out.push(c.dim(`  read: ${files.join(', ')}`));
    if (missing.length) out.push(c.dim(`  not detected: ${missing.map((a) => TARGET_NAMES[a.agent]).join(', ')}`));
    out.push('');

    const rows = matrixRows(r, det, opts.verbose ? 1000 : 15);
    if (rows.length) {
      const w = Math.min(46, Math.max(20, ...rows.map((x) => x.label.length)) + 2);
      out.push(`  ${c.bold('Who allows what')} ${c.dim('(✓ allow  ? ask  ✗ deny  · no rule)')}`);
      out.push(c.dim(`  ${pad('', w)}${det.map((a) => pad(TARGET_NAMES[a.agent].split(' ')[0]!, 9)).join('')}`));
      for (const row of rows) {
      row.label = redactPath(row.label, opts.ctx.home);
        const cells = det
          .map((a) => {
            const m = row.cells[a.agent];
            return pad(m === '✓' ? c.green(m) : m === '✗' ? c.red(m) : m === '?' ? c.yellow(m) : c.dim(m), 9);
          })
          .join('');
        out.push(`  ${pad(trunc(row.label, w - 2), w)}${cells}`);
      }
      const total = new Set(det.flatMap((a) => a.rules.filter((x) => x.category !== 'tool').map((x) => `${x.category} ${x.pattern}`))).size;
      if (!opts.verbose && total > rows.length) out.push(c.dim(`  … ${total - rows.length} more rules (--verbose)`));
      out.push('');
    }
  }

  if (r.findings.length) {
    const sum = { high: 0, medium: 0, low: 0 } as Record<Severity, number>;
    for (const f of r.findings) sum[f.severity]++;
    out.push(`  ${c.bold('Findings')} ${c.dim(`${sum.high} high · ${sum.medium} medium · ${sum.low} low`)}`);
    const list = opts.verbose ? r.findings : r.findings.filter((f) => f.severity !== 'low').slice(0, 25);
    for (const f of list) out.push(`  ${sevColor(c, f.severity, SEV_LABEL[f.severity])} ${redactPath(f.message, opts.ctx.home)}${f.file ? c.dim(`  ${show(f.file, opts.ctx)}`) : ''}`);
    const hidden = r.findings.length - list.length;
    if (hidden) out.push(c.dim(`  … ${hidden} more (low severity or beyond the first 25; --verbose)`));
  } else if (det.length) {
    out.push(`  ${c.green('No risky grants found.')}`);
  }
  out.push('');
  return out.join('\n') + '\n';
}

export function renderAuditMarkdown(r: AuditReport, opts: { ctx: Ctx; version: string }): string {
  const det = r.agents.filter((a) => a.detected);
  const out: string[] = ['## agentperms audit', ''];
  if (det.length) {
    out.push('| Agent | Mode | Shell | Read | Write | Web | MCP |', '|---|---|---|---|---|---|---|');
    for (const a of det)
      out.push(`| ${TARGET_NAMES[a.agent]} | ${modeOf(a)} | ${counts(a.rules, 'shell')} | ${counts(a.rules, 'read')} | ${counts(a.rules, 'write')} | ${counts(a.rules, 'web')} | ${counts(a.rules, 'mcp')} |`);
    out.push('', '<sub>Counts are allow/ask/deny rules.</sub>', '');
  } else out.push('_No agent configuration found._', '');
  if (r.findings.length) {
    out.push('| Severity | Agent | Finding | File |', '|---|---|---|---|');
    for (const f of r.findings)
      out.push(`| ${f.severity} | ${f.agent ? TARGET_NAMES[f.agent] : ''} | ${redactPath(f.message, opts.ctx.home).replace(/\|/g, '\\|')} | ${f.file ? `\`${show(f.file, opts.ctx)}\`` : ''} |`);
  } else out.push('No risky grants found. ✅');
  return out.join('\n') + '\n';
}

// ───────────────────────────── suggest ─────────────────────────────

export function renderSuggestText(
  r: SuggestReport,
  allow: PatternStat[],
  ask: PatternStat[],
  c: Colors,
  opts: { minCount: number; limit: number; verbose: boolean; sinceLabel: string; hasPolicy: boolean },
): string {
  const out: string[] = [''];
  const src = (Object.entries(r.sources) as [string, SuggestReport['sources']['claude']][])
    .filter(([, s]) => s.found)
    .map(([k, s]) => `${TARGET_NAMES[k as TargetId]} ${s.commands.toLocaleString('en-US')} cmds / ${s.sessions} sessions`);
  out.push(`  ${c.bold('agentperms suggest')} ${c.dim(`· since ${opts.sinceLabel} · ${src.length ? src.join(' · ') : 'no local history found'}`)}`);
  out.push(c.dim(`  ${r.commands.toLocaleString('en-US')} shell commands mined locally (read-only), ${r.patterns.length} distinct prefixes. Nothing left this machine.`), '');
  if (!r.commands) {
    out.push('  No shell commands found in local agent history for this period.', '');
    return out.join('\n');
  }
  const head = c.dim(`  ${pad('#', 4)}${pad('pattern', 34)}${pad('count', 8)}${pad('sessions', 10)}${pad('approved', 10)}source`);
  const row = (p: PatternStat, i: number) => {
    const line = `  ${pad(String(i + 1), 4)}${pad(c.bold(trunc(p.pattern, 32)), 34)}${pad(String(p.count), 8)}${pad(String(p.sessions), 10)}${pad(p.approved || p.rejected ? `${p.approved}${p.rejected ? c.red(` ✗${p.rejected}`) : ''}` : '—', 10)}${p.sources.join(',')}`;
    return opts.verbose ? `${line}\n      ${c.dim(`${p.reason} · e.g. ${p.example}`)}` : line;
  };
  out.push(`  ${c.green(c.bold('Suggested allow'))} ${c.dim(`(read-only, seen ≥${opts.minCount}×, never rejected, not in your policy yet)`)}`);
  if (allow.length) {
    out.push(head);
    allow.slice(0, opts.limit).forEach((p, i) => out.push(row(p, i)));
    if (allow.length > opts.limit) out.push(c.dim(`  … ${allow.length - opts.limit} more (--limit)`));
  } else out.push(c.dim('  nothing new: your policy already covers the safe commands you run often.'));
  out.push('');

  const askTop = ask.slice(0, opts.verbose ? opts.limit : 8);
  if (askTop.length) {
    out.push(`  ${c.yellow(c.bold('Keep asking'))} ${c.dim('(mutating or runs project code; add to shell.ask with --write --include-ask)')}`);
    out.push(`  ${askTop.map((p) => `${p.pattern} ${c.dim(`(${p.count})`)}`).join(c.dim(' · '))}`, '');
  }
  const never = r.patterns.filter((p) => p.cls === 'never' && p.count >= opts.minCount).slice(0, opts.verbose ? opts.limit : 8);
  if (never.length) {
    out.push(`  ${c.red(c.bold('Never auto-approved'))} ${c.dim('(network, destructive, arbitrary code or secrets: keep a human in the loop)')}`);
    out.push(`  ${never.map((p) => `${p.pattern} ${c.dim(`(${p.count})`)}`).join(c.dim(' · '))}`, '');
  }
  const already = r.patterns.filter((p) => p.policy === 'allowed').reduce((n, p) => n + p.count, 0);
  if (already) out.push(c.dim(`  ${already.toLocaleString('en-US')} command runs are already covered by your policy's allow list.`));
  if (allow.length)
    out.push(
      opts.hasPolicy
        ? `  Add them: ${c.bold('agentperms suggest --write')} ${c.dim('(merges into agentperms.yaml, keeps your comments)')}, then ${c.bold('agentperms apply')}.`
        : `  Create a policy first (${c.bold('agentperms init')}), then ${c.bold('agentperms suggest --write')}.`,
    );
  out.push('');
  return out.join('\n');
}

