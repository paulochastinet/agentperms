import { createReadStream, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { classifyPattern, type SafetyClass } from './safety.js';
import { looksSecret, maskCommand } from './secrets.js';
import { shellPatternCovers, splitCommand, stripWrappers } from './shell.js';
import type { Policy } from './types.js';

export type HistorySource = 'claude' | 'codex' | 'gemini';
export const HISTORY_SOURCES: HistorySource[] = ['claude', 'codex', 'gemini'];

export interface Observation {
  source: HistorySource;
  command: string;
  time: number;
  outcome: 'approved' | 'rejected' | 'unknown';
  session: string;
}

export interface PatternStat {
  pattern: string;
  count: number;
  sessions: number;
  approved: number;
  rejected: number;
  sources: HistorySource[];
  lastSeen: string;
  cls: SafetyClass;
  reason: string;
  /** Masked example (only exposed on request). */
  example: string;
  /** Status against the current policy. */
  policy: 'allowed' | 'asked' | 'denied' | 'new';
}

export interface SuggestReport {
  since: string;
  sources: Record<HistorySource, { files: number; commands: number; sessions: number; found: boolean }>;
  commands: number;
  skippedComplex: number;
  patterns: PatternStat[];
}

export interface MineOptions {
  home: string;
  sinceMs: number;
  sources?: HistorySource[];
  /** Only sessions whose cwd is inside this directory (Claude/Codex record it). */
  projectDir?: string;
}

// ───────────────────────────── file walking ─────────────────────────────

function walk(dir: string, accept: (f: string) => boolean, sinceMs: number, out: string[] = [], depth = 0): string[] {
  if (depth > 8) return out;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, accept, sinceMs, out, depth + 1);
    else if (e.isFile() && accept(e.name)) {
      try {
        if (statSync(p).mtimeMs >= sinceMs) out.push(p);
      } catch {
        /* vanished */
      }
    }
  }
  return out;
}

async function* lines(file: string): AsyncGenerator<string> {
  const rl = createInterface({ input: createReadStream(file, { encoding: 'utf8' }), crlfDelay: Infinity });
  try {
    for await (const l of rl) yield l;
  } finally {
    rl.close();
  }
}

const insideDir = (cwd: unknown, dir?: string) =>
  !dir || (typeof cwd === 'string' && (cwd === dir || cwd.startsWith(dir.endsWith(path.sep) ? dir : dir + path.sep)));

// ───────────────────────────── Claude Code ─────────────────────────────

const CLAUDE_REJECT = /doesn't want to proceed with this tool use|tool use was rejected|Permission to use \S+ (?:with command .* )?has been denied|was blocked by a permission rule|denied by your permission settings/i;

function resultText(c: unknown): string {
  if (typeof c === 'string') return c;
  if (Array.isArray(c)) return c.map((x) => (typeof x === 'string' ? x : typeof (x as { text?: unknown })?.text === 'string' ? (x as { text: string }).text : '')).join('\n');
  return '';
}

export async function mineClaude(opts: MineOptions, onFile?: () => void): Promise<{ obs: Observation[]; files: number; found: boolean }> {
  const root = path.join(opts.home, '.claude', 'projects');
  let found = false;
  try {
    found = statSync(root).isDirectory();
  } catch {
    /* none */
  }
  const files = found ? walk(root, (n) => n.endsWith('.jsonl'), opts.sinceMs) : [];
  const obs: Observation[] = [];
  for (const file of files) {
    onFile?.();
    const pending = new Map<string, Observation>();
    let sessionOk = !opts.projectDir;
    for await (const line of lines(file)) {
      if (!line.includes('"tool_use"') && !line.includes('"tool_result"') && sessionOk) continue;
      let d: Record<string, unknown>;
      try {
        d = JSON.parse(line) as Record<string, unknown>;
      } catch {
        continue;
      }
      if (!sessionOk && insideDir(d.cwd, opts.projectDir)) sessionOk = true;
      const msg = d.message as { content?: unknown } | undefined;
      if (!msg || !Array.isArray(msg.content)) continue;
      const ts = Date.parse(String(d.timestamp ?? '')) || 0;
      for (const c of msg.content as Record<string, unknown>[]) {
        if (c?.type === 'tool_use' && c.name === 'Bash' && d.type === 'assistant') {
          const input = c.input as { command?: unknown } | undefined;
          if (typeof input?.command !== 'string' || ts < opts.sinceMs) continue;
          if (opts.projectDir && !insideDir(d.cwd, opts.projectDir)) continue;
          const o: Observation = { source: 'claude', command: input.command, time: ts, outcome: 'unknown', session: String(d.sessionId ?? file) };
          pending.set(String(c.id), o);
          obs.push(o);
        } else if (c?.type === 'tool_result' && d.type === 'user') {
          const o = pending.get(String(c.tool_use_id));
          if (!o) continue;
          const text = resultText(c.content);
          o.outcome = CLAUDE_REJECT.test(text) ? 'rejected' : 'approved';
          pending.delete(String(c.tool_use_id));
        }
      }
    }
  }
  return { obs, files: files.length, found };
}

// ───────────────────────────── Codex CLI ─────────────────────────────

const CODEX_REJECT = /rejected by user|declined by user|user (?:denied|rejected|declined)|approval (?:was )?denied|exec command rejected/i;

function codexCommand(name: string, args: Record<string, unknown> | undefined, item: Record<string, unknown>): string | null {
  const fromArgv = (argv: unknown): string | null => {
    if (!Array.isArray(argv) || !argv.every((x) => typeof x === 'string')) return null;
    const a = argv as string[];
    if (a.length >= 3 && /(?:^|\/)(?:ba|z)?sh$/.test(a[0]!) && /^-l?c$|^-lc$|^-c$/.test(a[1]!)) return a.slice(2).join(' ');
    return a.map((x) => (/[\s"'$`\\|&;<>()]/.test(x) ? `'${x.replace(/'/g, `'\\''`)}'` : x)).join(' ');
  };
  if (item.type === 'local_shell_call') {
    const action = item.action as { command?: unknown } | undefined;
    return fromArgv(action?.command);
  }
  if (!args) return null;
  if (name === 'exec_command' && typeof args.cmd === 'string') return args.cmd;
  if ((name === 'shell_command' || name === 'shell') && typeof args.command === 'string') return args.command;
  if (name === 'shell' || name === 'container.exec' || name === 'local_shell') return fromArgv(args.command);
  return null;
}

export async function mineCodex(opts: MineOptions, onFile?: () => void): Promise<{ obs: Observation[]; files: number; found: boolean }> {
  const roots = [path.join(opts.home, '.codex', 'sessions'), path.join(opts.home, '.codex', 'archived_sessions')];
  let found = false;
  const files: string[] = [];
  for (const r of roots) {
    try {
      if (statSync(r).isDirectory()) {
        found = true;
        walk(r, (n) => n.endsWith('.jsonl'), opts.sinceMs, files);
      }
    } catch {
      /* none */
    }
  }
  const obs: Observation[] = [];
  for (const file of files) {
    onFile?.();
    const pending = new Map<string, Observation>();
    let session = file;
    let sessionCwd: unknown;
    const local: Observation[] = [];
    for await (const line of lines(file)) {
      let d: Record<string, unknown>;
      try {
        d = JSON.parse(line) as Record<string, unknown>;
      } catch {
        continue;
      }
      const item = (d.payload && typeof d.payload === 'object' ? d.payload : d) as Record<string, unknown>;
      const ts = Date.parse(String(d.timestamp ?? item.timestamp ?? '')) || 0;
      if (d.type === 'session_meta' || item.type === 'session_meta' || (d.id && d.instructions !== undefined)) {
        session = String(item.id ?? d.id ?? file);
        sessionCwd = item.cwd ?? d.cwd;
        continue;
      }
      if (item.type === 'turn_context' && item.cwd) sessionCwd ??= item.cwd;
      if (item.type === 'function_call' || item.type === 'local_shell_call') {
        let args: Record<string, unknown> | undefined;
        if (typeof item.arguments === 'string') {
          try {
            args = JSON.parse(item.arguments) as Record<string, unknown>;
          } catch {
            args = undefined;
          }
        } else if (item.arguments && typeof item.arguments === 'object') args = item.arguments as Record<string, unknown>;
        const cmd = codexCommand(String(item.name ?? ''), args, item);
        if (!cmd || (ts && ts < opts.sinceMs)) continue;
        const o: Observation = { source: 'codex', command: cmd, time: ts, outcome: 'unknown', session };
        pending.set(String(item.call_id ?? item.id), o);
        local.push(o);
      } else if (item.type === 'function_call_output' || item.type === 'local_shell_call_output') {
        const o = pending.get(String(item.call_id));
        if (!o) continue;
        const out = typeof item.output === 'string' ? item.output : JSON.stringify(item.output ?? '');
        o.outcome = CODEX_REJECT.test(out) ? 'rejected' : 'approved';
        pending.delete(String(item.call_id));
      }
    }
    if (insideDir(sessionCwd, opts.projectDir)) obs.push(...local.map((o) => ({ ...o, session })));
  }
  return { obs, files: files.length, found };
}

// ───────────────────────────── Gemini CLI ─────────────────────────────

export async function mineGemini(opts: MineOptions, onFile?: () => void): Promise<{ obs: Observation[]; files: number; found: boolean }> {
  const root = path.join(opts.home, '.gemini', 'tmp');
  let found = false;
  try {
    found = statSync(root).isDirectory();
  } catch {
    /* none */
  }
  const files = found ? walk(root, (n) => /\.jsonl?$/.test(n) && !/^logs\.json$/.test(n), opts.sinceMs) : [];
  const obs: Observation[] = [];
  if (opts.projectDir) return { obs, files: files.length, found }; // Gemini chats don't record the cwd
  for (const file of files) {
    onFile?.();
    let docs: unknown[] = [];
    try {
      const text = readFileSync(file, 'utf8');
      docs = file.endsWith('.jsonl') ? text.split('\n').filter(Boolean).map((l) => JSON.parse(l) as unknown) : [JSON.parse(text) as unknown];
    } catch {
      continue;
    }
    for (const doc of docs) {
      const d = doc as Record<string, unknown>;
      const session = String(d.sessionId ?? file);
      const messages = Array.isArray(d.messages) ? (d.messages as Record<string, unknown>[]) : [d];
      for (const m of messages) {
        const calls = Array.isArray(m.toolCalls) ? (m.toolCalls as Record<string, unknown>[]) : [];
        const ts = Date.parse(String(m.timestamp ?? d.startTime ?? '')) || 0;
        if (ts && ts < opts.sinceMs) continue;
        for (const c of calls) {
          if (c.name !== 'run_shell_command') continue;
          const cmd = (c.args as { command?: unknown } | undefined)?.command;
          if (typeof cmd !== 'string') continue;
          const status = String(c.status ?? '');
          obs.push({ source: 'gemini', command: cmd, time: ts, outcome: status === 'cancelled' || status === 'rejected' ? 'rejected' : status ? 'approved' : 'unknown', session });
        }
      }
    }
  }
  return { obs, files: files.length, found };
}

// ───────────────────────────── normalization ─────────────────────────────

const SUBCOMMAND_TOOLS = new Set([
  'git', 'npm', 'pnpm', 'yarn', 'bun', 'cargo', 'go', 'docker', 'podman', 'kubectl', 'gh', 'pip', 'pip3', 'uv', 'poetry',
  'brew', 'terraform', 'tofu', 'make', 'just', 'deno', 'npx', 'bunx', 'pnpx', 'uvx', 'node', 'python', 'python3', 'ruby',
  'perl', 'gradle', 'mvn', 'dotnet', 'swift', 'flutter', 'dart', 'mix', 'composer', 'bundle', 'rails', 'php',
]);
const VERSION_FLAGS = new Set(['--version', '-v', '-V', 'version', '--help', '-h']);
const SAFE_TOKEN = /^[\w@.:+=,%-][\w@.:/+=,%-]*$/;
const okToken = (t: string | undefined): t is string => !!t && t.length <= 48 && SAFE_TOKEN.test(t) && !looksSecret(t) && !/^\d{4,}$/.test(t);

/** Turn a concrete command (words) into a reusable prefix pattern, or null when it should not be generalized. */
export function derivePattern(input: string[]): string | null {
  const { words } = stripWrappers(input);
  const base = words[0];
  if (!base || base.includes('=') || base.startsWith('$') || base.startsWith('-')) return null;
  if (!okToken(base) && !/^\.{0,2}\/[\w./-]+$/.test(base)) return null;
  if (['cd', 'pushd', 'popd', 'export', 'unset', 'set', 'source', '.', 'exit', 'return', 'then', 'do', 'done', 'fi', 'else', 'for', 'while', 'until', 'select', 'function', 'elif', 'if', 'case', 'esac', '{', '}', '(', ')', '[[', '!', 'local', 'declare', 'read', 'trap', 'wait', 'shift', 'break', 'continue'].includes(base)) return null;
  const a1 = words[1];
  if (!SUBCOMMAND_TOOLS.has(base)) return `${base} *`;
  if (words.length === 2 && a1 && VERSION_FLAGS.has(a1)) return `${base} ${a1}`;

  if (a1 === undefined) return base;
  if (base === 'git') {
    if (a1.startsWith('-')) return null; // git -C dir ..., git -c k=v ...
    return okToken(a1) ? `git ${a1} *` : null;
  }
  if (['npm', 'pnpm', 'yarn', 'bun', 'deno'].includes(base)) {
    if (a1 === 'run' || a1 === 'run-script' || (base === 'deno' && a1 === 'task')) {
      const script = words[2];
      return okToken(script) && !script.startsWith('-') ? `${base} ${a1} ${script} *` : null;
    }
    return okToken(a1) && !a1.startsWith('-') ? `${base} ${a1} *` : null;
  }
  if (['python', 'python3', 'node', 'ruby', 'perl', 'php'].includes(base)) {
    if (a1 === '-m' && okToken(words[2])) return `${base} -m ${words[2]} *`;
    if (a1.startsWith('-')) return null;
    return okToken(a1) ? `${base} ${a1} *` : null;
  }
  if ((base === 'docker' || base === 'podman') && a1 === 'compose') return okToken(words[2]) ? `${base} compose ${words[2]} *` : null;
  if (base === 'gh') return okToken(a1) && okToken(words[2]) && !words[2].startsWith('-') ? `gh ${a1} ${words[2]} *` : okToken(a1) ? `gh ${a1} *` : null;
  if ((base === 'uv' || base === 'poetry') && a1 === 'run') return okToken(words[2]) ? `${base} run ${words[2]} *` : null;
  if (a1.startsWith('-')) return null;
  return okToken(a1) ? `${base} ${a1} *` : null;
}

function policyStatus(policy: Policy | null, pattern: string): PatternStat['policy'] {
  if (!policy) return 'new';
  if (policy.shell.deny.some((p) => shellPatternCovers(p, pattern) || shellPatternCovers(pattern, p))) return 'denied';
  if (policy.shell.ask.some((p) => shellPatternCovers(p, pattern))) return 'asked';
  if (policy.shell.allow.some((p) => shellPatternCovers(p, pattern))) return 'allowed';
  return 'new';
}

export function aggregate(observations: Observation[], policy: Policy | null): { patterns: PatternStat[]; commands: number; skippedComplex: number } {
  const map = new Map<string, { s: PatternStat; sessions: Set<string>; sources: Set<HistorySource>; last: number }>();
  let commands = 0;
  let skippedComplex = 0;
  for (const o of observations) {
    commands++;
    for (const seg of splitCommand(o.command)) {
      if (!seg.words) {
        skippedComplex++;
        continue;
      }
      const pattern = derivePattern(seg.words);
      if (!pattern) continue;
      let e = map.get(pattern);
      if (!e) {
        const v = classifyPattern(pattern);
        e = {
          s: { pattern, count: 0, sessions: 0, approved: 0, rejected: 0, sources: [], lastSeen: '', cls: v.cls, reason: v.reason, example: maskCommand(seg.text).slice(0, 160), policy: policyStatus(policy, pattern) },
          sessions: new Set(),
          sources: new Set(),
          last: 0,
        };
        map.set(pattern, e);
      }
      e.s.count++;
      e.sessions.add(o.session);
      e.sources.add(o.source);
      if (o.outcome === 'approved') e.s.approved++;
      if (o.outcome === 'rejected') e.s.rejected++;
      if (o.time > e.last) e.last = o.time;
    }
  }
  const patterns = [...map.values()].map(({ s, sessions, sources, last }) => ({
    ...s,
    sessions: sessions.size,
    sources: [...sources].sort(),
    lastSeen: last ? new Date(last).toISOString().slice(0, 10) : '',
  }));
  patterns.sort((a, b) => b.count - a.count || b.sessions - a.sessions || a.pattern.localeCompare(b.pattern));
  return { patterns, commands, skippedComplex };
}

export async function mine(opts: MineOptions, policy: Policy | null): Promise<SuggestReport> {
  const sources = opts.sources?.length ? opts.sources : HISTORY_SOURCES;
  const report: SuggestReport = {
    since: new Date(opts.sinceMs).toISOString(),
    sources: {
      claude: { files: 0, commands: 0, sessions: 0, found: false },
      codex: { files: 0, commands: 0, sessions: 0, found: false },
      gemini: { files: 0, commands: 0, sessions: 0, found: false },
    },
    commands: 0,
    skippedComplex: 0,
    patterns: [],
  };
  const all: Observation[] = [];
  const miners = { claude: mineClaude, codex: mineCodex, gemini: mineGemini };
  for (const s of sources) {
    const r = await miners[s](opts);
    report.sources[s] = { files: r.files, commands: r.obs.length, sessions: new Set(r.obs.map((o) => o.session)).size, found: r.found };
    all.push(...r.obs);
  }
  const agg = aggregate(all, policy);
  report.commands = agg.commands;
  report.skippedComplex = agg.skippedComplex;
  report.patterns = agg.patterns;
  return report;
}

/** Patterns that may be added to `shell.allow`. */
export function allowCandidates(r: SuggestReport, minCount: number): PatternStat[] {
  return r.patterns.filter((p) => p.cls === 'safe' && p.rejected === 0 && p.count >= minCount && p.policy === 'new');
}
export function askCandidates(r: SuggestReport, minCount: number): PatternStat[] {
  return r.patterns.filter((p) => p.cls === 'ask' && p.count >= minCount && p.policy === 'new');
}

export function parseSince(raw: string): number {
  const m = /^(\d+)\s*([hdwm])$/i.exec(raw.trim());
  if (!m) {
    const t = Date.parse(raw);
    if (!Number.isNaN(t)) return t;
    throw new Error(`--since expects a duration like 30d, 12h, 4w, 6m or a date (YYYY-MM-DD), got "${raw}"`);
  }
  const n = Number(m[1]);
  const unit = m[2]!.toLowerCase();
  const ms = unit === 'h' ? 3600e3 : unit === 'd' ? 86400e3 : unit === 'w' ? 7 * 86400e3 : 30 * 86400e3;
  return Date.now() - n * ms;
}
