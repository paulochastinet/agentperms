import { pathPatternCovers, splitMcp } from './glob.js';
import { classifyPattern } from './safety.js';
import { shellPatternCovers } from './shell.js';
import { TARGETS, type AgentSnapshot, type NativeRule } from './targets/index.js';
import { SEVERITY_RANK, TARGET_IDS, TARGET_NAMES, type Ctx, type Scope, type Severity, type TargetId } from './types.js';

export interface Finding {
  id: string;
  severity: Severity;
  agent: TargetId | null;
  scope?: Scope;
  file?: string;
  rule?: string;
  message: string;
}

export interface AuditReport {
  agents: AgentSnapshot[];
  findings: Finding[];
}

export interface AuditOptions {
  ctx: Ctx;
  scopes: Scope[];
  agents?: TargetId[];
}

const SECRET_SAMPLES = ['.env', 'config/.env.production'];
const GIT_SAMPLE = '.git/hooks/pre-commit';

function coversSecret(p: string): boolean {
  if (p.startsWith('re:')) return false;
  return SECRET_SAMPLES.some((s) => pathPatternCovers(p, s)) || p === '**' || p === '*' || p === '**/*';
}

/** Quote a pattern for a message, shortened. */
function q(p: string): string {
  const t = p.replace(/\s+/g, ' ');
  return `"${t.length > 70 ? t.slice(0, 67) + '...' : t}"`;
}

function nameOf(a: TargetId) {
  return TARGET_NAMES[a];
}

export function audit(opts: AuditOptions): AuditReport {
  const ids = opts.agents?.length ? opts.agents : TARGET_IDS;
  const agents = ids.map((id) => TARGETS[id].read(opts.ctx, opts.scopes));
  const findings: Finding[] = [];
  const push = (f: Finding) => {
    if (!findings.some((x) => x.id === f.id && x.agent === f.agent && x.message === f.message && x.file === f.file)) findings.push(f);
  };

  for (const snap of agents) {
    const A = snap.agent;
    for (const r of snap.rules) {
      if (r.decision !== 'allow') continue;
      const base = { agent: A, scope: r.scope, file: r.file, rule: r.native };
      if (r.category === 'shell') {
        if (r.pattern.startsWith('re:')) {
          if (/\.\*|\\S\*|\[\^"\]\*/.test(r.pattern) && /^re:(?:\.\*|"command":"\.\*)/.test(r.pattern))
            push({ ...base, id: 'shell-any', severity: 'high', message: `${nameOf(A)} auto-approves any shell command (${r.native})` });
          continue;
        }
        const v = classifyPattern(r.pattern);
        if (r.pattern === '*') {
          push({ ...base, id: 'shell-any', severity: 'high', message: `${nameOf(A)} auto-approves every shell command (${r.native})` });
        } else if (v.cls === 'never') {
          push({ ...base, id: 'dangerous-allow', severity: v.severity ?? 'high', message: `${q(r.pattern)} is auto-approved in ${nameOf(A)}: ${v.reason}` });
        } else if (v.severity) {
          push({ ...base, id: 'risky-allow', severity: v.severity, message: `${q(r.pattern)} is auto-approved in ${nameOf(A)}: ${v.reason}` });
        }
      } else if (r.category === 'read') {
        if (coversSecret(r.pattern))
          push({ ...base, id: 'secrets-read-allowed', severity: 'medium', message: `${nameOf(A)} pre-approves reading "${r.pattern}", which includes .env files` });
      } else if (r.category === 'write') {
        if (!r.pattern.startsWith('re:') && pathPatternCovers(r.pattern, GIT_SAMPLE) && r.pattern !== '**' && r.pattern !== '*')
          push({ ...base, id: 'git-write-allowed', severity: 'high', message: `${nameOf(A)} pre-approves writing "${r.pattern}", which includes .git/hooks (code that runs on every commit)` });
        else if (r.pattern === '**' || r.pattern === '*' || r.pattern === '**/*')
          push({ ...base, id: 'write-any', severity: 'medium', message: `${nameOf(A)} pre-approves every file write, including .git/hooks and CI config (${r.native})` });
      } else if (r.category === 'web') {
        if (r.pattern === '*') push({ ...base, id: 'web-any', severity: 'medium', message: `${nameOf(A)} fetches any URL without asking (${r.native}): an easy exfiltration channel` });
      } else if (r.category === 'mcp') {
        const [server, tool] = splitMcp(r.pattern);
        if (server === '*') push({ ...base, id: 'mcp-any', severity: 'medium', message: `${nameOf(A)} auto-approves tools from every MCP server (${r.native})` });
        else if (tool === '*' && /trust = true|approval_mode/.test(r.native))
          push({ ...base, id: 'mcp-trusted', severity: 'low', message: `${nameOf(A)} auto-approves every tool of MCP server "${server}" (${r.native})` });
      }
    }

    for (const s of snap.settings) {
      const base = { agent: A, scope: s.scope, file: s.file, rule: `${s.key} = ${s.value}` };
      const k = s.key;
      const v = s.value;
      if (A === 'claude') {
        if (k === 'defaultMode' && v === 'bypassPermissions')
          push({ ...base, id: 'bypass-mode', severity: 'high', message: 'Claude Code defaultMode is "bypassPermissions": no permission prompts at all' });
        if (k === 'defaultMode' && v === 'acceptEdits') push({ ...base, id: 'accept-edits', severity: 'low', message: 'Claude Code accepts file edits without asking (defaultMode "acceptEdits")' });
        if (k === 'skipDangerousModePermissionPrompt' && v === 'true')
          push({ ...base, id: 'bypass-mode', severity: 'medium', message: 'Claude Code skips the warning before entering bypass-permissions mode' });
        if (k === 'enableAllProjectMcpServers' && v === 'true')
          push({ ...base, id: 'mcp-auto-enable', severity: 'medium', message: 'Claude Code auto-starts every MCP server declared by any project .mcp.json' });
      }
      if (A === 'codex') {
        if (/sandbox_mode$/.test(k) && v === 'danger-full-access')
          push({ ...base, id: 'bypass-mode', severity: k.startsWith('profiles.') ? 'medium' : 'high', message: `Codex sandbox disabled (${k} = "danger-full-access")${k.startsWith('profiles.') ? ' in a profile' : ''}` });
        if (/approval_policy$/.test(k) && v === 'never')
          push({ ...base, id: 'never-ask', severity: 'medium', message: `Codex never asks for approval (${k} = "never")` });
        if (k === 'sandbox_workspace_write.network_access' && v === 'true')
          push({ ...base, id: 'network-on', severity: 'low', message: 'Codex sandboxed commands have network access (sandbox_workspace_write.network_access = true)' });
        if (k === 'default_permissions' && v === ':danger-full-access')
          push({ ...base, id: 'bypass-mode', severity: 'high', message: 'Codex default_permissions is ":danger-full-access"' });
      }
      if (A === 'gemini') {
        if (k === 'general.defaultApprovalMode' && /^yolo$/i.test(v))
          push({ ...base, id: 'bypass-mode', severity: 'high', message: 'Gemini CLI default approval mode is YOLO: every tool call is auto-approved' });
        if (k === 'general.defaultApprovalMode' && /^auto_?edit$/i.test(v))
          push({ ...base, id: 'accept-edits', severity: 'low', message: 'Gemini CLI auto-approves edits (defaultApprovalMode "auto_edit")' });
        if ((k === 'tools.autoAccept' || k === 'autoAccept') && v === 'true')
          push({ ...base, id: 'auto-accept', severity: 'medium', message: `Gemini CLI auto-accepts "safe" tool calls (${k} = true)` });
      }
      if (A === 'cursor' && (k === 'yolo' || k === 'force') && v === 'true')
        push({ ...base, id: 'bypass-mode', severity: 'high', message: `Cursor CLI runs everything without asking (${k} = true)` });
    }
  }

  // ── missing protections & inconsistencies ──
  const detected = agents.filter((a) => a.detected);
  const denies = (a: AgentSnapshot, cat: NativeRule['category']) => a.rules.filter((r) => r.category === cat && r.decision !== 'allow');
  for (const a of detected) {
    const readDenies = denies(a, 'read');
    if (!readDenies.some((r) => coversSecret(r.pattern) || /\\\.env/.test(r.pattern)))
      push({ id: 'secrets-unprotected', severity: 'medium', agent: a.agent, message: `nothing stops ${nameOf(a.agent)} from reading .env files (no read deny rule)` });
  }
  for (const a of detected) {
    for (const r of a.rules) {
      if (r.decision !== 'allow' || r.category !== 'shell' || r.pattern.startsWith('re:')) continue;
      for (const b of detected) {
        if (b === a) continue;
        for (const s of b.rules) {
          if (s.category !== 'shell' || s.decision === 'allow' || s.pattern.startsWith('re:')) continue;
          if (!shellPatternCovers(r.pattern, s.pattern)) continue;
          // does A itself restrict it?
          if (a.rules.some((x) => x.category === 'shell' && x.decision !== 'allow' && shellPatternCovers(x.pattern, s.pattern))) continue;
          push({
            id: 'inconsistent',
            severity: s.decision === 'deny' ? 'medium' : 'low',
            agent: a.agent,
            file: r.file,
            rule: r.native,
            message: `${q(s.pattern)} is ${s.decision === 'deny' ? 'denied' : 'set to ask'} in ${nameOf(b.agent)} but auto-approved in ${nameOf(a.agent)} by ${q(r.pattern)}`,
          });
        }
      }
    }
    // file read denies present elsewhere but missing here
    for (const b of detected) {
      if (b === a) continue;
      for (const s of denies(b, 'read')) {
        if (s.pattern.startsWith('re:') || s.decision !== 'deny') continue;
        if (a.rules.some((x) => x.category === 'read' && x.decision !== 'allow' && (x.pattern === s.pattern || pathPatternCovers(x.pattern, s.pattern)))) continue;
        push({ id: 'inconsistent', severity: 'low', agent: a.agent, message: `reading "${s.pattern}" is denied in ${nameOf(b.agent)} but not in ${nameOf(a.agent)}` });
      }
    }
  }
  findings.sort((x, y) => SEVERITY_RANK[y.severity] - SEVERITY_RANK[x.severity] || (x.agent ?? '').localeCompare(y.agent ?? ''));
  return { agents, findings };
}

export function worstSeverity(findings: Finding[]): Severity | null {
  let best: Severity | null = null;
  for (const f of findings) if (!best || SEVERITY_RANK[f.severity] > SEVERITY_RANK[best]) best = f.severity;
  return best;
}
