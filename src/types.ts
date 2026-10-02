export type Decision = 'allow' | 'ask' | 'deny';
export const DECISIONS: Decision[] = ['allow', 'ask', 'deny'];

export type TargetId = 'claude' | 'codex' | 'gemini' | 'cursor';
export const TARGET_IDS: TargetId[] = ['claude', 'codex', 'gemini', 'cursor'];
export const TARGET_NAMES: Record<TargetId, string> = {
  claude: 'Claude Code',
  codex: 'Codex CLI',
  gemini: 'Gemini CLI',
  cursor: 'Cursor CLI',
};

export type Scope = 'project' | 'user';

export interface RuleLists {
  allow: string[];
  ask: string[];
  deny: string[];
}

/** A validated, normalized agentperms.yaml. */
export interface Policy {
  version: 1;
  shell: RuleLists;
  files: { read: RuleLists; write: RuleLists };
  web: RuleLists;
  mcp: RuleLists;
  targets: TargetId[];
}

export type WarningLevel = 'info' | 'warn';

/** Something a target could not express exactly. */
export interface MappingWarning {
  target: TargetId;
  level: WarningLevel;
  message: string;
}

export interface Ctx {
  cwd: string;
  home: string;
}

export type Severity = 'high' | 'medium' | 'low';
export const SEVERITY_RANK: Record<Severity, number> = { high: 3, medium: 2, low: 1 };
