import { copyFileSync, mkdirSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import {
  applyEdits,
  findNodeAtLocation,
  modify,
  parseTree,
  type FormattingOptions,
  type Node as JsonNode,
  type ParseError,
} from 'jsonc-parser';
import { parse as parseToml } from 'smol-toml';
import { TARGETS } from './targets/index.js';
import {
  BLOCK_BEGIN,
  BLOCK_END,
  MANAGED_HEADER,
  readText,
  scopeRoot,
  type FilePlan,
  type JsonListPlan,
} from './targets/common.js';
import type { Ctx, MappingWarning, Policy, Scope, TargetId } from './types.js';
import { unifiedDiff } from './textdiff.js';

export const BACKUP_DIR = '.agentperms-backup';
const STATE_FILE = 'state.json';

export interface StateFile {
  version: 1;
  /** file (relative to the scope root) -> list key -> entries agentperms added and still owns */
  files: Record<string, Record<string, string[]>>;
}

export interface FileChange {
  target: TargetId;
  file: string;
  /** path shown to the user (relative / ~) */
  display: string;
  before: string | null;
  after: string | null;
  added: string[];
  removed: string[];
}

export interface FileError {
  target: TargetId;
  file: string;
  message: string;
}

export interface Plan {
  scope: Scope;
  root: string;
  changes: FileChange[];
  /** Files that are already up to date. */
  unchanged: { target: TargetId; display: string }[];
  warnings: MappingWarning[];
  errors: FileError[];
  state: StateFile;
  stateChanged: boolean;
}

export interface PlanOptions {
  scope: Scope;
  targets: TargetId[];
  ctx: Ctx;
  /** Overwrite owned files that exist without the agentperms header. */
  force?: boolean;
}

export function displayPath(file: string, ctx: Ctx): string {
  if (file.startsWith(ctx.cwd + path.sep)) return path.relative(ctx.cwd, file);
  if (ctx.home && file.startsWith(ctx.home + path.sep)) return '~/' + path.relative(ctx.home, file);
  return file;
}

export function statePath(root: string): string {
  return path.join(root, BACKUP_DIR, STATE_FILE);
}

export function loadState(root: string): StateFile {
  const { text } = readText(statePath(root));
  if (!text) return { version: 1, files: {} };
  try {
    const s = JSON.parse(text) as StateFile;
    if (s && s.version === 1 && s.files && typeof s.files === 'object') return s;
  } catch {
    /* ignore corrupt state */
  }
  return { version: 1, files: {} };
}

// ───────────────────────────── JSON list merge ─────────────────────────────

function detectFormatting(text: string): FormattingOptions {
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const m = /^([ \t]+)\S/m.exec(text);
  if (m && m[1]!.startsWith('\t')) return { insertSpaces: false, tabSize: 1, eol };
  const size = m ? m[1]!.length : 2;
  return { insertSpaces: true, tabSize: size > 0 && size <= 8 ? size : 2, eol };
}

function stringItems(node: JsonNode | undefined): (string | null)[] {
  if (!node || node.type !== 'array') return [];
  return (node.children ?? []).map((c) => (c.type === 'string' ? (c.value as string) : null));
}

/** Skip whitespace and comments starting at `i`. */
function skipTrivia(t: string, i: number): number {
  for (;;) {
    while (i < t.length && /\s/.test(t[i]!)) i++;
    if (t.startsWith('//', i)) {
      const nl = t.indexOf('\n', i);
      i = nl === -1 ? t.length : nl + 1;
    } else if (t.startsWith('/*', i)) {
      const end = t.indexOf('*/', i + 2);
      i = end === -1 ? t.length : end + 2;
    } else return i;
  }
}

/**
 * Remove one element of a JSON(C) array, keeping the array valid (no dangling or trailing commas).
 * (jsonc-parser's modify() can corrupt the document when removing the last element.)
 */
export function removeArrayItem(t: string, arr: JsonNode, index: number): string {
  const items = arr.children ?? [];
  const item = items[index]!;
  const itemEnd = item.offset + item.length;
  if (items.length === 1) {
    return t.slice(0, arr.offset + 1) + t.slice(arr.offset + arr.length - 1);
  }
  if (index < items.length - 1) {
    // remove the element, its comma and the trivia up to the next element (same-line comments go with it)
    return t.slice(0, item.offset) + t.slice(items[index + 1]!.offset);
  }
  // last element: remove from the end of the previous element (eating the separating comma)
  const prevEnd = items[index - 1]!.offset + items[index - 1]!.length;
  let end = itemEnd;
  const after = skipTrivia(t, itemEnd);
  if (t[after] === ',') end = after + 1; // trailing comma
  return t.slice(0, prevEnd) + t.slice(end);
}

export interface JsonMergeResult {
  text: string;
  added: string[];
  removed: string[];
  managed: Record<string, string[]>;
}

/**
 * Merge desired entries into JSON(C) arrays without touching anything else:
 * - entries agentperms added before (state) and no longer desired are removed;
 * - desired entries missing from the file are appended;
 * - entries the user added by hand are never removed or reordered.
 */
export function mergeJsonLists(text: string | null, lists: JsonListPlan[], prev: Record<string, string[]>): JsonMergeResult {
  let t = text ?? '';
  const isNew = !t.trim();
  if (isNew) t = '{}';
  const errors: ParseError[] = [];
  const root = parseTree(t, errors, { allowTrailingComma: true });
  if (errors.length || !root) throw new Error('invalid JSON (fix it or remove the file, then re-run)');
  if (root.type !== 'object') throw new Error('expected a JSON object at the top level');
  const fmt = detectFormatting(isNew ? '{\n  "x": 1\n}' : t);
  const added: string[] = [];
  const removed: string[] = [];
  const managed: Record<string, string[]> = {};

  for (const list of lists) {
    const prevManaged = prev[list.key] ?? [];
    let tree = parseTree(t, [], { allowTrailingComma: true })!;
    let node = findNodeAtLocation(tree, list.path);
    if (node && node.type !== 'array') throw new Error(`"${list.path.join('.')}" is not an array`);
    // parent must be an object if it exists
    const parent = findNodeAtLocation(tree, list.path.slice(0, -1));
    if (parent && parent.type !== 'object') throw new Error(`"${list.path.slice(0, -1).join('.')}" is not an object`);

    const current = stringItems(node);
    const toRemove = new Set(prevManaged.filter((e) => !list.entries.includes(e)));
    // remove (descending index so earlier indices stay valid)
    for (let i = current.length - 1; i >= 0; i--) {
      const v = current[i];
      if (v !== null && v !== undefined && toRemove.has(v)) {
        const arr = findNodeAtLocation(parseTree(t, [], { allowTrailingComma: true })!, list.path)!;
        t = removeArrayItem(t, arr, i);
        removed.push(v);
      }
    }
    tree = parseTree(t, [], { allowTrailingComma: true })!;
    node = findNodeAtLocation(tree, list.path);
    const present = new Set(stringItems(node).filter((x): x is string => x !== null));
    const toAdd = list.entries.filter((e) => !present.has(e));
    if (toAdd.length) {
      if (!node) {
        t = applyEdits(t, modify(t, list.path, toAdd, { formattingOptions: fmt }));
      } else {
        for (const e of toAdd) t = applyEdits(t, modify(t, [...list.path, -1], e, { formattingOptions: fmt, isArrayInsertion: true }));
      }
      added.push(...toAdd);
    }
    const owned = list.entries.filter((e) => toAdd.includes(e) || prevManaged.includes(e));
    if (owned.length) managed[list.key] = owned;
  }
  if (isNew && !added.length) return { text: text ?? '', added, removed, managed };
  if (!t.endsWith('\n') && (isNew || (text ?? '').endsWith('\n'))) t += fmt.eol ?? '\n';
  return { text: t, added, removed, managed };
}

// ───────────────────────────── TOML managed block ─────────────────────────────

export function replaceTomlBlock(text: string | null, block: string | null): string | null {
  const t = text ?? '';
  const start = t.indexOf(BLOCK_BEGIN);
  const endIdx = t.indexOf(BLOCK_END);
  if (start !== -1 && endIdx !== -1 && endIdx > start) {
    const end = endIdx + BLOCK_END.length;
    const after = t.slice(end).replace(/^\r?\n/, '');
    if (block === null) {
      const before = t.slice(0, start).replace(/\n{2,}$/, '\n');
      const out = before + after;
      return text === null ? null : out;
    }
    return t.slice(0, start) + block + '\n' + after;
  }
  if (block === null) return text;
  if (!t.trim()) return block + '\n';
  return t.replace(/\s*$/, '\n') + '\n' + block + '\n';
}

// ───────────────────────────── planning ─────────────────────────────

export function planApply(policy: Policy, opts: PlanOptions): Plan {
  const { scope, ctx } = opts;
  const root = scopeRoot(scope, ctx);
  const prevState = loadState(root);
  const state: StateFile = { version: 1, files: { ...prevState.files } };
  const plan: Plan = { scope, root, changes: [], unchanged: [], warnings: [], errors: [], state, stateChanged: false };

  for (const id of opts.targets) {
    const out = TARGETS[id].generate(policy, scope, ctx);
    plan.warnings.push(...out.warnings);
    for (const fp of out.files) {
      try {
        planFile(id, fp, plan, prevState, opts);
      } catch (e) {
        plan.errors.push({ target: id, file: displayPath(fp.file, ctx), message: (e as Error).message });
      }
    }
  }
  plan.stateChanged = JSON.stringify(sortObj(prevState.files)) !== JSON.stringify(sortObj(state.files));
  return plan;
}

function sortObj(o: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]]));
}

function planFile(target: TargetId, fp: FilePlan, plan: Plan, prev: StateFile, opts: PlanOptions) {
  const { ctx } = opts;
  const relKey = path.relative(plan.root, fp.file).split(path.sep).join('/');
  const display = displayPath(fp.file, ctx);
  const { text: before, error } = readText(fp.file);
  if (error) throw new Error(`cannot read (${error})`);
  let after: string | null = before;
  let added: string[] = [];
  let removed: string[] = [];

  if (fp.kind === 'json-lists') {
    const r = mergeJsonLists(before, fp.lists, prev.files[relKey] ?? {});
    after = before === null && !r.added.length ? null : r.text;
    added = r.added;
    removed = r.removed;
    if (Object.keys(r.managed).length) plan.state.files[relKey] = r.managed;
    else delete plan.state.files[relKey];
  } else if (fp.kind === 'owned') {
    const owned = before === null || before.includes(MANAGED_HEADER);
    if (!owned && !opts.force) {
      throw new Error(`exists and was not created by agentperms; refusing to overwrite (move it away or re-run with --force; a backup is kept)`);
    }
    after = fp.content;
    if (before === null && after === null) return;
  } else {
    if (before !== null) {
      const outside = before.replace(new RegExp(`${escape(BLOCK_BEGIN)}[\\s\\S]*?${escape(BLOCK_END)}`), '');
      if (/^\s*\[permissions\.agentperms[\].]/m.test(outside))
        throw new Error('defines [permissions.agentperms] outside the agentperms block; rename it or remove it');
      try {
        parseToml(before);
      } catch (e) {
        throw new Error(`invalid TOML, not touching it (${(e as Error).message.split('\n')[0]})`);
      }
    }
    after = replaceTomlBlock(before, fp.block);
    if (after !== null && after !== before) {
      try {
        parseToml(after);
      } catch (e) {
        throw new Error(`the edited file would not be valid TOML (${(e as Error).message.split('\n')[0]}); not writing it`);
      }
    }
  }

  if (after === before) {
    if (before !== null) plan.unchanged.push({ target, display });
    return;
  }
  plan.changes.push({ target, file: fp.file, display, before, after, added, removed });
}

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ───────────────────────────── execution ─────────────────────────────

export interface ApplyResult {
  written: string[];
  deleted: string[];
  backupDir: string | null;
}

function atomicWrite(file: string, content: string) {
  mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.agentperms-tmp-${process.pid}`;
  writeFileSync(tmp, content);
  renameSync(tmp, file);
}

export function executePlan(plan: Plan, now = new Date()): ApplyResult {
  const res: ApplyResult = { written: [], deleted: [], backupDir: null };
  const stamp = now.toISOString().replace(/[:.]/g, '-');
  const backupRoot = path.join(plan.root, BACKUP_DIR, stamp);
  for (const c of plan.changes) {
    if (c.before !== null) {
      const relp = path.relative(plan.root, c.file);
      const dest = relp.startsWith('..') ? path.join(backupRoot, '_abs', c.file) : path.join(backupRoot, relp);
      mkdirSync(path.dirname(dest), { recursive: true });
      copyFileSync(c.file, dest);
      res.backupDir = backupRoot;
    }
    if (c.after === null) {
      unlinkSync(c.file);
      res.deleted.push(c.file);
    } else {
      atomicWrite(c.file, c.after);
      res.written.push(c.file);
    }
  }
  if (plan.stateChanged || plan.changes.length) {
    atomicWrite(statePath(plan.root), JSON.stringify({ ...plan.state, files: sortObj(plan.state.files) }, null, 2) + '\n');
  }
  return res;
}

export function planDiffs(plan: Plan): string {
  return plan.changes
    .map((c) => unifiedDiff(c.before ?? '', c.after ?? '', c.before === null ? '/dev/null' : `a/${c.display}`, c.after === null ? '/dev/null' : `b/${c.display}`))
    .join('');
}
