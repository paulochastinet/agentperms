/**
 * Shell helpers shared by the policy model, the generators, `audit` and `suggest`.
 *
 * Policy shell patterns use Claude Code's semantics (the most expressive of the four agents):
 *  - a pattern without `*` matches one exact command;
 *  - `*` matches any text (including spaces);
 *  - a trailing ` *` that is the only wildcard also matches the bare command (`ls *` matches `ls`);
 *  - the legacy `:*` suffix is accepted and normalized to ` *`.
 */

export const OPERATOR_RE = /&&|\|\||;|\||&(?!>)|\n|`|\$\(/;

export interface ShellPattern {
  /** Normalized text (single spaces, `:*` -> ` *`). */
  text: string;
  tokens: string[];
  /** No wildcard at all. */
  exact: boolean;
  /** Ends with ` *` and that is the only wildcard. */
  trailing: boolean;
  /** Tokens before the first token containing `*`. */
  literalTokens: string[];
  /** Contains a `*` that is not the single trailing ` *`. */
  innerWildcard: boolean;
}

export function normalizeShellPattern(raw: string): string {
  let t = raw.replace(/\s+/g, ' ').trim();
  if (/:\*$/.test(t) && !/\s:\*$/.test(t)) t = t.slice(0, -2).trimEnd() + ' *';
  return t;
}

export function parseShellPattern(raw: string): ShellPattern {
  const text = normalizeShellPattern(raw);
  const tokens = text.split(' ').filter(Boolean);
  const stars = (text.match(/\*/g) ?? []).length;
  const trailing = stars === 1 && text.endsWith(' *');
  const literalTokens: string[] = [];
  for (const t of tokens) {
    if (t.includes('*')) break;
    literalTokens.push(t);
  }
  return { text, tokens, exact: stars === 0, trailing, literalTokens, innerWildcard: stars > 0 && !trailing };
}

/** Split a pattern that contains shell operators into its segments (`curl * | sh` -> [`curl *`, `sh`]). */
export function splitPatternOnOperators(text: string): string[] {
  return text
    .split(/&&|\|\||;|\|&|\||&|\n/)
    .map((s) => normalizeShellPattern(s))
    .filter((s) => s && s !== '*');
}

export function hasOperator(text: string): boolean {
  return OPERATOR_RE.test(text);
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

/** Regex that matches a single (already split) command against a policy pattern. */
export function shellPatternRegex(pattern: string): RegExp {
  const p = parseShellPattern(pattern);
  if (p.trailing) {
    const prefix = p.text.slice(0, -2);
    return new RegExp(`^${escapeRe(prefix)}(?: .*)?$`, 's');
  }
  return new RegExp(`^${p.text.split('*').map(escapeRe).join('.*')}$`, 's');
}

export function shellPatternMatches(pattern: string, command: string): boolean {
  return shellPatternRegex(pattern).test(command.replace(/\s+/g, ' ').trim());
}

/**
 * Does pattern `a` match every command that pattern `b` matches? (Conservative approximation.)
 * Used to detect when an allow rule shadows an ask/deny rule.
 */
export function shellPatternCovers(a: string, b: string): boolean {
  const pa = parseShellPattern(a);
  const pb = parseShellPattern(b);
  if (pa.text === pb.text) return true;
  if (pa.text === '*') return true;
  if (pb.exact) return shellPatternMatches(pa.text, pb.text);
  if (pa.trailing) {
    const prefix = pa.text.slice(0, -2);
    const bLit = pb.text.slice(0, pb.text.indexOf('*'));
    return bLit === prefix || bLit.startsWith(prefix + ' ');
  }
  if (pa.exact) return false;
  // generic: replace b's wildcards with a probe and test
  return shellPatternMatches(pa.text, pb.text.replace(/\*/g, 'X'));
}

/** Can a command matched by pattern `a` also be matched by pattern `b`? (Overlap, approximate.) */
export function shellPatternsOverlap(a: string, b: string): boolean {
  return shellPatternCovers(a, b) || shellPatternCovers(b, a);
}

// ───────────────────────── command tokenizing (for suggest/audit) ─────────────────────────

export interface Segment {
  /** The sub-command text, trimmed. */
  text: string;
  /** Shell words with quotes removed. `null` if the segment uses constructs we don't parse. */
  words: string[] | null;
  /** Has a redirection to a file (`>`, `>>`). */
  redirect: boolean;
  /** Uses command substitution / backticks / process substitution. */
  substitution: boolean;
}

/**
 * Split a shell command line into sub-commands on `&&`, `||`, `;`, `|`, `&` and newlines,
 * respecting quotes. Heredoc bodies are dropped.
 */
export function splitCommand(cmd: string): Segment[] {
  const out: Segment[] = [];
  let cur = '';
  let words: string[] = [];
  let word = '';
  let inWord = false;
  let redirect = false;
  let substitution = false;
  let quote: '"' | "'" | null = null;
  let heredoc: string | null = null;

  const pushWord = () => {
    if (inWord) words.push(word);
    word = '';
    inWord = false;
  };
  const pushSeg = () => {
    pushWord();
    const text = cur.trim();
    if (text) out.push({ text, words: substitution ? null : words, redirect, substitution });
    cur = '';
    words = [];
    redirect = false;
    substitution = false;
  };

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i]!;
    if (heredoc !== null) {
      // skip until a line equal to the delimiter
      const nl = cmd.indexOf('\n', i);
      const line = cmd.slice(i, nl === -1 ? cmd.length : nl);
      i = nl === -1 ? cmd.length : nl;
      if (line.trim() === heredoc) heredoc = null;
      continue;
    }
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else if (ch === '\\' && quote === '"' && i + 1 < cmd.length) {
        word += cmd[++i];
        cur += ch + cmd[i];
        continue;
      } else {
        if (quote === '"' && (ch === '`' || (ch === '$' && cmd[i + 1] === '('))) substitution = true;
        word += ch;
      }
      cur += ch;
      inWord = true;
      continue;
    }
    if (ch === '\\' && i + 1 < cmd.length) {
      if (cmd[i + 1] === '\n') {
        i++;
        cur += ' ';
        pushWord();
        continue;
      }
      word += cmd[i + 1];
      cur += ch + cmd[i + 1];
      inWord = true;
      i++;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      inWord = true;
      cur += ch;
      continue;
    }
    if (ch === '`' || (ch === '$' && cmd[i + 1] === '(') || ((ch === '<' || ch === '>') && cmd[i + 1] === '(')) {
      substitution = true;
      // swallow up to the matching close so its contents don't get split
      const close = ch === '`' ? '`' : ')';
      let depth = 0;
      let j = i + (ch === '`' ? 1 : 2);
      for (; j < cmd.length; j++) {
        const c = cmd[j];
        if (close === ')' && c === '(') depth++;
        if (c === close) {
          if (depth === 0) break;
          depth--;
        }
      }
      cur += cmd.slice(i, j + 1);
      word += cmd.slice(i, j + 1);
      inWord = true;
      i = j;
      continue;
    }
    if (ch === '<' && cmd[i + 1] === '<' && cmd[i + 2] !== '<') {
      const m = /^<<-?\s*(['"]?)([\w.-]+)\1/.exec(cmd.slice(i));
      if (m) {
        heredoc = m[2]!;
        cur += m[0];
        i += m[0].length - 1;
        // body starts at the next newline
        const nl = cmd.indexOf('\n', i);
        if (nl === -1) heredoc = null;
        else {
          // keep scanning the rest of the current line normally
          const rest = cmd.slice(i + 1, nl);
          const sub = splitCommand(rest);
          if (sub.length) {
            // the rest of the heredoc line may contain operators (e.g. `<<EOF | sh`)
            const first = sub[0]!;
            cur += ' ' + first.text;
            for (const w of first.words ?? []) words.push(w);
            redirect ||= first.redirect;
            substitution ||= first.substitution;
            pushSeg();
            for (const s of sub.slice(1)) out.push(s);
          }
          i = nl;
        }
        continue;
      }
    }
    if (ch === '>' || (ch === '&' && cmd[i + 1] === '>')) {
      const m = /^(?:&>>?|>>?|>\|)\s*(&\d|\S+)?/.exec(cmd.slice(i));
      const target = m?.[1] ?? '';
      if (!/^&\d$/.test(target) && target !== '/dev/null') redirect = true;
      pushWord();
      cur += m ? m[0] : ch;
      i += (m ? m[0].length : 1) - 1;
      continue;
    }
    if (/\d/.test(ch) && cmd[i + 1] === '>' && !inWord) {
      // 2>&1, 2>/dev/null
      const m = /^\d>>?\s*(&\d|\S+)/.exec(cmd.slice(i));
      if (m) {
        if (!/^&\d$/.test(m[1]!) && m[1] !== '/dev/null') redirect = true;
        cur += m[0];
        i += m[0].length - 1;
        continue;
      }
    }
    if (ch === '<') {
      const m = /^<\s*\S+/.exec(cmd.slice(i));
      pushWord();
      cur += m ? m[0] : ch;
      i += (m ? m[0].length : 1) - 1;
      continue;
    }
    if (ch === ';' || ch === '\n' || ch === '|' || ch === '&') {
      if (ch === '&' && cmd[i + 1] === '&') i++;
      else if (ch === '|' && (cmd[i + 1] === '|' || cmd[i + 1] === '&')) i++;
      pushSeg();
      continue;
    }
    if (ch === ' ' || ch === '\t') {
      pushWord();
      cur += ch;
      continue;
    }
    if (ch === '#' && !inWord && (cur === '' || /\s$/.test(cur))) {
      // comment to end of line
      const nl = cmd.indexOf('\n', i);
      i = (nl === -1 ? cmd.length : nl) - 1;
      continue;
    }
    word += ch;
    cur += ch;
    inWord = true;
  }
  pushSeg();
  return out;
}

const WRAPPERS = new Set(['timeout', 'time', 'nice', 'nohup', 'stdbuf', 'command', 'builtin', 'noglob']);

/** Strip leading `VAR=value` assignments and simple wrappers (`timeout 30`, `nice -n 5`, `time`...). */
export function stripWrappers(words: string[]): { words: string[]; envNames: string[] } {
  const envNames: string[] = [];
  let i = 0;
  for (;;) {
    const w = words[i];
    if (w === undefined) break;
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(w);
    if (m) {
      envNames.push(m[1]!);
      i++;
      continue;
    }
    if (w === 'command' && words[i + 1] === '-v') break;
    if (WRAPPERS.has(w)) {
      i++;
      // skip wrapper options/args: timeout <dur>, nice -n N, stdbuf -oL
      while (i < words.length && (/^-/.test(words[i]!) || (w === 'timeout' && /^\d+[smhd]?$/.test(words[i]!)))) {
        if (w === 'nice' && words[i] === '-n') i++;
        i++;
      }
      continue;
    }
    break;
  }
  return { words: words.slice(i), envNames };
}
