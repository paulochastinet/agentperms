/**
 * Secret masking for anything derived from shell history (adapted from promptwarden's detector).
 * `suggest` never prints a raw command: examples go through maskCommand() first.
 */

interface SecretPattern {
  re: RegExp;
  /** leading characters that are a public prefix (kept when masking) */
  prefix: number;
}

const SECRET_PATTERNS: SecretPattern[] = [
  { re: /\bsk-ant-(?:api|admin|oat)\d{2}-[A-Za-z0-9_-]{20,}/g, prefix: 7 },
  { re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g, prefix: 3 },
  { re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}\b/g, prefix: 4 },
  { re: /\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g, prefix: 11 },
  { re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g, prefix: 6 },
  { re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, prefix: 4 },
  { re: /\bxox[abposr]-[0-9A-Za-z-]{10,}\b/g, prefix: 5 },
  { re: /\bAIza[0-9A-Za-z_-]{35}\b/g, prefix: 4 },
  { re: /\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b/g, prefix: 8 },
  { re: /\bnpm_[A-Za-z0-9]{36}\b/g, prefix: 4 },
  { re: /\bhf_[A-Za-z]{30,}\b/g, prefix: 3 },
  { re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, prefix: 3 },
];

const MASK = '****';

/** Shannon entropy in bits per char. */
export function entropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let e = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

/** A word that looks like a credential (long, high-entropy, mixed classes). */
export function looksSecret(word: string): boolean {
  if (SECRET_PATTERNS.some((p) => { p.re.lastIndex = 0; return p.re.test(word); })) return true;
  const w = word.replace(/^['"]|['"]$/g, '');
  if (w.length < 20 || /^[\w.-]*\/[\w./-]*$/.test(w) && !/[A-Z].*\d|\d.*[A-Z]/.test(w)) return false;
  if (/^https?:\/\//.test(w)) return false;
  const classes = [/[a-z]/, /[A-Z]/, /\d/].filter((r) => r.test(w)).length;
  return classes >= 2 && entropy(w) >= 3.8 && /^[A-Za-z0-9_\-+/=.]+$/.test(w);
}

const SENSITIVE_KEY = /(?:TOKEN|SECRET|PASSW(?:OR)?D|PASSWD|PWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|SESSION|COOKIE|AUTH|DSN|DATABASE_URL|CONN(?:ECTION)?_?STR)/i;

/** Mask secrets inside a command line: known token formats, sensitive env/flag values, URL credentials, auth headers. */
export function maskCommand(cmd: string): string {
  let out = cmd;
  for (const p of SECRET_PATTERNS) {
    out = out.replace(p.re, (m) => m.slice(0, p.prefix) + MASK);
  }
  // URL credentials: scheme://user:pass@host
  out = out.replace(/\b([a-z][a-z0-9+.-]*:\/\/)([^\s:@/'"]+):([^\s@/'"]+)@/gi, (_m, s: string, u: string) => `${s}${u}:${MASK}@`);
  // Authorization headers
  out = out.replace(/((?:authorization|x-api-key|api-key|x-auth-token|cookie)\s*:\s*)(?:(bearer|basic|token)\s+)?([^\s'"]+)/gi, (_m, h: string, kind?: string) => `${h}${kind ? `${kind} ` : ''}${MASK}`);
  // FOO_TOKEN=value / export FOO_TOKEN=value
  out = out.replace(/\b([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;&|]+)/g, (m, k: string) => (SENSITIVE_KEY.test(k) ? `${k}=${MASK}` : m));
  // --token value / --password=value / -p value (mysql style)
  out = out.replace(/(--?(?:[\w-]*?[-_])?(?:token|secret|password|passwd|pass|api-?key|apikey|auth|key)\b[=\s]+)("[^"]*"|'[^']*'|[^\s;&|]+)/gi, (_m, f: string) => `${f}${MASK}`);
  out = out.replace(/(\s-p)(\S{3,})/g, (_m, f: string) => `${f}${MASK}`);
  // remaining long high-entropy words
  out = out.replace(/[A-Za-z0-9_\-+/=.]{20,}/g, (w) => (looksSecret(w) ? w.slice(0, 3) + MASK : w));
  return out;
}

/** Replace the home directory with `~` and drop user names from /Users/x, /home/x paths. */
export function redactPath(p: string, home: string): string {
  let out = p;
  if (home && home !== '/') out = out.split(home).join('~');
  return out.replace(/\/(?:Users|home)\/[^/\s'"]+/g, '/~');
}
