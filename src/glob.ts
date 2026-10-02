/**
 * Minimal gitignore-style path globs (enough for permission rules):
 *  - `*` matches within one path segment, `**` across segments, `?` one char;
 *  - a pattern without `/` (other than a trailing one) matches at any depth (`.env` == `** /.env`);
 *  - a leading `/` or `./` anchors at the project root.
 */
export function globToRegexSource(glob: string, segmentChar = '[^/]'): string {
  let out = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === '*') {
      if (glob[i + 1] === '*') {
        i++;
        if (glob[i + 1] === '/') {
          i++;
          out += '(?:.*/)?';
        } else out += '.*';
      } else out += `${segmentChar}*`;
    } else if (c === '?') out += segmentChar;
    else out += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return out;
}

/** True when a path pattern applies at any depth (gitignore semantics: no slash except a trailing one). */
export function isAnyDepth(pattern: string): boolean {
  const p = pattern.replace(/\/$/, '');
  return !p.includes('/') && !p.startsWith('~');
}

export function pathGlobRegex(pattern: string): RegExp {
  let p = pattern.trim();
  if (p.startsWith('./')) p = p.slice(2);
  if (p.endsWith('/')) p = p + '**';
  if (isAnyDepth(p)) return new RegExp(`^(?:.*/)?${globToRegexSource(p)}$`);
  if (p.startsWith('/')) p = p.slice(1);
  return new RegExp(`^${globToRegexSource(p)}$`);
}

export function pathMatches(pattern: string, relPath: string): boolean {
  return pathGlobRegex(pattern).test(relPath.replace(/^\.\//, ''));
}

/** Does a path pattern cover a sample path, or the other pattern literally? */
export function pathPatternCovers(a: string, b: string): boolean {
  const na = a.replace(/^\.\//, '');
  const nb = b.replace(/^\.\//, '');
  if (na === nb) return true;
  if (na === '**' || na === '**/*' || na === '*' && isAnyDepth(nb)) return true;
  return pathMatches(na, nb.replace(/\*\*?/g, 'x'));
}

/** Domain patterns: `example.com` exact, `*.example.com` any subdomain (not the apex), `*` everything. */
export function domainMatches(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase().replace(/\.$/, '');
  const h = host.toLowerCase().replace(/\.$/, '');
  if (p === '*') return true;
  if (p.startsWith('*.')) return h.endsWith(p.slice(1)) && h.length > p.length - 1;
  return p === h;
}

/** MCP patterns are `server:tool` with `*` globs on either side. */
export function mcpRegex(pattern: string): RegExp {
  const [server = '*', tool = '*'] = splitMcp(pattern);
  return new RegExp(`^${globToRegexSource(server, '.')}:${globToRegexSource(tool, '.')}$`);
}

export function splitMcp(pattern: string): [string, string] {
  const i = pattern.indexOf(':');
  if (i === -1) return [pattern, '*'];
  return [pattern.slice(0, i), pattern.slice(i + 1) || '*'];
}
