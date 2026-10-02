import { isSeq, parseDocument, Scalar, YAMLSeq } from 'yaml';
import { parsePolicy } from './load.js';

function quoted(v: string): Scalar {
  const s = new Scalar(v);
  s.type = 'QUOTE_DOUBLE';
  return s;
}

/**
 * Add patterns to `shell.<list>` of an agentperms.yaml, preserving comments and formatting.
 * Returns the new text (validated) and the patterns actually added.
 */
export function addShellPatterns(text: string, list: 'allow' | 'ask', patterns: string[], file = 'agentperms.yaml'): { text: string; added: string[] } {
  const doc = parseDocument(text);
  const current = doc.getIn(['shell', list], true);
  const existing = isSeq(current) ? current.items.map((i) => String((i as { value?: unknown }).value ?? i)) : [];
  const toAdd = patterns.filter((p) => !existing.includes(p));
  if (!toAdd.length) return { text, added: [] };
  if (isSeq(current)) {
    // flow-style `[]` becomes block style when it gets items
    if (current.flow && current.items.length === 0) current.flow = false;
    for (const p of toAdd) current.add(quoted(p));
  } else {
    const seq = new YAMLSeq();
    for (const p of toAdd) seq.add(quoted(p));
    if (!doc.hasIn(['shell'])) doc.setIn(['shell'], doc.createNode({}));
    doc.setIn(['shell', list], seq);
  }
  const out = doc.toString({ lineWidth: 0 });
  parsePolicy(out, file); // throws if we somehow produced an invalid policy
  return { text: out, added: toAdd };
}
