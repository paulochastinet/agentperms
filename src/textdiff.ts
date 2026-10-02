/** Minimal unified diff (LCS over lines). Config files are small, O(n*m) is fine. */
export function unifiedDiff(oldText: string, newText: string, oldName: string, newName: string, context = 3): string {
  const a = oldText === '' ? [] : oldText.replace(/\n$/, '').split('\n');
  const b = newText === '' ? [] : newText.replace(/\n$/, '').split('\n');
  const n = a.length;
  const m = b.length;
  const lcs: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--) lcs[i]![j] = a[i] === b[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);

  type Op = { t: ' ' | '-' | '+'; s: string; ai: number; bi: number };
  const ops: Op[] = [];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) {
      ops.push({ t: ' ', s: a[i]!, ai: i, bi: j });
      i++;
      j++;
    } else if (j < m && (i >= n || lcs[i]![j + 1]! >= lcs[i + 1]![j]!)) {
      ops.push({ t: '+', s: b[j]!, ai: i, bi: j });
      j++;
    } else {
      ops.push({ t: '-', s: a[i]!, ai: i, bi: j });
      i++;
    }
  }
  if (!ops.some((o) => o.t !== ' ')) return '';

  const out = [`--- ${oldName}`, `+++ ${newName}`];
  let k = 0;
  while (k < ops.length) {
    if (ops[k]!.t === ' ') {
      k++;
      continue;
    }
    let start = Math.max(0, k - context);
    let end = k;
    // extend hunk while changes are within 2*context
    for (;;) {
      let e = end;
      while (e < ops.length && ops[e]!.t !== ' ') e++;
      let next = e;
      while (next < ops.length && ops[next]!.t === ' ') next++;
      if (next < ops.length && next - e <= context * 2) {
        end = next;
        continue;
      }
      end = Math.min(ops.length, e + context);
      break;
    }
    const hunk = ops.slice(start, end);
    const aStart = hunk[0]!.ai;
    const bStart = hunk[0]!.bi;
    const aLen = hunk.filter((o) => o.t !== '+').length;
    const bLen = hunk.filter((o) => o.t !== '-').length;
    out.push(`@@ -${aLen ? aStart + 1 : aStart},${aLen} +${bLen ? bStart + 1 : bStart},${bLen} @@`);
    for (const o of hunk) out.push(`${o.t}${o.s}`);
    k = end;
    start = end;
  }
  return out.join('\n') + '\n';
}
