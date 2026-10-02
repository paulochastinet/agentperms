/**
 * Built-in safety model used by `suggest` (what may be proposed for the allowlist) and by `audit`
 * (which grants are dangerous).
 *
 *  safe   read-only / local-only inspection (git status, ls, rg, npm test...)  -> may be suggested as allow
 *  ask    mutates local state or runs project code that is usually fine           -> suggested as ask at most
 *  never  network, destructive, privilege escalation, arbitrary code, exfiltration -> never suggested
 *
 * Classes for patterns are computed for the *widest* command the pattern can match:
 * `git *` is "never" because it also matches `git push --force`.
 */
import { hasOperator, parseShellPattern, splitCommand, splitPatternOnOperators, stripWrappers } from './shell.js';
import type { Severity } from './types.js';

export type SafetyClass = 'safe' | 'ask' | 'never';

export interface Verdict {
  cls: SafetyClass;
  reason: string;
  /** How bad it is to have this pre-approved (audit). Only set for risky grants. */
  severity?: Severity;
}

const CLASS_RANK: Record<SafetyClass, number> = { safe: 0, ask: 1, never: 2 };
export function worst(a: Verdict, b: Verdict): Verdict {
  if (CLASS_RANK[b.cls] > CLASS_RANK[a.cls]) return b;
  if (CLASS_RANK[b.cls] === CLASS_RANK[a.cls] && sevRank(b.severity) > sevRank(a.severity)) return b;
  return a;
}
const sevRank = (s?: Severity) => (s === 'high' ? 3 : s === 'medium' ? 2 : s === 'low' ? 1 : 0);

const safe = (reason: string): Verdict => ({ cls: 'safe', reason });
const ask = (reason: string, severity?: Severity): Verdict => ({ cls: 'ask', reason, severity });
const never = (reason: string, severity: Severity = 'high'): Verdict => ({ cls: 'never', reason, severity });

/** Read-only tools whose every argument form is harmless. */
const SAFE_ANY_ARGS = new Set([
  'ls', 'pwd', 'cat', 'head', 'tail', 'wc', 'rg', 'grep', 'egrep', 'fgrep', 'ag', 'ack', 'which', 'whereis', 'type',
  'file', 'stat', 'tree', 'du', 'df', 'date', 'cal', 'uname', 'whoami', 'id', 'groups', 'hostname', 'uptime', 'echo',
  'printf', 'true', 'false', 'basename', 'dirname', 'realpath', 'readlink', 'sort', 'uniq', 'cut', 'tr', 'diff',
  'cmp', 'comm', 'jq', 'yq', 'column', 'nl', 'od', 'hexdump', 'strings', 'sha1sum', 'sha256sum', 'sha512sum',
  'shasum', 'md5', 'md5sum', 'cksum', 'test', '[', 'seq', 'ps', 'lsof', 'sw_vers', 'fd', 'bat', 'exa', 'eza', 'less',
  'more', 'wc', 'tac', 'rev', 'fold', 'fmt', 'expand', 'paste', 'join', 'look', 'locale', 'nproc', 'arch', 'cloc',
  'tokei', 'lsblk', 'free', 'vm_stat', 'pgrep', 'zcat', 'zgrep', 'xxd', 'man', 'tldr', 'sleep',
]);

/** Programs that are network / destructive / privilege / arbitrary-code with any arguments. */
const NEVER_ANY: Record<string, string> = {
  curl: 'network access (can download or upload anything)',
  wget: 'network access (can download anything)',
  ssh: 'remote shell',
  scp: 'network file copy',
  sftp: 'network file copy',
  rsync: 'network/remote file sync',
  nc: 'raw network socket',
  ncat: 'raw network socket',
  netcat: 'raw network socket',
  socat: 'raw network socket',
  telnet: 'raw network socket',
  ftp: 'network file transfer',
  sudo: 'privilege escalation',
  su: 'privilege escalation',
  doas: 'privilege escalation',
  dd: 'raw disk writes',
  shred: 'destroys files',
  mkfs: 'formats disks',
  diskutil: 'disk management',
  eval: 'evaluates arbitrary code',
  exec: 'replaces the shell with arbitrary code',
  source: 'runs arbitrary shell code',
  '.': 'runs arbitrary shell code',
  bash: 'arbitrary shell code',
  sh: 'arbitrary shell code',
  zsh: 'arbitrary shell code',
  fish: 'arbitrary shell code',
  dash: 'arbitrary shell code',
  ksh: 'arbitrary shell code',
  powershell: 'arbitrary shell code',
  pwsh: 'arbitrary shell code',
  osascript: 'arbitrary AppleScript (UI automation, keychain prompts)',
  security: 'macOS keychain access',
  crontab: 'persistence (cron jobs)',
  launchctl: 'persistence (launchd)',
  env: 'prints every environment variable (secrets) or runs arbitrary programs',
  printenv: 'prints environment variables (secrets)',
  export: 'changes the environment of later commands',
  xargs: 'runs arbitrary programs',
  kill: 'kills processes',
  killall: 'kills processes',
  pkill: 'kills processes',
  reboot: 'reboots the machine',
  shutdown: 'shuts down the machine',
  open: 'opens apps/URLs (network, arbitrary apps)',
  'xdg-open': 'opens apps/URLs',
  aws: 'cloud API with your credentials',
  gcloud: 'cloud API with your credentials',
  az: 'cloud API with your credentials',
  doctl: 'cloud API with your credentials',
  flyctl: 'cloud deploys',
  vercel: 'cloud deploys',
  netlify: 'cloud deploys',
  heroku: 'cloud deploys',
  firebase: 'cloud deploys',
  wrangler: 'cloud deploys',
  railway: 'cloud deploys',
  npx: 'downloads and runs arbitrary packages',
  bunx: 'downloads and runs arbitrary packages',
  pnpx: 'downloads and runs arbitrary packages',
  uvx: 'downloads and runs arbitrary packages',
  pipx: 'downloads and runs arbitrary packages',
};

const INTERPRETERS = new Set([
  'node', 'deno', 'bun', 'python', 'python2', 'python3', 'ruby', 'perl', 'php', 'lua', 'Rscript', 'julia', 'tsx', 'ts-node',
]);

/** Dev tools usually installed in the project, run through npx. */
const NPX_LOCAL_TOOLS = new Set(['tsc', 'vitest', 'jest', 'eslint', 'prettier', 'biome', 'mocha', 'playwright', 'stylelint', 'tsd', 'attw', 'publint']);

const VERSION_FLAGS = new Set(['--version', '-v', '-V', 'version', '--help', '-h', 'help']);

const SECRET_REF =
  /(?:^|[\s"'=/])(?:\.env(?:\.[\w.-]+)?|id_(?:rsa|ed25519|ecdsa|dsa)\b|\.ssh\/|\.aws\/credentials|\.netrc|\.git-credentials|\.npmrc|\.pypirc|\.docker\/config\.json|\.kube\/config|credentials\.json|secrets?\.(?:ya?ml|json|env|toml))/i;

const SCRIPT_SAFE = /^(?:test|tests|test:[\w:-]+|lint|lint:[\w:-]+|typecheck|type-check|types|check|check:[\w:-]+|format:check|fmt:check|build|build:[\w:-]+|compile|tsc|vitest|jest)$/;

function flagsOf(words: string[]): string[] {
  return words.filter((w) => w.startsWith('-'));
}

/** Classify a parsed command (words after wrappers). `open` = further arbitrary arguments allowed (pattern ends with `*`). */
export function classifyWords(input: string[], open: boolean): Verdict {
  const { words } = stripWrappers(input);
  const base0 = words[0];
  if (base0 === undefined || base0 === '*') return never('any command at all');
  if (base0.includes('*')) return never('wildcard in the program name matches any program');
  const base = base0.replace(/^.*\//, '');
  const args = words.slice(1);
  const sub = args[0];
  const all = words.join(' ');

  if (SECRET_REF.test(` ${all}`)) return never('touches credential files (.env, SSH keys, cloud credentials)');

  if (/^mkfs/.test(base)) return never(NEVER_ANY.mkfs!);
  if (NEVER_ANY[base]) {
    if (base === 'env' || base === 'printenv') return never(NEVER_ANY[base]!, 'medium');
    if (base === 'kill' || base === 'killall' || base === 'pkill') return never(NEVER_ANY[base]!, 'medium');
    if (base === 'open' || base === 'xdg-open') return never(NEVER_ANY[base]!, 'medium');
    if (['npx', 'bunx', 'pnpx'].includes(base) && sub && NPX_LOCAL_TOOLS.has(sub)) {
      const inner = classifyWords(args, open);
      return inner.cls === 'safe' ? safe(`runs the project's ${sub} (${base} may download it if it is not installed)`) : inner;
    }
    if (['npx', 'bunx', 'pnpx', 'uvx', 'pipx'].includes(base) && !open && args.length) {
      return ask(`${NEVER_ANY[base]}; this exact invocation may be fine`, 'medium');
    }
    if (['npx', 'bunx', 'pnpx', 'uvx', 'pipx', 'xargs'].includes(base)) return never(NEVER_ANY[base]!, 'medium');
    return never(NEVER_ANY[base]!);
  }

  if (base === 'rm' || base === 'rmdir' || base === 'unlink' || base === 'trash') {
    const rf = flagsOf(args).some((f) => /^-[a-zA-Z]*[rRf]/.test(f) || f === '--recursive' || f === '--force');
    if (rf || open) return never('deletes files' + (rf ? ' recursively/forcefully' : ''));
    return ask('deletes a file', 'medium');
  }
  if (base === 'chmod' || base === 'chown' || base === 'chgrp') {
    if (args.some((a) => /^(?:0?777|a\+rwx|ugo\+rwx|o\+w)$/.test(a)) || open) return never('changes permissions (can make files world-writable)', 'medium');
    return ask('changes file permissions');
  }
  if (INTERPRETERS.has(base) || /^python\d/.test(base)) {
    if (sub !== undefined && VERSION_FLAGS.has(sub) && args.length === 1) return safe('prints the version');
    if ((sub === '-m' || sub === '-m') && args[1] && /^(?:pytest|unittest|mypy|pyright|ruff|black|flake8|pylint|pip|venv|http\.server)$/.test(args[1])) {
      const mod = args[1];
      if (mod === 'pip') return classifyPip(args.slice(2), open);
      if (mod === 'http.server') return ask('starts a local web server');
      if (mod === 'black' || (mod === 'ruff' && args[2] === 'format')) return ask('reformats files');
      return safe(`runs ${mod}`);
    }
    if (args.some((a) => a === '-e' || a === '-c' || a === '--eval' || a === '-p' || a === '--print')) return never('evaluates inline code', 'high');
    if (sub && !sub.startsWith('-') && !sub.includes('*')) return ask(`runs the ${base} script ${sub}`, open ? 'low' : undefined);
    return open ? never(`runs arbitrary ${base} code`, 'medium') : ask(`runs ${base}`, 'low');
  }

  switch (base) {
    case 'git':
      return classifyGit(args, open);
    case 'npm':
    case 'pnpm':
    case 'yarn':
    case 'bun':
      return classifyNodePm(base, args, open);
    case 'pip':
    case 'pip3':
      return classifyPip(args, open);
    case 'uv':
      if (sub === 'run' && args[1] && /^(?:pytest|mypy|ruff|pyright)$/.test(args[1]) && !(args[1] === 'ruff' && args[2] === 'format')) return safe(`runs ${args[1]}`);
      if (sub === 'pip') return classifyPip(args.slice(1), open);
      if (sub === 'sync' || sub === 'lock' || sub === 'add' || sub === 'remove') return ask('changes dependencies');
      if (sub === 'tree' || (sub !== undefined && VERSION_FLAGS.has(sub))) return safe('read-only');
      return sub === 'run' ? never('runs arbitrary commands', 'medium') : ask('uv command');
    case 'poetry':
      if (sub === 'run' && args[1] && /^(?:pytest|mypy|ruff)$/.test(args[1])) return safe(`runs ${args[1]}`);
      if (sub === 'show' || sub === 'check' || (sub !== undefined && VERSION_FLAGS.has(sub))) return safe('read-only');
      if (sub === 'publish') return never('publishes a package');
      return sub === 'run' ? never('runs arbitrary commands', 'medium') : ask('changes the environment');
    case 'pytest':
    case 'mypy':
    case 'pyright':
    case 'tsc':
    case 'vitest':
    case 'jest':
    case 'mocha':
    case 'flake8':
    case 'pylint':
    case 'shellcheck':
    case 'hadolint':
      if (base === 'vitest' && sub === 'watch') return ask('starts a watcher');
      return safe(`runs ${base} (read-only checks/tests)`);
    case 'eslint':
    case 'prettier':
    case 'biome':
    case 'ruff':
    case 'black':
    case 'rustfmt':
    case 'gofmt':
    case 'stylelint':
      if (args.some((a) => /^--(?:fix|write)$/.test(a) || a === '-w' || a === 'format' || a === '--apply') || (base === 'black' && !args.includes('--check'))) return ask('rewrites files');
      if (open) return ask(`${base} can rewrite files with --fix/--write`);
      return safe(`runs ${base} in check mode`);
    case 'cargo':
      return classifyCargo(args, open);
    case 'go':
      return classifyGo(args, open);
    case 'make':
    case 'just':
    case 'task':
    case 'rake':
    case 'gradle':
    case './gradlew':
    case 'gradlew':
    case 'mvn':
    case './mvnw':
      if (sub && /^(?:test|check|lint|verify|build|compile)$/.test(sub) && !open) return safe(`runs the project's ${sub} target`);
      return ask(`runs project-defined tasks`, open ? 'low' : undefined);
    case 'docker':
    case 'podman':
      return classifyDocker(args, open);
    case 'kubectl':
      if (sub && /^(?:get|describe|logs|explain|version|config|top|api-resources)$/.test(sub) && !(sub === 'config' && args[1] !== 'view' && args[1] !== 'get-contexts' && args[1] !== 'current-context'))
        return safe('reads cluster state');
      return never('changes a cluster');
    case 'terraform':
    case 'tofu':
      if (sub && /^(?:fmt|validate|version|show|providers)$/.test(sub) && !(sub === 'fmt' && !args.includes('-check'))) return safe('read-only');
      if (sub === 'plan' || sub === 'init') return ask('contacts providers');
      return never('changes infrastructure');
    case 'gh':
      return classifyGh(args, open);
    case 'brew':
      if (sub && /^(?:list|ls|info|search|outdated|deps|leaves|config|doctor|--version)$/.test(sub)) return safe('read-only');
      return never('installs software');
    case 'find':
      if (args.some((a) => /^-(?:delete|exec|execdir|ok|okdir|fprint|fls|fprintf)$/.test(a))) return never('find with -exec/-delete runs or deletes', 'medium');
      return open ? ask('find can -delete or -exec', 'low') : safe('lists files');
    case 'sed':
      if (args.some((a) => /^-[a-zA-Z]*i/.test(a) || a.startsWith('--in-place'))) return ask('edits files in place');
      if (args.some((a) => /(^|[;}])\s*[ew]\b|\/[ew]\s*$/.test(a))) return never('sed e/w commands run code or write files', 'medium');
      return open ? ask('sed can edit files in place (-i)', 'low') : safe('stream edit to stdout');
    case 'awk':
    case 'gawk':
      if (args.some((a) => /system\s*\(|\|\s*"|print\s*>/.test(a))) return never('awk can run commands / write files', 'medium');
      return open ? ask('awk can run commands via system()', 'low') : safe('text processing');
    case 'tee':
      return ask('writes files');
    case 'touch':
    case 'mkdir':
    case 'cp':
    case 'mv':
    case 'ln':
    case 'install':
    case 'patch':
    case 'tar':
    case 'unzip':
    case 'zip':
    case 'gzip':
    case 'gunzip':
      return ask('changes files');
    case 'cd':
    case 'pushd':
    case 'popd':
      return safe('changes directory');
    case 'node_modules/.bin/vitest':
      return safe('runs tests');
    case 'code':
    case 'cursor':
      return ask('opens an editor');
    case 'base64':
      return args.some((a) => a === '-d' || a === '--decode' || a === '-D') || open ? ask('can decode data (often a payload)') : safe('encodes data');
    case 'sysctl':
      if (args.some((a) => a === '-w' || a.includes('='))) return never('changes kernel settings', 'medium');
      return open ? ask('sysctl -w changes kernel settings') : safe('reads kernel settings');
    case 'openssl':
      return ask('crypto operations');
    case 'claude':
    case 'codex':
    case 'gemini':
    case 'cursor-agent':
      return never('starts another agent (inherits or bypasses permissions)', 'medium');
  }
  if (SAFE_ANY_ARGS.has(base)) return safe('read-only');
  if (base0.startsWith('./') || base0.startsWith('../') || base0.startsWith('/') || base0.startsWith('~')) return ask('runs a local script');
  return ask('unknown program');
}

function classifyGit(args: string[], open: boolean): Verdict {
  // git -C <dir> / -c k=v before the subcommand
  let i = 0;
  while (i < args.length && args[i]!.startsWith('-')) {
    if (args[i] === '-c') return never('git -c can set config that runs programs (core.fsmonitor, core.sshCommand...)', 'medium');
    if (args[i] === '-C' || args[i] === '--git-dir' || args[i] === '--work-tree') i++;
    i++;
  }
  const sub = args[i];
  const rest = args.slice(i + 1);
  if (sub === undefined) return open ? never('every git subcommand, including push/reset --hard/clean', 'high') : safe('git usage');
  if (sub.includes('*')) return never('every git subcommand, including push/reset --hard/clean', 'high');
  const hasF = rest.some((a) => /^-[a-zA-Z]*f/.test(a) || a === '--force' || a.startsWith('--force-with-lease') || a.startsWith('+'));
  switch (sub) {
    case 'status':
    case 'diff':
    case 'log':
    case 'show':
    case 'blame':
    case 'ls-files':
    case 'ls-tree':
    case 'rev-parse':
    case 'rev-list':
    case 'describe':
    case 'shortlog':
    case 'grep':
    case 'reflog':
    case 'cat-file':
    case 'merge-base':
    case 'name-rev':
    case 'whatchanged':
    case 'count-objects':
    case 'check-ignore':
    case 'version':
    case '--version':
    case 'help':
      if (rest.some((a) => a.startsWith('--output') || a === '--ext-diff' || a.startsWith('--textconv'))) return ask('writes output to a file / runs external diff');
      return safe(`git ${sub} is read-only`);
    case 'branch':
    case 'tag':
    case 'remote':
    case 'stash':
    case 'worktree':
    case 'config':
      if (!open && rest.every((a) => /^(?:-a|-r|-v|-vv|--list|-l|--show-current|--all|--verbose|list|show|get|--get|--get-regexp|-n\d*|--contains|--merged|--no-merged)$/.test(a)))
        return safe(`git ${sub} (listing)`);
      if (sub === 'config' && open) return never('git config can set hooks/programs that run later', 'medium');
      if (rest.some((a) => a === '-D' || a === '--delete' || a === 'drop' || a === 'clear' || a === '-d')) return ask(`git ${sub} deletes refs`, 'low');
      return ask(`git ${sub} can modify refs/config`);
    case 'add':
    case 'commit':
    case 'checkout':
    case 'switch':
    case 'restore':
    case 'merge':
    case 'rebase':
    case 'cherry-pick':
    case 'revert':
    case 'mv':
    case 'rm':
    case 'apply':
    case 'am':
    case 'init':
    case 'bisect':
    case 'notes':
    case 'submodule':
    case 'sparse-checkout':
      if (sub === 'checkout' && rest.includes('.') ) return ask('discards local changes', 'medium');
      return ask(`git ${sub} changes the working tree or history`);
    case 'fetch':
    case 'pull':
    case 'clone':
    case 'ls-remote':
      return never(`git ${sub} talks to a remote`, 'low');
    case 'push':
      return never(hasF ? 'force-push rewrites remote history' : 'git push publishes to a remote', hasF || open ? 'high' : 'medium');
    case 'reset':
      if (rest.includes('--hard') || open) return never('git reset --hard discards work', open ? 'medium' : 'high');
      return ask('moves HEAD');
    case 'clean':
      return never('git clean deletes untracked files', 'high');
    case 'gc':
    case 'prune':
    case 'filter-branch':
    case 'filter-repo':
    case 'update-ref':
      return never(`git ${sub} rewrites/deletes repository data`, 'medium');
    case 'send-email':
    case 'daemon':
    case 'credential':
      return never(`git ${sub} sends data / exposes credentials`, 'high');
  }
  return ask(`git ${sub}`);
}

function classifyNodePm(pm: string, args: string[], open: boolean): Verdict {
  const sub = args[0];
  if (sub === undefined) return open ? never(`every ${pm} command, including publish`, 'high') : ask(`${pm} install`);
  if (sub.includes('*')) return never(`every ${pm} command, including publish`, 'high');
  if (VERSION_FLAGS.has(sub)) return safe('prints version/help');
  if (sub === 'test' || sub === 't' || sub === 'tst') return safe('runs the project test script');
  if (sub === 'run' || sub === 'run-script' || (pm !== 'npm' && !KNOWN_PM_SUBS.has(sub))) {
    const script = sub === 'run' || sub === 'run-script' ? args[1] : sub;
    if (script === undefined) return open ? never('runs any package script', 'medium') : safe('lists scripts');
    if (script.includes('*')) return never('runs any package script', 'medium');
    if (SCRIPT_SAFE.test(script)) return safe(`runs the "${script}" script`);
    if (/^(?:dev|start|serve|preview|watch)/.test(script)) return ask(`starts a long-running "${script}" script`);
    if (/publish|release|deploy|upload/.test(script)) return never(`"${script}" publishes or deploys`, 'medium');
    return ask(`runs the "${script}" script`);
  }
  switch (sub) {
    case 'ls':
    case 'list':
    case 'll':
    case 'why':
    case 'explain':
    case 'config':
    case 'root':
    case 'prefix':
    case 'bin':
    case 'help':
      if (sub === 'config' && args[1] && args[1] !== 'get' && args[1] !== 'list') return ask('changes npm config');
      return safe(`${pm} ${sub} is read-only`);
    case 'outdated':
    case 'view':
    case 'info':
    case 'show':
    case 'search':
    case 'audit':
      if (sub === 'audit' && args[1] === 'fix') return ask('changes dependencies');
      return ask(`${pm} ${sub} queries the registry`, undefined);
    case 'install':
    case 'i':
    case 'ci':
    case 'add':
    case 'remove':
    case 'rm':
    case 'uninstall':
    case 'update':
    case 'up':
    case 'upgrade':
    case 'dedupe':
    case 'prune':
    case 'link':
    case 'rebuild':
      if (args.some((a) => a === '-g' || a === '--global')) return never('installs globally', 'medium');
      return ask(`${pm} ${sub} changes dependencies and runs install scripts`, open ? 'low' : undefined);
    case 'exec':
    case 'x':
    case 'dlx':
    case 'create':
    case 'init':
      return never(`${pm} ${sub} downloads and runs arbitrary packages`, 'medium');
    case 'publish':
    case 'unpublish':
    case 'deprecate':
    case 'dist-tag':
    case 'owner':
    case 'access':
    case 'token':
    case 'login':
    case 'adduser':
    case 'logout':
    case 'pack':
      if (sub === 'pack') return ask('creates a tarball');
      return never(`${pm} ${sub} changes the registry or credentials`, 'high');
  }
  return ask(`${pm} ${sub}`);
}

const KNOWN_PM_SUBS = new Set([
  'install', 'i', 'add', 'remove', 'rm', 'uninstall', 'update', 'up', 'upgrade', 'run', 'test', 't', 'exec', 'x', 'dlx',
  'publish', 'ls', 'list', 'why', 'info', 'view', 'outdated', 'audit', 'create', 'init', 'link', 'pack', 'login', 'config',
  'ci', 'dedupe', 'prune', 'rebuild', 'store', 'workspace', 'workspaces', 'cache', 'bin', 'root', 'prefix', 'help', 'version', 'pm',
]);

function classifyPip(args: string[], open: boolean): Verdict {
  const sub = args[0];
  if (sub && /^(?:list|show|freeze|check|--version|-V|help|inspect)$/.test(sub)) return safe(`pip ${sub} is read-only`);
  if (sub === 'install' || sub === 'uninstall' || sub === 'download') return ask(`pip ${sub} changes the environment (network)`, open ? 'low' : undefined);
  return open ? never('any pip command', 'low') : ask(`pip ${sub ?? ''}`.trim());
}

function classifyCargo(args: string[], open: boolean): Verdict {
  const sub = args[0];
  if (sub === undefined || sub.includes('*')) return open ? never('every cargo command, including publish', 'medium') : safe('cargo');
  if (/^(?:test|build|check|clippy|doc|tree|metadata|bench|--version|version|help|nextest|verify-project|locate-project|search)$/.test(sub)) {
    if (sub === 'clippy' && args.includes('--fix')) return ask('rewrites files');
    return safe(`cargo ${sub}`);
  }
  if (sub === 'fmt') return args.includes('--check') ? safe('cargo fmt --check') : ask('reformats files');
  if (sub === 'publish' || sub === 'yank' || sub === 'login' || sub === 'owner') return never(`cargo ${sub} changes the registry`, 'high');
  if (sub === 'install') return never('installs a binary from the network', 'medium');
  return ask(`cargo ${sub}`);
}

function classifyGo(args: string[], open: boolean): Verdict {
  const sub = args[0];
  if (sub === undefined || sub.includes('*')) return open ? never('every go command', 'medium') : safe('go');
  if (/^(?:test|build|vet|list|version|env|doc|help)$/.test(sub)) {
    if (sub === 'env' && args.includes('-w')) return ask('changes go env');
    return safe(`go ${sub}`);
  }
  if (sub === 'fmt' || sub === 'generate' || sub === 'mod' || sub === 'get' || sub === 'work') return ask(`go ${sub} changes files`);
  if (sub === 'run') return open ? never('runs arbitrary go code', 'medium') : ask('runs a go program');
  if (sub === 'install') return never('installs a binary from the network', 'medium');
  return ask(`go ${sub}`);
}

function classifyDocker(args: string[], open: boolean): Verdict {
  const sub = args[0] === 'compose' ? args[1] : args[0];
  if (sub === undefined || sub.includes('*')) return open ? never('every docker command (run --privileged, rm...)', 'high') : safe('docker');
  if (/^(?:ps|images|logs|inspect|version|info|stats|top|port|history|ls|config|events)$/.test(sub)) return safe(`docker ${sub} is read-only`);
  if (sub === 'build' || sub === 'pull' || sub === 'up' || sub === 'start' || sub === 'stop' || sub === 'restart') return ask(`docker ${sub}`);
  if (sub === 'run' || sub === 'exec') {
    if (args.some((a) => a === '--privileged' || /^-v\s*\/:/.test(a) || a.startsWith('--pid=host') || a === '--network=host')) return never('privileged container / host mounts');
    return open ? never(`docker ${sub} runs arbitrary code with host mounts`, 'medium') : ask(`docker ${sub}`);
  }
  if (sub === 'push' || sub === 'login') return never(`docker ${sub} talks to a registry with your credentials`, 'medium');
  return never(`docker ${sub} can delete containers/images/volumes`, 'low');
}

function classifyGh(args: string[], open: boolean): Verdict {
  const [group, action] = args;
  if (group === undefined || group.includes('*')) return open ? never('every GitHub CLI command (merge, delete, secrets...)', 'high') : safe('gh');
  if (group === 'auth') return action === 'status' ? safe('gh auth status') : never('gh auth handles credentials', 'high');
  if (group === 'api') return never('gh api can call any GitHub endpoint with your token', 'medium');
  if (group === 'secret' || group === 'ssh-key' || group === 'gpg-key') return never(`gh ${group} manages credentials`, 'high');
  if (action && /^(?:view|list|status|diff|checks|search|watch)$/.test(action)) return ask(`gh ${group} ${action} reads from GitHub (network)`);
  if (action && /^(?:delete|merge|close|archive|transfer|rename|edit|lock)$/.test(action)) return never(`gh ${group} ${action} changes GitHub state`, 'medium');
  return ask(`gh ${group}${action ? ` ${action}` : ''} talks to GitHub`, open ? 'low' : undefined);
}

/** Classify a policy / native shell pattern (`git status *`, `npm run test *`, `*`). */
export function classifyPattern(pattern: string): Verdict {
  if (hasOperator(pattern)) {
    // native rules sometimes contain whole compound commands: classify every segment
    if (!pattern.includes('*')) return classifyCommand(pattern);
    return splitPatternOnOperators(pattern).reduce<Verdict>((v, seg) => worst(v, classifyPattern(seg)), safe('read-only'));
  }
  const p = parseShellPattern(pattern);
  if (!p.tokens.length || p.text === '*') return never('any command at all');
  const open = !p.exact;
  // use the literal tokens; a wildcard token is kept so classification knows it is open-ended
  const words = p.innerWildcard ? p.tokens : p.literalTokens;
  return classifyWords(words.length ? words : p.tokens, open);
}

/** Classify a concrete command line (worst sub-command wins). Pipes into shells are always "never". */
export function classifyCommand(cmd: string): Verdict {
  if (/\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\|\s*(?:python\d?|node|perl|ruby)\s*(?:-\s*)?$/m.test(cmd)) return never('pipes content into a shell/interpreter');
  if (/\/dev\/tcp\//.test(cmd)) return never('network redirection');
  let v: Verdict = safe('read-only');
  const segs = splitCommand(cmd);
  if (!segs.length) return ask('empty command');
  for (const s of segs) {
    if (!s.words) {
      v = worst(v, ask('uses command substitution'));
      continue;
    }
    let sv = classifyWords(s.words, false);
    if (s.redirect && sv.cls === 'safe') sv = ask('redirects output into a file');
    v = worst(v, sv);
  }
  return v;
}
