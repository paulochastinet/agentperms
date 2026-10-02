import { existsSync } from 'node:fs';
import path from 'node:path';

export const PRESETS = ['safe-readonly', 'node', 'python', 'go', 'rust'] as const;
export type Preset = (typeof PRESETS)[number];

interface PresetSpec {
  title: string;
  allow: string[];
  ask: string[];
  web: string[];
}

const COMMON_ALLOW = [
  'git status *',
  'git diff *',
  'git log *',
  'git show *',
  'git blame *',
  'git ls-files *',
  'git rev-parse *',
  'git branch --show-current',
  'ls *',
  'pwd',
  'cat *',
  'head *',
  'tail *',
  'wc *',
  'rg *',
  'grep *',
  'which *',
  'tree *',
];

const SPECS: Record<Preset, PresetSpec> = {
  'safe-readonly': {
    title: 'read-only inspection only',
    allow: [],
    ask: [],
    web: [],
  },
  node: {
    title: 'Node.js / TypeScript',
    allow: ['npm test *', 'npm run test *', 'npm run lint *', 'npm run typecheck *', 'npm run build *', 'node --version'],
    ask: ['npm install *', 'npm ci *'],
    web: ['docs.npmjs.com', 'nodejs.org', 'developer.mozilla.org', 'www.typescriptlang.org'],
  },
  python: {
    title: 'Python',
    allow: ['pytest *', 'python -m pytest *', 'python3 -m pytest *', 'mypy *', 'pip list *', 'pip show *'],
    ask: ['pip install *', 'uv sync *', 'uv add *'],
    web: ['docs.python.org', 'pypi.org'],
  },
  go: {
    title: 'Go',
    allow: ['go build *', 'go test *', 'go vet *', 'go list *', 'go version'],
    ask: ['go mod tidy *', 'go get *', 'go generate *'],
    web: ['pkg.go.dev', 'go.dev'],
  },
  rust: {
    title: 'Rust',
    allow: ['cargo build *', 'cargo check *', 'cargo test *', 'cargo clippy *', 'cargo fmt --check *', 'cargo tree *', 'cargo metadata *'],
    ask: ['cargo add *', 'cargo update *', 'cargo fmt *'],
    web: ['docs.rs', 'crates.io', 'doc.rust-lang.org'],
  },
};

const q = (s: string) => JSON.stringify(s);
const list = (items: string[], indent = '    ') => items.map((i) => `${indent}- ${q(i)}`).join('\n');

export function detectPreset(cwd: string): Preset {
  const has = (f: string) => existsSync(path.join(cwd, f));
  if (has('package.json')) return 'node';
  if (has('pyproject.toml') || has('requirements.txt') || has('setup.py') || has('uv.lock')) return 'python';
  if (has('go.mod')) return 'go';
  if (has('Cargo.toml')) return 'rust';
  return 'safe-readonly';
}

export function renderPreset(preset: Preset): string {
  const s = SPECS[preset];
  const allow = [...COMMON_ALLOW, ...s.allow];
  const web = ['docs.github.com', ...s.web];
  return `# agentperms.yaml: one permission policy for every AI coding agent.
# Preset: ${preset} (${s.title}). Docs: https://github.com/paulochastinet/agentperms
#
#   npx agentperms apply --dry-run   # preview the native configs (unified diff)
#   npx agentperms apply             # write them (non-destructive, backups in .agentperms-backup/)
#   npx agentperms audit             # what is allowed today, in every agent
#
# Shell patterns use Claude Code's syntax: "git diff *" matches "git diff" and "git diff <anything>";
# a pattern without "*" matches one exact command. Precedence everywhere: deny > ask > allow.
version: 1

shell:
  # Run without asking. Keep these read-only: \`agentperms suggest\` proposes more from your history.
  allow:
${list(allow)}
  # Always ask, even if a broader allow rule matches.
  ask:
${list(['git commit *', 'git push *', 'git checkout *', 'git reset *', 'curl *', 'wget *', ...s.ask])}
  # Never run.
  deny:
${list(['rm -rf *', 'sudo *', 'git push --force *', 'git push -f *', 'git reset --hard *', 'git clean *', 'chmod 777 *', 'dd *'])}

files:
  read:
    # Secrets stay out of the model's context. Patterns are gitignore-style (".env" = at any depth).
    deny:
${list(['.env', '.env.*', 'secrets/**', '*.pem', '*.key', 'id_rsa', 'id_ed25519'], '      ')}
  write:
    deny:
${list(['.git/**', '.env', '.env.*'], '      ')}

web:
  # Domains the agent may fetch without asking ("*.example.com" = any subdomain, not the apex).
  allow:
${list(web)}

mcp:
  # "server:tool", "server:*" or "*:tool".
  allow: []
  #   - "github:get_*"
  deny: []
  #   - "*:delete_*"

# Agents to generate configs for: claude, codex, gemini, cursor.
targets: [claude, codex, gemini, cursor]
`;
}
