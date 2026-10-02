<h1 align="center">agentperms</h1>

<p align="center"><b>One permission policy for every AI coding agent.</b></p>

<p align="center">
  <a href="https://github.com/paulochastinet/agentperms/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/paulochastinet/agentperms/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://www.npmjs.com/package/agentperms"><img alt="npm" src="https://img.shields.io/npm/v/agentperms.svg"></a>
  <a href="./LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <img alt="Node >= 18.18" src="https://img.shields.io/badge/node-%3E%3D18.18-brightgreen.svg">
</p>

Write **`agentperms.yaml`** once and get the native permission config of **Claude Code, OpenAI Codex CLI,
Gemini CLI and Cursor CLI**. Audit what every agent is allowed to do today, and mine your local session
history for a safe allowlist, so you stop approving `git status` for the hundredth time.

```console
$ npx agentperms audit --home

  agentperms audit v0.1.0  ·  project + user (~)  ·  ~/code/app

               mode                      shell      read     write    web      mcp
  Claude Code  default                   49/0/0     —        —        1/0/0    —
  Cursor CLI   default                   —          —        —        —        —
               counts are allow/ask/deny rules
  read: ~/.claude/settings.json, ~/.claude/settings.local.json
  not detected: Codex CLI, Gemini CLI

  Who allows what (✓ allow  ? ask  ✗ deny  · no rule)
                            Claude   Cursor
  shell curl *              ✓        ·
  shell gh *                ✓        ·
  shell git push *          ✓        ·
  shell rm *                ✓        ·
  shell ssh *               ✓        ·
  shell npm install *       ✓        ·
  shell open *              ✓        ·
  shell python3 *           ✓        ·
  … 35 more rules (--verbose)

  Findings 15 high · 13 medium · 4 low
  HIGH "rm *" is auto-approved in Claude Code: deletes files  ~/.claude/settings.local.json
  HIGH "gh *" is auto-approved in Claude Code: every GitHub CLI command (merge, delete, secrets...)  ~/.claude/settings.local.json
  HIGH "git push *" is auto-approved in Claude Code: git push publishes to a remote  ~/.claude/settings.local.json
  HIGH "curl *" is auto-approved in Claude Code: network access (can download or upload anything)  ~/.claude/settings.local.json
  HIGH "ssh *" is auto-approved in Claude Code: remote shell  ~/.claude/settings.local.json
  MED  "python3 *" is auto-approved in Claude Code: runs arbitrary python3 code  ~/.claude/settings.local.json
  MED  "npx create-next-app *" is auto-approved in Claude Code: downloads and runs arbitrary packages  ~/.claude/settings.local.json
  MED  Claude Code skips the warning before entering bypass-permissions mode  ~/.claude/settings.json
  MED  nothing stops Claude Code from reading .env files (no read deny rule)
  MED  nothing stops Cursor CLI from reading .env files (no read deny rule)
  LOW  "npm install *" is auto-approved in Claude Code: npm install changes dependencies and runs install scripts
```

<sub>Real output from the author's machine, excerpted: rows and findings that named private hosts, IPs and
projects were removed. That is 49 "Yes, and don't ask again" clicks piling up in <code>settings.local.json</code>,
including <code>curl *</code>, <code>rm *</code> and <code>ssh *</code>.</sub>

## Why

**Permission fatigue is real.** Coding agents ask before running `git status`, `ls` or `npm test`, so you
click "Yes, and don't ask again" until the allowlist is a pile of one-off approvals, some of them far broader
than you meant (`Bash(curl:*)`, `Bash(rm:*)`). Then:

- every agent has its **own format**: Claude Code `Bash(git diff *)`, Codex `prefix_rule(...)` in Starlark,
  Gemini CLI policy-engine TOML, Cursor `Shell(git)`;
- the lists **drift**: `git push` is forbidden in Codex but auto-approved in Claude Code; `.env` is denied
  in one agent and readable in the other three;
- nobody can say **what is actually allowed** across the user and project files of four tools.

`agentperms` gives you one reviewed, version-controlled policy, generates each native config
**non-destructively**, audits what is really allowed everywhere (great in CI), and proposes an allowlist
from what you already run, without ever proposing network, destructive or secret-touching commands.

## Quickstart

```bash
npx agentperms init              # writes a commented agentperms.yaml (preset auto-detected)
npx agentperms apply --dry-run   # unified diff of every native file it would touch
npx agentperms apply             # write them (merged, backed up, idempotent)
npx agentperms audit             # what is allowed today, in every agent
npx agentperms suggest           # mine your local history for safe allow rules
```

Straight from GitHub (no npm publish needed):

```bash
npx github:paulochastinet/agentperms init && npx github:paulochastinet/agentperms apply
```

## The policy file

```yaml
version: 1
shell:
  allow: ["git status", "git diff *", "npm run test *", "ls *"]
  ask:   ["git push *"]
  deny:  ["rm -rf *", "curl * | sh"]
files:
  read:  { deny: [".env", ".env.*", "secrets/**"] }
  write: { deny: [".git/**"] }
web:  { allow: ["docs.github.com", "*.npmjs.com"] }
mcp:  { allow: ["github:*"], deny: ["*:delete_*"] }
targets: [claude, codex, gemini, cursor]
```

| Section | Values | Notes |
|---|---|---|
| `shell.allow / ask / deny` | Claude Code syntax: `git status` (exact), `git diff *` (also matches bare `git diff`), `git * main` | Legacy `ls:*` is accepted. Allow patterns may not contain shell operators; deny/ask patterns that do (`curl * \| sh`) are split into each sub-command (stricter), because every agent checks sub-commands separately. |
| `files.read / write` `.allow / ask / deny` | gitignore-style globs: `.env` (any depth), `secrets/**` (from the project root), `/abs/path`, `~/path` | |
| `web.allow / ask / deny` | `docs.github.com`, `*.npmjs.com` (subdomains, not the apex), `*` | URLs are reduced to their host. |
| `mcp.allow / ask / deny` | `server:tool`, `server:*`, `*:tool` | |
| `targets` | `claude`, `codex`, `gemini`, `cursor` | default: all four |

Precedence everywhere is **deny > ask > allow**. Validation errors point at the line:

```console
$ agentperms apply
✗ agentperms.yaml: invalid policy
  3:25 shell.allow[1]: allow patterns cannot contain shell operators (&&, ||, ;, |, &, $(...), backticks): agents check each sub-command separately. List each command on its own instead
  6:1 fiels: unknown key "fiels" (did you mean "files"?). Allowed: version, shell, files, web, mcp, targets
```

**Presets:** `agentperms init --preset safe-readonly | node | python | go | rust` (auto-detected from
`package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml`). Every preset allows only commands the built-in
safety model classifies as read-only, asks before commits, pushes and network tools, denies `rm -rf`,
`sudo`, force-push and friends, and hides `.env`, keys and `secrets/` from the model.

## Commands

| Command | What it does |
|---|---|
| `init [--preset <p>] [--force]` | Write a commented `agentperms.yaml`. |
| `apply [--target <list>] [--scope project\|user] [--dry-run] [--force]` | Generate native configs. `--dry-run` prints a unified diff and writes nothing. |
| `diff [--target <list>] [--scope project\|user] [--format text\|json]` | Drift between the policy and each native config. Exit `1` on drift. |
| `audit [--scope project\|user\|all] [--format text\|json\|markdown] [--fail-on high\|medium\|low]` | Read every agent's project + user config, normalize it into one table, flag risky grants and inconsistencies. `--home` (bare) is accepted and means "include user config", which is the default. |
| `suggest [--since 30d] [--min-count 3] [--source claude,codex,gemini] [--project] [--write] [--include-ask]` | Mine local history and propose allow rules. `--write` merges them into `agentperms.yaml` (comments preserved). |

Global: `--cwd <dir>`, `--home <dir>` (read/write user config somewhere else, used by the tests),
`--policy <file>`, `-v/--verbose`, `--no-color` (and `NO_COLOR`), `-h`, `-V`.
**Exit codes:** `0` ok · `1` findings at/above `--fail-on`, or drift (`diff`) · `2` usage or policy error.

### How `apply` writes (non-destructive by design)

- **JSON files** (Claude Code, Cursor) are edited in place with `jsonc-parser`: only the
  `permissions.allow|ask|deny` arrays are touched, one element at a time. Comments, formatting, unrelated
  keys and **rules you added by hand** are preserved. agentperms remembers which entries it added
  (`.agentperms-backup/state.json`), so when you remove a rule from the policy it removes exactly that entry
  and nothing else.
- **Files it owns** (`.codex/rules/agentperms.rules`, `.gemini/policies/agentperms.toml`) start with a
  "Managed by agentperms" header. A file with the same name that agentperms did not create is never
  overwritten (unless `--force`).
- **Codex `config.toml`**: only a delimited `# >>> agentperms managed block` is added/replaced; the rest of
  the file is left byte-for-byte intact, and the result is re-parsed before it is written.
- Originals are **backed up** to `.agentperms-backup/<timestamp>/` (project) or `~/.agentperms-backup/` (user).
  Add `.agentperms-backup/` to your `.gitignore`.
- **Idempotent**: running `apply` twice changes nothing the second time; `diff` then exits `0`.

## What each agent supports

agentperms never widens a permission to make a rule fit. If an agent can't express a rule, an allow is
dropped (the agent keeps asking) and a deny/ask is broadened (stricter); you get a note either way
(`--verbose` shows every note; gaps that leave a deny unenforced are always shown).

| | Claude Code | Codex CLI | Gemini CLI | Cursor CLI |
|---|:-:|:-:|:-:|:-:|
| Files | `.claude/settings.json` | `.codex/rules/agentperms.rules` + `config.toml` block | `.gemini/policies/agentperms.toml` | `.cursor/cli.json` |
| Shell allow / ask / deny | ✓ / ✓ / ✓ | prefix ✓ / ✓ / ✓ (exact allow not mapped) | ✓ / ✓ / ✓ | ✓ / → deny or default prompt / ✓ |
| Exact command (`git status`) | ✓ | allow not mapped, deny broadened | ✓ (anchored regex) | ✓ (`Shell(git:status)`) |
| File read/write deny | ✓ | permission profile (inactive until you select it) | ✓ (`argsPattern`) | ✓ |
| File allow | ✓ | — (sandbox) | — | ✓ |
| Web allow / deny | ✓ / ✓ | — (sandbox network) | — / ✓ | ✓ / ✓ |
| MCP allow / deny | named server ✓ / ✓ | — / **not enforced** | named server ✓ / ✓ | ✓ / ✓ |
| Project scope works today | ✓ | trusted projects only | **no** (workspace policies are disabled upstream; use `--scope user`) | ✓ |

The full rule-by-rule mapping, with links to each vendor's docs, is in [docs/formats.md](./docs/formats.md).

## audit in CI

Fail a PR that commits a dangerous grant (`Bash(*)`, `bypassPermissions`, `danger-full-access`, YOLO,
`curl *`, `rm *`, writes to `.git`, `.env` readable...), and post the report to the job summary:

```yaml
# .github/workflows/agentperms.yml
name: agentperms
on: [pull_request]

jobs:
  permissions:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - name: Audit agent permissions
        run: npx -y agentperms audit --scope project --format markdown --fail-on high >> "$GITHUB_STEP_SUMMARY"
      - name: Native configs match agentperms.yaml
        run: npx -y agentperms diff
```

`audit` checks: bypass modes (`bypassPermissions`, `danger-full-access`, `approval_policy = "never"`, YOLO,
auto-accept), shell grants classified by the safety model (any command, network, destructive, privilege
escalation, arbitrary code, publishing), `.env` readable (explicit allow or no deny at all), writes to
`.git/**` or everywhere, `WebFetch` to any domain, MCP auto-approval for every server or trusted servers, and
**inconsistencies** ("`git push *` is denied in Codex CLI but auto-approved in Cursor CLI by `git *`").
Use `--format json` for a stable machine-readable report (`schemaVersion: 1`).

## suggest: an allowlist from what you already run

```console
$ npx agentperms suggest

  agentperms suggest · since 30d · Claude Code 34,216 cmds / 13 sessions
  34,216 shell commands mined locally (read-only), 572 distinct prefixes. Nothing left this machine.

  Suggested allow (read-only, seen ≥3×, never rejected, not in your policy yet)
  #   pattern                           count   sessions  approved  source
  1   cat *                             8232    13        8232      claude
  2   tail *                            6318    11        6314      claude
  3   ls *                              3840    11        3840      claude
  4   wc *                              1404    10        1404      claude
  5   npx vitest *                      879     3         877       claude
  6   git diff *                        781     5         781       claude
  7   git status *                      704     7         704       claude
  8   npx tsc *                         528     6         528       claude
  9   git log *                         440     7         439       claude
  10  git show *                        340     4         340       claude
  … 49 more (--limit)

  Keep asking (mutating or runs project code; add to shell.ask with --write --include-ask)
  sed * (12246) · mkdir * (645) · awk * (636) · npx eslint * (398) · cp * (390) · find * (369)

  Never auto-approved (network, destructive, arbitrary code or secrets: keep a human in the loop)
  curl * (1316) · npx tsx * (830) · rm * (573) · gh api * (99) · xargs * (97) · bash * (90)
```

<sub>Real output from the author's machine (30 days, ~9 s), excerpted; project-specific script names removed.</sub>

How it works:

1. **Reads** (never writes) local transcripts: Claude Code `~/.claude/projects/**/*.jsonl` (`Bash` tool calls
   and whether you approved or rejected them), Codex `~/.codex/sessions/**/rollout-*.jsonl`
   (`exec_command`, `shell`, `shell_command`, `local_shell_call`), Gemini CLI `~/.gemini/tmp/*/chats/*.json`.
   `--project` keeps only sessions recorded under `--cwd`.
2. Splits compound commands (`a && b | c`, quotes and heredocs respected), strips wrappers (`timeout 30`,
   `NODE_ENV=test`), and generalizes each command into a prefix pattern: `git diff HEAD~1 -- src` →
   `git diff *`, `npm run test -- --run` → `npm run test *`, `python3 -m pytest -q` → `python3 -m pytest *`.
   Commands it can't read safely (`git -C dir ...`, substitutions, secret-looking tokens) are not generalized.
3. Classifies each pattern with the [safety model](#safety-model) and ranks by count. Only `safe` patterns
   seen `--min-count` times, **never rejected**, and not already in your policy are suggested.
4. `--write` appends them to `shell.allow` in `agentperms.yaml` (comments kept). Review, then `apply`.

**Privacy:** 100% local. No network calls, no telemetry, transcripts are opened read-only. Output contains
patterns and counts, not commands; the optional examples (`--verbose`) are **masked** first: API keys and
tokens (OpenAI, Anthropic, GitHub, AWS, Slack, Stripe, npm, JWTs...), `*_TOKEN=`/`*_SECRET=`/`PASSWORD=`
values, `Authorization:` headers, `user:password@` in URLs, `--password`/`--token` flags and any long
high-entropy string. Paths under your home directory are shown as `~`.

## Safety model

| Class | Examples | `suggest` | `audit` (when auto-approved) |
|---|---|---|---|
| **safe** (read-only, local) | `git status/diff/log/show/blame`, `ls`, `cat`, `rg`, `grep`, `wc`, `jq`, `npm test`, `npm run lint/typecheck/build`, `cargo test/check/clippy`, `go test/vet`, `pytest`, `npx tsc`, `docker ps` | suggested as allow | — |
| **ask** (mutates local state / runs project code) | `git commit/add/checkout`, `npm install`, `sed`, `awk`, `find`, `mkdir`, `cp`, `mv`, `node script.js`, `make` | listed, `--include-ask` adds them to `shell.ask` | low/medium when broad |
| **never** (network, destructive, privilege, arbitrary code, secrets) | `curl`, `wget`, `ssh`, `scp`, `rm -rf`, `sudo`, `git push`, `git reset --hard`, `git clean`, `npm publish`, `npx <anything>`, `bash -c`, `eval`, `env`, `python *`, anything piped into `sh`, anything touching `.env`/SSH keys/cloud credentials | never suggested | high/medium |

Patterns are judged by the **widest** command they match: `git status *` is safe, `git *` is not (it
includes `git push --force`). The risky-command knowledge is shared with
[promptwarden](https://github.com/paulochastinet/promptwarden).

## FAQ

**Will `apply` clobber my existing settings?**
No. It edits only the permission arrays (JSON) or its own files/blocks, keeps comments and hand-written
rules, backs up every file it changes, and `--dry-run` shows the exact diff first.

**Claude Code already offers to remember approvals. Why this?**
Those approvals are per-agent, accumulate silently (often broader than intended) and never get reviewed.
agentperms makes the allowlist a reviewed file in your repo, consistent across four agents, and audits the
leftovers.

**Why are some rules "not mapped" for Codex/Gemini?**
Because mapping them would grant more than you wrote. Codex rules are argv *prefixes*, so an exact
`git status` can't be allowed without allowing `git status <anything>`; Gemini's `web_fetch` takes a free
prompt, so a domain allow could approve other URLs. Those agents simply keep asking.

**Gemini CLI ignores the project file?**
Yes, today. Gemini documents the workspace policy tier as disabled, and workspace settings can't add policy
paths. Use `agentperms apply --scope user --target gemini` to install the policy for your user.

**My Codex file rules don't apply.**
Codex file-system rules live in a *permission profile*, which replaces `sandbox_mode`. agentperms writes the
profile but doesn't switch your sandbox for you: set `default_permissions = "agentperms"` when you're ready.

**Does it send anything anywhere?** No. Everything runs locally, offline.

**Windows?** Should work (paths use `node:path`), but CI covers Linux and macOS only for now.

## Limitations

- Pattern matching is modelled on each agent's documented behaviour; edge cases (wrappers, odd quoting) can
  differ. Agent shell rules are not a security boundary: use the agents' sandboxes for that.
- Cursor's glob semantics for arguments containing `/` are not documented; `Shell(cmd:args *)` may not match
  every path argument.
- Codex: MCP rules and web rules are not generated; file rules need the profile to be activated.
  Gemini: project-scope policies are not loaded upstream; web allows are not generated.
- `audit` reads user and project files only: managed/enterprise policies, Claude Code `~/.claude.json`
  per-project state, CLI flags and IDE settings are not included.
- `suggest` reads Claude Code and Codex transcript formats as of October 2026 and Gemini CLI chat files
  best-effort; formats are undocumented and may change.
- Removing a target from `targets:` leaves its previously generated entries in place (remove them with a
  final `apply` that still includes the target, or by hand).

## Part of a toolkit

`agentperms` is one of four small, single-purpose CLIs for people building with AI agents:

- [**context-diet**](https://github.com/paulochastinet/context-diet): see what your coding agent loads before you type a word (instruction files, skills, MCP tool schemas) and how many tokens it costs.
- [**promptwarden**](https://github.com/paulochastinet/promptwarden): scan agent skills, rules and MCP configs for prompt injection, hidden Unicode, exfiltration and secrets.
- [**mcp-diff**](https://github.com/paulochastinet/mcp-diff): catch breaking and risky changes in MCP servers before your users' agents do.
- **agentperms** (this repo): one permission policy for Claude Code, Codex, Gemini CLI and Cursor, plus an audit of risky grants.

## Contributing

Issues and PRs welcome, see [CONTRIBUTING.md](./CONTRIBUTING.md). Security issues: [SECURITY.md](./SECURITY.md).

## License

[MIT](./LICENSE) © 2026 Paulo Chastinet
