# Native permission formats (verified October 2026)

This is the reference `agentperms` is built against. Every claim links to the official source it was
checked against on **2026-10-02**. Agents change fast: if something here is out of date, please open an
issue with a link to the current docs.

- [Claude Code](#claude-code)
- [OpenAI Codex CLI](#openai-codex-cli)
- [Gemini CLI](#gemini-cli)
- [Cursor CLI](#cursor-cli)
- [How agentperms maps the policy](#how-agentperms-maps-the-policy)

---

## Claude Code

Source: [Configure permissions](https://code.claude.com/docs/en/permissions) ·
[Settings](https://code.claude.com/docs/en/settings)

| | |
|---|---|
| Files | `~/.claude/settings.json` (user), `.claude/settings.json` (project, shared), `.claude/settings.local.json` (project, personal), managed settings (enterprise) |
| Keys | `permissions.allow`, `permissions.ask`, `permissions.deny`, `permissions.defaultMode`, `permissions.additionalDirectories`, `permissions.disableBypassPermissionsMode` |
| Precedence | Rules are evaluated **deny → ask → allow**; the first match wins and specificity does not matter. A deny at any settings level cannot be overridden by an allow at another level. |
| Modes | `default` (alias `manual`), `acceptEdits`, `plan`, `auto`, `dontAsk`, `bypassPermissions` |

Rule syntax is `Tool` or `Tool(specifier)`:

- **Bash**: `Bash(npm run build)` is an exact match. `*` matches any text including spaces and can appear
  anywhere. A trailing ` *` that is the only wildcard also matches the bare command (`Bash(ls *)` matches
  `ls` but not `lsof`; `Bash(ls*)` matches `lsof`). The legacy `:*` suffix is equivalent to a trailing ` *`
  (`Bash(ls:*)`), and is only recognized at the end. Claude splits compound commands on `&&`, `||`, `;`,
  `|`, `|&`, `&` and newlines: an allow rule must match **each** sub-command; deny and ask rules apply when
  **any** sub-command matches. Wrappers such as `timeout`, `time`, `nice`, `nohup`, `stdbuf` and bare
  `xargs` are stripped before matching.
- **Read / Edit**: gitignore-style patterns. `//path` is absolute, `~/path` is relative to home, `/path`
  is relative to the settings source (project root for project settings), `path` or `./path` is relative
  to the current directory. A pattern without a slash (`.env`) matches at any depth. `Edit` rules cover
  every built-in editing tool; `Write(...)` path rules are accepted but never consulted, so use `Edit`.
  A `Read` deny also blocks edits of the same path and recognized file commands in Bash (`cat`, `head`...).
- **WebFetch**: `WebFetch(domain:example.com)`; `WebFetch(domain:*.example.com)` matches subdomains but not
  the apex; `WebFetch(domain:*)` matches every domain; a bare `WebFetch` allows/denies the whole tool.
- **MCP**: `mcp__server` or `mcp__server__*` (every tool of a server), `mcp__server__tool`. Deny and ask
  rules accept tool-name globs (`mcp__*`); **allow globs must start with a literal `mcp__<server>__`**.

## OpenAI Codex CLI

Sources: [Rules](https://developers.openai.com/codex/rules) (now served at
`learn.chatgpt.com/docs/agent-configuration/rules`) ·
[Configuration reference](https://developers.openai.com/codex/config-reference) ·
[Permissions](https://developers.openai.com/codex/permissions) ·
[execpolicy README](https://github.com/openai/codex/blob/main/codex-rs/execpolicy/README.md)

| | |
|---|---|
| Config | `~/.codex/config.toml` (user); `.codex/config.toml` (project, **only loaded in trusted projects**; trust is `[projects."<path>"] trust_level = "trusted"`) |
| Approval | `approval_policy = "on-request" \| "never" \| { granular = {...} }` (`"on-failure"` is deprecated) |
| Sandbox | `sandbox_mode = "read-only" \| "workspace-write" \| "danger-full-access"`, `[sandbox_workspace_write] network_access, writable_roots` |
| Profiles | `[profiles.<name>]` (model/approval/sandbox presets) |
| Permission profiles | `default_permissions = "<name>"` + `[permissions.<name>]` with `extends`, `filesystem` (`"read"`, `"write"`, `"deny"`; `":workspace_roots"` sub-table for workspace-relative globs such as `"**/*.env" = "deny"`) and `network` (`enabled`, `domains`). Configure **either** `default_permissions`/`[permissions]` **or** `sandbox_mode`/`[sandbox_workspace_write]`, not both. Unbounded `**` deny-read globs need `glob_scan_max_depth` on Linux/WSL/Windows. |
| MCP | `[mcp_servers.<id>] enabled_tools`, `disabled_tools`, `default_tools_approval_mode`, `[mcp_servers.<id>.tools.<tool>] approval_mode` |
| Command rules | Starlark files in `~/.codex/rules/*.rules` (user; the TUI writes `default.rules`) and `<repo>/.codex/rules/` (trusted projects) |

Command rules:

```python
prefix_rule(
    pattern = ["gh", "pr", ["view", "list"]],   # argv prefix; a nested list = alternatives
    decision = "prompt",                         # "allow" (default) | "prompt" | "forbidden"
    justification = "Viewing PRs needs approval",
    match = [...], not_match = [...],            # optional self-tests checked at load time
)
```

When several rules match, Codex applies the **most restrictive** decision (`forbidden > prompt > allow`).
Simple scripts joined with `&&`, `||`, `;` or `|` are split and each command is evaluated; scripts with
redirections, substitutions, variables or globs are evaluated as a single `bash -lc` invocation.
Test with `codex execpolicy check --pretty --rules <file> -- <command>`.

## Gemini CLI

Sources: [Policy engine](https://geminicli.com/docs/reference/policy-engine/)
([source](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md)) ·
[Configuration](https://geminicli.com/docs/reference/configuration/) ·
[`packages/core/src/policy/config.ts`](https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/policy/config.ts)

| | |
|---|---|
| Policy files | `~/.gemini/policies/*.toml` (user tier). The **workspace tier** (`<project>/.gemini/policies/*.toml`) is documented as **currently disabled**, and workspace settings cannot set `policyPaths`. Admin tier: `/etc/gemini-cli/policies`, `/Library/Application Support/GeminiCli/policies`, `C:\ProgramData\gemini-cli\policies`. |
| Rule | `[[rule]]` with `toolName` (string or list, wildcards like `mcp_server_*`), `mcpName`, `commandPrefix` (string or list), `commandRegex`, `argsPattern`, `decision = "allow" \| "deny" \| "ask_user"`, `priority` (0–999), `modes`, `denyMessage`, `interactive`, `allowRedirection` |
| Precedence | Highest priority wins: final priority = tier base (default 1, extension 2, workspace 3, user 4, admin 5) + `priority/1000`. |
| Settings | `general.defaultApprovalMode` (`default`, `auto_edit`, `plan`; YOLO via flag), `security.disableYoloMode`, `security.folderTrust.enabled`, `tools.core`, `tools.allowed`, `tools.exclude` (deprecated in favour of policies), `mcpServers.<name>.trust`, `mcpServers.<name>.excludeTools`, `mcp.allowed` / `mcp.excluded` |

Details that matter for a correct mapping (verified in the source):

- `commandPrefix` is matched against the JSON-encoded args and is **word-bounded**: the prefix must be
  followed by whitespace or the end of the command (`git diff` does not match `git difftool`).
- `commandRegex` is tested against the JSON args **after** `"command":"`, so a trailing `"` anchors the end
  of the command (exact match).
- The legacy `tools.allowed: ["run_shell_command(git status)"]` setting is converted into rules **plus an
  implicit "narrowing" deny of every other shell command** at a slightly lower priority, so agentperms never
  writes it.
- Built-in tool names: `run_shell_command`, `read_file`, `read_many_files`, `write_file`, `replace`,
  `web_fetch`, `glob`, `grep_search`, `list_directory`.

## Cursor CLI

Sources: [CLI permissions](https://cursor.com/docs/cli/reference/permissions) ·
[CLI configuration](https://cursor.com/docs/cli/reference/configuration)

| | |
|---|---|
| Files | `~/.cursor/cli-config.json` (global), `<project>/.cursor/cli.json` (project) |
| Keys | `permissions.allow`, `permissions.deny` (no "ask": anything not allowed prompts) |
| Precedence | Deny rules take precedence over allow rules |

Tokens:

- `Shell(commandBase)`: the first token of the command, any arguments (`Shell(git)`); `Shell(cmd:args)`
  matches the arguments with a glob (`Shell(curl:*)`).
- `Read(pathOrGlob)`, `Write(pathOrGlob)`: `**`, `*`, `?`; relative paths are workspace-scoped, absolute
  paths can target files outside the project.
- `WebFetch(domainOrPattern)`: `example.com` exact, `*.example.com` subdomains, `*` everything.
- `Mcp(server:tool)` with `*` wildcards on either side.

---

## How agentperms maps the policy

The policy uses Claude Code's shell syntax (the most expressive). Where an agent cannot express a rule
exactly, agentperms **never widens**: allows are dropped (the agent keeps prompting), denies/asks are
broadened (stricter), and a note is printed (`--verbose` shows all of them; real gaps are always shown).

| Policy | Claude Code | Codex CLI | Gemini CLI | Cursor CLI |
|---|---|---|---|---|
| `shell.allow "git status"` (exact) | `Bash(git status)` | not mapped (prefix-only rules) | `commandRegex = 'git status"'` | `Shell(git:status)` |
| `shell.allow "git diff *"` | `Bash(git diff *)` | `prefix_rule(["git","diff"], "allow")` | `commandPrefix = "git diff"` | `Shell(git:diff)`, `Shell(git:diff *)` |
| `shell.allow "ls *"` | `Bash(ls *)` | `prefix_rule(["ls"])` | `commandPrefix = "ls"` | `Shell(ls)` |
| `shell.allow "pwd"` (bare exact) | `Bash(pwd)` | not mapped | exact regex | not mapped |
| `shell.allow "git log * main"` | as is | not mapped | regex; `*` cannot cross quotes or shell operators | `Shell(git:log * main)` |
| `shell.ask` | `ask` | `decision = "prompt"` | `ask_user` | no "ask": left out (Cursor prompts by default); **mapped to deny** when a policy allow would cover it |
| `shell.deny "rm -rf *"` | `Bash(rm -rf *)` | `"forbidden"` | `deny`, priority 900 | `Shell(rm:-rf)`, `Shell(rm:-rf *)` |
| `shell.deny "git push * main"` | as is | broadened to `["git","push"]` | regex | glob |
| `shell.deny "curl * \| sh"` | split: `curl *` + `sh` | split | split | split |
| `files.read.deny ".env"` | `Read(.env)` | permission profile `"**/.env" = "deny"` (inactive until selected) | `read_file`/`read_many_files` + `argsPattern` | `Read(.env)`, `Read(**/.env)` |
| `files.write.deny ".git/**"` | `Edit(.git/**)` | profile `".git/**" = "read"` | `write_file`/`replace` + `argsPattern` | `Write(.git/**)` |
| `files.*.allow` | `Read(...)` / `Edit(...)` | not mapped (sandbox decides) | not mapped (absolute-path regex could escape the project) | `Read(...)` / `Write(...)` |
| `web.allow "*.npmjs.com"` | `WebFetch(domain:*.npmjs.com)` | not mapped (sandbox network) | not mapped (free-form prompt) | `WebFetch(*.npmjs.com)` |
| `web.deny` | `WebFetch(domain:...)` | not mapped | `web_fetch` + URL regex | `WebFetch(...)` |
| `mcp.allow "github:*"` | `mcp__github__*` | not mapped | `mcpName = "github"` | `Mcp(github:*)` |
| `mcp.allow "*:search"` | not mapped (allow needs a server) | not mapped | not mapped | `Mcp(*:search)` |
| `mcp.deny "*:delete_*"` | `mcp__*__delete_*` | **not enforced** (warning) | `toolName = "mcp_*_delete_*"` | `Mcp(*:delete_*)` |

Files written:

| | project scope (default) | `--scope user` |
|---|---|---|
| Claude Code | `.claude/settings.json` (merged) | `~/.claude/settings.json` (merged) |
| Codex CLI | `.codex/rules/agentperms.rules` (owned) + managed block in `.codex/config.toml` | `~/.codex/rules/agentperms.rules` + block in `~/.codex/config.toml` |
| Gemini CLI | `.gemini/policies/agentperms.toml` (owned; **not loaded by Gemini today**) | `~/.gemini/policies/agentperms.toml` (owned) |
| Cursor CLI | `.cursor/cli.json` (merged) | `~/.cursor/cli-config.json` (merged) |
