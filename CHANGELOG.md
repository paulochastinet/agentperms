# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-02

### Added

- `agentperms.yaml` policy (version 1): `shell`, `files.read`, `files.write`, `web` and `mcp` allow / ask / deny
  lists plus `targets`, validated with line-numbered errors and "did you mean" hints.
- `init` with commented presets: `safe-readonly`, `node`, `python`, `go`, `rust` (auto-detected).
- `apply` for Claude Code (`.claude/settings.json`), Codex CLI (`.codex/rules/agentperms.rules` + a managed
  permission-profile block in `config.toml`), Gemini CLI (`.gemini/policies/agentperms.toml`) and Cursor CLI
  (`.cursor/cli.json`), in project or user scope. Non-destructive JSON(C) merge that keeps comments, unrelated
  keys and hand-written rules; owned files with a managed header; backups in `.agentperms-backup/`;
  `--dry-run` unified diff; idempotent.
- Conservative mapping: rules an agent can't express are never widened (allows dropped, denies/asks
  broadened) and every gap is reported.
- `diff`: drift between the policy and native configs (exit 1 on drift).
- `audit`: one normalized view of the project + user permissions of all four agents, risky-grant detection
  (bypass modes, `Bash(*)`, network/destructive/arbitrary-code grants, `.env` readable, `.git` writable,
  any-domain fetch, MCP auto-approval) and cross-agent inconsistencies. `text`, `json` and `markdown`
  output, `--fail-on` for CI.
- `suggest`: mines Claude Code, Codex CLI and Gemini CLI local history (read-only), generalizes commands into
  prefix patterns, classifies them with a built-in safety model, masks secrets, and `--write` merges safe
  patterns into `agentperms.yaml` with comments preserved.
- Format reference with sources: [docs/formats.md](./docs/formats.md).

[0.1.0]: https://github.com/paulochastinet/agentperms/releases/tag/v0.1.0
