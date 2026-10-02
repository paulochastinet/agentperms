# Contributing to agentperms

Thanks for helping make agent permissions boring and safe!

## Setup

```bash
git clone https://github.com/paulochastinet/agentperms
cd agentperms
npm install        # also builds dist/ via the `prepare` script
npm run typecheck
npm test
node dist/cli.js audit --home
```

Requires Node.js >= 18.18.

## Project layout

```
src/
  cli.ts / run.ts        entry point, argument handling, exit codes
  policy/                agentperms.yaml loading + validation, presets, comment-preserving writer
  targets/               one generator + reader per agent (claude, codex, gemini, cursor)
  apply.ts               planning, JSON(C) list merge, TOML managed block, backups, state
  audit.ts               risk findings and cross-agent inconsistencies
  suggest.ts             history miners (Claude Code, Codex, Gemini) and pattern aggregation
  safety.ts              the safety model (safe / ask / never)
  shell.ts, glob.ts      shell splitting, pattern semantics, path/domain globs
  secrets.ts             secret masking
  render.ts              text / markdown output
docs/formats.md          native formats + sources + the mapping table
test/                    vitest suites; fixtures/ holds a fake home (configs + transcripts), a project,
                         the reference policy and golden files for every target
```

## Ground rules

- **Never widen.** If an agent can't express a rule exactly, drop an allow or broaden a deny/ask, and emit a
  `MappingWarning`. Add a test proving the generated config is not more permissive than the policy.
- **Never destroy.** Native files are merged, not rewritten. New edit paths need a test that comments,
  unrelated keys and hand-written rules survive, and that a second `apply` is a no-op.
- **Never leak.** Anything derived from history goes through `maskCommand()`; add fixtures for new secret shapes.
- Keep dependencies minimal; prefer `node:` built-ins.
- Update [docs/formats.md](./docs/formats.md) with a link to the official source whenever a mapping changes.

## Golden files

`test/targets.test.ts` compares generated configs with `test/fixtures/golden/*`. After an intentional change:

```bash
UPDATE_GOLDEN=1 npx vitest run test/targets.test.ts
git diff test/fixtures/golden   # review every line
```

## Fixtures and global gitignores

Fixtures include files such as `.claude/settings.local.json` that many global gitignores exclude. Check with
`git status --ignored` and add them with `git add -f`.

## Adding an agent

1. Add the id to `TargetId` / `TARGET_IDS` / `TARGET_NAMES` in `src/types.ts`.
2. Create `src/targets/<id>.ts` implementing `Target` (`generate` + `read`) and register it in `src/targets/index.ts`.
3. Add golden files, audit fixtures, a row in the README support matrix and a section in `docs/formats.md`.

## Releasing

Update `CHANGELOG.md`, bump the version in `package.json`, tag `vX.Y.Z`, then `npm publish`.
