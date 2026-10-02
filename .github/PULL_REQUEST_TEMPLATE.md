## What

<!-- What does this PR change, and why? Link related issues. -->

## How was it tested?

- [ ] `npm run typecheck`
- [ ] `npm test`
- [ ] Ran `node dist/cli.js apply --dry-run` / `audit` locally (paste relevant output, with secrets, private paths and host names removed)

## Checklist

- [ ] No generated config can be more permissive than the policy (test added for new mappings)
- [ ] Native files are merged, not rewritten (comments / unrelated keys / hand-written rules preserved)
- [ ] Golden files updated and reviewed (`UPDATE_GOLDEN=1`)
- [ ] `docs/formats.md`, README and CHANGELOG updated where relevant
