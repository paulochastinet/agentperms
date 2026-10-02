# Security policy

`agentperms` writes the permission configuration of AI coding agents, so a bug can directly widen what an
agent may do without asking. Reports are taken seriously.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✓ |

## Reporting a vulnerability

Please **do not open a public issue**. Use
[GitHub private vulnerability reporting](https://github.com/paulochastinet/agentperms/security/advisories/new)
with a minimal `agentperms.yaml`, the generated native file and the agent version. You can expect a first
answer within a few days.

Especially in scope:

- a policy whose generated config **allows more** than the policy says (in any agent);
- `apply` destroying or corrupting unrelated content in a native config file;
- `suggest` printing a secret from local history, or proposing a `never`-class command;
- `audit` missing a dangerous grant that it claims to detect.

## Design guarantees

- Everything runs locally. No network access, no telemetry.
- Session transcripts are opened read-only.
- `apply --dry-run`, `diff`, `audit` and `suggest` (without `--write`) never write to disk.
- Every file `apply` changes is backed up first.
