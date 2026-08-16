---
repo: architecture
path: docs/architecture/aw-app-ssh.md
source: generated
edited: false
checksum: sha256:58020d3fc3fe8231e0127414710afde23f6208f8d67e2c30bfdec4e1343356df
---
# SSH

- **repo**: aw-app-ssh
- **layer**: app
- **technologies**: python
- **health** (derived): planned

Contributes `aw-workspace-cli ssh` and `aw-workspace-cli rsync`: the real tools, with the private key or password fetched from the workspace vault (aw-app-secrets) and injected into an ephemeral ssh-agent, so the caller — usually an agent — connects without ever seeing the credential. Arguments are ssh's/rsync's own; this app only adds `--aw-*` flags.

## Connections
- `other` → **aw-app-secrets** — Every credential this app injects comes from aw-app-secrets' /api/apps/secrets/* — the vault, the approval gate and the per-secret auto-approve flag all live there

## MCP tools
_none exposed_

## Requirements
_none documented_
