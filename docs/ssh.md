# `aw-workspace-cli ssh`

## Why this exists

A plain `ssh` inside an agent container has nowhere to get a credential from
without either asking a human to paste one into the shell (so it ends up in
the transcript and the process table) or storing it on disk where any process
in the container can read it. This command is `ssh` with that gap closed: the
private key or password comes out of the workspace vault (`aw-app-secrets`)
and is injected without ever becoming an argument, an env var dump, or a file
on disk that outlives the connection — see the main `README.md` for exactly
how (ephemeral `ssh-agent` for keys, `SSH_ASKPASS` for passwords).

## What it does

`aw-workspace-cli ssh [ssh's own args...]` resolves which vault secret
matches the target (`user@host` found in the argv, same as real `ssh` would
parse it — see `ssh_app/target.py`), fetches it, attaches it, and then execs
the real `ssh` binary with the **original argv untouched**. Nothing this app
adds is positional; everything it consumes is namespaced under `--aw-*` and
stripped before `ssh` ever sees it.

```bash
aw-workspace-cli ssh root@aw.tekflox.com
aw-workspace-cli ssh -p 18765 user@host 'systemctl status nginx'
```

### Subcommands

```
aw-workspace-cli ssh status <user@host>      which secret would be used
aw-workspace-cli ssh list                    every ssh credential in the vault
aw-workspace-cli ssh add-key <user@host>     store a key/password from stdin
aw-workspace-cli ssh hosts                    per-host defaults (ports)
aw-workspace-cli ssh set-host <host> -p N     remember this host's ssh port
```

`status` and `--aw-dry-run` are the two that resolve and print the plan
without fetching anything or asking anybody — the right first move before an
agent risks putting an approval prompt on someone's phone over a typo'd
hostname.

### `--aw-*` flags consumed before `ssh` runs

| flag | meaning |
|---|---|
| `--aw-secret NAME` | use this vault entry instead of the resolved one |
| `--aw-scope SCOPE` | `one_shot` (default) \| `10min` \| `60min` |
| `--aw-wait SECONDS` | how long to wait for approval (default 300) |
| `--aw-request ID` | collect this specific outstanding approval instead of opening a new one |
| `--aw-host-keys MODE` | `accept-new` (default) \| `yes` \| `no` |
| `--aw-dry-run` | resolve the secret and print the plan; ask nobody |

Shared implementation and shared secret-resolution order with `rsync` — see
[`rsync.md`](rsync.md) and `ssh_app/cli.py`. The agent-facing version of this
same material, written for a caller deciding what to do rather than for
someone reading a reference, is [`skills/aw-ssh/SKILL.md`](../skills/aw-ssh/SKILL.md).
