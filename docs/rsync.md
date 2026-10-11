# `aw-workspace-cli rsync`

## Why this exists

`rsync` over ssh needs the exact same credential this app already injects for
plain `ssh` — a key or password it must never see as an argument or leave on
disk. Rather than build a second credential path, `rsync` is the same
implementation as [`ssh`](ssh.md) under a different program name
(`ssh_app/cli.py::main("rsync", ...)`), so "which secret, and how does it get
in" has exactly one answer and cannot drift between the two commands.

## What it does

`aw-workspace-cli rsync [rsync's own args...]` resolves the remote target out
of the argv, fetches the matching vault secret, attaches it, and execs the
real `rsync` binary with the **original argv untouched**.

```bash
aw-workspace-cli rsync -avz --delete ./dist/ user@host:/var/www/
aw-workspace-cli rsync -avz user@host:/srv/ ./srv/
```

Either side of an `rsync` invocation may be the remote one (`ssh_app/target.py::parse_rsync`)
— `rsync a b` with both sides local simply has no target to resolve, and the
command falls through to running `rsync` with no credential involved at all.
A bare word with no `:` is never mistaken for a remote target, and an
explicit `-e`/`--port`/`-l`/`-o User=` wins over anything this app would have
guessed.

### Subcommands and flags

Identical surface to `ssh` — same subcommands (`status`, `list`, `add-key`,
`hosts`, `set-host`) and the same `--aw-*` flags (`--aw-secret`, `--aw-scope`,
`--aw-wait`, `--aw-request`, `--aw-host-keys`, `--aw-dry-run`). See
[`ssh.md`](ssh.md) for the full table — it is not repeated here because it
would just be the same table twice, and the one place it could drift is
exactly the place it must not.

```bash
aw-workspace-cli rsync --aw-dry-run -avz ./dist/ user@host:/var/www/   # which secret, no transfer, asks nobody
aw-workspace-cli rsync status user@host
```

The agent-facing version of this material is
[`skills/aw-ssh/SKILL.md`](../skills/aw-ssh/SKILL.md).
