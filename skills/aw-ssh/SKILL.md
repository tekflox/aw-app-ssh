---
name: aw-ssh
description: Connect to a remote host over ssh, or move files with rsync, without holding the credential. `aw-workspace-cli ssh` / `aw-workspace-cli rsync` take the real tool's arguments and pull the key or password from the workspace vault themselves. Use whenever a task needs a remote shell or a file transfer — and read this BEFORE running either, because a wrong hostname can put an approval prompt on someone's phone.
---

# aw-ssh — remote hosts, without the key

Two commands, from `aw-app-ssh`:

```
aw-workspace-cli ssh    [ssh args...]
aw-workspace-cli rsync  [rsync args...]
```

The arguments are **ssh's and rsync's own**. There is no wrapper syntax. Every
flag you know works, in the order you would write it:

```
aw-workspace-cli ssh root@aw.tekflox.com
aw-workspace-cli ssh -p 18765 user@host 'systemctl status nginx'
aw-workspace-cli rsync -avz --delete ./dist/ user@host:/var/www/
aw-workspace-cli rsync -avz user@host:/var/log/nginx/ ./logs/
```

What the app adds is the credential. It looks up the vault entry for that
host, asks aw-app-secrets for it, and hands it to an ephemeral `ssh-agent` that
dies with the connection. **The value is never printed, never an argument, and
never reaches you.** You do not need it and you will not get it.

## Do this first: `--aw-dry-run`

```
aw-workspace-cli ssh --aw-dry-run root@aw.tekflox.com
```

```
target : root@aw.tekflox.com
login  : root
secret : private_root_aw.tekflox.com
scope  : one_shot
argv   : ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=… root@aw.tekflox.com
(dry run — no approval requested, nothing connected)
```

It resolves everything and **asks nobody**. Use it to confirm a host has a
credential before you commit to a command that will interrupt a human. The
same answer, shorter, comes from `aw-workspace-cli ssh status <user@host>`, and
`aw-workspace-cli ssh list` prints every ssh credential the vault holds.

## What a real run costs

Reading a secret is gated: unless that entry's gate has been turned off in
Settings › Secrets, the first command sends a Telegram approval to the
workspace owner and waits up to five minutes for a tap. So:

- **Check with `--aw-dry-run` before connecting to a host you have not used
  in this task.** A typo'd hostname otherwise becomes a notification for a
  secret that was never going to exist — except it does not, because the app
  resolves names against the free, ungated inventory first and refuses locally
  instead of asking. `--aw-dry-run` is how you see that refusal without
  spending a connection attempt.
- **Do not loop or retry.** A denial is an answer. An expiry means nobody was
  looking, not that trying again will work.
- **Batch your remote work into one command.** Each invocation is a separate
  one-shot grant and therefore a separate prompt. `ssh host 'a && b && c'`
  costs one tap; three `ssh host` calls cost three. If you genuinely need
  several round trips, ask for a window once — `--aw-scope 10min` — rather
  than paying per command.

## How the credential is chosen

From `user@host`, in this order, and only names that actually exist in the
vault are ever requested:

1. `--aw-secret NAME` — explicit, wins over everything
2. `private_<user>_<host>` — the convention the vault is already full of
3. `ssh_<user>_<host>`
4. `ssh_<host>` / `private_<host>` — host-wide, any user
5. exactly one `private_*_<host>` / `ssh_*_<host>` — this is what makes
   `aw-workspace-cli ssh box` work with no user in the command. **Two matches
   is an error, not a coin flip**: connecting as a user the caller never named
   is the wrong way to be helpful.

Key or password is decided by **looking at the value** (`-----BEGIN … PRIVATE
KEY-----`), not by the name. So one entry name works for either, and nobody has
to remember a second convention.

## Adding a credential

```
aw-workspace-cli ssh add-key root@newhost < ~/.ssh/id_ed25519
printf '%s' "$PASSWORD" | aw-workspace-cli ssh add-key user@host
```

Writing is **not** gated — you already hold the value, so a prompt would
confirm nothing. Note the consequence: an existing name is overwritten with no
warning. Run `aw-workspace-cli ssh list` first if you are unsure.

## The `--aw-*` flags

| flag | default | what it does |
|---|---|---|
| `--aw-dry-run` | off | resolve and print the plan; ask nobody, connect to nothing |
| `--aw-secret NAME` | — | use this vault entry instead of the resolved one |
| `--aw-scope` | `one_shot` | `10min` / `60min` let this same process re-read without a second prompt |
| `--aw-wait N` | `300` | seconds to wait for the human before giving up |
| `--aw-host-keys` | `accept-new` | `yes` (strict) / `no`. See below before reaching for `no`. |

Everything else is passed through untouched. `--aw-` is a prefix ssh and rsync
do not use, which is why there is no escape hatch to learn.

## Host keys

`known_hosts` lives under the workspace home, not `~/.ssh` — a per-container
file would make every first connection unverified *again* after each restart,
which teaches everyone to ignore the warning. The default `accept-new` trusts a
host the first time and refuses if its key later changes.

If a connection fails with a changed host key, **that is the check working**.
Do not "fix" it with `--aw-host-keys no`; find out why the key changed.

## Failure modes

| what you see | means | what to do |
|---|---|---|
| `no credential in the vault for user@host` | nothing matches, and nobody was asked | check the hostname, then `aw-workspace-cli ssh list` |
| `N secrets match host … did not say which user` | ambiguous | write `user@host`, or `--aw-secret <name>` |
| `refused` / `denied by the human` | they said no | **stop.** Report it; do not retry |
| `nobody answered the approval within Ns` | no tap within the window | the request is still live — ask the user in chat before running it again |
| `no secret store reachable` | this workspace never completed the `/link` handshake | not a missing key — say the workspace is unlinked |

## Local paths

`ssh` and `rsync` are always available — that is the app's problem, not yours,
and it is solved. Run the command.

The one thing worth knowing is where "local" points. The command runs in the
same place you are, so a path like `./out/` lands in **your** filesystem, not
the workspace container's. `/opt/aw-workspace/...` is shared and visible from
both; anywhere else may not be. When in doubt, transfer into
`/opt/aw-workspace/.tmp/<something>/` and it will be where you expect.

## What "never sees the credential" does and does not mean

It keeps the value out of your transcript and out of the process table: the key
goes through a pipe into an `ssh-agent`, never onto a filesystem; a password
goes into a 0600 file inside a 0700 directory that is deleted when the command
exits, read by OpenSSH's own `SSH_ASKPASS`.

It is **not** a sandbox against the calling process, which runs as the same
uid. Treat it as "the secret is not in your context", not as "the secret is
unreachable to you". Do not go looking for it — the audit log records who asked
for what, and the honest boundary is the one that makes this app safe to use at
all.
