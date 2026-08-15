# aw-app-ssh

`aw-workspace-cli ssh` and `aw-workspace-cli rsync` — the real tools, with the
private key or password pulled from the workspace vault and injected, so the
caller connects without ever holding the credential.

The successor to the monolith's `./aw ssh` / `./aw rsync`, decoupled into an
app: the vault lives in aw-app-secrets, the commands live here, and neither is
a branch inside aw-workspace core.

```bash
aw-workspace-cli ssh root@aw.tekflox.com
aw-workspace-cli ssh -p 18765 user@host 'systemctl status nginx'
aw-workspace-cli rsync -avz --delete ./dist/ user@host:/var/www/

aw-workspace-cli ssh --aw-dry-run root@host   # which secret — asks nobody
aw-workspace-cli ssh list                     # every ssh credential in the vault
aw-workspace-cli ssh add-key root@new < ~/.ssh/id_ed25519
```

The arguments are ssh's and rsync's own. This app only adds `--aw-*` flags,
which it strips before the real tool runs — see
[`skills/aw-ssh/SKILL.md`](skills/aw-ssh/SKILL.md) for the full surface.

## How the credential gets in

| kind | mechanism | where it lives while in use |
|---|---|---|
| private key | ephemeral `ssh-agent`, fed through an inherited pipe (`ssh-add -`) | the agent's memory only — never a filesystem |
| password | OpenSSH's own `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE=force` | a 0600 file in a 0700 dir, deleted when the command exits |

Which one it is comes from **looking at the value** (`-----BEGIN … PRIVATE
KEY-----`), not from the name — so one naming convention covers both, and no
`sshpass` dependency is needed for the password case.

The value is never an argument, never printed, never logged. That keeps it out
of an agent's transcript and out of the process table. It is **not** a sandbox
against the calling process, which runs as the same uid; the honest boundary is
stated in the skill and in `ssh_app/spawn.py`.

## Choosing the secret

Resolution runs against `list_secrets`, which is free and ungated, **before**
anything is requested — so a typo'd hostname fails locally instead of putting
an approval prompt on someone's phone.

1. `--aw-secret NAME`
2. `private_<user>_<host>` — the convention the vault already uses
3. `ssh_<user>_<host>`
4. `ssh_<host>` / `private_<host>`
5. exactly one `private_*_<host>` — two matches is an error, not a coin flip

When the match came from the host alone, the user encoded in the name is passed
to ssh as `-o User=`; otherwise the right key would be offered for the wrong
account.

## Layout

| path | what |
|---|---|
| `commands/ssh.py`, `commands/rsync.py` | discovered by `aw-workspace-cli` from the installed app dir; both call `ssh_app.cli.main` |
| `ssh_app/target.py` | pulling `user@host` out of a real ssh/rsync argv |
| `ssh_app/credentials.py` | which secret, and fetching it through aw-app-secrets |
| `ssh_app/spawn.py` | the injection, and the argv/`-e` surgery around it |
| `ssh_app/provision.py` | making ssh/rsync exist in *this* container, with or without root |
| `ssh_app/plugin.py` | activation: installs `openssh-client` + `rsync` (`python:3.12-slim` has neither) |
| `skills/aw-ssh/` | the agent-facing skill |

## Requirements

* **aw-app-secrets ≥ 0.6.0** — the vault, the approval gate and the per-secret
  auto-approve flag all live there.
* Runs in **whatever container invoked it**: ssh is interactive and cannot be
  proxied over HTTP. The binaries are provisioned per container — installed if
  there is root, fetched and unpacked without it if there is not (see
  `ssh_app/provision.py`). Nothing to check before use.

## Tests

```bash
python3 -m pytest tests/ -q
```

The ones worth knowing about are in `tests/test_spawn.py`: they run the real
`run()` against a fake `ssh` that dumps its own argv and environment, so the
obvious wrong implementation — passing the key on the command line — fails
there rather than in someone's shell history.
