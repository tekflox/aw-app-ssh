"""``aw-workspace-cli ssh`` / ``rsync`` — one implementation, two front doors.

The contract with the caller is that **the arguments are ssh's arguments**.
Anything this app adds is namespaced under ``--aw-`` and stripped before the
real tool ever sees it, so muscle memory, man pages and copy-pasted commands
all keep working, and there is no wrapper syntax to learn or to get wrong.

    aw-workspace-cli ssh root@host                     # ssh's argv, verbatim
    aw-workspace-cli ssh -p 2222 user@host uptime
    aw-workspace-cli rsync -avz user@host:/srv/ ./srv/
    aw-workspace-cli ssh --aw-dry-run root@host        # which secret, no prompt

``--aw-dry-run`` is the one an agent should reach for first: it answers "is
there a credential for this host, and which one" without sending anybody a
notification.
"""
from __future__ import annotations

import os
import sys

from . import credentials as creds
from . import spawn
from .credentials import ApprovalRefused, CredentialError
from .target import Target, parse_rsync, parse_ssh
from .workspace_client import WorkspaceUnreachable, request

USAGE = """aw-workspace-cli {prog} — {prog} with credentials injected from the workspace vault.

  aw-workspace-cli {prog} [{prog} args...]        run {prog}, credential attached
  aw-workspace-cli {prog} status <user@host>      which secret would be used
  aw-workspace-cli {prog} list                    every ssh credential in the vault
  aw-workspace-cli {prog} add-key <user@host>     store a key/password from stdin

Options this app consumes (everything else goes straight to {prog}):
  --aw-secret NAME     use this vault entry instead of the resolved one
  --aw-scope SCOPE     one_shot (default) | 10min | 60min
  --aw-wait SECONDS    how long to wait for approval (default 300)
  --aw-host-keys MODE  accept-new (default) | yes | no
  --aw-dry-run         resolve the secret and print the plan; ask nobody
"""

_FLAGS_WITH_VALUE = {"--aw-secret", "--aw-scope", "--aw-wait", "--aw-host-keys"}


def _split_own_flags(args: list[str]) -> tuple[dict, list[str]]:
    """Ours out, theirs through — untouched and in the original order."""
    opts: dict = {"secret": None, "scope": "one_shot", "wait": 300,
                  "host_keys": "accept-new", "dry_run": False}
    rest: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--aw-dry-run":
            opts["dry_run"] = True
        elif a in _FLAGS_WITH_VALUE:
            if i + 1 >= len(args):
                raise CredentialError(f"{a} needs a value")
            _assign(opts, a, args[i + 1])
            i += 1
        elif a.startswith("--aw-") and "=" in a:
            k, v = a.split("=", 1)
            if k not in _FLAGS_WITH_VALUE:
                raise CredentialError(f"unknown option {k}")
            _assign(opts, k, v)
        elif a.startswith("--aw-"):
            raise CredentialError(f"unknown option {a}")
        else:
            rest.append(a)
        i += 1
    return opts, rest


def _assign(opts: dict, flag: str, value: str) -> None:
    if flag == "--aw-secret":
        opts["secret"] = value
    elif flag == "--aw-scope":
        if value not in ("one_shot", "10min", "60min"):
            raise CredentialError(f"--aw-scope must be one_shot, 10min or 60min (got {value!r})")
        opts["scope"] = value
    elif flag == "--aw-wait":
        if not value.isdigit():
            raise CredentialError("--aw-wait takes a number of seconds")
        opts["wait"] = int(value)
    elif flag == "--aw-host-keys":
        if value not in ("accept-new", "yes", "no"):
            raise CredentialError("--aw-host-keys must be accept-new, yes or no")
        opts["host_keys"] = value


def _binary_status(prog: str) -> str:
    """What a dry run can say about the tool without installing it."""
    import shutil

    from . import provision
    found = shutil.which(prog) or provision.provisioned_path(prog)
    return found or f"not here yet — {provision.PACKAGE_FOR.get(prog, prog)} " \
                    f"will be fetched on the first real run"


def _announce(message: str) -> None:
    """Progress that is not output. stderr, so it never lands in a pipe the
    caller is parsing — ``aw-workspace-cli ssh host cat file > out`` has to
    stay usable."""
    print(message, file=sys.stderr)


def _parse_target(prog: str, args: list[str]) -> Target | None:
    return parse_ssh(args) if prog == "ssh" else parse_rsync(args)


def main(prog: str, args: list[str]) -> int:
    """``prog`` is ``ssh`` or ``rsync``; ``args`` is everything after it."""
    if not args or args[0] in ("-h", "--help", "help"):
        print(USAGE.format(prog=prog))
        return 0
    try:
        if args[0] == "list":
            return _cmd_list()
        if args[0] == "status":
            return _cmd_status(prog, args[1:])
        if args[0] == "add-key":
            return _cmd_add_key(args[1:])
        return _cmd_run(prog, args)
    except (CredentialError, ApprovalRefused, WorkspaceUnreachable,
            spawn.BinaryMissing) as exc:
        print(f"aw-workspace-cli {prog}: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


# ── subcommands ──────────────────────────────────────────────────────────

def _cmd_list() -> int:
    names = [n for n in creds.list_secret_names()
             if n.startswith(("ssh_", "private_"))]
    if not names:
        print("No ssh credentials in the vault. Add one with:\n"
              "    aw-workspace-cli ssh add-key user@host < ~/.ssh/id_ed25519")
        return 0
    print(f"{len(names)} ssh credential(s):")
    for n in sorted(names):
        print(f"  {n}")
    return 0


def _cmd_status(prog: str, args: list[str]) -> int:
    """Deliberately does not fetch anything — status must never cost a prompt."""
    opts, rest = _split_own_flags(args)
    target = _parse_target(prog, rest) or _parse_target("ssh", rest)
    if not target:
        print(f"Usage: aw-workspace-cli {prog} status <user@host>", file=sys.stderr)
        return 1
    try:
        name = creds.resolve_name(target, opts["secret"])
    except CredentialError as exc:
        print(f"  {target.label} : no credential — {exc}")
        return 1
    print(f"  {target.label} : {name}")
    return 0


def _cmd_add_key(args: list[str]) -> int:
    """Writing is ungated on purpose (aw-app-secrets): the caller already holds
    the value, so a prompt would confirm nothing."""
    opts, rest = _split_own_flags(args)
    if not rest:
        print("Usage: aw-workspace-cli ssh add-key <user@host> < keyfile", file=sys.stderr)
        return 1
    target = parse_ssh(rest)
    if not target or not target.user:
        print("add-key needs a full user@host — the user is part of the secret's name.",
              file=sys.stderr)
        return 1
    if sys.stdin.isatty():
        print("Reading the key from stdin; paste it and press Ctrl-D.", file=sys.stderr)
    value = sys.stdin.read().strip()
    if not value:
        print("Nothing on stdin — no key stored.", file=sys.stderr)
        return 1

    name = opts["secret"] or f"private_{target.user}_{target.host}"
    kind = "private key" if value.lstrip().startswith("-----BEGIN ") else "password"
    status, body = request("POST", f"{creds.SECRETS_PREFIX}/secrets", {
        "name": name, "value": value,
        "description": f"SSH {kind} for {target.label} (aw-app-ssh)",
    })
    if status >= 400:
        print(f"Could not store {name!r} (HTTP {status}): {body}", file=sys.stderr)
        return 1
    print(f"Stored {kind} as {name!r}. Reading it back needs approval unless you "
          f"turn that off in Settings › Secrets.")
    return 0


def _cmd_run(prog: str, args: list[str]) -> int:
    opts, rest = _split_own_flags(args)
    target = _parse_target(prog, rest)
    if not target:
        hint = ("no user@host:/path found — with no remote side there is nothing "
                "to authenticate, so run rsync directly."
                if prog == "rsync" else "no host found in the arguments.")
        print(f"aw-workspace-cli {prog}: {hint}", file=sys.stderr)
        return 1

    name = creds.resolve_name(target, opts["secret"])
    # The argv named no user but the credential's name knows one: without
    # passing it on, ssh would log in as whatever the local account is and the
    # server would reject a key it would otherwise have accepted.
    login_user = None if target.user else creds.login_user_from_name(name, target.host)

    if opts["dry_run"]:
        argv = spawn.build_argv(prog, rest, host_key_policy=opts["host_keys"],
                                login_user=login_user)
        print(f"target : {target.label}\n"
              f"login  : {target.user or login_user or '(local user)'}\n"
              f"secret : {name}\n"
              f"scope  : {opts['scope']}\n"
              f"binary : {_binary_status(prog)}\n"
              f"argv   : {prog} {' '.join(argv)}\n"
              f"(dry run — no approval requested, nothing connected)")
        return 0

    # Before anything that can interrupt a human. Found by running it for real:
    # in a container without rsync, the command fetched the credential — one
    # approval, one notification, one one-shot grant spent — and only then died
    # on the missing binary. Everything that can fail without asking must fail
    # first, and installing the binary is one of those things.
    #
    # After the dry-run branch, not before it: a dry run promises to ask nobody
    # and do nothing, and downloading a package is not nothing.
    spawn.require(prog, _announce)

    reason = f"aw-workspace-cli {prog} {' '.join(rest)}"[:400]
    print(f"# requesting '{name}' for {target.label} — approve on Telegram if asked",
          file=sys.stderr)
    credential = creds.fetch(name, reason, opts["scope"], opts["wait"])
    print(f"# got {credential.kind}; connecting as {target.label}", file=sys.stderr)

    return spawn.run(prog, rest, credential,
                     host_key_policy=opts["host_keys"], login_user=login_user,
                     cwd=os.environ.get("AW_ORIGINAL_CWD") or os.getcwd(),
                     announce=_announce)


__all__ = ["main", "USAGE"]
