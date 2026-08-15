"""Pulling ``user@host`` (and the port) out of a real ssh/rsync argv.

This is the part that has to be right, because everything downstream — which
secret gets requested, and therefore whose phone lights up — is keyed on what
comes out of here. Two rules do most of the work:

* **A flag's *value* is not a target.** ``ssh -o User=root box`` and
  ``rsync -e 'ssh -p 2222' a b`` both contain arguments that look nothing like
  flags but are consumed by one. Skipping them is why each parser carries its
  own set of value-taking short flags rather than sharing one: ssh's ``-f`` is
  a boolean (go to background) while rsync's ``-f`` takes a filter rule, so a
  merged set would misparse one of them.
* **Everything after the target is the remote command**, not more targets.
  ``ssh root@a ssh root@b`` connects to ``a`` — taking ``b`` as well would
  request a second person's key for a string this command never interprets.

Where the two differ: ssh's target is a bare word (``[user@]host``), rsync's is
a word containing a colon (``[user@]host:path``) which may be either the source
or the destination. Hence two functions rather than one with a mode flag.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# ssh(1) short flags that consume the NEXT argv entry. Booleans (-4 -6 -A -a -C
# -f -G -g -K -k -M -N -n -q -s -T -t -V -v -X -x -Y -y) deliberately absent:
# listing one here would silently swallow the target that follows it.
_SSH_VALUE_FLAGS = frozenset(
    "-B -b -c -D -E -e -F -I -i -J -L -l -m -O -o -P -p -Q -R -S -W -w".split()
)

# rsync(1)'s. Much shorter — rsync spells almost everything as --long=value.
_RSYNC_VALUE_FLAGS = frozenset("-e -f -M -T --rsh --port --password-file".split())

_HOST_RE = r"[A-Za-z0-9._\-\[\]:%]+"
_SSH_TARGET_RE = re.compile(rf"^(?:(?P<user>[^@/\s]+)@)?(?P<host>{_HOST_RE})$")
_RSYNC_TARGET_RE = re.compile(rf"^(?:(?P<user>[^@/\s]+)@)?(?P<host>[A-Za-z0-9._\-]+):")


@dataclass(frozen=True)
class Target:
    """Who we are connecting as, and where.

    ``user`` is ``None`` when the argv never said — ``ssh box`` logs in as
    whatever the local user is. That is NOT the same as an empty string, and
    the distinction matters one layer up: an unknown user means the secret has
    to be found by host alone instead of by an exact name.
    """

    user: str | None
    host: str
    port: int | None = None

    @property
    def label(self) -> str:
        base = f"{self.user}@{self.host}" if self.user else self.host
        return f"{base}:{self.port}" if self.port else base


def _split_uri(arg: str) -> tuple[str | None, str, int | None] | None:
    """``ssh://user@host:port/...`` — accepted by both tools, easy to forget."""
    if not arg.startswith(("ssh://", "rsync://")):
        return None
    rest = arg.split("://", 1)[1].split("/", 1)[0]
    user = None
    if "@" in rest:
        user, rest = rest.rsplit("@", 1)
    port = None
    if ":" in rest and not rest.startswith("["):
        rest, _, p = rest.rpartition(":")
        port = int(p) if p.isdigit() else None
    return (user or None), rest, port


def _scan(args: list[str], value_flags: frozenset[str],
          match) -> tuple[tuple[str | None, str, int | None], int] | None:
    """Walk argv once, honouring ``--`` and flags that eat their next entry.

    Returns the parsed target *and its index*. The index is not decoration:
    ssh only accepts options before the target, and command-line options are
    first-one-wins, so injected defaults have to land exactly here — after
    everything the caller wrote (theirs still wins) and before the host
    (ssh still parses them).
    """
    skip = False
    literal = False
    for i, arg in enumerate(args):
        if skip:
            skip = False
            continue
        if not literal:
            if arg == "--":
                literal = True
                continue
            if arg in value_flags:
                skip = True
                continue
            # -p2222 / --rsh=ssh — value glued on, nothing to skip.
            if arg.startswith("-") and arg != "-":
                continue
        hit = _split_uri(arg) or match(arg, args, i)
        if hit:
            return hit, i
    return None


def _ssh_match(arg, _args, _i):
    m = _SSH_TARGET_RE.match(arg)
    return (m.group("user"), m.group("host"), None) if m else None


def _rsync_match(arg, _args, _i):
    m = _RSYNC_TARGET_RE.match(arg)
    return (m.group("user"), m.group("host"), None) if m else None


def parse_ssh(args: list[str]) -> Target | None:
    """First bare word wins; ``-p``/``-l`` still override what it said."""
    hit = _scan(args, _SSH_VALUE_FLAGS, _ssh_match)
    if not hit:
        return None
    (user, host, port), _ = hit
    return Target(_explicit_user(args) or user, host, _explicit_port(args) or port)


def ssh_target_index(args: list[str]) -> int | None:
    """Where the host sits in argv — the insertion point for ssh options."""
    hit = _scan(args, _SSH_VALUE_FLAGS, _ssh_match)
    return hit[1] if hit else None


def parse_rsync(args: list[str]) -> Target | None:
    """Either side may be the remote one; ``rsync a b`` (both local) has none."""
    hit = _scan(args, _RSYNC_VALUE_FLAGS, _rsync_match)
    if not hit:
        return None
    (user, host, port), _ = hit
    return Target(user, host, _explicit_port(args) or port)


def _explicit_user(args: list[str]) -> str | None:
    """``ssh -l root box`` means root, even though the argv says only ``box``."""
    for i, a in enumerate(args):
        if a == "-l" and i + 1 < len(args):
            return args[i + 1]
        if a.startswith("-l") and len(a) > 2 and not a.startswith("--"):
            return a[2:]
        if a == "-o" and i + 1 < len(args) and args[i + 1].lower().startswith("user="):
            return args[i + 1].split("=", 1)[1]
    return None


def _explicit_port(args: list[str]) -> int | None:
    """``-p`` for ssh, ``--port`` for rsync-over-daemon; both may be glued."""
    for i, a in enumerate(args):
        if a in ("-p", "--port") and i + 1 < len(args) and args[i + 1].isdigit():
            return int(args[i + 1])
        if a.startswith("-p") and a[2:].isdigit():
            return int(a[2:])
        if a.startswith("--port=") and a[7:].isdigit():
            return int(a[7:])
    return None


__all__ = ["Target", "parse_ssh", "parse_rsync", "ssh_target_index"]
