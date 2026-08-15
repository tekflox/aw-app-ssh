"""Turning a ``user@host`` into an actual credential, via aw-app-secrets.

Two jobs, and the order between them is the point.

**1. Pick the name without asking anyone.** ``list_secrets`` is free and
ungated, so the inventory is consulted BEFORE any read is requested. A name
that isn't in it is never requested at all. That is not an optimisation: every
``read_secret`` on a non-existent name is a Telegram notification on someone's
phone for a secret that was never going to exist, and the old ``./aw ssh``
sent exactly that whenever a hostname was typed slightly wrong.

**2. Let the value say what it is.** A private key and a password are stored
the same way and read the same way; which one arrived is decided by looking at
it (``-----BEGIN … PRIVATE KEY-----``), not by a naming convention the human
has to remember and this code has to police. So ``private_root_host`` holding a
password works, and so does a key stored under any of the accepted names.

Naming conventions accepted, in priority order, for ``user@host``:

  1. ``--aw-secret NAME``      — explicit, always wins, checked for existence
  2. ``private_<user>_<host>`` — what ``./aw ssh`` used; the live vault is full
                                 of these, so it is first among the conventions
  3. ``ssh_<user>_<host>``     — the name people reach for when adding a new one
  4. ``ssh_<host>`` / ``private_<host>`` — host-wide, any user
  5. a unique ``private_*_<host>`` / ``ssh_*_<host>`` — the fallback that makes
     ``ssh box`` (no user in the argv) work. Only when exactly ONE matches:
     two candidates is ambiguous, and picking either would silently connect as
     somebody the caller did not name.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from . import caller
from . import pending
from .target import Target
from .workspace_client import request

SECRETS_PREFIX = "/api/apps/secrets"

_KEY_MARKERS = ("-----BEGIN ", "PuTTY-User-Key-File")


class CredentialError(RuntimeError):
    """No usable credential — the message always names what was looked for."""


class ApprovalRefused(RuntimeError):
    """The human said no, or nobody answered. Not a transient failure."""


@dataclass(frozen=True)
class Credential:
    name: str
    value: str

    @property
    def is_private_key(self) -> bool:
        return self.value.lstrip().startswith(_KEY_MARKERS)

    @property
    def kind(self) -> str:
        return "private key" if self.is_private_key else "password"


def candidate_names(target: Target) -> list[str]:
    """Exact names to try, best first. Prefix matching is handled separately —
    it needs the inventory, and an exact hit should never be beaten by a fuzzy
    one."""
    host, user = target.host, target.user
    names = []
    if user:
        names += [f"private_{user}_{host}", f"ssh_{user}_{host}"]
    names += [f"ssh_{host}", f"private_{host}"]
    return names


def login_user_from_name(name: str, host: str) -> str | None:
    """The user encoded in ``private_<user>_<host>``, when the argv had none.

    Without this, ``aw-workspace-cli ssh somehost`` resolves the right key by
    host and then hands it to ssh with no user, so ssh logs in as whoever the
    local account is and the server rejects a key it would have accepted. The
    name knows who the key belongs to; use it rather than making the caller
    repeat what the lookup already worked out.

    Returns ``None`` for host-wide entries (``ssh_<host>``), where the name
    genuinely does not say — inventing a user there would be a guess.
    """
    for prefix in ("private_", "ssh_"):
        if name.startswith(prefix) and name.endswith(f"_{host}"):
            user = name[len(prefix):-len(host) - 1]
            return user or None
    return None


def list_secret_names() -> list[str]:
    status, body = request("GET", f"{SECRETS_PREFIX}/secrets")
    if status == 503:
        raise CredentialError(
            "this workspace has no secret store: it never completed the "
            "aw-remote-host /link handshake, so there is nothing to read a key from."
        )
    if status >= 400 or not isinstance(body, dict):
        raise CredentialError(f"could not list secrets (HTTP {status}): {body}")
    return [s.get("name", "") for s in body.get("secrets", []) if s.get("name")]


def resolve_name(target: Target, override: str | None = None) -> str:
    """The secret to ask for. Raises rather than guess when it cannot tell."""
    available = list_secret_names()

    if override:
        if override not in available:
            raise CredentialError(
                f"--aw-secret {override!r} is not in the vault. Present: "
                f"{', '.join(sorted(available)) or '(none)'}"
            )
        return override

    for name in candidate_names(target):
        if name in available:
            return name

    suffix = f"_{target.host}"
    fuzzy = sorted(n for n in available
                   if n.endswith(suffix) and n.startswith(("private_", "ssh_")))
    if len(fuzzy) == 1:
        return fuzzy[0]
    if len(fuzzy) > 1:
        raise CredentialError(
            f"{len(fuzzy)} secrets match host {target.host!r} and the command did "
            f"not say which user to connect as: {', '.join(fuzzy)}. Name the user "
            f"(user@host) or pass --aw-secret <name>."
        )

    raise CredentialError(
        f"no credential in the vault for {target.label}. Looked for: "
        f"{', '.join(candidate_names(target))}. Add one with:\n"
        f"    aw-workspace-cli ssh add-key {target.label} < ~/.ssh/id_ed25519"
    )


POLL_INTERVAL_S = 2.0


def fetch(name: str, reason: str, scope: str = "one_shot",
          max_wait_s: int = 300, request_id_override: str | None = None) -> Credential:
    """Request the value, waiting for the human if the gate is still on.

    Waits, unlike the MCP tool: a person typing ``aw-workspace-cli ssh`` is
    sitting in front of the terminal and cannot "collect it later" — there is
    no later, the process either connects or it does not. Secrets whose gate
    has been turned off in Settings come back on the very first response with
    no prompt at all.

    The waiting is done **here, in short polls**, rather than by handing
    ``max_wait_s`` to the server and holding one long request open. That is not
    a style choice: a command run from an agent-runner container reaches the
    workspace through the tunnel edge, which cuts any request at ~30s. A
    server-side wait would therefore die at 30 seconds with "502 workspace
    offline" — a message that describes neither what happened nor what to do —
    while the approval it was waiting for was still perfectly alive.
    """
    request_id, body = _resume(name, request_id_override)
    if body is None:
        status, body = request("POST", f"{SECRETS_PREFIX}/secrets/{name}/read",
                               {"reason": reason, "scope": scope, "max_wait_s": 0,
                                # Who a window grant would belong to. Computed
                                # HERE because only this process can see its own
                                # session or shell — see caller.py.
                                "caller_key": caller.caller_key(allow_local=True),
                                # Stable across runs, so a scheduled task can
                                # be named on a secret's allowlist and read it
                                # without waking anybody.
                                "agent": caller.agent_identity()})
        body = _checked(name, status, body)
        request_id = body.get("request_id") or ""
        if request_id:
            # Written down BEFORE the wait, not after: the whole point is to
            # survive this process giving up, or dying.
            pending.remember(name, request_id)
    deadline = time.monotonic() + max(0, max_wait_s)
    while True:
        if body.get("status") != "pending":
            pending.forget(name)
            value = body.get("value")
            if not value:
                raise CredentialError(
                    f"{name!r} was approved but carried no value — a one-shot grant "
                    f"that had already been delivered. Run the command again to "
                    f"request a fresh one."
                )
            return Credential(name=name, value=value)

        if not request_id:
            raise CredentialError(
                f"the approval for {name!r} is pending but carried no request id, "
                f"so there is nothing to poll. This is a bug in aw-app-secrets."
            )
        if time.monotonic() >= deadline:
            raise ApprovalRefused(
                f"nobody answered the approval for {name!r} within {max_wait_s}s. "
                f"The request is still live and has been noted — approve it on "
                f"Telegram whenever you get to it and run the SAME command again; "
                f"it will pick up your answer instead of asking twice."
            )
        time.sleep(POLL_INTERVAL_S)
        status, body = request("GET", f"{SECRETS_PREFIX}/requests/{request_id}")
        body = _checked(name, status, body)


def _resume(name: str, override: str | None) -> tuple[str, dict | None]:
    """An outstanding request for this secret, if one is still collectable.

    Returns ``(request_id, body)`` with ``body`` None when there is nothing to
    resume and a fresh request has to be made. A dead id is dropped quietly —
    the caller wanted a connection, not a report on an old request.
    """
    request_id = override or pending.get(name)
    if not request_id:
        return "", None
    status, body = request("GET", f"{SECRETS_PREFIX}/requests/{request_id}")
    if status >= 400 or not isinstance(body, dict) or body.get("status") in (
            None, "not_found", "expired", "denied", "rejected"):
        pending.forget(name)
        if override:
            # Asked for explicitly: silence would look like it had worked.
            raise CredentialError(
                f"request {override!r} is no longer collectable "
                f"({_detail(body) or body.get('status') if isinstance(body, dict) else status})"
            )
        return "", None
    return request_id, body


def _checked(name: str, status: int, body) -> dict:
    """Turn an HTTP answer into either a usable body or the right exception.

    A 403 is the human saying no — an answer, not a failure — so it has its own
    type and must never be retried.
    """
    if status == 403:
        raise ApprovalRefused(_detail(body) or f"the request for {name!r} was refused")
    if status == 503:
        raise CredentialError(_detail(body) or "no secret store reachable")
    if status >= 400 or not isinstance(body, dict):
        raise CredentialError(f"could not read {name!r} (HTTP {status}): {_detail(body)}")
    return body


def _detail(body) -> str:
    if isinstance(body, dict):
        return str(body.get("detail") or body.get("error") or "")
    return str(body or "")


__all__ = ["Credential", "CredentialError", "ApprovalRefused",
           "candidate_names", "resolve_name", "fetch", "list_secret_names",
           "login_user_from_name"]
