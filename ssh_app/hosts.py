"""Per-host defaults — today that means the port, and the port matters.

The credential lookup already recovers *who* to log in as, because the secret's
name says so. It cannot recover *how to reach* the host, and for at least one
real host here that is not port 22:

    ssh -p 18765 u888-smwcgrxvnrg3@ssh.sapatariacrispal.com

Without somewhere to keep that number, every caller has to carry it, and the
failure when they don't is the expensive kind — measured: the command requested
the key, interrupted a human, spent a one-shot grant, and *then* timed out
against port 22. A wrong port is not a connection error you discover cheaply;
it is a notification somebody answered for nothing.

So the number lives here, next to the credential it belongs with, and is
injected as ``-o Port=`` — the same first-one-wins pool as every other option
this app adds, so an explicit ``-p`` on the command line still overrides it.

Deliberately not ``~/.ssh/config``: that file belongs to whoever is using the
container, this app should not rewrite it, and it would not survive a container
being recreated. This one sits beside ``known_hosts`` on the workspace's shared
storage, so every container — and the next one — sees the same answer.
"""
from __future__ import annotations

import json
import os

CONTAINER_DIR = os.environ.get("AW_WORKSPACE_CONTAINER_DIR", "/opt/aw-workspace")


def path() -> str:
    home = os.environ.get("AW_WORKSPACE_HOME") or os.path.join(CONTAINER_DIR, ".aw-workspace")
    return os.path.join(home, "data", "ssh", "hosts.json")


def load() -> dict:
    """Every known host. A missing or unreadable file is an empty dict, never
    an error — a broken defaults file must not stop somebody connecting to a
    host that needed no defaults in the first place."""
    try:
        with open(path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def get(host: str) -> dict:
    entry = load().get(host)
    return entry if isinstance(entry, dict) else {}


def port_for(host: str) -> int | None:
    value = get(host).get("port")
    try:
        return int(value) if value else None
    except (TypeError, ValueError):
        return None


def set_host(host: str, *, port: int | None = None, note: str = "") -> dict:
    """Record defaults for one host. Merges, so setting a port later does not
    silently drop a note somebody wrote."""
    host = (host or "").strip()
    if not host:
        raise ValueError("host is required")
    data = load()
    entry = dict(data.get(host) or {})
    if port is not None:
        if not 1 <= int(port) <= 65535:
            raise ValueError(f"port {port} is not a port number")
        entry["port"] = int(port)
    if note:
        entry["note"] = note
    data[host] = entry
    _write(data)
    return entry


def forget(host: str) -> bool:
    data = load()
    if host not in data:
        return False
    del data[host]
    _write(data)
    return True


def _write(data: dict) -> None:
    target = path()
    os.makedirs(os.path.dirname(target), exist_ok=True)
    # Written beside and renamed, so a reader never sees half a file — this is
    # read on the way into every connection.
    tmp = target + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, target)


__all__ = ["load", "get", "port_for", "set_host", "forget", "path"]
