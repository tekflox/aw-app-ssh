"""Entrypoint referenced by aw-app.json's runtime.entrypoint.

This app has almost no runtime: the work happens in a CLI command, in the
caller's own process, at the moment somebody types ``aw-workspace-cli ssh``.
Activation exists for the one thing that must happen in the workspace rather
than per invocation — putting the binaries there.

The aw-workspace base image is ``python:3.12-slim``, which ships neither an ssh
client nor rsync, so without this the command would exist and then die on its
first use. ``ctx.commands.install_system_cli`` is the framework's gated,
journaled path for that: it runs the app's own idempotent installer, registers
the CLI with the runtime's healer (which re-runs the installer if the binary
later stops being *healthy*, not merely present), and journals a revert hook so
uninstall reverses what install did.

Installation is deliberately not fatal. A workspace where apt is unavailable
should still load this app with its command present and failing with a message
that names the missing binary — an app that refused to activate would take its
own repair path down with it, and the healer could never fix anything.

It stores nothing and registers no routes. The credential never passes through
this process: it goes from aw-app-secrets straight into the ssh-agent of a
process the CLI spawned, in whatever container the human or the agent is in.
"""
from __future__ import annotations

import json
import logging
import os
import shutil

log = logging.getLogger("aw_apps.ssh")


class SshAppPlugin:
    async def activate(self, ctx) -> None:
        self.ctx = ctx
        package_dir = getattr(ctx, "package_dir", "") or ""

        installed, failed = [], []
        for cli in _declared_clis(package_dir):
            try:
                ctx.commands.install_system_cli(
                    cli["name"], cli["installer"],
                    uninstall="scripts/uninstall.sh",
                    verify=cli.get("verify"),
                )
                installed.append(cli["name"])
            except Exception as exc:  # noqa: BLE001 — see module docstring
                failed.append(f"{cli['name']} ({exc})")

        if failed:
            log.warning(
                "aw-app-ssh: could not install %s here — not fatal: the CLI "
                "provisions what it needs at call time (ssh_app.provision), and "
                "the runtime's system-CLI healer retries this path too",
                "; ".join(failed))

        missing = [b for b in ("ssh", "ssh-agent", "rsync") if not shutil.which(b)]
        log.info("aw-app-ssh activated (installed=%s, still missing here=%s)",
                 ", ".join(installed) or "none", ", ".join(missing) or "none")

    async def deactivate(self) -> None:
        # Revert is the framework's journal reverse-replay running
        # scripts/uninstall.sh once on uninstall — nothing to undo here.
        log.info("aw-app-ssh deactivated")


def _declared_clis(package_dir: str) -> list[dict]:
    """Read them from the manifest rather than hardcoding the pair here, so
    the manifest stays the single place the contribution is declared."""
    try:
        with open(os.path.join(package_dir, "aw-app.json"), encoding="utf-8") as fh:
            entries = json.load(fh).get("contributes", {}).get("system_clis", [])
    except (OSError, ValueError) as exc:
        log.warning("aw-app-ssh: could not read its own manifest (%s)", exc)
        return []
    return [e for e in entries if isinstance(e, dict) and e.get("name") and e.get("installer")]
