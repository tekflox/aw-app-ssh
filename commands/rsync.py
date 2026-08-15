"""``aw-workspace-cli rsync`` — this app's own CLI command.

The twin of ``commands/ssh.py``; see that file for how discovery works and why
the ``sys.path`` line is needed. Both call the same ``ssh_app.cli.main`` with a
different program name, so "which credential, and how does it get in" has one
implementation and cannot drift between the two.
"""
from __future__ import annotations

import os
import sys

COMMAND = "rsync"
DESCRIPTION = "rsync over ssh with the key/password injected from the workspace vault"

APP_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def run(args: list[str]) -> int:
    if APP_DIR not in sys.path:
        sys.path.insert(0, APP_DIR)
    from ssh_app.cli import main

    return main("rsync", list(args or []))
