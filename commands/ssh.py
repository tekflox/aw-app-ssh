"""``aw-workspace-cli ssh`` — this app's own CLI command.

Auto-discovered by aw-workspace-cli from this app's installed directory
(``<apps_root>/ssh/commands/``, since this file lives at ``commands/`` in this
repo's root — see aw-workspace's ``src/cli/discovery.py``, which loads every
``<apps_root>/<slug>/commands/*.py`` exposing ``COMMAND``/``DESCRIPTION``/
``run``).

Everything real lives in ``ssh_app.cli``, shared with the ``rsync`` command
next door. This file only puts the app's package dir on ``sys.path``: Tier-1
apps load under a synthetic ``aw_apps.<id>`` namespace inside the *workspace*
process, so ``ssh_app`` is not importable as a plain top-level package from the
separate ``aw-workspace-cli`` process without it.
"""
from __future__ import annotations

import os
import sys

COMMAND = "ssh"
DESCRIPTION = "ssh with the key/password injected from the workspace vault"

APP_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def run(args: list[str]) -> int:
    if APP_DIR not in sys.path:
        sys.path.insert(0, APP_DIR)
    from ssh_app.cli import main

    return main("ssh", list(args or []))
