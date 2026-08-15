"""Every test gets its own workspace home.

This app keeps real state under ``$AW_WORKSPACE_HOME/data/ssh`` — known_hosts,
remembered ports, outstanding approval ids — on storage shared with every
container in the workspace. Without this fixture the suite reads and writes
*that*: a run on a developer's machine reached in and truncated the live
`pending.json`, and two tests then failed because they were reading state left
behind by a third.

Autouse, so it cannot be forgotten by the next module. A test that genuinely
wants the real paths has to say so by overriding the env var itself, which is
the right way round.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolated_workspace_home(tmp_path, monkeypatch):
    monkeypatch.setenv("AW_WORKSPACE_HOME", str(tmp_path / "aw-workspace-home"))
    return tmp_path / "aw-workspace-home"
