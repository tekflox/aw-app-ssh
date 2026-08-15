"""aw-app.json must match what the app actually ships.

A manifest that names a script or skill file which is not in the repo installs
fine and then fails at activation, in a container log nobody reads — the
silent-degradation shape this workspace keeps hitting. Cheaper to catch here.
"""
from __future__ import annotations

import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="module")
def manifest():
    with open(os.path.join(ROOT, "aw-app.json"), encoding="utf-8") as fh:
        return json.load(fh)


def test_required_fields(manifest):
    for key in ("manifest_version", "id", "name", "version", "description",
                "tier", "runtime", "permissions", "contributes"):
        assert key in manifest, f"missing {key}"
    assert manifest["id"] == "ssh"


def test_resource_estimate_has_no_template_placeholder(manifest):
    """``"-"`` left unfilled is what made an earlier app's marketplace sync
    fail schema validation after the release had already been cut."""
    for field, value in manifest["resource_estimate"].items():
        assert value in ("low", "medium", "high") or "MB" in value, \
            f"resource_estimate.{field} is {value!r}"


def test_every_declared_script_exists(manifest):
    for cli in manifest["contributes"]["system_clis"]:
        assert os.path.isfile(os.path.join(ROOT, cli["installer"])), cli["installer"]
        assert os.access(os.path.join(ROOT, cli["installer"]), os.X_OK), \
            f"{cli['installer']} is not executable"
    assert os.path.isfile(os.path.join(ROOT, "scripts/uninstall.sh"))


def test_every_declared_skill_exists(manifest):
    for skill in manifest["contributes"]["skills"]:
        assert os.path.isfile(os.path.join(ROOT, skill["path"])), skill["path"]


def test_installing_system_clis_is_the_only_capability_asked_for(manifest):
    """CLI commands under ``commands/`` need no permission at all — they are
    discovered from the installed directory. Asking for more than
    ``commands:install`` here would be a capability nothing uses."""
    assert manifest["permissions"] == ["commands:install"]


def test_it_depends_on_the_app_that_holds_the_secrets(manifest):
    """Without aw-app-secrets there is no vault to inject from, and the
    failure would surface as an HTTP 404 from a route nobody mounted."""
    ids = [d["id"] for d in manifest["dependencies"]["apps"]]
    assert "secrets" in ids


def test_the_commands_it_promises_are_present():
    for name in ("ssh", "rsync"):
        path = os.path.join(ROOT, "commands", f"{name}.py")
        assert os.path.isfile(path), path
        src = open(path, encoding="utf-8").read()
        assert f'COMMAND = "{name}"' in src
        assert "def run(" in src


def test_uninstall_does_not_delete_accumulated_host_keys():
    """Every entry in known_hosts is a host key somebody accepted. Deleting
    them silently downgrades the next connection to each of those hosts back to
    trust-on-first-use — the same reasoning that made aw-workspace keep an
    app's settings across an uninstall rather than reset them."""
    script = open(os.path.join(ROOT, "scripts/uninstall.sh"), encoding="utf-8").read()

    assert "known_hosts" in script, "the decision should be stated, not implicit"
    for line in script.splitlines():
        if line.strip().startswith("#"):
            continue
        assert not ("rm " in line and "known_hosts" in line), line
