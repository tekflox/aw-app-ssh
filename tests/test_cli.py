"""The command surface: flag splitting, dry run, and the paths that must not
reach the network.

``--aw-dry-run`` gets the most attention here because it is what the skill tells
agents to run first. If it ever requests a secret, the advice becomes "check
whether this host exists by interrupting someone", which is the opposite of the
point.
"""
from __future__ import annotations

import pytest

from ssh_app import cli
from ssh_app import credentials as creds
from ssh_app import spawn
from ssh_app.credentials import Credential, CredentialError

KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----"


@pytest.fixture
def vault(monkeypatch):
    """Inventory present, reads recorded — so a test can assert none happened."""
    reads = []

    def _request(method, path, body=None, timeout=None):
        if method == "GET":
            return 200, {"secrets": [{"name": "private_root_host"},
                                     {"name": "resend_api_key"}]}
        reads.append((path, body))
        return 200, {"status": "approved", "value": KEY}

    monkeypatch.setattr(creds, "request", _request)
    return reads


@pytest.fixture
def spawned(monkeypatch):
    calls = []
    monkeypatch.setattr(spawn, "run",
                        lambda *a, **k: calls.append((a, k)) or 0)
    monkeypatch.setattr(cli.spawn, "run", spawn.run)
    return calls


# ── flag splitting ───────────────────────────────────────────────────────

def test_our_flags_are_removed_and_everything_else_survives_in_order():
    """The contract is "these are ssh's arguments". A wrapper that reordered
    or dropped one would break copy-pasted commands in ways nobody would
    connect back to this app."""
    opts, rest = cli._split_own_flags(
        ["-avz", "--aw-scope", "10min", "user@h:/x", "--aw-dry-run", "./y"])

    assert rest == ["-avz", "user@h:/x", "./y"]
    assert opts["scope"] == "10min" and opts["dry_run"] is True


def test_equals_form_works_too():
    opts, rest = cli._split_own_flags(["--aw-secret=custom_name", "root@h"])
    assert opts["secret"] == "custom_name" and rest == ["root@h"]


def test_an_unknown_aw_flag_is_an_error_not_a_passthrough():
    """Passing ``--aw-typo`` through would hand ssh an option it rejects, and
    the error would blame ssh for this app's mistake."""
    with pytest.raises(CredentialError, match="unknown option"):
        cli._split_own_flags(["--aw-scpoe", "10min", "root@h"])


def test_a_bad_scope_is_refused_rather_than_widened():
    """Silently falling back would be fine; silently widening would not, and
    the failure mode is invisible either way. Refuse."""
    with pytest.raises(CredentialError, match="one_shot"):
        cli._split_own_flags(["--aw-scope", "forever", "root@h"])


# ── dry run ──────────────────────────────────────────────────────────────

def test_dry_run_resolves_without_requesting_anything(vault, capsys):
    assert cli.main("ssh", ["--aw-dry-run", "root@host"]) == 0
    out = capsys.readouterr().out

    assert "private_root_host" in out
    assert vault == [], "a dry run asked a human for a secret"


def test_dry_run_shows_the_argv_that_would_run(vault, capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("AW_WORKSPACE_HOME", str(tmp_path))
    cli.main("ssh", ["--aw-dry-run", "-v", "root@host", "uptime"])

    assert "StrictHostKeyChecking" in capsys.readouterr().out


def test_status_never_costs_a_prompt(vault, capsys):
    assert cli.main("ssh", ["status", "root@host"]) == 0
    assert "private_root_host" in capsys.readouterr().out
    assert vault == []


def test_status_on_an_unknown_host_fails_without_asking(vault, capsys):
    assert cli.main("ssh", ["status", "root@nowhere"]) == 1
    assert vault == []


# ── the connecting path ──────────────────────────────────────────────────

def test_a_real_run_fetches_then_spawns(vault, monkeypatch):
    seen = {}
    monkeypatch.setattr(cli.spawn, "run",
                        lambda prog, args, cred, **k: seen.update(
                            prog=prog, args=args, cred=cred) or 0)

    assert cli.main("ssh", ["root@host", "uptime"]) == 0
    assert seen["prog"] == "ssh"
    assert seen["args"] == ["root@host", "uptime"], "our flags leaked into ssh's argv"
    assert seen["cred"].is_private_key
    assert len(vault) == 1, "expected exactly one read request"


def test_the_reason_sent_to_the_human_names_the_command(vault, monkeypatch):
    monkeypatch.setattr(cli.spawn, "run", lambda *a, **k: 0)
    cli.main("ssh", ["root@host", "systemctl restart nginx"])

    assert "systemctl restart nginx" in vault[0][1]["reason"]


def test_rsync_with_no_remote_side_is_refused_before_any_lookup(vault, capsys):
    """Both paths local: there is nothing to authenticate, and resolving a
    credential for it would be asking for a key to copy a file to itself."""
    assert cli.main("rsync", ["-a", "./a/", "./b/"]) == 1
    assert "nothing to authenticate" in capsys.readouterr().err
    assert vault == []


def test_the_tools_exit_code_is_returned(vault, monkeypatch):
    # require() is stubbed because this container genuinely has no rsync; what
    # is under test is that a non-zero exit propagates, not binary presence.
    monkeypatch.setattr(cli.spawn, "require", lambda b, a=None: b)
    monkeypatch.setattr(cli.spawn, "run", lambda *a, **k: 23)
    assert cli.main("rsync", ["user@host:/x", "./y"]) == 23


def test_a_missing_credential_is_reported_not_raised(vault, capsys):
    assert cli.main("ssh", ["root@nowhere"]) == 1
    assert "no credential in the vault" in capsys.readouterr().err


def test_help_needs_no_workspace_at_all(capsys):
    """A broken workspace link must not make ``--help`` unreadable."""
    assert cli.main("ssh", ["--help"]) == 0
    assert "--aw-dry-run" in capsys.readouterr().out


def test_the_resolved_user_is_passed_to_ssh_when_the_argv_had_none(monkeypatch, capsys):
    """The bug this catches: the right key, handed to ssh with no user, so it
    logs in as the local account and is refused."""
    monkeypatch.setattr(creds, "request", lambda m, p, b=None, timeout=None:
                        (200, {"secrets": [{"name": "private_deploy_box"}]}))
    cli.main("ssh", ["--aw-dry-run", "box"])
    out = capsys.readouterr().out

    assert "User=deploy" in out
    assert "login  : deploy" in out


def test_an_explicit_user_is_not_second_guessed(monkeypatch, capsys):
    monkeypatch.setattr(creds, "request", lambda m, p, b=None, timeout=None:
                        (200, {"secrets": [{"name": "private_root_host"}]}))
    cli.main("ssh", ["--aw-dry-run", "root@host"])

    assert "User=" not in capsys.readouterr().out


def test_a_missing_binary_is_caught_before_anyone_is_asked(vault, monkeypatch, capsys):
    """Found by running it for real: in a container without rsync the command
    fetched the credential — one notification, one one-shot grant spent — and
    only then died on the missing binary."""
    monkeypatch.setattr(cli.spawn, "require", _raise_missing)

    assert cli.main("rsync", ["user@host:/x", "./y"]) == 1
    assert "not installed" in capsys.readouterr().err
    assert vault == [], "asked for a secret it could never have used"


def _raise_missing(binary, announce=None):
    raise spawn.BinaryMissing(f"{binary!r} is not installed in this container.")


def test_a_dry_run_does_not_install_anything(vault, monkeypatch, capsys):
    """It promises to ask nobody and do nothing. Downloading a package is not
    nothing — and on a slow link it would make the cheap, safe check the
    expensive one."""
    monkeypatch.setattr(cli.spawn, "require", _explode_on_require)

    assert cli.main("ssh", ["--aw-dry-run", "root@host"]) == 0
    assert "private_root_host" in capsys.readouterr().out


def _explode_on_require(binary, announce=None):
    raise AssertionError("a dry run tried to install a binary")


def test_the_dry_run_says_nothing_about_binaries(vault, monkeypatch, capsys):
    """Whether ssh and rsync exist here is the app's problem, and it is solved.
    Reporting it would invite a caller to plan around a question that has no
    answer they can act on."""
    monkeypatch.setattr(cli.spawn, "require", _explode_on_require)
    cli.main("ssh", ["--aw-dry-run", "root@host"])
    out = capsys.readouterr().out

    assert "binary" not in out.lower()
    assert "fetch" not in out.lower()
