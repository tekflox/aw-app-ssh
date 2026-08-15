"""Injection: the credential gets in, and does not get out.

The leak tests are the reason this file exists. They run the real ``run()``
against a fake "ssh" that records its own argv, environment and stdin, so a
future change that passes the key on the command line — the obvious, wrong
implementation — fails here instead of in someone's shell history.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess

import pytest

from ssh_app import spawn
from ssh_app.credentials import Credential

KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nsecretmaterial\n-----END OPENSSH PRIVATE KEY-----"
PASSWORD = "hunter2-do-not-leak"


@pytest.fixture
def fake_tools(tmp_path, monkeypatch):
    """A PATH holding fake ssh/rsync/ssh-agent that dump what they were given."""
    log = tmp_path / "invocation.log"

    (tmp_path / "ssh").write_text(
        "#!/bin/sh\n"
        f'{{ echo "ARGV: $*"; echo "ENV: $(env | tr "\\n" " ")"; }} >> "{log}"\n'
    )
    (tmp_path / "rsync").write_text(
        "#!/bin/sh\n" f'echo "ARGV: $*" >> "{log}"\n'
    )
    # ssh-agent -s prints the env that reaches the daemon; -k stops it.
    (tmp_path / "ssh-agent").write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        f'  -k) echo "AGENT_KILLED" >> "{log}"; exit 0 ;;\n'
        f'  -s) echo "AGENT_STARTED" >> "{log}"\n'
        f'      echo "SSH_AUTH_SOCK={tmp_path}/agent.sock; export SSH_AUTH_SOCK;"\n'
        '      echo "SSH_AGENT_PID=4242; export SSH_AGENT_PID;"; exit 0 ;;\n'
        'esac\n'
    )
    # ssh-add takes the key on stdin — recording it is how the "arrived
    # intact" assertion is possible.
    (tmp_path / "ssh-add").write_text(
        "#!/bin/sh\n" f'cat >> "{tmp_path}/ssh-add.log"\n'
    )
    for name in ("ssh", "rsync", "ssh-agent", "ssh-add"):
        (tmp_path / name).chmod(0o755)

    # Prepended, not replaced: the fake ssh-agent shells out to sh/env/tr, and
    # a PATH holding only the fakes would fail for a reason that has nothing to
    # do with what is being tested.
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ.get('PATH', '')}")
    monkeypatch.setenv("AW_WORKSPACE_HOME", str(tmp_path / "home"))
    return tmp_path, log


def _read(path):
    return path.read_text() if path.exists() else ""


# ── the leak tests ───────────────────────────────────────────────────────

def test_a_private_key_is_never_an_argument(fake_tools):
    tmp, log = fake_tools
    spawn.run("ssh", ["root@host"], Credential("k", KEY))

    assert "secretmaterial" not in _read(log), "the key reached ssh's argv or env"


def test_a_private_key_never_touches_the_filesystem(fake_tools, monkeypatch):
    """The previous ./aw ssh wrote it 0600 to /dev/shm, ssh-add'ed it, then
    rm'ed it. A crash in that window left a key on a tmpfs; a pipe has no
    such window."""
    tmp, _ = fake_tools
    written = []
    real_open = open

    def _watch(file, mode="r", *a, **k):
        if isinstance(file, str) and any(m in mode for m in "wa+"):
            written.append(file)
        return real_open(file, mode, *a, **k)

    monkeypatch.setattr("builtins.open", _watch)
    spawn.run("ssh", ["root@host"], Credential("k", KEY))

    for path in written:
        assert KEY not in _read_path(path), f"key material landed in {path}"


def _read_path(path):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def test_the_key_actually_arrives_in_the_agent(fake_tools):
    """The mirror of the leak tests: proving it is hidden is worthless if it
    is also simply absent."""
    tmp, log = fake_tools
    spawn.run("ssh", ["root@host"], Credential("k", KEY))

    assert "AGENT_STARTED" in _read(log)
    assert "secretmaterial" in _read(tmp / "ssh-add.log")
    assert "AGENT_KILLED" in _read(log), "the agent outlived the command"


def test_a_password_is_not_an_argument_and_its_file_is_cleaned_up(fake_tools):
    tmp, log = fake_tools
    dirs_before = set(os.listdir("/dev/shm")) if os.path.isdir("/dev/shm") else set()

    spawn.run("ssh", ["root@host"], Credential("k", PASSWORD))

    assert PASSWORD not in _read(log), "the password reached ssh's argv or env"
    assert "SSH_ASKPASS" in _read(log), "askpass was never wired up"
    if os.path.isdir("/dev/shm"):
        leftover = [d for d in set(os.listdir("/dev/shm")) - dirs_before
                    if d.startswith("aw-ssh-")]
        assert not leftover, f"password directory survived the run: {leftover}"


def test_the_askpass_helper_itself_holds_no_secret(tmp_path, monkeypatch):
    """It reads a sibling file. A helper with the password baked into its text
    would be a 0700 script containing a credential, which is worse than the
    file it replaces."""
    monkeypatch.setattr("tempfile.mkdtemp", lambda **k: str(tmp_path))
    d = spawn._password_dir(PASSWORD)

    helper = os.path.join(d, "askpass")
    assert PASSWORD not in open(helper).read()
    assert stat.S_IMODE(os.stat(os.path.join(d, "pw")).st_mode) == 0o600


# ── argv construction ────────────────────────────────────────────────────

def test_our_ssh_options_land_before_the_host(monkeypatch, tmp_path):
    """ssh only accepts options before the target, and takes the FIRST value
    for each — so ours must come after everything the caller wrote."""
    monkeypatch.setenv("AW_WORKSPACE_HOME", str(tmp_path))
    argv = spawn.build_argv("ssh", ["-v", "root@host", "uptime"])

    assert argv.index("-o") == 1
    assert argv.index("root@host") > argv.index("StrictHostKeyChecking=accept-new")
    assert argv[-1] == "uptime"


def test_the_caller_can_still_override_the_host_key_policy(monkeypatch, tmp_path):
    """Their -o comes first in argv, and first wins in ssh."""
    monkeypatch.setenv("AW_WORKSPACE_HOME", str(tmp_path))
    argv = spawn.build_argv("ssh", ["-o", "StrictHostKeyChecking=yes", "root@host"])

    assert argv[:2] == ["-o", "StrictHostKeyChecking=yes"]


def test_rsync_gets_its_options_through_dash_e(monkeypatch, tmp_path):
    monkeypatch.setenv("AW_WORKSPACE_HOME", str(tmp_path))
    argv = spawn.build_argv("rsync", ["-avz", "user@host:/x", "./y"])

    assert argv[0] == "-e"
    assert argv[1].startswith("ssh ") and "StrictHostKeyChecking" in argv[1]


def test_an_existing_dash_e_is_extended_not_replaced(monkeypatch, tmp_path):
    """Replacing it would silently drop the transport the caller chose — for
    instance the port in ``-e 'ssh -p 2222'``."""
    monkeypatch.setenv("AW_WORKSPACE_HOME", str(tmp_path))
    argv = spawn.build_argv("rsync", ["-e", "ssh -p 2222", "user@host:/x", "./y"])

    assert argv.count("-e") == 1
    value = argv[argv.index("-e") + 1]
    assert "-p 2222" in value and "StrictHostKeyChecking" in value


def test_known_hosts_lives_outside_the_container_home(tmp_path, monkeypatch):
    """A per-container known_hosts makes every first connection unverified
    again after each restart, which trains people to ignore the warning."""
    monkeypatch.setenv("AW_WORKSPACE_HOME", str(tmp_path))
    path = spawn.known_hosts_path()

    assert path.startswith(str(tmp_path))
    assert os.path.exists(path)


def test_a_missing_binary_names_itself(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(spawn.BinaryMissing, match="rsync"):
        spawn.require("rsync")


def test_the_exit_code_is_the_tools(fake_tools):
    """A wrapper that swallowed rsync's exit code would report every failed
    transfer as a success."""
    tmp, _ = fake_tools
    (tmp / "rsync").write_text("#!/bin/sh\nexit 23\n")
    (tmp / "rsync").chmod(0o755)

    assert spawn.run("rsync", ["user@host:/x", "./y"], Credential("k", PASSWORD)) == 23


@pytest.mark.skipif(not shutil.which("ssh-agent") or not shutil.which("ssh-keygen"),
                    reason="needs a real OpenSSH client")
def test_a_real_agent_really_accepts_a_real_key(tmp_path):
    """The half a fake cannot check — and the half that broke.

    The previous implementation handed the key to ssh-agent on an inherited
    file descriptor. Every fake passed; the real thing worked in one container
    and died with "Bad file descriptor" in another, because fd survival across
    ssh-agent's exec is not something ssh-agent promises. This test talks to
    the real binaries, so that class of failure cannot reach a release again.
    """
    keyfile = tmp_path / "id_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(keyfile)],
                   check=True)

    env = spawn._start_agent(dict(os.environ))
    try:
        spawn._add_key(env, keyfile.read_text())
        listed = subprocess.run(["ssh-add", "-l"], env=env, capture_output=True, text=True)
        assert listed.returncode == 0 and "ED25519" in listed.stdout
    finally:
        spawn._kill_agent(env)


def test_a_key_the_agent_rejects_is_reported_as_such(fake_tools, tmp_path):
    """"ssh-add failed" and "the server refused the key" are different
    problems; conflating them sends people to the wrong host to debug."""
    tmp, _ = fake_tools
    (tmp / "ssh-add").write_text("#!/bin/sh\ncat >/dev/null\necho 'bad format' >&2\nexit 1\n")
    (tmp / "ssh-add").chmod(0o755)

    with pytest.raises(spawn.AgentError, match="bad format"):
        spawn.run("ssh", ["root@host"], Credential("k", KEY))
