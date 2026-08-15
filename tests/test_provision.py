"""Making the binary exist, in a container that may not let you install one.

The unit tests here pin the decisions; the one real test at the bottom is
opt-in because it downloads a package. That split is deliberate — the last two
bugs in this app both survived a full green suite and died on contact with a
second container, so there is a test that touches the real thing, and it is
kept out of CI's way rather than watered down until it would pass anywhere.
"""
from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from ssh_app import provision


@pytest.fixture(autouse=True)
def isolated_prefix(tmp_path, monkeypatch):
    monkeypatch.setenv("AW_WORKSPACE_HOME", str(tmp_path))
    return tmp_path


# ── where things go ──────────────────────────────────────────────────────

def test_the_prefix_is_keyed_by_distro_and_arch(isolated_prefix):
    """It lives on a filesystem shared with containers running a different
    image. An Ubuntu 24.04 amd64 tree unpacked over a Debian container's would
    be a very confusing kind of broken."""
    key = os.path.basename(provision.prefix())

    assert key.count("-") >= 2, key
    assert provision.prefix().startswith(str(isolated_prefix))


def test_a_provisioned_binary_is_found_in_the_prefix(isolated_prefix):
    binary = os.path.join(provision.prefix(), "usr/bin", "rsync")
    os.makedirs(os.path.dirname(binary))
    open(binary, "w").close()
    os.chmod(binary, 0o755)

    assert provision.provisioned_path("rsync") == binary


def test_a_non_executable_file_is_not_a_provisioned_binary(isolated_prefix):
    binary = os.path.join(provision.prefix(), "usr/bin", "rsync")
    os.makedirs(os.path.dirname(binary))
    open(binary, "w").close()
    os.chmod(binary, 0o644)

    assert provision.provisioned_path("rsync") is None


# ── strategy selection ───────────────────────────────────────────────────

def test_something_on_path_is_never_reinstalled(monkeypatch):
    """The overwhelmingly common case, and it must cost nothing — no apt, no
    network, no lock."""
    monkeypatch.setattr(provision, "_run", _explode)
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/bin/" + b)

    assert provision.ensure("rsync") == "/usr/bin/rsync"


def test_an_unknown_binary_is_refused_rather_than_guessed(monkeypatch):
    """Mapping a name to a package by guessing would let a typo install
    something arbitrary from the archive."""
    monkeypatch.setattr(shutil, "which", lambda b: None)
    with pytest.raises(provision.ProvisionError, match="does not|not one"):
        provision.ensure("rsyncc")


def test_sudo_that_would_prompt_does_not_count_as_sudo(monkeypatch):
    """`sudo -n` matters: an agent-runner container HAS sudo and refuses it
    without a password. Discovering that by hanging on a password prompt
    inside a non-interactive command is the worst way to learn it."""
    monkeypatch.setattr(os, "geteuid", lambda: 1001)
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/bin/sudo")
    monkeypatch.setattr(provision, "_run",
                        lambda cmd, **k: subprocess.CompletedProcess(cmd, 1, "", "password"))

    assert provision._can_install_system_wide() is False


def test_root_needs_no_sudo(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert provision._can_install_system_wide() is True


# ── what gets unpacked, and what never does ──────────────────────────────

def test_glibc_is_never_vendored():
    """A downloaded libc under the host's loader is how a container ends up
    with a binary that segfaults for reasons that look nothing like the cause.
    If the image is too old, say so — do not paper over it."""
    for package in ("libc6", "libc6-dev", "libc-bin", "libgcc-s1"):
        assert package.startswith(provision._NEVER_VENDOR)


def test_dependencies_are_parsed_past_versions_and_alternatives(monkeypatch):
    """Real Depends lines look like
    ``libssl3t64 (>= 3.0.0) | libssl3, libc6 (>= 2.38)``."""
    monkeypatch.setattr(provision, "_run", lambda cmd, **k: subprocess.CompletedProcess(
        cmd, 0, "libacl1 (>= 2.2.23), libssl3t64 (>= 3.0.0) | libssl3, lsb-base\n", ""))

    assert provision._dependencies("x.deb") == ["libacl1", "libssl3t64", "lsb-base"]


def test_a_binary_whose_libraries_are_missing_is_not_working(monkeypatch, tmp_path):
    """Present, executable, and useless — the distinction this workspace keeps
    relearning. `which` says yes and every call fails."""
    monkeypatch.setattr(provision, "_run", lambda cmd, **k: subprocess.CompletedProcess(
        cmd, 127, "", "rsync: error while loading shared libraries: libpopt.so.0"))

    assert provision._works(str(tmp_path / "rsync")) is False


def test_a_binary_that_runs_is_working(monkeypatch, tmp_path):
    monkeypatch.setattr(provision, "_run", lambda cmd, **k: subprocess.CompletedProcess(
        cmd, 0, "rsync  version 3.2.7", ""))

    assert provision._works(str(tmp_path / "rsync")) is True


def test_missing_sonames_are_read_off_ldd(monkeypatch, tmp_path):
    monkeypatch.setattr(provision, "_run", lambda cmd, **k: subprocess.CompletedProcess(
        cmd, 0,
        "\tlibpopt.so.0 => not found\n"
        "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f)\n", ""))

    assert provision._missing_sonames(str(tmp_path / "rsync")) == ["libpopt.so.0"]


def test_apt_is_pointed_at_a_private_state_dir():
    """The whole unprivileged trick: apt needs root for its paths, not for its
    work."""
    opts = " ".join(provision._apt_private("/somewhere"))

    assert "Dir::State::Lists=/somewhere/lists" in opts
    assert "Dir::Cache=/somewhere/cache" in opts


def test_the_library_path_only_lists_directories_that_exist(isolated_prefix):
    lib = os.path.join(provision.prefix(), "usr/lib/x86_64-linux-gnu")
    os.makedirs(lib)

    assert lib in provision.library_path()
    assert "::" not in provision.library_path(), "an empty entry means the cwd"


def test_a_container_with_no_apt_says_so_instead_of_failing_obscurely(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda b: None)
    with pytest.raises(provision.ProvisionError, match="added to the image"):
        provision._fetch_unprivileged("rsync", "rsync")


# ── the real thing ───────────────────────────────────────────────────────

@pytest.mark.skipif(os.environ.get("AW_SSH_TEST_PROVISION") != "1",
                    reason="downloads a package; set AW_SSH_TEST_PROVISION=1")
def test_it_really_installs_rsync_without_root(isolated_prefix):
    """The test that would have caught both of this app's shipped bugs.

    Runs the actual unprivileged path — private apt state, .deb fetch, unpack,
    missing-library resolution — and then RUNS the binary. "It unpacked" is not
    the claim; "it works here" is.
    """
    path = provision.ensure("rsync")

    assert os.path.isfile(path)
    env = dict(os.environ)
    if provision.library_path():
        env["LD_LIBRARY_PATH"] = provision.library_path()
    out = subprocess.run([path, "--version"], capture_output=True, text=True, env=env)
    assert out.returncode == 0 and "rsync" in out.stdout


def _explode(*_a, **_k):
    raise AssertionError("shelled out when the binary was already on PATH")


@pytest.mark.skipif(os.environ.get("AW_SSH_TEST_PROVISION") != "1",
                    reason="downloads a package; set AW_SSH_TEST_PROVISION=1")
def test_it_does_not_leave_the_package_index_behind(isolated_prefix):
    """~30MB of durable, shared storage for a 400KB binary. This workspace has
    already had apps vanish once because the host disk reached 100%."""
    provision.ensure("rsync")

    assert not os.path.isdir(os.path.join(provision.prefix(), ".apt"))
    size = sum(os.path.getsize(os.path.join(r, f))
               for r, _d, fs in os.walk(provision.prefix()) for f in fs)
    assert size < 20 * 1024 * 1024, f"prefix is {size // 1024 // 1024}MB"
