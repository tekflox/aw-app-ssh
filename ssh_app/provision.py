"""Making sure ssh/rsync exist here, whatever "here" turns out to be.

The command runs in whatever container invoked it, and those containers are not
the same image. The workspace container is `python:3.12-slim` with sudo; an
agent-runner container is Ubuntu with **no sudo at all** (`sudo: a password is
required`). So "the app installs its binaries on activation" only ever covered
one of the two places the app is used, and everywhere else the command existed
and then refused to work — which is the app telling the user to go and solve
the app's own problem.

This module closes that. Three strategies, tried in order, first one that
applies wins:

1. **already on PATH** — nothing to do, and the overwhelmingly common case.
2. **root or passwordless sudo** — a normal `apt-get install`. Clean, system
   wide, and what the workspace container gets.
3. **neither** — fetch the .deb without root and unpack it into a prefix on the
   workspace's shared filesystem.

(3) is the interesting one. `apt-get` needs root only because of where it
writes; pointed at a private state and cache directory it runs perfectly well
as an ordinary user, which is what `_APT_PRIVATE` does. The package is then
unpacked with `dpkg-deb -x` and only the shared libraries that are genuinely
*missing* get unpacked alongside it.

**glibc is never vendored.** Mixing a downloaded libc with the host's dynamic
loader is how a container ends up with a binary that segfaults for reasons that
look nothing like the cause. If something needs a newer libc than this image
has, that is a fact about the image and it should be said out loud rather than
worked around.

The prefix is keyed by distro *and* architecture — an Ubuntu 24.04 amd64 tree
is useless to a Debian container sharing the same filesystem. Because it lives
under the workspace home, the second container to need rsync finds the first
one's copy already there.
"""
from __future__ import annotations

import glob
import logging
import os
import shutil
import subprocess
import tempfile

log = logging.getLogger("aw_apps.ssh")

CONTAINER_DIR = os.environ.get("AW_WORKSPACE_CONTAINER_DIR", "/opt/aw-workspace")

#: Which package carries which binary. ssh, ssh-add and ssh-agent all ship in
#: openssh-client, so asking for any one of them provisions the other two.
PACKAGE_FOR = {
    "ssh": "openssh-client",
    "ssh-add": "openssh-client",
    "ssh-agent": "openssh-client",
    "ssh-keygen": "openssh-client",
    "rsync": "rsync",
}

#: Never unpacked from a .deb, no matter what an ldd says is missing. See the
#: module docstring — a vendored libc is a worse problem than a missing one.
_NEVER_VENDOR = ("libc6", "libc-bin", "libgcc-s1", "libcrypt1")

_VERSION_FLAG = {"ssh": "-V", "ssh-agent": "-h", "ssh-add": "-l"}


class ProvisionError(RuntimeError):
    """Could not make the binary exist, and the message says how far it got."""


# ── where things live ────────────────────────────────────────────────────

def _workspace_home() -> str:
    return os.environ.get("AW_WORKSPACE_HOME") or os.path.join(CONTAINER_DIR, ".aw-workspace")


def _platform_key() -> str:
    """``ubuntu-24.04-amd64``. Distro AND arch, because the prefix sits on a
    filesystem shared with containers running neither."""
    name, version = "linux", "unknown"
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            fields = dict(
                line.rstrip("\n").split("=", 1) for line in fh if "=" in line)
        name = fields.get("ID", name).strip('"')
        version = fields.get("VERSION_ID", version).strip('"')
    except OSError:
        pass
    arch = _run(["dpkg", "--print-architecture"]).stdout.strip() or "unknown"
    return f"{name}-{version}-{arch}"


def prefix() -> str:
    return os.path.join(_workspace_home(), "data", "ssh", "pkg", _platform_key())


def library_path() -> str:
    """The ``LD_LIBRARY_PATH`` entries a provisioned binary needs, if any."""
    root = prefix()
    dirs = [d for d in glob.glob(os.path.join(root, "usr/lib/*"))
            + glob.glob(os.path.join(root, "lib/*"))
            + [os.path.join(root, "usr/lib"), os.path.join(root, "lib")]
            if os.path.isdir(d)]
    return os.pathsep.join(dirs)


def provisioned_path(binary: str) -> str | None:
    for rel in ("usr/bin", "bin", "usr/sbin"):
        candidate = os.path.join(prefix(), rel, binary)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


# ── the entry point ──────────────────────────────────────────────────────

def ensure(binary: str, *, announce=None) -> str:
    """Return a working path to ``binary``, installing it if it is missing.

    ``announce`` is called with a one-line human message before anything slow
    happens, so a first run says why it is pausing instead of appearing hung.
    """
    found = shutil.which(binary)
    if found:
        return found

    already = provisioned_path(binary)
    if already and _works(already):
        return already

    package = PACKAGE_FOR.get(binary)
    if not package:
        raise ProvisionError(f"{binary!r} is not one this app knows how to install")

    if announce:
        announce(f"# {binary} is not installed here — fetching {package} "
                 f"(first run in this container only)")

    if _can_install_system_wide():
        _apt_install(package)
        found = shutil.which(binary)
        if found:
            return found
        log.warning("aw-app-ssh: apt installed %s but %s is still not on PATH",
                    package, binary)

    _fetch_unprivileged(package, binary)
    path = provisioned_path(binary)
    if not path:
        raise ProvisionError(
            f"unpacked {package} but found no {binary} in {prefix()} — the "
            f"package layout is not what this app expects"
        )
    if not _works(path):
        raise ProvisionError(
            f"{binary} was fetched to {path} but will not run here. Missing "
            f"shared libraries that could not be resolved without root; this "
            f"container needs {package} installed in its image."
        )
    return path


# ── strategy 2: root / sudo ──────────────────────────────────────────────

def _can_install_system_wide() -> bool:
    if os.geteuid() == 0:
        return True
    if not shutil.which("sudo"):
        return False
    # -n: never prompt. A sudo that would ask for a password is a sudo we do
    # not have, and finding that out by hanging on a password prompt inside a
    # non-interactive command is the worst possible way to learn it.
    return _run(["sudo", "-n", "true"]).returncode == 0


def _apt_install(package: str) -> None:
    sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]
    _run(sudo + ["apt-get", "update", "-qq"], timeout=300)
    out = _run(sudo + ["apt-get", "install", "-y", "--no-install-recommends", package],
               timeout=600)
    if out.returncode != 0:
        log.warning("aw-app-ssh: apt-get install %s failed (%s) — falling back "
                    "to an unprivileged fetch", package, out.stderr.strip()[:200])


# ── strategy 3: no root at all ───────────────────────────────────────────

def _apt_private(state: str) -> list[str]:
    """apt-get options that move every write into ``state``.

    This is the whole trick: apt needs root for its *paths*, not its work.
    """
    return [
        "-o", f"Dir::State::Lists={state}/lists",
        "-o", f"Dir::Cache={state}/cache",
        "-o", "Debug::NoLocking=1",
        "-o", "APT::Sandbox::User=root",
        # Translations are a third of the index and this never shows a
        # localised package description to anyone.
        "-o", "Acquire::Languages=none",
    ]


def _fetch_unprivileged(package: str, binary: str) -> None:
    if not shutil.which("apt-get") or not shutil.which("dpkg-deb"):
        raise ProvisionError(
            f"{binary!r} is missing and this container has no apt-get/dpkg-deb "
            f"to fetch it with, nor root to install it. It has to be added to "
            f"the image."
        )

    state = os.path.join(prefix(), ".apt")
    for sub in ("lists/partial", "cache/archives/partial"):
        os.makedirs(os.path.join(state, sub), exist_ok=True)

    if not glob.glob(os.path.join(state, "lists", "*Packages*")):
        out = _run(["apt-get"] + _apt_private(state) + ["update"], timeout=600)
        if not glob.glob(os.path.join(state, "lists", "*Packages*")):
            raise ProvisionError(
                f"could not read the package lists without root: "
                f"{out.stderr.strip()[:300] or 'apt-get update produced nothing'}"
            )

    with tempfile.TemporaryDirectory(dir=state) as work:
        deb = _download(package, state, work)
        _unpack(deb, prefix())
        _resolve_missing_libraries(deb, binary, state, work)

    # The package index is ~30MB and provisioning happens about once per
    # container image. Keeping it would make a rare second fetch quick at the
    # cost of holding 30MB of durable, shared storage forever — and this
    # workspace has already had apps vanish once because the host disk hit
    # 100%. Re-downloading occasionally is the cheaper mistake.
    shutil.rmtree(state, ignore_errors=True)


def _download(package: str, state: str, work: str) -> str:
    out = _run(["apt-get"] + _apt_private(state) + ["download", package],
               cwd=work, timeout=600)
    debs = glob.glob(os.path.join(work, "*.deb"))
    if not debs:
        raise ProvisionError(
            f"could not download {package}: {out.stderr.strip()[:300] or 'no .deb produced'}")
    return debs[0]


def _unpack(deb: str, target: str) -> None:
    """Unpack into a staging dir and move it in, so a half-written tree is
    never what another container finds."""
    os.makedirs(target, exist_ok=True)
    staging = tempfile.mkdtemp(prefix=".unpack-", dir=target)
    try:
        _run(["dpkg-deb", "-x", deb, staging], timeout=300)
        for root, _dirs, files in os.walk(staging):
            rel = os.path.relpath(root, staging)
            dest_dir = os.path.join(target, rel) if rel != "." else target
            os.makedirs(dest_dir, exist_ok=True)
            for name in files:
                os.replace(os.path.join(root, name), os.path.join(dest_dir, name))
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _resolve_missing_libraries(deb: str, binary: str, state: str, work: str) -> None:
    """Unpack the dependencies that supply a soname ldd reports as missing.

    Only those. Unpacking every dependency would drag in glibc and half the
    base system for the sake of one small library, and would replace working
    system libraries with whatever version the archive happens to serve.
    """
    path = provisioned_path(binary)
    if not path:
        return

    for _round in range(3):          # deps of deps; three is far past enough
        missing = _missing_sonames(path)
        if not missing:
            return
        progressed = False
        for dep in _dependencies(deb):
            if dep.startswith(_NEVER_VENDOR):
                continue
            try:
                dep_deb = _download(dep, state, tempfile.mkdtemp(dir=work))
            except ProvisionError:
                continue
            if any(so in _run(["dpkg-deb", "-c", dep_deb]).stdout for so in missing):
                _unpack(dep_deb, prefix())
                progressed = True
        if not progressed:
            return


def _dependencies(deb: str) -> list[str]:
    raw = _run(["dpkg-deb", "-f", deb, "Depends"]).stdout
    names = []
    for clause in raw.split(","):
        # "libssl3t64 (>= 3.0.0) | libssl3" — take the first alternative
        name = clause.split("|")[0].split("(")[0].strip()
        if name and name not in names:
            names.append(name)
    return names


def _missing_sonames(path: str) -> list[str]:
    env = dict(os.environ)
    lib = library_path()
    if lib:
        env["LD_LIBRARY_PATH"] = lib + os.pathsep + env.get("LD_LIBRARY_PATH", "")
    out = _run(["ldd", path], env=env)
    return [line.split("=>")[0].strip()
            for line in out.stdout.splitlines() if "not found" in line]


# ── helpers ──────────────────────────────────────────────────────────────

def _works(path: str) -> bool:
    """Runs, rather than merely exists. A binary whose libraries are missing is
    present, executable, and useless — the distinction this workspace keeps
    relearning."""
    binary = os.path.basename(path)
    env = dict(os.environ)
    lib = library_path()
    if lib:
        env["LD_LIBRARY_PATH"] = lib + os.pathsep + env.get("LD_LIBRARY_PATH", "")
    out = _run([path, _VERSION_FLAG.get(binary, "--version")], env=env, timeout=30)
    # ssh -V and ssh-add -l exit non-zero by design; a loader failure is what
    # is actually being detected, and it always says so on stderr.
    return "error while loading shared libraries" not in out.stderr


def _run(cmd: list[str], *, cwd: str | None = None, env: dict | None = None,
         timeout: float = 120) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, cwd=cwd, env=env, timeout=timeout,
                              capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(cmd, 1, "", str(exc))


__all__ = ["ensure", "prefix", "library_path", "provisioned_path",
           "ProvisionError", "PACKAGE_FOR"]
