"""Running the real ssh/rsync with the credential attached, and out of sight.

The whole point of this app is that the caller — usually an LLM — types the
command and never sees the key. So the rule this module exists to keep is:

    **the credential is never an argument, never printed, and never written
    anywhere the calling process reads back.**

How each kind gets in:

* **private key** → an ephemeral ``ssh-agent`` that lives exactly as long as
  the connection, fed through an inherited pipe (``ssh-add -``). The key never
  touches a filesystem, not even ``/dev/shm``, which is what the previous
  ``./aw ssh`` did (write 0600, ``ssh-add``, ``rm``). One less window in which
  a crash leaves a key on a tmpfs.
* **password** → ``SSH_ASKPASS`` with ``SSH_ASKPASS_REQUIRE=force``. That is
  OpenSSH's own mechanism, so there is no ``sshpass`` dependency to install and
  no pty to fake. The helper script contains no secret: it reads a 0600 file in
  a 0700 directory that is unlinked when the command exits.

**What this is not.** It keeps the value out of the agent's transcript and out
of the process table. It is not a sandbox against the caller: the parent
process runs as the same uid and could read the child's ``/proc`` if it set out
to. Anything stronger needs the connection to happen in a different trust
domain entirely, which is a different app. Saying so here so nobody reads
"never sees it" as a stronger claim than it is.

**known_hosts.** Kept under the workspace home rather than ``~/.ssh``, because
``~`` is inside a container that gets recreated: a per-container known_hosts
means the first connection to a host is unverified *every time*, which trains
everyone to ignore the warning. On the shared path it is written once and then
actually means something. The default policy is ``accept-new`` — trust on first
use, refuse on change — because ``strict`` breaks that first connection and
``no`` would silently accept a changed key forever.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

from .credentials import Credential
from .target import ssh_target_index

CONTAINER_DIR = os.environ.get("AW_WORKSPACE_CONTAINER_DIR", "/opt/aw-workspace")

_ASKPASS = "#!/bin/sh\nexec cat \"$(dirname \"$0\")/pw\"\n"


class BinaryMissing(RuntimeError):
    """The tool itself isn't installed here — say where "here" is."""


def known_hosts_path() -> str:
    home = os.environ.get("AW_WORKSPACE_HOME") or os.path.join(CONTAINER_DIR, ".aw-workspace")
    path = os.path.join(home, "data", "ssh", "known_hosts")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            open(path, "a").close()
            os.chmod(path, 0o600)
    except OSError:
        # A read-only or absent workspace home must not stop the connection;
        # ssh will fall back to its own default and warn, which is survivable.
        return ""
    return path


def ssh_options(host_key_policy: str = "accept-new",
                login_user: str | None = None) -> list[str]:
    """Defaults injected after the caller's own options, so theirs win.

    ``login_user`` is set only when the argv named no user and the credential's
    name did (``private_<user>_<host>``). Passing it as ``-o User=`` rather
    than ``-l`` keeps it in the same first-one-wins pool as everything else
    here, so a caller who did write ``-l`` still overrides it.
    """
    opts = ["-o", f"StrictHostKeyChecking={host_key_policy}"]
    path = known_hosts_path()
    if path:
        opts += ["-o", f"UserKnownHostsFile={path}"]
    if login_user:
        opts += ["-o", f"User={login_user}"]
    return opts


def require(binary: str) -> str:
    found = shutil.which(binary)
    if found:
        return found
    raise BinaryMissing(
        f"{binary!r} is not installed in this container. aw-app-ssh installs it "
        f"into the workspace container on activation (contributes.system_clis); "
        f"if you are seeing this from an agent runner container, that is a "
        f"different image and {binary} has to be present there too."
    )


#: The key pipe always arrives as this descriptor in the child. It is dup'd
#: there rather than passed at whatever number ``os.pipe()`` handed out,
#: because ``/bin/sh`` is dash on Debian and dash's ``<&N`` only parses a
#: single digit: a process that happened to be holding ten files open would
#: get "Bad fd number" and no key, intermittently and only under load.
_KEY_FD = 3


def _agent_script(program: str, read_fd: int = _KEY_FD) -> str:
    """Load the key from the inherited pipe, then become the real tool.

    ``exec`` matters: without it the shell stays as a parent and signal
    handling (Ctrl-C on an interactive session) goes to the wrong process.
    """
    return f'ssh-add -q - <&{read_fd} || exit 1\nexec {program} "$@"'


def _password_dir(value: str) -> str:
    base = "/dev/shm" if os.path.isdir("/dev/shm") else None
    d = tempfile.mkdtemp(prefix="aw-ssh-", dir=base)
    os.chmod(d, 0o700)
    with open(os.path.join(d, "pw"), "w", encoding="utf-8") as fh:
        fh.write(value if value.endswith("\n") else value + "\n")
    os.chmod(os.path.join(d, "pw"), 0o600)
    askpass = os.path.join(d, "askpass")
    with open(askpass, "w", encoding="utf-8") as fh:
        fh.write(_ASKPASS)
    os.chmod(askpass, 0o700)
    return d


def build_argv(program: str, args: list[str], *,
               host_key_policy: str = "accept-new",
               login_user: str | None = None) -> list[str]:
    """Insert our ssh defaults where ssh will still parse them.

    For ``ssh`` that is immediately before the host. For ``rsync`` it is inside
    ``-e``: an existing ``-e``/``--rsh`` from the caller is EXTENDED rather than
    replaced, because replacing it would quietly drop the transport they chose.
    """
    opts = ssh_options(host_key_policy, login_user)
    if not opts:
        return list(args)

    if program == "ssh":
        idx = ssh_target_index(args)
        if idx is None:
            return list(args)
        return list(args[:idx]) + opts + list(args[idx:])

    quoted = " ".join(_shell_quote(o) for o in opts)
    out = list(args)
    for i, a in enumerate(out):
        if a in ("-e", "--rsh") and i + 1 < len(out):
            out[i + 1] = f"{out[i + 1]} {quoted}"
            return out
        if a.startswith("--rsh="):
            out[i] = f"{a} {quoted}"
            return out
    return ["-e", f"ssh {quoted}"] + out


def _shell_quote(s: str) -> str:
    return s if s and all(c.isalnum() or c in "-_=./:" for c in s) else "'" + s.replace("'", "'\\''") + "'"


def run(program: str, args: list[str], credential: Credential, *,
        host_key_policy: str = "accept-new", login_user: str | None = None,
        cwd: str | None = None) -> int:
    """Spawn ``program`` with ``credential`` attached. Returns its exit code.

    stdin/stdout/stderr are inherited untouched — an interactive ssh session
    and rsync's progress bar both need a real terminal, and wrapping them in
    pipes is how a tool like this becomes unusable for the human case while
    still passing every non-interactive test.

    Inherited by *omission* (``Popen``'s default), not by passing ``sys.stdin``.
    They are not the same thing: ``sys.stdin`` may be a Python-level object with
    no file descriptor behind it — under pytest's capture, or anything else that
    replaces the stream — and passing it then raises before ssh ever starts.
    """
    require(program)
    argv = [program] + build_argv(program, args, host_key_policy=host_key_policy,
                                  login_user=login_user)
    env = dict(os.environ)
    cwd = cwd or os.getcwd()

    if credential.is_private_key:
        require("ssh-agent")
        read_fd, write_fd = os.pipe()
        try:
            os.set_inheritable(read_fd, True)
            # preexec_fn runs in the forked child after subprocess has closed
            # everything outside pass_fds, so this is where the pipe becomes
            # fd 3 — see _KEY_FD. Safe here specifically because this is a
            # single-threaded CLI; it would not be inside the server.
            proc = subprocess.Popen(
                ["ssh-agent", "sh", "-c", _agent_script(program), "--"] + argv[1:],
                # _KEY_FD is in pass_fds as well as read_fd: subprocess closes
                # every descriptor outside that set AFTER preexec_fn runs, so
                # without it the dup'd fd 3 is closed again before exec and the
                # child gets "Bad file descriptor" instead of a key.
                pass_fds=tuple(sorted({read_fd, _KEY_FD})), env=env, cwd=cwd,
                preexec_fn=(lambda fd=read_fd: os.dup2(fd, _KEY_FD)),
            )
            os.close(read_fd)
            read_fd = -1
            with os.fdopen(write_fd, "w") as fh:
                write_fd = -1
                fh.write(credential.value if credential.value.endswith("\n")
                         else credential.value + "\n")
            return proc.wait()
        finally:
            for fd in (read_fd, write_fd):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass

    d = _password_dir(credential.value)
    try:
        env["SSH_ASKPASS"] = os.path.join(d, "askpass")
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env.setdefault("DISPLAY", ":0")  # pre-8.4 ssh ignores askpass without it
        proc = subprocess.Popen(argv, env=env, cwd=cwd)
        return proc.wait()
    finally:
        shutil.rmtree(d, ignore_errors=True)


__all__ = ["run", "build_argv", "ssh_options", "known_hosts_path", "require",
           "BinaryMissing"]
