"""Running the real ssh/rsync with the credential attached, and out of sight.

The whole point of this app is that the caller — usually an LLM — types the
command and never sees the key. So the rule this module exists to keep is:

    **the credential is never an argument, never printed, and never written
    anywhere the calling process reads back.**

How each kind gets in:

* **private key** → an ``ssh-agent`` started for this one command and killed
  when it returns, with the key handed to ``ssh-add`` on its stdin. The key
  never touches a filesystem, not even ``/dev/shm``, which is what the previous
  ``./aw ssh`` did (write 0600, ``ssh-add``, ``rm``). One less window in which
  a crash leaves a key on a tmpfs.

  An earlier version passed the key on an inherited descriptor to
  ``ssh-agent sh -c 'ssh-add - <&3; exec ssh'``. It worked in the agent-runner
  container and failed in the workspace container with "Bad file descriptor" —
  whether an arbitrary fd survives ssh-agent's exec is not something ssh-agent
  promises, and it varies by build. Worth remembering before anyone reaches for
  that trick again: it looks tidier and is not portable.
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
import re
import subprocess
import tempfile

from . import provision
from .credentials import Credential
from .target import ssh_target_index

CONTAINER_DIR = os.environ.get("AW_WORKSPACE_CONTAINER_DIR", "/opt/aw-workspace")

_ASKPASS = "#!/bin/sh\nexec cat \"$(dirname \"$0\")/pw\"\n"


class BinaryMissing(RuntimeError):
    """The tool itself isn't installed here — say where "here" is."""


class AgentError(RuntimeError):
    """The key never reached an agent — distinct from ssh refusing it."""


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
                login_user: str | None = None,
                port: int | None = None) -> list[str]:
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
    if port:
        opts += ["-o", f"Port={port}"]
    return opts


def require(binary: str, announce=None) -> str:
    """The path to ``binary``, installing it here if this container lacks it.

    Used to raise and tell the caller to go and run the command somewhere else,
    which was the app handing its own problem to the user. It now provisions —
    see ``provision.py`` for what that means without root — and only fails when
    it genuinely cannot.
    """
    try:
        return provision.ensure(binary, announce=announce)
    except provision.ProvisionError as exc:
        raise BinaryMissing(f"{binary}: {exc}") from exc


def _start_agent(env: dict) -> dict:
    """Start an ssh-agent of our own and return the env that reaches it.

    The obvious implementation — ``ssh-agent sh -c 'ssh-add - <&3; exec ssh'``
    with the key on an inherited descriptor — is what this replaces. It worked
    in one container and failed in another with "Bad file descriptor": whether
    an arbitrary fd survives ssh-agent's exec is not something ssh-agent
    promises, and it differs between OpenSSH builds. Nothing in this app should
    depend on that.

    So the agent is started as a daemon, the key goes in over ``ssh-add``'s own
    stdin — a pipe, still never a file — and the connection inherits only
    ``SSH_AUTH_SOCK``. Portable, and the same shape on every host.
    """
    out = subprocess.run(["ssh-agent", "-s"], capture_output=True, text=True, env=env)
    if out.returncode != 0:
        raise AgentError(f"ssh-agent would not start: {out.stderr.strip() or out.returncode}")
    agent_env = dict(env)
    for key in ("SSH_AUTH_SOCK", "SSH_AGENT_PID"):
        m = re.search(rf"{key}=([^;]+);", out.stdout)
        if m:
            agent_env[key] = m.group(1)
    if "SSH_AUTH_SOCK" not in agent_env:
        raise AgentError("ssh-agent started but printed no SSH_AUTH_SOCK")
    return agent_env


def _add_key(agent_env: dict, value: str) -> None:
    """Feed the key to the agent on stdin. Its stderr is safe to surface —
    ssh-add never echoes key material, only what went wrong with it."""
    out = subprocess.run(
        ["ssh-add", "-"], input=value if value.endswith("\n") else value + "\n",
        capture_output=True, text=True, env=agent_env,
    )
    if out.returncode != 0:
        raise AgentError(
            f"the key could not be loaded into ssh-agent: "
            f"{out.stderr.strip() or 'ssh-add exited ' + str(out.returncode)}"
        )


def _kill_agent(agent_env: dict) -> None:
    subprocess.run(["ssh-agent", "-k"], env=agent_env,
                   capture_output=True, check=False)


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
               login_user: str | None = None,
               port: int | None = None) -> list[str]:
    """Insert our ssh defaults where ssh will still parse them.

    For ``ssh`` that is immediately before the host. For ``rsync`` it is inside
    ``-e``: an existing ``-e``/``--rsh`` from the caller is EXTENDED rather than
    replaced, because replacing it would quietly drop the transport they chose.
    """
    opts = ssh_options(host_key_policy, login_user, port)
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


def _env_for_provisioned(env: dict) -> dict:
    """Put the app's own package prefix in front of PATH and LD_LIBRARY_PATH.

    Needed even when the program itself was found on PATH: ssh shells out to
    ssh-agent and ssh-add, and rsync shells out to ssh. If one of those was the
    binary this app had to fetch, the child has to be able to find it too.
    """
    root = provision.prefix()
    bins = [d for d in (os.path.join(root, "usr/bin"), os.path.join(root, "bin"))
            if os.path.isdir(d)]
    if bins:
        env["PATH"] = os.pathsep.join(bins + [env.get("PATH", "")])
    libs = provision.library_path()
    if libs:
        env["LD_LIBRARY_PATH"] = os.pathsep.join(
            [libs] + ([env["LD_LIBRARY_PATH"]] if env.get("LD_LIBRARY_PATH") else []))
    return env


def run(program: str, args: list[str], credential: Credential, *,
        host_key_policy: str = "accept-new", login_user: str | None = None,
        port: int | None = None, cwd: str | None = None, announce=None) -> int:
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
    program_path = require(program, announce)
    argv = [program_path] + build_argv(program, args, host_key_policy=host_key_policy,
                                       login_user=login_user, port=port)
    env = _env_for_provisioned(dict(os.environ))
    cwd = cwd or os.getcwd()

    if credential.is_private_key:
        require("ssh-agent", announce)
        require("ssh-add", announce)
        agent_env = _start_agent(env)
        try:
            _add_key(agent_env, credential.value)
            return subprocess.Popen(argv, env=agent_env, cwd=cwd).wait()
        finally:
            _kill_agent(agent_env)

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
           "BinaryMissing", "AgentError"]
