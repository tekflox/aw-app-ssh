#!/usr/bin/env bash
# Installs the OpenSSH *client* (ssh, ssh-agent, ssh-add) into the workspace.
#
# The aw-workspace base image is python:3.12-slim, which has no ssh at all —
# so without this the `aw-workspace-cli ssh` command exists and then dies on
# its first invocation. sudo is required because the container's default user
# is unprivileged (the image ships sudo with NOPASSWD for exactly this).
#
# Idempotent: safe to re-run on install, on every reconcile pass after a
# workspace recreation, and from the runtime's system-CLI healer — which is
# what re-installs it if an unrelated apt operation removes it later.
#
# Only openssh-client. openssh-server would open a listening sshd in a
# container that has no business having one.
set -euo pipefail

if command -v ssh >/dev/null 2>&1 && ssh -V >/dev/null 2>&1 \
   && command -v ssh-agent >/dev/null 2>&1 && command -v ssh-add >/dev/null 2>&1; then
  echo "openssh-client already installed: $(ssh -V 2>&1)"
  exit 0
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || {
    echo "install_openssh.sh: not root and no sudo — cannot install openssh-client" >&2
    exit 1
  }
  SUDO="sudo"
fi

$SUDO apt-get update -qq
$SUDO apt-get install -y --no-install-recommends openssh-client
$SUDO rm -rf /var/lib/apt/lists/*

ssh -V
