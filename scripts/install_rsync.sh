#!/usr/bin/env bash
# Installs rsync into the workspace. Same reasoning as install_openssh.sh:
# python:3.12-slim ships neither, and the CLI command is useless without them.
#
# Separate script rather than one that installs both, because the runtime
# tracks and heals system CLIs individually — a shared script would make the
# healer reinstall rsync to fix ssh, and report "rsync installed" when what
# actually failed was ssh.
set -euo pipefail

if command -v rsync >/dev/null 2>&1 && rsync --version >/dev/null 2>&1; then
  echo "rsync already installed: $(rsync --version | head -1)"
  exit 0
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || {
    echo "install_rsync.sh: not root and no sudo — cannot install rsync" >&2
    exit 1
  }
  SUDO="sudo"
fi

$SUDO apt-get update -qq
$SUDO apt-get install -y --no-install-recommends rsync
$SUDO rm -rf /var/lib/apt/lists/*

rsync --version | head -1
