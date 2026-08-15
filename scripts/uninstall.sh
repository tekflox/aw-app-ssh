#!/usr/bin/env bash
# Runs when the app is uninstalled.
#
# It deliberately does NOT apt-get remove openssh-client or rsync. Both are
# ordinary system tools that anything in the workspace may have started
# depending on — a terminal session, another app's script, a git remote over
# ssh. Uninstalling an app should remove that app, not quietly break unrelated
# things because this one happened to be what installed a common binary.
#
# What it does clean up is this app's own state: the shared known_hosts it
# maintains under the workspace home. Left behind, it is a file nobody owns.
set -euo pipefail

HOME_DIR="${AW_WORKSPACE_HOME:-/opt/aw-workspace/.aw-workspace}"
KNOWN_HOSTS="$HOME_DIR/data/ssh/known_hosts"

if [ -f "$KNOWN_HOSTS" ]; then
  rm -f "$KNOWN_HOSTS"
  rmdir "$HOME_DIR/data/ssh" 2>/dev/null || true
  echo "removed $KNOWN_HOSTS"
fi

echo "aw-app-ssh uninstalled — openssh-client and rsync left installed on purpose"
