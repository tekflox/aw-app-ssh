#!/usr/bin/env bash
# Runs when the app is uninstalled.
#
# It deliberately does NOT apt-get remove openssh-client or rsync. Both are
# ordinary system tools that anything in the workspace may have started
# depending on — a terminal session, another app's script, a git remote over
# ssh. Uninstalling an app should remove that app, not quietly break unrelated
# things because this one happened to be what installed a common binary.
#
# It also leaves known_hosts alone. That used to be deleted here, on the
# reasoning that it was this app's own state; it is not. Every entry in it is a
# host key somebody accepted, and throwing them away silently downgrades the
# next connection to every one of those hosts back to trust-on-first-use. It is
# the same call aw-workspace already made for app settings — uninstalling an
# app keeps them rather than resetting them (aw-workspace 3a37efb) — and a
# 142-byte file is a far smaller problem than a security check that quietly
# forgets what it knew.
#
# What it does remove is the unpacked package prefix: binaries this app
# downloaded, which nothing else refers to and which are re-fetched on demand.
set -euo pipefail

HOME_DIR="${AW_WORKSPACE_HOME:-/opt/aw-workspace/.aw-workspace}"
PKG_DIR="$HOME_DIR/data/ssh/pkg"

if [ -d "$PKG_DIR" ]; then
  rm -rf "$PKG_DIR"
  echo "removed $PKG_DIR"
fi

echo "aw-app-ssh uninstalled — known_hosts, openssh-client and rsync left in place on purpose"
