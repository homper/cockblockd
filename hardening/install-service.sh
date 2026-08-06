#!/bin/bash
# Install the cockblock-update system service (the cap-endowed update channel)
# and grant CAP_LINUX_IMMUTABLE to the cockblock-updat binary via file caps.
#
# Run as root, AFTER `sudo bpf/install.sh` and BEFORE the cap-drop
# (hardening/install-cap-drop.sh). Order matters:
#   1. sudo bpf/install.sh              # BPF gate + +i files/dir/updater
#   2. sudo hardening/install-service.sh   # (this) runner + service + setcap
#   3. sudo hardening/install-cap-drop.sh  # user-session cap-drop
#
# Why a service: once the cap-drop is installed, a user-shell (sudo from a
# terminal) lacks CAP_LINUX_IMMUTABLE, so it cannot run cockblock-updat to clear
# +i. Updates must go through this SYSTEM service, which keeps the cap. update.sh
# builds, writes a manifest, and `systemctl start`s this service.
#
# setcap must run while the updater is NOT +i (immutable blocks xattr writes),
# so we clear +i first (via the repo updater), setcap, then re-+i. The cap xattr
# then persists on the +i'd inode and the kernel grants it at exec.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
DEST=/opt/cockblock/bpf
UPDATER_INSTALLED="$DEST/cockblock-updat"
UPDATER_REPO="$REPO/bpf/cockblock-updat"

if [ "$(id -u)" -ne 0 ]; then
  echo "Must run as root." >&2; exit 1
fi
command -v setcap >/dev/null 2>&1 || {
  echo "ERROR: 'setcap' not found. Install: apt install libcap2-bin" >&2; exit 1
}

# setcap needs the updater non-+i. If a previous install +i'd it, clear first via
# the gated repo updater (works pre-cap-drop, since root still has the cap).
if [ -e "$UPDATER_INSTALLED" ] && lsattr "$UPDATER_INSTALLED" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
  echo "Clearing +i on $UPDATER_INSTALLED to setcap ..."
  "$UPDATER_REPO" clear "$UPDATER_INSTALLED"
fi

# Grant CAP_LINUX_IMMUTABLE to the updater binary (effective+permitted).
setcap CAP_LINUX_IMMUTABLE+ep "$UPDATER_INSTALLED"
echo "setcap CAP_LINUX_IMMUTABLE+ep on $UPDATER_INSTALLED"
getcap "$UPDATER_INSTALLED" || true

# Re-apply +i (the cap xattr persists; +i blocks further xattr writes, not reads).
"$UPDATER_REPO" set "$UPDATER_INSTALLED"

# Install the runner + the system service unit.
# The /opt dir is +i (from bpf/install.sh), which blocks CREATING the new runner
# file (immutable dir refuses new entries). Clear the dir's +i first (gated
# updater: the dir is immutable, so only cockblock-updat can clear it), install
# the runner + unit, then re-+i the dir.
if [ -d "$DEST" ] && lsattr -d "$DEST" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
  "$UPDATER_REPO" clear "$DEST"
fi
install -m0755 "$HERE/cockblock-update-runner.sh" "$DEST/cockblock-update-runner.sh"
install -m0644 "$HERE/cockblock-update.service" /etc/systemd/system/cockblock-update.service
systemctl daemon-reload
if [ -d "$DEST" ] && ! lsattr -d "$DEST" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
  "$UPDATER_REPO" set "$DEST"
fi
# Do NOT enable: this is a triggered oneshot (no [Install]); it's started on
# demand by `systemctl start cockblock-update` from update.sh.
echo "installed cockblock-update.service (started on demand by update.sh)"

echo
echo "Done. After installing the cap-drop (hardening/install-cap-drop.sh), test:"
echo "  sudo ./update.sh          # triggers the service; should refresh + reload"
echo "  systemctl status cockblock-update.service"
echo "  getcap $UPDATER_INSTALLED   # CAP_LINUX_IMMUTABLE+ep"
