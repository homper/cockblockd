#!/bin/bash
# Build + install the cockblock BPF LSM signal blocker + the gated updater.
#
# Run as root, e.g.:  sudo ./install.sh
#
# What it does:
#   * verifies BPF LSM + BTF prerequisites
#   * builds the BPF object, the userspace loader, and the cockblock-updat
#     gated +i setter/clearer (via make)
#   * copies artifacts to /opt/cockblock/bpf/
#   * installs + enables the cockblock-bpf.service systemd unit so the LSM
#     program is attached and pinned at every boot, before cockblock.service
#   * loads the program immediately (without requiring a reboot)
#   * makes the BPF binaries + their directory immutable (+i): the dir +i
#     blocks removal/rename of any file in it; the file +i blocks content
#     tampering. The gated updater (comm "cockblock-updat") is the only thing
#     that can clear +i to refresh them — see update.sh.
#
# Once loaded, SIGHUP/SIGINT/SIGQUIT/SIGKILL/SIGUSR1/SIGUSR2/SIGSTOP sent to
# the cockblock process (comm == "cockblockd", the C daemon) are denied even
# for root; SIGTERM is allowed so systemd's RuntimeMaxSec restart loop still
# works. The block_setflags_immutable program also denies clearing +i via raw
# FS_IOC_SETFLAGS ioctl (bypassing the chattr binary) except for the updater.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/cockblock/bpf
UNIT_SRC="$HERE/cockblock-bpf.service"
UNIT_DST=/etc/systemd/system/cockblock-bpf.service

if [ "$(id -u)" -ne 0 ]; then
  echo "Must be run as root (use: sudo $0)" >&2
  exit 1
fi

# --- Prerequisites -----------------------------------------------------------

if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
  echo "ERROR: 'bpf' is not in /sys/kernel/security/lsm." >&2
  echo "       Add 'bpf' to the LSM list on the kernel command line, e.g.:" >&2
  echo "         lsm=lockdown,yama,integrity,apparmor,bpf" >&2
  echo "       (requires CONFIG_BPF_LSM=y) and reboot." >&2
  exit 1
fi

if [ ! -e /sys/kernel/btf/vmlinux ]; then
  echo "ERROR: /sys/kernel/btf/vmlinux missing (need CONFIG_DEBUG_INFO_BTF=y)." >&2
  exit 1
fi

for tool in clang-19 clang-18 clang-17 clang-16 clang-15 clang-14 clang bpftool; do
  command -v "$tool" >/dev/null 2>&1 && { FOUND_CLANG="$tool"; break; }
done
if [ -z "${FOUND_CLANG:-}" ]; then
  echo "ERROR: no clang found. Install: apt install clang bpftool libbpf-dev linux-headers-\$(uname -r) build-essential" >&2
  exit 1
fi
export CLANG="$FOUND_CLANG"
command -v bpftool >/dev/null 2>&1 || {
  echo "ERROR: 'bpftool' not found. Install: apt install bpftool" >&2
  exit 1
}
pkg-config --exists libbpf 2>/dev/null || {
  echo "ERROR: libbpf headers not found. Install: apt install libbpf-dev" >&2
  exit 1
}

# Ensure bpffs is mounted.
if ! mountpoint -q /sys/fs/bpf; then
  echo "Mounting bpffs at /sys/fs/bpf ..."
  mount -t bpf bpf /sys/fs/bpf
  if ! grep -q ' /sys/fs/bpf ' /etc/fstab 2>/dev/null; then
    echo 'none /sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime 0 0' >> /etc/fstab
  fi
fi

# --- Build -------------------------------------------------------------------

echo "Building BPF object + loader + updater ..."
make -C "$HERE" clean
make -C "$HERE" all

if [ ! -x "$HERE/cockblock-updat" ]; then
  echo "ERROR: cockblock-updat did not build." >&2
  exit 1
fi

# --- Install -----------------------------------------------------------------
#
# Idempotent re-runs: if a previous install +i'd the binaries, clear +i first
# via the repo-built cockblock-updat (comm "cockblock-updat" — the BPF gate
# allows it to clear +i even while the program is attached). A normal shell /
# chattr -i cannot. On a fresh install the files aren't +i yet, so this is a
# no-op. The directory's +i is NOT cleared here (it blocks removal of the
# binaries during the refresh); only the FILE +i is cleared for overwriting.

mkdir -p "$DEST"
if ! lsattr -d "$DEST" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
  chmod 0755 "$DEST" 2>/dev/null || true
fi

# Use the gated updater's atomic `update` mode when the destination already
# exists. It clears file +i, copies content, and re-+is — all without
# touching the directory's +i, so removal stays blocked the whole time.
# On first install the destination is missing, so fall back to plain cp.
refresh_file() {
  local dst="$1" src="$2" mode="$3"
  if [ -e "$dst" ]; then
    "$HERE/cockblock-updat" update "$dst" "$src"
  else
    cp "$src" "$dst"
    chmod "$mode" "$dst"
  fi
}

refresh_file "$DEST/cockblock_loader"    "$HERE/cockblock_loader"    0755
refresh_file "$DEST/cockblock_lsm.bpf.o" "$HERE/cockblock_lsm.bpf.o" 0644
refresh_file "$DEST/cockblock-updat"     "$HERE/cockblock-updat"     0755

install -m0644 "$UNIT_SRC" "$UNIT_DST"
systemctl daemon-reload

# Load immediately. The loader is idempotent: it attaches every program in
# the .o that isn't already pinned, and skips ones that are. This handles
# both fresh installs (no pins) and upgrades (task_kill pin exists, new
# setflags pin doesn't → only the new program is attached).
"$DEST/cockblock_loader" "$DEST/cockblock_lsm.bpf.o"

systemctl enable --now cockblock-bpf.service

# Apply +i AFTER install+load+enable. Files first (block content tampering +
# block replacing the updater with a lookalike), then the directory (block
# removal/rename of any entry). Setting +i is ungated (target not yet
# immutable), so this works even if the BPF program isn't active yet.
# cockblock-updat is +i'd so it can't be replaced; it can still be refreshed by
# update.sh (which clears its +i via the gated repo updater, overwrites, re-+is).
SET_LIST=()
for f in "$DEST/cockblock_loader" "$DEST/cockblock_lsm.bpf.o" "$DEST/cockblock-updat"; do
  if [ -e "$f" ] && ! lsattr "$f" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
    SET_LIST+=("$f")
  fi
done
if [ "${#SET_LIST[@]}" -gt 0 ]; then
  "$HERE/cockblock-updat" set "${SET_LIST[@]}"
fi

# Grant the updater the capability it needs to clear +i (used by the cap-drop
# hardening; harmless if the cap-drop is not installed).
if command -v setcap >/dev/null 2>&1; then
  setcap cap_mac_admin+ep "$DEST/cockblock-updat" 2>/dev/null || true
fi

# Grant the updater the capability it needs to clear +i (used by the cap-drop
# hardening; harmless if the cap-drop is not installed).
if command -v setcap >/dev/null 2>&1; then
  setcap cap_mac_admin+ep "$DEST/cockblock-updat" 2>/dev/null || true
fi
# NOTE: lsattr on a directory lists its CONTENTS, not the dir's own flags — so
# we MUST use `lsattr -d` here, otherwise the check sees 'i' on the files
# inside and wrongly thinks the dir is already immutable (the old bug that left
# the dir non-+i, so removal was never blocked).
if [ -d "$DEST" ] && ! lsattr -d "$DEST" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
  "$HERE/cockblock-updat" set "$DEST"
fi

echo
echo "Done. Verify with:"
echo "  lsattr $DEST/cockblock_loader $DEST/cockblock_lsm.bpf.o $DEST   # all 'i'"
echo "  ls -l /sys/fs/bpf/cockblock_lsm /sys/fs/bpf/cockblock_setflags"
echo "  bpftool prog show | grep -E 'block_kill_cockblock|block_setflags_immutable'"
echo "  bpftool link show"
echo "  systemctl status cockblock-bpf.service"
echo
echo "Test (the following should now fail with EPERM, even as root):"
echo "  sudo kill -9 \$(pgrep -x cockblockd)"
echo "  sudo chattr -i $DEST/cockblock_loader     # denied by BPF (not gated updater)"
echo "  sudo rm $DEST/cockblock_loader            # denied: dir is +i"
echo
echo "To refresh protected files later (update without removing):"
echo "  sudo ./update.sh                # from the repo root"
