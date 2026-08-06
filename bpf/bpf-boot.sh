#!/bin/bash
# cockblock-bpf firstboot installer.
#
# Installed to an obscure system path (see Makefile: install-bpf-boot) and run
# once at boot via cockblock-bpf-firstboot.service. It:
#   1. waits until `bpf` is in the active LSM list (defers + retries next boot
#      until the kernel registered BPF LSM after the grub change + reboot);
#   2. mounts bpffs if needed and attaches+pins the pre-built BPF LSM program;
#   3. enables the PERSISTENT cockblock-bpf.service so every later boot
#      re-attaches automatically (no need for this one-shot again);
#   4. removes ITSELF + its own systemd unit and daemon-reloads, so the
#      installer leaves no script behind in any system path.
#
# Pre-built artifacts (built once at `make` time, before reboot) are staged at
# /opt/cockblock/bpf/. Nothing here builds anything - the toolchain is not
# needed at boot.
#
# On any failure (bpf not active yet, attach fails) it exits non-zero and does
# NOT self-delete, so systemd retries it on the next boot.
set -euo pipefail

LOADER=/opt/cockblock/bpf/cockblock_loader
OBJ=/opt/cockblock/bpf/cockblock_lsm.bpf.o
PERSIST_UNIT=cockblock-bpf.service
PERSIST_FILE=/etc/systemd/system/$PERSIST_UNIT
SELF_UNIT=cockblock-bpf-firstboot.service
SELF_FILE=/etc/systemd/system/$SELF_UNIT
LOG=/var/log/cockblock-bpf-firstboot.log

log() { echo "[$(date -Is)] $*" >> "$LOG"; }

if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
  log "bpf not in active LSM list yet; deferring to next boot"
  exit 1
fi

# bpffs must be mounted for the pin.
if ! mountpoint -q /sys/fs/bpf; then
  mount -t bpf bpf /sys/fs/bpf
  log "mounted bpffs"
fi

# Attach + pin (loader is idempotent: skips programs already pinned, attaches
# any new ones). The loader derives pin paths from program names internally.
if ! "$LOADER" "$OBJ" >>"$LOG" 2>&1; then
  log "loader failed; will retry next boot"
  exit 1
fi
log "attached + pinned BPF LSM programs"

# Enable the persistent service for all future boots.
if [ -f "$PERSIST_FILE" ]; then
  systemctl enable "$PERSIST_UNIT" >/dev/null 2>&1 || log "could not enable $PERSIST_UNIT"
fi

# Self-destruct: disable + remove this one-shot unit and this script, then
# reload so systemd forgets it. The persistent service handles future boots.
# Best-effort: a successful load+pin+enable must NOT be negated by a cleanup
# failure (e.g. read-only mount). The script lives under /var/lib/cockblock
# (writable under the unit's ProtectSystem=strict) so this normally succeeds;
# the guard just prevents a cleanup hiccup from failing an otherwise-done job.
systemctl disable "$SELF_UNIT" >/dev/null 2>&1 || true
rm -f "$SELF_FILE" "$0" 2>/dev/null || log "self-remove partial (unit/script may linger)"
systemctl daemon-reload
log "firstboot complete; self-removed ($0, $SELF_FILE)"
