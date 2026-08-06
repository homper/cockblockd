#!/bin/bash
# cockblock update mechanism.
#
# Refresh the protected on-disk artifacts (BPF binaries + AppArmor profiles)
# IN PLACE, without removing them and without detaching the BPF program.
#
# "Can update, can't remove":
#   * Protected files + their directory are chattr +i. The block_setflags_immutable
#     BPF program denies clearing +i (via chattr OR raw ioctl) unless the caller
#     is the gated updater (comm "cockblock-updat"). The directory's +i blocks
#     unlink/rename the whole time, so removal is impossible even mid-update.
#   * The refresh is ATOMIC per file: cockblock-updat update <dst> <src> clears
#     +i, copies, re-+is in one process — the file is never left non-immutable.
#   * After the cap-drop (hardening/install-cap-drop.sh) a user shell lacks
#     CAP_LINUX_IMMUTABLE so it cannot clear +i at all. The actual +i work is done
#     by the cockblock-update SYSTEM service (cap-endowed), which this script
#     triggers. If that service isn't installed yet, it falls back to running the
#     updater directly (works pre-cap-drop, while root still has the cap).
#
# AppArmor profiles reload live (via the service or directly). The BPF .o is
# updated on disk; running BPF programs are pinned and keep running. BPF CODE
# changes apply on next boot, or pass --reload-bpf to detach+reload now (uses
# the still-open loophole #2: rm of bpffs pins).
#
# Residual (documented): a determined root can forge the comm / hardlink the
# updater / use systemd-run to regain CAP_LINUX_IMMUTABLE, then corrupt a file's
# CONTENT via the updater. Removal stays blocked by the directory +i. Fully
# closing content-tampering needs the trusted live-USB build.
#
# Usage (as root):
#   sudo ./update.sh               # update files + reload AppArmor
#   sudo ./update.sh --reload-bpf  # also detach+reload the BPF programs live
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
BPF_DIR="$REPO_ROOT/bpf"
AA_DIR="$REPO_ROOT/apparmor"
UPDATER="$BPF_DIR/cockblock-updat"
MANIFEST=/run/cockblock-update-manifest
SERVICE=cockblock-update.service

OPT_BPF_RELOAD=0
if [ "${1:-}" = "--reload-bpf" ]; then
  OPT_BPF_RELOAD=1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Must run as root (use: sudo $0)" >&2
  exit 1
fi

# Protected installed files and their repo sources ("dst|src"). All are +i'd
# EXCEPT the runner (it lives in the +i'd /opt/cockblock/bpf/ dir but is not
# itself +i, so it can be refreshed in-place by `cockblock-updat update` without
# touching the dir). The runner MUST be listed so `make update` deploys runner
# changes (e.g. new manifest directives like APT_PIN=) — otherwise the installed
# runner stays stale and new update.sh features never take effect.
PROTECTED=(
  "/opt/cockblock/bpf/cockblock_loader|$BPF_DIR/cockblock_loader"
  "/opt/cockblock/bpf/cockblock_lsm.bpf.o|$BPF_DIR/cockblock_lsm.bpf.o"
  "/opt/cockblock/bpf/cockblock-updat|$BPF_DIR/cockblock-updat"
  "/opt/cockblock/bpf/cockblock-update-runner.sh|$REPO_ROOT/hardening/cockblock-update-runner.sh"
  "/etc/apparmor.d/usr.bin.chattr|$AA_DIR/usr.bin.chattr"
  "/etc/apparmor.d/usr.bin.apparmor_parser|$AA_DIR/usr.bin.apparmor_parser"
  "/etc/apparmor.d/shell-bpf|$AA_DIR/shell-bpf"
)

# Non-protected (non-+i) source assets that install-core deploys. These are
# plain copies root can do directly — no cap-endowed updater needed. Listed so
# `make update` keeps them in sync alongside the protected +i artifacts. Each
# entry is "dst|src"; a src may deploy to multiple dsts (listed separately).
NONPROTECTED=(
  "/opt/cockblock/policies.json|$REPO_ROOT/policies.json"
  "/opt/cockblock/policies-unblocked.json|$REPO_ROOT/policies-unblocked.json"
  "/opt/cockblock/userChrome.css|$REPO_ROOT/userChrome.css"
  "/opt/cockblock/userContent.css|$REPO_ROOT/userContent.css"
  "/opt/cockblock/vivaldi-policies.json|$REPO_ROOT/vivaldi-policies.json"
  "/opt/cockblock/vivaldi-policies-unblocked.json|$REPO_ROOT/vivaldi-policies-unblocked.json"
  "/opt/cockblock/cb_ff_activeblock.py|$REPO_ROOT/cb_ff_activeblock.py"
  "/opt/cockblock/cb_vv_leechblock.py|$REPO_ROOT/cb_vv_leechblock.py"
  "/etc/firefox/policies/policies.json|$REPO_ROOT/policies.json"
  "/etc/vivaldi/policies/managed/cockblock.json|$REPO_ROOT/vivaldi-policies.json"
)

# --- Build -------------------------------------------------------------------
echo "=== Building (make -C bpf all) ==="
make -C "$BPF_DIR" all
if [ ! -x "$UPDATER" ]; then
  echo "ERROR: $UPDATER missing after build." >&2
  exit 1
fi

# --- Build + install the C daemon (not +i-protected, plain install works) -----
echo
echo "=== Building + installing the C daemon (make -C src install) ==="
make -C "$REPO_ROOT/src" install

# --- Refresh non-protected source assets (plain copies) -----------------------
echo
echo "=== Refreshing non-protected assets (policies / userChrome / scripts) ==="
for entry in "${NONPROTECTED[@]}"; do
  dst="${entry%%|*}"; src="${entry#*|}"
  if [ ! -e "$src" ]; then
    echo "SKIP $dst: source $src missing" >&2
    continue
  fi
  mkdir -p "$(dirname "$dst")"
  # Preserve the mode install-core uses: 0644 for data, 0755 for scripts.
  case "$dst" in
    *.py) install -m0755 "$src" "$dst" ;;
    *)    install -m0644 "$src" "$dst" ;;
  esac
  echo "refreshed $dst"
done

# --- Refresh via the cap-endowed service, or directly if it isn't installed ----
service_installed=0
if systemctl list-unit-files "$SERVICE" >/dev/null 2>&1 && \
   systemctl list-unit-files "$SERVICE" | grep -q "$SERVICE"; then
  service_installed=1
fi

if [ "$service_installed" = "1" ]; then
  echo
  echo "=== Delegating to $SERVICE (cap-endowed) ==="
  # Write the manifest the runner reads.
  {
    echo "REPO=$REPO_ROOT"
    echo "RELOAD_BPF=$OPT_BPF_RELOAD"
    echo "APT_PIN=1"
    for entry in "${PROTECTED[@]}"; do
      dst="${entry%%|*}"; src="${entry#*|}"
      [ -e "$src" ] && echo "$dst|$src"
    done
  } > "$MANIFEST"
  chmod 0600 "$MANIFEST"
  systemctl start "$SERVICE"
  echo "--- service output (last lines) ---"
  journalctl -u "$SERVICE" --no-pager -n 40 -o cat 2>/dev/null || \
    systemctl status "$SERVICE" --no-pager 2>&1 | tail -40
else
  echo
  echo "=== (service not installed) running updater directly ==="
  echo "    Install it for post-cap-drop updates: sudo hardening/install-service.sh"
  for entry in "${PROTECTED[@]}"; do
    dst="${entry%%|*}"; src="${entry#*|}"
    [ -e "$src" ] || { echo "SKIP $dst: src $src missing" >&2; continue; }
    "$UPDATER" update "$dst" "$src"
  done
  echo
  echo "=== Refreshing apt browser-install block ==="
  PREF_FILE=/etc/apt/preferences.d/99-cockblock-no-browsers
  if [ -x "$AA_DIR/gen-browser-pin.sh" ]; then
    # Clear +i on the pin file so we can overwrite it. Pre-cap-drop the shell
    # still has the cap; cockblock-updat works directly.
    if [ -f "$PREF_FILE" ] && lsattr "$PREF_FILE" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
      "$UPDATER" clear "$PREF_FILE" || chattr -i "$PREF_FILE" 2>/dev/null || true
    fi
    "$AA_DIR/gen-browser-pin.sh" > "$PREF_FILE"
    chmod 0644 "$PREF_FILE"
    # Re-+i. Setting +i is ungated by the BPF program.
    "$UPDATER" set "$PREF_FILE" 2>/dev/null || chattr +i "$PREF_FILE" 2>/dev/null || true
    echo "regenerated $PREF_FILE"
  else
    echo "SKIP apt browser pin: $AA_DIR/gen-browser-pin.sh missing" >&2
  fi
  echo
  echo "=== Reloading AppArmor profiles (from repo source) ==="
  for f in usr.bin.chattr usr.bin.apparmor_parser shell-bpf; do
    if apparmor_parser -Q "$AA_DIR/$f" >/dev/null 2>&1; then
      apparmor_parser -r "$AA_DIR/$f" && echo "reloaded $f" || echo "WARN reload $f" >&2
    else
      echo "SKIP $f (syntax check failed)"
    fi
  done
  if [ "$OPT_BPF_RELOAD" = "1" ]; then
    echo
    echo "=== Reloading BPF live (uses loophole #2) ==="
    for pin in /sys/fs/bpf/cockblock_lsm /sys/fs/bpf/cockblock_setflags; do
      [ -e "$pin" ] && rm -f "$pin" && echo "detached $pin"
    done
    /opt/cockblock/bpf/cockblock_loader /opt/cockblock/bpf/cockblock_lsm.bpf.o
  fi
fi

echo
echo "Done. Verify:"
echo "  lsattr ${PROTECTED[*]%%|*}   # all 'i'"
echo "  lsattr -d /opt/cockblock/bpf/  # dir 'i' (blocks removal)"
echo "  sudo aa-status"
echo "  bpftool prog show | grep -E 'block_kill_cockblock|block_setflags_immutable'"
