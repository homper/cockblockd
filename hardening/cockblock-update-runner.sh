#!/bin/bash
# cockblock-update-runner.sh — the cap-endowed update worker.
#
# Runs as the cockblock-update systemd SYSTEM service (Type=oneshot), which has
# CAP_LINUX_IMMUTABLE in its bounding set (system services keep it even after the
# user-session cap-drop). It reads a manifest that update.sh writes to
# /run/cockblock-update-manifest, then for each protected file runs
#   cockblock-updat update <dst> <src>   (atomic: clear +i -> copy -> re-+i)
# and reloads AppArmor (and BPF if requested). The user invokes it indirectly via
# `sudo ./update.sh` -> `systemctl start cockblock-update`; the user's own shell
# lacks CAP_LINUX_IMMUTABLE (after the cap-drop) so they CANNOT run cockblock-updat
# themselves to clear +i — only this service can.
#
# Actor = a /tmp COPY of the installed updater (basename "cockblock-updat" so the
# comm gate still matches; not +i so it runs; root service gives it the cap). Using
# the copy (not the installed binary) avoids ETXTBSY when updating the updater
# ITSELF (the installed binary would be the running actor otherwise).
set -euo pipefail

UPDATER_INST=/opt/cockblock/bpf/cockblock-updat
MANIFEST=/run/cockblock-update-manifest

if [ ! -f "$MANIFEST" ]; then
  echo "cockblock-update: no manifest at $MANIFEST" >&2
  exit 1
fi
if [ ! -x "$UPDATER_INST" ]; then
  echo "cockblock-update: $UPDATER_INST missing" >&2
  exit 1
fi

# /tmp copy of the updater as the actor (see header).
TMPD="$(mktemp -d)"
cp "$UPDATER_INST" "$TMPD/cockblock-updat"
UPDATER="$TMPD/cockblock-updat"
trap 'rm -rf "$TMPD"' EXIT

REPO=""
RELOAD_BPF=0
APT_PIN=0
ENTRIES=()

while IFS= read -r line; do
  [ -z "$line" ] && continue
  case "$line" in
    REPO=*)       REPO="${line#REPO=}" ;;
    RELOAD_BPF=*) RELOAD_BPF="${line#RELOAD_BPF=}" ;;
    APT_PIN=*)    APT_PIN="${line#APT_PIN=}" ;;
    /*)           ENTRIES+=("$line") ;;
    *)            echo "cockblock-update: bad manifest line '$line'" >&2 ;;
  esac
done < "$MANIFEST"

if [ -z "$REPO" ]; then
  echo "cockblock-update: manifest missing REPO=" >&2
  exit 1
fi

echo "=== cockblock-update: refreshing protected files (cap-endowed) ==="
for entry in "${ENTRIES[@]}"; do
  dst="${entry%%|*}"; src="${entry#*|}"
  if [ ! -e "$src" ]; then
    echo "SKIP $dst: source $src missing" >&2
    continue
  fi
  "$UPDATER" update "$dst" "$src"
done

echo
echo "=== cockblock-update: regenerating apt browser-install block ==="
if [ "$APT_PIN" = "1" ]; then
  PREF_FILE=/etc/apt/preferences.d/99-cockblock-no-browsers
  GEN="$REPO/apparmor/gen-browser-pin.sh"
  if [ -x "$GEN" ]; then
    mkdir -p "$(dirname "$PREF_FILE")"
    # We are cap-endowed (system service) so we can clear +i via the updater.
    if [ -f "$PREF_FILE" ] && lsattr "$PREF_FILE" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
      "$UPDATER" clear "$PREF_FILE"
    fi
    "$GEN" > "$PREF_FILE"
    chmod 0644 "$PREF_FILE"
    # Re-+i. Setting +i is ungated by the BPF program.
    "$UPDATER" set "$PREF_FILE"
    echo "regenerated $PREF_FILE"
  else
    echo "SKIP apt pin: $GEN missing" >&2
  fi
else
  echo "(APT_PIN not requested; leaving apt pin as-is)"
fi

echo
echo "=== cockblock-update: reloading AppArmor profiles (from $REPO) ==="
for f in usr.bin.chattr usr.bin.apparmor_parser shell-bpf; do
  if apparmor_parser -Q "$REPO/apparmor/$f" >/dev/null 2>&1; then
    apparmor_parser -r "$REPO/apparmor/$f" && echo "reloaded $f" || echo "WARN: reload $f failed" >&2
  else
    echo "SKIP $f (syntax check failed)"
  fi
done

if [ "$RELOAD_BPF" = "1" ]; then
  echo
  echo "=== cockblock-update: reloading BPF live (uses loophole #2) ==="
  for pin in /sys/fs/bpf/cockblock_lsm /sys/fs/bpf/cockblock_setflags; do
    [ -e "$pin" ] && rm -f "$pin" && echo "detached $pin"
  done
  /opt/cockblock/bpf/cockblock_loader /opt/cockblock/bpf/cockblock_lsm.bpf.o
else
  echo
  echo "=== cockblock-update: BPF .o updated on disk; programs keep running (next boot) ==="
fi

rm -f "$MANIFEST"
echo "cockblock-update: done."
