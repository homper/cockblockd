#!/bin/bash
# cockblock verify — one-shot check of the whole protection stack.
#
# Run after a reboot / re-login (once the cap-drop applies to your new session):
#   sudo ./verify.sh
# Prints a PASS/FAIL report for every layer and exits non-zero if any failed.
#
# Checks: BPF progs+pins, +i on all protected files/dirs, the cap-drop drop-in,
# the current session's CapBnd (CAP_LINUX_IMMUTABLE bit), the update service,
# setcap on the updater, the BPF gate actively blocking, AppArmor enforce mode,
# and the cockblock services enabled/active.
set -u

PASS=0
FAIL=0
ok()   { echo "  [PASS] $*"; PASS=$((PASS+1)); }
no()   { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
chk()  { if eval "$1"; then ok "$2"; else no "$2"; fi; }

echo "=== cockblock verify ==="

echo "[1] BPF LSM programs loaded + pinned"
chk 'bpftool prog show 2>/dev/null | grep -q block_kill_cockblock' "block_kill_cockblock loaded"
chk 'bpftool prog show 2>/dev/null | grep -q block_setflags_immutable' "block_setflags_immutable loaded"
chk '[ -e /sys/fs/bpf/cockblock_lsm ]' "pin /sys/fs/bpf/cockblock_lsm"
chk '[ -e /sys/fs/bpf/cockblock_setflags ]' "pin /sys/fs/bpf/cockblock_setflags"

echo "[2] Immutable (+i) flags"
for p in \
  /opt/cockblock/bpf/cockblock_loader \
  /opt/cockblock/bpf/cockblock_lsm.bpf.o \
  /opt/cockblock/bpf/cockblock-updat \
  /opt/cockblock/cockblockd \
  /etc/systemd/system/cockblock.service \
  /etc/systemd/system/cockblock.target \
  /etc/apparmor.d/usr.bin.chattr \
  /etc/apparmor.d/usr.bin.apparmor_parser \
  /etc/apparmor.d/shell-bpf \
  /etc/systemd/system/apparmor.service.d/override.conf ; do
  chk "lsattr \"\$p\" 2>/dev/null | cut -c1-22 | grep -q 'i'" "+i on $p"
done
for d in /opt/cockblock/bpf /etc/systemd/system/cockblock.target.wants ; do
  chk "lsattr -d \"\$d\" 2>/dev/null | cut -c1-22 | grep -q 'i'" "+i on dir $d"
done

echo "[3] Cap-drop (CAP_LINUX_IMMUTABLE removed from user sessions)"
for unit in user@.service lightdm.service getty@.service; do
  chk "[ -f /etc/systemd/system/${unit}.d/cockblock-cap-drop.conf ]" "$unit cap-drop drop-in installed"
done
# CAP_LINUX_IMMUTABLE is capability number 9. From a capped user session (sudo)
# CapBnd bit 9 should be 0. (If you run this from a root tty or boot service,
# bit 9 may still be 1 — re-test from a normal graphical/ssh session.)
echo -n "  [INFO] "; grep CapBnd /proc/self/status
bnd=$(grep CapBnd /proc/self/status | awk '{print $2}')
bit9=$(( 16#$bnd & 0x200 ))
if [ "${bit9:-1}" = "0" ]; then
  ok "session lacks CAP_LINUX_IMMUTABLE (CapBnd=$bnd) — cap-drop active"
else
  no "session still HAS CAP_LINUX_IMMUTABLE (CapBnd=$bnd) — re-login/reboot after installing session cap-drop"
fi

echo "[4] Update channel"
chk 'systemctl list-unit-files 2>/dev/null | grep -q cockblock-update.service' "cockblock-update.service installed"
chk 'getcap /opt/cockblock/bpf/cockblock-updat 2>/dev/null | grep -q cap_linux_immutable' "updater has CAP_LINUX_IMMUTABLE (setcap)"

echo "[5] BPF gate actively blocks a non-updater clear"
t=$(mktemp /tmp/cb-verify.XXXXXX)
chattr +i "$t" 2>/dev/null
if chattr -i "$t" 2>/dev/null; then no "chattr -i on +i file SUCCEEDED (gate NOT blocking)"; else ok "chattr -i on +i file DENIED (gate blocking)"; fi
/opt/cockblock/bpf/cockblock-updat clear "$t" 2>/dev/null || chattr -i "$t" 2>/dev/null
rm -f "$t" 2>/dev/null

echo "[6] AppArmor profiles in enforce mode"
# Profiles load under their PROFILE NAME (the `profile <name>` token), NOT the
# on-disk filename: chattr profile is `profile chattr ...`, the parser one is
# `profile apparmor-parser ...`. The default `aa-status` output lists one name
# per line (indented) under the "N profiles are in enforce mode." header; we
# extract that section with awk and match the name exactly.
# NOTE: `aa-status --enforced` prints only the COUNT (e.g. "159"), not the names,
# so it cannot be used for per-profile name matching.
if command -v aa-status >/dev/null 2>&1; then
  enforced=$(aa-status 2>/dev/null | awk '
    /profiles are in enforce mode\./ { in_enf=1; next }
    /^[0-9]+ profiles are in /        { in_enf=0 }
    in_enf { sub(/^[[:space:]]+/,""); sub(/[[:space:]]+$/,""); if(length($0)) print }
  ')
  for name in chattr apparmor-parser; do
    if printf '%s\n' "$enforced" | grep -qx "$name"; then
      ok "AppArmor $name enforce"
    else
      no "AppArmor $name enforce"
    fi
  done
else
  no "aa-status not installed (apt install apparmor-utils) — skipping AA profile checks"
fi

echo "[7] cockblock services"
chk 'systemctl is-enabled cockblock.service 2>/dev/null | grep -q enabled' "cockblock.service enabled"
chk 'systemctl is-active cockblock.service   2>/dev/null | grep -q active'  "cockblock.service active"
chk 'systemctl is-enabled cockblock-bpf.service 2>/dev/null | grep -q enabled' "cockblock-bpf.service enabled"

echo
echo "=== RESULT: $PASS passed, $FAIL failed ==="

[ "$FAIL" = 0 ]
