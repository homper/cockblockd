#!/bin/bash
# Install session-level cap-drop: remove CAP_LINUX_IMMUTABLE from the bounding
# set of the services that actually FORK login sessions, so every process in
# those sessions (terminals, sudo, su, scripts) inherits a bounding set WITHOUT
# cap 9. sudo is setuid root, but a setuid-root binary can only ever gain caps
# that are in its INHERITED bounding set — so even `sudo chattr -i` on a +i
# file is denied by the kernel at FS_IOC_SETFLAGS, independent of the BPF gate
# (which remains the primary layer; this is the boot/early-stage backstop).
#
# Why these units (the existing user@.service drop-in is NOT enough):
#  - lightdm.service forks the GRAPHICAL session. The session runs in
#    session-N.scope, which is a SIBLING of user@<uid>.service under
#    user-<uid>.slice, NOT a child of it. So user@.service's CapabilityBoundingSet
#    never reaches the graphical session. lightdm forks the session process, so
#    lightdm's bounding set (set by systemd at service start) is what the session
#    inherits. A drop here reaches the whole graphical session tree.
#  - getty@.service forks the TTY login shell (via login). autovt@.service is an
#    alias to getty@.service, so this drop-in covers VT logins too.
#  - user@.service (already installed by install-cap-drop.sh) is kept as-is: it
#    covers `systemctl --user` units, which are forked by the user manager.
#
# Effect: after `systemctl daemon-reload` + a lightdm restart (or reboot), the
# graphical session's CapBnd bit 9 (CAP_LINUX_IMMUTABLE = 0x200) is 0. Verify:
#   grep CapBnd /proc/self/status   # expect bit 9 clear
#   sudo ./verify.sh                 # [3] should now PASS (session lacks the cap)
#
# RECOVERY (these drop-ins are PLAIN files, intentionally NOT +i'd, matching the
# user@.service cap-drop design so you can always revert):
#   sudo rm /etc/systemd/system/lightdm.service.d/cockblock-cap-drop.conf \
#            /etc/systemd/system/getty@.service.d/cockblock-cap-drop.conf
#   sudo systemctl daemon-reload
#   reboot   # or restart lightdm / re-login, to regain the cap in a new session
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Must run as root (use: sudo $0)" >&2; exit 1
fi

CAP=CAP_LINUX_IMMUTABLE

install_dropin() {
  local unit="$1"
  local dir="/etc/systemd/system/${unit}.d"
  local file="$dir/cockblock-cap-drop.conf"
  mkdir -p "$dir"
  # Re-run safety: clear +i if a prior install locked it (shouldn't happen —
  # these are intentionally left plain — but be safe). chattr -i is fine here
  # because this runs as root before any BPF-gate consideration on the drop-in
  # itself; if the BPF gate denies chattr, the file wasn't +i to begin with.
  if [ -f "$file" ] && lsattr "$file" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
    chattr -i "$file" 2>/dev/null || true
  fi
  cat > "$file" <<EOF
# Added by cockblock: drop $CAP from this unit's bounding set so all sessions
# forked by it (and their sudo/su children) can NEVER gain it. The '~' subtracts
# the cap from systemd's default (full) set. Recovery: delete this file,
# daemon-reload, re-login/reboot. See hardening/install-session-capdrop.sh.
[Service]
CapabilityBoundingSet=~$CAP
EOF
  echo "installed $file"
}

install_dropin lightdm.service
install_dropin getty@.service

systemctl daemon-reload

echo
echo "Done. The drop applies to NEWLY started sessions only (the bounding set is"
echo "fixed at fork time), so take effect via:"
echo "  - graphical: reboot, OR 'sudo systemctl restart lightdm' (logs you out!)"
echo "  - TTY:       next login on a getty VT"
echo
echo "After re-login, verify:"
echo "  grep CapBnd /proc/self/status   # bit 9 (0x200) must be 0"
echo "  sudo ./verify.sh                 # [3] should now PASS"
echo
echo "RECOVERY:"
echo "  sudo rm /etc/systemd/system/lightdm.service.d/cockblock-cap-drop.conf \\"
echo "           /etc/systemd/system/getty@.service.d/cockblock-cap-drop.conf"
echo "  sudo systemctl daemon-reload && sudo reboot"
