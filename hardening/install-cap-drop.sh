#!/bin/bash
# Install the user-session cap-drop: remove CAP_LINUX_IMMUTABLE from the
# session-spawning systemd units (user@.service, lightdm.service, getty@.service,
# autovt@.service). After this, a root shell obtained via a terminal/ssh/sudo
# (all run inside a user session) LACKS CAP_LINUX_IMMUTABLE, so the KERNEL
# itself denies FS_IOC_SETFLAGS on +i files — the user cannot clear +i from a
# shell at all (chattr -i, raw ioctl, etc.). Only the cap-endowed cockblock-updat
# (run via cockblock-update.service) can.
#
# Run as root, AFTER `make install-update-service` (which the `make install-cap-
# drop` target depends on, so the service + setcap are already in place):
#   1. sudo bpf/install.sh
#   2. make install-update-service
#   3. make install-cap-drop        # (this) then RE-LOGIN
#
# RECOVERY (if you ever need to clear +i manually): the drop-ins are PLAIN files
# (intentionally NOT +i'd) so you can always revert:
#   sudo rm /etc/systemd/system/{user@,lightdm,getty@,autovt@}.service.d/cockblock-cap-drop.conf
#   sudo systemctl daemon-reload
#   # log out and back in (or reboot) so your new session regains the cap
#
# NOTE: the drop-ins apply to NEW sessions. Your CURRENT session keeps its
# caps until you log out/in (or reboot). So test from a fresh login.
set -euo pipefail

install_cap_drop() {
  local unit="$1"
  local dropdir="/etc/systemd/system/${unit}.d"
  local dropfile="${dropdir}/cockblock-cap-drop.conf"

  mkdir -p "$dropdir"

  # Replace any prior version.
  cat > "$dropfile" <<'EOF'
# Added by cockblock: drop CAP_LINUX_IMMUTABLE from this unit so a shell
# (incl. sudo/su from the session) cannot clear the +i flag on protected
# files. Only the cockblock-update system service (and its cap-endowed updater)
# can. Recovery: remove this file, daemon-reload, re-login/restart. See
# hardening/install-cap-drop.sh.
[Service]
CapabilityBoundingSet=~CAP_LINUX_IMMUTABLE
EOF

  echo "Installed $dropfile"
}

for unit in user@.service lightdm.service getty@.service autovt@.service; do
  install_cap_drop "$unit"
done

systemctl daemon-reload

echo
echo "Installed cap-drop drop-ins for: user@.service, lightdm.service, getty@.service, autovt@.service"
echo "  -> new sessions (after re-login/reboot) will lack CAP_LINUX_IMMUTABLE."
echo
echo "Verify (from a NEW login):"
echo "   grep CapBnd /proc/self/status    # bit 9 (CAP_LINUX_IMMUTABLE, 0x200) should be 0"
echo
echo "RECOVERY: sudo rm /etc/systemd/system/{user@,lightdm,getty@,autovt@}.service.d/cockblock-cap-drop.conf && sudo systemctl daemon-reload  (then re-login)"
