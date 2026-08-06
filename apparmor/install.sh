#!/bin/bash
# Install the cockblock protection (filesystem immutable + AppArmor).
# Run as root, e.g.:  sudo ./install.sh
#
# This blocks `systemctl disable cockblock` in a cockblock-SPECIFIC way (does
# NOT affect other units) by combining two layers:
#
#   1. Filesystem immutable DIRECTORY: cockblock.service is
#      WantedBy=cockblock.target, and cockblock.target is
#      WantedBy=multi-user.target. We `chattr +i` the
#      cockblock.target.wants/ DIRECTORY so the kernel refuses to unlink any
#      entry inside it. When `systemctl disable cockblock` tries to unlink the
#      cockblock.service enable symlink from cockblock.target.wants/, it fails
#      with EPERM. The symlink stays a real symlink (systemd honors it), so the
#      unit still auto-starts at boot - unlike the old hardlink trick, which
#      broke systemd's enablement recognition (systemd only honors symlinks in
#      .wants/). We also `chattr +i` the unit and target files themselves.
#
#      NOTE: symlinks cannot carry +i on ext4, and `chattr +i` on the unit file
#      inode does NOT protect the .wants/ symlink (a separate inode) that
#      `systemctl disable` removes. The immutable DIRECTORY is the only
#      cockblock-specific mechanism that blocks the unlink.
#
#      Residual bypass (intentional): the TOP-level enable symlink
#      multi-user.target.wants/cockblock.target lives in the SHARED
#      multi-user.target.wants/ dir, which we do NOT make immutable. So
#      `systemctl disable cockblock.target` still succeeds and prevents
#      boot-time start (the running instance survives via Restart=always).
#      To close this globally, `chattr +i` that shared dir (blocks ALL units).
#
#   2. AppArmor: confine `chattr` so the user cannot `chattr -i` to undo the
#      immutable flags on the cockblock files / the cockblock.target.wants/
#      directory, and confine rm/mv/cp/... so the files can't be
#      removed/overwritten by the common tools either.
#
# Order matters: the immutable flags are set BEFORE the AppArmor chattr profile
# is loaded, otherwise the install's own `chattr +i` would be blocked (the
# chattr profile denies opening the cockblock paths for chattr, including +i).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
AA_DIR="/etc/apparmor.d"

UNIT=/etc/systemd/system/cockblock.service
TARGET=/etc/systemd/system/cockblock.target
TARGET_WANTS_DIR=/etc/systemd/system/cockblock.target.wants
SERVICE_WANTS_LINK="$TARGET_WANTS_DIR/cockblock.service"
MU_TARGET_LINK=/etc/systemd/system/multi-user.target.wants/cockblock.target
# Obsolete wants entry from the OLD (broken) scheme: a hardlink at
# multi-user.target.wants/cockblock.service. The new scheme does not use it.
OLD_MU_SERVICE_LINK=/etc/systemd/system/multi-user.target.wants/cockblock.service
ENV=/etc/default/cockblock
# apt preferences pin that blocks install/upgrade of any non-installed browser
# via apt (Pin-Priority: -1). Already-installed browsers (e.g. firefox,
# vivaldi-stable, managed by cockblock itself) are EXCLUDED from the pin at
# install time so they keep receiving security upgrades.
PREF_FILE=/etc/apt/preferences.d/99-cockblock-no-browsers
REPO_ROOT="$(cd "$HERE/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "Must run as root (use: sudo $0)" >&2
  exit 1
fi

# cb_attr set|clear <file> — set/clear the +i flag.
# Once the BPF gate (block_setflags_immutable) is loaded AND the AppArmor chattr
# profile is enforced, `chattr -i`/`chattr +i` on cockblock-protected +i files is
# DENIED (chattr is AppArmor-confined + the BPF gate only allows comm
# "cockblock-updat" to clear +i). So we try chattr first (works on a FIRST
# install before the gate/profile load, and on non-protected paths), then fall
# back to cockblock-updat (raw FS_IOC_SETFLAGS ioctl; NOT AppArmor-confined; the
# BPF gate allows it because comm == "cockblock-updat"). cockblock-updat needs
# CAP_LINUX_IMMUTABLE (root has it pre-cap-drop; for post-cap-drop maintenance,
# revert the cap-drop first). Setting +i is ungated by the BPF program; only
# clearing +i is gated.
cb_attr() {
  local mode="$1" f="$2"
  if [ "$mode" = set ]; then
    chattr +i "$f" 2>/dev/null && return 0
  else
    chattr -i "$f" 2>/dev/null && return 0
  fi
  if [ -x "$REPO_ROOT/bpf/cockblock-updat" ]; then
    "$REPO_ROOT/bpf/cockblock-updat" "$mode" "$f" && return 0
    echo "ERROR: cockblock-updat $mode $f failed" >&2
    return 1
  fi
  echo "ERROR: cannot $mode +i on $f (chattr denied; build cockblock-updat: make bpf)" >&2
  return 1
}

for need in "$UNIT" "$ENV"; do
  if [ ! -e "$need" ]; then
    echo "Missing $need - install the cockblock systemd unit first (make install)." >&2
    exit 1
  fi
done

# Sanity: the installed cockblock.service MUST use WantedBy=cockblock.target
# (the new scheme). If it still says multi-user.target, the unit was not
# refreshed (run `make install` / `make install-core` first).
if ! grep -q '^WantedBy=cockblock.target$' "$UNIT"; then
  echo "ERROR: $UNIT does not contain 'WantedBy=cockblock.target'." >&2
  echo "       The installed unit is stale. Re-run 'make install' (or" >&2
  echo "       'make install-core') to install the updated cockblock.service" >&2
  echo "       and cockblock.target, then re-run this script." >&2
  exit 1
fi

# --- Layer 1: filesystem immutable -------------------------------------------
#
# Goal (cockblock-specific): block `systemctl disable cockblock` by making the
# cockblock.target.wants/ DIRECTORY immutable, so the kernel refuses to unlink
# the cockblock.service enable symlink inside it. That symlink stays a real
# symlink (systemd only honors symlinks in .wants/) so boot-time start works.

# Install the intermediate target unit from the repo if it is missing, or
# refresh it if present and NOT already immutable (a previous install would
# have made it immutable, in which case we must not/should not overwrite).
if [ ! -e "$TARGET" ]; then
  install -m0644 "$REPO_ROOT/cockblock.target" "$TARGET"
  echo "installed $TARGET"
elif lsattr "$TARGET" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
  echo "$TARGET already present and immutable; leaving as-is"
else
  install -m0644 "$REPO_ROOT/cockblock.target" "$TARGET"
  echo "refreshed $TARGET"
fi

# Clean up the obsolete OLD-scheme wants entry (hardlink at
# multi-user.target.wants/cockblock.service). On a fresh install it is absent;
# on an upgrade from the broken scheme it should already have been removed by
# the recovery step. Remove it only if it is not immutable.
if [ -e "$OLD_MU_SERVICE_LINK" ]; then
  if lsattr "$OLD_MU_SERVICE_LINK" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
    echo "WARNING: obsolete $OLD_MU_SERVICE_LINK is immutable and still present." >&2
    echo "         Run the recovery step (clear +i) before re-running." >&2
  else
    rm -f "$OLD_MU_SERVICE_LINK"
    echo "removed obsolete old-scheme wants entry $OLD_MU_SERVICE_LINK"
  fi
fi

# Enable the intermediate target (creates $MU_TARGET_LINK, a symlink in the
# shared multi-user.target.wants/ - NOT immutable, see cockblock.target docs).
if [ -L "$MU_TARGET_LINK" ] || [ -e "$MU_TARGET_LINK" ]; then
  echo "target enable symlink already present: $MU_TARGET_LINK"
else
  systemctl enable cockblock.target
  echo "enabled cockblock.target ($MU_TARGET_LINK)"
fi

# Enable the service (creates the cockblock.service symlink inside
# $TARGET_WANTS_DIR). MUST happen BEFORE we make that directory immutable.
mkdir -p "$TARGET_WANTS_DIR"
if [ -L "$SERVICE_WANTS_LINK" ] || [ -e "$SERVICE_WANTS_LINK" ]; then
  echo "service enable symlink already present: $SERVICE_WANTS_LINK"
else
  systemctl enable cockblock.service
  echo "enabled cockblock.service ($SERVICE_WANTS_LINK)"
fi

# Make the unit file, target file, and the cockblock.target.wants/ DIRECTORY
# immutable. The directory immutability is what blocks `systemctl disable
# cockblock` (kernel EPERM on unlink of the service symlink inside it).
# Idempotent: skip each if already immutable.
for f in "$UNIT" "$TARGET" "$TARGET_WANTS_DIR"; do
  if [ -d "$f" ]; then
    flags=$(lsattr -d "$f" 2>/dev/null | cut -c1-22 || true)
  else
    flags=$(lsattr "$f" 2>/dev/null | cut -c1-22 || true)
  fi
  if echo "$flags" | grep -q 'i'; then
    echo "$f is already immutable"
  else
    # chattr is confined by the chattr AppArmor profile (enforce) on cockblock
    # paths once that profile is loaded; on a FIRST install it isn't loaded yet
    # so chattr works. If chattr is denied, fall back to the gated cockblock-updat
    # (raw FS_IOC_SETFLAGS ioctl, NOT AppArmor-confined; setting +i is ungated
    # by the BPF program) if it's been built.
    if chattr +i "$f" 2>/dev/null; then
      echo "set +i (immutable) on $f"
    elif [ -x "$REPO_ROOT/bpf/cockblock-updat" ]; then
      "$REPO_ROOT/bpf/cockblock-updat" set "$f"
      echo "set +i (immutable) on $f (via cockblock-updat)"
    else
      echo "ERROR: could not set +i on $f (chattr denied; build cockblock-updat: make bpf)" >&2
      exit 1
    fi
  fi
done

systemctl daemon-reload

# --- Layer 2: AppArmor profiles ----------------------------------------------

# Remove the obsolete all-units systemctl dbus profile if a previous install
# left it (it blocks `systemctl disable` for ALL units - we no longer use it).
if [ -f "$AA_DIR/usr.bin.systemctl" ]; then
  apparmor_parser -R "$AA_DIR/usr.bin.systemctl" || true
  rm -f "$AA_DIR/usr.bin.systemctl"
  echo "removed obsolete $AA_DIR/usr.bin.systemctl"
fi

# New + existing protection profiles. The cockblock-related ones are also made
# immutable on disk (chattr +i) AFTER loading so that even a non-confined
# writer can't replace them on disk (the apparmor_parser profile stops -R/-r
# at runtime; the immutable flag stops on-disk tampering).
#
# NOTE: after converting to enforce mode, apparmor_parser cannot read the
# cockblock profile files from /etc/apparmor.d/ (self-protection). Syntax-
# checks and loads therefore read from the repo source path ($HERE) instead.
AA_PROFILES=(
  usr.bin.chattr
  usr.bin.apparmor_parser
  shell-bpf
)
# Profiles whose on-disk files we also chattr +i (self-protection of the
# protection). Done AFTER loading so the install's own writes succeed.
IMMUTABLE_PROFILES=(
  usr.bin.chattr
  usr.bin.apparmor_parser
  shell-bpf
)

for f in "${AA_PROFILES[@]}"; do
  # Re-run safety: a previous install chattr +i'd these profile files. Clear
  # the flag before overwriting. Use the gated repo updater if available
  # (it can clear +i even when the BPF program is active); otherwise fall
  # back to chattr for first-time installs before the BPF gate is loaded.
  if [ -f "$AA_DIR/$f" ] && lsattr "$AA_DIR/$f" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
    if [ -x "$REPO_ROOT/bpf/cockblock-updat" ]; then
      "$REPO_ROOT/bpf/cockblock-updat" clear "$AA_DIR/$f" || true
    else
      chattr -i "$AA_DIR/$f" || true
    fi
  fi
  install -m0644 "$HERE/$f" "$AA_DIR/$f"
  # Syntax-check (does not load into kernel); load if it passes, else skip.
  # This keeps the install resilient: e.g. the `bpf` AppArmor rule (used by
  # shell-bpf) is not supported on every parser/kernel, and we must not abort
  # the whole lockdown because one optional profile won't parse.
  #
  # Load from the repo source path ($HERE) rather than $AA_DIR because the
  # apparmor_parser binary is confined by the (enforce-mode) apparmor-parser
  # profile, which denies reading the cockblock profile files from /etc/apparmor.d/.
  if apparmor_parser -Q "$HERE/$f" >/dev/null 2>&1; then
    apparmor_parser -r "$HERE/$f"
    echo "loaded $f"
  else
    echo "SKIP $f (syntax check failed - rule not supported by this AppArmor); file left in place but not loaded"
  fi
done

# --- Layer 3: make the protection profile files immutable --------------------

for f in "${IMMUTABLE_PROFILES[@]}"; do
  if [ -f "$AA_DIR/$f" ] && ! lsattr "$AA_DIR/$f" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
    if [ -x "$REPO_ROOT/bpf/cockblock-updat" ]; then
      "$REPO_ROOT/bpf/cockblock-updat" set "$AA_DIR/$f" || true
    else
      chattr +i "$AA_DIR/$f" || true
    fi
    echo "set +i on $AA_DIR/$f"
  fi
done

# --- Layer 4: harden the apparmor systemd unit (refuse manual stop) -----------
# Create a drop-in override so `systemctl stop apparmor` (which would unload
# ALL profiles) is refused. Restarts/shutdown are unaffected. This protects the
# apparmor unit itself, complementing the cockblock unit's RefuseManualStop.

AA_OVERRIDE_DIR=/etc/systemd/system/apparmor.service.d
mkdir -p "$AA_OVERRIDE_DIR"
# Re-run safety: clear +i on the override if a previous install set it. Use
# cb_attr (chattr, else cockblock-updat): if the override is +i and the BPF gate
# is loaded, chattr -i is DENIED (only the gated updater can clear +i).
if [ -f "$AA_OVERRIDE_DIR/override.conf" ] && lsattr "$AA_OVERRIDE_DIR/override.conf" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
  cb_attr clear "$AA_OVERRIDE_DIR/override.conf"
fi
cat > "$AA_OVERRIDE_DIR/override.conf" <<'EOF'
# Added by cockblock: refuse manual stop so profiles can't be bulk-unloaded.
[Unit]
RefuseManualStop=yes
EOF
if ! lsattr "$AA_OVERRIDE_DIR/override.conf" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
  cb_attr set "$AA_OVERRIDE_DIR/override.conf"
  echo "set +i on $AA_OVERRIDE_DIR/override.conf"
fi
systemctl daemon-reload

# --- Layer 5: kernel hardening (sysctl) ---------------------------------------
# kernel.sysrq=0 : disable magic SysRq (could be used to send signals / reset).
# Set unconditionally - it's safe and reversible until next boot only if you
# re-run with a different value; default distro value is usually 176.
if [ -w /proc/sys/kernel/sysrq ]; then
  echo 0 > /proc/sys/kernel/sysrq
  if ! grep -q '^kernel.sysrq' /etc/sysctl.d/99-cockblock.conf 2>/dev/null; then
    echo 'kernel.sysrq = 0' >> /etc/sysctl.d/99-cockblock.conf
  fi
  echo "set kernel.sysrq=0"
fi

# kernel.modules_disabled=1 : ONE-WAY. Once set, NO module load/unload is
# possible until reboot (blocks rmmod/modprobe/insmod for everything, not just
# cockblock). This is the strongest userspace-accessible module protection.
# BPF programs are NOT modules, so the cockblock BPF LSM is unaffected.
#
# This is opt-in and off by default because it is irreversible until reboot and
# also blocks loading unrelated modules. To enable, run:
#     sudo SET_MODULES_DISABLED=1 ./install.sh
# Only set it AFTER the cockblock BPF service is loaded + enabled (see bpf/).
if [ "${SET_MODULES_DISABLED:-0}" = "1" ]; then
  if [ "$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo 0)" != "1" ]; then
    echo 1 > /proc/sys/kernel/modules_disabled
    if ! grep -q '^kernel.modules_disabled' /etc/sysctl.d/99-cockblock.conf 2>/dev/null; then
      echo 'kernel.modules_disabled = 1' >> /etc/sysctl.d/99-cockblock.conf
    fi
    echo "set kernel.modules_disabled=1 (IRREVERSIBLE until reboot)"
  fi
else
  echo "NOTE: kernel.modules_disabled NOT set (opt-in). Enable with SET_MODULES_DISABLED=1"
  echo "      AFTER installing+enabling the BPF service (bpf/install.sh)."
fi

# --- Layer 6: apt browser install block (preferences pin + immutable) ----------
#
# Goal: stop the user from installing any OTHER browser via apt (firefox-esr,
# chromium, chromium-browser (the snap stub), opera, chrome, edge, brave, ...).
# cockblock-MANAGED browsers (firefox, vivaldi-stable) are EXCLUDED from the pin
# (NOT "all installed browsers") so they keep receiving security upgrades.
# This matters because on Ubuntu the firefox AND chromium-browser .debs are
# snap stubs: both show as "installed" but only firefox is managed by cockblock.
#
# Mechanism:
#   /etc/apt/preferences.d/99-cockblock-no-browsers pins the listed packages to
#   Pin-Priority: -1, which makes `apt install <pkg>` fail with "no installation
#   candidate". The pin is recomputed on every install.sh run AND every
#   `make update` (which routes through the cap-endowed cockblock-update service,
#   the path that works post-cap-drop). Generation logic lives in the shared
#   apparmor/gen-browser-pin.sh so install.sh and the update runner stay in sync.
#
# Protection of the pin file itself mirrors the cockblock unit files:
#   * chattr +i on the file -> kernel EPERM on rm/mv/truncate/overwrite, even
#     as root.
#   * The file's path is added to the usr.bin.chattr deny list so `chattr -i`
#     on it is blocked once that AppArmor profile is enforced (re-run safety:
#     before the profile is reloaded, the gated cockblock-updat clears +i).
#
# LIMITATIONS (same threat model as the other layers):
#   * The pin only affects apt resolution. `dpkg -i <some.deb>` bypasses the
#     pin entirely. Closing that requires an AppArmor hook on dpkg, which is
#     brittle and out of scope here.
#   * The pin does NOT block snap installs: `snap install chromium` is an apt-
#     independent path. An already-installed chromium SNAP keeps working. Snap
#     blocking is handled separately (see README / snap layer).
#   * A non-confined FS_IOC_SETFLAGS tool (debugfs, custom ioctl binary, live
#     USB) can still clear +i and remove the pin. The custom live-USB image is
#     what closes that globally.

GEN_PIN="$HERE/gen-browser-pin.sh"
if [ ! -x "$GEN_PIN" ]; then
  echo "ERROR: $GEN_PIN missing or not executable" >&2
  exit 1
fi

mkdir -p "$(dirname "$PREF_FILE")"
# Re-run safety: clear +i before overwriting (gated updater if BPF is active).
if [ -f "$PREF_FILE" ] && lsattr "$PREF_FILE" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
  cb_attr clear "$PREF_FILE"
fi
# Generate the preferences file content from the shared script. The script only
# emits data (no +i handling); this caller owns the immutable flag around the write.
"$GEN_PIN" > "$PREF_FILE"
chmod 0644 "$PREF_FILE"
echo "wrote $PREF_FILE (firefox + vivaldi-stable excluded; all other browsers pinned)"

# Make the preferences file immutable (kernel EPERM on rm/mv/overwrite).
if lsattr "$PREF_FILE" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
  echo "$PREF_FILE is already immutable"
else
  if chattr +i "$PREF_FILE" 2>/dev/null; then
    echo "set +i (immutable) on $PREF_FILE"
  elif [ -x "$REPO_ROOT/bpf/cockblock-updat" ]; then
    "$REPO_ROOT/bpf/cockblock-updat" set "$PREF_FILE"
    echo "set +i (immutable) on $PREF_FILE (via cockblock-updat)"
  else
    echo "ERROR: could not set +i on $PREF_FILE (chattr denied; build cockblock-updat: make bpf)" >&2
    exit 1
  fi
fi

# --- Layer 7: BPF LSM (separate installer) ------------------------------------
# The actual signal-blocking (incl. root SIGKILL) is the BPF LSM program in
# bpf/. It is installed separately because it needs a build toolchain:
#
#   sudo bpf/install.sh
#
# Recommended order on a fresh setup:
#   1. sudo apparmor/install.sh                 (this script)
#   2. sudo bpf/install.sh                     (build+load BPF LSM)
#   3. sudo SET_MODULES_DISABLED=1 apparmor/install.sh   (lock modules)

echo
echo "Done. Verify with:"
echo "  sudo aa-status"
echo "  lsattr $UNIT $TARGET $TARGET_WANTS_DIR $PREF_FILE   # all should show 'i'"
echo "  systemctl is-enabled cockblock            # should say 'enabled'"
echo "  systemctl show -p Wants cockblock.target # should list cockblock.service"
echo "  sudo systemctl disable cockblock         # should fail: Operation not permitted"
echo "    (EPERM from unlink in the immutable $TARGET_WANTS_DIR dir)"
echo "  sudo chattr -i $UNIT $TARGET_WANTS_DIR   # should fail (AppArmor chattr profile)"
echo "  sudo rm $UNIT                             # should fail: file is immutable (chattr +i)"
echo "  sudo apparmor_parser -R \$AA_DIR/usr.bin.chattr   # should fail (denied read)"
echo "  sudo systemctl stop apparmor             # should fail (RefuseManualStop)"
echo "  sudo apt install chromium               # should fail: no installation candidate"
echo "    (pinned to -1 in $PREF_FILE)"
echo "  sudo rm $PREF_FILE                       # should fail: file is immutable"
echo
echo "RESIDUAL BYPASS (intentional): 'sudo systemctl disable cockblock.target'"
echo "  still succeeds (its top-level enable symlink lives in the SHARED"
echo "  multi-user.target.wants/ dir, which we do NOT make immutable). It"
echo "  prevents boot-time start of cockblock on the NEXT reboot; the running"
echo "  instance keeps alive via Restart=always. To close it globally:"
echo "  sudo chattr +i /etc/systemd/system/multi-user.target.wants/"
echo "  (blocks enable/disable for ALL units in multi-user.target.wants/)."
echo
echo "Next: build+install the BPF signal blocker with:  sudo bpf/install.sh"
echo
echo "Build+install the C daemon (replaces main.py) BEFORE starting cockblock:"
echo "  cd src && make && sudo make install   # installs /opt/cockblock/cockblockd"
