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
#
# The cockblockd daemon binary is protected here too: it is the running
# enforcement process, so its refresh goes through cockblock-updat's atomic
# update (clear +i -> copy -> re-+i), which falls back to a temp+rename replace
# on ETXTBSY since the binary is executing. This closes the gap where a root
# shell could otherwise `rm /opt/cockblock/cockblockd` and break the next boot.
PROTECTED=(
  "/opt/cockblock/bpf/cockblock_loader|$BPF_DIR/cockblock_loader"
  "/opt/cockblock/bpf/cockblock_lsm.bpf.o|$BPF_DIR/cockblock_lsm.bpf.o"
  "/opt/cockblock/bpf/cockblock-updat|$BPF_DIR/cockblock-updat"
  "/opt/cockblock/bpf/cockblock-update-runner.sh|$REPO_ROOT/hardening/cockblock-update-runner.sh"
  "/opt/cockblock/policies.json|$REPO_ROOT/policies.json"
  "/opt/cockblock/cockblockd|$REPO_ROOT/src/cockblockd"
  "/etc/apparmor.d/usr.bin.chattr|$AA_DIR/usr.bin.chattr"
  "/etc/apparmor.d/usr.bin.apparmor_parser|$AA_DIR/usr.bin.apparmor_parser"
  "/etc/apparmor.d/shell-bpf|$AA_DIR/shell-bpf"
)

# Non-protected (non-+i) source assets that install-core deploys. These are
# plain copies root can do directly — no cap-endowed updater needed. Listed so
# `make update` keeps them in sync alongside the protected +i artifacts. Each
# entry is "dst|src"; a src may deploy to multiple dsts (listed separately).
NONPROTECTED=(
  "/opt/cockblock/policies-unblocked.json|$REPO_ROOT/policies-unblocked.json"
  "/opt/cockblock/userChrome.css|$REPO_ROOT/userChrome.css"
  "/opt/cockblock/userContent.css|$REPO_ROOT/userContent.css"
  "/opt/cockblock/vivaldi-policies.json|$REPO_ROOT/vivaldi-policies.json"
  "/opt/cockblock/vivaldi-policies-unblocked.json|$REPO_ROOT/vivaldi-policies-unblocked.json"
  "/opt/cockblock/cb_ff_activeblock.py|$REPO_ROOT/cb_ff_activeblock.py"
  "/opt/cockblock/cb_ff_leechblock.py|$REPO_ROOT/cb_ff_leechblock.py"
  "/opt/cockblock/cb_vv_leechblock.py|$REPO_ROOT/cb_vv_leechblock.py"
  "/opt/cockblock/cb_ff_clear_kwset.py|$REPO_ROOT/cb_ff_clear_kwset.py"
  "/opt/cockblock/cb_av_check.py|$REPO_ROOT/cb_av_check.py"
  "/opt/cockblock/cb_break_check.py|$REPO_ROOT/cb_break_check.py"
  "/opt/cockblock/safeeyes.json|$REPO_ROOT/safeeyes.json"
  "/opt/cockblock/safeeyes-night.json|$REPO_ROOT/safeeyes-night.json"
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

# --- Build + install the C daemon (cb-pause/template/hash; daemon refreshed
# below via the gated PROTECTED loop, since it is +i-protected and running) ---
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

# --- Page Keyword Filter extension + managed-storage block list -------------
echo
echo "=== Page Keyword Filter extension (.xpi) + keyword manifest ==="
# Snap Firefox is confined: it can read $HOME (home interface) and its own
# ~/snap/firefox/common home, but NOT /opt or /usr/lib. So the xpi deploys to
# the snap's own ~/.mozilla/cb-extensions/ (~/snap/firefox/common/.mozilla/)
# and the managed-storage manifest to ~/.mozilla/managed-storage/.
# update.sh runs as root (sudo), so $HOME is /root -- resolve the real user's
# home. SUDO_USER can be lost through a double-sudo (sudo make update -> make
# runs sudo ./update.sh -> SUDO_USER=root), so fall back to loginctl.
REAL_USER="${SUDO_USER:-${USER:-root}}"
if [ "$REAL_USER" = "root" ]; then
  REAL_USER="$(loginctl list-users --no-legend 2>/dev/null | head -1 | awk '{print $2}')"
  [ -n "$REAL_USER" ] || REAL_USER="root"
fi
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
[ -n "$REAL_HOME" ] || REAL_HOME="$HOME"
CBHOME="$REAL_HOME/snap/firefox/common/.mozilla"
if [ ! -d "$CBHOME" ]; then CBHOME="$REAL_HOME/.mozilla"; fi

# --- Deploy the vendored SafeEyes package -------------------------------------
# Shadow the apt `safeeyes` Python package with the patched copy (break_screen.py
# keyboard grab removed) at /opt/cockblock/safeeyes/. cockblockd sets
# PYTHONPATH=/opt/cockblock so `import safeeyes` resolves here instead of
# /usr/lib/python3/dist-packages. The running safeeyes has its modules loaded in
# memory, so replacing the dir on disk is safe.
echo
echo "=== Deploying vendored SafeEyes package -> /opt/cockblock/safeeyes/ ==="
if [ -d "$REPO_ROOT/vendor/safeeyes" ]; then
  # Detect whether the deployed copy differs from the repo source. If nothing
  # changed, skip both the redeploy AND the safeeyes quit -- so `make update`
  # for an unrelated file (policy tweak, FF script) does NOT reset the
  # in-progress work timer. `rsync -c` (checksum) compares file CONTENTS, not
  # just mtime/size, so a re-cp of identical bytes is a no-op.
  se_need_sync=0
  if [ ! -d /opt/cockblock/safeeyes ]; then
    se_need_sync=1
  else
    # rsync --dry-run --checksum --itemize-changes lists files that would
    # change; anything in the output => a real difference.
    if rsync -rn -c --out-format='%n' \
        --exclude='__pycache__' \
        "$REPO_ROOT/vendor/safeeyes/" /opt/cockblock/safeeyes/ 2>/dev/null \
        | grep -q .; then
      se_need_sync=1
    fi
  fi

  if [ "$se_need_sync" = "1" ]; then
    rm -rf /opt/cockblock/safeeyes
    cp -a "$REPO_ROOT/vendor/safeeyes" /opt/cockblock/safeeyes
    find /opt/cockblock/safeeyes -name "__pycache__" -type d -prune -exec rm -rf {} +
    find /opt/cockblock/safeeyes -type d -exec chmod 0755 {} +
    find /opt/cockblock/safeeyes -type f -exec chmod 0644 {} +
    echo "refreshed /opt/cockblock/safeeyes/ (vendored, grab-patched)"

    # The deployed bytes changed: quit a running safeeyes so the patched
    # package is loaded on next launch (the running process has the OLD modules
    # in memory). cockblockd relaunches within ~30s with
    # PYTHONPATH=/opt/cockblock. Prefer `safeeyes -q` (clean GApplication
    # shutdown) if a graphical D-Bus session is reachable; otherwise pkill as
    # root (works from a TTY too). Either way cockblockd's keep-alive picks it
    # up on the next cycle.
    if pgrep -x safeeyes >/dev/null 2>&1; then
      quit_done=0
      if [ -n "$REAL_USER" ] && [ "$REAL_USER" != "root" ]; then
        DBUS_SOCK="unix:path=/run/user/$(id -u "$REAL_USER")/bus"
        if dbus-send --bus="$DBUS_SOCK" --print-reply --dest=org.freedesktop.DBus \
             /org/freedesktop/DBus org.freedesktop.DBus.GetId >/dev/null 2>&1; then
          sudo -u "$REAL_USER" \
            DBUS_SESSION_BUS_ADDRESS="$DBUS_SOCK" \
            XDG_RUNTIME_DIR="/run/user/$(id -u "$REAL_USER")" \
            DISPLAY=:0 PYTHONPATH=/opt/cockblock \
            safeeyes -q 2>/dev/null || true
          quit_done=1
        fi
      fi
      # Fallback / confirmation: if -q didn't bring it down within ~3s, SIGTERM
      # as root. This also covers the TTY case (no D-Bus reachable).
      for i in 1 2 3 4 5 6; do
        pgrep -x safeeyes >/dev/null 2>&1 || break
        [ "$i" = "1" ] && [ "$quit_done" = "0" ] && pkill -TERM -x safeeyes 2>/dev/null || true
        sleep 0.5
      done
      if pgrep -x safeeyes >/dev/null 2>&1; then
        pkill -TERM -x safeeyes 2>/dev/null || true
      fi
      echo "quit safeeyes; cockblockd will relaunch it with the patched package (~30s)"
    fi
  else
    echo "no changes in /opt/cockblock/safeeyes/ (vendored copy already up to date)"
  fi
else
  echo "SKIP vendored safeeyes: $REPO_ROOT/vendor/safeeyes missing" >&2
fi

# The signed .xpi lives in cb_keyword_block/web-ext-artifacts/ after a
# `web-ext sign` run (versioned filename); refresh the stable installed path.
# Snap Firefox can only fetch force-installed xpis via file:// from paths its
# plugs grant read of. The home interface excludes dotdirs and snap-data dirs;
# the only provably file://-readable path is /etc/firefox (etc-firefox plug,
# already used for policies). Deploy the xpi there.
xpi="$(
  ls -t "$REPO_ROOT/cb_keyword_block/web-ext-artifacts/"*.xpi 2>/dev/null \
    | head -1
)"
xpdir="/etc/firefox/cb-extensions"
mkdir -p "$xpdir"
if [ -n "$xpi" ] && [ -f "$xpi" ]; then
  rm -f "$xpdir/page_keyword_filter.xpi"
  install -m0644 "$xpi" "$xpdir/page_keyword_filter.xpi"
  echo "refreshed $xpdir/page_keyword_filter.xpi (from $xpi)"
else
  echo "SKIP $xpdir/page_keyword_filter.xpi: no .xpi in" \
       "cb_keyword_block/web-ext-artifacts/ (download the signed .xpi from AMO" \
       "into that dir, then re-run)" >&2
fi

# Patch the Page Keyword Filter install_url in the deployed Firefox policies
# to point at /etc/firefox/cb-extensions/ (the only file://-readable path for
# snap Firefox). The repo policies.json default already uses this path;
# re-assert it here so a stale /etc copy can't win.
xpurl="file:///etc/firefox/cb-extensions/page_keyword_filter.xpi"
if [ -f /etc/firefox/policies/policies.json ]; then
  sed -i "s#\"install_url\": \"[^\"]*\"#\"install_url\": \"$xpurl\"#" \
    /etc/firefox/policies/policies.json
  echo "patched install_url -> $xpurl in /etc/firefox/policies/policies.json"
fi

# The managed-storage manifest holds the live keyword list (added via
# `cb_ff_leechblock.py kw-add`). NEVER clobber it -- only deploy the empty
# repo template on first install, so user-added words survive updates.
mandir="$CBHOME/managed-storage"
mkdir -p "$mandir"
if [ -f "$mandir/page-keyword-filter-7f3a@local.addons.json" ]; then
  echo "SKIP managed-storage manifest: exists (preserving user-added keywords)"
else
  install -m0644 "$REPO_ROOT/cb_keyword_managed_storage.json" \
    "$mandir/page-keyword-filter-7f3a@local.addons.json"
  echo "installed empty keyword template"
fi

# --- Clear vestigial LeechBlock keyword set 5 --------------------------------
# Set 5 was the catch-all keyword blocker (sites="*" + times="0000-2359") whose
# secsLeft=0 clobbered the countdown badge of every timed set on every page.
# Keyword matching moved to the Page Keyword Filter extension, so set 5 must
# stay blanked. Best-effort: skip if Firefox is running (sqlite write lock).
echo "=== Clearing LeechBlock keyword set 5 ==="
if pgrep -x firefox >/dev/null 2>&1; then
  echo "SKIP: firefox is running (stop it and run:" \
       "/opt/cockblock/cb_ff_clear_kwset.py)" >&2
else
  /opt/cockblock/cb_ff_clear_kwset.py || true
fi

# --- Lock Firefox profiles.ini (+i) -----------------------------------------
# Block new-profile creation via `firefox -P` (the BlockAboutProfiles policy
# only hides about:profiles, not the -P profile manager). Making profiles.ini
# immutable lets Firefox read+load the existing default profile but refuse to
# write new entries. Cap-aware: prefers the gated cockblock-updat (works
# post-cap-drop) and falls back to plain chattr. No-op if already +i.
echo "=== Locking Firefox profiles.ini (+i) ==="
"$REPO_ROOT/lock-firefox-profiles.sh" || true

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

# --- Force the night break immediately after an update -----------------------
# `make update` refreshes safeeyes{,-night}.json. cockblockd will detect the
# src-hash drift on its next ~30s cycle and re-seed + force the break -- but
# that quit+relaunch window (and the cycle delay) is a gap the user could use.
# To close it, force the night break RIGHT NOW if we are in night hours: quit
# safeeyes (so it reloads the just-refreshed config), relaunch, and send -t.
# Runs as the real user (safeeyes is a per-user GApplication). Best-effort: if
# it fails, cockblockd's next cycle will catch up.
hour="$(date +%H)"
if [ "$hour" -lt 8 ]; then
  echo
  echo "=== Night mode: forcing SafeEyes break immediately ==="
  SE_NIGHT_SRC="/opt/cockblock/safeeyes-night.json"
  SE_LIVE="$REAL_HOME/.config/safeeyes/safeeyes.json"
  if [ -f "$SE_NIGHT_SRC" ] && [ -n "$REAL_USER" ]; then
    # Seed the live config + patch duration to seconds left until 08:00.
    install -d -m0755 "$(dirname "$SE_LIVE")"
    install -m0644 -o "$REAL_USER" "$SE_NIGHT_SRC" "$SE_LIVE"
    secs_left=$(( 3600 * (8 - 10#$hour) - 10#$(date +%M) * 60 - 10#$(date +%S) ))
    [ "$secs_left" -lt 0 ] && secs_left=$(( secs_left + 86400 ))
    python3 -c "
import json,sys
p='$SE_LIVE'
d=json.load(open(p))
d['short_break_duration']=$secs_left
json.dump(d,open(p,'w'),indent=4)
" 2>/dev/null && echo "patched short_break_duration=$secs_left (to 08:00)"

    # Quit + relaunch + force break as the user — only if we can reach the
    # D-Bus session bus (requires running graphical login, not a TTY).
    DBUS_SOCK="unix:path=/run/user/$(id -u "$REAL_USER")/bus"
    if dbus-send --bus="$DBUS_SOCK" --print-reply \
         --dest=org.freedesktop.DBus /org/freedesktop/DBus \
         org.freedesktop.DBus.GetId >/dev/null 2>&1; then
    sudo -u "$REAL_USER" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u "$REAL_USER")/bus" \
      XDG_RUNTIME_DIR="/run/user/$(id -u "$REAL_USER")" \
      DISPLAY=:0 \
      PYTHONPATH=/opt/cockblock \
      safeeyes -q 2>/dev/null || true
    sleep 2
    sudo -u "$REAL_USER" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u "$REAL_USER")/bus" \
      XDG_RUNTIME_DIR="/run/user/$(id -u "$REAL_USER")" \
      DISPLAY=:0 \
      PYTHONPATH=/opt/cockblock \
      safeeyes 2>/dev/null & disown
    sleep 4
    for i in 1 2 3 4; do
      sudo -u "$REAL_USER" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u "$REAL_USER")/bus" \
        XDG_RUNTIME_DIR="/run/user/$(id -u "$REAL_USER")" \
        DISPLAY=:0 \
        PYTHONPATH=/opt/cockblock \
        safeeyes -t 2>/dev/null && break
      sleep 1
    done
    echo "forced night break (safeeyes -t)"
    # Leave a flag so cockblockd's next cycle absorbs the new src-hash WITHOUT
    # quit+relaunch (which would briefly lift the overlay). cockblockd deletes
    # this file after absorbing.
    touch /var/lib/cockblock/se_forced_by_update
    chmod 0644 /var/lib/cockblock/se_forced_by_update 2>/dev/null || true
    else
      echo "No graphical session bus reachable (TTY?)."
      echo "Config seeded; cockblockd will quit+relaunch safeeyes on its next cycle (~30s)."
      # Do NOT set se_forced_by_update here: that flag tells cockblockd to
      # absorb the hash WITHOUT quit+relaunch (update.sh already did it). In
      # the TTY case we did NOT relaunch, so we must let cockblockd detect
      # src-drift and do a normal quit+relaunch + force-break.
    fi
  fi
fi

echo
echo "=== Deploying cb_startwork SafeEyes plugin -> ~/.config/safeeyes/plugins/ ==="
SE_PLUGINS_DIR="$REAL_HOME/.config/safeeyes/plugins/cb_startwork"
SE_PLUGIN_NEW=0
if [ -n "$REAL_USER" ] && [ "$REAL_USER" != "root" ]; then
  # Detect first-time deploy: if the plugin dir didn't exist before, we must
  # restart SafeEyes once so it loads the new plugin (plugins load at startup,
  # no live-reload). On subsequent updates the dir already exists, so we SKIP
  # the restart -- preserving the in-progress 30-min work cycle (the daemon's
  # day-drift-preserve also avoids a reset). One-time reset only.
  if [ ! -d "$SE_PLUGINS_DIR" ]; then SE_PLUGIN_NEW=1; fi
  sudo -u "$REAL_USER" install -d -m0755 "$REAL_HOME/.config/safeeyes/plugins/cb_startwork"
  sudo -u "$REAL_USER" install -m0644 "$REPO_ROOT/cb_startwork/config.json" "$SE_PLUGINS_DIR/config.json"
  sudo -u "$REAL_USER" install -m0755 "$REPO_ROOT/cb_startwork/plugin.py" "$SE_PLUGINS_DIR/plugin.py"
  echo "installed cb_startwork plugin -> $SE_PLUGINS_DIR"
  if [ "$SE_PLUGIN_NEW" = "1" ]; then
    DBUS_SOCK="unix:path=/run/user/$(id -u "$REAL_USER")/bus"
    if dbus-send --bus="$DBUS_SOCK" --print-reply --dest=org.freedesktop.DBus \
         /org/freedesktop/DBus org.freedesktop.DBus.GetId >/dev/null 2>&1; then
      echo "first deploy of cb_startwork: restarting SafeEyes to load the plugin"
      sudo -u "$REAL_USER" \
        DBUS_SESSION_BUS_ADDRESS="$DBUS_SOCK" \
        XDG_RUNTIME_DIR="/run/user/$(id -u "$REAL_USER")" \
        PYTHONPATH=/opt/cockblock \
        DISPLAY=:0 safeeyes -q 2>/dev/null || true
      # cockblockd's keep-alive relaunches SafeEyes within ~30s with the new
      # config (already seeded). Leave the forced flag so the daemon absorbs
      # the new src-hash without a second restart.
      touch /var/lib/cockblock/se_forced_by_update 2>/dev/null || true
      chmod 0644 /var/lib/cockblock/se_forced_by_update 2>/dev/null || true
    else
      echo "first deploy of cb_startwork: no graphical session; cockblockd will relaunch on its next cycle"
    fi
  fi
else
  echo "SKIP cb_startwork: no real user resolved (running as root w/o session)" >&2
fi

echo
echo "Done. Verify:"
echo "  lsattr ${PROTECTED[*]%%|*}   # all 'i'"
echo "  lsattr -d /opt/cockblock/bpf/  # dir 'i' (blocks removal)"
echo "  sudo aa-status"
echo "  bpftool prog show | grep -E 'block_kill_cockblock|block_setflags_immutable'"
