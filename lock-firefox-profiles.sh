#!/bin/bash
# lock-firefox-profiles.sh - make Firefox's profiles.ini immutable (+i) so the
# user cannot create new profiles via `firefox -P --no-remote` (which bypasses
# the BlockAboutProfiles policy). Firefox can still READ profiles.ini and load
# the existing default profile; it just cannot WRITE new profile entries.
#
# This is a pragmatic bar matching the rest of the cockblock stack: hard to
# bypass casually, not impervious (a determined user can still pass
# `firefox -profile /tmp/foo` to point at an arbitrary dir, skipping
# profiles.ini entirely; closing that needs an AppArmor profile restricting
# snap Firefox to one profile dir). Reversible with `chattr -i`.
#
# Cap-aware: after install-cap-drop / install-session-capdrop, user shells
# (and even `sudo chattr +i`) lack CAP_LINUX_IMMUTABLE, so direct chattr fails.
# This script prefers the cap-endowed cockblock-updat "set" subcommand when
# available; falls back to plain chattr (works pre-cap-drop / as plain root).
#
# Usage (as root):
#   sudo ./lock-firefox-profiles.sh
set -euo pipefail

# Resolve the real (non-root) user's home, mirroring update.sh.
REAL_USER="${SUDO_USER:-${USER:-root}}"
if [ "$REAL_USER" = "root" ]; then
	REAL_USER="$(loginctl list-users --no-legend 2>/dev/null | head -1 | awk '{print $2}')"
	[ -n "$REAL_USER" ] || REAL_USER="root"
fi
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
[ -n "$REAL_HOME" ] || REAL_HOME="$HOME"

# Snap Firefox keeps profiles.ini under ~/snap/firefox/common/.mozilla/firefox/;
# non-snap Firefox under ~/.mozilla/firefox/. Try snap first (the supported
# config here), then the classic path.
PROFILES_INI=""
for cand in \
	"$REAL_HOME/snap/firefox/common/.mozilla/firefox/profiles.ini" \
	"$REAL_HOME/.mozilla/firefox/profiles.ini"; do
	if [ -f "$cand" ]; then
		PROFILES_INI="$cand"
		break
	fi
done

if [ -z "$PROFILES_INI" ]; then
	echo "SKIP lock-firefox-profiles: no profiles.ini found under $REAL_HOME (Firefox not yet launched?)"
	exit 0
fi

# Already +i? Nothing to do.
if lsattr "$PROFILES_INI" 2>/dev/null | cut -c1-22 | grep -q 'i'; then
	echo "already +i: $PROFILES_INI"
	exit 0
fi

# Prefer the cap-endowed updater (works post-cap-drop). Try the repo build
# output first (make update context), then the installed copy.
UPDATER=""
for u in \
	"$(cd "$(dirname "$0")" && pwd)/bpf/cockblock-updat" \
	"/opt/cockblock/bpf/cockblock-updat"; do
	if [ -x "$u" ]; then
		UPDATER="$u"
		break
	fi
done

if [ -n "$UPDATER" ]; then
	# cockblock-updat set <path> sets +i (CAP_LINUX_IMMUTABLE endowed via setcap
	# on the installed copy, or plain root pre-cap-drop on the repo build).
	if "$UPDATER" set "$PROFILES_INI" 2>/dev/null; then
		echo "locked (+i via cockblock-updat): $PROFILES_INI"
		exit 0
	fi
	# Fall through to chattr if the updater refused (e.g. repo build without
	# setcap and cap dropped).
fi

# Direct chattr (works as plain root pre-cap-drop; fails post-cap-drop with
# EPERM). Fall back to systemd-run (runs in a fresh root scope with full
# bounding set, so CAP_LINUX_IMMUTABLE is present even when this session
# has it dropped). This is the path `make update` takes on a hardened box.
if chattr +i "$PROFILES_INI" 2>/dev/null; then
	echo "locked (+i via chattr): $PROFILES_INI"
	exit 0
fi

# systemd-run fallback: spawn chattr in a transient unit owned by init/system,
# outside this session's (cap-dropped) bounding set.
if command -v systemd-run >/dev/null 2>&1 && \
   systemd-run --quiet --collect --wait chattr +i "$PROFILES_INI" 2>/dev/null; then
	echo "locked (+i via systemd-run chattr): $PROFILES_INI"
	exit 0
fi

echo "WARN: could not set +i on $PROFILES_INI" >&2
echo "      (CAP_LINUX_IMMUTABLE dropped and no cap-endowed path worked)." >&2
echo "      Run from a root TTY or pre-cap-drop, or via 'make update'." >&2
exit 1

