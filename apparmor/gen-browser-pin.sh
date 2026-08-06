#!/bin/bash
# Generate the cockblock apt browser-install-block preferences file.
#
# Writes the apt preferences pin (Pin-Priority: -1) to stdout, blocking
# install/upgrade of every browser EXCEPT the ones cockblock itself manages.
#
# Why an explicit MANAGED allowlist instead of "exclude installed":
#   On Ubuntu 22.04+, firefox and chromium-browser are SNAP STUB packages
#   (transitional .debs whose postinst just `snap install` the real browser).
#   Both show up as "installed" in dpkg, but only firefox is managed by
#   cockblock; chromium-browser is an unwanted browser. Excluding by
#   "installed" would let chromium through. So we pin everything except an
#   explicit managed list.
#
# Pin-Priority: -1 on a package: apt refuses to install it. If the package is
# already installed (e.g. the chromium-browser stub), -1 won't auto-remove it
# (removal needs an explicit `apt remove`), but it also won't be upgraded and a
# fresh `apt install <pkg>` after a removal fails with "no installation
# candidate". Good enough for the apt path.
#
# This script is PURE DATA generation: it writes the file content to stdout
# and does NOT touch chattr/immutable. The caller (install.sh OR the cap-endowed
# cockblock-update runner) is responsible for clearing/setting +i around the
# write, because only the cap-endowed context can clear +i post-cap-drop.
#
# Usage:
#   ./gen-browser-pin.sh > /etc/apt/preferences.d/99-cockblock-no-browsers
set -euo pipefail

# Browsers cockblock MANAGES - excluded from the pin so they keep receiving
# security upgrades. Add a managed browser here when cockblock starts managing it.
MANAGED_BROWSERS="firefox vivaldi-stable"

# Every known browser package name we want to block from apt install/upgrade.
# Snap-stub transitional packages (chromium-browser, google-chrome-stable when
# provided as a stub, etc.) are included on purpose: installing the stub
# installs the real browser, so the stub must be pinned too.
ALL_BROWSERS="firefox firefox-esr chromium chromium-browser chromium-snap
  epiphany-browser midori opera opera-stable google-chrome-stable
  vivaldi vivaldi-stable vivaldi-snapshot brave brave-browser
  microsoft-edge-stable microsoft-edge-dev konqueror falkon qutebrowser
  waterfox waterfox-classic waterfox-current palemoon palemoon-bin
  seamonkey seamonkey-bin torbrowser-launcher nyxt dillo netsurf-gtk
  netsurf-browser surf luakit rekonq elinks links2 links lynx w3m"

PIN_LIST=""
for _p in $ALL_BROWSERS; do
  managed=0
  for _m in $MANAGED_BROWSERS; do
    [ "$_p" = "$_m" ] && { managed=1; break; }
  done
  if [ "$managed" -eq 1 ]; then
    continue
  fi
  PIN_LIST+="$_p "
done
PIN_LIST="${PIN_LIST% }"

cat <<EOF
# Added by cockblock: block install/upgrade of non-managed browsers via apt.
# Regenerated on every apparmor/install.sh run AND every 'make update' (via the
# cap-endowed cockblock-update service). cockblock-MANAGED browsers
# (currently: $(echo "$MANAGED_BROWSERS" | tr '\n' ' ')) are EXCLUDED so they
# keep receiving security upgrades. Do not edit by hand - this file is
# chattr +i protected.
Package: $PIN_LIST
Pin: release *
Pin-Priority: -1
EOF
