#!/bin/bash
# End-to-end test for the block_setflags_immutable BPF LSM program.
#
# Verifies loophole #3 is closed: clearing the +i flag via a DIRECT ioctl
# (bypassing the AppArmor-confined chattr binary) is denied even for root.
#
# Prereqs: the BPF loader must have attached+pinned both programs. If you
# haven't loaded yet, run as root first:
#     /opt/cockblock/bpf/cockblock_loader /opt/cockblock/bpf/cockblock_lsm.bpf.o
# (or from the repo: bpf/cockblock_loader bpf/cockblock_lsm.bpf.o)
#
# Usage (as root):  sudo ./test-setflags.sh
#
# Exit codes: 0 = BPF blocked the ioctl (PASS), 1 = BPF did NOT block (FAIL).
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
HELPER="$HERE/ioctl_clear"
TESTFILE="$(mktemp /tmp/cockblock-setflags-test.XXXXXX)"

if [ "$(id -u)" -ne 0 ]; then
  echo "Must run as root (chattr +i and the ioctl both need it)." >&2
  exit 2
fi

# --- Build the helpers if missing -------------------------------------------
# ioctl_clear: a NON-updater (comm "ioctl_clear") whose direct ioctl clear
#              attempt MUST be denied by the BPF gate (negative test).
# cockblock-updat: the gated updater (comm "cockblock-updat") whose clear
#                  attempt MUST be ALLOWED by the BPF gate (positive test).
UPDATER="$HERE/../cockblock-updat"
if [ ! -x "$HELPER" ]; then
  echo "Building ioctl_clear helper ..."
  cc -O2 -Wall "$HERE/ioctl_clear.c" -o "$HELPER" || { echo "build failed" >&2; exit 2; }
fi
if [ ! -x "$UPDATER" ]; then
  echo "Building cockblock-updat ..."
  cc -O2 -Wall "$HERE/../cockblock-updat.c" -o "$UPDATER" || { echo "updater build failed" >&2; exit 2; }
fi

# PASS: negative test (non-updater denied). UPDATER_OK: positive test (updater allowed).
PASS=1
UPDATER_OK=1

cleanup() {
  # Best-effort: if the file is still immutable, try to clear it so mktemp's
  # dir cleanup can remove it. (chattr -i may itself be denied; that's fine.)
  chattr -i "$TESTFILE" 2>/dev/null
  rm -f "$TESTFILE" 2>/dev/null
}
trap cleanup EXIT

echo "=== BPF load state ==="
ls -l /sys/fs/bpf/cockblock_lsm /sys/fs/bpf/cockblock_setflags 2>/dev/null || true
bpftool prog show 2>/dev/null | grep -E 'block_kill_cockblock|block_setflags_immutable' || true

# The gate test is meaningless unless block_setflags_immutable is actually
# attached. Fail fast with a clear instruction instead of a confusing FAIL.
if [ ! -e /sys/fs/bpf/cockblock_setflags ] || \
   ! bpftool prog show 2>/dev/null | grep -q 'block_setflags_immutable'; then
  echo
  echo "ERROR: block_setflags_immutable is NOT loaded/attached." >&2
  echo "       Only block_kill_cockblock is loaded (that's a different program)." >&2
  echo "       Load both programs first, e.g.:" >&2
  echo "         sudo bpf/install.sh" >&2
  echo "       (or: sudo bpf/cockblock_loader bpf/cockblock_lsm.bpf.o)" >&2
  echo "       Then re-run this test." >&2
  exit 2
fi

echo
echo "=== Setting up immutable test file: $TESTFILE ==="
chattr +i "$TESTFILE" || { echo "chattr +i failed (AppArmor chattr profile?)" >&2; exit 2; }
lsattr "$TESTFILE"

echo
echo "=== Attempt 1: clear +i via DIRECT ioctl (bypasses chattr binary) ==="
"$HELPER" "$TESTFILE"
RC=$?
echo "helper exit code = $RC"

if [ "$RC" -eq 1 ]; then
  echo "RESULT: ioctl DENIED — BPF program is working (PASS)."
  PASS=0
elif [ "$RC" -eq 0 ]; then
  echo "RESULT: ioctl SUCCEEDED — BPF program did NOT block (FAIL)."
  echo "        The file's immutable flag was cleared by raw ioctl."
  # Re-assert immutable so the control below is meaningful.
  chattr +i "$TESTFILE" 2>/dev/null
else
  echo "RESULT: helper error (see above)."
  exit 2
fi

echo
echo "=== Attempt 2 (control): chattr -i via the confined binary ==="
if chattr -i "$TESTFILE" 2>/dev/null; then
  echo "control: chattr -i SUCCEEDED (expected: /tmp is not a cockblock path, so the chattr profile does not block it)."
else
  echo "control: chattr -i DENIED (AppArmor chattr profile blocking — expected on cockblock paths)."
fi

echo
echo "=== Attempt 3: clear +i via the GATED updater (should SUCCEED) ==="
# Re-assert +i for this attempt (Attempt 1/2 may have left it in either state).
chattr +i "$TESTFILE" 2>/dev/null
lsattr "$TESTFILE"
if "$UPDATER" clear "$TESTFILE"; then
  echo "RESULT: updater CLEARED +i — BPF gate allows cockblock-updat (update mechanism OK)."
  UPDATER_OK=0
else
  echo "RESULT: updater DENIED — gate did NOT allow cockblock-updat (update mechanism BROKEN)."
  UPDATER_OK=1
fi
# Best-effort: drop +i so cleanup's rm can remove the temp file. Use the
# updater (gate allows it) since chattr -i may be AppArmor-blocked on some paths.
"$UPDATER" clear "$TESTFILE" 2>/dev/null

echo
if [ "$PASS" -ne 0 ]; then
  echo "OVERALL: FAIL — non-updater ioctl was NOT denied by the BPF gate"
  exit 1
elif [ "$UPDATER_OK" -ne 0 ]; then
  echo "OVERALL: FAIL — gated updater could NOT clear +i (update mechanism broken)"
  exit 1
else
  echo "OVERALL: PASS — non-updater denied, gated updater allowed"
  exit 0
fi
