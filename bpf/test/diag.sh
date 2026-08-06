#!/bin/bash
# Diagnose why block_setflags_immutable returns 0 (allow) instead of -EPERM.
#
# Reloads the (diagnostic) setflags program, clears the trace buffer, reproduces
# the FS_IOC_SETFLAGS- clears-+i ioctl on a +i file, then prints the
# bpf_trace_printk "sf ..." lines that the program emits at each decision point:
#   sf cmd=<hex>            -> hook fired for FS_IOC_SETFLAGS
#   sf r1=<ret> ino=<hex>   -> bpf_probe_read_kernel(file->f_inode): ret + inode ptr
#   sf r2=<ret> ifl=<hex>   -> bpf_probe_read_kernel(inode->i_flags): ret + flags
#   sf match=<0|1>          -> comm matched UPDATE_COMM (gated updater)?
#   sf DENY                 -> program is about to return -EPERM
#
# If r1!=0 / ino=0  -> reading file->f_inode fails (ctx/offset problem).
# If r2!=0 / ifl=0  -> reading inode->i_flags fails (offset/read problem) even
#                      though the file is +i, so S_IMMUTABLE is never seen -> allow.
# If ifl has bit 0x10 but no DENY (and match=0) -> comm gate logic issue.
#
# Run as root:  sudo ./diag.sh
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
BPF="$HERE/.."
OBJ="$BPF/cockblock_lsm.bpf.o"
LOADER="$BPF/cockblock_loader"
HELPER="$HERE/ioctl_clear"
UPDATER="$BPF/cockblock-updat"
TRACE=/sys/kernel/debug/tracing/trace

if [ "$(id -u)" -ne 0 ]; then
  echo "Must run as root." >&2; exit 2
fi
if [ ! -f "$OBJ" ]; then
  echo "ERROR: $OBJ missing. Build it as YOUR user (not root) first: make -C $BPF cockblock_lsm.bpf.o" >&2
  exit 2
fi
[ -x "$HELPER" ]  || cc -O2 -Wall "$HERE/ioctl_clear.c" -o "$HELPER"
[ -x "$UPDATER" ] || cc -O2 -Wall "$BPF/cockblock-updat.c" -o "$UPDATER"

echo "=== current BPF progs ==="
bpftool prog show 2>/dev/null | grep -E 'block_kill_cockblock|block_setflags_immutable' || true

echo "=== reloading the diagnostic setflags program ==="
# Detach the old (pinned) setflags link, then re-attach the diagnostic .o.
# (task_kill stays pinned; the loader skips already-pinned programs.)
rm -f /sys/fs/bpf/cockblock_setflags
"$LOADER" "$OBJ"

echo "=== clearing trace buffer ==="
echo > "$TRACE"

F="$(mktemp /tmp/cb-diag.XXXXXX)"
chattr +i "$F" || { echo "chattr +i failed on $F" >&2; exit 2; }
echo "=== reproduce: ioctl_clear on +i file $F ==="
"$HELPER" "$F"
echo "helper exit=$?"
echo "--- chattr -i (may be denied by BPF if reads work) ---"
chattr -i "$F" 2>/dev/null && echo "chattr -i OK" || echo "chattr -i DENIED"

echo
echo "=== TRACE OUTPUT (sf lines) ==="
grep -a 'sf ' "$TRACE" || { echo "(no 'sf' lines found; full trace below)"; cat "$TRACE"; }

# cleanup: clear +i via the gated updater (works whether or not BPF reads work),
# then remove the temp file.
"$UPDATER" clear "$F" 2>/dev/null
rm -f "$F" 2>/dev/null
