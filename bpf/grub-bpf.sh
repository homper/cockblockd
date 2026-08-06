#!/bin/bash
# Safely add `bpf` to the kernel LSM list via GRUB_CMDLINE_LINUX_DEFAULT.
#
# Usage (run as root):
#   ./grub-bpf.sh status    # show current vs running LSMs (no changes)
#   ./grub-bpf.sh enable     # back up /etc/default/grub, append bpf to lsm=,
#                            # run update-grub, auto-revert on any failure,
#                            # then DELETE the backup (no manual revert path)
#
# Safety:
#   * backs up /etc/default/grub to a timestamped copy + a .latest pointer
#     BEFORE editing; on any failure (update-grub non-zero, verification fail)
#     the original is restored and update-grub re-run to undo grub.cfg.
#   * idempotent: if `bpf` is already in the running LSM list it does nothing.
#   * preserves every currently-active LSM: the new lsm= value is taken from
#     /sys/kernel/security/lsm (the live list) with `bpf` appended, so no
#     existing LSM is dropped. If GRUB_CMDLINE_LINUX_DEFAULT already has an
#     lsm= token, `bpf` is appended to THAT value instead.
#   * never edits more than the one GRUB_CMDLINE_LINUX_DEFAULT= line.
set -euo pipefail

GRUB=/etc/default/grub
BACKUP_DIR=/etc/default
BACKUP_PREFIX=grub.cockblock.bak
BACKUP_LATEST=$BACKUP_DIR/$BACKUP_PREFIX.latest

LSM_FILE=/sys/kernel/security/lsm

err() { echo "grub-bpf: $*" >&2; }
need_root() {
  [ "$(id -u)" -eq 0 ] || { err "must run as root"; exit 1; }
}
lsm_running() { cat "$LSM_FILE" 2>/dev/null; }
has_bpf_running() { lsm_running | tr ',' '\n' | grep -qx bpf; }

# Pretty-print a GRUB_CMDLINE value, one token per line for inspection.
show_cmdline() {
  # strip leading/trailing quotes, split on spaces
  sed -n 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"$/\1/p' "$GRUB" \
    | tr ' ' '\n' | sed '/^$/d'
}

# Extract the current lsm= token value from GRUB (empty if none).
grub_lsm_value() {
  show_cmdline | sed -n 's/^lsm=\(.*\)$/\1/p'
}

# Backup pristine grub once. Keeps the FIRST backup as .latest so repeated
# runs don't overwrite the original-snapshot (revert always goes to pristine).
backup_once() {
  if [ -e "$BACKUP_LATEST" ]; then return 0; fi
  local ts; ts=$(date +%Y%m%d%H%M%S)
  local copy="$BACKUP_DIR/$BACKUP_PREFIX.$ts"
  cp -a "$GRUB" "$copy"
  ln -sf "$copy" "$BACKUP_LATEST"
  echo "grub-bpf: backed up $GRUB -> $copy"
}

# Restore from .latest and re-run update-grub so grub.cfg matches.
do_revert() {
  need_root
  if [ ! -e "$BACKUP_LATEST" ]; then
    err "no backup to revert to"; exit 1
  fi
  local src; src="$(readlink -f "$BACKUP_LATEST")"
  cp -a "$src" "$GRUB"
  echo "grub-bpf: restored $GRUB from $src"
  update-grub
  echo "grub-bpf: update-grub re-run; revert complete"
}

do_status() {
  echo "running LSMs : $(lsm_running || echo '(unreadable)')"
  echo "grub lsm=    : $(grub_lsm_value || echo '(none in GRUB_CMDLINE_LINUX_DEFAULT)')"
  if has_bpf_running; then echo "bpf in running list: YES (no action needed)"; \
  else echo "bpf in running list: NO"; fi
  if [ -e "$BACKUP_LATEST" ]; then
    echo "backup       : $(readlink -f "$BACKUP_LATEST")"
  else
    echo "backup       : (none yet)"
  fi
}

do_enable() {
  need_root
  if has_bpf_running; then
    echo "grub-bpf: bpf already in running LSM list; nothing to do."
    return 0
  fi
  [ -f "$GRUB" ] || { err "$GRUB not found"; exit 1; }
  command -v update-grub >/dev/null 2>&1 || { err "update-grub not found (install grub2-common)"; exit 1; }

  backup_once

  # Decide the new lsm= value.
  existing_grub_lsm="$(grub_lsm_value || true)"
  if [ -n "$existing_grub_lsm" ]; then
    if echo "$existing_grub_lsm" | tr ',' '\n' | grep -qx bpf; then
      echo "grub-bpf: GRUB already has lsm=...bpf but kernel didn't load it; rebuild+reboot only."
      # nothing to change in /etc/default/grub
    else
      new_lsm="$existing_grub_lsm,bpf"
    fi
  else
    # Use the live list (preserves all active LSMs) + bpf.
    live="$(lsm_running || true)"
    if [ -z "$live" ]; then
      err "cannot read $LSM_FILE and no lsm= in grub; refusing to guess"
      exit 1
    fi
    # strip a trailing comma if present
    live="${live%,}"
    new_lsm="$live,bpf"
  fi

  # Build the new GRUB_CMDLINE_LINUX_DEFAULT= line.
  # Strategy: operate on the single matching line only.
  if [ -n "${new_lsm:-}" ]; then
    # Work on a temp copy; only modify if the lsm= token needs adding/changing.
    tmp=$(mktemp)
    # If an lsm= token already exists in the line, replace its value;
    # otherwise append ` lsm=<new>` before the closing quote.
    if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=".*lsm=' "$GRUB"; then
      sed -E "s/(^GRUB_CMDLINE_LINUX_DEFAULT=\".*lsm=)[^\"]*([^\"]*)/\1${new_lsm}\2/" "$GRUB" > "$tmp"
    else
      sed -E "s/^(GRUB_CMDLINE_LINUX_DEFAULT=\"[^\"]*)\"$/\1 lsm=${new_lsm}\"/" "$GRUB" > "$tmp"
    fi

    if ! diff -q "$GRUB" "$tmp" >/dev/null; then
      cp -a "$tmp" "$GRUB"
      echo "grub-bpf: updated GRUB_CMDLINE_LINUX_DEFAULT with lsm=$new_lsm"
    else
      echo "grub-bpf: no change to GRUB line (already set)"
    fi
    rm -f "$tmp"
  fi

  echo "grub-bpf: running update-grub ..."
  if ! update-grub; then
    err "update-grub failed; reverting /etc/default/grub"
    do_revert
    exit 1
  fi

  # Verify the new lsm value landed in /etc/default/grub.
  final="$(grub_lsm_value || true)"
  if ! echo "$final" | tr ',' '\n' | grep -qx bpf; then
    err "verification failed: bpf not found in final lsm= ($final); reverting"
    do_revert
    exit 1
  fi

  echo "grub-bpf: OK. Reboot to activate: $(lsm_running),bpf  ->  $final"
  # Wipe the backup + .latest pointer so there is no easy manual revert path
  # (the project goal is to make disabling hard). Auto-revert-on-failure above
  # already ran if anything went wrong, so the backup is no longer needed.
  if [ -e "$BACKUP_LATEST" ]; then
    rm -f "$(readlink -f "$BACKUP_LATEST")" "$BACKUP_LATEST"
    echo "grub-bpf: removed backup (no manual revert available)"
  fi
  rm -f "$BACKUP_DIR/$BACKUP_PREFIX."* 2>/dev/null || true
}

case "${1:-}" in
  status)  do_status ;;
  enable)  do_enable ;;
  *) err "usage: $0 {status|enable}"; exit 2 ;;
esac
