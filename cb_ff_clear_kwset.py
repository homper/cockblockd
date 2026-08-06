#!/usr/bin/env python3
# cb_ff_clear_kwset.py - one-shot clearer for LeechBlock's keyword set (set 5).
#
# Set 5 was the catch-all keyword blocker (sites="*" + times="0000-2359") whose
# secsLeft=0 clobbered the countdown badge of every timed set on every page.
# Keyword matching is now done by the separate Page Keyword Filter extension
# (via managed storage), so set 5 is vestigial and must stay fully blanked so
# the timers keep working.
#
# This clears ONLY set 5 (hardcoded). It is NOT a generic disable-set tool --
# there is no set-number argument -- so it cannot be used to disable the timed
# sets (1-4) or the URL-regex set (6). Re-running it is idempotent.
#
# Firefox MUST be stopped (sqlite write lock + so Firefox does not overwrite
# the row on next sync). Prints what it did and drops the addonStartup cache.
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cb_ff_leechblock as lb

SET = 5

KEYS_BLANK = (
    "sites", "blockRE", "keywordRE", "regexpBlock", "times",
    "limitMins", "limitPeriod", "limitOffset", "days",
)
KEYS_FALSE = ("activeBlock", "showTimer", "conjMode")
KEYS_EMPTY_NAME = ("setName",)


def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        return
    readonly = "--print" in sys.argv
    path = lb.infer_sqlite_path()
    if lb.firefox_running() and not readonly:
        sys.exit("ERROR: firefox is running. Stop it first "
                 "(cockblockd or `pkill firefox`) so it does not overwrite "
                 "the row, then re-run.")
    con = lb.open_db(path, readonly)
    d = lb.load(con)
    changed = []
    for k in KEYS_BLANK:
        full = "%s%d" % (k, SET)
        if d.get(full, "") != "":
            d[full] = ""
            changed.append(full)
    for k in KEYS_FALSE:
        full = "%s%d" % (k, SET)
        if d.get(full, False) is not False:
            d[full] = False
            changed.append(full + "=False")
    for k in KEYS_EMPTY_NAME:
        full = "%s%d" % (k, SET)
        if d.get(full, "") != "":
            d[full] = ""
            changed.append(full)
    if not changed:
        print("set %d already blanked (no changes)" % SET)
        con.close()
        return
    if readonly:
        print("DRY-RUN would clear set %d: %s" % (SET, ", ".join(changed)))
        print(json.dumps(d, indent=2, ensure_ascii=False))
        con.close()
        return
    lb.commit(con, d)
    con.close()
    removed = lb.drop_startup_cache(path)
    print("CLEARED LeechBlock set %d: %s" % (SET, ", ".join(changed)))
    if removed:
        print("DROPPED startup cache: %s (extension reloads on next launch)"
              % ", ".join(removed))


if __name__ == "__main__":
    main()
