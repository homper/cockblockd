#!/usr/bin/env python3
# cb_vv_leechblock.py - read / set / sync LeechBlock NG state in Vivaldi's
# chrome.storage.local LevelDB. Used by cockblockd to mirror the Firefox
# LeechBlock SITE LISTS into Vivaldi and force them to be ALWAYS blocked
# (24/7, no time window, no daily limit), independent of the per-set
# schedule / active toggles configured in Firefox.
#
#   cb_vv_leechblock.py <vv_leveldb>                  -> print "1,1,0,0,0,0"
#                                                      (activeBlock1..6)
#   cb_vv_leechblock.py <vv_leveldb> <0/1 csv>         -> set activeBlock1..6
#   cb_vv_leechblock.py <vv_leveldb> --nonempty        -> print "1,1,1,0,0,0"
#                                                      (sites{n} non-empty csv)
#   cb_vv_leechblock.py <vv_leveldb> --sync-from <ff_sqlite>
#                                                    -> mirror ONLY the site
#                                                       lists (sites1..6) from
#                                                       Firefox and force every
#                                                       non-empty set to be
#                                                       always blocked; prints
#                                                       "SYNCED" or "CHANGED <n>"
#   cb_vv_leechblock.py <vv_leveldb> --diff <ff_sqlite>
#                                                    -> read-only drift check
#                                                       against the SAME managed
#                                                       keys --sync-from writes
#                                                       (works while Vivaldi
#                                                       runs; no write lock);
#                                                       prints "DRIFT <n>" / "OK"
#
# "Managed keys" are the only keys --sync-from / --diff touch. Per set n:
#   sites{n}        copied from Firefox (the site list; "" if empty/absent)
#   activeBlock{n}  forced True for non-empty sets, False for empty sets
#   days{n}         forced [true,true,true,true,true,true,true]  (every day)
#   times{n}        forced "0000-2359"  (full-day window -> withinTimePeriods
#                   is always true in LeechBlock -> blocks 24/7. NOTE: blank
#                   "" would mean NO time window, which does NOT block.)
#   limitMins{n}    forced ""   (no daily time allowance; with a full-day times
#                   window the set is always within it, so this never unblocks)
#   limitPeriod{n}  forced ""
#   limitOffset{n}  forced ""
#   disable{n}      forced false
# Plus the two global storage-backend keys, forced false so Vivaldi keeps
# reading chrome.storage.local (Local Extension Settings), where we write:
#   sync            forced false
#   autoExportSync  forced false
# All OTHER LeechBlock keys (blockURL, closeTab, applyFilter, timedata,
# prev* snapshots, override runtime, captcha image, ...) are left untouched
# in Vivaldi.
#
# Vivaldi MUST be stopped for the set / --sync-from forms (LevelDB write lock).
# The --sync-from / --diff forms read Firefox's storage-sync-v2.sqlite
# read-only, so Firefox may be running.
import json, os, shutil, sqlite3, sys, tempfile, time

import plyvel

LB_FF_ID = "leechblockng@proginosko.com"
NUM_SETS = 6
ALL_DAYS = [True] * 7

# Regex metacharacters LeechBlock escapes when compiling sites{n} into
# blockRE{n}. NOTE: "*" is intentionally NOT in this set; it is handled
# separately as the path wildcard "[^\/]*" (see sites_to_blockre).
LB_RE_SPECIALS = ".+?^${}()|[]\\"


# Replicate LeechBlock NG's site-list -> blockRE compiler so the daemon can
# force a freshly synced sites{n} to actually take effect WITHOUT requiring
# the user to open & Save the LeechBlock Options page (which the policies
# block). LeechBlock matches URLs against blockRE{n}, NOT sites{n}; sites{n}
# is only re-compiled into blockRE{n} on Save. Verified byte-identical to the
# extension's own output for wildcard ("*"), plain, and path ("/*") entries.
def sites_to_blockre(sites):
    parts = []
    for tok in sites.split():
        esc = ""
        for ch in tok:
            if ch == "*":
                esc += "[^\\/]*"
            elif ch in LB_RE_SPECIALS:
                esc += "\\" + ch
            else:
                esc += ch
        parts.append("(www\\.)?" + esc)
    if not parts:
        return ""
    return "^(https?|file):\\/+([\\w:]+@)?(" + "|".join(parts) + ")"


def load_firefox(ff_sqlite):
    con = sqlite3.connect("file:%s?mode=ro" % ff_sqlite, uri=True)
    row = con.execute(
        "SELECT data FROM storage_sync_data WHERE ext_id=?", (LB_FF_ID,)
    ).fetchone()
    con.close()
    return json.loads(row[0]) if row and row[0] else {}


def compact(v):
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode()


# The fixed list of (key, value) pairs --sync-from writes and --diff compares.
# `sites{n}` is mirrored from Firefox; everything else is forced to the
# always-blocked value. Returns a list of (key, python_value).
def managed_items(ff):
    out = [("sync", False), ("autoExportSync", False)]
    for n in range(1, NUM_SETS + 1):
        sites = ff.get("sites%d" % n, "")
        if not isinstance(sites, str):
            sites = ""
        nonempty = bool(sites.strip())
        out.append(("sites%d" % n, sites))
        out.append(("blockRE%d" % n, sites_to_blockre(sites) if nonempty else ""))
        out.append(("activeBlock%d" % n, True if nonempty else False))
        out.append(("days%d" % n, ALL_DAYS))
        out.append(("times%d" % n, "0000-2359"))
        out.append(("limitMins%d" % n, ""))
        out.append(("limitPeriod%d" % n, ""))
        out.append(("limitOffset%d" % n, ""))
        out.append(("disable%d" % n, False))
    return out


# Open the live LevelDB for writing. Acquires the exclusive LOCK, so Vivaldi
# MUST be stopped (cockblockd term_and_wait()s first). If the lock lingers a
# moment after the kill, retry for ~10s. On a persistent failure print "LOCKED"
# and exit non-zero so the C side logs instead of silently no-op'ing (the old
# behaviour: plyvel raised, the script crashed with empty stdout, and
# cockblockd reported success).
def open_writable(path):
    last = None
    for _ in range(40):
        try:
            return plyvel.DB(path, create_if_missing=True)
        except Exception as e:        # plyvel.Error / lock contention
            last = e
            time.sleep(0.25)
    print("LOCKED %s" % last)
    sys.exit(2)


# Open a READ-ONLY snapshot of the LevelDB that works WHILE Vivaldi is running.
# plyvel has no read_only mode and always takes the LOCK, so we cannot open the
# live dir directly. Instead we copy the small directory (CURRENT / MANIFEST /
# *.ldb / *.log) to a temp dir and open the copy - leveldb replays the .log to
# rebuild the memtable, so this faithfully reflects current state including
# unflushed writes. Reading live files that Vivaldi is appending to is safe on
# Linux. Returns (tmpdir, db) or (None, None) if the dir is missing / unreadable
# (caller then treats everything as drift). The caller MUST close db and rmtree
# tmpdir.
def open_snapshot(path):
    if not os.path.isdir(path):
        return None, None
    tmp = tempfile.mkdtemp(prefix="cbvv_")
    try:
        for f in os.listdir(path):
            sp = os.path.join(path, f)
            if os.path.isfile(sp):
                try:
                    shutil.copy2(sp, os.path.join(tmp, f))
                except OSError:
                    pass
        db = plyvel.DB(tmp, create_if_missing=False)
        return tmp, db
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        return None, None


def read_active(db):
    out = []
    for i in range(1, NUM_SETS + 1):
        raw = db.get(("activeBlock%d" % i).encode())
        out.append(1 if (raw is not None and json.loads(raw) is True) else 0)
    return out


def read_nonempty(db):
    out = []
    for i in range(1, NUM_SETS + 1):
        raw = db.get(("sites%d" % i).encode())
        v = json.loads(raw) if raw is not None else ""
        out.append(1 if (isinstance(v, str) and v.strip()) else 0)
    return out


def main():
    path = sys.argv[1]
    if len(sys.argv) == 2:
        tmp, db = open_snapshot(path)
        if db is None:
            print("0,0,0,0,0,0")
        else:
            print(",".join(str(x) for x in read_active(db)))
            db.close()
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
        return
    arg = sys.argv[2]
    if arg == "--nonempty":
        tmp, db = open_snapshot(path)
        if db is None:
            print("0,0,0,0,0,0")
        else:
            print(",".join(str(x) for x in read_nonempty(db)))
            db.close()
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
        return
    if arg == "--diff":
        # Read-only snapshot: works WHILE Vivaldi is running (no live LOCK).
        # Compares ONLY the managed keys (the same ones --sync-from writes) so
        # the two forms agree: after a sync the diff is 0, so cockblockd does
        # not kill+restart Vivaldi every cycle. Prints "DRIFT <n>" or "OK".
        ff_sqlite = sys.argv[3]
        ff = load_firefox(ff_sqlite)
        items = managed_items(ff)
        tmp, db = open_snapshot(path)
        if db is None:
            # Vivaldi LevelDB missing / unreadable: treat all managed keys as
            # drift so the C side will (re)create it via --sync-from when safe.
            print("DRIFT %d" % len(items))
            return
        n = 0
        for k, v in items:
            if db.get(k.encode()) != compact(v):
                n += 1
        db.close()
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
        print("DRIFT %d" % n if n else "OK")
        return
    if arg == "--sync-from":
        ff_sqlite = sys.argv[3]
        ff = load_firefox(ff_sqlite)
        db = open_writable(path)     # exits 2 ("LOCKED") if held
        changed = 0
        for k, v in managed_items(ff):
            kb = k.encode()
            want = compact(v)
            if db.get(kb) != want:
                db.put(kb, want)
                changed += 1
        db.close()
        print("SYNCED" if changed == 0 else "CHANGED %d" % changed)
        return
    # set activeBlock1..6 from csv
    vals = [x == "1" for x in arg.split(",")][:NUM_SETS]
    db = open_writable(path)
    for i, v in enumerate(vals):
        db.put(("activeBlock%d" % (i + 1)).encode(),
               compact(True if v else False))
    db.close()


if __name__ == "__main__":
    main()
