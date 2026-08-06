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
#                                                    -> mirror the site
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
#   blockRE{n}      compiled from sites{n} (mirrors Firefox's compile)
#   keywordRE{n}    copied from Firefox (title/body keyword regex)
#   titleOnly{n}    copied from Firefox (True = title only, False = title+body)
#   allowKeywords{n} copied from Firefox (True = allowlist, False = blocklist)
#   closeTab{n}     copied from Firefox (True = close matched tab instead of
#                   redirecting to the block page)
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
#   numSets         copied from Firefox (how many sets the extension checks)
# Plus the two global storage-backend keys, forced false so Vivaldi keeps
# reading chrome.storage.local (Local Extension Settings), where we write:
#   sync            forced false
#   autoExportSync  forced false
# All OTHER LeechBlock keys (blockURL, applyFilter, timedata,
# prev* snapshots, override runtime, captcha image, ...) are left untouched
# in Vivaldi.
#
# Vivaldi MUST be stopped for the set / --sync-from forms (LevelDB write lock).
# The --sync-from / --diff forms read Firefox's storage-sync-v2.sqlite
# read-only, so Firefox may be running.
import json, os, re, shutil, sqlite3, sys, tempfile, time

import plyvel

LB_FF_ID = "leechblockng@proginosko.com"
NUM_SETS = 6
ALL_DAYS = [True] * 7

# Regex metacharacters LeechBlock escapes when compiling sites{n}.
_LB_RE_SPECIALS = ".|?+^$()[]{}\\"


def _pattern_to_regexp(pattern, match_subdomains):
    # Replicates LeechBlock NG common.js patternToRegExp exactly:
    #   escape specials -> unicode percent-encode -> strip www. -> wildcards
    # Subdomains prefix is NOT escaped (it is regex syntax).
    special = re.compile("[.\\\\|?+^$(){}[\\]]")
    out = special.sub(lambda m: "\\" + m.group(0), pattern)
    # Unicode percent-encode (matches encodeURIComponent behaviour).
    buf = []
    for ch in out:
        cp = ord(ch)
        if cp >= 0x80:
            buf.append("%%%02X" % cp)
        else:
            buf.append(ch)
    out = "".join(buf)
    # Strip a leading already-escaped "www." (avoids double-prefix).
    out = re.sub(r"^www\\\.", "", out)
    # Plus-wildcard: "*+" (where + was already escaped to \+) -> ".+"
    out = out.replace("*\\+", ".+")
    # Super-wildcard: "**" or more -> ".*"
    out = re.sub(r"\*{2,}", ".*", out)
    # Single wildcard: "*" -> "[^\/]*"
    out = out.replace("*", "[^\\/]*")
    subdomains = "([^/]*\\.)?" if match_subdomains else "(www\\.)?"
    return subdomains + out


def _keyword_to_regexp(keyword):
    # Replicates LeechBlock NG common.js keywordToRegExp:
    #   escape specials -> underscores to \s+ -> stars to [\p{L}\p{N}]*
    special = re.compile("[.\\\\|?+^$(){}[\\]]")
    out = special.sub(lambda m: "\\" + m.group(0), keyword)
    out = re.sub(r"_+", r"\\s+", out)
    out = re.sub(r"\*+", r"[\\p{L}\\p{N}]*", out)
    return out


# Replicate LeechBlock NG's site-list -> blockRE/allowRE/referRE/keywordRE
# compiler so the daemon can force a freshly synced sites{n} to actually take
# effect WITHOUT requiring the user to open & Save the LeechBlock Options page
# (which the policies block). Verified against common.js getRegExpSites /
# patternToRegExp / keywordToRegExp for wildcard, plain, path, and keyword
# entries.
def sites_to_regexps(sites, match_subdomains=False):
    if not isinstance(sites, str) or not sites.strip():
        return {
            "block": "",
            "allow": "",
            "refer": "",
            "keyword": "",
        }
    block_files = False
    allow_files = False
    blocks = []
    allows = []
    refers = []
    keywords = []
    for raw in sites.split():
        if raw == "FILE":
            block_files = True
            continue
        if raw == "+FILE":
            allow_files = True
            continue
        if not raw:
            continue
        first = raw[0]
        if first == "~":
            keywords.append(_keyword_to_regexp(raw[1:]))
        elif first == ">":
            refers.append(_pattern_to_regexp(raw[1:], match_subdomains))
        elif first == "+":
            allows.append(_pattern_to_regexp(raw[1:], match_subdomains))
        elif first == "#":
            continue
        else:
            blocks.append(_pattern_to_regexp(raw, match_subdomains))
    prefix = ""
    if block_files:
        prefix = "file:|"
    if blocks:
        prefix += "(https?|file):\\/+([\\w:]+@)?(" + "|".join(blocks) + ")"
    block_re = "^" + prefix if prefix else ""
    a_prefix = ""
    if allow_files:
        a_prefix = "file:|"
    if allows:
        a_prefix += "(https?|file):\\/+([\\w:]+@)?(" + "|".join(allows) + ")"
    allow_re = "^" + a_prefix if a_prefix else ""
    r_prefix = ""
    if refers:
        r_prefix = "(https?|file):\\/+([\\w:]+@)?(" + "|".join(refers) + ")"
    refer_re = "^" + r_prefix if r_prefix else ""
    kw_re = ""
    if keywords:
        u_word_char = "[\\p{L}\\p{N}]"
        u_begin = "(?<!" + u_word_char + ")(?=" + u_word_char + ")"
        u_end = "(?<=" + u_word_char + ")(?!" + u_word_char + ")"
        kw_re = u_begin + "(" + "|".join(keywords) + ")" + u_end
    return {
        "block": block_re,
        "allow": allow_re,
        "refer": refer_re,
        "keyword": kw_re,
    }


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
# `sites{n}` is mirrored from Firefox; blockRE is recompiled; keyword/title/
# allow settings and numSets are mirrored too. Returns a list of (key,
# python_value).
def managed_items(ff):
    out = [("sync", False), ("autoExportSync", False)]
    num_sets = int(ff.get("numSets", NUM_SETS))
    if num_sets < 1:
        num_sets = 1
    if num_sets > NUM_SETS:
        num_sets = NUM_SETS
    # Raise numSets to cover any non-empty managed set.
    highest_nonempty = 0
    for n in range(1, NUM_SETS + 1):
        sites = ff.get("sites%d" % n, "")
        if not isinstance(sites, str):
            sites = ""
        if sites.strip() or ff.get("keywordRE%d" % n) or ff.get("regexpBlock%d" % n):
            highest_nonempty = n
    num_sets = max(num_sets, highest_nonempty)
    out.append(("numSets", num_sets))
    for n in range(1, NUM_SETS + 1):
        sites = ff.get("sites%d" % n, "")
        if not isinstance(sites, str):
            sites = ""
        nonempty = bool(sites.strip()) or bool(ff.get("keywordRE%d" % n)) or bool(ff.get("regexpBlock%d" % n))
        compiled = sites_to_regexps(sites, False)
        out.append(("sites%d" % n, sites))
        out.append(("blockRE%d" % n, compiled["block"] if nonempty else ""))
        out.append(("allowRE%d" % n, compiled["allow"]))
        out.append(("referRE%d" % n, compiled["refer"]))
        out.append(("keywordRE%d" % n, ff.get("keywordRE%d" % n, "")))
        out.append(("titleOnly%d" % n, ff.get("titleOnly%d" % n, False)))
        out.append(("allowKeywords%d" % n, ff.get("allowKeywords%d" % n, False)))
        out.append(("closeTab%d" % n, ff.get("closeTab%d" % n, False)))
        out.append(("showTimer%d" % n, ff.get("showTimer%d" % n, True)))
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
        except Exception as e:
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
