#!/usr/bin/env python3
# cb_ff_leechblock.py - manage LeechBlock NG rules directly in Firefox's
# storage-sync-v2.sqlite WITHOUT opening the LeechBlock Options page (which
# the cockblockd Firefox policies block). Mirrors the Vivaldi tool's name
# (cb_vv_leechblock.py): Firefox-side counterpart for rule editing.
#
# LeechBlock only (re)compiles sites{n} -> blockRE{n}/keywordRE{n} on Save in
# the Options UI; the extension reads the stored blockRE{n}/keywordRE{n}/
# regexpBlock{n} directly at load (createRegExps). So every write here also
# writes the compiled regex values, otherwise a freshly edited sites{n} would
# not take effect until the user opens & Saves Options.
#
# Subcommands:
#   list                              show all block sets (name, type, active,
#                                     limits, site count, keywords)
#   add-rule --keywords "w1 w2 ..."   set up always-blocked keyword (set 5) +
#                                     URL-regex (set 6) sets from scratch
#                                     (overwrites those two sets)
#   add-keywords "w1 w2 ..."          APPEND keywords to sets 5 (title/body)
#                                     and 6 (URL); inits them if absent
#   add-sites <set> "s1 s2 ..."       APPEND site patterns to a set's site
#                                     list and recompile its blockRE
#
#   cb_ff_leechblock.py [sqlite] list
#   cb_ff_leechblock.py [sqlite] add-rule   --keywords "w1 w2 ..." \
#       [--kw-set 5] [--url-set 6] [--title-only] [--no-close] \
#       [--name-kw STR] [--name-url STR] [--print]
#   cb_ff_leechblock.py [sqlite] add-keywords "w1 w2 ..." \
#       [--kw-set 5] [--url-set 6] [--print]
#   cb_ff_leechblock.py [sqlite] add-sites <set> "s1 s2 ..." [--print]
#
# The <sqlite> path is optional; if omitted it is inferred from profiles.ini
# (snap path ~/snap/firefox/common/.mozilla/firefox first, then the classic
# ~/.mozilla/firefox), mirroring cockblockd's find_profile_path().
#
# Firefox MUST be stopped for write subcommands (sqlite write lock + so
# Firefox does not overwrite the row on next sync). Bumps sync_change_counter
# so Firefox pushes the new state to Mozilla Sync on next launch, and drops
# addonStartup.json.lz4 so the extension reloads config cleanly.
import glob, json, os, re, sqlite3, subprocess, sys, time as _time

EXT = "leechblockng@proginosko.com"
ALL_DAYS = [True] * 7
NUM_SETS = 6

# Page Keyword Filter extension (separate signed WebExtension that does the
# title/body keyword matching, so LeechBlock's catch-all keyword set can be
# dropped and the timed sets keep their countdown badge). Its block list is a
# managed-storage manifest on disk -- managed here so the live word list never
# has to be committed to the repo. Root-owned system path (installed by
# make install); not user-writable, so kw-add must run as root.
PKF_EXT_ID = "page-keyword-filter-7f3a@local.addons"
# Snap Firefox is confined: it cannot read /usr/lib/mozilla/managed-storage or
# /opt/cockblock. Its readable home is ~/snap/firefox/common, where it looks
# for ~/.mozilla/managed-storage/. Deploy the manifest there so the extension
# (and kw-add/kw-list) reach it. For non-snap Firefox, /usr/lib/mozilla would
# be correct; this snap layout is the supported config here.
_M_HOME = os.path.join(os.path.expanduser("~"), "snap/firefox/common/.mozilla")
if not os.path.isdir(_M_HOME):
    _M_HOME = os.path.join(os.path.expanduser("~"), ".mozilla")
PKF_MANAGED_PATH = os.path.join(_M_HOME, "managed-storage", "%s.json" % PKF_EXT_ID)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cb_vv_leechblock import sites_to_regexps


# Infer the storage-sync-v2.sqlite path from Firefox's profiles.ini, mirroring
# cockblockd's find_profile_path(). Tries the snap layout first (where this
# machine's Firefox lives), then the classic ~/.mozilla/firefox layout. Returns
# the sqlite path or raises RuntimeError with a helpful message.
#
# When run as root (e.g. via sudo for kw-add / cb_ff_clear_kwset.py), "~" is
# /root, which has no Firefox profile. So the real user's home is resolved
# from $SUDO_USER (or $USER) and /home/* is scanned as a fallback -- a single
# Firefox user is the normal case here.
def _profile_homes():
    homes = []
    me = os.path.expanduser("~")
    homes.append(me)
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd as _pwd
            homes.append(_pwd.getpwnam(sudo_user).pw_dir)
        except Exception:
            pass
    # Fallback: scan /home for any profile (single-user machine).
    for h in (glob.glob("/home/*"), glob.glob("/root")):
        for d in h:
            if d not in homes:
                homes.append(d)
    # De-duplicate, keep order.
    seen = set(); out = []
    for h in homes:
        if h not in seen:
            seen.add(h); out.append(h)
    return out


def infer_sqlite_path():
    for home in _profile_homes():
        candidates = [
            os.path.join(home, "snap/firefox/common/.mozilla/firefox"),
            os.path.join(home, ".mozilla/firefox"),
        ]
        for base in candidates:
            ini = os.path.join(base, "profiles.ini")
            if not os.path.isfile(ini):
                continue
            with open(ini, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("Path="):
                        prof = line[5:]
                        sqlite = os.path.join(base, prof,
                                              "storage-sync-v2.sqlite")
                        if os.path.isfile(sqlite):
                            return sqlite
    raise RuntimeError(
        "could not infer Firefox storage-sync-v2.sqlite path: no profiles.ini "
        "with a Path= pointing at an existing profile. Run as the Firefox user "
        "(not root), or pass the path explicitly as the first argument.")


def firefox_running():
    try:
        out = subprocess.run(["pgrep", "-x", "firefox"],
                             capture_output=True, text=True)
        return out.returncode == 0
    except Exception:
        return False


def recompile_from_sites(d, n):
    sites = d.get("sites%d" % n, "")
    if not isinstance(sites, str):
        sites = ""
    compiled = sites_to_regexps(sites, False)
    d["blockRE%d" % n] = compiled["block"]
    d["allowRE%d" % n] = compiled["allow"]
    d["referRE%d" % n] = compiled["refer"]
    d["keywordRE%d" % n] = compiled["keyword"]


def keyword_tokens_in_sites(sites):
    if not isinstance(sites, str):
        return []
    return [t[1:] for t in sites.split() if t.startswith("~") and len(t) > 1]


def ensure_always_blocked(d, n, name=None, close_tab=True, title_only=False):
    d["activeBlock%d" % n] = True
    d["disable%d" % n] = False
    d["days%d" % n] = ALL_DAYS
    d["times%d" % n] = "0000-2359"
    d["limitMins%d" % n] = ""
    d["limitPeriod%d" % n] = ""
    d["limitOffset%d" % n] = ""
    d["allowKeywords%d" % n] = False
    d["closeTab%d" % n] = close_tab
    d["titleOnly%d" % n] = title_only
    d["showTimer%d" % n] = False
    if name:
        d["setName%d" % n] = name


def bump_numsets(d, *sets):
    cur = int(d.get("numSets", str(NUM_SETS)) or str(NUM_SETS))
    need = max([cur] + list(sets))
    if need > NUM_SETS:
        sys.exit("ERROR: set index %d exceeds NUM_SETS (%d)" % (need, NUM_SETS))
    d["numSets"] = str(need)


def open_db(path, readonly):
    if readonly:
        return sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    return sqlite3.connect(path, timeout=10)


def load(con):
    row = con.execute(
        "SELECT data FROM storage_sync_data WHERE ext_id=?", (EXT,)).fetchone()
    return json.loads(row[0]) if row and row[0] else {}


def commit(con, d):
    s = json.dumps(d, ensure_ascii=False)
    con.execute("UPDATE storage_sync_data SET data=?, "
                "sync_change_counter=COALESCE(sync_change_counter,0)+1 "
                "WHERE ext_id=?", (s, EXT))
    con.commit()


def drop_startup_cache(path):
    profile = os.path.dirname(os.path.abspath(path))
    removed = []
    for f in ("addonStartup.json.lz4", "addonStartup.json"):
        p = os.path.join(profile, f)
        try:
            if os.path.isfile(p):
                os.remove(p)
                removed.append(f)
        except OSError:
            pass
    return removed


# --- subcommands ---------------------------------------------------------

def _period_start(now, limit_period, limit_offset):
    limit_period = int(limit_period) if limit_period else 3600
    limit_offset = int(limit_offset) if limit_offset else 0
    if limit_period <= 0:
        return 0
    ps = now - (now % limit_period)
    if limit_period > 3600:
        ps += limit_offset * 3600
        import datetime
        # JS getTimezoneOffset() returns UTC-local in minutes (negative for
        # UTC+); Python utcoffset() returns local-UTC (positive for UTC+).
        # Negate to match LeechBlock's behaviour.
        ps -= datetime.datetime.now().astimezone().utcoffset().total_seconds()
        if limit_period > 86400:
            ps -= 345600
        while ps > now:
            ps -= limit_period
        while ps <= now - limit_period:
            ps += limit_period
    return int(ps)


def _fmt_secs(secs):
    if secs is None or secs < 0:
        return "-"
    h = int(secs) // 3600
    m = (int(secs) % 3600) // 60
    s = int(secs) % 60
    return "%d:%02d:%02d" % (h, m, s)


def _time_left(d, n):
    limit_mins = d.get("limitMins%d" % n, "") or ""
    limit_period = d.get("limitPeriod%d" % n, "") or ""
    limit_offset = d.get("limitOffset%d" % n, "") or ""
    if not limit_mins or not limit_period:
        return None
    now = int(_time.time())
    td = d.get("timedata%d" % n)
    if not isinstance(td, list) or len(td) < 4:
        return int(limit_mins) * 60
    ps = _period_start(now, limit_period, limit_offset)
    spent = td[3] if td[2] == ps else 0
    return max(0, int(limit_mins) * 60 - int(spent))


def cmd_list(d):
    num = int(d.get("numSets", str(NUM_SETS)) or str(NUM_SETS))
    print("numSets = %d" % num)
    hdr = "%-4s %-22s %-7s %-5s %-7s %-8s %-20s %s"
    print(hdr % ("set", "name", "active", "sites", "left", "limitM", "times", "keywords / regexpBlock"))
    print("-" * 110)
    for n in range(1, NUM_SETS + 1):
        name = (d.get("setName%d" % n, "") or "")[:22]
        active = "yes" if d.get("activeBlock%d" % n) else "no"
        sites = d.get("sites%d" % n, "") or ""
        site_tokens = [t for t in sites.split()
                       if t and not t.startswith("~") and t != "*"]
        nsites = str(len(site_tokens))
        if sites.strip() and not site_tokens:
            nsites = "*" if "*" in sites.split() else "0"
        limit_mins = d.get("limitMins%d" % n, "") or ""
        limit = _fmt_secs(int(limit_mins) * 60) if limit_mins else "-"
        times = (d.get("times%d" % n, "") or "") or "-"
        left = _fmt_secs(_time_left(d, n)) if limit else "-"
        kws = keyword_tokens_in_sites(sites)
        regexp_block = d.get("regexpBlock%d" % n, "") or ""
        extra = []
        if kws:
            extra.append("kw[%s]" % ",".join(kws))
        if regexp_block:
            extra.append("url[%s]" % regexp_block)
        kwstr = " ".join(extra) if extra else "-"
        mark = "" if n <= num else "  (beyond numSets)"
        print(hdr % (n, name, active, nsites, left, limit, times, kwstr) + mark)


def cmd_add_rule(d, args):
    keywords = None
    kw_set = 5
    url_set = 6
    title_only = False
    name_kw = "keyword-block"
    name_url = "url-block"
    close_tab = True
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--keywords":
            keywords = args[i + 1]; i += 2
        elif a == "--kw-set":
            kw_set = int(args[i + 1]); i += 2
        elif a == "--url-set":
            url_set = int(args[i + 1]); i += 2
        elif a == "--title-only":
            title_only = True; i += 1
        elif a == "--no-close":
            close_tab = False; i += 1
        elif a == "--name-kw":
            name_kw = args[i + 1]; i += 2
        elif a == "--name-url":
            name_url = args[i + 1]; i += 2
        else:
            sys.exit("unknown arg: %s" % a)
    kw_tokens = [t for t in (keywords or "").split() if t]
    if not kw_tokens:
        sys.exit("ERROR: --keywords is required for add-rule "
                 '(e.g. --keywords "word1 word2")')

    kw_sites = "* " + " ".join("~" + t for t in kw_tokens)
    url_re = "|".join(kw_tokens)

    # keyword set (title/body): sites="*" gate + ~tokens -> keywordRE
    d["sites%d" % kw_set] = kw_sites
    recompile_from_sites(d, kw_set)
    ensure_always_blocked(d, kw_set, name_kw, close_tab, title_only)

    # url-regex set: regexpBlock matched against full URL; no site gate
    d["sites%d" % url_set] = ""
    recompile_from_sites(d, url_set)
    d["regexpBlock%d" % url_set] = url_re
    ensure_always_blocked(d, url_set, name_url, close_tab, False)

    bump_numsets(d, kw_set, url_set)
    return ("set %d keyword[%s] + set %d url-regex[%s]; numSets=%s"
            % (kw_set, " ".join(kw_tokens), url_set, url_re, d["numSets"]))


def cmd_add_keywords(d, args):
    if not args or args[0].startswith("--"):
        sys.exit('ERROR: add-keywords needs a word list, e.g. add-keywords "w1 w2"')
    words = args[0]
    kw_set = 5
    url_set = 6
    i = 1
    while i < len(args):
        a = args[i]
        if a == "--kw-set":
            kw_set = int(args[i + 1]); i += 2
        elif a == "--url-set":
            url_set = int(args[i + 1]); i += 2
        else:
            sys.exit("unknown arg: %s" % a)
    new_tokens = [t for t in words.split() if t]
    if not new_tokens:
        sys.exit("ERROR: no keywords given")

    # Keyword set (title/body): append ~tokens to sites, recompile keywordRE.
    sites = d.get("sites%d" % kw_set, "") or ""
    existing_kw = set(keyword_tokens_in_sites(sites))
    site_tokens = [t for t in sites.split() if not t.startswith("~")]
    has_gate = "*" in site_tokens
    appended_kw = [w for w in new_tokens if w not in existing_kw]
    if not appended_kw:
        print("no new keywords to add to set %d (all already present)" % kw_set)
    else:
        parts = []
        if has_gate:
            parts.append("*")
        parts += [t for t in site_tokens if t != "*"]
        parts += ["~" + w for w in (list(existing_kw) + appended_kw)]
        d["sites%d" % kw_set] = " ".join(parts)
        recompile_from_sites(d, kw_set)
        ensure_always_blocked(d, kw_set)

    # URL-regex set: append alternations to regexpBlock, recompile.
    regexp_block = d.get("regexpBlock%d" % url_set, "") or ""
    existing_url = set(re.split(r"\|", regexp_block)) if regexp_block else set()
    appended_url = [w for w in new_tokens if w not in existing_url]
    if not appended_url:
        print("no new keywords to add to set %d (all already present)" % url_set)
    else:
        all_url = [w for w in (regexp_block.split("|") if regexp_block else [])
                   if w] + appended_url
        d["regexpBlock%d" % url_set] = "|".join(all_url)
        d["sites%d" % url_set] = d.get("sites%d" % url_set, "") or ""
        recompile_from_sites(d, url_set)
        ensure_always_blocked(d, url_set)

    bump_numsets(d, kw_set, url_set)
    return ("appended to set %d kw[%s] + set %d url[%s]"
            % (kw_set, " ".join(appended_kw or ["(none)"]),
               url_set, " ".join(appended_url or ["(none)"])))


def cmd_add_sites(d, args):
    if len(args) < 2:
        sys.exit('ERROR: add-sites needs <set> <sites>, e.g. add-sites 2 "a.com b.com"')
    n = int(args[0])
    if n < 1 or n > NUM_SETS:
        sys.exit("ERROR: set must be 1..%d" % NUM_SETS)
    new_sites = [t for t in args[1].split() if t]
    if not new_sites:
        sys.exit("ERROR: no sites given")
    sites = d.get("sites%d" % n, "") or ""
    existing = [t for t in sites.split()]
    existing_set = set(existing)
    appended = [t for t in new_sites if t not in existing_set]
    if not appended:
        print("no new sites to add to set %d (all already present)" % n)
        return None
    combined = (existing + appended)
    d["sites%d" % n] = " ".join(combined)
    recompile_from_sites(d, n)
    # Preserve regexpBlock if present (URL-regex sets); do not touch schedule
    # keys of pre-existing timed sets (1-4) so their limits stay intact.
    return ("appended %d site(s) to set %d: %s" %
            (len(appended), n, " ".join(appended)))


# --- Page Keyword Filter managed-storage block list ----------------------
#
# The keyword block list lives in a managed-storage manifest at PKF_MANAGED_PATH
# (read by the Page Keyword Filter extension via browser.storage.managed). It is
# NOT part of the signed .xpi, so the live words never have to be committed to
# the repo and AMO signs the extension clean. The repo ships only an empty
# template (cb_keyword_managed_storage.json) used on first install; once the
# file exists, `make update` leaves it alone so user-added words survive.

def _load_managed():
    if not os.path.isfile(PKF_MANAGED_PATH):
        return None
    with open(PKF_MANAGED_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def cmd_kw_list():
    # Page Keyword Filter managed-storage list (title/body matching).
    m = _load_managed()
    if not m or m.get("type") != "storage":
        sys.exit("ERROR: managed-storage manifest not found at %s "
                 "(run `make install` first to deploy the template)" % PKF_MANAGED_PATH)
    data = m.get("data", {}) or {}
    kws = data.get("keywords", [])
    title_only = bool(data.get("titleOnly", False))
    print("--- Page Keyword Filter (title/body) ---")
    if not kws:
        print("keywords: (empty)")
    else:
        print("keywords (%d): %s" % (len(kws), " ".join(kws)))
    print("titleOnly: %s" % title_only)
    # LeechBlock set 6 (URL-regex matching).
    print("--- LeechBlock set 6 (url-regex) ---")
    try:
        con = open_db(infer_sqlite_path(), True)
        d = load(con)
        con.close()
    except Exception as e:
        print("(could not read LeechBlock: %s)" % e)
        return
    rb = d.get("regexpBlock6", "") or ""
    url_words = [w for w in rb.split("|") if w] if rb else []
    if not url_words:
        print("keywords: (empty)")
    else:
        print("keywords (%d): %s" % (len(url_words), " ".join(url_words)))


def cmd_kw_add(args):
    if not args:
        sys.exit('ERROR: kw-add needs a word list, e.g. kw-add "word1 word2"')
    words = [w for w in args[0].split() if w]
    if not words:
        sys.exit("ERROR: no words given")
    if os.geteuid() != 0:
        sys.exit("ERROR: kw-add must run as root (the managed-storage manifest "
                 "is root-owned at %s); use: sudo cb_ff_leechblock.py kw-add ..."
                 % PKF_MANAGED_PATH)
    m = _load_managed()
    if m is None:
        sys.exit("ERROR: managed-storage manifest not found at %s "
                 "(run `make install` first)" % PKF_MANAGED_PATH)

    # 1) Page Keyword Filter managed storage (title/body matching).
    data = m.setdefault("data", {})
    if not isinstance(data, dict):
        data = {}
        m["data"] = data
    existing_kw = data.get("keywords", [])
    if not isinstance(existing_kw, list):
        existing_kw = []
    kw_set = set(existing_kw)
    appended_kw = [w for w in words if w not in kw_set]
    if appended_kw:
        data["keywords"] = existing_kw + appended_kw
        s = json.dumps(m, ensure_ascii=False, indent=2)
        with open(PKF_MANAGED_PATH, "w", encoding="utf-8") as f:
            f.write(s)
            f.write("\n")
        print("ADDED %d to Page Keyword Filter (title/body): %s"
              % (len(appended_kw), " ".join(appended_kw)))
    else:
        print("Page Keyword Filter: no new words (all present)")

    # 2) LeechBlock set 6 (URL-regex matching). Requires Firefox stopped.
    appended_url = []
    if firefox_running():
        print("LeechBlock set 6: SKIPPED (firefox is running; stop it to add "
              "url-regex words, then re-run)")
    else:
        con = open_db(infer_sqlite_path(), False)
        d = load(con)
        rb = d.get("regexpBlock6", "") or ""
        existing_url = set(re.split(r"\|", rb)) if rb else set()
        appended_url = [w for w in words if w not in existing_url]
        if appended_url:
            all_url = [w for w in rb.split("|") if w] + appended_url
            d["regexpBlock6"] = "|".join(all_url)
            d["sites6"] = d.get("sites6", "") or ""
            recompile_from_sites(d, 6)
            ensure_always_blocked(d, 6)
            bump_numsets(d, 6, 6)
            commit(con, d)
        con.close()
        if appended_url:
            print("ADDED %d to LeechBlock set 6 (url-regex): %s"
                  % (len(appended_url), " ".join(appended_url)))
        else:
            print("LeechBlock set 6: no new words (all present)")

    # Drop the addonStartup cache so both extensions reload on next launch.
    try:
        removed = drop_startup_cache(infer_sqlite_path())
    except Exception:
        removed = []
    if removed:
        print("DROPPED startup cache: %s (extensions reload on next launch)"
              % ", ".join(removed))


SUBCOMMANDS = {"list", "add-rule", "add-keywords", "add-sites",
                "kw-list", "kw-add"}


USAGE = """\
cb_ff_leechblock.py - manage LeechBlock NG rules in Firefox without opening
the browser UI. Writes directly to storage-sync-v2.sqlite, recompiles the
stored blockRE/keywordRE/regexpBlock (so changes take effect without a
Options-page Save), bumps the sync counter, and drops the addonStartup cache
so the extension reloads config on next launch.

USAGE
    cb_ff_leechblock.py [sqlite] <subcommand> [options]

The [sqlite] path is optional; if omitted it is inferred from Firefox's
profiles.ini (snap path first, then classic ~/.mozilla/firefox).

SUBCOMMANDS
    list
        Print a table of all block sets: name, active, site count, daily
        limit (mins), time window, and any keywords / URL-regex.

    add-rule --keywords "w1 w2 ..."
        Create two always-blocked (24/7, every day, no limit) sets from
        scratch (overwrites their previous content):
          set 5 (keyword): sites="*" + ~w1 ~w2 ...  -> matches the page
                           title AND body text (use --title-only to scan
                           title only).
          set 6 (url):     regexpBlock="w1|w2|..."  -> matches anywhere in
                           the page URL (host + path); blocks before render.
        Matched tabs are closed (--no-close to redirect to block page instead).
        Options: [--kw-set N] [--url-set N] [--title-only] [--no-close]
                 [--name-kw STR] [--name-url STR] [--print]

    add-keywords "w1 w2 ..."
        APPEND words to the keyword set (5) and url-regex set (6), without
        clobbering existing keywords. Inits the sets if they are absent.
        Options: [--kw-set 5] [--url-set 6] [--print]

    add-sites <set> "s1 s2 ..."
        APPEND site patterns to a set's site list and recompile its blockRE.
        Does NOT touch the set's limit/schedule/active keys, so timed sets
        (e.g. 1-4) keep their daily limits intact.
        Options: [--print]

    kw-list
        Print BOTH keyword block lists:
          - Page Keyword Filter extension (title/body matching; managed storage)
          - LeechBlock set 6 (URL-regex matching)

    kw-add "w1 w2 ..."
        APPEND words to BOTH block lists in one shot:
          - Page Keyword Filter (title/body matching; managed storage at %s)
          - LeechBlock set 6 (URL-regex matching; storage-sync sqlite)
        The managed-storage write needs root. The LeechBlock write needs Firefox
        STOPPED (sqlite lock); if Firefox is running, the managed-storage part
        still succeeds and set 6 is skipped with a message (stop Firefox and
        re-run to add the url-regex words). Drops the addonStartup cache so both
        extensions reload on next launch. The timed sets (1-4) are untouched.

COMMON OPTIONS
    --print     Dry-run: show the resulting JSON instead of writing. Works
                with add-rule / add-keywords / add-sites. Implied for list.
    --help, -h  Show this help.

NOTES
    Firefox MUST be stopped for write subcommands (sqlite write lock + so
    Firefox does not overwrite the row on next sync). cockblockd mirrors the
    result into Vivaldi automatically on its next cycle.
""" % PKF_MANAGED_PATH


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("--help", "-h", "help"):
        sys.exit(USAGE)
    # kw-list / kw-add manage the Page Keyword Filter managed-storage manifest,
    # not Firefox's LeechBlock sqlite -- handle them before opening the db and
    # without requiring a profile path. They still take an optional leading
    # sqlite path arg for consistency, but ignore it.
    cmd = None
    rest = []
    if args[0] not in SUBCOMMANDS and len(args) >= 2 and args[1] in SUBCOMMANDS:
        cmd = args[1]
        rest = args[2:]
    elif args[0] in SUBCOMMANDS:
        cmd = args[0]
        rest = args[1:]
    if cmd == "kw-list":
        if "--help" in rest or "-h" in rest:
            sys.exit(USAGE)
        cmd_kw_list()
        return
    if cmd == "kw-add":
        if "--help" in rest or "-h" in rest:
            sys.exit(USAGE)
        cmd_kw_add(rest)
        return

    # LeechBlock sqlite subcommands below.
    if args[0] in SUBCOMMANDS:
        path = infer_sqlite_path()
        cmd = args[0]
        rest = args[1:]
    else:
        if len(args) < 2 or args[1] not in SUBCOMMANDS:
            sys.exit(USAGE + "\nERROR: expected a subcommand "
                     "(list|add-rule|add-keywords|add-sites|kw-list|kw-add)")
        path = args[0]
        cmd = args[1]
        rest = args[2:]
    readonly_cmds = {"list"}
    if "--help" in rest or "-h" in rest:
        sys.exit(USAGE)
    has_print = "--print" in rest
    rest = [a for a in rest if a != "--print"]
    if cmd == "add-rule":
        readonly = has_print
    elif cmd in readonly_cmds:
        readonly = True
    elif cmd in ("add-keywords", "add-sites"):
        readonly = has_print
    else:
        sys.exit("unknown subcommand: %s "
                 "(use list|add-rule|add-keywords|add-sites|kw-list|kw-add)" % cmd)

    con = open_db(path, readonly)
    d = load(con)

    if cmd == "list":
        cmd_list(d)
        con.close()
        return

    if cmd == "add-rule":
        summary = cmd_add_rule(d, rest)
    elif cmd == "add-keywords":
        summary = cmd_add_keywords(d, rest)
    elif cmd == "add-sites":
        summary = cmd_add_sites(d, rest)
    else:
        con.close()
        sys.exit("unknown subcommand: %s" % cmd)

    if readonly:
        print(json.dumps(d, indent=2, ensure_ascii=False))
        con.close()
        return

    if summary is None:
        con.close()
        return

    if firefox_running():
        con.close()
        sys.exit("ERROR: firefox is running. Stop it first "
                 "(cockblockd or `pkill firefox`) so it does not overwrite "
                 "the row, then re-run.")
    commit(con, d)
    con.close()
    removed = drop_startup_cache(path)
    print("WROTE " + summary)
    if removed:
        print("DROPPED startup cache: %s (extension reloads on next launch)"
              % ", ".join(removed))


if __name__ == "__main__":
    main()
