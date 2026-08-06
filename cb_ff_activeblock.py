#!/usr/bin/env python3
# cb_ff_activeblock.py - read or set LeechBlock NG activeBlock1..6 in Firefox's
# storage-sync-v2.sqlite. Used by cockblockd to snapshot block-set state before
# a pause-unblock window and to re-enable any set the user disabled during it.
#
#   cb_ff_activeblock.py <sqlite_path>             -> print "1,1,1,0,1,1"
#                                                     (activeBlock1..6)
#   cb_ff_activeblock.py <sqlite_path> --nonempty   -> print "1,1,1,0,0,0"
#                                                     (sites{n} non-empty csv)
#   cb_ff_activeblock.py <sqlite_path> <0/1 csv>    -> set activeBlock1..6, commit
#
# Firefox MUST be stopped before the set form (sqlite write lock). The set bumps
# sync_change_counter so Firefox pushes the corrected state to Mozilla Sync on
# next launch (preventing the cloud from re-pulling the disabled state).
import json, sqlite3, sys

EXT = "leechblockng@proginosko.com"


def load(con):
    row = con.execute(
        "SELECT data FROM storage_sync_data WHERE ext_id=?", (EXT,)).fetchone()
    return json.loads(row[0]) if row and row[0] else {}


def main():
    path = sys.argv[1]
    con = sqlite3.connect(path)
    if len(sys.argv) >= 3 and sys.argv[2] == "--nonempty":
        d = load(con)
        print(",".join(
            "1" if ((isinstance(d.get("sites%d" % (i + 1)), str)
                    and d.get("sites%d" % (i + 1)).strip())
                   or (isinstance(d.get("regexpBlock%d" % (i + 1)), str)
                       and d.get("regexpBlock%d" % (i + 1)).strip())) else "0"
            for i in range(6)))
    elif len(sys.argv) < 3:
        d = load(con)
        print(",".join("1" if d.get("activeBlock%d" % (i + 1)) else "0"
                       for i in range(6)))
    else:
        vals = [x == "1" for x in sys.argv[2].split(",")][:6]
        d = load(con)
        for i, v in enumerate(vals):
            d["activeBlock%d" % (i + 1)] = v
        s = json.dumps(d)
        con.execute("UPDATE storage_sync_data SET data=?, "
                    "sync_change_counter=COALESCE(sync_change_counter,0)+1 "
                    "WHERE ext_id=?", (s, EXT))
        con.commit()
    con.close()


main()
