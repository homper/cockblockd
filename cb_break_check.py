#!/usr/bin/env python3
# cb_break_check.py - detect whether a SafeEyes break overlay is currently
# shown, and which type (short / long). Used by cockblockd so that suspending
# the machine mid-break cannot be used to escape the break: the daemon records
# the break start + type each cycle and, on resume, re-imposes a break for the
# TIME LEFT (not a full break) if the suspend was shorter than the break.
#
#   cb_break_check.py   -> prints a single token line:
#                            IDLE         - no break screen
#                            BREAK_SHORT  - a short break overlay is up
#                            BREAK_LONG   - a long break overlay is up
#                            BREAK        - a break overlay is up but the
#                                           type could not be determined
#
# SafeEyes titles its fullscreen break windows "SafeEyes-0", "SafeEyes-1", ...
# (ui/break_screen.py: set_title("SafeEyes-" + str(i))). They are real managed
# toplevels, so Wnck lists them. We match the prefix "SafeEyes-" followed by a
# digit to avoid matching the settings/about dialogs ("Safe Eyes ...").
#
# Type: SafeEyes writes the current break's NAME to session.json under the
# "break" key (set when the break's wait period begins, so it is the in-progress
# break while the overlay is up). We match that name against the live config's
# short_breaks / long_breaks name lists to classify short vs long. The match is
# by name; names are unique across the two lists in the shipped configs.
#
# Fail-safe: on any error (no DISPLAY, Wnck missing, X down, unreadable config)
# we print IDLE when no window is found, or BREAK (type unknown) when a window
# is found but classification fails -- so the daemon falls back to re-imposing
# a full break rather than falsely reporting IDLE (which would let a suspend
# escape the break).
import json
import os
import sys

CONFIG_PATH = os.path.expanduser("~/.config/safeeyes/safeeyes.json")
SESSION_PATH = os.path.expanduser("~/.config/safeeyes/session.json")


def _wnck_break_windows():
    try:
        import gi
        gi.require_version("Gdk", "3.0")
        gi.require_version("Gtk", "3.0")
        gi.require_version("Wnck", "3.0")
        from gi.repository import Gdk, Gtk, Wnck
    except Exception:
        return None  # detection unavailable
    if not os.environ.get("DISPLAY"):
        return None
    try:
        Gdk.init([])
        Gtk.init([])
        screen = Wnck.Screen.get_default()
        if screen is None:
            return False
        screen.force_update()
        found = []
        for w in screen.get_windows():
            name = w.get_name() or ""
            if len(name) >= 9 and name[:9] == "SafeEyes-" and name[9:10].isdigit():
                found.append(name)
        return found
    except Exception:
        return False


def _classify():
    # Returns "BREAK_SHORT", "BREAK_LONG", or "BREAK" (unknown type).
    try:
        cfg = json.load(open(CONFIG_PATH))
        sess = json.load(open(SESSION_PATH))
    except Exception:
        return "BREAK"
    cur = (sess.get("break") or "").strip()
    if not cur:
        return "BREAK"
    short_names = {b.get("name", "") for b in cfg.get("short_breaks", [])}
    long_names = {b.get("name", "") for b in cfg.get("long_breaks", [])}
    if cur in long_names:
        return "BREAK_LONG"
    if cur in short_names:
        return "BREAK_SHORT"
    return "BREAK"


def main():
    wins = _wnck_break_windows()
    if wins is None or wins is False:
        print("IDLE")
        return
    if not wins:
        print("IDLE")
        return
    # A break overlay is up. Try to classify short vs long.
    print(_classify())


if __name__ == "__main__":
    main()
