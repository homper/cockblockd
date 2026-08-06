#!/usr/bin/env python
# Safe Eyes plugin: after a break ends NATURALLY, show a fullscreen modal
# "Start work" dialog and hold the next work interval at zero until the user
# presses Start. SKIPS the dialog if the break was interrupted by a system
# suspend (lid close) -- waking up after a sleep just continues work.
#
# Why fullscreen/modal: a plain GTK window can be alt-tabbed away from or lost
# behind other windows. fullscreen() covers the whole screen + present() raises
# it, so the user must engage with it before working.
#
# Logging: SafeEyes in non-debug mode attaches NO logging handlers (it sets
# propagate=False), so logging.info() is silently dropped. We write our own
# debug trail to ~/.cb_startwork.log so the daemon/user can see the decision
# (natural end vs suspend-skip) without needing `safeeyes --debug`.
#
# Mechanism:
#   - on_stop_break() runs synchronously on the GTK main thread, BEFORE
#     __start_next_break() schedules the next work interval (core.py:363->369).
#   - On a natural end we call core.stop() directly (synchronous). That sets
#     running=False, so __start_next_break's `if self.running:` guard skips
#     scheduling -> the next break is NOT queued -> work timer paused. We then
#     show a fullscreen window.
#   - After a completed break, the Start button calls core.start() and schedules
#     a fresh work interval. For an idle gate, it instead restores the exact
#     work time that remained when the user went away.
#
# Suspend detection:
#   - on_countdown(countdown, seconds) fires every second during a break. We
#     record the last countdown value + wall-clock time.
#   - Natural end: last countdown == 1, gap ~1s (the final __wait_for(1)).
#     -> show dialog.
#   - Suspend: running goes False mid-countdown; the pending 1s GLib timeout
#     fires on resume and hits the else-branch -> on_stop_break, with a gap
#     equal to the suspend duration. gap > 3s => suspend => skip dialog, let
#     work continue.
#   - Composes with cockblockd's time-left re-impose: a suspend SHORTER than
#     the break -> daemon relaunches a fresh time-left break -> ends naturally
#     -> small gap -> dialog (you're back). Suspend LONGER -> large gap -> no
#     dialog, continue work.

import json
import logging
import os
import subprocess
import threading
import time

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, Gio, GLib, Gtk

# X11 native surface access (for the EWMH keep-above hint). Optional: only used
# on X11; the import is guarded so the plugin still loads on a Wayland-only box.
try:
    gi.require_version("GdkX11", "4.0")
    from gi.repository import GdkX11
except Exception:
    GdkX11 = None

# SafeEyes State enum (WAITING = working, PRE_BREAK/RESTING = in a break).
# Imported lazily-safe: this module only loads inside the safeeyes process,
# where safeeyes.model is always importable (smartpause does the same).
try:
    from safeeyes.model import State
except Exception:
    State = None

context = None
core = None
message = "Break is over. Press Start to begin your next work session."
button_label = "Start work"

# --- Idle gate config --------------------------------------------------------
# When the user is away (no keyboard/mouse input AND no browser video/audio
# playing) for idle_gate_seconds, pause the scheduler (core.stop) and show the
# SAME "Start work" dialog as after a natural break end. The user must press
# Start to resume the next work interval. This brackets every work session
# with a Start gate on both ends (break-over and away-too-long).
#
# REQUIRES smartpause DISABLED in safeeyes.json: smartpause calls
# disable_safeeyes() at idle_time (5s) -> core state RESTING, which fires
# before this threshold and would prevent the gate from ever triggering; and
# its _on_resumed calls enable_safeeyes() (= core.start) on activity, which
# would bypass the Start gate. With smartpause off, this plugin owns all idle
# handling.
_idle_gate = True
_idle_gate_seconds = 150        # 2.5 min (mid of the user's "2-3 minutes")
_idle_poll_seconds = 5
_idle_monitor_thread = None
_idle_monitor_stop = threading.Event()
_idle_gated = False             # we triggered the idle gate; dialog is up
_idle_next_break_delay = None   # active work seconds left when idle gate fired

# PipeWire playback streams whose application/media name matches one of these
# tokens count as "browser video playing" -> do NOT gate (the user is
# consuming media, not away).
_BROWSER_APP_TOKENS = ("firefox", "vivaldi", "chromium", "chrome", "brave")

_last_countdown_value = None
_last_countdown_time = 0.0
_dialog = None

# Own file logger (SafeEyes drops logs when not --debug).
_log = logging.getLogger("cb_startwork")
_log.setLevel(logging.DEBUG)
try:
    _h = logging.FileHandler(os.path.expanduser("~/.cb_startwork.log"))
    _h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    _log.addHandler(_h)
except Exception:
    pass


def _log_decision(action, **kw):
    msg = " ".join(f"{k}={v}" for k, v in kw.items())
    _log.info("%s | %s", action, msg)


def init(ctx, safeeyes_config, plugin_config):
    global context, core, message, button_label
    global _idle_gate, _idle_gate_seconds, _idle_poll_seconds
    context = ctx
    try:
        core = ctx.api._application.safe_eyes_core
    except Exception:
        core = None
        _log_decision("init", error="no safe_eyes_core")
    message = plugin_config.get("message", message)
    button_label = plugin_config.get("button_label", button_label)
    _idle_gate = bool(plugin_config.get("idle_gate", _idle_gate))
    _idle_gate_seconds = int(plugin_config.get("idle_gate_seconds", _idle_gate_seconds))
    _idle_poll_seconds = int(plugin_config.get("idle_poll_seconds", _idle_poll_seconds))
    _log_decision("init", core=core is not None, msg=message[:30],
                  idle_gate=_idle_gate, idle_secs=_idle_gate_seconds)
    _last_countdown_reset()
    _setup_suspend_listener()
    _start_idle_monitor()


def _setup_suspend_listener():
    # SafeEyes' OWN logind PrepareForSleep handler (safeeyes.py:
    # handle_suspend_callback) calls core.start() on resume. That overrides the
    # core.stop() we issued to hold the Start-work gate: after suspend -> wake
    # -> relogin the scheduler silently resumes and the user can work without
    # pressing Start (and the X keyboard grab is dropped across the VT switch).
    # We subscribe to the SAME signal and, on resume while our dialog is up,
    # re-stop the core + re-grab the keyboard + re-raise the window so the gate
    # is re-imposed. Runs the work on the GTK main thread (core/window/Xlib
    # grab are all main-thread-affine).
    try:
        proxy = Gio.DBusProxy.new_for_bus_sync(
            Gio.BusType.SYSTEM,
            Gio.DBusProxyFlags.DO_NOT_LOAD_PROPERTIES,
            None,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            None,
        )

        def _on_signal(_proxy, _sender, signal, params):
            if signal != "PrepareForSleep":
                return
            (sleeping,) = params
            if not sleeping:
                GLib.idle_add(_on_resume_while_gating)

        proxy.connect("g-signal", _on_signal)
    except Exception as e:
        _log_decision("init", error="suspend_listener_failed: %s" % e)


def _on_resume_while_gating():
    # Only meaningful while our Start-work dialog is up (gate active).
    if _dialog is None:
        return False
    _log_decision("resume while dialog up; re-imposing gate")
    # SafeEyes' resume handler just called core.start(); undo it so the
    # scheduler stays paused until the user presses Start.
    if core is not None and getattr(core, "running", False):
        try:
            core.stop()
        except Exception as e:
            _log_decision("  re-stop failed", error=str(e))
    # Re-raise the fullscreen window + re-assert the keep-above hint (the lock
    # screen / other windows raised during suspend may have covered it).
    try:
        _dialog.present()
        _apply_keep_above_x11(_dialog)
    except Exception:
        pass
    return False


# --- Idle gate (away-from-PC detection) -------------------------------------
#
# A daemon thread polls every _idle_poll_seconds:
#   1. X11 screensaver idle (ms since last keyboard/mouse input) via python3-xlib
#      (no xprintidle dependency; a fresh Display per tick avoids sharing the
#      keyboard-grab thread's Display, which Xlib is not thread-safe for).
#      Wayland -> None -> no gating (the box is X11).
#   2. Only when idle >= threshold: run `pw-dump` once and look for a running
#      PipeWire Stream/Output/Audio node whose app/media name is a browser. If
#      one is playing, the user is watching a video -> do NOT gate.
#   3. If idle >= threshold and no browser media: marshal _do_idle_gate to the
#      GTK main thread (core.stop + show dialog must be main-thread-affine).
#
# Gates only fire while state == WAITING (active work) and core.running and no
# dialog is already up. The daemon (cockblockd) skips all enforcement while
# /tmp/cb_startwork_dialog exists, which _do_idle_gate sets, so it won't fight
# the gate (no -d/-e, no quit/relaunch, no break re-impose).

def _start_idle_monitor():
    global _idle_monitor_thread
    if not _idle_gate:
        return
    _idle_monitor_stop.clear()
    if _idle_monitor_thread and _idle_monitor_thread.is_alive():
        return
    _idle_monitor_thread = threading.Thread(target=_idle_monitor_loop, daemon=True)
    _idle_monitor_thread.start()
    _log_decision("idle_monitor started")


def _stop_idle_monitor():
    _idle_monitor_stop.set()
    t = _idle_monitor_thread
    if t and t.is_alive():
        t.join(timeout=2.0)


def _idle_monitor_loop():
    while not _idle_monitor_stop.is_set():
        if _idle_monitor_stop.wait(_idle_poll_seconds):
            break
        try:
            _idle_tick()
        except Exception as e:
            _log_decision("idle_tick err", error=str(e))


def _state_is_waiting():
    if context is None or State is None:
        return False
    try:
        return context.get("state") == State.WAITING
    except Exception:
        return False


def _idle_tick():
    if not _idle_gate or _dialog is not None or _idle_gated:
        return
    if not _state_is_waiting():
        return
    if core is None or not getattr(core, "running", False):
        return
    idle_ms = _x11_idle_ms()
    if idle_ms is None:
        return
    idle_s = idle_ms / 1000.0
    if idle_s < _idle_gate_seconds:
        return
    if _browser_audio_playing():
        _log_decision("idle_tick", idle_s=round(idle_s, 1), skip="browser_audio")
        return
    _log_decision("idle_gate trigger", idle_s=round(idle_s, 1))
    GLib.idle_add(_do_idle_gate)


def _x11_idle_ms():
    # Fresh Xlib connection per call (every _idle_poll_seconds). Opening a
    # Display is ~1-2ms; cheap at this cadence and avoids sharing the
    # keyboard-grab thread's Display (Xlib is not thread-safe per-Display).
    if os.environ.get("XDG_SESSION_TYPE", "") == "wayland":
        return None
    try:
        from Xlib import display as xlib_display
        d = xlib_display.Display()
        try:
            return d.screen().root.screensaver_query_info().idle
        finally:
            d.close()
    except Exception:
        return None


def _browser_audio_playing():
    # True if a browser-origin audio playback stream is running in PipeWire.
    # Fail-safe: on any error returns False (a missing audio stack does NOT
    # falsely prevent gating).
    try:
        out = subprocess.run(
            ["pw-dump"], capture_output=True, text=True, timeout=5
        ).stdout
    except Exception:
        return False
    try:
        nodes = json.loads(out) if out.strip() else []
    except json.JSONDecodeError:
        return False
    for o in nodes:
        if not isinstance(o, dict):
            continue
        if o.get("type") != "PipeWire:Interface:Node":
            continue
        info = o.get("info")
        if not isinstance(info, dict):
            continue
        if info.get("state") != "running":
            continue
        props = info.get("props") or {}
        if not isinstance(props, dict):
            continue
        if props.get("media.class", "") != "Stream/Output/Audio":
            continue
        app = (props.get("application.name") or "").lower()
        mname = (props.get("media.name") or "").lower()
        if any(tok in app or tok in mname for tok in _BROWSER_APP_TOKENS):
            return True
    return False


def _do_idle_gate():
    # Runs on the GTK main thread (queued via GLib.idle_add). Mirrors the
    # natural-break-end path in on_stop_break: set the sentinel the daemon
    # respects, stop the scheduler so __start_next_break does not queue the
    # next work interval, then show the same Start-work dialog.
    global _idle_gated, _idle_next_break_delay
    if _dialog is not None:
        _idle_gated = False
        return False
    if core is None:
        return False
    _idle_next_break_delay = None
    next_break = getattr(core, "scheduled_next_break_time", None)
    if next_break is not None:
        _idle_next_break_delay = max(
            1, round(next_break.timestamp() - time.time())
        )
    _log_decision(
        "idle_gate; pausing core + showing dialog",
        remaining=_idle_next_break_delay,
    )
    _idle_gated = True
    _set_flag()
    try:
        core.stop()
    except Exception as e:
        _log_decision("  core.stop failed (idle_gate)", error=str(e))
    _show_dialog()
    return False


def _last_countdown_reset():
    global _last_countdown_value, _last_countdown_time
    _last_countdown_value = None
    _last_countdown_time = 0.0


def _apply_keep_above_x11(win):
    # Mirror SafeEyes' __window_set_keep_above_x11: send a _NET_WM_STATE
    # ClientMessage (ADD) for ABOVE + STICKY so the WM keeps the fullscreen
    # dialog on top of all other windows and visible on all desktops. This
    # REPLACES the old keyboard grab, which blocked the screen locker from
    # grabbing the keyboard (so the idle lock never fired while the gate hung).
    # With only the keep-above hint, alt-tab can move input focus but the
    # dialog stays covering the screen, and the locker is free to engage.
    # No-op on Wayland (no _NET_WM_STATE; Wayland compositors ignore it).
    if GdkX11 is None:
        return
    try:
        from Xlib import X, display as xlib_display, protocol
    except Exception:
        return
    try:
        surface = win.get_surface()
    except Exception:
        return
    if surface is None or not isinstance(surface, GdkX11.X11Surface):
        return
    try:
        xid = GdkX11.X11Surface.get_xid(surface)
    except Exception:
        return
    try:
        d = xlib_display.Display()
        try:
            root = d.screen().root
            NET_WM_STATE = d.intern_atom("_NET_WM_STATE")
            NET_WM_STATE_ABOVE = d.intern_atom("_NET_WM_STATE_ABOVE")
            NET_WM_STATE_STICKY = d.intern_atom("_NET_WM_STATE_STICKY")
            root.send_event(
                protocol.event.ClientMessage(
                    window=xid,
                    client_type=NET_WM_STATE,
                    data=(32, [
                        1,                   # _NET_WM_STATE_ADD
                        NET_WM_STATE_ABOVE,
                        NET_WM_STATE_STICKY, # second property to also set
                        1,                   # source indication: app
                        0,
                    ]),
                ),
                event_mask=X.SubstructureRedirectMask | X.SubstructureNotifyMask,
            )
            d.sync()
            _log_decision("  keep_above set")
        finally:
            d.close()
    except Exception as e:
        _log_decision("  keep_above failed", error=str(e))


def _on_key_pressed(_controller, keyval, _keycode, _state):
    # Enter / Space / KP-Enter -> Start, regardless of which widget has focus.
    # Replaces the old X keyboard-grab consume loop. Works on X11 and Wayland.
    if keyval in (Gdk.KEY_Return, Gdk.KEY_KP_Enter, Gdk.KEY_space):
        _log_decision("  start key pressed (controller)")
        _on_start_clicked(None)
        return True
    return False


def on_start_break(break_obj):
    # Reset countdown tracking at the start of each break so stale values from
    # a previous break don't leak in.
    _last_countdown_reset()
    _log_decision("on_start_break", name=getattr(break_obj, "name", "?"),
                  long=getattr(break_obj, "is_long_break", lambda: False)())


def on_countdown(countdown, seconds):
    global _last_countdown_value, _last_countdown_time
    _last_countdown_value = countdown
    _last_countdown_time = time.time()


STARTWORK_FLAG = "/tmp/cb_startwork_dialog"


def _set_flag():
    try:
        with open(STARTWORK_FLAG, "w") as f:
            f.write("1")
    except Exception:
        pass


def _clear_flag():
    try:
        os.remove(STARTWORK_FLAG)
    except Exception:
        pass


def on_stop_break():
    global _dialog
    if core is None:
        _log_decision("on_stop_break", skip="no_core")
        return

    now = time.time()
    gap = now - _last_countdown_time if _last_countdown_time else None

    _log_decision("on_stop_break", last_val=_last_countdown_value,
                  gap=round(gap, 1) if gap is not None else None)

    # Suspend (or otherwise interrupted) => skip the dialog, continue work.
    if gap is None:
        _log_decision("  -> skip", why="no_countdown_seen")
        return
    if gap > 3.0:
        _log_decision("  -> skip", why="suspend_gap", gap=round(gap, 1))
        return
    if _last_countdown_value is not None and _last_countdown_value > 1:
        _log_decision("  -> skip", why="early_end", last_val=_last_countdown_value)
        return

    # Natural end: pause the scheduler so __start_next_break (about to run right
    # after this hook returns) does NOT queue the next work interval.
    _log_decision("  -> natural end; pausing core + showing dialog")
    _set_flag()
    try:
        core.stop()
    except Exception as e:
        _log_decision("  core.stop failed", error=str(e))

    _show_dialog()


def _show_dialog():
    global _dialog
    win = Gtk.Window()
    _dialog = win
    win.set_title("SafeEyes")
    # Mirror the break screen: no window chrome (decorated=False, deletable=False).
    try:
        win.set_decorated(False)
        win.set_deletable(False)
    except Exception:
        pass

    # Fullscreen covers the whole screen; present raises it to the top.
    try:
        win.fullscreen()
    except Exception:
        pass

    # Apply the black background to the WINDOW itself, not just an inner box.
    # A box only sizes to its content, so putting break_screen_root on a box
    # leaves the window's default grey visible around the button/text. On the
    # window node the black fill covers the whole fullscreen area.
    try:
        win.add_css_class("break_screen_root")
    except Exception:
        pass

    # Root container centers the message + button. No CSS class needed here --
    # the window already provides the black background.
    outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
    outer.set_halign(Gtk.Align.FILL)
    outer.set_valign(Gtk.Align.FILL)
    outer.set_hexpand(True)
    outer.set_vexpand(True)
    win.set_child(outer)

    # Inner centered box holds the message + button (so they're centered on the
    # black fill, while the black covers the whole screen).
    center = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=30)
    center.set_halign(Gtk.Align.CENTER)
    center.set_valign(Gtk.Align.CENTER)
    center.set_hexpand(True)
    center.set_vexpand(True)
    outer.append(center)

    # lbl_message -> 22pt white bold (matches the break screen's message).
    lbl = Gtk.Label(label=message)
    lbl.set_wrap(True)
    lbl.set_halign(Gtk.Align.CENTER)
    lbl.set_justify(Gtk.Justification.CENTER)
    lbl.set_margin_bottom(20)
    try:
        lbl.add_css_class("lbl_message")
    except Exception:
        pass
    center.append(lbl)

    # btn_skip style -> white outline, inverts on hover. Reused for the Start
    # button so it visually matches the break screen's buttons.
    btn = Gtk.Button(label=button_label)
    btn.set_halign(Gtk.Align.CENTER)
    btn.set_size_request(220, 60)
    try:
        btn.add_css_class("btn_skip")
    except Exception:
        pass
    btn.connect("clicked", _on_start_clicked)
    center.append(btn)

    # Closing the window without the button (WM close / destroy) proceeds to
    # start anyway -- never trap the user indefinitely.
    win.connect("close-request", _on_start_clicked)

    # Enter / Space -> Start (capture phase, fires regardless of focus). No X
    # keyboard grab: works on both X11 and Wayland and does NOT block the
    # screen locker from grabbing the keyboard.
    controller = Gtk.EventControllerKey()
    controller.connect("key_pressed", _on_key_pressed)
    controller.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
    win.add_controller(controller)

    win.present()
    # No widget holds focus, so pressing Space doesn't natively activate the
    # button (the EventControllerKey below handles Enter/Space -> Start). Mouse
    # clicks still work without focus. Mirrors SafeEyes' break_screen.py:232.
    try:
        win.set_focus(None)
    except Exception:
        pass
    # Keep the fullscreen dialog on top (EWMH _NET_WM_STATE_ABOVE + STICKY on
    # X11). Must run AFTER present() so the window is realized and has a native
    # surface to get the xid from. No-op on Wayland.
    _apply_keep_above_x11(win)
    _log_decision("  dialog shown")


def _on_start_clicked(_widget):
    global _dialog, _idle_gated, _idle_next_break_delay
    next_break_time = -1
    if _idle_gated and _idle_next_break_delay is not None:
        next_break_time = round(time.time()) + _idle_next_break_delay
    _log_decision(
        "start_pressed; resuming core",
        remaining=_idle_next_break_delay if _idle_gated else None,
    )
    _clear_flag()
    _idle_gated = False
    _idle_next_break_delay = None
    if _dialog is not None:
        d = _dialog
        _dialog = None
        try:
            d.destroy()
        except Exception:
            pass
    if core is not None and not core.running:
        try:
            core.start(next_break_time)
        except Exception as e:
            _log_decision("  core.start failed", error=str(e))


def on_exit():
    # SafeEyes is exiting: stop the idle-gate monitor thread.
    _stop_idle_monitor()
