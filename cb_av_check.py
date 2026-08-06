#!/usr/bin/env python3
# cb_av_check.py - detect whether a camera or microphone is currently in use.
# Used by cockblockd to pause SafeEyes during calls (day mode only).
#
#   cb_av_check.py        -> prints a single token line:
#                             CAMERA  - a /dev/video* device is open by a process
#                             MIC     - a PipeWire capture stream is running
#                             IDLE    - neither (or detection unavailable)
#
# Camera: scan /proc/*/fd/* readlinks for any resolving to /dev/video*.
#         cockblockd runs as root, so it sees every process's fds directly
#         without needing this helper; but the helper is self-contained and
#         runnable as the user too (it will then only see the user's own fds,
#         which is the common case for a personal call).
#
# Mic: run `pw-dump` and look for any PipeWire node whose media.class is
#      Stream/Input/Audio or Stream/Input/Video and whose state is "running".
#      (Audio/Source / Video/Source are device nodes, always present - NOT a
#      client capture. pactl is not installed on this box, so pw-dump is used.)
#      If pw-dump is missing or PipeWire is down, returns no mic (fail-safe:
#      a missing audio stack does not falsely pause SafeEyes).
import glob
import json
import os
import subprocess
import sys

CAPTURE_CLASSES = {"Stream/Input/Audio", "Stream/Input/Video"}


def camera_in_use():
    for link in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            target = os.readlink(link)
        except OSError:
            continue
        if target.startswith("/dev/video"):
            return True
    return False


def mic_in_use():
    try:
        out = subprocess.run(
            ["pw-dump"], capture_output=True, text=True, timeout=5
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
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
        props = info.get("props") or {}
        if not isinstance(props, dict):
            continue
        mc = props.get("media.class", "")
        if mc in CAPTURE_CLASSES and info.get("state") == "running":
            return True
    return False


def main():
    if camera_in_use():
        print("CAMERA")
    elif mic_in_use():
        print("MIC")
    else:
        print("IDLE")


if __name__ == "__main__":
    main()
