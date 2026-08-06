# cockblockd

cockblockd is a self-enforcing daemon that keeps a Firefox self-blocking setup
intact. It re-enables the leechblock-ng extension if it has been disabled, keeps
`/etc/firefox/policies/policies.json` and the profile's `userChrome.css` in sync
with its own copies, and restarts Firefox when anything changed. It only
relaunches Firefox if it was already running. The daemon is a single C binary
(named `cockblockd` so its kernel `comm` is unique) run by a systemd service
that self-cycles every 30s and restarts forever.

Optional hardening layers make it hard to disable:
- AppArmor + immutable file lockdown (`make install-armor`) - blocks
  `systemctl disable`, edits and removal of the unit file.
- BPF LSM signal blocker (`make install-bpf-boot`) - denies SIGHUP/SIGINT/
  SIGQUIT/SIGKILL/SIGUSR1/SIGUSR2/SIGSTOP to the daemon even for root; SIGTERM
  stays allowed so the 30s restart loop works.

## SafeEyes layer (pomodoro + night block)

The daemon also enforces [SafeEyes](https://slgobinath.github.io/SafeEyes/)
(`sudo apt install safeeyes`) as a second blocking surface:

- **Auto-start + keep-alive**: if SafeEyes isn't running, the daemon starts it
  as the logged-in user; if the user kills it, it respawns within ~30s.
- **DAY (08:00-23:59)**: a strict pomodoro schedule - 30 min work, 5 min break,
  30 min long break after 4 cycles. Breaks are un-skippable/un-postponable and
  the tray disable is off. The only escape hatch is an active camera or mic
  (a call): the daemon runs `safeeyes -d` for the call's duration, then
  `safeeyes -e` ~1 min after it ends.
- **NIGHT (00:00-08:00)**: a single strict 8h break blanks the screen for the
  whole night. The camera/mic check is skipped at night - no call lifts it.

Source configs are `safeeyes.json` (day) and `safeeyes-night.json` (night),
seeded into `~/.config/safeeyes/safeeyes.json` and applied via a quit+relaunch
at each 00:00 / 08:00 boundary. AV detection uses `cb_av_check.py`
(`/proc/*/fd` -> `/dev/video*` for camera; `pw-dump` for mic, so PipeWire must
be running in the user session).

Note: SafeEyes itself is not SIGKILL-immune in v1 (only `cockblockd` is); it
is enforced by respawn, not by the BPF signal blocker.

## Install

Run from the project directory. `make install` builds and installs the daemon,
assets, policies and the systemd unit, then offers to install the two hardening
layers interactively.

1. Build and install the daemon:
   ```
   make install
   ```
   When prompted, answer `y` to optionally install AppArmor lockdown and/or
   stage the BPF firstboot.

2. (For BPF) enable the BPF LSM in GRUB and stage the auto-loading firstboot:
   ```
   make grub
   make install-bpf-boot
   ```
   `make grub` adds `bpf` to the kernel `lsm=` list (auto-reverts on failure,
   no manual revert path). It requires a reboot to activate.

3. Reboot. On the next boot, the BPF firstboot attaches + pins the signal
   blocker, enables the persistent `cockblock-bpf.service`, then deletes
   itself - no installer script left in any system path.

4. (Optional, one-way) lock the unit file with AppArmor + immutable. Do this
   last, because afterward `make install` can no longer overwrite
   `cockblock.service`:
   ```
   make install-armor
   ```

## BPF toolchain

The BPF layer needs the build toolchain. `make install` (or `make
install-bpf-boot`) auto-installs any missing packages via apt:

```
sudo apt install clang bpftool libbpf-dev linux-headers-$(uname -r) build-essential
```

`clang` is required (the BPF C is compiled to BPF bytecode; gcc cannot emit
that). A versioned `clang-NN` (e.g. `clang-18`) is accepted automatically - the
build falls back to it if the plain `clang` symlink is absent. `bpftool` and
`libbpf` (libbpf-dev) are also required; `linux-headers-$(uname -r)` and
`build-essential` are needed for the loader.

## Other targets

- `make` / `make all` - build daemon + BPF
- `make daemon` / `make bpf` - build one
- `make check` - smoke-test the daemon binary (no root, no install)
- `make clean` - remove all generated artifacts
- `make grub-revert` is intentionally NOT provided (would disable BPF).

## Local test (no service, no root)

```
make daemon
./src/cockblockd                 # real run
COCKBLOCK_DRY_RUN=1 ./src/cockblockd   # preview, no kills/writes
```
