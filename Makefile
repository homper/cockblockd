# Top-level Makefile for the cockblock stack.
#
# Drives the two subprojects (C daemon + BPF LSM) from one place:
#   make            # build everything (daemon + bpf object/loader)
#   make daemon     # build only the C daemon (src/cockblockd)
#   make bpf        # build only the BPF LSM program + loader
#   make clean      # remove all generated artifacts
#   make install       # install daemon + service + policies (needs root)
#   make install-armor  # also install AppArmor + immutable lockdown (ONE-WAY:
#                       #   chattr +i on the unit file -> `make install` can no
#                       #   longer overwrite cockblock.service afterward)
#   make install-bpf-boot # build+stage BPF + install a self-deleting firstboot
#                         #   that loads it on the first boot where bpf is active
#                         #   (run `make grub` first, then reboot)
#   make grub           # only add `bpf` to GRUB LSM cmdline (auto-reverts on
#                       #   fail during install; no manual revert exposed)
#   make check          # quick build smoke test (no install, no root)
#
# Build only - no root needed for `make` / `make check` / `make clean`.
# `make install` runs root-only steps and will `sudo` internally where it
# must, so run it as a normal user (it will prompt) or as root.

.PHONY: all daemon bpf clean install install-core install-armor install-bpf-boot grub check update install-update-service install-cap-drop install-session-capdrop

all: daemon bpf

daemon:
	$(MAKE) -C src all

bpf:
	@pkgs=""; \
	found=0; for c in clang clang-19 clang-18 clang-17 clang-16 clang-15 clang-14; do \
		command -v $$c >/dev/null 2>&1 && { found=1; break; }; done; \
	[ $$found -eq 1 ] || pkgs="$$pkgs clang"; \
	command -v bpftool >/dev/null 2>&1 || pkgs="$$pkgs bpftool"; \
	pkg-config --exists libbpf 2>/dev/null || pkgs="$$pkgs libbpf-dev"; \
	if [ -n "$$pkgs" ]; then \
		echo "Installing BPF toolchain (sudo apt):$$pkgs"; \
		sudo apt-get update -qq && sudo apt-get install -y $$pkgs \
			|| { echo "apt failed; run manually: sudo apt install$$pkgs"; exit 1; }; \
	fi
	$(MAKE) -C bpf all

clean:
	$(MAKE) -C src clean
	$(MAKE) -C bpf clean

install-armor: install-core
	@echo ">> AppArmor + immutable lockdown (ONE-WAY: after this, 'make install'"
	@echo "   can no longer overwrite cockblock.service because it is chattr +i)"
	@# If CAP_LINUX_IMMUTABLE has been dropped from the current session
	@# (hardening/install-cap-drop.sh / install-session-capdrop.sh, in effect
	@# after re-login/reboot), the kernel itself denies FS_IOC_SETFLAGS, so
	@# install.sh cannot clear +i on already-locked files to refresh them.
	@# Re-running install.sh in that state fails partway (EPERM on chattr -i /
	@# cockblock-updat clear). The correct re-run path is `make update`, which
	@# delegates the +i work to the cap-endowed cockblock-update systemd service.
	@if sudo capsh --decode=$$(awk '/^CapBnd:/{print $$2}' /proc/self/status) 2>/dev/null \
			| grep -qw cap_linux_immutable; then \
		:; \
	else \
		printf '\033[1;91mERROR:\033[0m CAP_LINUX_IMMUTABLE is dropped from this session\n' >&2; \
		printf '       (install-cap-drop / install-session-capdrop is in effect).\n' >&2; \
		printf '       `make install-armor` cannot clear +i on already-locked files\n' >&2; \
		printf '       to refresh them, so re-running it would fail with EPERM.\n' >&2; \
		printf '\n' >&2; \
		printf '       Run \033[1;94mmake update\033[0m instead — it delegates the +i work\n' >&2; \
		printf '       to the cap-endowed cockblock-update systemd service.\n' >&2; \
		exit 1; \
	fi
	sudo ./apparmor/install.sh

install-bpf-boot: bpf
	@echo ">> Staging BPF artifacts -> /opt/cockblock/bpf/"
	sudo mkdir -p /opt/cockblock/bpf
	sudo chmod 0755 /opt/cockblock/bpf 2>/dev/null || true
	sudo install -m0755 bpf/cockblock_loader       /opt/cockblock/bpf/cockblock_loader
	sudo install -m0644 bpf/cockblock_lsm.bpf.o    /opt/cockblock/bpf/cockblock_lsm.bpf.o
	sudo install -m0755 bpf/cockblock-updat        /opt/cockblock/bpf/cockblock-updat
	@echo ">> Making BPF artifacts immutable"
	sudo chattr +i /opt/cockblock/bpf/cockblock_loader /opt/cockblock/bpf/cockblock_lsm.bpf.o /opt/cockblock/bpf
	@echo ">> Installing persistent cockblock-bpf.service (NOT enabled yet)"
	sudo install -m0644 bpf/cockblock-bpf.service /etc/systemd/system/cockblock-bpf.service
	@echo ">> Installing self-deleting firstboot -> /var/lib/cockblock/cockblockd-bpf-boot"
	sudo install -d -m0700 /var/lib/cockblock
	sudo install -m0755 bpf/bpf-boot.sh /var/lib/cockblock/cockblockd-bpf-boot
	@echo ">> Installing + enabling cockblock-bpf-firstboot.service"
	sudo install -m0644 bpf/cockblock-bpf-firstboot.service /etc/systemd/system/cockblock-bpf-firstboot.service
	sudo systemctl daemon-reload
	sudo systemctl enable cockblock-bpf-firstboot.service
	@echo
	@echo "BPF staged. On the next boot where bpf is in the LSM list, the"
	@echo "firstboot will attach+pin the program, enable the persistent"
	@echo "cockblock-bpf.service, then delete itself."
	@printf '\033[1;91m[!]\033[0m \033[1;94mIf not already done: run `make grub`, then reboot.\033[0m\n'
	@printf '\n'

grub:
	sudo ./bpf/grub-bpf.sh enable

check: daemon
	@test -x src/cockblockd && echo "daemon: ok"

install-core: daemon
	@echo ">> Checking python3-plyvel (Vivaldi LeechBlock sync needs it)"
	@if ! python3 -c "import plyvel" 2>/dev/null; then \
		echo "Installing python3-plyvel (sudo apt)"; \
		sudo apt-get update -qq && sudo apt-get install -y python3-plyvel \
			|| { echo "apt failed; run manually: sudo apt install python3-plyvel"; exit 1; }; \
	fi
	@echo ">> Installing C daemon -> /opt/cockblock/cockblockd"
	sudo $(MAKE) -C src install
	@echo ">> Installing source assets -> /opt/cockblock/ (daemon CWD)"
	sudo install -m0644 policies.json /opt/cockblock/policies.json
	sudo install -m0644 policies-unblocked.json /opt/cockblock/policies-unblocked.json
	sudo install -m0644 userChrome.css /opt/cockblock/userChrome.css
	sudo install -m0644 userContent.css /opt/cockblock/userContent.css
	sudo install -m0644 vivaldi-policies.json /opt/cockblock/vivaldi-policies.json
	sudo install -m0644 vivaldi-policies-unblocked.json /opt/cockblock/vivaldi-policies-unblocked.json
	sudo install -m0755 cb_ff_activeblock.py /opt/cockblock/cb_ff_activeblock.py
	sudo install -m0755 cb_vv_leechblock.py /opt/cockblock/cb_vv_leechblock.py
	@echo ">> Installing policies.json -> /etc/firefox/policies/"
	sudo install -d -m0755 /etc/firefox/policies
	sudo install -m0644 policies.json /etc/firefox/policies/policies.json
	@echo ">> Installing vivaldi-policies.json -> /etc/vivaldi/policies/managed/"
	sudo install -d -m0755 /etc/vivaldi/policies/managed
	sudo install -m0644 vivaldi-policies.json /etc/vivaldi/policies/managed/cockblock.json
	@echo ">> Installing systemd units -> /etc/systemd/system/"
	# cockblock.service and cockblock.target are both skipped if already
	# immutable (+i), i.e. after install-armor locked them. install.sh also
	# installs cockblock.target itself if missing, but we install it here too so
	# `make install` alone yields a working enabled setup without install-armor.
	@if sudo lsattr /etc/systemd/system/cockblock.service 2>/dev/null | cut -c1-22 | grep -q 'i'; then \
		echo "SKIP: /etc/systemd/system/cockblock.service is immutable (+i, locked by install-armor)"; \
		echo "      cannot update via make install; leaving the existing unit in place."; \
	else \
		sudo install -m0644 cockblock.service /etc/systemd/system/cockblock.service; \
	fi
	@if sudo lsattr /etc/systemd/system/cockblock.target 2>/dev/null | cut -c1-22 | grep -q 'i'; then \
		echo "SKIP: /etc/systemd/system/cockblock.target is immutable (+i, locked by install-armor)"; \
	else \
		sudo install -m0644 cockblock.target /etc/systemd/system/cockblock.target; \
	fi
	@echo ">> Ensuring /etc/default/cockblock exists (AppArmor guard needs it)"
	echo '# cockblock env (unused by the C daemon; kept for apparmor guard)' \
		| sudo tee /etc/default/cockblock >/dev/null
	sudo systemctl daemon-reload
	# Enable order: enable the intermediate target first (creates the symlink in
	# multi-user.target.wants/), then enable the service (creates the symlink in
	# cockblock.target.wants/). After install-armor makes cockblock.target.wants/
	# immutable, `systemctl enable cockblock.service` cannot create the symlink,
	# so check the path directly and skip if already present. Both checks use the
	# real symlink paths (systemd only honors symlinks in .wants/).
	@if [ -e /etc/systemd/system/multi-user.target.wants/cockblock.target ]; then \
		echo "cockblock.target enable symlink already present; skipping"; \
	else \
		sudo systemctl enable cockblock.target; \
	fi
	@if [ -e /etc/systemd/system/cockblock.target.wants/cockblock.service ]; then \
		echo "cockblock.service enable symlink already present; skipping"; \
	else \
		sudo systemctl enable cockblock.service; \
	fi
	# NOTE: RefuseManualStop blocks `systemctl restart/stop`. `start` is allowed
	# (starts if down; no-op if up). The daemon has RuntimeMaxSec=30s +
	# Restart=always, so a freshly installed binary is picked up on the next
	# (<=30s) cycle automatically. Only start if not already active, so this
	# step never errors when the unit is up or failed.
	@systemctl is-active --quiet cockblock.service 2>/dev/null \
		|| sudo systemctl start cockblock.service
	@echo
	@echo "Daemon installed + (re)started."

install: install-core
	@printf '\033[1;36mOptional hardening (run in this order):\033[0m\n'
	@printf '  \033[1;36m1.\033[0m make install-armor          # AppArmor + immutable unit lockdown (ONE-WAY; no reboot)\n'
	@printf '  \033[1;36m2.\033[0m sudo bpf/install.sh         # BPF gate + +i /opt files/dir/updater (if 'bpf' already\n'
	@printf '      \033[1;36m\033[0m                           #   active in /sys/kernel/security/lsm; else: make grub,\n'
	@printf '      \033[1;36m\033[0m                           #   make install-bpf-boot, reboot)\n'
	@printf '  \033[1;36m3.\033[0m make install-update-service # cap-endowed cockblock-update service + setcap on updater\n'
	@printf '  \033[1;36m4.\033[0m make install-cap-drop       # drop CAP_LINUX_IMMUTABLE from user sessions (opt-in;\n'
	@printf '      \033[1;36m\033[0m                           #   re-login to take effect; also runs step 3)\n'
	@printf '  \033[1;36m5.\033[0m make install-session-capdrop # drop CAP_LINUX_IMMUTABLE from lightdm/getty SESSION bounding\n'
	@printf '      \033[1;36m\033[0m                           #   sets (the real fix; step 4 alone does NOT reach\n'
	@printf '      \033[1;36m\033[0m                           #   lightdm graphical sessions). Reboot to take effect.\n'
	@printf '  \033[1;36m•\033[0m sudo ./verify.sh             # one-shot check of the whole stack (run after re-login)\n'
	@if sudo grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then \
		printf '\033[1;91m[!]\033[0m \033[1;94mBPF already active in LSM list; safe to run make install-bpf-boot now.\033[0m\n'; \
	elif sudo grep -qE 'GRUB_CMDLINE_LINUX_DEFAULT=.*lsm=[^"]*bpf' /etc/default/grub 2>/dev/null; then \
		printf '\033[1;91m[!]\033[0m \033[1;94mBPF in GRUB but not active yet; run make install-bpf-boot, then reboot.\033[0m\n'; \
	else \
		printf '\033[1;91m[!]\033[0m \033[1;94mBPF not set up: run make grub, then make install-bpf-boot, then reboot.\033[0m\n'; \
	fi
	@printf '\n'
	@read -r -p "Install AppArmor lockdown now? [y/N] " aa; case "$$aa" in y|Y) $(MAKE) install-armor;; esac
	@read -r -p "Install BPF gate now (sudo bpf/install.sh; needs 'bpf' in LSM)? [y/N] " bb; case "$$bb" in y|Y) sudo ./bpf/install.sh;; esac
	@read -r -p "Install update-service + cap-drop now (re-login after)? [y/N] " cc; case "$$cc" in y|Y) $(MAKE) install-cap-drop;; esac
	@read -r -p "Install session-level cap-drop for lightdm/getty now (re-login after)? [y/N] " dd; case "$$dd" in y|Y) $(MAKE) install-session-capdrop;; esac

update:
	@echo ">> Updating cockblock (build + refresh protected artifacts)"
	sudo ./update.sh

install-update-service:
	@echo ">> Installing cap-endowed cockblock-update service + setcap on updater"
	sudo ./hardening/install-service.sh

# install-cap-drop depends on install-update-service: the cap-drop makes user
# shells lack CAP_LINUX_IMMUTABLE, so update.sh can only work via the
# cockblock-update system service (installed here). Order enforced by make.
install-cap-drop: install-update-service
	@echo ">> Installing capability-drop hardening (drops CAP_LINUX_IMMUTABLE from user sessions)"
	sudo ./hardening/install-cap-drop.sh

# install-session-capdrop is the REAL session cap-drop: user@.service (from
# install-cap-drop) does NOT reach lightdm graphical sessions (session-N.scope
# is a sibling of user@<uid>.service, not a child). This drops the cap from the
# bounding set of lightdm.service + getty@.service — the units that actually
# FORK login sessions — so the whole session tree (terminals, sudo, su) inherits
# a bounding set without CAP_LINUX_IMMUTABLE. Takes effect on next lightdm
# restart / reboot. Safe to run with or without install-cap-drop.
install-session-capdrop:
	@echo ">> Dropping CAP_LINUX_IMMUTABLE from lightdm/getty session bounding sets"
	sudo ./hardening/install-session-capdrop.sh
