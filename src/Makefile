# Build + install the cockblock enforcement daemon (C port of main.py) and the
# cb-pause interactive client.
#
# The binary name `cockblockd` becomes the kernel `comm`, giving the BPF LSM
# signal blocker a precise match (instead of the broad "python3").
#
# Build:  make
# Install (as root):  make install
#
# Requires a C compiler only (no external libs). The daemon reads
# ./policies.json and ./userChrome.css from its working directory
# (set via WorkingDirectory= in cockblock.service).

CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra -pedantic
PREFIX  ?= /opt/cockblock
DAEMON  := cockblockd
CLIENT  := cb-pause
DDEST   := $(PREFIX)/$(DAEMON)
CDEST   := $(PREFIX)/$(CLIENT)
CTMPL   := $(PREFIX)/.cb-pause.tmpl
HASHDIR := /var/lib/cockblock
HASH    := $(HASHDIR)/cb_pause_hash

.PHONY: all install clean

all: $(DAEMON) $(CLIENT)

$(DAEMON): cockblockd.c
	$(CC) $(CFLAGS) -o $@ cockblockd.c

$(CLIENT): cb-pause.c
	$(CC) $(CFLAGS) -o $@ cb-pause.c

install: $(DAEMON) $(CLIENT)
	install -d -m0755 $(PREFIX)
	install -m0755 $(DAEMON) $(DDEST)
	# cb-pause: install a root-only template (the daemon recreates the runnable
	# copy from it and deletes it after each answered question) + the runnable
	# copy itself.
	install -m0644 $(CLIENT) $(CTMPL)
	install -m0755 $(CLIENT) $(CDEST)
	# Trust anchor: sha256 of the genuine template, root-only. The daemon
	# verifies the running cb-pause binary's hash against this before trusting
	# a pause answer.
	install -d -m0700 $(HASHDIR)
	sha256sum $(CTMPL) | awk '{print $$1}' > $(HASH)
	chmod 0600 $(HASH)
	@echo "installed $(DDEST)"
	@echo "installed $(CDEST) (+ template $(CTMPL), hash $(HASH))"
	@echo "update cockblock.service ExecStart to: $(DDEST)"

clean:
	rm -f $(DAEMON) $(CLIENT)
