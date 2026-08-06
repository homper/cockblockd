# Build the cockblock BPF LSM program + userspace loader + gated updater.
#
# Prereqs (install once, as root):
#   apt install clang llvm libbpf-dev bpftool linux-headers-$(uname -r) build-essential
#
# Then:  make            (generates vmlinux.h, builds .bpf.o, the loader, and
#                          the cockblock-updat +i setter/clearer)
#        make install    (root; copies artifacts to /opt/cockblock/bpf + unit)
#
# Requires CONFIG_BPF_LSM=y, CONFIG_DEBUG_INFO_BTF=y, and "bpf" in
# /sys/kernel/security/lsm. The install script checks these.

# Prefer a plain `clang`; fall back to a versioned clang-NN if only that is
# installed (the libbpf BPF workflow needs clang - gcc cannot emit BPF bytecode).
CLANG       ?= $(shell for c in clang clang-19 clang-18 clang-17 clang-16 clang-15 clang-14; do command -v $$c >/dev/null 2>&1 && { echo $$c; break; }; done)
LLVM_STRIP  ?= llvm-strip
BPFTOOL     ?= bpftool
CC          ?= cc
CFLAGS      ?= -O2 -g -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/ppc64le/powerpc/; s/mips64/mips/')
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS   := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz)

# Multiarch include dir for vmlinux-independent system headers if needed.
SYS_INC := /usr/include/$(shell uname -m)-linux-gnu

BPF_O    := cockblock_lsm.bpf.o
LOADER   := cockblock_loader
# Gated +i setter/clearer. The binary name MUST be exactly "cockblock-updat"
# (15 chars) so the kernel sets the task comm to "cockblock-updat", which the
# block_setflags_immutable BPF program matches to allow clearing +i.
UPDATER  := cockblock-updat

.PHONY: all clean install
all: vmlinux.h $(BPF_O) $(LOADER) $(UPDATER)

vmlinux.h:
	@echo "Generating vmlinux.h from /sys/kernel/btf/vmlinux ..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_O): cockblock_lsm.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I$(SYS_INC) -I. -I/usr/include \
		-Wall -Wno-unused-value -Wno-pointer-sign \
		-c cockblock_lsm.bpf.c -o $@
	-$(LLVM_STRIP) -g $@

$(LOADER): cockblock_loader.c
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) cockblock_loader.c -o $@ $(LIBBPF_LIBS)

# No libbpf dependency; plain C. The name is significant (see UPDATER note).
$(UPDATER): cockblock-updat.c
	$(CC) $(CFLAGS) cockblock-updat.c -o $@

install: all
	@echo "Run bpf/install.sh as root instead (it sets up the systemd unit)."
	@false

clean:
	rm -f $(BPF_O) $(LOADER) $(UPDATER) vmlinux.h
