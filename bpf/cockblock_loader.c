/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Userspace loader for the cockblock BPF LSM programs.
 *
 * Opens the .o, loads it, then attaches EVERY lsm/* program found in the
 * object and pins each bpf_link in bpffs. Once pinned, the links survive the
 * loader exiting - the pin holds the kernel reference, keeping the programs
 * attached across reboots (the boot systemd unit re-runs this loader).
 *
 * Pin paths are derived from the program name via a lookup table (see
 * pin_path_for()). Existing pins are skipped (idempotent re-runs).
 *
 * Run as root (needs CAP_BPF / CAP_SYS_ADMIN depending on kernel version).
 *
 *   ./cockblock_loader [bpf.o]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#ifndef BPF_OBJ_PATH
#define BPF_OBJ_PATH "/opt/cockblock/bpf/cockblock_lsm.bpf.o"
#endif

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list ap)
{
	if (level <= LIBBPF_INFO)
		return vfprintf(stderr, format, ap);
	return 0;
}

/* Map program names to bpffs pin paths. Existing names keep their paths for
 * backward compatibility; new programs get /sys/fs/bpf/cockblock_<name>. */
static const char *pin_path_for(const char *prog_name)
{
	if (strcmp(prog_name, "block_kill_cockblock") == 0)
		return "/sys/fs/bpf/cockblock_lsm";
	if (strcmp(prog_name, "block_setflags_immutable") == 0)
		return "/sys/fs/bpf/cockblock_setflags";
	/* Fallback for future programs. */
	static char buf[256];
	snprintf(buf, sizeof(buf), "/sys/fs/bpf/cockblock_%s", prog_name);
	return buf;
}

int main(int argc, char **argv)
{
	const char *obj_path = (argc > 1) ? argv[1] : BPF_OBJ_PATH;
	int err, attached = 0;

	libbpf_set_print(libbpf_print_fn);

	struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "open_file(%s) failed: %s\n", obj_path, strerror(-err));
		return 1;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load failed: %s\n", strerror(-err));
		return 1;
	}

	/* Iterate every program in the object. Attach + pin each that isn't
	 * already pinned (skip idempotently on re-runs). */
	struct bpf_program *prog;
	bpf_object__for_each_program(prog, obj) {
		const char *name = bpf_program__name(prog);
		const char *pin = pin_path_for(name);

		if (access(pin, F_OK) == 0) {
			printf("cockblock: %s already pinned at %s; skipping\n", name, pin);
			continue;
		}

		struct bpf_link *link = bpf_program__attach_lsm(prog);
		err = libbpf_get_error(link);
		if (err) {
			fprintf(stderr, "attach_lsm(%s) failed: %s\n", name, strerror(-err));
			continue;
		}

		err = bpf_link__pin(link, pin);
		if (err) {
			fprintf(stderr, "pin(%s, %s) failed: %s\n", name, pin, strerror(-err));
			bpf_link__destroy(link);
			continue;
		}

		printf("cockblock: %s attached and pinned at %s\n", name, pin);
		bpf_link__disconnect(link);
		bpf_link__destroy(link);
		attached++;
	}

	bpf_object__close(obj);

	if (attached == 0) {
		printf("cockblock: all programs already pinned; nothing to do.\n");
	}
	return 0;
}
