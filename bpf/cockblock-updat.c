/* SPDX-License-Identifier: GPL-2.0 */
/*
 * cockblock-updat — the gated +i manager.
 *
 * Binary name is "cockblock-updat" (exactly 15 chars), so the kernel sets the
 * task comm to "cockblock-updat" on exec. The block_setflags_immutable BPF LSM
 * program allows FS_IOC_SETFLAGS on IMMUTABLE inodes (i.e. clearing +i) ONLY
 * when the caller's comm matches UPDATE_COMM — i.e. only this program. So only
 * this binary can clear +i on protected files; a normal root shell cannot
 * (chattr -i is denied by AppArmor; raw ioctl is denied by the BPF gate).
 *
 * Modes:
 *   cockblock-updat set    <file>...          set +i (FS_IMMUTABLE_FL).
 *                         Setting +i is UNGATED by the BPF program (target not
 *                         yet immutable), so any caller can set +i; this mode is
 *                         used by install.sh for the initial lockdown.
 *   cockblock-updat clear  <file>...          clear +i (GATED — only this comm).
 *                         Used by install.sh re-runs and diagnostics.
 *   cockblock-updat update <dst> <src>        ATOMIC refresh: clear +i on dst
 *                         (if set), copy src->dst, re-apply +i — all in one
 *                         process. The file is never left non-immutable in a
 *                         window a shell could exploit. Used by update.sh.
 *
 * Uses the raw FS_IOC_GETFLAGS / FS_IOC_SETFLAGS ioctls directly (not the
 * /usr/bin/chattr binary), so it is unaffected by the AppArmor chattr profile.
 *
 * Raise-the-bar, not absolute: comm is forgeable by root (rename any binary to
 * cockblock-updat). The planned cap-drop (pam_cap + file capabilities) makes
 * this moot: a normal shell then lacks CAP_LINUX_IMMUTABLE so the KERNEL denies
 * +i changes entirely, and only this cap-endowed binary can change them.
 *
 * Exit: 0 if all ops succeeded, 1 if any failed.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>

static int get_flags(const char *path, unsigned long *out)
{
	int fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
		return -1;
	}
	if (ioctl(fd, FS_IOC_GETFLAGS, out) < 0) {
		fprintf(stderr, "GETFLAGS(%s): %s\n", path, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int set_flags(const char *path, unsigned long flags)
{
	int fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
		return -1;
	}
	if (ioctl(fd, FS_IOC_SETFLAGS, &flags) < 0) {
		fprintf(stderr, "SETFLAGS(%s): %s\n", path, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

/* Atomic-replace variant of the copy, used when a direct O_TRUNC open on dst
 * fails with ETXTBSY — i.e. dst is a RUNNING executable (the live cockblockd
 * daemon being refreshed in place). Linux forbids opening an executing binary's
 * text inode for writing, so we cannot truncate it. Instead we copy src to a
 * temp file in dst's directory and rename() over dst: the running process
 * retains the old (now +i-cleared) inode; the path atomically switches to the
 * fresh inode, which the caller then re-+is. There is never a window in which
 * the path is missing (unlike unlink+create), so a failure leaves dst intact. */
static int copy_file_rename(const char *src, const char *dst)
{
	const char *slash = strrchr(dst, '/');
	char *dir = slash ? strndup(dst, (size_t)(slash - dst)) : strdup(".");
	if (!dir) {
		fprintf(stderr, "oom\n");
		return -1;
	}
	size_t tlen = strlen(dir) + 24;
	char *tmp = malloc(tlen);
	if (!tmp) {
		free(dir);
		fprintf(stderr, "oom\n");
		return -1;
	}
	snprintf(tmp, tlen, "%s/.cbupd-XXXXXX", dir);
	free(dir);

	int out = mkstemp(tmp);
	if (out < 0) {
		fprintf(stderr, "mkstemp(%s): %s\n", tmp, strerror(errno));
		free(tmp);
		return -1;
	}

	int in = open(src, O_RDONLY);
	if (in < 0) {
		fprintf(stderr, "open(%s): %s\n", src, strerror(errno));
		close(out);
		unlink(tmp);
		free(tmp);
		return -1;
	}

	char buf[65536];
	ssize_t n;
	int rc = 0;
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		ssize_t off = 0;
		while (off < n) {
			ssize_t w = write(out, buf + off, (size_t)(n - off));
			if (w < 0) {
				fprintf(stderr, "write(%s): %s\n", tmp, strerror(errno));
				rc = -1;
				break;
			}
			off += w;
		}
		if (rc < 0)
			break;
	}
	if (n < 0) {
		fprintf(stderr, "read(%s): %s\n", src, strerror(errno));
		rc = -1;
	}
	close(in);

	struct stat sst;
	if (stat(src, &sst) == 0) {
		if (fchmod(out, sst.st_mode & 07777) < 0)
			fprintf(stderr, "fchmod(%s): %s (continuing)\n", tmp, strerror(errno));
	}
	if (fsync(out) < 0)
		fprintf(stderr, "fsync(%s): %s (continuing)\n", tmp, strerror(errno));
	close(out);

	if (rc == 0 && rename(tmp, dst) < 0) {
		fprintf(stderr, "rename(%s -> %s): %s\n", tmp, dst, strerror(errno));
		rc = -1;
	}
	if (rc < 0)
		unlink(tmp);
	free(tmp);
	return rc;
}

/* Copy src -> dst, then make dst's mode match src's (so a 0755 binary stays
 * 0755, a 0644 object stays 0644). Truncates the existing dst inode (preserving
 * its mode) or creates it with src's mode if missing. If dst is a running
 * executable, the O_TRUNC open fails with ETXTBSY and we fall back to an atomic
 * temp+rename replace (see copy_file_rename). */
static int copy_file(const char *src, const char *dst)
{
	int in = open(src, O_RDONLY);
	if (in < 0) {
		fprintf(stderr, "open(%s): %s\n", src, strerror(errno));
		return -1;
	}
	int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (out < 0) {
		if (errno == ETXTBSY) {
			close(in);
			return copy_file_rename(src, dst);
		}
		fprintf(stderr, "open(%s): %s\n", dst, strerror(errno));
		close(in);
		return -1;
	}
	char buf[65536];
	ssize_t n;
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		ssize_t off = 0;
		while (off < n) {
			ssize_t w = write(out, buf + off, n - off);
			if (w < 0) {
				fprintf(stderr, "write(%s): %s\n", dst, strerror(errno));
				close(in);
				close(out);
				return -1;
			}
			off += w;
		}
	}
	if (n < 0) {
		fprintf(stderr, "read(%s): %s\n", src, strerror(errno));
		close(in);
		close(out);
		return -1;
	}
	close(in);
	close(out);

	struct stat st;
	if (stat(src, &st) == 0) {
		if (chmod(dst, st.st_mode & 07777) < 0)
			fprintf(stderr, "chmod(%s): %s (continuing)\n", dst, strerror(errno));
	}
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
		"Usage:\n"
		"  cockblock-updat set    <file>...           # set +i\n"
		"  cockblock-updat clear  <file>...           # clear +i (gated)\n"
		"  cockblock-updat update <dst> <src>         # atomic: clear+copy+re-+i\n");
	exit(2);
}

int main(int argc, char **argv)
{
	if (argc < 3)
		usage();

	const char *mode = argv[1];

	if (strcmp(mode, "set") == 0 || strcmp(mode, "clear") == 0) {
		unsigned long fl = FS_IMMUTABLE_FL;
		int ret = 0;
		for (int i = 2; i < argc; i++) {
			unsigned long cur = 0;
			if (get_flags(argv[i], &cur) < 0) {
				ret = 1;
				continue;
			}
			unsigned long want = (mode[0] == 's') ? (cur | fl) : (cur & ~fl);
			if (want == cur) {
				printf("%s: already %simmutable\n", argv[i],
				       (mode[0] == 's') ? "" : "non-");
				continue;
			}
			if (set_flags(argv[i], want) < 0)
				ret = 1;
			else
				printf("%s: %simmutable\n", argv[i],
				       (mode[0] == 's') ? "" : "non-");
		}
		return ret ? 1 : 0;
	}

	if (strcmp(mode, "update") == 0) {
		if (argc != 4)
			usage();
		const char *dst = argv[2];
		const char *src = argv[3];
		unsigned long fl = FS_IMMUTABLE_FL;

		/* 1. clear +i on dst if it is immutable (gated — only this comm) */
		unsigned long cur = 0;
		if (get_flags(dst, &cur) < 0)
			return 1;
		if (cur & fl) {
			if (set_flags(dst, cur & ~fl) < 0)
				return 1;
		}
		/* 2. overwrite content */
		if (copy_file(src, dst) < 0) {
			/* try to restore +i so we don't leave dst mutable on failure */
			set_flags(dst, cur | fl);
			return 1;
		}
		/* 3. re-apply +i (ungated: dst no longer immutable) */
		if (set_flags(dst, (cur & ~fl) | fl) < 0)
			return 1;
		printf("%s: updated from %s (+i re-applied)\n", dst, src);
		return 0;
	}

	usage();
	return 2;
}
