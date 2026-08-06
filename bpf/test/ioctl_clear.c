/* Direct FS_IOC_SETFLAGS ioctl helper — bypasses the /usr/bin/chattr binary.
 *
 * Used to verify the block_setflags_immutable BPF LSM program: it should deny
 * clearing the immutable flag via raw ioctl even for root, closing the hole
 * that the AppArmor chattr profile cannot (that profile confines only the
 * chattr *binary*, not the ioctl itself).
 *
 *   ioctl_clear <file>
 *
 * Reads current flags, prints them, then attempts to CLEAR the immutable flag
 * (FS_IMMUTABLE_FL) via FS_IOC_SETFLAGS. Prints the errno result. With the BPF
 * program loaded and the file already +i, this MUST fail with EPERM (1).
 * Without the program (or on a non-immutable file), it succeeds (exit 0).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* Match the kernel's <linux/fs.h> ioctl/flag constants exactly. */
#define FS_IOC_GETFLAGS   _IOR('f', 1, long)   /* 0x80086601 */
#define FS_IOC_SETFLAGS   _IOW('f', 2, long)   /* 0x40086602 */
#define FS_IMMUTABLE_FL   0x00000010

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <file>\n", argv[0]);
		return 2;
	}

	int fd = open(argv[1], O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		fprintf(stderr, "open(%s): %s\n", argv[1], strerror(errno));
		return 2;
	}

	long flags = 0;
	if (ioctl(fd, FS_IOC_GETFLAGS, &flags) < 0) {
		fprintf(stderr, "GETFLAGS(%s): %s\n", argv[1], strerror(errno));
		close(fd);
		return 2;
	}
	printf("current flags = 0x%lx%s\n", flags,
	       (flags & FS_IMMUTABLE_FL) ? " (IMMUTABLE set)" : "");

	/* Attempt to CLEAR the immutable flag via direct ioctl. */
	long new_flags = flags & ~FS_IMMUTABLE_FL;
	printf("attempting SETFLAGS = 0x%lx (immutable cleared) ...\n", new_flags);

	if (ioctl(fd, FS_IOC_SETFLAGS, &new_flags) < 0) {
		int e = errno;
		printf("SETFLAGS DENIED: %s (errno=%d)\n", strerror(e), e);
		close(fd);
		return 1;
	}

	printf("SETFLAGS OK — immutable flag cleared (BPF did NOT block).\n");
	close(fd);
	return 0;
}
