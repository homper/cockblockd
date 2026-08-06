/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF LSM programs for cockblock protection.
 *
 * Program 1: block_kill_cockblock (lsm/task_kill)
 *   Deny SIGHUP/SIGINT/SIGQUIT/SIGKILL/SIGUSR1/SIGUSR2/SIGSTOP to the
 *   cockblock daemon (comm == "cockblockd"). SIGTERM is allowed so systemd's
 *   RuntimeMaxSec restart loop still works. This is the only userspace-accessible
 *   mechanism that truly blocks root SIGKILL (AppArmor cannot).
 *
 * Program 2: block_setflags_immutable (lsm/file_ioctl)
 *   Deny FS_IOC_SETFLAGS on files whose inode already has S_IMMUTABLE set,
 *   except the gated updater (comm == UPDATE_COMM). See the gate comment below.
 *
 * Both programs use bpf_probe_read_kernel / _str for field access (NOT
 * BPF_CORE_READ_* macros): on the Ubuntu 7.0 kernel the CO-RE relocations
 * fail silently, returning 0 bytes. Direct reads work correctly.
 * block_setflags_immutable uses bpf_get_current_comm() for the caller comm
 * (a standard helper, no CO-RE relocation) and bpf_probe_read_kernel for the
 * target inode fields.
 *
 * Requires CONFIG_BPF_LSM=y and "bpf" in /sys/kernel/security/lsm, plus BTF
 * (CONFIG_DEBUG_INFO_BTF=y).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/* vmlinux.h does not export errno/ioctl constants; define what we need. */
#define EPERM 1

/* FS_IOC_SETFLAGS: _IOW('f', 2, long) on x86_64 = 0x40086602. This is the ioctl
 * that chattr (and direct ioctl callers) use to set/clear file attributes. */
#define FS_IOC_SETFLAGS 0x40086602

/* IMPORTANT: there are TWO different "immutable" values and they are NOT the
 * same bit:
 *   FS_IMMUTABLE_FL = 0x10  -> the ON-DISK flag returned by FS_IOC_GETFLAGS
 *                              (this is what `lsattr` / ioctl GETFLAGS show).
 *   S_IMMUTABLE     = 0x08  -> the IN-MEMORY inode flag (inode->i_flags) that
 *                              the kernel sets when FS_IMMUTABLE_FL is applied.
 * This program reads inode->i_flags (in-memory), so it must check S_IMMUTABLE
 * (0x08), NOT FS_IMMUTABLE_FL (0x10). Using 0x10 here was the original bug: the
 * read returned 0x08 but the check masked 0x10, so immutable files were never
 * detected and every clear was allowed. (Confirmed via bpf_trace_printk: a +i
 * file reads ifl=0x8.) See include/linux/fs.h for the S_* defines. */
#define S_IMMUTABLE 0x00000008

/* The protected executable's comm (task_struct->comm, max 16 bytes, NUL-padded).
 * MUST be a fixed 16-byte array for bpf_strncmp's full 16-byte compare. */
static const char MATCH_COMM[16] = "cockblockd";

/* The dedicated updater's comm. When FS_IOC_SETFLAGS targets an IMMUTABLE
 * inode (i.e. someone is trying to CLEAR +i), we allow it only if the calling
 * task's comm matches this. The updater binary is named "cockblock-updat"
 * (exactly 15 chars) so the kernel sets its comm to this on exec. Keep <= 15
 * chars + NUL. Change this and you MUST also rename the updater binary (and
 * update.sh's reference) to match, then rebuild+reload. */
static const char UPDATE_COMM[16] = "cockblock-updat";

static const int blocked_sigs[] = {
	1,  /* SIGHUP   */
	2,  /* SIGINT   */
	3,  /* SIGQUIT  */
	9,  /* SIGKILL  */
	10, /* SIGUSR1  */
	12, /* SIGUSR2  */
	19, /* SIGSTOP  */
};

static __always_inline int is_blocked(int sig)
{
	for (int i = 0; i < (int)(sizeof(blocked_sigs) / sizeof(blocked_sigs[0])); i++) {
		if (sig == blocked_sigs[i])
			return 1;
	}
	return 0;
}

/* LSM hook task_kill(p, info, sig, cred): ALL four args must be listed so the
 * BPF_PROG ctx-slot mapping stays aligned. */
SEC("lsm/task_kill")
int BPF_PROG(block_kill_cockblock, struct task_struct *target,
	     struct kernel_siginfo *info, int sig, const struct cred *cred)
{
	if (!is_blocked(sig))
		return 0;

	/* Read target comm directly (bpf_probe_read_kernel_str, not CO-RE). */
	char comm[16] = {};
	bpf_probe_read_kernel_str(comm, sizeof(comm), &target->comm);

	if (bpf_strncmp(comm, sizeof(comm), MATCH_COMM) != 0)
		return 0;

	return -EPERM;
}

/* LSM hook file_ioctl(file, cmd, arg): deny FS_IOC_SETFLAGS on immutable
 * inodes (clearing +i), EXCEPT the gated updater (comm == UPDATE_COMM) which
 * may clear +i to refresh protected files in place. Setting +i on a
 * not-yet-immutable inode is allowed for everyone. */
SEC("lsm/file_ioctl")
int BPF_PROG(block_setflags_immutable, struct file *file,
	     unsigned int cmd, unsigned long arg)
{
	if (cmd != FS_IOC_SETFLAGS)
		return 0;

	/* Read the inode pointer from the file struct (direct read, not CO-RE). */
	struct inode *inode = NULL;
	bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode);
	if (!inode)
		return 0;

	/* Read the inode's in-memory i_flags. S_IMMUTABLE (0x08) is set when the
	 * file is +i (chattr +i / FS_IMMUTABLE_FL applied). */
	__u32 i_flags = 0;
	bpf_probe_read_kernel(&i_flags, sizeof(i_flags), &inode->i_flags);

	/* Not immutable yet -> allow (covers setting +i on a fresh file). */
	if (!(i_flags & S_IMMUTABLE))
		return 0;

	/* Immutable: this SETFLAGS would clear/change the flag. Allow ONLY the
	 * gated updater. bpf_get_current_comm fills the caller's comm directly. */
	char cur[16] = {};
	bpf_get_current_comm(cur, sizeof(cur));
	if (bpf_strncmp(cur, sizeof(cur), UPDATE_COMM) == 0)
		return 0;

	/* Everyone else (incl. a normal root shell) is denied. */
	return -EPERM;
}
