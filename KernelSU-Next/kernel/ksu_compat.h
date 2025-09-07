/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KernelSU compatibility header for older kernels (like 5.4)
 * Provides missing symbols for KernelSU patches.
 */

#ifndef _KSU_COMPAT_H
#define _KSU_COMPAT_H

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/syscalls.h>
#include <linux/version.h>

/*
 * Fallback for kernels that don't have path_umount().
 * Use ksys_umount(), which is exported.
 */
static inline int path_umount(struct path *path, int flags)
{
    char *pathname;
    int err;

    /* Convert struct path to a string path */
    pathname = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!pathname)
        return -ENOMEM;

    err = d_path(path, pathname, PATH_MAX);
    if (IS_ERR(pathname)) {
        kfree(pathname);
        return PTR_ERR(pathname);
    }

    /* Use the syscall helper */
    err = ksys_umount(pathname, flags);

    kfree(pathname);
    return err;
}

/*
 * Seccomp filter_count exists only in >= 5.9 kernels.
 * On 5.4 we stub it out.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,9,0)
#define ksu_reset_seccomp_filter() do {} while (0)
#else
#define ksu_reset_seccomp_filter() \
    atomic_set(&current->seccomp.filter_count, 0)
#endif

#endif /* _KSU_COMPAT_H */