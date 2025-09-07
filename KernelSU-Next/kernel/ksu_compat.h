/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KernelSU compatibility header for older kernels (like 5.4)
 * Provides missing symbols for KernelSU patches.
 */

#ifndef _KSU_COMPAT_H
#define _KSU_COMPAT_H

#include <linux/fs.h>

/*
 * On kernels < 5.9, path_umount() does not exist.
 * Instead, do_umount() is used internally.
 */
static inline int path_umount(struct path *path, int flags)
{
    return do_umount(path, flags);
}

#endif /* _KSU_COMPAT_H */