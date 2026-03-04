#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/types.h>

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#endif

#include "kernel_umount.h"
#include "klog.h" // IWYU pragma: keep
#include "allowlist.h"
#include "selinux/selinux.h"
#include "feature.h"
#include "ksud.h"
#include "manager.h"

static bool ksu_kernel_umount_enabled = true;

#ifdef CONFIG_KSU_SUSFS
bool susfs_is_boot_completed_triggered = false;

/* Define SUSFS SID variables */
u32 susfs_zygote_sid = 0;
u32 susfs_ksu_sid = 0;
u32 susfs_kernel_sid = 0;

/* Export symbols for SUSFS */
EXPORT_SYMBOL(susfs_zygote_sid);
EXPORT_SYMBOL(susfs_ksu_sid);
EXPORT_SYMBOL(susfs_kernel_sid);

bool susfs_is_current_ksu_domain(void)
{
	return is_ksu_domain();
}
EXPORT_SYMBOL(susfs_is_current_ksu_domain);

bool susfs_is_sid_equal(void *security, u32 sid)
{
	return ksu_sid_equal(security, sid);
}
EXPORT_SYMBOL(susfs_is_sid_equal);

extern bool susfs_is_mnt_devname_ksu(struct path *path);
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
extern void susfs_run_sus_path_loop(uid_t uid);
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
extern bool susfs_is_log_enabled __read_mostly;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
static bool susfs_is_umount_for_zygote_system_process_enabled = false;
static bool susfs_is_umount_for_zygote_iso_service_enabled = false;
extern bool susfs_hide_sus_mnts_for_all_procs;
extern void susfs_reorder_mnt_id(void);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
extern bool susfs_is_auto_add_sus_bind_mount_enabled;
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
extern bool susfs_is_auto_add_sus_ksu_default_mount_enabled;
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
extern bool susfs_is_auto_add_try_umount_for_bind_mount_enabled;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_SU
bool susfs_is_sus_su_ready = false;
int susfs_sus_su_working_mode = 0;
bool susfs_is_sus_su_hooks_enabled __read_mostly = true;
bool ksu_devpts_hook = false;

EXPORT_SYMBOL(susfs_is_sus_su_ready);
EXPORT_SYMBOL(susfs_sus_su_working_mode);
EXPORT_SYMBOL(susfs_is_sus_su_hooks_enabled);
EXPORT_SYMBOL(ksu_devpts_hook);

bool susfs_is_allow_su(void)
{
	return ksu_is_allow_uid_for_current(current_uid().val);
}
EXPORT_SYMBOL(susfs_is_allow_su);

void ksu_susfs_enable_sus_su(void)
{
	susfs_sus_su_working_mode = 2; /* SUS_SU_WITH_HOOKS */
	susfs_is_sus_su_hooks_enabled = false;
	susfs_is_sus_su_ready = true;
	ksu_devpts_hook = true;
	pr_info("KernelSU: sus_su enabled\n");
}
EXPORT_SYMBOL(ksu_susfs_enable_sus_su);

void ksu_susfs_disable_sus_su(void)
{
	susfs_sus_su_working_mode = 0; /* SUS_SU_DISABLED */
	susfs_is_sus_su_hooks_enabled = true;
	susfs_is_sus_su_ready = false;
	ksu_devpts_hook = false;
	pr_info("KernelSU: sus_su disabled\n");
}
EXPORT_SYMBOL(ksu_susfs_disable_sus_su);

int ksu_handle_devpts(struct inode *inode)
{
	if (!ksu_devpts_hook)
		return 0;
	/* Handle devpts for sus_su */
	return 0;
}
EXPORT_SYMBOL(ksu_handle_devpts);
#endif

void susfs_on_post_fs_data(void) {
	struct path path;
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	if (!kern_path(DATA_ADB_UMOUNT_FOR_ZYGOTE_SYSTEM_PROCESS, 0, &path)) {
		susfs_is_umount_for_zygote_system_process_enabled = true;
		path_put(&path);
	}
	pr_info("susfs_is_umount_for_zygote_system_process_enabled: %d\n", susfs_is_umount_for_zygote_system_process_enabled);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
	if (!kern_path(DATA_ADB_NO_AUTO_ADD_SUS_BIND_MOUNT, 0, &path)) {
		susfs_is_auto_add_sus_bind_mount_enabled = false;
		path_put(&path);
	}
	pr_info("susfs_is_auto_add_sus_bind_mount_enabled: %d\n", susfs_is_auto_add_sus_bind_mount_enabled);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
	if (!kern_path(DATA_ADB_NO_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT, 0, &path)) {
		susfs_is_auto_add_sus_ksu_default_mount_enabled = false;
		path_put(&path);
	}
	pr_info("susfs_is_auto_add_sus_ksu_default_mount_enabled: %d\n", susfs_is_auto_add_sus_ksu_default_mount_enabled);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
	if (!kern_path(DATA_ADB_NO_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT, 0, &path)) {
		susfs_is_auto_add_try_umount_for_bind_mount_enabled = false;
		path_put(&path);
	}
	pr_info("susfs_is_auto_add_try_umount_for_bind_mount_enabled: %d\n", susfs_is_auto_add_try_umount_for_bind_mount_enabled);
#endif
}

void susfs_on_boot_completed(void) {
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	susfs_is_boot_completed_triggered = true;
#endif
}

void susfs_set_umount_for_zygote_iso_service(bool enabled) {
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	susfs_is_umount_for_zygote_iso_service_enabled = enabled;
	pr_info("susfs_is_umount_for_zygote_iso_service_enabled: %d\n", enabled);
#endif
}

static inline bool is_some_system_uid(uid_t uid)
{
	return (uid >= 1000 && uid < 10000);
}

static inline bool is_zygote_isolated_service_uid(uid_t uid)
{
	return ((uid >= 90000 && uid < 100000) || (uid >= 1090000 && uid < 1100000));
}

static inline bool is_zygote_normal_app_uid(uid_t uid)
{
	return ((uid >= 10000 && uid < 19999) || (uid >= 1010000 && uid < 1019999));
}
#endif // CONFIG_KSU_SUSFS

static int kernel_umount_feature_get(u64 *value)
{
	*value = ksu_kernel_umount_enabled ? 1 : 0;
	return 0;
}

static int kernel_umount_feature_set(u64 value)
{
	bool enable = value != 0;
	ksu_kernel_umount_enabled = enable;
	pr_info("kernel_umount: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler kernel_umount_handler = {
	.feature_id = KSU_FEATURE_KERNEL_UMOUNT,
	.name = "kernel_umount",
	.get_handler = kernel_umount_feature_get,
	.set_handler = kernel_umount_feature_set,
};

extern int path_umount(struct path *path, int flags);

static void ksu_umount_mnt(struct path *path, int flags)
{
	int err = path_umount(path, flags);
	if (err) {
		pr_info("umount %s failed: %d\n", path->dentry->d_iname, err);
	}
}

#ifdef CONFIG_KSU_SUSFS
static bool should_umount(struct path *path)
{
	if (!path) {
		return false;
	}

	if (current->nsproxy->mnt_ns == init_nsproxy.mnt_ns) {
		pr_info("ignore global mnt namespace process: %d\n",
			current_uid().val);
		return false;
	}

	return susfs_is_mnt_devname_ksu(path);
}
#endif

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
void try_umount(const char *mnt, bool check_mnt, int flags, uid_t uid)
{
	struct path path;
	int err = kern_path(mnt, 0, &path);
	if (err) {
		return;
	}

	if (path.dentry != path.mnt->mnt_root) {
		path_put(&path);
		return;
	}

	if (check_mnt && !should_umount(&path)) {
		path_put(&path);
		return;
	}

#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	if (susfs_is_log_enabled) {
		pr_info("susfs: umounting '%s' for uid: %d\n", mnt, uid);
	}
#endif

	ksu_umount_mnt(&path, flags);
}

static void susfs_try_umount_all(uid_t uid) {
	susfs_try_umount(uid);
	/* For Legacy KSU only */
	try_umount("/odm", true, 0, uid);
	try_umount("/system", true, 0, uid);
	try_umount("/vendor", true, 0, uid);
	try_umount("/product", true, 0, uid);
	try_umount("/system_ext", true, 0, uid);
	try_umount("/data/adb/modules", false, MNT_DETACH, uid);
	/* For both Legacy KSU and Magic Mount KSU */
	try_umount("/debug_ramdisk", true, MNT_DETACH, uid);
	try_umount("/sbin", false, MNT_DETACH, uid);

	// try umount hosts file
	try_umount("/system/etc/hosts", false, MNT_DETACH, uid);

	// try umount lsposed dex2oat bins
	try_umount("/apex/com.android.art/bin/dex2oat64", false, MNT_DETACH, uid);
	try_umount("/apex/com.android.art/bin/dex2oat32", false, MNT_DETACH, uid);
}
#else
static void try_umount(const char *mnt, int flags)
{
	struct path path;
	int err = kern_path(mnt, 0, &path);
	if (err) {
		return;
	}

	if (path.dentry != path.mnt->mnt_root) {
		path_put(&path);
		return;
	}

	ksu_umount_mnt(&path, flags);
}
#endif // CONFIG_KSU_SUSFS_TRY_UMOUNT

struct umount_tw {
	struct callback_head cb;
	const struct cred *old_cred;
};

static void umount_tw_func(struct callback_head *cb)
{
	struct umount_tw *tw = container_of(cb, struct umount_tw, cb);
	const struct cred *saved = NULL;
	if (tw->old_cred) {
		saved = override_creds(tw->old_cred);
	}

	struct mount_entry *entry;
	down_read(&mount_list_lock);
	list_for_each_entry(entry, &mount_list, list) {
		pr_info("%s: unmounting: %s flags 0x%x\n", __func__, entry->umountable, entry->flags);
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
		try_umount(entry->umountable, false, entry->flags, current_uid().val);
#else
		try_umount(entry->umountable, entry->flags);
#endif
	}
	up_read(&mount_list_lock);

	if (saved)
		revert_creds(saved);

	if (tw->old_cred)
		put_cred(tw->old_cred);

	kfree(tw);
}

#ifdef CONFIG_KSU_SUSFS
int ksu_handle_umount(uid_t old_uid, uid_t new_uid)
{
	// if there isn't any module mounted, just ignore it!
	if (!ksu_module_mounted) {
		return 0;
	}

	if (!ksu_kernel_umount_enabled) {
		return 0;
	}

	// We only interest in process spawned by zygote
	if (!susfs_is_sid_equal(get_current_cred()->security, susfs_zygote_sid)) {
		return 0;
	}

	// Check if spawned process is isolated service first, and force to do umount if so
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	if (is_zygote_isolated_service_uid(new_uid) && susfs_is_umount_for_zygote_iso_service_enabled) {
		goto do_umount;
	}
#endif

	// Since ksu manager app uid is excluded in allow_list_arr, so ksu_uid_should_umount(manager_uid)
	// will always return true, that's why we need to explicitly check if new_uid belongs to ksu manager
	if (ksu_is_manager_uid_valid() &&
		(new_uid % 1000000 == ksu_get_manager_uid())) // % 1000000 in case it is private space uid
	{
		return 0;
	}

	// Check if spawned process is normal user app and needs to be umounted
	if (likely(is_zygote_normal_app_uid(new_uid) && ksu_uid_should_umount(new_uid))) {
		goto do_umount;
	}

	// Lastly, Check if spawned process is some system process and needs to be umounted
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	if (unlikely(is_some_system_uid(new_uid) && susfs_is_umount_for_zygote_system_process_enabled)) {
		goto do_umount;
	}
#endif

	return 0;

do_umount:
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	// susfs come first, and lastly umount by ksu, make sure umount in reversed order
	susfs_try_umount_all(new_uid);
#else
	try_umount("/odm", true, 0);
	try_umount("/system", true, 0);
	try_umount("/vendor", true, 0);
	try_umount("/product", true, 0);
	try_umount("/system_ext", true, 0);
	try_umount("/data/adb/modules", false, MNT_DETACH);
	try_umount("/debug_ramdisk", false, MNT_DETACH);
	try_umount("/sbin", false, MNT_DETACH);
	try_umount("/system/etc/hosts", false, MNT_DETACH);
	try_umount("/apex/com.android.art/bin/dex2oat64", false, MNT_DETACH);
	try_umount("/apex/com.android.art/bin/dex2oat32", false, MNT_DETACH);
#endif

	get_task_struct(current);

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	// We can reorder the mnt_id now after all sus mounts are umounted
	susfs_reorder_mnt_id();
#endif

	susfs_set_current_proc_umounted();

	put_task_struct(current);

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	susfs_run_sus_path_loop(new_uid);
#endif
	return 0;
}
#else
int ksu_handle_umount(uid_t old_uid, uid_t new_uid)
{
	struct umount_tw *tw;

	// if there isn't any module mounted, just ignore it!
	if (!ksu_module_mounted) {
		return 0;
	}

	if (!ksu_kernel_umount_enabled) {
		return 0;
	}

	// There are 5 scenarios:
	// 1. Normal app: zygote -> appuid
	// 2. Isolated process forked from zygote: zygote -> isolated_process
	// 3. App zygote forked from zygote: zygote -> appuid
	// 4. Isolated process forked from app zygote: appuid -> isolated_process (already handled by 3)
	// 5. Isolated process forked from webview zygote (no need to handle, app cannot run custom code)
	if (!is_appuid(new_uid) && !is_isolated_process(new_uid)) {
		return 0;
	}

	if (!ksu_uid_should_umount(new_uid) && !is_isolated_process(new_uid)) {
		return 0;
	}

	// check old process's selinux context, if it is not zygote, ignore it!
	// because some su apps may setuid to untrusted_app but they are in global mount namespace
	// when we umount for such process, that is a disaster!
	// also handle case 4 and 5
	bool is_zygote_child = is_zygote(get_current_cred());
	if (!is_zygote_child) {
		pr_info("handle umount ignore non zygote child: %d\n", current->pid);
		return 0;
	}
	// umount the target mnt
	pr_info("handle umount for uid: %d, pid: %d\n", new_uid, current->pid);

	tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw)
		return 0;

	tw->old_cred = get_current_cred();
	tw->cb.func = umount_tw_func;

	int err = task_work_add(current, &tw->cb, TWA_RESUME);
	if (err) {
		if (tw->old_cred) {
			put_cred(tw->old_cred);
		}
		kfree(tw);
		pr_warn("unmount add task_work failed\n");
	}

	return 0;
}
#endif // CONFIG_KSU_SUSFS

void ksu_kernel_umount_init(void)
{
	if (ksu_register_feature_handler(&kernel_umount_handler)) {
		pr_err("Failed to register kernel_umount feature handler\n");
	}
}

void ksu_kernel_umount_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_KERNEL_UMOUNT);
}
