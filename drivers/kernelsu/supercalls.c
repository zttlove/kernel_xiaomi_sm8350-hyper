#include <linux/anon_inodes.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/spinlock.h>

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#endif

#include "supercalls.h"
#include "arch.h"
#include "allowlist.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "ksud.h"
#include "kernel_umount.h"
#include "manager.h"
#include "selinux/selinux.h"
#include "objsec.h"
#include "file_wrapper.h"
#include "syscall_hook_manager.h"

// Permission check functions
bool only_manager(void)
{
	return is_manager();
}

bool only_root(void)
{
	return current_uid().val == 0;
}

bool manager_or_root(void)
{
	return current_uid().val == 0 || is_manager();
}

bool always_allow(void)
{
	return true; // No permission check
}

bool allowed_for_su(void)
{
	uid_t uid = current_uid().val;
	bool is_mgr = is_manager();
	bool is_allowed_uid = ksu_is_allow_uid_for_current(uid);
	bool is_allowed = is_mgr || is_allowed_uid;
	pr_info("allowed_for_su: uid=%d manager_uid=%d is_manager=%d is_allowed_uid=%d result=%d\n",
		uid, ksu_get_manager_uid(), is_mgr, is_allowed_uid, is_allowed);
	return is_allowed;
}

static int do_grant_root(void __user *arg)
{
	// we already check uid above on allowed_for_su()
	escape_with_root_profile();
	return 0;
}

static int do_get_info(void __user *arg)
{
	struct ksu_get_info_cmd cmd = {.version = KERNEL_SU_VERSION, .flags = 0};

#ifdef MODULE
	cmd.flags |= 0x1;
#endif

	if (is_manager()) {
		cmd.flags |= 0x2;
	}
	cmd.features = KSU_FEATURE_MAX;

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_version: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_report_event(void __user *arg)
{
	struct ksu_report_event_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	switch (cmd.event) {
	case EVENT_POST_FS_DATA: {
		static bool post_fs_data_lock = false;
		if (!post_fs_data_lock) {
			post_fs_data_lock = true;
			pr_info("post-fs-data triggered\n");
#ifdef CONFIG_KSU_SUSFS
			susfs_on_post_fs_data();
#endif
			on_post_fs_data();
		}
		break;
	}
	case EVENT_BOOT_COMPLETED: {
		static bool boot_complete_lock = false;
		if (!boot_complete_lock) {
			boot_complete_lock = true;
			pr_info("boot_complete triggered\n");
#ifdef CONFIG_KSU_SUSFS
			susfs_on_boot_completed();
#endif
			on_boot_completed();
		}
		break;
	}
	case EVENT_MODULE_MOUNTED: {
		pr_info("module mounted!\n");
		on_module_mounted();
		break;
	}
	default:
		break;
	}

	return 0;
}

static int do_set_sepolicy(void __user *arg)
{
	struct ksu_set_sepolicy_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	return handle_sepolicy(cmd.cmd, (void __user *)cmd.arg);
}

static int do_check_safemode(void __user *arg)
{
	struct ksu_check_safemode_cmd cmd;

	cmd.in_safe_mode = ksu_is_safe_mode();

	if (cmd.in_safe_mode) {
		pr_warn("safemode enabled!\n");
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("check_safemode: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_allow_list(void __user *arg)
{
	struct ksu_get_allow_list_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	bool success = ksu_get_allow_list((int *)cmd.uids, (int *)&cmd.count, true);

	if (!success) {
		return -EFAULT;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_allow_list: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_deny_list(void __user *arg)
{
	struct ksu_get_allow_list_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	bool success = ksu_get_allow_list((int *)cmd.uids, (int *)&cmd.count, false);

	if (!success) {
		return -EFAULT;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_deny_list: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_uid_granted_root(void __user *arg)
{
	struct ksu_uid_granted_root_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	cmd.granted = ksu_is_allow_uid_for_current(cmd.uid);

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("uid_granted_root: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_uid_should_umount(void __user *arg)
{
	struct ksu_uid_should_umount_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	cmd.should_umount = ksu_uid_should_umount(cmd.uid);

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("uid_should_umount: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_manager_uid(void __user *arg)
{
	struct ksu_get_manager_uid_cmd cmd;

	cmd.uid = ksu_get_manager_uid();

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_manager_uid: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_app_profile(void __user *arg)
{
	struct ksu_get_app_profile_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("get_app_profile: copy_from_user failed\n");
		return -EFAULT;
	}

	if (!ksu_get_app_profile(&cmd.profile)) {
		return -ENOENT;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_app_profile: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_set_app_profile(void __user *arg)
{
	struct ksu_set_app_profile_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("set_app_profile: copy_from_user failed\n");
		return -EFAULT;
	}

	if (!ksu_set_app_profile(&cmd.profile, true)) {
		return -EFAULT;
	}

	return 0;
}

static int do_get_feature(void __user *arg)
{
	struct ksu_get_feature_cmd cmd;
	bool supported;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("get_feature: copy_from_user failed\n");
		return -EFAULT;
	}


	ret = ksu_get_feature(cmd.feature_id, &cmd.value, &supported);
	cmd.supported = supported ? 1 : 0;

	if (ret && supported) {
		pr_err("get_feature: failed for feature %u: %d\n", cmd.feature_id, ret);
		return ret;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_feature: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_set_feature(void __user *arg)
{
	struct ksu_set_feature_cmd cmd;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("set_feature: copy_from_user failed\n");
		return -EFAULT;
	}


	ret = ksu_set_feature(cmd.feature_id, cmd.value);
	if (ret) {
		pr_err("set_feature: failed for feature %u: %d\n", cmd.feature_id, ret);
		return ret;
	}

	return 0;
}

static int do_get_wrapper_fd(void __user *arg) {
	if (!ksu_file_sid) {
		return -EINVAL;
	}

	struct ksu_get_wrapper_fd_cmd cmd;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("get_wrapper_fd: copy_from_user failed\n");
		return -EFAULT;
	}

	struct file* f = fget(cmd.fd);
	if (!f) {
		return -EBADF;
	}

	struct ksu_file_wrapper *data = ksu_create_file_wrapper(f);
	if (data == NULL) {
		ret = -ENOMEM;
		goto put_orig_file;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define getfd_secure anon_inode_create_getfd
#else
#define getfd_secure anon_inode_getfd_secure
#endif
	ret = getfd_secure("[ksu_fdwrapper]", &data->ops, data, f->f_flags, NULL);
	if (ret < 0) {
		pr_err("ksu_fdwrapper: getfd failed: %d\n", ret);
		goto put_wrapper_data;
	}
	struct file* pf = fget(ret);

	struct inode* wrapper_inode = file_inode(pf);
	// copy original inode mode
    wrapper_inode->i_mode = file_inode(f)->i_mode;
	struct inode_security_struct *sec = selinux_inode(wrapper_inode);
	if (sec) {
		sec->sid = ksu_file_sid;
	}

	fput(pf);
	goto put_orig_file;
put_wrapper_data:
	ksu_delete_file_wrapper(data);
put_orig_file:
	fput(f);

	return ret;
}

static int do_manage_mark(void __user *arg)
{
	struct ksu_manage_mark_cmd cmd;
	int ret = 0;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("manage_mark: copy_from_user failed\n");
		return -EFAULT;
	}

	switch (cmd.operation) {
	case KSU_MARK_GET: {
		// Get task mark status
		ret = ksu_get_task_mark(cmd.pid);
		if (ret < 0) {
			pr_err("manage_mark: get failed for pid %d: %d\n", cmd.pid, ret);
			return ret;
		}
		cmd.result = (u32)ret;
		break;
	}
	case KSU_MARK_MARK: {
		if (cmd.pid == 0) {
			ksu_mark_all_process();
		} else {
			ret = ksu_set_task_mark(cmd.pid, true);
			if (ret < 0) {
				pr_err("manage_mark: set_mark failed for pid %d: %d\n", cmd.pid,
					ret);
				return ret;
			}
		}
		break;
	}
	case KSU_MARK_UNMARK: {
		if (cmd.pid == 0) {
			ksu_unmark_all_process();
		} else {
			ret = ksu_set_task_mark(cmd.pid, false);
			if (ret < 0) {
				pr_err("manage_mark: set_unmark failed for pid %d: %d\n",
					cmd.pid, ret);
				return ret;
			}
		}
		break;
	}
	case KSU_MARK_REFRESH: {
		ksu_mark_running_process();
		break;
	}
	default: {
		pr_err("manage_mark: invalid operation %u\n", cmd.operation);
		return -EINVAL;
	}
	}
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("manage_mark: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_hook_mode(void __user *arg)
{
	struct ksu_get_hook_mode_cmd cmd = {0};

	strscpy(cmd.mode, "Kprobes", sizeof(cmd.mode));

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_hook_mode: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_version_tag(void __user *arg)
{
	struct ksu_get_version_tag_cmd cmd = {0};

	strscpy(cmd.tag, KERNEL_SU_VERSION_TAG, sizeof(cmd.tag));

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_version_tag: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_nuke_ext4_sysfs(void __user *arg)
{
    struct ksu_nuke_ext4_sysfs_cmd cmd;
    char mnt[256];
    long ret;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;

    if (!cmd.arg)
        return -EINVAL;

    memset(mnt, 0, sizeof(mnt));

    ret = strncpy_from_user(mnt, cmd.arg, sizeof(mnt));
    if (ret < 0) {
        pr_err("nuke ext4 copy mnt failed: %ld\\n", ret);
        return -EFAULT;   // 或者 return ret;
    }

    if (ret == sizeof(mnt)) {
        pr_err("nuke ext4 mnt path too long\\n");
        return -ENAMETOOLONG;
    }

    return nuke_ext4_sysfs(mnt);
}

struct list_head mount_list = LIST_HEAD_INIT(mount_list);
DECLARE_RWSEM(mount_list_lock);

static int add_try_umount(void __user *arg)
{
    struct mount_entry *new_entry, *entry, *tmp;
    struct ksu_add_try_umount_cmd cmd;
    char buf[256] = {0};

    if (copy_from_user(&cmd, arg, sizeof cmd))
        return -EFAULT;

    switch (cmd.mode) {
        case KSU_UMOUNT_WIPE: {
            struct mount_entry *entry, *tmp;
		down_write(&mount_list_lock);
		list_for_each_entry_safe(entry, tmp, &mount_list, list) {
			list_del(&entry->list);
			kfree(entry->umountable);
			kfree(entry);
		}
		up_write(&mount_list_lock);

            return 0;
        }

        case KSU_UMOUNT_ADD: {
            long len = strncpy_from_user(buf, (const char __user *)cmd.arg, 256);
            if (len <= 0)
                return -EFAULT;    
            
            buf[sizeof(buf) - 1] = '\0';

            new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
            if (!new_entry)
                return -ENOMEM;

            new_entry->umountable = kstrdup(buf, GFP_KERNEL);
            if (!new_entry->umountable) {
                kfree(new_entry);
                return -1;
            }

            down_write(&mount_list_lock);

		// disallow dupes
		list_for_each_entry(entry, &mount_list, list) {
			if (!strcmp(entry->umountable, buf)) {
				up_write(&mount_list_lock);
				kfree(new_entry->umountable);
				kfree(new_entry);
				return -EEXIST;
			}
		}

            // now check flags and add
            // this also serves as a null check
            if (cmd.flags)
                new_entry->flags = cmd.flags;
            else
                new_entry->flags = 0;

		list_add(&new_entry->list, &mount_list);
		up_write(&mount_list_lock);

		return 0;
        }

        // this is just strcmp'd wipe anyway
        case KSU_UMOUNT_DEL: {
            long len = strncpy_from_user(buf, (const char __user *)cmd.arg, sizeof(buf) - 1);
            if (len <= 0)
                return -EFAULT;
            
            buf[sizeof(buf) - 1] = '\0';

		down_write(&mount_list_lock);
		list_for_each_entry_safe(entry, tmp, &mount_list, list) {
			if (!strcmp(entry->umountable, buf)) {
				list_del(&entry->list);
				kfree(entry->umountable);
				kfree(entry);
			}
		}
		up_write(&mount_list_lock);
            
            return 0;
        }
        
        default: {
            pr_err("cmd_add_try_umount: invalid operation %u\n", cmd.mode);
            return -EINVAL;
        }

    } // switch(cmd.mode)
    
    return 0;
}

#ifdef CONFIG_KSU_SUSFS
// SUSFS command handlers
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
static int do_susfs_add_sus_path(void __user *arg)
{
	return susfs_add_sus_path((struct st_susfs_sus_path __user*)arg);
}

static int do_susfs_add_sus_path_loop(void __user *arg)
{
	return susfs_add_sus_path_loop((struct st_susfs_sus_path __user*)arg);
}

static int do_susfs_set_android_data_root_path(void __user *arg)
{
	return susfs_set_i_state_on_external_dir((char __user*)arg, CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH);
}

static int do_susfs_set_sdcard_root_path(void __user *arg)
{
	return susfs_set_i_state_on_external_dir((char __user*)arg, CMD_SUSFS_SET_SDCARD_ROOT_PATH);
}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
extern bool susfs_hide_sus_mnts_for_all_procs;

static int do_susfs_add_sus_mount(void __user *arg)
{
	return susfs_add_sus_mount((struct st_susfs_sus_mount __user*)arg);
}

static int do_susfs_hide_sus_mnts_for_all_procs(void __user *arg)
{
	unsigned long val;
	if (copy_from_user(&val, arg, sizeof(val)))
		return -EFAULT;
	if (val != 0 && val != 1)
		return -EINVAL;
	susfs_hide_sus_mnts_for_all_procs = val;
	return 0;
}

static int do_susfs_umount_for_zygote_iso_service(void __user *arg)
{
	unsigned long val;
	if (copy_from_user(&val, arg, sizeof(val)))
		return -EFAULT;
	if (val != 0 && val != 1)
		return -EINVAL;
	susfs_set_umount_for_zygote_iso_service(val);
	return 0;
}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
static int do_susfs_add_sus_kstat(void __user *arg)
{
	return susfs_add_sus_kstat((struct st_susfs_sus_kstat __user*)arg);
}

static int do_susfs_update_sus_kstat(void __user *arg)
{
	return susfs_update_sus_kstat((struct st_susfs_sus_kstat __user*)arg);
}
#endif

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
static int do_susfs_add_try_umount(void __user *arg)
{
	return susfs_add_try_umount((struct st_susfs_try_umount __user*)arg);
}
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
static int do_susfs_set_uname(void __user *arg)
{
	return susfs_set_uname((struct st_susfs_uname __user*)arg);
}
#endif

#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
static int do_susfs_enable_log(void __user *arg)
{
	unsigned char val;
	if (get_user(val, (unsigned char __user *)arg))
		return -EFAULT;
	if (val != 0 && val != 1)
		return -EINVAL;
	susfs_set_log(val);
	return 0;
}
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
static int do_susfs_set_cmdline_or_bootconfig(void __user *arg)
{
	return susfs_set_cmdline_or_bootconfig((char __user*)arg);
}
#endif

#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
static int do_susfs_add_open_redirect(void __user *arg)
{
	return susfs_add_open_redirect((struct st_susfs_open_redirect __user*)arg);
}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_SU
static int do_susfs_sus_su(void __user *arg)
{
	return susfs_sus_su((struct st_sus_su __user*)arg);
}

static int do_susfs_is_sus_su_ready(void __user *arg)
{
	extern bool susfs_is_sus_su_ready;
	if (copy_to_user(arg, &susfs_is_sus_su_ready, sizeof(susfs_is_sus_su_ready)))
		return -EFAULT;
	return 0;
}

static int do_susfs_show_sus_su_working_mode(void __user *arg)
{
	int mode = susfs_get_sus_su_working_mode();
	if (copy_to_user(arg, &mode, sizeof(mode)))
		return -EFAULT;
	return 0;
}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_MAP
static int do_susfs_add_sus_map(void __user *arg)
{
	return susfs_add_sus_map((struct st_susfs_sus_map __user*)arg);
}
#endif

static int do_susfs_show_version(void __user *arg)
{
	char *version = SUSFS_VERSION;
	if (copy_to_user(arg, version, strlen(version) + 1))
		return -EFAULT;
	return 0;
}

static int do_susfs_show_variant(void __user *arg)
{
	char *variant = SUSFS_VARIANT;
	if (copy_to_user(arg, variant, strlen(variant) + 1))
		return -EFAULT;
	return 0;
}

static int do_susfs_show_enabled_features(void __user *arg)
{
	return susfs_get_enabled_features((char __user*)arg, 1024);
}

static int do_susfs_enable_avc_log_spoofing(void __user *arg)
{
	unsigned long val;
	if (copy_from_user(&val, arg, sizeof(val)))
		return -EFAULT;
	if (val != 0 && val != 1)
		return -EINVAL;
	susfs_set_avc_log_spoofing(val);
	return 0;
}
#endif // CONFIG_KSU_SUSFS

// IOCTL handlers mapping table
static const struct ksu_ioctl_cmd_map ksu_ioctl_handlers[] = {
	{ .cmd = KSU_IOCTL_GRANT_ROOT, .name = "GRANT_ROOT", .handler = do_grant_root, .perm_check = allowed_for_su },
	{ .cmd = KSU_IOCTL_GET_INFO, .name = "GET_INFO", .handler = do_get_info, .perm_check = always_allow },
	{ .cmd = KSU_IOCTL_REPORT_EVENT, .name = "REPORT_EVENT", .handler = do_report_event, .perm_check = only_root },
	{ .cmd = KSU_IOCTL_SET_SEPOLICY, .name = "SET_SEPOLICY", .handler = do_set_sepolicy, .perm_check = only_root },
	{ .cmd = KSU_IOCTL_CHECK_SAFEMODE, .name = "CHECK_SAFEMODE", .handler = do_check_safemode, .perm_check = always_allow },
	{ .cmd = KSU_IOCTL_GET_ALLOW_LIST, .name = "GET_ALLOW_LIST", .handler = do_get_allow_list, .perm_check = manager_or_root },
	{ .cmd = KSU_IOCTL_GET_DENY_LIST, .name = "GET_DENY_LIST", .handler = do_get_deny_list, .perm_check = manager_or_root },
	{ .cmd = KSU_IOCTL_UID_GRANTED_ROOT, .name = "UID_GRANTED_ROOT", .handler = do_uid_granted_root, .perm_check = manager_or_root },
	{ .cmd = KSU_IOCTL_UID_SHOULD_UMOUNT, .name = "UID_SHOULD_UMOUNT", .handler = do_uid_should_umount, .perm_check = manager_or_root },
	{ .cmd = KSU_IOCTL_GET_MANAGER_UID, .name = "GET_MANAGER_UID", .handler = do_get_manager_uid, .perm_check = manager_or_root },
	{ .cmd = KSU_IOCTL_GET_APP_PROFILE, .name = "GET_APP_PROFILE", .handler = do_get_app_profile, .perm_check = only_manager },
	{ .cmd = KSU_IOCTL_SET_APP_PROFILE, .name = "SET_APP_PROFILE", .handler = do_set_app_profile, .perm_check = only_manager },
	{ .cmd = KSU_IOCTL_GET_FEATURE, .name = "GET_FEATURE", .handler = do_get_feature, .perm_check = manager_or_root },
	{ .cmd = KSU_IOCTL_SET_FEATURE, .name = "SET_FEATURE", .handler = do_set_feature, .perm_check = manager_or_root },
	{ .cmd = KSU_IOCTL_GET_WRAPPER_FD, .name = "GET_WRAPPER_FD", .handler = do_get_wrapper_fd, .perm_check = manager_or_root },
	{ .cmd = KSU_IOCTL_MANAGE_MARK, .name = "MANAGE_MARK", .handler = do_manage_mark, .perm_check = manager_or_root },
	{ .cmd = KSU_IOCTL_NUKE_EXT4_SYSFS, .name = "NUKE_EXT4_SYSFS", .handler = do_nuke_ext4_sysfs, .perm_check = manager_or_root },
	{ .cmd = KSU_IOCTL_ADD_TRY_UMOUNT, .name = "ADD_TRY_UMOUNT", .handler = add_try_umount, .perm_check = manager_or_root },
	{ .cmd = KSU_IOCTL_GET_HOOK_MODE, .name = "GET_HOOK_MODE", .handler = do_get_hook_mode, .perm_check = manager_or_root },
	{ .cmd = KSU_IOCTL_GET_VERSION_TAG, .name = "GET_VERSION_TAG", .handler = do_get_version_tag, .perm_check = manager_or_root },
#ifdef CONFIG_KSU_SUSFS
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	{ .cmd = KSU_IOCTL_SUSFS_ADD_SUS_PATH, .name = "SUSFS_ADD_SUS_PATH", .handler = do_susfs_add_sus_path, .perm_check = only_root },
	{ .cmd = KSU_IOCTL_SUSFS_ADD_SUS_PATH_LOOP, .name = "SUSFS_ADD_SUS_PATH_LOOP", .handler = do_susfs_add_sus_path_loop, .perm_check = only_root },
	{ .cmd = KSU_IOCTL_SUSFS_SET_ANDROID_DATA_ROOT_PATH, .name = "SUSFS_SET_ANDROID_DATA_ROOT_PATH", .handler = do_susfs_set_android_data_root_path, .perm_check = only_root },
	{ .cmd = KSU_IOCTL_SUSFS_SET_SDCARD_ROOT_PATH, .name = "SUSFS_SET_SDCARD_ROOT_PATH", .handler = do_susfs_set_sdcard_root_path, .perm_check = only_root },
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	{ .cmd = KSU_IOCTL_SUSFS_ADD_SUS_MOUNT, .name = "SUSFS_ADD_SUS_MOUNT", .handler = do_susfs_add_sus_mount, .perm_check = only_root },
	{ .cmd = KSU_IOCTL_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS, .name = "SUSFS_HIDE_SUS_MNTS", .handler = do_susfs_hide_sus_mnts_for_all_procs, .perm_check = only_root },
	{ .cmd = KSU_IOCTL_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE, .name = "SUSFS_UMOUNT_ISO_SVC", .handler = do_susfs_umount_for_zygote_iso_service, .perm_check = only_root },
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	{ .cmd = KSU_IOCTL_SUSFS_ADD_SUS_KSTAT, .name = "SUSFS_ADD_SUS_KSTAT", .handler = do_susfs_add_sus_kstat, .perm_check = only_root },
	{ .cmd = KSU_IOCTL_SUSFS_UPDATE_SUS_KSTAT, .name = "SUSFS_UPDATE_SUS_KSTAT", .handler = do_susfs_update_sus_kstat, .perm_check = only_root },
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	{ .cmd = KSU_IOCTL_SUSFS_ADD_TRY_UMOUNT, .name = "SUSFS_ADD_TRY_UMOUNT", .handler = do_susfs_add_try_umount, .perm_check = only_root },
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	{ .cmd = KSU_IOCTL_SUSFS_SET_UNAME, .name = "SUSFS_SET_UNAME", .handler = do_susfs_set_uname, .perm_check = only_root },
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	{ .cmd = KSU_IOCTL_SUSFS_ENABLE_LOG, .name = "SUSFS_ENABLE_LOG", .handler = do_susfs_enable_log, .perm_check = only_root },
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	{ .cmd = KSU_IOCTL_SUSFS_SET_CMDLINE_OR_BOOTCONFIG, .name = "SUSFS_SET_CMDLINE", .handler = do_susfs_set_cmdline_or_bootconfig, .perm_check = only_root },
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	{ .cmd = KSU_IOCTL_SUSFS_ADD_OPEN_REDIRECT, .name = "SUSFS_ADD_OPEN_REDIRECT", .handler = do_susfs_add_open_redirect, .perm_check = only_root },
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_SU
	{ .cmd = KSU_IOCTL_SUSFS_SUS_SU, .name = "SUSFS_SUS_SU", .handler = do_susfs_sus_su, .perm_check = only_root },
	{ .cmd = KSU_IOCTL_SUSFS_IS_SUS_SU_READY, .name = "SUSFS_IS_SUS_SU_READY", .handler = do_susfs_is_sus_su_ready, .perm_check = only_root },
	{ .cmd = KSU_IOCTL_SUSFS_SHOW_SUS_SU_WORKING_MODE, .name = "SUSFS_SUS_SU_MODE", .handler = do_susfs_show_sus_su_working_mode, .perm_check = only_root },
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
	{ .cmd = KSU_IOCTL_SUSFS_ADD_SUS_MAP, .name = "SUSFS_ADD_SUS_MAP", .handler = do_susfs_add_sus_map, .perm_check = only_root },
#endif
	{ .cmd = KSU_IOCTL_SUSFS_SHOW_VERSION, .name = "SUSFS_SHOW_VERSION", .handler = do_susfs_show_version, .perm_check = only_root },
	{ .cmd = KSU_IOCTL_SUSFS_SHOW_VARIANT, .name = "SUSFS_SHOW_VARIANT", .handler = do_susfs_show_variant, .perm_check = only_root },
	{ .cmd = KSU_IOCTL_SUSFS_SHOW_ENABLED_FEATURES, .name = "SUSFS_SHOW_FEATURES", .handler = do_susfs_show_enabled_features, .perm_check = only_root },
	{ .cmd = KSU_IOCTL_SUSFS_ENABLE_AVC_LOG_SPOOFING, .name = "SUSFS_AVC_LOG_SPOOF", .handler = do_susfs_enable_avc_log_spoofing, .perm_check = only_root },
#endif // CONFIG_KSU_SUSFS
	{ .cmd = 0, .name = NULL, .handler = NULL, .perm_check = NULL } // Sentinel
	};

#ifdef CONFIG_KSU_SUSFS
// Forward declaration for SUSFS legacy command translation
static unsigned int susfs_translate_legacy_cmd(unsigned int cmd);

// SUSFS magic number used by ksu_susfs tool
#define SUSFS_MAGIC2 0xfafafafa

// The ksu_susfs binary stores a marker (0x7e) at different offsets depending on command
// We need to write the result at the correct offset for each command type
// Analysis from disassembly:
// - Buffer base is typically at sp+4752 for most commands
// - Marker stored at sp+4768 (offset 16) for show version/variant
// - Marker stored at sp+5020 (offset 268) for show enabled_features, add_sus_path, etc
// - Marker stored at sp+4884 (offset 132) for set_uname
// - Marker stored at sp+5008 (offset 256) for add_try_umount
// - Marker stored at sp+5120 (offset 368) for other commands
// - Some commands use sp+128 as buffer base with marker at sp+388 (offset 260)
static int get_susfs_result_offset(unsigned int cmd)
{
	switch (cmd) {
	// Commands with result at offset 16 (sp+4768 - sp+4752)
	case CMD_SUSFS_SHOW_VERSION:
	case CMD_SUSFS_SHOW_VARIANT:
	case CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE:
		return 16;
	
	// show enabled_features uses calloc(1, 0x2004) with marker at offset 8192
	case CMD_SUSFS_SHOW_ENABLED_FEATURES:
		return 8192;
	
	// Commands with result at offset 268 (sp+5020 - sp+4752)
	case CMD_SUSFS_ADD_SUS_PATH:
	case CMD_SUSFS_ADD_SUS_PATH_LOOP:
	case CMD_SUSFS_ADD_SUS_KSTAT:
	case CMD_SUSFS_UPDATE_SUS_KSTAT:
	case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:
	case CMD_SUSFS_ADD_OPEN_REDIRECT:
	case CMD_SUSFS_ADD_SUS_MAP:
		return 268;
	
	// Commands with result at offset 132 (sp+4884 - sp+4752)
	case CMD_SUSFS_SET_UNAME:
		return 132;
	
	// Commands with result at offset 256 (sp+5008 - sp+4752)
	case CMD_SUSFS_ADD_SUS_MOUNT:
	case CMD_SUSFS_SUS_SU:
		return 256;
	
	// Commands with result at offset 260 (sp+388 - sp+128, different buffer base)
	case CMD_SUSFS_ADD_TRY_UMOUNT:
		return 260;
	
	// Commands with result at offset 4 (small buffer commands)
	case CMD_SUSFS_ENABLE_LOG:
	case CMD_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS:
	case CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE:
	case CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING:
	case CMD_SUSFS_IS_SUS_SU_READY:
		return 4;
	
	// Commands with result at offset 368 (sp+5120 - sp+4752)
	case CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH:
	case CMD_SUSFS_SET_SDCARD_ROOT_PATH:
	case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG:
	default:
		return 368;
	}
}

// Execute SUSFS command and return result
static int handle_susfs_command(unsigned int cmd, void __user *argp)
{
	int i;
	int ret = -ENOSYS;
	int result_offset;
	unsigned int translated_cmd;

	// Only allow root to use SUSFS commands
	if (current_uid().val != 0) {
		return -EPERM;
	}

	// Get result offset using the ORIGINAL legacy command code (before translation)
	result_offset = get_susfs_result_offset(cmd);

	// Translate legacy command format to IOCTL format
	translated_cmd = susfs_translate_legacy_cmd(cmd);

	// Find and execute the handler
	for (i = 0; ksu_ioctl_handlers[i].handler; i++) {
		if (translated_cmd == ksu_ioctl_handlers[i].cmd) {
			if (ksu_ioctl_handlers[i].perm_check &&
			    !ksu_ioctl_handlers[i].perm_check()) {
				ret = -EPERM;
				break;
			}
			ret = ksu_ioctl_handlers[i].handler(argp);
			break;
		}
	}

	// Write result at the correct offset for this command
	// The binary checks if marker (0x7e = 126) was modified
	// On success (ret == 0), we write 0 which != 0x7e, so binary knows it succeeded
	// On failure, we write the error code which also != 0x7e
	if (result_offset >= 0) {
		put_user(ret, (int __user *)((char __user *)argp + result_offset));
	}

	return ret;
}
#endif

/*
 * Direct hook from kernel/reboot.c - handles KernelSU and SUSFS commands
 * via the reboot syscall with special magic numbers.
 *
 * Returns: 1 if the call was handled (result set), 0 if not handled
 */
int ksu_handle_reboot_syscall(int magic1, int magic2, unsigned int cmd,
			      void __user *arg, int *result)
{
	// Check for KSU fd installation request
	if (magic1 == KSU_INSTALL_MAGIC1 && magic2 == KSU_INSTALL_MAGIC2) {
		int fd = ksu_install_fd();
		if (arg && copy_to_user(arg, &fd, sizeof(fd))) {
			pr_err("ksu_handle_reboot: copy fd to user failed\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
			close_fd(fd);
#else
			ksys_close(fd);
#endif
			*result = -EFAULT;
		} else {
			*result = 0;
		}
		return 1; // Handled
	}

#ifdef CONFIG_KSU_SUSFS
	// Check for SUSFS command (magic2 = 0xfafafafa)
	if (magic1 == KSU_INSTALL_MAGIC1 && magic2 == (int)SUSFS_MAGIC2) {
		*result = handle_susfs_command(cmd, arg);
		return 1; // Handled
	}
#endif

	return 0; // Not handled, let normal reboot proceed
}
EXPORT_SYMBOL(ksu_handle_reboot_syscall);

void ksu_supercalls_init(void)
{
}

void ksu_supercalls_exit(void)
{
	// Nothing to unregister - using direct syscall hook
}

// SUSFS legacy command compatibility - translate old prctl-style commands to new IOCTL commands
#ifdef CONFIG_KSU_SUSFS
static unsigned int susfs_translate_legacy_cmd(unsigned int cmd)
{
	switch (cmd) {
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	case CMD_SUSFS_ADD_SUS_PATH:
		return KSU_IOCTL_SUSFS_ADD_SUS_PATH;
	case CMD_SUSFS_ADD_SUS_PATH_LOOP:
		return KSU_IOCTL_SUSFS_ADD_SUS_PATH_LOOP;
	case CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH:
		return KSU_IOCTL_SUSFS_SET_ANDROID_DATA_ROOT_PATH;
	case CMD_SUSFS_SET_SDCARD_ROOT_PATH:
		return KSU_IOCTL_SUSFS_SET_SDCARD_ROOT_PATH;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	case CMD_SUSFS_ADD_SUS_MOUNT:
		return KSU_IOCTL_SUSFS_ADD_SUS_MOUNT;
	case CMD_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS:
		return KSU_IOCTL_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS;
	case CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE:
		return KSU_IOCTL_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	case CMD_SUSFS_ADD_SUS_KSTAT:
	case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:
		return KSU_IOCTL_SUSFS_ADD_SUS_KSTAT;
	case CMD_SUSFS_UPDATE_SUS_KSTAT:
		return KSU_IOCTL_SUSFS_UPDATE_SUS_KSTAT;
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	case CMD_SUSFS_ADD_TRY_UMOUNT:
		return KSU_IOCTL_SUSFS_ADD_TRY_UMOUNT;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	case CMD_SUSFS_SET_UNAME:
		return KSU_IOCTL_SUSFS_SET_UNAME;
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	case CMD_SUSFS_ENABLE_LOG:
		return KSU_IOCTL_SUSFS_ENABLE_LOG;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG:
		return KSU_IOCTL_SUSFS_SET_CMDLINE_OR_BOOTCONFIG;
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	case CMD_SUSFS_ADD_OPEN_REDIRECT:
		return KSU_IOCTL_SUSFS_ADD_OPEN_REDIRECT;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_SU
	case CMD_SUSFS_SUS_SU:
		return KSU_IOCTL_SUSFS_SUS_SU;
	case CMD_SUSFS_IS_SUS_SU_READY:
		return KSU_IOCTL_SUSFS_IS_SUS_SU_READY;
	case CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE:
		return KSU_IOCTL_SUSFS_SHOW_SUS_SU_WORKING_MODE;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
	case CMD_SUSFS_ADD_SUS_MAP:
		return KSU_IOCTL_SUSFS_ADD_SUS_MAP;
#endif
	case CMD_SUSFS_SHOW_VERSION:
		return KSU_IOCTL_SUSFS_SHOW_VERSION;
	case CMD_SUSFS_SHOW_VARIANT:
		return KSU_IOCTL_SUSFS_SHOW_VARIANT;
	case CMD_SUSFS_SHOW_ENABLED_FEATURES:
		return KSU_IOCTL_SUSFS_SHOW_ENABLED_FEATURES;
	case CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING:
		return KSU_IOCTL_SUSFS_ENABLE_AVC_LOG_SPOOFING;
	default:
		return cmd; // Return original if no translation needed
	}
}
#endif

// IOCTL dispatcher
static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int i;

#ifdef CONFIG_KSU_SUSFS
	// Translate legacy SUSFS commands to new IOCTL format
	cmd = susfs_translate_legacy_cmd(cmd);
#endif

	for (i = 0; ksu_ioctl_handlers[i].handler; i++) {
		if (cmd == ksu_ioctl_handlers[i].cmd) {
			// Check permission first
			if (ksu_ioctl_handlers[i].perm_check &&
			    !ksu_ioctl_handlers[i].perm_check()) {
				pr_warn("ksu ioctl: permission denied for cmd=0x%x uid=%d\n",
					cmd, current_uid().val);
				return -EPERM;
			}
			// Execute handler
			return ksu_ioctl_handlers[i].handler(argp);
		}
	}

	pr_warn("ksu ioctl: unsupported command 0x%x\n", cmd);
	return -ENOTTY;
}

// File release handler
static int anon_ksu_release(struct inode *inode, struct file *filp)
{
	return 0;
}

// File operations structure
static const struct file_operations anon_ksu_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = anon_ksu_ioctl,
	.compat_ioctl = anon_ksu_ioctl,
	.release = anon_ksu_release,
};

// Install KSU fd to current process
int ksu_install_fd(void)
{
	struct file *filp;
	int fd;

	// Get unused fd
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("ksu_install_fd: failed to get unused fd\n");
		return fd;
	}

	// Create anonymous inode file
	filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL, O_RDWR | O_CLOEXEC);
	if (IS_ERR(filp)) {
		pr_err("ksu_install_fd: failed to create anon inode file\n");
		put_unused_fd(fd);
		return PTR_ERR(filp);
	}

	// Install fd
	fd_install(fd, filp);

	return fd;
}
