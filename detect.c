#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/tracepoint.h>
#include <linux/sched.h>
#include <linux/utsname.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/string.h>

#define TARGET_PROCESS_NAME "syz-executor"  // 監視したいプロセス名を指定

// トレースポイントのプローブ関数
void sys_enter_probe(void *ignore, struct pt_regs *regs, long id)
{
    struct files_struct *files;
    struct fdtable *fdt;
    int i;

    // 対象プロセス名のチェック
    if (strcmp(current->comm, TARGET_PROCESS_NAME) == 0) {
        printk(KERN_INFO "Target Process: %s, Syscall ID: %ld\n", current->comm, id);

        // プロセスのファイルディスクリプタを取得
        files = current->files;
        fdt = files_fdtable(files);

        // ファイルディスクリプタとその名前を表示
        for (i = 0; i < fdt->max_fds; i++) {
            struct file *file = fdt->fd[i];
            if (file) {
                struct path *path = &file->f_path;
                char *buf = (char *)__get_free_page(GFP_KERNEL);

                if (buf) {
                    char *tmp = d_path(path, buf, PAGE_SIZE);
                    printk(KERN_INFO "FD %d: %s\n", i, tmp);
                    free_page((unsigned long)buf);
                }
            }
        }
    }
}

// トレースポイントを登録する関数
static int __init syscall_monitor_init(void)
{
    int ret;

    // sys_enter のトレースポイントを登録
    ret = register_trace_sys_enter(sys_enter_probe, NULL);
    if (ret) {
        printk(KERN_ERR "Failed to register tracepoint\n");
        return ret;
    }

    printk(KERN_INFO "Syscall monitor module loaded\n");
    return 0;
}

// トレースポイントを解除する関数
static void __exit syscall_monitor_exit(void)
{
    unregister_trace_sys_enter(sys_enter_probe, NULL);
    printk(KERN_INFO "Syscall monitor module unloaded\n");
}

module_init(syscall_monitor_init);
module_exit(syscall_monitor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seiga Ueno");
MODULE_DESCRIPTION("A module to monitor specific process syscalls and print FD, process name, and syscall ID");
