#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/tracepoint.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/fdtable.h>
#include <linux/delay.h>
#include <linux/fs_struct.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module to hook syscalls when they exit using tracepoints");

static void sys_exit_callback(void *data, struct pt_regs *regs, long ret);
static void tp_callback(struct tracepoint *tp, void *priv);

static struct tracepoint *tp_sys_exit = NULL;
struct vfsmount *container_root = NULL;

static void find_process_ns_init(void)
{
    struct task_struct *task;
    while(1){
        for_each_process(task) {
            if (strcmp(task->comm, "entrypoint.sh") == 0) {
                container_root = task->fs->root.mnt;
                printk(KERN_INFO "Container root vfsmount: 0x%p\n", container_root);
                return;
            } 
        }
        printk(KERN_INFO "Process not found. Sleeping for 1 second.\n");
        msleep(1000);
    }
}


static void sys_exit_callback(void *data, struct pt_regs *regs, long ret)
{
    struct task_struct *task = current;
    long syscall_id = regs->orig_ax;  // x86_64 architectureの場合

    if (strcmp(task->comm, "syz-executor") == 0)
    {
        struct files_struct *files=task->files;
        struct fdtable *fdt=files_fdtable(files);
        struct file *filp;
        struct path path;
        struct vfsmount *fd_root;
        char *pathname;
        int i;

        rcu_read_lock();
        files = rcu_dereference(task->files);;
        fdt = files_fdtable(files);

        for(i=2;i<fdt->max_fds;i++){
            filp = rcu_dereference(fdt->fd[i]);
            if(filp){
                path = filp->f_path;
                pathname = kmalloc(256,GFP_ATOMIC);
                if (!pathname) {
                    printk(KERN_ERR "Failed to allocate memory\n");
                    continue;
                }                
                path_get(&path);
                char *tmp=d_path(&path,pathname,256);
                fd_root = path.mnt;

                printk(KERN_INFO "Process %d (%s) is executing syscall %ld. fd(%d), File path: %s, vfsmount: 0x%p\n", task->pid, task->comm, syscall_id, i,tmp, fd_root);
                kfree(pathname);
                
                if(fd_root != container_root){
                    printk(KERN_ERR "Container Escape Detected : Process %d (%s) executing syscall %ld. fd(%d), File path: %s, vfsmount: 0x%p\n", task->pid, task->comm, syscall_id, i,tmp, fd_root);
                    BUG();  
                    return;
                }
            }
        }
        rcu_read_unlock();
    }
}

static void tp_callback(struct tracepoint *tp, void *priv)
{
    if (strcmp(tp->name, "sys_exit") == 0)
    {
        tp_sys_exit = tp;
        tracepoint_probe_register(tp_sys_exit, sys_exit_callback, NULL);
        printk(KERN_INFO "Tracepoint for sys_exit registered.\n");
    }
}

static void lookup_tracepoints(void)
{
    for_each_kernel_tracepoint(tp_callback, NULL);
    if (!tp_sys_exit)
    {
        printk(KERN_ERR "Tracepoint for sys_exit not found.\n");
    }
}

static int __init syscall_hook_init(void)
{
    printk(KERN_INFO "Syscall hook module loaded.\n");
    find_process_ns_init();
    lookup_tracepoints();
    return 0;
}

static void __exit syscall_hook_exit(void)
{
    if (tp_sys_exit)
    {
        tracepoint_probe_unregister(tp_sys_exit, sys_exit_callback, NULL);
        printk(KERN_INFO "Tracepoint for sys_exit unregistered.\n");
    }
    printk(KERN_INFO "Syscall hook module unloaded.\n");
}

module_init(syscall_hook_init);
module_exit(syscall_hook_exit);
