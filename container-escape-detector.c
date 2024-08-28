#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/tracepoint.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/fdtable.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module to hook syscalls when they exit using tracepoints");

static void sys_exit_callback(void *data, struct pt_regs *regs, long ret);
static void tp_callback(struct tracepoint *tp, void *priv);

static struct tracepoint *tp_sys_exit = NULL;

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
        char *pathname;
        int i;

        for(i=0;i<fdt->max_fds;i++){
            filp=fdt->fd[i];
            if(filp){
                path=filp->f_path;
                pathname=kmalloc(256,GFP_KERNEL);
                path_get(&path);
                char *tmp=d_path(&path,pathname,256);
                printk(KERN_INFO "Process %d (%s) is executing syscall %ld. fd(%d), File path: %s\n", task->pid, task->comm, syscall_id, i,tmp);
                kfree(pathname);
                if(i > 2){
                    printk(KERN_ERR "This is test oops. Process %d (%s) executing syscall %ld. fd(%d), File path: %s\n", task->pid, task->comm, syscall_id, i,tmp);
                    BUG();  
                    return;
                }
            }
        }

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
