#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/tracepoint.h>
#include <linux/syscalls.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module to hook all syscalls using tracepoints");

// 関数プロトタイプを追加
static void sys_enter_callback(void *data, long id, struct pt_regs *regs);
static void tp_callback(struct tracepoint *tp, void *priv);

static struct tracepoint *tp_sys_enter = NULL;

static void sys_enter_callback(void *data, long id, struct pt_regs *regs)
{
    struct task_struct *task = current;
    printk(KERN_INFO "Process: %s (PID: %d), Syscall ID: %ld\n", task->comm, task->pid, id);
}

static void tp_callback(struct tracepoint *tp, void *priv)
{
    if (strcmp(tp->name, "sys_exit") == 0)
    {
        tp_sys_enter = tp;
        tracepoint_probe_register(tp_sys_enter, sys_enter_callback, NULL);
        printk(KERN_INFO "Tracepoint for sys_enter registered.\n");
    }
}

static void lookup_tracepoints(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,2,0)
    for_each_kernel_tracepoint(tp_callback, NULL);

    if (!tp_sys_enter)
    {
        printk(KERN_ERR "Tracepoint for sys_enter not found.\n");
    }
#else
    printk(KERN_ERR "Kernel version not supported.\n");
#endif
}

static int __init syscall_hook_init(void)
{
    printk(KERN_INFO "Syscall hook module loaded.\n");
    lookup_tracepoints();
    return 0;
}

static void __exit syscall_hook_exit(void)
{
    if (tp_sys_enter)
    {
        tracepoint_probe_unregister(tp_sys_enter, sys_enter_callback, NULL);
        printk(KERN_INFO "Tracepoint for sys_enter unregistered.\n");
    }
    printk(KERN_INFO "Syscall hook module unloaded.\n");
}

module_init(syscall_hook_init);
module_exit(syscall_hook_exit);
