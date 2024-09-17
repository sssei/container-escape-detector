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
#include <linux/nsproxy.h>
#include <linux/ns_common.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seiga Ueno");
MODULE_DESCRIPTION("Hook syscalls and check namespace to detect container escape");

static void sys_exit_callback(void *data, struct pt_regs *regs, long ret);
static void tp_callback(struct tracepoint *tp, void *priv);

static struct tracepoint *tp_sys_exit = NULL;
static struct nsproxy host_ns;

static void host_nsproxy(void)
{
    struct task_struct *task;
    
    while(1){
        for_each_process(task) {
            if (strcmp(task->comm, "systemd") == 0) {
                host_ns.uts_ns = task->nsproxy->uts_ns;
                host_ns.pid_ns_for_children = task->nsproxy->pid_ns_for_children;
                host_ns.net_ns = task->nsproxy->net_ns;
                host_ns.mnt_ns = task->nsproxy->mnt_ns;
                host_ns.ipc_ns = task->nsproxy->ipc_ns;                
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
        if(host_ns.uts_ns == task->nsproxy->uts_ns){
            printk(KERN_INFO "Process %d (%s) is executing syscall %ld. UTS namespace (0x%p) is the same as host's (0x%p).\n", task->pid, task->comm, syscall_id, task->nsproxy->uts_ns, host_ns.uts_ns);
            BUG();
        }

        if(host_ns.pid_ns_for_children == task->nsproxy->pid_ns_for_children){
            printk(KERN_INFO "Process %d (%s) is executing syscall %ld. PID namespace (0x%p) is the same as host's (0x%p).\n", task->pid, task->comm, syscall_id, task->nsproxy->pid_ns_for_children, host_ns.pid_ns_for_children);
            BUG();
        }

        if(host_ns.net_ns == task->nsproxy->net_ns){
            printk(KERN_INFO "Process %d (%s) is executing syscall %ld. Network namespace (0x%p) is the same as host's (0x%p).\n", task->pid, task->comm, syscall_id, task->nsproxy->net_ns, host_ns.net_ns);
            BUG();            
        }

        if(host_ns.mnt_ns == task->nsproxy->mnt_ns){
            printk(KERN_INFO "Process %d (%s) is executing syscall %ld. Mount namespace (0x%p) is the same as host's (0x%p).\n", task->pid, task->comm, syscall_id, task->nsproxy->mnt_ns, host_ns.mnt_ns);
            BUG();            
        }

        if(host_ns.ipc_ns == task->nsproxy->ipc_ns){
            printk(KERN_INFO "Process %d (%s) is executing syscall %ld. IPC namespace (0x%p) is the same as host's (0x%p).\n", task->pid, task->comm, syscall_id, task->nsproxy->ipc_ns, host_ns.ipc_ns);
            BUG();            
        }            
    }
    return;
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
    host_nsproxy();
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
