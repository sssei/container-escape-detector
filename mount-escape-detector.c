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
#include <linux/mnt_namespace.h>
#include "/home/seiga/workspace/qemu/noble/fs/mount.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seiga Ueno");
MODULE_DESCRIPTION("Kernel module to detect mount namespace escape");


static void sys_exit_callback(void *data, struct pt_regs *regs, long ret);
static void tp_callback(struct tracepoint *tp, void *priv);

static struct tracepoint *tp_sys_exit = NULL;


struct vfsmount_list_entry {
    struct list_head list;
    struct vfsmount *mnt;
};

struct vfsmount_list{
    int mount_count;
    struct list_head head;
};

struct vfsmount_list *container_vfsmount = NULL;

static void set_container_vfsmount(void)
{
    struct task_struct *task;
    struct mnt_namespace *mnt_ns = NULL;

    INIT_LIST_HEAD(&container_vfsmount->head);
    container_vfsmount->mount_count = 0;
    
    while(1){
        for_each_process(task) {
            if (strcmp(task->comm, "entrypoint.sh") == 0) {
                mnt_ns = task->nsproxy->mnt_ns;
                printk(KERN_INFO "mnt_ns : %p\n", mnt_ns);
                struct rb_node *node;
                struct mount *mnt;
                struct vfsmount *vfsmount;
                for(node = rb_first(&mnt_ns->mounts); node; node = rb_next(node)){
                    mnt = rb_entry(node, struct mount, mnt_node);
                    vfsmount = &mnt->mnt;
                    struct vfsmount_list_entry *entry = kmalloc(sizeof(struct vfsmount_list_entry), GFP_KERNEL);
                    if (!entry) {
                        printk(KERN_ERR "Failed to allocate memory\n");
                        return;
                    }
                    entry->mnt = vfsmount;
                    list_add(&entry->list, &container_vfsmount->head);
                    container_vfsmount->mount_count++;
                }
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

        struct files_struct* files;
        struct fdtable *fdt;
        struct file *filp;
        struct path path;
        struct vfsmount *fd_root;
        char *pathname;
        int i;

        rcu_read_lock();
        files = rcu_dereference(task->files);;
        fdt = files_fdtable(files);

        for(i = 0; i < fdt->max_fds; i++){
            filp = rcu_dereference(fdt->fd[i]);
            if(filp){

                // check if the file is regular file or directory
                if (!(S_ISREG(filp->f_inode->i_mode) || S_ISDIR(filp->f_inode->i_mode) || S_ISLNK(filp->f_inode->i_mode))) {
                    continue;
                }

                path = filp->f_path;
                pathname = kmalloc(256,GFP_ATOMIC);
                if (!pathname) {
                    printk(KERN_ERR "Failed to allocate memory\n");
                    continue;
                }                
                path_get(&path);
                char *tmp=d_path(&path,pathname,256);
                fd_root = path.mnt;

                // printk(KERN_INFO "Process %d (%s) is executing syscall %ld. fd(%d), File path: %s, vfsmount: 0x%p\n", task->pid, task->comm, syscall_id, i,tmp, fd_root);                    
                kfree(pathname);

                // check if the file is in the container vfsmount
                struct vfsmount_list_entry *entry;
                int found = 0;
                list_for_each_entry(entry, &container_vfsmount->head, list) {
                    if (entry->mnt == fd_root) {
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    printk(KERN_ERR "Container Escape Detected : Process %d (%s) executing syscall %ld. fd(%d), File path: %s, vfsmount: 0x%p\n", task->pid, task->comm, syscall_id, i,tmp, fd_root);
                    rcu_read_unlock();
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
    container_vfsmount = kmalloc(sizeof(struct vfsmount_list), GFP_KERNEL);
    if (!container_vfsmount) {
        printk(KERN_ERR "Failed to allocate memory\n");
        return 1;
    }    
    set_container_vfsmount();

    // print container vfsmount 
    struct vfsmount_list_entry *entry;
    list_for_each_entry(entry, &container_vfsmount->head, list) {
        printk(KERN_INFO "vfsmount : %p\n", entry->mnt);
        char *pathname = kmalloc(256,GFP_ATOMIC);
        if (!pathname) {
            printk(KERN_ERR "Failed to allocate memory\n");
            return 1;
        }
        struct path path;
        path.mnt = entry->mnt;
        path.dentry = entry->mnt->mnt_root;
        path_get(&path);
        char *tmp=d_path(&path,pathname,256);
        printk(KERN_INFO "vfsmount path : %s\n", tmp);        
        kfree(pathname);
    }

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
