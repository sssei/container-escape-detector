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
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module to hook syscalls when they exit using tracepoints");


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

bool is_dev_file(struct file *file)
{
    struct inode *inode = file->f_path.dentry->d_inode;
    return S_ISBLK(inode->i_mode) || S_ISCHR(inode->i_mode);
}

static struct vfsmount_list* get_container_vfsmount(void)
{
    struct task_struct *task;
    struct mnt_namespace *mnt_ns = NULL;
    struct vfsmount_list *vfsmount_list = kmalloc(sizeof(struct vfsmount_list), GFP_KERNEL);
    if (!vfsmount_list) {
        printk(KERN_ERR "Failed to allocate memory\n");
        return NULL;
    }
    INIT_LIST_HEAD(&vfsmount_list->head);
    vfsmount_list->mount_count = 0;

    
    while(1){
        for_each_process(task) {
            if (strcmp(task->comm, "entrypoint.sh") == 0) {
                mnt_ns = task->nsproxy->mnt_ns;
                //down_read(&mnt_ns->ns_rwsem);
                printk(KERN_INFO "mnt_ns : %p\n", mnt_ns);
                struct rb_node *node;
                struct mount *mnt;
                struct vfsmount *vfsmount;
                for(node = rb_first(&mnt_ns->mounts); node; node = rb_next(node)){
                    mnt = rb_entry(node, struct mount, mnt_node);
                    vfsmount = &mnt->mnt;
                    printk(KERN_INFO "vfsmount : %p\n", vfsmount);
                    struct vfsmount_list_entry *entry = kmalloc(sizeof(struct vfsmount_list_entry), GFP_KERNEL);
                    if (!entry) {
                        printk(KERN_ERR "Failed to allocate memory\n");
                        return NULL;
                    }
                    entry->mnt = vfsmount;
                    list_add(&entry->list, &vfsmount_list->head);
                    vfsmount_list->mount_count++;
                }
                return vfsmount_list;                
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

                if(is_dev_file(filp)){
                    printk(KERN_INFO "Process %d (%s) is executing syscall %ld. fd(%d) is a device file : %s\n", task->pid, task->comm, syscall_id, i, tmp);
                    kfree(pathname);
                }else{
                    printk(KERN_INFO "Process %d (%s) is executing syscall %ld. fd(%d), File path: %s, vfsmount: 0x%p\n", task->pid, task->comm, syscall_id, i,tmp, fd_root);                    
                    kfree(pathname);
//                    if(fd_root != container_root){
//                        printk(KERN_ERR "Container Escape Detected : Process %d (%s) executing syscall %ld. fd(%d), File path: %s, vfsmount: 0x%p\n", task->pid, task->comm, syscall_id, i,tmp, fd_root);
//                        BUG();  
//                        return;
//                    }
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
    struct vfsmount_list *container_vfsmount = get_container_vfsmount();
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
