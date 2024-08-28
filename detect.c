#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module to list all process names in a loop");

#define LOOP_INTERVAL (5 * HZ)  // 5秒間隔でループ

static struct task_struct *task;   // プロセス構造体へのポインタ
static struct task_struct *monitor_thread;  // カーネルスレッド用ポインタ

// ループ関数: 全てのプロセスの名前を出力
static void scan_processes(void) {
    for_each_process(task) {
        printk(KERN_INFO "Process: %s [PID: %d]\n", task->comm, task->pid);
    }
}

// カーネルスレッド関数
static int monitor_fn(void *data) {
    while (!kthread_should_stop()) {
        scan_processes();  // プロセス走査
        msleep(LOOP_INTERVAL);  // 5秒間隔で待機
    }
    return 0;
}

// モジュールの初期化関数
static int __init monitor_init(void) {
    printk(KERN_INFO "Starting process monitor module.\n");
    
    // カーネルスレッドの作成と開始
    monitor_thread = kthread_run(monitor_fn, NULL, "process_monitor_thread");
    if (IS_ERR(monitor_thread)) {
        printk(KERN_ERR "Failed to create monitor thread.\n");
        return PTR_ERR(monitor_thread);
    }

    return 0;
}

// モジュールの終了関数
static void __exit monitor_exit(void) {
    printk(KERN_INFO "Stopping process monitor module.\n");

    // カーネルスレッドの停止
    if (monitor_thread) {
        kthread_stop(monitor_thread);
    }
}

module_init(monitor_init);
module_exit(monitor_exit);

