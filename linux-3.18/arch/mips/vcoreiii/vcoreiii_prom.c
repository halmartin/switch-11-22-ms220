/*
 *
 * VCore-III PROM functionality
 *
 * Copyright (C) 2010 Vitesse Semiconductor Inc.
 * Author: Lars Povlsen (lpovlsen@vitesse.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * VITESSE SEMICONDUCTOR INC SHALL HAVE NO LIABILITY WHATSOEVER OF ANY
 * KIND ARISING OUT OF OR RELATED TO THE PROGRAM OR THE OPEN SOURCE
 * MATERIALS UNDER ANY THEORY OF LIABILITY.
 *
 */
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/serial_reg.h>
#include <linux/ioport.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>

#include <asm/io.h>
#include <asm/mipsregs.h>
#include <asm/pgtable.h>
#include <asm/tlbmisc.h>

#include <asm/mach-vcoreiii/hardware.h>

struct _uart_ptr {
	volatile uint32_t rbr_thr;
	volatile uint32_t ier;
	volatile uint32_t iir_fcr;
	volatile uint32_t lcr;
	volatile uint32_t mcr;
	volatile uint32_t lsr;
	volatile uint32_t msr;
	volatile uint32_t scr;
	volatile uint32_t usr;
};


#define UART_BASE (0x70100000)

#define MMU_REGIO_RW ((2 << 3) | 7) /* Uncached, read/write, global, valid */

#define SYSTEM_CLOCK (418 * 1000 * 1000)
#define BAUD_RATE (115200)
#define UART_DIVISOR ((SYSTEM_CLOCK/2)/(BAUD_RATE*16))

#ifdef CONFIG_EARLY_PRINTK

static struct _uart_ptr *uart_ptr;
static struct vm_struct console_early_vm;

#endif /* CONFIG_EARLY_PRINTK */

void __init prom_init(void)
{
#ifdef CONFIG_EARLY_PRINTK

	write_c0_wired(0);
	console_early_vm.flags = VM_ALLOC;
	console_early_vm.size = 1 << PAGE_SHIFT;
	vm_area_register_early(&console_early_vm, PAGE_SIZE);
	uart_ptr = (struct _uart_ptr *)console_early_vm.addr;

	add_wired_entry(MMU_REGIO_RW | (UART_BASE >> 6),
			MMU_REGIO_RW | ((UART_BASE + (4 << 10)) >> 6),
			(unsigned long)uart_ptr, PM_4K);

	uart_ptr->lcr = UART_LCR_DLAB; /* Enable divisor latch */

	uart_ptr->rbr_thr = UART_DIVISOR & 0xff; /* Set baud rate LSB */
	uart_ptr->ier = UART_DIVISOR >> 8;	 /* Set baud rate MSB */

	uart_ptr->lcr = UART_LCR_WLEN8;	/* 8 bits, no parity, 1 stop bit */
	udelay(1);			 /* Let BRG settle */

#endif /* CONFIG_EARLY_PRINTK */
}

unsigned long prom_free_prom_memory(void)
{
        return 0; /* "Freeing unused memory: %ldk freed\n" */
}

#ifdef CONFIG_EARLY_PRINTK
void __init prom_putchar(char c)
{
	/*
	 * When tlb_init() is called, it will destroy our wired mapping.
	 * So, if there are no wired mappings, put ours back in. Ugly.
	 */

	if (read_c0_wired() == 0) {
		add_wired_entry(MMU_REGIO_RW | (UART_BASE >> 6),
				MMU_REGIO_RW | ((UART_BASE + (4 << 10)) >> 6),
				(unsigned long)uart_ptr, PM_4K);
	}

	while ((uart_ptr->lsr & UART_LSR_THRE) == 0) ;

	uart_ptr->rbr_thr = c;
}

static int __init remove_early_console_mapping(void)
{
	/*
	 * Very very very ugly. We should be the only thing that installed
	 * a wired mapping, so it is safe for us to remove it. However,
	 * if there are other wired mappings, we should just warn about
	 * it and do nothing. There are only 16 TLBs on the VCore-III
	 * so using a wired TLB is a bad idea.
	 */

	if (read_c0_wired() == 1) {
		write_c0_wired(0);
	} else {
		printk(KERN_ERR "%s: unable to remove wired mapping, "
		       "count = %d\n", __func__, read_c0_wired());
	}
	return 0;
}


late_initcall_sync(remove_early_console_mapping);

#endif /* CONFIG_EARLY_PRINTK */
