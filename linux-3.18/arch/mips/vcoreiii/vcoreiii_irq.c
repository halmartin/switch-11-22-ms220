/*
 *
 * VCore-III IRQ Handling
 *
 * Copyright (C) 2010 Vitesse Semiconductor Inc.
 * Author: Lars Povlsen (lpovlsen@vitesse.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
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
#include <linux/irq.h>
#include <linux/interrupt.h>

#include <asm/irq_cpu.h>
#include <asm/irq_regs.h>
#include <asm/mach-vcoreiii/irq.h>
#include <asm/mach-vcoreiii/hardware.h>

void __iomem *vcoreiii_irq0_ident;

#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
extern void __iomem *vcoreiii_slv_irq_ident;
#endif

static inline int clz(unsigned long x)
{
	__asm__ (
	"	.set	push					\n"
	"	.set	mips32					\n"
	"	clz	%0, %1					\n"
	"	.set	pop					\n"
	: "=r" (x)
	: "r" (x));

	return x;
}

static inline unsigned int irq_ffs(unsigned int pending)
{
	return -clz(pending) + 31;
}

asmlinkage void plat_irq_dispatch(void)
{
	unsigned int pending = read_c0_cause() & read_c0_status() & ST0_IM;

        if (pending & STATUSF_IP7)                      /* cpu timer */
                do_IRQ(TIMER_IRQ);
        else if (pending & STATUSF_IP2) {               /* vcoreiii pic */
                int irq = readl(vcoreiii_irq0_ident);
                if (unlikely(irq == 0)) {
                        spurious_interrupt();
                        return;
                }
		irq = ICPU_IRQ0_BASE + irq_ffs(irq);
#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
		if (irq == EXT1_IRQ && vcoreiii_slv_irq_ident) {
			irq = slv_readl(vcoreiii_slv_irq_ident);
			if (unlikely(irq == 0)) {
				struct irq_data* data = irq_get_irq_data(EXT1_IRQ);
				struct irq_chip* chip = irq_data_get_irq_chip(data);

				/* Ack the cascaded (master) IRQ */
				chip->irq_ack(data);
				spurious_interrupt();
				return;
			}
			irq = SLV_IRQ_BASE + irq_ffs(irq);
		}
#endif
                do_IRQ(irq);
        } else if (pending & STATUSF_IP0)               /* user line 0 */
                do_IRQ(MIPS_SOFTINT0_IRQ);
        else if (pending & STATUSF_IP1)                 /* user line 1 */
                do_IRQ(MIPS_SOFTINT1_IRQ);
        else
                spurious_interrupt();
}

void __init arch_init_irq(void)
{
	mips_cpu_irq_init();
}
