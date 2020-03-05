/*
 *
 * VCore-III IRQ Handling
 *
 * Copyright (C) 2011 Meraki, Inc.
 * Author: Kevin Paul Herbert (kph@meraki.net)
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
 * Hardware specific interrupt handling.
 *
 */

#include <linux/init.h>
#include <linux/irq.h>
#include <linux/interrupt.h>

#include <asm/irq_cpu.h>
#include <asm/irq_regs.h>
#include <asm/mach-vcoreiii/irq.h>
#include <asm/mach-vcoreiii/hardware.h>

static void _ack_irq_ioc(unsigned int irq)
{
	writel(1 << (irq - ICPU_IRQ0_BASE), VTSS_ICPU_CFG_INTR_INTR);
}

static void ack_irq_ioc(struct irq_data *data)
{
	_ack_irq_ioc(data->irq); /* Ack sticky */
}

static void mask_irq_ioc(struct irq_data *data)
{
	writel(1 << (data->irq - ICPU_IRQ0_BASE), VTSS_ICPU_CFG_INTR_INTR_ENA_CLR); /* Disable */
}

static void mask_ack_irq_ioc(struct irq_data *data)
{
	writel(1 << (data->irq - ICPU_IRQ0_BASE), VTSS_ICPU_CFG_INTR_INTR_ENA_CLR); /* Disable */
	writel(1 << (data->irq - ICPU_IRQ0_BASE), VTSS_ICPU_CFG_INTR_INTR); /* Ack sticky */
}

static void unmask_irq_ioc(struct irq_data *data)
{
	writel(1 << (data->irq - ICPU_IRQ0_BASE), VTSS_ICPU_CFG_INTR_INTR_ENA_SET); /* Enable */
}

static struct irq_chip vcoreiii_irq_ioc = {
	.name = "vc3_pri",
	.irq_ack = ack_irq_ioc,
	.irq_mask = mask_irq_ioc,
	.irq_mask_ack = mask_ack_irq_ioc,
	.irq_unmask = unmask_irq_ioc,
};

static void inline __init vcoreiii_irq_init(void)
{
	u32 i;

	if (vcoreiii_check_chip_id()) {

		writel(0, VTSS_ICPU_CFG_INTR_INTR_ENA); /* Mask all */
		writel(0xffffffff, VTSS_ICPU_CFG_INTR_INTR); /* Ack pending */

		for (i = ICPU_IRQ0_BASE; i <= MIIM1_INTR_IRQ ; i++)
			irq_set_chip_and_handler(i, &vcoreiii_irq_ioc,
						 handle_level_irq);
		irq_set_chained_handler(INT0_IRQ, handle_simple_irq);

		vcoreiii_irq0_ident = VTSS_ICPU_CFG_INTR_ICPU_IRQ0_IDENT;
	}
}
