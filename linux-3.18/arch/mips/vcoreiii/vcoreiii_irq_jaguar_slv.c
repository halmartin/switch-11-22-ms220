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

#define SUPPORT_VTSS_VCOREIII_JAGUAR

#include <linux/init.h>
#include <linux/irq.h>
#include <linux/interrupt.h>

#include <asm/irq_cpu.h>
#include <asm/irq_regs.h>

#include <asm/mach-vcoreiii/irq.h>
#include <asm/mach-vcoreiii/hardware.h>
#include <asm/mach-vcoreiii/vcoreiii_gpio.h>

void __iomem *vcoreiii_slv_irq_ident;

static void slv_ack_irq_ioc(struct irq_data *data)
{
    //printk("%s: %d\n", __FUNCTION__, irq - SLV_IRQ_BASE);
    slv_writel(1 << (data->irq - SLV_IRQ_BASE), VTSS_ICPU_CFG_INTR_INTR); /* Ack sticky */
    writel(1 << (EXT1_IRQ - ICPU_IRQ0_BASE), VTSS_ICPU_CFG_INTR_INTR); /* Ack master ext1 sticky */
}

static void slv_mask_irq_ioc(struct irq_data *data)
{
    //printk("%s: %d\n", __FUNCTION__, irq - SLV_IRQ_BASE);
    slv_writel(1 << (data->irq - SLV_IRQ_BASE), VTSS_ICPU_CFG_INTR_INTR_ENA_CLR); /* Disable */
}

static void slv_mask_ack_irq_ioc(struct irq_data *data)
{
    //printk("%s: %d\n", __FUNCTION__, irq - SLV_IRQ_BASE);
    slv_writel(1 << (data->irq - SLV_IRQ_BASE), VTSS_ICPU_CFG_INTR_INTR_ENA_CLR); /* Disable */
    slv_writel(1 << (data->irq - SLV_IRQ_BASE), VTSS_ICPU_CFG_INTR_INTR); /* Ack sticky */
    writel(1 << (EXT1_IRQ - ICPU_IRQ0_BASE), VTSS_ICPU_CFG_INTR_INTR); /* Ack master ext1 sticky */
}

static void slv_unmask_irq_ioc(struct irq_data *data)
{
    slv_writel(1 << (data->irq - SLV_IRQ_BASE), VTSS_ICPU_CFG_INTR_INTR_ENA_SET); /* Enable */
}

static struct irq_chip vcoreiii_slvirq_ioc = {
    .name = "vc3_sec",
    .irq_ack = slv_ack_irq_ioc,
    .irq_mask = slv_mask_irq_ioc,
    .irq_mask_ack = slv_mask_ack_irq_ioc,
    .irq_unmask = slv_unmask_irq_ioc,
};

void __init vcoreiii_dual_irq_init(void)
{
	int i;

	if (!map_base_slv_switch)
		return;		/* No slave switch connected */

        /* EXT1-master (input) is connected to EXT0-slave (output) */
        /* Slave EXT0 is output, active low */
	slv_writel(VTSS_F_ICPU_CFG_INTR_EXT_IRQ0_INTR_CFG_EXT_IRQ0_INTR_DRV |
                   VTSS_F_ICPU_CFG_INTR_EXT_IRQ0_INTR_CFG_EXT_IRQ0_INTR_DIR,
                   VTSS_ICPU_CFG_INTR_EXT_IRQ0_INTR_CFG);
        /* Master EXT1 is input, active low */
	writel(0, VTSS_ICPU_CFG_INTR_EXT_IRQ1_INTR_CFG);

        /* Route EXT_IRQ1 (input) and all internal interrupts to EXT_IRQ0 (output). */

#define JR_INTR_CFG_EXTERNAL(intr) slv_writel(VTSS_F_ICPU_CFG_INTR_##intr##_INTR_CFG_##intr##_INTR_SEL(2), VTSS_ICPU_CFG_INTR_##intr##_INTR_CFG) /* External, active low input, to EXT_IRQ0 */

#define JR_INTR_CFG_INTERNAL(intr) slv_writel(VTSS_F_ICPU_CFG_INTR_##intr##_INTR_CFG_##intr##_INTR_SEL(2), VTSS_ICPU_CFG_INTR_##intr##_INTR_CFG) /* Internal, to EXT_IRQ0 */

        /* EXT_IRQ1 is an input on the secondary chip. Route it to EXT_IRQ0. */
        JR_INTR_CFG_EXTERNAL(EXT_IRQ1);

        /* Remaining interrupts are also routed to EXT_IRQ0. */
        JR_INTR_CFG_INTERNAL(SW0);
        JR_INTR_CFG_INTERNAL(SW1);
        JR_INTR_CFG_INTERNAL(MIIM1);
        JR_INTR_CFG_INTERNAL(MIIM0);
        JR_INTR_CFG_INTERNAL(PI_SD0);
        JR_INTR_CFG_INTERNAL(PI_SD1);
        JR_INTR_CFG_INTERNAL(UART);
        JR_INTR_CFG_INTERNAL(TIMER0);
        JR_INTR_CFG_INTERNAL(TIMER1);
        JR_INTR_CFG_INTERNAL(TIMER2);
        JR_INTR_CFG_INTERNAL(FDMA);
        JR_INTR_CFG_INTERNAL(TWI);
        JR_INTR_CFG_INTERNAL(GPIO);
        JR_INTR_CFG_INTERNAL(SGPIO);
        JR_INTR_CFG_INTERNAL(DEV_ALL);
        JR_INTR_CFG_INTERNAL(BLK_ANA);
        JR_INTR_CFG_INTERNAL(XTR_RDY0);
        JR_INTR_CFG_INTERNAL(XTR_RDY1);
        JR_INTR_CFG_INTERNAL(XTR_RDY2);
        JR_INTR_CFG_INTERNAL(XTR_RDY3);
        JR_INTR_CFG_INTERNAL(INJ_RDY0);
        JR_INTR_CFG_INTERNAL(INJ_RDY1);
        JR_INTR_CFG_INTERNAL(INJ_RDY2);
        JR_INTR_CFG_INTERNAL(INJ_RDY3);
        JR_INTR_CFG_INTERNAL(INJ_RDY4);
        JR_INTR_CFG_INTERNAL(INTEGRITY);
        JR_INTR_CFG_INTERNAL(PTP_SYNC);

        /* GPIO Alternate functions EXT1(master) <-> EXT0(slave) */
	vcoreiii_io_clr(VTSS_DEVCPU_GCB_GPIO_GPIO_ALT(1),
			VTSS_BIT(7));
	vcoreiii_io_set(VTSS_DEVCPU_GCB_GPIO_GPIO_ALT(0),
			VTSS_BIT(7));

	/* Slave GPIO6 = EXT0 */
        vcoreiii_gpio_set_alternate(VCOREIII_GPIO_BASE_SLV + 6, 1);

        /* Enable EXT0 to drive it */
        slv_writel(VTSS_F_ICPU_CFG_INTR_EXT_IRQ0_ENA_EXT_IRQ0_ENA,
                   VTSS_ICPU_CFG_INTR_EXT_IRQ0_ENA);

	slv_writel(0, VTSS_ICPU_CFG_INTR_INTR_ENA); /* Mask all */
	slv_writel(0xffffffff, VTSS_ICPU_CFG_INTR_INTR); /* Ack pending */

	vcoreiii_slv_irq_ident = VTSS_ICPU_CFG_INTR_EXT_IRQ0_IDENT;

	for (i = SLV_IRQ_BASE; i <= SLV_MIIM1_INTR_IRQ ; i++)
            irq_set_chip_and_handler(i, &vcoreiii_slvirq_ioc, handle_level_irq);
	irq_set_chained_handler(EXT1_IRQ, handle_simple_irq);
}
