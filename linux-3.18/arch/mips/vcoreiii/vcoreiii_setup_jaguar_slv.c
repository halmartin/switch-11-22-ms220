/*
 *
 * VCore-III System initialization
 *
 * Copyright (C) 2011 Meraki, Inc.
 * Author: Kevin Paul Herbert (kph@meraki.net)
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
 * Jaguar dual chip support.
 */

#define SUPPORT_VTSS_VCOREIII_JAGUAR

#include <linux/init.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/spinlock.h>

#include <asm/mach-vcoreiii/hardware.h>
#include <asm/mach-vcoreiii/vcoreiii_gpio.h>

void __iomem *map_base_slv_switch;
extern const char *_machine_name;

EXPORT_SYMBOL(map_base_slv_switch);

struct vcoreiii_gpio_ctrl *vcoreiii_gpio_slv;
EXPORT_SYMBOL(vcoreiii_gpio_slv);

spinlock_t vcoreiii_indirect_access_lock;

#define SLAVE_CS 3              /* Slave switch on CS3 by default */

static struct resource vcoreiii_switch_slave_registers = {
	.name   = "Switch registers - Slave unit",
	.start  = VTSS_IO_PI_REGION(SLAVE_CS), /* CS3 */
	.end    = VTSS_IO_PI_REGION(SLAVE_CS) + VTSS_IO_ORIGIN1_SIZE - 1,
	.flags  = IORESOURCE_MEM
};

static void vtss_callout_indirect_lock(unsigned long *flags)
{
	spin_lock_irqsave(&vcoreiii_indirect_access_lock, *flags);
}
EXPORT_SYMBOL(vtss_callout_indirect_lock);

static void vtss_callout_indirect_unlock(unsigned long *flags)
{
	spin_unlock_irqrestore(&vcoreiii_indirect_access_lock, *flags);
}
EXPORT_SYMBOL(vtss_callout_indirect_unlock);

u32 slv_indirect_readl(volatile u32 __iomem *addr)
{
    u32 val, ctl;
    unsigned long flags;

    spin_lock_irqsave(&vcoreiii_indirect_access_lock, flags);

    slv_direct_writel(slv_region2_offset(addr), VTSS_DEVCPU_GCB_VCORE_ACCESS_VA_ADDR);
    val = slv_direct_readl(VTSS_DEVCPU_GCB_VCORE_ACCESS_VA_DATA);
    do {
        ctl = slv_direct_readl(VTSS_DEVCPU_GCB_VCORE_ACCESS_VA_CTRL);
    } while(ctl & VTSS_F_DEVCPU_GCB_VCORE_ACCESS_VA_CTRL_VA_BUSY);
    if(ctl & VTSS_F_DEVCPU_GCB_VCORE_ACCESS_VA_CTRL_VA_ERR) {
        printk(KERN_ERR ": Slave Read error on address %p, ctl = 0x%08x\n", addr, ctl);
    }
    val = slv_direct_readl(VTSS_DEVCPU_GCB_VCORE_ACCESS_VA_DATA_INERT);

    spin_unlock_irqrestore(&vcoreiii_indirect_access_lock, flags);

    //printk("Rd(%p) = 0x%08x\n", addr, val);
    return val;
}

EXPORT_SYMBOL(slv_indirect_readl);

void slv_indirect_writel(u32 val, volatile u32 __iomem *addr)
{
    u32 ctl;
    unsigned long flags;
    //printk("Wr(%p) = 0x%08x\n", addr, val);

    spin_lock_irqsave(&vcoreiii_indirect_access_lock, flags);
    slv_direct_writel(slv_region2_offset(addr), VTSS_DEVCPU_GCB_VCORE_ACCESS_VA_ADDR);
    slv_direct_writel(val, VTSS_DEVCPU_GCB_VCORE_ACCESS_VA_DATA);
    do {
        ctl = slv_direct_readl(VTSS_DEVCPU_GCB_VCORE_ACCESS_VA_CTRL);
    } while(ctl & VTSS_F_DEVCPU_GCB_VCORE_ACCESS_VA_CTRL_VA_BUSY);
    if(ctl & VTSS_F_DEVCPU_GCB_VCORE_ACCESS_VA_CTRL_VA_ERR) {
        printk(KERN_ERR "Write error on address %p, ctl = 0x%08x\n", addr, ctl);
    }
    spin_unlock_irqrestore(&vcoreiii_indirect_access_lock, flags);
}

EXPORT_SYMBOL(slv_indirect_writel);

void __init vcoreiii_jaguar_dual_setup(void)
{
	u32 slv_chip_id;
	u32 read_error;

	if (!request_mem_region(vcoreiii_switch_slave_registers.start,
				resource_size(&vcoreiii_switch_slave_registers),
				vcoreiii_switch_slave_registers.name)) {
		printk(KERN_ERR "Slave I/O space in use\n");
		return;
	}

	map_base_slv_switch = ioremap(vcoreiii_switch_slave_registers.start,
				      resource_size
				      (&vcoreiii_switch_slave_registers));
	if(!map_base_slv_switch) {
		printk(KERN_ERR "Unable to ioremap slave switch register space\n");
		return;
	}

	spin_lock_init(&vcoreiii_indirect_access_lock);

	vcoreiii_gpio_slv = (struct vcoreiii_gpio_ctrl *)
		master2slave_addr(VTSS_DEVCPU_GCB_GPIO_GPIO_OUT_SET);

	/* GPIO 18 + cs is used for Slave switch */
	vcoreiii_gpio_set_alternate(VCOREIII_GPIO_BASE + 18 + SLAVE_CS, 1);

	//gpio_direction_output(18 + SLAVE_CS, 0);

	/* Configure Slow PI */
	vcoreiii_io_mask_set(VTSS_ICPU_CFG_PI_MST_PI_MST_CFG,
			     VTSS_M_ICPU_CFG_PI_MST_PI_MST_CFG_CLK_DIV,
			     VTSS_F_ICPU_CFG_PI_MST_PI_MST_CFG_CLK_DIV(0x1f));

	/* Enable the PI interface */
	vcoreiii_io_set(VTSS_ICPU_CFG_CPU_SYSTEM_CTRL_GENERAL_CTRL,
			VTSS_F_ICPU_CFG_CPU_SYSTEM_CTRL_GENERAL_CTRL_IF_MASTER_PI_ENA);
	/* Enable 2048-cycle PI bus timeout on slave PI interface */
	vcoreiii_io_set(VTSS_ICPU_CFG_PI_MST_PI_MST_CTRL(3), VTSS_F_ICPU_CFG_PI_MST_PI_MST_CTRL_DEVICE_PACED_TIMEOUT_ENA
	                | VTSS_F_ICPU_CFG_PI_MST_PI_MST_CTRL_DEVICE_PACED_TIMEOUT(7));

	/* Reset slave device */
	slv_writel(VTSS_F_DEVCPU_GCB_DEVCPU_RST_REGS_SOFT_CHIP_RST_SOFT_CHIP_RST,
		   VTSS_DEVCPU_GCB_DEVCPU_RST_REGS_SOFT_CHIP_RST);

	/* Small nap during reset */
	udelay(10);

	/* Initialize slave device for '16-bit ndone' mode (again) */
	slv_writel(0x18181818, VTSS_DEVCPU_PI_PI_PI_MODE);
	slv_writel(0x18181818, VTSS_DEVCPU_PI_PI_PI_MODE);

	vcoreiii_io_set(VTSS_ICPU_CFG_PI_MST_PI_MST_CTRL(SLAVE_CS), 0x00C200B3); /* Slv CS settings */

	vcoreiii_io_set(VTSS_ICPU_CFG_PI_MST_PI_MST_STATUS(3), VTSS_F_ICPU_CFG_PI_MST_PI_MST_STATUS_TIMEOUT_ERR_STICKY);
	slv_chip_id = slv_readl(VTSS_DEVCPU_GCB_CHIP_REGS_CHIP_ID);
	read_error = readl(VTSS_ICPU_CFG_PI_MST_PI_MST_STATUS(3)) & VTSS_F_ICPU_CFG_PI_MST_PI_MST_STATUS_TIMEOUT_ERR_STICKY;
	if (slv_chip_id == 0xffffffff || read_error) {
		printk(KERN_INFO "VCore-III slave not found\n");
		iounmap(map_base_slv_switch);
		map_base_slv_switch = NULL;
		release_mem_region(vcoreiii_switch_slave_registers.start,
				   resource_size(&vcoreiii_switch_slave_registers)
				   );
		vcoreiii_gpio_set_alternate(VCOREIII_GPIO_BASE + 18 + SLAVE_CS, 0);
	} else {
		printk(KERN_INFO "VCore-III slave device ID %x found\n",
		       VTSS_X_DEVCPU_GCB_CHIP_REGS_CHIP_ID_PART_ID(slv_chip_id));

		_machine_name = "Vitesse VCore-III VSC7434 Dual";
	}
#ifndef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL_PI_TIMEOUT
	/* Disable PI timeout */
	vcoreiii_io_clr(VTSS_ICPU_CFG_PI_MST_PI_MST_CTRL(3), VTSS_F_ICPU_CFG_PI_MST_PI_MST_CTRL_DEVICE_PACED_TIMEOUT_ENA);
#endif
}
