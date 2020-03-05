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
 * Board specific code dealing with setup/initialization/shutdown
 */

#include <linux/init.h>
#include <linux/types.h>
#include <linux/device.h>

#include <asm/mach-vcoreiii/hardware.h>
#include <asm/mach-vcoreiii/vcoreiii_gpio.h>
#include <asm/idle.h>

extern const char *_machine_name;

static void vcoreiii_machine_restart(char *command)
{
	writel(0, VTSS_ICPU_CFG_SPI_MST_SW_MODE); /* Reset SPI SW mode */
        writel(VTSS_F_DEVCPU_GCB_DEVCPU_RST_REGS_SOFT_CHIP_RST_SOFT_CHIP_RST,
               VTSS_DEVCPU_GCB_DEVCPU_RST_REGS_SOFT_CHIP_RST);

        while (1)
                cpu_wait();
}

static void __init vcoreiii_pi_setup(void)
{
	/* Enable the PI interface */
	vcoreiii_io_set(VTSS_ICPU_CFG_CPU_SYSTEM_CTRL_GENERAL_CTRL,
			VTSS_F_ICPU_CFG_CPU_SYSTEM_CTRL_GENERAL_CTRL_IF_MASTER_PI_ENA);

        /* Configure Fast PI */
	vcoreiii_io_mask_set(VTSS_ICPU_CFG_PI_MST_PI_MST_CFG,
                             VTSS_M_ICPU_CFG_PI_MST_PI_MST_CFG_CLK_DIV,
                             VTSS_F_ICPU_CFG_PI_MST_PI_MST_CFG_CLK_DIV(2));
}

static void __init vcoreiii_setup_globals(void)
{
	vcoreiii_gpio_main =
		(struct vcoreiii_gpio_ctrl *)VTSS_DEVCPU_GCB_GPIO_GPIO_OUT_SET;
}
