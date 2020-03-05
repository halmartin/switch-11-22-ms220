/*
 *
 * VCore-III MTD NAND hardware-specific driver
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
 * Jaguar glue.
 */

#ifdef CONFIG_MTD_NAND

#define SUPPORT_VTSS_VCOREIII_JAGUAR

#define NAND_ADDR_BIT_ALE (1 << 13)
#define NAND_ADDR_BIT_CLE (1 << 14)

#include "vcoreiii_mtd.h"

#include <asm/mach-vcoreiii/vcoreiii_gpio.h>

static struct resource vcoreiii_nand_resource[] = {
	{
		.start = 0x50000000 + 0x4000000, /* CS1 */
		.end   = 0x50000000 + 0x4000000 + NAND_ADDR_BIT_CLE*2,
		.flags = IORESOURCE_MEM,
	},
};

static struct platform_device vcoreiii_nand_cs1 = {
	.name		= "gen_nand",
	.num_resources	= 1,
	.resource	= &vcoreiii_nand_resource[0],
	.id		= 0,
	.dev		= {
		.platform_data = &vcoreiii_nand_platdata,
	}
};

static struct platform_device *vcoreiii_nand[] __initdata = {
	&vcoreiii_nand_cs1,
};

static int __init vcoreiii_jaguar_mtd_init(void)
{
	if (vcoreiii_check_chip_id()) {

		/* Request the GPIOs and set alternate */
		gpio_request(19, "n_CS1");
		vcoreiii_gpio_set_alternate(19, 1);

                /* Pin 20 is used as a GPIO on the MS320-24
                   platform. */
                vcoreiii_gpio_set_alternate(20, 0);

		/* Slow down Chip select via waitcc - appx 77ns */
		vcoreiii_io_mask_set(VTSS_ICPU_CFG_PI_MST_PI_MST_CTRL(1),
				     VTSS_M_ICPU_CFG_PI_MST_PI_MST_CTRL_WAITCC,
				     VTSS_F_ICPU_CFG_PI_MST_PI_MST_CTRL_WAITCC(16));

		platform_add_devices(vcoreiii_nand, ARRAY_SIZE(vcoreiii_nand));

		return 0;
	}

	return -ENODEV;
}

module_init(vcoreiii_jaguar_mtd_init);

#endif /* CONFIG_MTD_NAND */
