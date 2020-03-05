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
 * Luton26 glue.
 */

#ifdef CONFIG_MTD_NAND

#define SUPPORT_VTSS_VCOREIII_LUTON26

#define NAND_ADDR_BIT_ALE (1 << 2)
#define NAND_ADDR_BIT_CLE (1 << 3)

#include "vcoreiii_mtd.h"

static struct resource vcoreiii_nand_resource = {
	.start = 0x50000000 + 0x0000000, /* CS0 */
	.end   = 0x50000000 + 0x0000000 + NAND_ADDR_BIT_CLE*2,
	.flags = IORESOURCE_MEM,
};

static struct platform_device vcoreiii_nand = {
	.name		= "gen_nand",
	.num_resources	= 1,
	.resource	= &vcoreiii_nand_resource,
	.id		= 0,
	.dev		= {
		.platform_data = &vcoreiii_nand_platdata,
	}
};

int __init vcoreiii_luton26_mtd_init(void)
{
	if (vcoreiii_check_chip_id()) {

		/* Slow down CS=nand via waitcc - appx 77ns */
		vcoreiii_io_mask_set(VTSS_ICPU_CFG_PI_MST_PI_MST_CTRL(0),
				     VTSS_M_ICPU_CFG_PI_MST_PI_MST_CTRL_WAITCC,
				     VTSS_F_ICPU_CFG_PI_MST_PI_MST_CTRL_WAITCC(16));
		platform_device_register(&vcoreiii_nand);

		return 0;

	}

	return -ENODEV;
}

module_init(vcoreiii_luton26_mtd_init);

#endif /* CONFIG_MTD_NAND */
