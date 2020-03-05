/*
 *
 * VCore-III MTD platform driver
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
#include <linux/platform_device.h>
#include <linux/mtd/partitions.h>
#include <mtd/mtd-abi.h>
#include <linux/spi/spi.h>
#include <linux/spi/flash.h>

#include <asm/mach-vcoreiii/hardware.h>

#if defined(CONFIG_MTD_M25P80) && defined(CONFIG_SPI_MASTER)

static struct flash_platform_data vcoreiii_spi_flash_data = {
	.name		= "m25p80",
};

static struct spi_board_info vcoreiii_spi_board_info[] __initdata = {
	{
		/* the modalias must be the same as spi device driver name */
		.modalias = "m25p80", /* Name of spi_driver for this device */
		.max_speed_hz = 50000000,     /* max spi clock (SCK) speed in HZ */
		.bus_num = 0, /* Framework bus number */
		.chip_select = 1, /* Framework chip select. */
		.platform_data = &vcoreiii_spi_flash_data,
		.controller_data = (void *)1, /* platform driver chip select */
		.mode = SPI_MODE_0,
	},
};

static struct platform_device vcoreiii_spi_device = {
	.name			= "vcoreiii_spi",
	.id			= 0, /* Bus number */
};

int __init vcoreiii_spi_mtd_init(void)
{
	platform_device_register(&vcoreiii_spi_device);
	spi_register_board_info(vcoreiii_spi_board_info,
				ARRAY_SIZE(vcoreiii_spi_board_info));

	return 0;
}

module_init(vcoreiii_spi_mtd_init);

#endif /* CONFIG_MTD_M25P80 && CONFIG_SPI_MASTER */
