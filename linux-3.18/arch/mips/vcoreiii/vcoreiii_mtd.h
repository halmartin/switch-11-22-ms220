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
 * This is the hardware specific support for NAND on VCore-III.
 */

#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/mtd/nand.h>
#include <mtd/mtd-abi.h>

#include <asm/mach-vcoreiii/hardware.h>

/* hardware specific access to control-lines */
static void vcoreiii_nand_cmd_ctl(struct mtd_info *mtd, int dat,
			   unsigned int ctrl)
{
	struct nand_chip *this = mtd->priv;
	int offset = (int)this->priv;

//	printk("ctrl 0x%02x cmd 0x%08x\n", ctrl, dat);

	if (ctrl & NAND_CTRL_CHANGE) {
		offset = 0;
		if(ctrl & NAND_CLE) offset |= NAND_ADDR_BIT_CLE;
		if(ctrl & NAND_ALE) offset |= NAND_ADDR_BIT_ALE;
		this->priv = (void *)offset;
	}
	if (dat != NAND_CMD_NONE) {
		//printk("ctrl: writeb(0x%02x, %p) - offset 0x%x base %p\n", dat & 0xff, this->IO_ADDR_W + offset, offset, this->IO_ADDR_W);
		writeb(dat, this->IO_ADDR_W + offset);
	}
}

static struct platform_nand_data vcoreiii_nand_platdata = {
	.chip = {
		.nr_chips = 1,
		.chip_offset = 0,
		.chip_delay = 30,
		.eccmode = NAND_ECC_SOFT_BCH,
	},
	.ctrl = {
		.cmd_ctrl = vcoreiii_nand_cmd_ctl,
	},
};
