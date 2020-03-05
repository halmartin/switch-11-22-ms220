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
 * Luton26 glue.
 */

#define SUPPORT_VTSS_VCOREIII_LUTON26

#include <linux/init.h>

#include <asm/reboot.h>

#include "vcoreiii_setup.h"

void __init vcoreiii_luton26_plat_setup(void)
{
	if (vcoreiii_check_chip_id()) {
		_machine_restart = vcoreiii_machine_restart;
		if (VTSS_X_DEVCPU_GCB_CHIP_REGS_CHIP_ID_PART_ID
		    (readl(VTSS_DEVCPU_GCB_CHIP_REGS_CHIP_ID)) == 0x7425) {
			_machine_name = "Vitesse VCore-III VSC7425";
		} else {
			_machine_name = "Vitesse VCore-III VSC7427";
		}
		vcoreiii_setup_globals();
		vcoreiii_pi_setup();
	}
}
