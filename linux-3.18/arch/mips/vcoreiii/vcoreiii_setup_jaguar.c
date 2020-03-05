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
 * Jaguar glue.
 */

#define SUPPORT_VTSS_VCOREIII_JAGUAR

#include <linux/init.h>

#include <asm/reboot.h>

#include "vcoreiii_setup.h"

#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
extern void vcoreiii_jaguar_dual_setup(void);
#endif

void __init vcoreiii_jaguar_plat_setup(void)
{
	if (vcoreiii_check_chip_id()) {
		_machine_restart = vcoreiii_machine_restart;
		_machine_name = "Vitesse VCore-III VSC7434";
		vcoreiii_setup_globals();
#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
		vcoreiii_jaguar_dual_setup();
#endif /* CONFIG_VTSS_VCOREIII_JAGUAR_DUAL */
		vcoreiii_pi_setup();
	}
}
