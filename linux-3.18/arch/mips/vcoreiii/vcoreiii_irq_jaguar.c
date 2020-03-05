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
 * Jaguar glue.
 *
 */

#define SUPPORT_VTSS_VCOREIII_JAGUAR

#include "vcoreiii_irq.h"

#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
extern void __init vcoreiii_dual_irq_init(void);
#endif

void __init vcoreiii_jaguar_irq_init(void)
{
	vcoreiii_irq_init();
#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
	vcoreiii_dual_irq_init();
#endif
}
