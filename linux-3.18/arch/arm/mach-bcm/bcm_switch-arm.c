/*
 * Meraki common switch-arm support
 *
 * Copyright 2015 Cisco Systems
 * Dean Thomas <dean.thomas@meraki.com>
 * Adam Funkenbusch <adam.funkenbusch@meraki.net>
 *
 * Licensed under the GNU/GPL. See COPYING for details.
 */
#include "bcm_switch-arm.h"

#include <asm/siginfo.h>
#include <asm/signal.h>

static bool first_fault = true;

int switch_arm_abort_handler(unsigned long addr, unsigned int fsr,
				 struct pt_regs *regs)
{
	if (fsr == 0x1c06 && first_fault) {
		first_fault = false;

		/*
		 * These faults with code 0x1c06 happens for no good reason,
		 * possibly left over from the CFE boot loader.
		 */
		pr_warn("External imprecise Data abort at addr=%#lx, fsr=%#x ignored.\n",
		addr, fsr);

		/* Returning non-zero causes fault display and panic */
		return 0;
	}

	/* Others should cause a fault */
	return 1;
}
