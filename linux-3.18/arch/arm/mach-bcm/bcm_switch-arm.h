/*
 * Meraki switch-arm support
 *
 * Copyright 2015 Cisco Systems
 * Dean Thomas <dean.thomas@meraki.com>
 * Adam Funkenbusch <adam.funkenbusch@meraki.net>
 *
 * Licensed under the GNU/GPL. See COPYING for details.
 */
#ifndef BCM_SWITCH_ARM_H
#define BCM_SWITCH_ARM_H

#include <linux/of_platform.h>
#include <asm/hardware/cache-l2x0.h>

#include <asm/mach/arch.h>
#include <asm/siginfo.h>
#include <asm/signal.h>


int switch_arm_abort_handler(unsigned long addr, unsigned int fsr,
                                           struct pt_regs *regs);

#endif
