/*
 * Meraki Wolfcastle support
 *
 * Copyright 2015 Cisco Systems
 * Dean Thomas <dean.thomas@meraki.com>
 *
 * Licensed under the GNU/GPL. See COPYING for details.
 */
#include "bcm_switch-arm.h"

#define CONFIG_MACH_HX4
#include <mach/iproc_regs.h>
#undef CONFIG_MACH_HX4

#include <linux/of_platform.h>
#include <asm/hardware/cache-l2x0.h>

#include <asm/io.h>
#include <asm/siginfo.h>
#include <asm/signal.h>

/*
 *  Reset the system
 */
static void wolfcastle_restart(enum reboot_mode mode, const char *cmd)
{
	void * __iomem reg_addr = ioremap_nocache(DMU_PCU_IPROC_CONTROL + DMU_CRU_RESET_BASE, 4);
	u32 reg = __raw_readl(reg_addr);
	reg &= ~((u32) 1 << 1); // trigger iproc-only reset
	__raw_writel(reg, reg_addr);
}

static int wolfcastle_restart_notify(struct notifier_block *this,
				 unsigned long mode, void *cmd)
{
	wolfcastle_restart(mode, cmd);
	return NOTIFY_DONE;
}

static struct notifier_block restart_handler;
static void __init wolfcastle_init_early(void)
{
	int ret;

	restart_handler.notifier_call = wolfcastle_restart_notify;
	restart_handler.priority = 128;
	ret = register_restart_handler(&restart_handler);
	if (ret) {
		printk(KERN_ERR "Wolfcastle cannot register restart handler\n");
	}

	/* Install our hook */
	hook_fault_code(16 + 6, switch_arm_abort_handler, SIGBUS, BUS_OBJERR,
			"imprecise external abort");
}

static const char __initconst *wolfcastle_dt_compat[] = {
	"meraki,wolfcastle",
	"brcm",
	NULL,
};

DT_MACHINE_START(WOLFCASTLE, "WOLFCASTLE")
	.l2c_aux_val	= 0,
	.l2c_aux_mask	= ~0,
	.init_early	= wolfcastle_init_early,
	.dt_compat	= wolfcastle_dt_compat,
MACHINE_END
