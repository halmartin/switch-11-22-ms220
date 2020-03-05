/*
 * Meraki Hungry Hungry Hippo support
 *
 * Copyright 2015 Cisco Systems
 * Adam Funkenbusch <adam.funkenbusch@meraki.net>
 *
 * Licensed under the GNU/GPL. See COPYING for details.
 */
#include "bcm_switch-arm.h"

#include <linux/kernel.h>
#include <linux/of_platform.h>
#include <asm/hardware/cache-l2x0.h>

#include <asm/io.h>
#include <asm/siginfo.h>
#include <asm/signal.h>

#include <mach/socregs_nsp_open.h>


static void hungry_hungry_hippo_restart(enum reboot_mode mode, const char *cmd)
{
	void __iomem *reg_addr;
	u32 reg;

	/* drive gpios to tri-state by setting them all as inputs */
	reg_addr = ioremap_nocache(NSP_CHIPCOMMONA_GPIOOUTEN, 4);
	__raw_writel(0, reg_addr);

	/* trigger iproc SW reset */
	reg_addr = ioremap_nocache(NSP_CRU_CONTROL, 4);
	reg = __raw_readl(reg_addr);
	reg |= NSP_CRU_SW_RESET;
	__raw_writel(reg, reg_addr);
}

static int __init hungry_hungry_hippo_init_arch(void)
{
	void __iomem *reg_addr;
	uint32_t data;

	/* take Trident2 MAC out of reset */
	reg_addr = ioremap_nocache(NSP_CRU_GPIO_CONTROL0, 4);
	if (!reg_addr) {
		printk(KERN_ERR "%s: Failed to map CRU GPIO control register\n", __func__);
		return -ENOMEM;
	}
	data = ioread32(reg_addr);
	data |= 0x1 << 3;
	iowrite32(data, reg_addr);
	iounmap(reg_addr);
	reg_addr = ioremap_nocache(NSP_CHIPCOMMONA_GPIOOUT, 4);
	if (!reg_addr) {
		printk(KERN_ERR "%s: Failed to map GPIO output register\n", __func__);
		return -ENOMEM;
	}
	data = ioread32(reg_addr);
	data |= 0x1 << 3;
	iowrite32(data, reg_addr);
	iounmap(reg_addr);

	reg_addr = ioremap_nocache(NSP_CHIPCOMMONA_GPIOOUTEN, 4);
	if (!reg_addr) {
		printk(KERN_ERR "%s: Failed to map GPIO output enable register\n", __func__);
		return -ENOMEM;
	}
	data = ioread32(reg_addr);
	data |= 0x1 << 3;
	iowrite32(data, reg_addr);
	iounmap(reg_addr);

	return 0;
}
arch_initcall(hungry_hungry_hippo_init_arch);

static void __init hungry_hungry_hippo_init_early(void)
{
	/* Install our hook */
	hook_fault_code(16 + 6, switch_arm_abort_handler, SIGBUS, BUS_OBJERR,
			"imprecise external abort");
}

static const char __initconst *hungry_hungry_hippo_dt_compat[] = {
	"meraki,hungry-hungry-hippo",
	"brcm",
	NULL,
};

DT_MACHINE_START(HUNGRY_HUNGRY_HIPPO, "HUNGRY_HUNGRY_HIPPO")
	.l2c_aux_val	= 0,
	.l2c_aux_mask	= ~0,
	.init_early	= hungry_hungry_hippo_init_early,
	.restart	= hungry_hungry_hippo_restart,
	.dt_compat	= hungry_hungry_hippo_dt_compat,
MACHINE_END
