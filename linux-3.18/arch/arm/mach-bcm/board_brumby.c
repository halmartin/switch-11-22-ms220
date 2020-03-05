/*
 * Meraki Brumby support
 *
 * Copyright 2016 Cisco Systems
 *
 * Licensed under the GNU/GPL. See COPYING for details.
 */

#include "xldk/hr3/hr3_regs.h"
#include "bcm_switch-arm.h"

#include <asm/hardware/cache-l2x0.h>
#include <asm/io.h>
#include <asm/siginfo.h>
#include <asm/signal.h>
#include <linux/amba/pl330.h>
#include <linux/clk-provider.h>
#include <linux/clocksource.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>


extern void request_idm_timeout_interrupts(struct device_node *);

static void __iomem *dmu_pcu_base = NULL;
static void __iomem *idm_base = NULL;
static void __iomem *idm_base_phys = NULL;
static void __iomem *wrap_ctrl_base = NULL;
#ifdef CONFIG_PL330_DMA
static void __iomem *dmac_idm_base = NULL;
#endif

void __iomem *get_hr3_idm_base(void) {
	return idm_base;
}

void __iomem *get_hr3_idm_base_phys(void) {
	return idm_base_phys;
}

static void __init hr3_init_machine(void)
{
	struct device_node *np;
	struct platform_device *pdev = NULL;
	struct resource *res_mem;

	l2x0_of_init(0, ~0UL);

	np = of_find_compatible_node(NULL, NULL, "broadcom,hr3-dmu-pcu");
	if (!np) {
		printk(KERN_ERR "No DMU PCU node in device tree\n");
		return;
	}
	dmu_pcu_base = of_iomap(np, 0);
	if (!dmu_pcu_base) {
		printk(KERN_ERR "DMU PCU iomap error\n");
		return;
	}

	np = of_find_compatible_node(NULL, NULL, "broadcom,hr3-wrap-ctrl");
	if (!np) {
		printk(KERN_ERR "No wrap control node in device tree\n");
		return;
	}
	wrap_ctrl_base = of_iomap(np, 0);
	if (!wrap_ctrl_base) {
		printk(KERN_ERR "Wrap CTRL iomap error\n");
		return;
	}

	np = of_find_compatible_node(NULL, NULL, "broadcom,hr3-idm");
	if (!np) {
		printk(KERN_ERR "No IDM node in device tree\n");
		return;
	};
	idm_base = of_iomap(np, 0);
	if (!idm_base) {
		printk(KERN_ERR "IDM ioremap error\n");
		return;
	};

#ifdef CONFIG_PL330_DMA
	dmac_idm_base = idm_base + DMAC_IDM_RESET_OFFSET;
	writel_relaxed(readl_relaxed(dmac_idm_base) & 0xFFFFFFFE, dmac_idm_base);
#endif

	of_platform_populate(NULL, of_default_bus_match_table, NULL, NULL);

	pdev = of_find_device_by_node(np);
	if (!pdev) {
		printk(KERN_ERR "No IDM platform device found\n");
		return;
	}

	res_mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	idm_base_phys = (void __iomem *)res_mem->start;

	request_idm_timeout_interrupts(np);
};

static void __init brumby_init_timer(void)
{
	hook_fault_code(16 + 6, switch_arm_abort_handler, SIGBUS, BUS_OBJERR,
                    "imprecise external abort");

	of_clk_init(NULL);

    clocksource_of_init();
};

static void brumby_restart(enum reboot_mode mode, const char *cmd)
{
	void * __iomem reg_addr;
	u32 reg;

	reg_addr = (void * __iomem)(dmu_pcu_base + DMU_CRU_RESET_BASE);

	reg = readl_relaxed(reg_addr);
	reg &= ~((u32)1<<1);
	writel_relaxed(reg, reg_addr);
}

static const char __initconst *brumby_dt_compat[] = {
	"meraki,brumby",
    NULL,
};


DT_MACHINE_START(BRUMBY, "BRUMBY")
	.init_machine = hr3_init_machine,
	.init_time = brumby_init_timer,
	.dt_compat = brumby_dt_compat,
	.restart = brumby_restart,
MACHINE_END
