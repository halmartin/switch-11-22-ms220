/*
 * Copyright (C) 2014 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */


#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/clk-provider.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/clkdev.h>
#include <linux/of_address.h>

#include "clk-xgs-iproc.h"

#ifdef CONFIG_MACH_SB2
#error "Don't configure MACH_SB2. This driver needs to work with multiple chips."

#define IPROC_WRAP_IPROC_PLL_CTRL_1_OFFSET	0x04
#define IPROC_WRAP_IPROC_PLL_CTRL_3_OFFSET	0x0C
#define IPROC_WRAP_IPROC_PLL_CTRL_5_OFFSET	0x14
#define IPROC_WRAP_IPROC_PLL_CTRL_1__PDIV_R 27
#define IPROC_WRAP_IPROC_PLL_CTRL_3__NDIV_INT_R 20
#define IPROC_WRAP_IPROC_PLL_CTRL_5__CH1_MDIV_R 8
#define IPROC_WRAP_IPROC_PLL_CTRL_1__PDIV_WIDTH 4
#define IPROC_WRAP_IPROC_PLL_CTRL_3__NDIV_INT_WIDTH 10
#define IPROC_WRAP_IPROC_PLL_CTRL_5__CH1_MDIV_WIDTH 8

#else

#define IPROC_WRAP_GEN_PLL_CTRL1_OFFSET 0x4
#define IPROC_WRAP_GEN_PLL_CTRL2_OFFSET 0x8
#define IPROC_WRAP_GEN_PLL_CTRL1__NDIV_INT_R 0
#define IPROC_WRAP_GEN_PLL_CTRL1__NDIV_INT_WIDTH 10
#define IPROC_WRAP_GEN_PLL_CTRL1__PDIV_R 10
#define IPROC_WRAP_GEN_PLL_CTRL2__CH3_MDIV_R	8
#define IPROC_WRAP_GEN_PLL_CTRL2__CH3_MDIV_WIDTH 8

#endif /*CONFIG_MACH_SB2*/


struct iproc_gen_pll {
	struct clk_hw hw;
	void __iomem *base;
};

#define to_iproc_gen_pll(phw) container_of(phw, struct iproc_gen_pll, hw)


#if defined(CONFIG_MACH_SB2)
#error "Don't configure MACH_SB2. This driver needs to work with multiple chips."
static unsigned long iproc_gen_pll_recalc_rate(struct clk_hw *hw, unsigned long parent_rate)
{
	uint32_t ndiv, mdiv, pdiv;
	struct iproc_gen_pll *pll = to_iproc_gen_pll(hw);

    ndiv = (readl(pll->base + IPROC_WRAP_IPROC_PLL_CTRL_3_OFFSET) >> IPROC_WRAP_IPROC_PLL_CTRL_3__NDIV_INT_R) &
			((1 << IPROC_WRAP_IPROC_PLL_CTRL_3__NDIV_INT_WIDTH) -1);

    mdiv = (readl(pll->base + IPROC_WRAP_IPROC_PLL_CTRL_5_OFFSET) >> IPROC_WRAP_IPROC_PLL_CTRL_5__CH1_MDIV_R) &
			((1 << IPROC_WRAP_IPROC_PLL_CTRL_5__CH1_MDIV_WIDTH) -1);

    pdiv = (readl(pll->base + IPROC_WRAP_IPROC_PLL_CTRL_1_OFFSET) >> IPROC_WRAP_IPROC_PLL_CTRL_1__PDIV_R) &
			((1 << IPROC_WRAP_IPROC_PLL_CTRL_1__PDIV_WIDTH) -1);

    return (parent_rate * ndiv / pdiv / mdiv);
}
#else
static unsigned long iproc_gen_pll_recalc_rate(struct clk_hw *hw, unsigned long parent_rate)
{
	uint32_t ndiv, mdiv, pdiv;
	uint32_t pdiv_width = 0;
	struct iproc_gen_pll *pll = to_iproc_gen_pll(hw);

	if (of_find_compatible_node(NULL, NULL, "broadcom,hr3") ||
	    of_find_compatible_node(NULL, NULL, "broadcom,gh" ) ||
	    of_find_compatible_node(NULL, NULL, "broadcom,gh2")) {
		pdiv_width = 4;
	} else if (of_find_compatible_node(NULL, NULL, "broadcom,hx4") ||
	           of_find_compatible_node(NULL, NULL, "broadcom,hr2")) {
		pdiv_width = 3;
	} else {
		printk("This clock driver doesn't support your board. Check your device tree.\n");
	}

	ndiv = (readl(pll->base + IPROC_WRAP_GEN_PLL_CTRL1_OFFSET) >> IPROC_WRAP_GEN_PLL_CTRL1__NDIV_INT_R) &
			((1 << IPROC_WRAP_GEN_PLL_CTRL1__NDIV_INT_WIDTH) -1);
   	if(ndiv == 0)
	   	ndiv = 1 << IPROC_WRAP_GEN_PLL_CTRL1__NDIV_INT_WIDTH;

   	pdiv = (readl(pll->base + IPROC_WRAP_GEN_PLL_CTRL1_OFFSET) >> IPROC_WRAP_GEN_PLL_CTRL1__PDIV_R) &
			((1 << pdiv_width) -1);
   	if(pdiv == 0)
		pdiv = 1 << pdiv_width;

   	mdiv = (readl(pll->base + IPROC_WRAP_GEN_PLL_CTRL2_OFFSET) >> IPROC_WRAP_GEN_PLL_CTRL2__CH3_MDIV_R) &
			((1 << IPROC_WRAP_GEN_PLL_CTRL2__CH3_MDIV_WIDTH) -1);
   	if(mdiv == 0)
	   	mdiv = 1 << IPROC_WRAP_GEN_PLL_CTRL2__CH3_MDIV_WIDTH;

	return  (parent_rate * ndiv / pdiv / mdiv);
}
#endif

static const struct clk_ops iproc_gen_pll_ops = {
	.recalc_rate = iproc_gen_pll_recalc_rate,
};

void __init iproc_genpll_setup(struct device_node *node)
{
	int ret;
	struct clk *clk;
	struct iproc_gen_pll *pll;
	struct clk_init_data init;
	const char *parent_name;

	pll = kzalloc(sizeof(*pll), GFP_KERNEL);
	if (WARN_ON(!pll))
		return;

	pll->base = of_iomap(node, 0);
	if (WARN_ON(!pll->base))
		goto err_free_pll;

	init.name = node->name;
	init.ops = &iproc_gen_pll_ops;
	init.flags = 0;
	parent_name = of_clk_get_parent_name(node, 0);
	init.parent_names = (parent_name ? &parent_name : NULL);
	init.num_parents = (parent_name ? 1 : 0);
	pll->hw.init = &init;

	clk = clk_register(NULL, &pll->hw);
	if (WARN_ON(IS_ERR(clk)))
		goto err_iounmap;

	ret = of_clk_add_provider(node, of_clk_src_simple_get, clk);
	if (WARN_ON(ret))
		goto err_clk_unregister;

	return;

err_clk_unregister:
	clk_unregister(clk);
err_iounmap:
	iounmap(pll->base);
err_free_pll:
	kfree(pll);
}

CLK_OF_DECLARE(iproc_genpll, "brcm,iproc-genpll", iproc_genpll_setup);
