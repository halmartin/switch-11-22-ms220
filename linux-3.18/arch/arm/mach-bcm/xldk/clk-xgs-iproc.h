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

#ifndef _CLK_IPROC_H
#define _CLK_IPROC_H

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/of.h>
#include <linux/clk-provider.h>

#include <linux/clk.h>


#define IPROC_CLK_NAME_LEN 25
#define IPROC_CLK_INVALID_OFFSET 0xffffffff
#define bit_mask(width) ((1 << (width)) - 1)

/* clock should not be disabled at runtime */
#define IPROC_CLK_AON BIT(0)

/* PLL requires gating through ASIU */
#define IPROC_CLK_PLL_ASIU BIT(1)

/* PLL has fractional part of the NDIV */
#define IPROC_CLK_PLL_HAS_NDIV_FRAC BIT(2)
/* Fix me: defined in clk-provider.h */

/*
 * Parameters for VCO frequency configuration
 *
 * VCO frequency =
 * ((ndiv_int + ndiv_frac / 2^20) * (ref freqeuncy  / pdiv)
 */
struct iproc_pll_vco_freq_param {
	unsigned long rate;
	unsigned int ndiv_int;
	unsigned int ndiv_frac;
	unsigned int pdiv;
};

struct iproc_clk_reg_op {
	unsigned int offset;
	unsigned int shift;
	unsigned int width;
};

/*
 * Clock gating control at the top ASIU level
 */
struct iproc_asiu_gate {
	unsigned int offset;
	unsigned int en_shift;
};

/*
 * Control of powering on/off of a PLL
 *
 * Before powering off a PLL, input isolation (ISO) needs to be enabled
 */
struct iproc_pll_aon_pwr_ctrl {
	unsigned int offset;
	unsigned int pwr_width;
	unsigned int pwr_shift;
	unsigned int iso_shift;
};

/*
 * Control of the PLL reset, with Ki, Kp, and Ka parameters
 */
struct iproc_pll_reset_ctrl {
	unsigned int offset;
	unsigned int reset_shift;
	unsigned int p_reset_shift;
	unsigned int ki_shift;
	unsigned int ki_width;
	unsigned int kp_shift;
	unsigned int kp_width;
	unsigned int ka_shift;
	unsigned int ka_width;
};

struct iproc_pll_vco_ctrl {
	unsigned int u_offset;
	unsigned int l_offset;
};

/*
 * Main PLL control parameters
 */
struct iproc_pll_ctrl {
	unsigned long flags;
	struct iproc_pll_aon_pwr_ctrl aon;
	struct iproc_asiu_gate asiu;
	struct iproc_pll_reset_ctrl reset;
	struct iproc_clk_reg_op ndiv_int;
	struct iproc_clk_reg_op ndiv_frac;
	struct iproc_clk_reg_op pdiv;
	struct iproc_pll_vco_ctrl vco_ctrl;
	struct iproc_clk_reg_op status;
};

/*
 * Controls enabling/disabling a PLL derived clock
 */
struct iproc_clk_enable_ctrl {
	unsigned int offset;
	unsigned int enable_shift;
	unsigned int hold_shift;
	unsigned int bypass_shift;
};

/*
 * Main clock control parameters for clocks derived from the PLLs
 */
struct iproc_clk_ctrl {
	unsigned int channel;
	unsigned long flags;
	struct iproc_clk_enable_ctrl enable;
	struct iproc_clk_reg_op mdiv;
};

/*
 * Divisor of the ASIU clocks
 */
struct iproc_asiu_div {
	unsigned int offset;
	unsigned int en_shift;
	unsigned int high_shift;
	unsigned int high_width;
	unsigned int low_shift;
	unsigned int low_width;
};

extern void __init iproc_armpll_setup(struct device_node *node);
extern void __init iproc_pll_setup(struct device_node *node,
		const struct iproc_pll_ctrl *ctrl,
		const struct iproc_pll_vco_freq_param *vco_param,
		unsigned int num_freqs);
extern void __init iproc_clk_setup(struct device_node *node,
		const struct iproc_clk_ctrl *ctrl, unsigned int num_clks);
extern void __init iproc_asiu_setup(struct device_node *node,
		const struct iproc_asiu_div *div,
		const struct iproc_asiu_gate *gate, unsigned int num_clks);

#endif /* _CLK_IPROC_H */
