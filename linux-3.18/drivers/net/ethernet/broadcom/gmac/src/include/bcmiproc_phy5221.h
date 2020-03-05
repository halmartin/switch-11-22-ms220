/*
 * Copyright (C) 2013, Broadcom Corporation. All Rights Reserved.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * These routines provide access to the external phy
 *
 */

#ifndef _bcm_iproc_phy5221_h_
#define _bcm_iproc_phy5221_h_


/* ---- Include Files ---------------------------------------------------- */
#include <typedefs.h>

#define PHY_AUX_MULTIPLE_PHYr_BANK		0x0000
#define PHY_AUX_MULTIPLE_PHYr_ADDR		0x1e

#define PHY522X_SUPER_ISOLATE_MODE    (1<<3)

/* ---- External Function Prototypes ------------------------------------- */

extern int phy5221_wr_reg(uint eth_num, uint phyaddr, uint16 reg_bank,
				uint8 reg_addr, uint16 *data);
extern int phy5221_rd_reg(uint eth_num, uint phyaddr, uint16 reg_bank,
				uint8 reg_addr, uint16 *data);
extern int phy5221_mod_reg(uint eth_num, uint phyaddr, uint16 reg_bank,
				uint8 reg_addr, uint16 data, uint16 mask);
extern int phy5221_init(uint eth_num, uint phyaddr);
extern int phy5221_link_get(uint eth_num, uint phyaddr, int *link);
extern int phy5221_enable_set(uint eth_num, uint phyaddr, int enable);
extern int phy5221_speed_get(uint eth_num, uint phyaddr, int *speed, int *duplex);

#endif	/* _bcm_iproc_phy5221_h_ */
