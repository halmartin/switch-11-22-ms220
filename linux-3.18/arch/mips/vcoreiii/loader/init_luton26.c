/*
 *
 * VCore-III ROM Loader Luton initialization
 *
 * Copyright (C) 2011 Meraki, Inc.
 * Author: Kevin Paul Herbert <kph@meraki.net>
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
 */

#include <vtss_luton26_core_regs.h>

#define LOADER_BUILD_VCOREIII_LUTON26 1
#define EXPECTED_CHIP_ID 0x7427


#define VTSS_MACRO_CTRL_PLL5G_STATUS_PLL5G_STATUS0  VTSS_IOREG(VTSS_TO_MACRO_CTRL,0x6)
#define  VTSS_F_MACRO_CTRL_PLL5G_STATUS_PLL5G_STATUS0_LOCK_STATUS  VTSS_BIT(0)

#define VTSS_MACRO_CTRL_PLL5G_CFG_PLL5G_CFG0  VTSS_IOREG(VTSS_TO_MACRO_CTRL,0x0)
#define VTSS_MACRO_CTRL_PLL5G_CFG_PLL5G_CFG2  VTSS_IOREG(VTSS_TO_MACRO_CTRL,0x2)

#define  VTSS_F_MACRO_CTRL_PLL5G_CFG_PLL5G_CFG0_CPU_CLK_DIV(x)  VTSS_ENCODE_BITFIELD(x,6,6)
#define  VTSS_M_MACRO_CTRL_PLL5G_CFG_PLL5G_CFG0_CPU_CLK_DIV     VTSS_ENCODE_BITMASK(6,6)
#define  VTSS_X_MACRO_CTRL_PLL5G_CFG_PLL5G_CFG0_CPU_CLK_DIV(x)  VTSS_EXTRACT_BITFIELD(x,6,6)

/* Micron 1Gb MT47H128M8-3 16Meg x 8 x 8 banks, DDR-533@CL4 @ 4.80ns */
#define VC3_MPAR_bank_addr_cnt    3
#define VC3_MPAR_row_addr_cnt     14
#define VC3_MPAR_col_addr_cnt     10
#define VC3_MPAR_tREFI            1625
#define VC3_MPAR_tRAS_min         9
#define VC3_MPAR_CL               5
#define VC3_MPAR_tWTR             2
#define VC3_MPAR_tRC              12
#define VC3_MPAR_tFAW             8
#define VC3_MPAR_tRP              4
#define VC3_MPAR_tRRD             2
#define VC3_MPAR_tRCD             4
#define VC3_MPAR_tRPA             4
#define VC3_MPAR_tRP              4
#define VC3_MPAR_tMRD             2
#define VC3_MPAR_tRFC             27
#define VC3_MPAR__400_ns_dly      84
#define VC3_MPAR_tWR              4

#include <linux/types.h>

static inline void
init_gpio(void)
{
    /*
     * Enable UART_RX and UART_TX - bit 31 + 30
     * Enable SGPIO SIO_CLO and SIO_D0 - bit 2 + 0
     */
    VTSS_DEVCPU_GCB_GPIO_GPIO_ALT(0) |= VTSS_BIT(31) | VTSS_BIT(30) |
	VTSS_BIT(2) | VTSS_BIT(0);
    VTSS_DEVCPU_GCB_GPIO_GPIO_ALT(1) &= ~(VTSS_BIT(31)| VTSS_BIT(30) |
					  VTSS_BIT(2) | VTSS_BIT(0));
}

static inline void
init_pi(void)
{
    /* No PI to deal with */
}

#include "init.h"

static inline void
init_board(void)
{
    register u_int16_t data;
    register int32_t result;
    register int i;

    ANNOUNCE_PROGRESS();

    data = read_mii(1, 12, 0);	/* Read MII register zero */
    data |= 0x8000;		/* Set SW reset */

    if (get_chip_id() != 0x7425) /* Meraki 7425-based boards lack an external PHY */
    {
        write_mii(1, 12, 0, data);	/* Reset the PHY */

        for (i = 0; i < 1000000; i++) {
            result = read_mii(1, 12, 0); /* Read back the value */
            if (result < 0)
                continue;		/* Loop if the PHY is busy */
            if ((result & 0x8000) == 0)
                break;		/* Exit the loop when the reset is done */
        }

        if (result < 0) {
            ANNOUNCE_LITERAL(" phy reset failed\n");
        } else {
            write_mii(1, 12, 31, 16);	/* Address GPIO space */
            write_mii(1, 12, 13, 0x0f00); /* Set GPIO13 and GPIO14 as GPIO */
            write_mii(1, 12, 17, 0x30);	/* Set GPIO13 and GPIO14 as outputs */
            write_mii(1, 12, 16, 0x20);	/* Turn on the orange LED */
            write_mii(1, 12, 31, 0);	/* Address page 0 */
        }
    }
    /*
     * Initialize the LEDs on the SGPIO controller
     */

    VTSS_DEVCPU_GCB_SIO_CTRL_SIO_PORT_ENABLE = 0xffffffff; /* Enable all */
    VTSS_DEVCPU_GCB_SIO_CTRL_SIO_CLOCK = 0x14; /* Set clock to 12.5MHz */
    VTSS_DEVCPU_GCB_SIO_CTRL_SIO_CONFIG =
	VTSS_F_DEVCPU_GCB_SIO_CTRL_SIO_CONFIG_SIO_BURST_GAP(0x1F) |
	VTSS_F_DEVCPU_GCB_SIO_CTRL_SIO_CONFIG_SIO_PORT_WIDTH(2-1) |
	VTSS_F_DEVCPU_GCB_SIO_CTRL_SIO_CONFIG_SIO_AUTO_REPEAT;
    for (i = 0; i < 32; i++) {
	if (i == 10 && get_chip_id() == 0x7425) /* Leave power orange LED enabled on MS220 */
	    VTSS_DEVCPU_GCB_SIO_CTRL_SIO_PORT_CONFIG(i) = 0x248;
	else
	    VTSS_DEVCPU_GCB_SIO_CTRL_SIO_PORT_CONFIG(i) = 0x249; /* Forced 1 */
    }

    ANNOUNCE_OK();
}

u_int32_t *
init_system_luton26(void)
{
    return init_system();
}

