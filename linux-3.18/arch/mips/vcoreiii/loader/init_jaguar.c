/*
 *
 * VCore-III ROM Loader Jaguar initialization
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

#include <vtss_jaguar_regs_common.h>
#include <vtss_jaguar_core_regs.h>

#define LOADER_BUILD_VCOREIII_JAGUAR 1
#define MIPS_VCOREIII_MEMORY_16BIT 1
#define EXPECTED_CHIP_ID 0x7460
#define VTSS_DEVCPU_PI_PI_PI_MODE            VTSS_IOREG(VTSS_TO_DEVCPU_PI,0x3)

#define VTSS_MACRO_CTRL_PLL5G_STATUS_PLL5G_STATUS0  VTSS_IOREG(VTSS_TO_HSIO,0x6)
#define  VTSS_F_MACRO_CTRL_PLL5G_STATUS_PLL5G_STATUS0_LOCK_STATUS  VTSS_BIT(0)

#define VTSS_MACRO_CTRL_PLL5G_CFG_PLL5G_CFG0  VTSS_IOREG(VTSS_TO_HSIO,0x0)
#define VTSS_MACRO_CTRL_PLL5G_CFG_PLL5G_CFG2  VTSS_IOREG(VTSS_TO_HSIO,0x2)

#define  VTSS_F_MACRO_CTRL_PLL5G_CFG_PLL5G_CFG0_CPU_CLK_DIV(x)  VTSS_ENCODE_BITFIELD(x,6,6)
#define  VTSS_M_MACRO_CTRL_PLL5G_CFG_PLL5G_CFG0_CPU_CLK_DIV     VTSS_ENCODE_BITMASK(6,6)
#define  VTSS_X_MACRO_CTRL_PLL5G_CFG_PLL5G_CFG0_CPU_CLK_DIV(x)  VTSS_EXTRACT_BITFIELD(x,6,6)

/* Micron 1Gb MT47H64M16-3 8Meg x 16 x 8 banks, DDR-533@CL4 @ 4.80ns */
#define VC3_MPAR_bank_addr_cnt    3
#define VC3_MPAR_row_addr_cnt     13
#define VC3_MPAR_col_addr_cnt     10
#define VC3_MPAR_tREFI            1625
#define VC3_MPAR_tRAS_min         9
#define VC3_MPAR_CL               4
#define VC3_MPAR_tWTR             2
#define VC3_MPAR_tRC              12
#define VC3_MPAR_tFAW             11
#define VC3_MPAR_tRP              4
#define VC3_MPAR_tRRD             3
#define VC3_MPAR_tRCD             4
#define VC3_MPAR_tRPA             4
#define VC3_MPAR_tRP              4
#define VC3_MPAR_tMRD             2
#define VC3_MPAR_tRFC             27
#define VC3_MPAR__400_ns_dly      84
#define VC3_MPAR_tWR              4

#define SLV_ADDR(addr) (*(volatile ulong *)((((ulong)(&addr))+(VTSS_PI_CS3_TO - VTSS_IO_ORIGIN1_OFFSET))))

static inline void init_pi(void);

static inline void
init_gpio(void)
{
	/* Place PHY in reset (low, GPIO 12, MS220-48 / MS320-24 / MS320-48 / MS42),
	 * turn amber power LED on (high, GPIO 23, dual-chip platforms),
	 * unselect slave chip (if any) (high, GPIO 21, dual-chip platforms),
	 * turn on fan (high, GPIO 20, MS220-48),
	 * turn amber power LED on (high, GPIO 20, MS320-24).
	 *
	 * This incidentally turns on the green power LED for
	 * MS320-24's (GPIO 21) */
	VTSS_DEVCPU_GCB_GPIO_GPIO_OUT = (VTSS_BIT(20) | VTSS_BIT(21) |
					 VTSS_BIT(23));
	VTSS_DEVCPU_GCB_GPIO_GPIO_OE = (VTSS_BIT(12) | VTSS_BIT(20) |
					VTSS_BIT(21) | VTSS_BIT(23));

	/* Enable UART_RX and UART_TX - bit 10 + 11 */
	/* Enable LED_CLK and LED_DO - bit 4 + 5 */

	VTSS_DEVCPU_GCB_GPIO_GPIO_ALT(0) |= (VTSS_BIT(11) | VTSS_BIT(10) |
                                             VTSS_BIT(4) | VTSS_BIT(5));
	VTSS_DEVCPU_GCB_GPIO_GPIO_ALT(1) &= ~(VTSS_BIT(11) | VTSS_BIT(10) |
					      VTSS_BIT(4) | VTSS_BIT(5));
}

#include "init.h"

/* Note: This function can only be called after the parallel interface
   has been set up. */
static inline int
detect_slave(void)
{
	/* Unset error bit -- we use this to detect failure of read */
	VTSS_ICPU_CFG_PI_MST_PI_MST_STATUS(3) |= VTSS_F_ICPU_CFG_PI_MST_PI_MST_STATUS_TIMEOUT_ERR_STICKY;
	if ((VTSS_X_DEVCPU_GCB_CHIP_REGS_CHIP_ID_PART_ID
		 (SLV_ADDR(VTSS_DEVCPU_GCB_CHIP_REGS_CHIP_ID)) != EXPECTED_CHIP_ID) ||
		(VTSS_ICPU_CFG_PI_MST_PI_MST_STATUS(3) & VTSS_F_ICPU_CFG_PI_MST_PI_MST_STATUS_TIMEOUT_ERR_STICKY))
		return 0;
	return 1;
} __attribute__((always_inline))

static inline void
init_pi(void)
{
	ANNOUNCE_PROGRESS();

	VTSS_ICPU_CFG_PI_MST_PI_MST_CFG |=
		(VTSS_ICPU_CFG_PI_MST_PI_MST_CFG &
		 ~VTSS_M_ICPU_CFG_PI_MST_PI_MST_CFG_CLK_DIV) |
		VTSS_F_ICPU_CFG_PI_MST_PI_MST_CFG_CLK_DIV(0x1f);

	VTSS_ICPU_CFG_CPU_SYSTEM_CTRL_GENERAL_CTRL |=
		VTSS_F_ICPU_CFG_CPU_SYSTEM_CTRL_GENERAL_CTRL_IF_MASTER_PI_ENA;

	/* Enable 2048-cycle PI bus timeout on slave PI interface -- CPU hangs on failure otherwise */
	VTSS_ICPU_CFG_PI_MST_PI_MST_CTRL(3) |= VTSS_F_ICPU_CFG_PI_MST_PI_MST_CTRL_DEVICE_PACED_TIMEOUT_ENA
		| VTSS_F_ICPU_CFG_PI_MST_PI_MST_CTRL_DEVICE_PACED_TIMEOUT(7);

	/* Enable CS3 slave chip select - bit 21 */
	VTSS_DEVCPU_GCB_GPIO_GPIO_ALT(0) |= VTSS_BIT(21);
	VTSS_DEVCPU_GCB_GPIO_GPIO_ALT(1) &= ~VTSS_BIT(21);

	SLV_ADDR(VTSS_DEVCPU_GCB_DEVCPU_RST_REGS_SOFT_CHIP_RST) =
		VTSS_F_DEVCPU_GCB_DEVCPU_RST_REGS_SOFT_CHIP_RST_SOFT_CHIP_RST;

	PAUSE();
	PAUSE();
	PAUSE();

	SLV_ADDR(VTSS_DEVCPU_PI_PI_PI_MODE) = 0x18181818;
	SLV_ADDR(VTSS_DEVCPU_PI_PI_PI_MODE) = 0x18181818;

	VTSS_ICPU_CFG_PI_MST_PI_MST_CTRL(3) |= 0x00C200B3;

	if (!detect_slave()) {
		ANNOUNCE_LITERAL(" not found\n");
		VTSS_DEVCPU_GCB_GPIO_GPIO_ALT(0) &= ~VTSS_BIT(21);
		/* Assume we're MS320-24: turn off green LED (gpio 21). */
		VTSS_DEVCPU_GCB_GPIO_GPIO_OUT &= ~VTSS_BIT(21);
	} else {
		ANNOUNCE_OK();
	}
}

static inline void
init_board(void)
{
	register u_int16_t data;
	register int32_t result;
	register int i;

	ANNOUNCE_PROGRESS();

	VTSS_DEVCPU_GCB_GPIO_GPIO_OUT_SET = VTSS_BIT(12); /* Unreset PHY */

	data = read_mii(0, 0, 0);	/* Read MII register zero */
	data |= 0x8000;			/* Set SW reset */
	write_mii(0, 0, 0, data);	/* Reset the PHY */

	for (i = 0; i < 1000000; i++) {
		result = read_mii(0, 0, 0); /* Read back the value */
		if (result < 0)
			continue;	/* Loop if the PHY is busy */
	if ((result & 0x8000) == 0)
		break;		/* Exit the loop when the reset is done */
	}

	if (result < 0) {
		uart_puts(" phy reset failed\n");
		return;			/* Don't mess with it if reset failed */
	}

	write_mii(0, 0, 31, 16); /* Address GPIO space */

	write_mii(0, 0, 13, 0x0003); /* Set SFP0_SD as controlled by GPIO */
	write_mii(0, 0, 17, 0x0001); /* Enable the output */
	write_mii(0, 0, 16, 0x0001); /* Set the output, fan is on */

	write_mii(0, 0, 31, 0); /* Address page 0 */

	/*
	 * Initialize the LEDs on the SGPIO controller
	 */

	VTSS_DEVCPU_GCB_SIO_CTRL_SIO_PORT_ENABLE(1) = 0xffffffff; /* Enable all */
	VTSS_DEVCPU_GCB_SIO_CTRL_SIO_CLOCK(1) = 0x14; /* Set clock to 12.5MHz */
	VTSS_DEVCPU_GCB_SIO_CTRL_SIO_CONFIG(1) =
	  VTSS_F_DEVCPU_GCB_SIO_CTRL_SIO_CONFIG_SIO_BURST_GAP(0x1F) |
	  VTSS_F_DEVCPU_GCB_SIO_CTRL_SIO_CONFIG_SIO_PORT_WIDTH(2-1) |
	  VTSS_F_DEVCPU_GCB_SIO_CTRL_SIO_CONFIG_SIO_AUTO_REPEAT;
	for (i = 0; i < 32; i++)
	  VTSS_DEVCPU_GCB_SIO_CTRL_SIO_PORT_CONFIG(1, i) = 0x249; /* Forced 1 */

	/*
	 * Initialize the LEDs on the secondary CPU
	 */

	if (detect_slave()) {
		SLV_ADDR(VTSS_DEVCPU_GCB_GPIO_GPIO_ALT(0)) |= VTSS_BIT(4) | VTSS_BIT(5);
		SLV_ADDR(VTSS_DEVCPU_GCB_GPIO_GPIO_ALT(1)) &=
			~(VTSS_BIT(4) | VTSS_BIT(5));

		SLV_ADDR(VTSS_DEVCPU_GCB_SIO_CTRL_SIO_PORT_ENABLE(1)) = 0xffffffff; /* Enable all */
		SLV_ADDR(VTSS_DEVCPU_GCB_SIO_CTRL_SIO_CLOCK(1)) = 0x14; /* Set clock to 12.5MHz */
		SLV_ADDR(VTSS_DEVCPU_GCB_SIO_CTRL_SIO_CONFIG(1)) =
			VTSS_F_DEVCPU_GCB_SIO_CTRL_SIO_CONFIG_SIO_BURST_GAP(0x1F) |
			VTSS_F_DEVCPU_GCB_SIO_CTRL_SIO_CONFIG_SIO_PORT_WIDTH(2-1) |
			VTSS_F_DEVCPU_GCB_SIO_CTRL_SIO_CONFIG_SIO_AUTO_REPEAT;
		for (i = 0; i < 32; i++)
			SLV_ADDR(VTSS_DEVCPU_GCB_SIO_CTRL_SIO_PORT_CONFIG(1, i)) =
				0x249; /* Forced 1 */
	}

	ANNOUNCE_OK();
}

u_int32_t *
init_system_jaguar1(void)
{
    return init_system();
}
