/*
 * $Copyright Open Broadcom Corporation$
 *
 * Broadcom Home Networking Division 10/100 Mbit/s Ethernet
 * Greyhound2 sudo EROM
 *
 */
#include <typedefs.h>

uint32 gh2_erom[] = {
	//#define CC_CORE_ID		0x800		/* chipcommon core */
	0x4bf80001, 0x2a004201, 0x18000005, 0x181200c5,
	//#define	GMAC_CORE_ID		0x82d		/* Gigabit MAC core */
	0x4bf82d01, 0x04004211, 0x00000103, 0x18042005, 0x181100c5,
	0x0000000f
};

