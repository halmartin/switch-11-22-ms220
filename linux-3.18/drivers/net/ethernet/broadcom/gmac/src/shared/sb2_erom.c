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
 * Broadcom Home Networking Division 10/100 Mbit/s Ethernet
 * Saber2 sudo EROM
 *
 */
#include <typedefs.h>

uint32 sb2_erom[] = {
	// LOOP 1  :  #define  MFGID_BRCM   0x4bf   /* Manufacturer Ids (mfg) */
	//            #define  CC_CORE_ID   0x800   /* chipcommon core (cid) */
	0x4bf80001, 
	// crev = 0x2a, nsw = 0x0 (mask = 0x0x00f80000), nmw = 0x1 (mask = 0x0007c000), nsp = 0x1 (mask = 0x00003e00), nmp = 0x0 (mask = 0x000001f0)
	0x2a004201, 
	// First Slave Address Descriptor should be port 0: the main register space for the core
	// addr1 = 0x18000000 (mask = 0xfffff000), addrh = 0x0 (AD_AG32	=	0x00000008), sizeh = 0x0, 
	// sz = 0x0 (AD_SZ_MASK = 0x00000030), sizel = 0x00001000 (0x00001000 << (sz >> 4))
	0x18000005, 
	// Now get master wrappers (i = 0)
	// addr1 = 0x18120000 (AD_ADDR_MASK = 0xfffff000), addrh = 0x0 (AD_AG32	=	0x00000008), sizeh = 0x0,
	// sz = 0x0 (AD_SZ_MASK = 0x00000030), sizel = 0x00001000 (0x00001000 << (sz >> 4))
	0x181200c5,
	
	// LOOP 2  :  #define  MFGID_BRCM   0x4bf   /* Manufacturer Ids (mfg) */
	//            #define  GMAC_CORE_ID   0x82d   /* Gigabit MAC core */
	// cia = 0x4bf82d01
	// cid = 0x82d (cia & CIA_CID_MASK(0x000fff00)) >> CIA_CID_SHIFT(8), mfg = 0x4bf (cia & CIA_MFG_MASK(0xfff00000)) >> CIA_MFG_SHIFT(20)
	0x4bf82d01, 
	// cib = 0x04004211
	// crev = 0x04 (cib & CIB_REV_MASK(0xff000000)) >> CIB_REV_SHIFT(24), nmw = 0x01 (cib & CIB_NMW_MASK(0x0007c000)) >> CIB_NMW_SHIFT(14)
	// nsw = 0x0 (cib & CIB_NSW_MASK(0x00f80000)) >> CIB_NSW_SHIFT(19), nmp = 0x01 (cib & CIB_NMP_MASK(0x000001f0)) >> CIB_NMP_SHIFT(4)
	// nsp = 0x01 (cib & CIB_NSP_MASK(0x00003e00)) >> CIB_NSP_SHIFT(9)
	0x04004211,
	// mpd = 0x00000103
	0x00000103,
	// First Slave Address Descriptor should be port 0: the main register space for the core
	// addr1 = 0x18042000 (AD_ADDR_MASK = 0xfffff000), addrh = 0x0 (AD_AG32	=	0x00000008), sizeh = 0x0,
	// sz = 0x0 (AD_SZ_MASK = 0x00000030), sizel = 0x00001000 (0x00001000 << (sz >> 4))
	0x18042005,
	// Now get master wrappers (i = 0)
	// addr1 = 0x18110000 (AD_ADDR_MASK = 0xfffff000), addrh = 0x0 (AD_AG32	=	0x00000008), sizeh = 0x0,
	// sz = 0x0 (AD_SZ_MASK = 0x00000030), sizel = 0x00001000 (0x00001000 << (sz >> 4))
	0x181100c5,
	
	// LOOP 3  :  #define  MFGID_BRCM   0x4bf   /* Manufacturer Ids (mfg) */
	//            #define  GMAC_CORE_ID   0x82d   /* Gigabit MAC core */
	// cia = 0x4bf82d01
	// cid = 0x82d (cia & CIA_CID_MASK(0x000fff00)) >> CIA_CID_SHIFT(8), mfg = 0x4bf (cia & CIA_MFG_MASK(0xfff00000)) >> CIA_MFG_SHIFT(20)
	0x4bf82d01,
	// cib = 0x04004211
	// crev = 0x04 (cib & CIB_REV_MASK(0xff000000)) >> CIB_REV_SHIFT(24), nmw = 0x01 (cib & CIB_NMW_MASK(0x0007c000)) >> CIB_NMW_SHIFT(14)
	// nsw = 0x0 (cib & CIB_NSW_MASK(0x00f80000)) >> CIB_NSW_SHIFT(19), nmp = 0x01 (cib & CIB_NMP_MASK(0x000001f0)) >> CIB_NMP_SHIFT(4)
	// nsp = 0x01 (cib & CIB_NSP_MASK(0x00003e00)) >> CIB_NSP_SHIFT(9)
	0x04004211,
	// mpd = 0x00000203
	0x00000203,
	// First Slave Address Descriptor should be port 0: the main register space for the core
	// addr1 = 0x1804a000 (AD_ADDR_MASK = 0xfffff000), addrh = 0x0 (AD_AG32	=	0x00000008), sizeh = 0x0,
	// sz = 0x0 (AD_SZ_MASK = 0x00000030), sizel = 0x00001000 (0x00001000 << (sz >> 4))
	0x1804a005,
	// Now get master wrappers (i = 0)
	// addr1 = 0x18110000 (AD_ADDR_MASK = 0xfffff000), addrh = 0x0 (AD_AG32	=	0x00000008), sizeh = 0x0,
	// sz = 0x0 (AD_SZ_MASK = 0x00000030), sizel = 0x00001000 (0x00001000 << (sz >> 4))
	0x181110c5,
	
	// END of parse loop 0x0f = (ER_END(0x0e) | ER_VALID(0x01))
	0x0000000f
};
