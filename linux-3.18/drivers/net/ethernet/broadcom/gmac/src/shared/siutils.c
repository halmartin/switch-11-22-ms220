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
 * Misc utility routines for accessing chip-specific features
 * of the SiliconBackplane-based Broadcom chips.
 *
 * $Id: siutils.c 328955 2012-04-23 09:06:12Z $
 */

#include <bcm_cfg.h>
#include <typedefs.h>
#include <bcmdefs.h>
#include <osl.h>
#include <bcmutils.h>
#include <siutils.h>
#include <bcmdevs.h>
#include <hndsoc.h>
#include <sbchipc.h>
#include <bcmnvram.h>
#include <pcicfg.h>
#include <sbsocram.h>

#include "siutils_priv.h"

/* local prototypes */
static si_info_t *si_doattach(si_info_t *sii, uint devid, osl_t *osh, void *regs,
                              uint bustype, void *sdh, char **vars, uint *varsz);
static bool si_buscore_setup(si_info_t *sii, chipcregs_t *cc, uint bustype, uint32 savewin,
	uint *origidx, void *regs);

static void si_nvram_process(si_info_t *sii, char *pvars);
/* dev path concatenation util */
static char *si_devpathvar(si_t *sih, char *var, int len, const char *name);
static bool _si_clkctl_cc(si_info_t *sii, uint mode);

/* global variable to indicate reservation/release of gpio's */
static uint32 si_gpioreservation = 0;

/* global flag to prevent shared resources from being initialized multiple times in si_attach() */

/*
 * Allocate a si handle.
 * devid - pci device id (used to determine chip#)
 * osh - opaque OS handle
 * regs - virtual address of initial core registers
 * bustype - pci/pcmcia/sb/sdio/etc
 * vars - pointer to a pointer area for "environment" variables
 * varsz - pointer to int to return the size of the vars
 */
si_t *
BCMATTACHFN(si_attach)(uint devid, osl_t *osh, void *regs,
                       uint bustype, void *sdh, char **vars, uint *varsz)
{
	si_info_t *sii;
	si_t *sih;

	/* alloc si_info_t */
	if ((sii = MALLOC(osh, sizeof (si_info_t))) == NULL) {
		SI_ERROR(("si_attach: malloc failed! malloced %d bytes\n", MALLOCED(osh)));
		return (NULL);
	}

	if (si_doattach(sii, devid, osh, regs, bustype, sdh, vars, varsz) == NULL) {
		MFREE(osh, sii, sizeof(si_info_t));
		SI_ERROR(("%s si_doattach() failed\n", __FUNCTION__));
		return (NULL);
	}
	sii->vars = vars ? *vars : NULL;
	sii->varsz = varsz ? *varsz : 0;

	sih = (si_t*)sii;
	printk("%s socitype(0x%x) chip(0x%x) chiprev(0x%x) chippkg(0x%x)\n",
			__FUNCTION__, sih->socitype, sih->chip, sih->chiprev, sih->chippkg);

	return (si_t *)sii;
}

static bool
BCMATTACHFN(si_buscore_setup)(si_info_t *sii, chipcregs_t *cc, uint bustype, uint32 savewin,
	uint *origidx, void *regs)
{
	bool pci, pcie;
	uint i;
	uint pciidx, pcieidx, pcirev, pcierev;

	cc = si_setcoreidx(&sii->pub, SI_CC_IDX);
	ASSERT((uintptr)cc);

	/* get chipcommon rev */
	sii->pub.ccrev = (int)si_corerev(&sii->pub);

	/* get chipcommon chipstatus */
	if (sii->pub.ccrev >= 11) {
		sii->pub.chipst = R_REG(sii->osh, &cc->chipstatus);
	}

	/* get chipcommon capabilites */
	sii->pub.cccaps = R_REG(sii->osh, &cc->capabilities);
	/* get chipcommon extended capabilities */
	if (sii->pub.ccrev >= 35) {
		sii->pub.cccaps_ext = R_REG(sii->osh, &cc->capabilities_ext);
	}

	/* get pmu rev and caps */
	if (sii->pub.cccaps & CC_CAP_PMU) {
		sii->pub.pmucaps = R_REG(sii->osh, &cc->pmucapabilities);
		sii->pub.pmurev = sii->pub.pmucaps & PCAP_REV_MASK;
	}

	SI_MSG(("Chipc: rev %d, caps 0x%x, chipst 0x%x pmurev %d, pmucaps 0x%x\n",
		sii->pub.ccrev, sii->pub.cccaps, sii->pub.chipst, sii->pub.pmurev,
		sii->pub.pmucaps));

	/* figure out bus/orignal core idx */
	sii->pub.buscoretype = NODEV_CORE_ID;
	sii->pub.buscorerev = (uint)NOREV;
	sii->pub.buscoreidx = BADIDX;

	pci = pcie = FALSE;
	pcirev = pcierev = (uint)NOREV;
	pciidx = pcieidx = BADIDX;

	for (i = 0; i < sii->numcores; i++) {
		uint cid, crev;

		si_setcoreidx(&sii->pub, i);
		cid = si_coreid(&sii->pub);
		crev = si_corerev(&sii->pub);

		/* Display cores found */
		SI_VMSG(("CORE[%d]: id 0x%x rev %d base 0x%x regs 0x%p\n",
		        i, cid, crev, sii->coresba[i], sii->regs[i]));

		/* find the core idx before entering this func. */
		if ((savewin && (savewin == sii->coresba[i])) ||
		    (regs == sii->regs[i])) {
			*origidx = i;
		}
	}

	SI_VMSG(("Buscore id/type/rev %d/0x%x/%d\n", sii->pub.buscoreidx, sii->pub.buscoretype,
	         sii->pub.buscorerev));

	/* return to the original core */
	si_setcoreidx(&sii->pub, *origidx);

	return TRUE;
}

static void
BCMATTACHFN(si_nvram_process)(si_info_t *sii, char *pvars)
{
	/* get boardtype and boardrev */
	switch (BUSTYPE(sii->pub.bustype)) {
	case SI_BUS:
		sii->pub.boardvendor = VENDOR_BROADCOM;
		if (pvars == NULL || ((sii->pub.boardtype = getintvar(pvars, "prodid")) == 0)) {
			if ((sii->pub.boardtype = getintvar(NULL, "boardtype")) == 0) {
				sii->pub.boardtype = 0xffff;
			}
		}
		break;
	}

	if (sii->pub.boardtype == 0) {
		SI_ERROR(("si_doattach: unknown board type\n"));
		ASSERT(sii->pub.boardtype);
	}

	sii->pub.boardrev = getintvar(pvars, "boardrev");
	sii->pub.boardflags = getintvar(pvars, "boardflags");
}

static si_info_t *
BCMATTACHFN(si_doattach)(si_info_t *sii, uint devid, osl_t *osh, void *regs,
                       uint bustype, void *sdh, char **vars, uint *varsz)
{
	struct si_pub *sih = &sii->pub;
	uint32 w, savewin;
	chipcregs_t *cc;
	char *pvars = NULL;
	uint origidx;
	ASSERT(GOODREGS(regs));

	bzero((uchar*)sii, sizeof(si_info_t));

	savewin = 0;
	sih->buscoreidx = BADIDX;
	sii->curmap = regs;
	sii->sdh = sdh;
	sii->osh = osh;

	/* find Chipcommon address */
	cc = (chipcregs_t *)REG_MAP(SI_ENUM_BASE, SI_CORE_SIZE);

	sih->bustype = bustype;
	if (bustype != BUSTYPE(bustype)) {
		SI_ERROR(("si_doattach: bus type %d does not match configured bus type %d\n",
			bustype, BUSTYPE(bustype)));
		return NULL;
	}

	/* ChipID recognition.
	 *   We assume we can read chipid at offset 0 from the regs arg.
	 *   If we add other chiptypes (or if we need to support old sdio hosts w/o chipcommon),
	 *   some way of recognizing them needs to be added here.
	 */
	if (!cc) {
		SI_ERROR(("%s: chipcommon register space is null \n", __FUNCTION__));
		return NULL;
	}
	w = R_REG(osh, &cc->chipid);
	printk("%s chipid: 0x%x\n", __FUNCTION__, w);
#if defined(CONFIG_MACH_IPROC_P7)
	sih->socitype = SOCI_AI;
	/* get chip id rev & pkg */
	sih->chip = w & 0xfffff;
	sih->chippkg = (w & CID_PKG_MASK) >> CID_PKG_SHIFT;
	w = R_REG(osh, &cc->capabilities);
	sih->chiprev = w & 0xff;
#else
	sih->socitype = (w & CID_TYPE_MASK) >> CID_TYPE_SHIFT;
	/* Might as wll fill in chip id rev & pkg */
	sih->chip = w & CID_ID_MASK;
	sih->chiprev = (w & CID_REV_MASK) >> CID_REV_SHIFT;
	sih->chippkg = (w & CID_PKG_MASK) >> CID_PKG_SHIFT;
	/* printk("%s chip: 0x%x; chiprev: 0x%x; chippkg: 0x%x\n", __FUNCTION__, sih->chip, sih->chiprev, sih->chippkg); */
#endif /* CONFIG_MACH_IPROC_P7 */

	sih->issim = IS_SIM(sih->chippkg);

	/* scan for cores */
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		SI_MSG(("Found chip type SB (0x%08x)\n", w));
		sb_scan(sih, regs, devid);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
	    SI_MSG(("Found chip type %s (0x%08x)\n", (CHIPTYPE(sih->socitype) == SOCI_AI) ? "AI" : "NS", w));
		ai_scan(sih, (void *)(uintptr)cc, devid);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		SI_MSG(("Found chip type UBUS (0x%08x), chip id = 0x%4x\n", w, sih->chip));
		ub_scan(sih, (void *)(uintptr)cc, devid);
	} else {
		SI_ERROR(("Found chip of unknown type (0x%08x)\n", w));
		return NULL;
	}
	
	/* no cores found, bail out */
	if (sii->numcores == 0) {
		SI_ERROR(("si_doattach: could not find any cores\n"));
		return NULL;
	}
	/* bus/core/clk setup */
	origidx = SI_CC_IDX;
	if (!si_buscore_setup(sii, cc, bustype, savewin, &origidx, regs)) {
		SI_ERROR(("si_doattach: si_buscore_setup failed\n"));
		goto exit;
	}

    spin_lock_init(&sih->sih_lock);

	/* Init nvram from flash if it exists */
	nvram_init((void *)sih);
	
	pvars = vars ? *vars : NULL;
	si_nvram_process(sii, pvars);

		/* bootloader should retain default pulls */
#ifndef BCM_BOOTLOADER
		if (sih->ccrev >= 20) {
			uint32 gpiopullup = 0, gpiopulldown = 0;
			cc = (chipcregs_t *)si_setcore(sih, CC_CORE_ID, 0);
			ASSERT(cc != NULL);

			W_REG(osh, &cc->gpiopullup, gpiopullup);
			W_REG(osh, &cc->gpiopulldown, gpiopulldown);
			si_setcoreidx(sih, origidx);
		}
#endif /* !BCM_BOOTLOADER */


	/* setup the GPIO based LED powersave register */
	if (sih->ccrev >= 16) {
		if ((w = getintvar(pvars, "leddc")) == 0) {
			w = DEFAULT_GPIOTIMERVAL;
		}
		si_corereg(sih, SI_CC_IDX, OFFSETOF(chipcregs_t, gpiotimerval), ~0, w);
	}

#if !defined(_CFE_) || defined(CFG_WL)
	/* enable GPIO interrupts when clocks are off */
	if (sih->ccrev >= 21) {
		uint32 corecontrol;
		corecontrol = si_corereg(sih, SI_CC_IDX, OFFSETOF(chipcregs_t, corecontrol),
		                         0, 0);
		corecontrol |= CC_ASYNCGPIO;
		si_corereg(sih, SI_CC_IDX, OFFSETOF(chipcregs_t, corecontrol),
		           corecontrol, corecontrol);
	}
#endif /* !_CFE_ || CFG_WL */

	return (sii);
exit:
	return NULL;
}

/* may be called with core in reset */
void
BCMATTACHFN(si_detach)(si_t *sih)
{
	si_info_t *sii;
	uint idx;

	sii = SI_INFO(sih);
	if (sii == NULL) {
		return;
	}

	if (BUSTYPE(sih->bustype) == SI_BUS) {
		for (idx = 0; idx < SI_MAXCORES; idx++) {
			if (sii->regs[idx]) {
				REG_UNMAP(sii->regs[idx]);
				sii->regs[idx] = NULL;
			}
		}
	}

	MFREE(sii->osh, sii, sizeof(si_info_t));
}

void *
si_osh(si_t *sih)
{
	si_info_t *sii;

	sii = SI_INFO(sih);
	return sii->osh;
}

void
si_setosh(si_t *sih, osl_t *osh)
{
	si_info_t *sii;

	sii = SI_INFO(sih);
	if (sii->osh != NULL) {
		SI_ERROR(("osh is already set....\n"));
		ASSERT(!sii->osh);
	}
	sii->osh = osh;
}

uint
si_intflag(si_t *sih)
{
	si_info_t *sii = SI_INFO(sih);

	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		return sb_intflag(sih);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		return R_REG(sii->osh, ((uint32 *)(uintptr)
			    (sii->oob_router + OOB_STATUSA)));
	}
	
    ASSERT(0);
    return 0;
}

uint
si_flag(si_t *sih)
{
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		return sb_flag(sih);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		return ai_flag(sih);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		return ub_flag(sih);
	}
	
    ASSERT(0);
    return 0;
}

void
si_setint(si_t *sih, int siflag)
{
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		sb_setint(sih, siflag);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		ai_setint(sih, siflag);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		ub_setint(sih, siflag);
	} else {
		ASSERT(0);
	}
}

uint
si_coreid(si_t *sih)
{
	si_info_t *sii;

	sii = SI_INFO(sih);
	return sii->coreid[sii->curidx];
}

uint
si_coreidx(si_t *sih)
{
	si_info_t *sii;

	sii = SI_INFO(sih);
	return sii->curidx;
}

/* return the core-type instantiation # of the current core */
uint
si_coreunit(si_t *sih)
{
	si_info_t *sii;
	uint idx;
	uint coreid;
	uint coreunit;
	uint i;

	sii = SI_INFO(sih);
	coreunit = 0;

	idx = sii->curidx;

	ASSERT(GOODREGS(sii->curmap));
	coreid = si_coreid(sih);

	/* count the cores of our type */
	for (i = 0; i < idx; i++) {
		if (sii->coreid[i] == coreid) {
			coreunit++;
		}
	}

	return (coreunit);
}

uint
si_corevendor(si_t *sih)
{
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		return sb_corevendor(sih);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		return ai_corevendor(sih);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		return ub_corevendor(sih);
	} 

    ASSERT(0);
    return 0;
}

bool
si_backplane64(si_t *sih)
{
	return ((sih->cccaps & CC_CAP_BKPLN64) != 0);
}

uint
si_corerev(si_t *sih)
{
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		return sb_corerev(sih);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		return ai_corerev(sih);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		return ub_corerev(sih);
	} 

    ASSERT(0);
    return 0;
}

/* return index of coreid or BADIDX if not found */
uint
si_findcoreidx(si_t *sih, uint coreid, uint coreunit)
{
	si_info_t *sii;
	uint found;
	uint i;

	sii = SI_INFO(sih);

	found = 0;

	for (i = 0; i < sii->numcores; i++) {
		if (sii->coreid[i] == coreid) {
			if (found == coreunit)
				return (i);
			found++;
		}
	}

	return (BADIDX);
}

/* return list of found cores */
uint
si_corelist(si_t *sih, uint coreid[])
{
	si_info_t *sii;

	sii = SI_INFO(sih);

	bcopy((uchar*)sii->coreid, (uchar*)coreid, (sii->numcores * sizeof(uint)));
	return (sii->numcores);
}

/* return current register mapping */
void *
si_coreregs(si_t *sih)
{
	si_info_t *sii;

	sii = SI_INFO(sih);
	ASSERT(GOODREGS(sii->curmap));

	return (sii->curmap);
}

/*
 * This function changes logical "focus" to the indicated core;
 * must be called with interrupts off.
 * Moreover, callers should keep interrupts off during switching out of and back to d11 core
 */
void *
si_setcore(si_t *sih, uint coreid, uint coreunit)
{
	uint idx;

	idx = si_findcoreidx(sih, coreid, coreunit);
	if (!GOODIDX(idx)) {
		return (NULL);
	}

	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		return sb_setcoreidx(sih, idx);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		return ai_setcoreidx(sih, idx);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		return ub_setcoreidx(sih, idx);
	} 

    ASSERT(0);
    return NULL;
}

void *
si_setcoreidx(si_t *sih, uint coreidx)
{
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		return sb_setcoreidx(sih, coreidx);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		return ai_setcoreidx(sih, coreidx);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		return ub_setcoreidx(sih, coreidx);
	} 

    ASSERT(0);
    return 0;
}

/* Turn off interrupt as required by sb_setcore, before switch core */
void *
si_switch_core(si_t *sih, uint coreid, uint *origidx, uint *intr_val)
{
	void *cc;
	si_info_t *sii;

	sii = SI_INFO(sih);

	if (SI_FAST(sii)) {
		/* Overloading the origidx variable to remember the coreid,
		 * this works because the core ids cannot be confused with
		 * core indices.
		 */
		*origidx = coreid;
		if (coreid == CC_CORE_ID) {
			return (void *)CCREGS_FAST(sii);
		} else if (coreid == sih->buscoretype) {
			return (void *)PCIEREGS(sii);
		}
	}
	INTR_OFF(sii, *intr_val);
	*origidx = sii->curidx;
	cc = si_setcore(sih, coreid, 0);
	ASSERT(cc != NULL);

	return cc;
}

/* restore coreidx and restore interrupt */
void
si_restore_core(si_t *sih, uint coreid, uint intr_val)
{
	si_info_t *sii;

	sii = SI_INFO(sih);
	if (SI_FAST(sii) && ((coreid == CC_CORE_ID) || (coreid == sih->buscoretype))) {
		return;
	}

	si_setcoreidx(sih, coreid);
	INTR_RESTORE(sii, intr_val);
}

int
si_numaddrspaces(si_t *sih)
{
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		return sb_numaddrspaces(sih);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		return ai_numaddrspaces(sih);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		return ub_numaddrspaces(sih);
	} 

    ASSERT(0);
    return 0;
}

uint32
si_addrspace(si_t *sih, uint asidx)
{
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		return sb_addrspace(sih, asidx);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		return ai_addrspace(sih, asidx);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		return ub_addrspace(sih, asidx);
	} 

    ASSERT(0);
    return 0;
}

uint32
si_addrspacesize(si_t *sih, uint asidx)
{
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		return sb_addrspacesize(sih, asidx);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		return ai_addrspacesize(sih, asidx);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		return ub_addrspacesize(sih, asidx);
	} 

    ASSERT(0);
    return 0;
}

void
si_coreaddrspaceX(si_t *sih, uint asidx, uint32 *addr, uint32 *size)
{
	/* Only supported for SOCI_AI */
	if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		ai_coreaddrspaceX(sih, asidx, addr, size);
	} else {
		*size = 0;
	}
}

uint32
si_core_cflags(si_t *sih, uint32 mask, uint32 val)
{
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		return sb_core_cflags(sih, mask, val);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		return ai_core_cflags(sih, mask, val);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		return ub_core_cflags(sih, mask, val);
	} 

    ASSERT(0);
    return 0;
}

void
si_core_cflags_wo(si_t *sih, uint32 mask, uint32 val)
{
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		sb_core_cflags_wo(sih, mask, val);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		ai_core_cflags_wo(sih, mask, val);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		ub_core_cflags_wo(sih, mask, val);
	} else {
		ASSERT(0);
	}
}

uint32
si_core_sflags(si_t *sih, uint32 mask, uint32 val)
{
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		return sb_core_sflags(sih, mask, val);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		return ai_core_sflags(sih, mask, val);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		return ub_core_sflags(sih, mask, val);
	} 

    ASSERT(0);
    return 0;
}

bool
si_iscoreup(si_t *sih)
{
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		return sb_iscoreup(sih);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		return ai_iscoreup(sih);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		return ub_iscoreup(sih);
	} 

    ASSERT(0);
    return FALSE;
}

uint
si_wrapperreg(si_t *sih, uint32 offset, uint32 mask, uint32 val)
{
	/* only for AI back plane chips */
	if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		return (ai_wrap_reg(sih, offset, mask, val));
	}
	return 0;
}

uint
si_corereg(si_t *sih, uint coreidx, uint regoff, uint mask, uint val)
{
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		return sb_corereg(sih, coreidx, regoff, mask, val);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		return ai_corereg(sih, coreidx, regoff, mask, val);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		return ub_corereg(sih, coreidx, regoff, mask, val);
	} 

    ASSERT(0);
    return 0;
}

void
si_core_disable(si_t *sih, uint32 bits)
{
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		sb_core_disable(sih, bits);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		ai_core_disable(sih, bits);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		ub_core_disable(sih, bits);
	}
}

void
si_core_reset(si_t *sih, uint32 bits, uint32 resetbits)
{
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		sb_core_reset(sih, bits, resetbits);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		ai_core_reset(sih, bits, resetbits);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		ub_core_reset(sih, bits, resetbits);
	}
}

/* Run bist on current core. Caller needs to take care of core-specific bist hazards */
int
si_corebist(si_t *sih)
{
	uint32 cflags;
	int result = 0;

	/* Read core control flags */
	cflags = si_core_cflags(sih, 0, 0);

	/* Set bist & fgc */
	si_core_cflags(sih, ~0, (SICF_BIST_EN | SICF_FGC));

	/* Wait for bist done */
	SPINWAIT(((si_core_sflags(sih, 0, 0) & SISF_BIST_DONE) == 0), 100000);

	if (si_core_sflags(sih, 0, 0) & SISF_BIST_ERROR) {
		result = BCME_ERROR;
	}

	/* Reset core control flags */
	si_core_cflags(sih, 0xffff, cflags);

	return result;
}

static uint32
BCMINITFN(factor6)(uint32 x)
{
	switch (x) {
	case CC_F6_2:	return 2;
	case CC_F6_3:	return 3;
	case CC_F6_4:	return 4;
	case CC_F6_5:	return 5;
	case CC_F6_6:	return 6;
	case CC_F6_7:	return 7;
	default:	return 0;
	}
}

/* calculate the speed the SI would run at given a set of clockcontrol values */
uint32
BCMINITFN(si_clock_rate)(uint32 pll_type, uint32 n, uint32 m)
{
	uint32 n1, n2, clock, m1, m2, m3, mc;

	n1 = n & CN_N1_MASK;
	n2 = (n & CN_N2_MASK) >> CN_N2_SHIFT;

	if (pll_type == PLL_TYPE6) {
		if (m & CC_T6_MMASK) {
			return CC_T6_M1;
		} else {
			return CC_T6_M0;
		}
	} else if ((pll_type == PLL_TYPE1) ||
	           (pll_type == PLL_TYPE3) ||
	           (pll_type == PLL_TYPE4) ||
	           (pll_type == PLL_TYPE7)) {
		n1 = factor6(n1);
		n2 += CC_F5_BIAS;
	} else if (pll_type == PLL_TYPE2) {
		n1 += CC_T2_BIAS;
		n2 += CC_T2_BIAS;
		ASSERT((n1 >= 2) && (n1 <= 7));
		ASSERT((n2 >= 5) && (n2 <= 23));
	} else if (pll_type == PLL_TYPE5) {
		return (100000000);
	} else {
		ASSERT(0);
	}

	/* PLL types 3 and 7 use BASE2 (25Mhz) */
	if ((pll_type == PLL_TYPE3) ||
	    (pll_type == PLL_TYPE7)) {
		clock = CC_CLOCK_BASE2 * n1 * n2;
	} else {
		clock = CC_CLOCK_BASE1 * n1 * n2;
    }
    
	if (clock == 0) {
		return 0;
	}

	m1 = m & CC_M1_MASK;
	m2 = (m & CC_M2_MASK) >> CC_M2_SHIFT;
	m3 = (m & CC_M3_MASK) >> CC_M3_SHIFT;
	mc = (m & CC_MC_MASK) >> CC_MC_SHIFT;

	if ((pll_type == PLL_TYPE1) ||
	    (pll_type == PLL_TYPE3) ||
	    (pll_type == PLL_TYPE4) ||
	    (pll_type == PLL_TYPE7)) {
		m1 = factor6(m1);
		if ((pll_type == PLL_TYPE1) || (pll_type == PLL_TYPE3)) {
			m2 += CC_F5_BIAS;
		} else {
			m2 = factor6(m2);
		}
		m3 = factor6(m3);

		switch (mc) {
		case CC_MC_BYPASS:	return (clock);
		case CC_MC_M1:		return (clock / m1);
		case CC_MC_M1M2:	return (clock / (m1 * m2));
		case CC_MC_M1M2M3:	return (clock / (m1 * m2 * m3));
		case CC_MC_M1M3:	return (clock / (m1 * m3));
		default:		return (0);
		}
	} else {
		ASSERT(pll_type == PLL_TYPE2);

		m1 += CC_T2_BIAS;
		m2 += CC_T2M2_BIAS;
		m3 += CC_T2_BIAS;
		ASSERT((m1 >= 2) && (m1 <= 7));
		ASSERT((m2 >= 3) && (m2 <= 10));
		ASSERT((m3 >= 2) && (m3 <= 7));

		if ((mc & CC_T2MC_M1BYP) == 0) {
			clock /= m1;
		}
		if ((mc & CC_T2MC_M2BYP) == 0) {
			clock /= m2;
		}
		if ((mc & CC_T2MC_M3BYP) == 0) {
			clock /= m3;
		}

		return (clock);
	}
}

uint32
BCMINITFN(si_clock)(si_t *sih)
{
    if (sih->chippkg == BCM4709_PKG_ID) {
    	return NS_SI_CLOCK;
    }
    return NS_SLOW_SI_CLOCK;
}

#if defined(BCMDBG)
/* print interesting sbconfig registers */
void
si_dumpregs(si_t *sih, struct bcmstrbuf *b)
{
	si_info_t *sii;
	uint origidx, intr_val = 0;

	sii = SI_INFO(sih);
	origidx = sii->curidx;

	INTR_OFF(sii, intr_val);
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		sb_dumpregs(sih, b);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		ai_dumpregs(sih, b);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		ub_dumpregs(sih, b);
	} else {
		ASSERT(0);
	}

	si_setcoreidx(sih, origidx);
	INTR_RESTORE(sii, intr_val);
}
#endif	

#ifdef BCMDBG
void
si_view(si_t *sih, bool verbose)
{
	if (CHIPTYPE(sih->socitype) == SOCI_SB) {
		sb_view(sih, verbose);
	} else if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		ai_view(sih, verbose);
	} else if (CHIPTYPE(sih->socitype) == SOCI_UBUS) {
		ub_view(sih, verbose);
	} else {
		ASSERT(0);
	}
}

void
si_viewall(si_t *sih, bool verbose)
{
	si_info_t *sii;
	uint curidx, i;
	uint intr_val = 0;

	sii = SI_INFO(sih);
	curidx = sii->curidx;

	INTR_OFF(sii, intr_val);
	if ((CHIPTYPE(sih->socitype) == SOCI_AI) || (CHIPTYPE(sih->socitype) == SOCI_NS)) {
		ai_viewall(sih, verbose);
	} else {
		SI_ERROR(("si_viewall: num_cores %d\n", sii->numcores));
		for (i = 0; i < sii->numcores; i++) {
			si_setcoreidx(sih, i);
			si_view(sih, verbose);
		}
	}
	si_setcoreidx(sih, curidx);
	INTR_RESTORE(sii, intr_val);
}
#endif	/* BCMDBG */

/* return the slow clock source - LPO, XTAL, or PCI */
static uint
si_slowclk_src(si_info_t *sii)
{
	chipcregs_t *cc;

	ASSERT(SI_FAST(sii) || si_coreid(&sii->pub) == CC_CORE_ID);

	if (sii->pub.ccrev < 6) {
		return (SCC_SS_XTAL);
	} else if (sii->pub.ccrev < 10) {
		cc = (chipcregs_t *)si_setcoreidx(&sii->pub, sii->curidx);
		return (R_REG(sii->osh, &cc->slow_clk_ctl) & SCC_SS_MASK);
	} else {	/* Insta-clock */
		return (SCC_SS_XTAL);
	}
}

/* return the ILP (slowclock) min or max frequency */
static uint
si_slowclk_freq(si_info_t *sii, bool max_freq, chipcregs_t *cc)
{
	uint32 slowclk;
	uint div;

	ASSERT(SI_FAST(sii) || si_coreid(&sii->pub) == CC_CORE_ID);

	/* shouldn't be here unless we've established the chip has dynamic clk control */
	ASSERT(R_REG(sii->osh, &cc->capabilities) & CC_CAP_PWR_CTL);

	slowclk = si_slowclk_src(sii);
	if (sii->pub.ccrev < 6) {
		if (slowclk == SCC_SS_PCI) {
			return (max_freq ? (PCIMAXFREQ / 64) : (PCIMINFREQ / 64));
		} else {
			return (max_freq ? (XTALMAXFREQ / 32) : (XTALMINFREQ / 32));
	    }
	} else if (sii->pub.ccrev < 10) {
		div = 4 *
		        (((R_REG(sii->osh, &cc->slow_clk_ctl) & SCC_CD_MASK) >> SCC_CD_SHIFT) + 1);
		if (slowclk == SCC_SS_LPO) {
			return (max_freq ? LPOMAXFREQ : LPOMINFREQ);
		} else if (slowclk == SCC_SS_XTAL) {
			return (max_freq ? (XTALMAXFREQ / div) : (XTALMINFREQ / div));
		} else if (slowclk == SCC_SS_PCI) {
			return (max_freq ? (PCIMAXFREQ / div) : (PCIMINFREQ / div));
		} else {
			ASSERT(0);
		}
	} else {
		/* Chipc rev 10 is InstaClock */
		div = R_REG(sii->osh, &cc->system_clk_ctl) >> SYCC_CD_SHIFT;
		div = 4 * (div + 1);
		return (max_freq ? XTALMAXFREQ : (XTALMINFREQ / div));
	}
	return (0);
}

static void
BCMINITFN(si_clkctl_setdelay)(si_info_t *sii, void *chipcregs)
{
	chipcregs_t *cc = (chipcregs_t *)chipcregs;
	uint slowmaxfreq, pll_delay, slowclk;
	uint pll_on_delay, fref_sel_delay;

	pll_delay = PLL_DELAY;

	/* If the slow clock is not sourced by the xtal then add the xtal_on_delay
	 * since the xtal will also be powered down by dynamic clk control logic.
	 */

	slowclk = si_slowclk_src(sii);
	if (slowclk != SCC_SS_XTAL) {
		pll_delay += XTAL_ON_DELAY;
	}

	/* Starting with 4318 it is ILP that is used for the delays */
	slowmaxfreq = si_slowclk_freq(sii, (sii->pub.ccrev >= 10) ? FALSE : TRUE, cc);

	pll_on_delay = ((slowmaxfreq * pll_delay) + 999999) / 1000000;
	fref_sel_delay = ((slowmaxfreq * FREF_DELAY) + 999999) / 1000000;

	W_REG(sii->osh, &cc->pll_on_delay, pll_on_delay);
	W_REG(sii->osh, &cc->fref_sel_delay, fref_sel_delay);
}

/* initialize power control delay registers */
void
BCMINITFN(si_clkctl_init)(si_t *sih)
{
	si_info_t *sii;
	uint origidx = 0;
	chipcregs_t *cc;
	bool fast;

	if (!CCCTL_ENAB(sih)) {
		return;
	}

	sii = SI_INFO(sih);
	fast = SI_FAST(sii);
	if (!fast) {
		origidx = sii->curidx;
		if ((cc = (chipcregs_t *)si_setcore(sih, CC_CORE_ID, 0)) == NULL) {
			return;
		}
	} else if ((cc = (chipcregs_t *)CCREGS_FAST(sii)) == NULL) {
		return;
	}
	ASSERT(cc != NULL);

	/* set all Instaclk chip ILP to 1 MHz */
	if (sih->ccrev >= 10) {
		SET_REG(sii->osh, &cc->system_clk_ctl, SYCC_CD_MASK,
		        (ILP_DIV_1MHZ << SYCC_CD_SHIFT));
    }

	si_clkctl_setdelay(sii, (void *)(uintptr)cc);

	if (!fast) {
		si_setcoreidx(sih, origidx);
	}
}

/* turn primary xtal and/or pll off/on */
int
si_clkctl_xtal(si_t *sih, uint what, bool on)
{
	switch (BUSTYPE(sih->bustype)) {

	default:
		return (-1);
	}

}

/*
 *  clock control policy function throught chipcommon
 *
 *    set dynamic clk control mode (forceslow, forcefast, dynamic)
 *    returns true if we are forcing fast clock
 *    this is a wrapper over the next internal function
 *      to allow flexible policy settings for outside caller
 */
bool
si_clkctl_cc(si_t *sih, uint mode)
{
	si_info_t *sii;

	sii = SI_INFO(sih);

	/* chipcommon cores prior to rev6 don't support dynamic clock control */
	if (sih->ccrev < 6) {
		return FALSE;
	}

	return _si_clkctl_cc(sii, mode);
}

/* clk control mechanism through chipcommon, no policy checking */
static bool
_si_clkctl_cc(si_info_t *sii, uint mode)
{
	uint origidx = 0;
	chipcregs_t *cc;
	uint32 scc;
	uint intr_val = 0;
	bool fast = SI_FAST(sii);

	/* chipcommon cores prior to rev6 don't support dynamic clock control */
	if (sii->pub.ccrev < 6) {
		return (FALSE);
	}

	/* Chips with ccrev 10 are EOL and they don't have SYCC_HR which we use below */
	ASSERT(sii->pub.ccrev != 10);

	if (!fast) {
		INTR_OFF(sii, intr_val);
		origidx = sii->curidx;

		if ((BUSTYPE(sii->pub.bustype) == SI_BUS) &&
		    si_setcore(&sii->pub, MIPS33_CORE_ID, 0) &&
		    (si_corerev(&sii->pub) <= 7) && (sii->pub.ccrev >= 10)) {
			goto done;
		}

		cc = (chipcregs_t *) si_setcore(&sii->pub, CC_CORE_ID, 0);
	} else if ((cc = (chipcregs_t *) CCREGS_FAST(sii)) == NULL) {
		goto done;
	}
	
	ASSERT(cc != NULL);

	if (!CCCTL_ENAB(&sii->pub) && (sii->pub.ccrev < 20)) {
		goto done;
	}

	switch (mode) {
	case CLK_FAST:	/* FORCEHT, fast (pll) clock */
		if (sii->pub.ccrev < 10) {
			/* don't forget to force xtal back on before we clear SCC_DYN_XTAL.. */
			si_clkctl_xtal(&sii->pub, XTAL, ON);
			SET_REG(sii->osh, &cc->slow_clk_ctl, (SCC_XC | SCC_FS | SCC_IP), SCC_IP);
		} else if (sii->pub.ccrev < 20) {
			OR_REG(sii->osh, &cc->system_clk_ctl, SYCC_HR);
		} else {
			OR_REG(sii->osh, &cc->clk_ctl_st, CCS_FORCEHT);
		}

		/* wait for the PLL */
		if (PMUCTL_ENAB(&sii->pub)) {
			uint32 htavail = CCS_HTAVAIL;

			SPINWAIT(((R_REG(sii->osh, &cc->clk_ctl_st) & htavail) == 0),
			         PMU_MAX_TRANSITION_DLY);
			ASSERT(R_REG(sii->osh, &cc->clk_ctl_st) & htavail);
		} else {
			OSL_DELAY(PLL_DELAY);
		}
		break;

	case CLK_DYNAMIC:	/* enable dynamic clock control */
		if (sii->pub.ccrev < 10) {
			scc = R_REG(sii->osh, &cc->slow_clk_ctl);
			scc &= ~(SCC_FS | SCC_IP | SCC_XC);
			if ((scc & SCC_SS_MASK) != SCC_SS_XTAL) {
				scc |= SCC_XC;
			}
			W_REG(sii->osh, &cc->slow_clk_ctl, scc);

			/* for dynamic control, we have to release our xtal_pu "force on" */
			if (scc & SCC_XC) {
				si_clkctl_xtal(&sii->pub, XTAL, OFF);
			}
		} else if (sii->pub.ccrev < 20) {
			/* Instaclock */
			AND_REG(sii->osh, &cc->system_clk_ctl, ~SYCC_HR);
		} else {
			AND_REG(sii->osh, &cc->clk_ctl_st, ~CCS_FORCEHT);
		}
		break;

	default:
		ASSERT(0);
	}

done:
	if (!fast) {
		si_setcoreidx(&sii->pub, origidx);
		INTR_RESTORE(sii, intr_val);
	}
	return (mode == CLK_FAST);
}

/* Build device path. Support SI, PCI, and JTAG for now. */
int
BCMNMIATTACHFN(si_devpath)(si_t *sih, char *path, int size)
{
	int slen;

	ASSERT(path != NULL);
	ASSERT(size >= SI_DEVPATH_BUFSZ);

	if (!path || size <= 0)
		return -1;

	switch (BUSTYPE(sih->bustype)) {
	case SI_BUS:
		slen = snprintf(path, (size_t)size, "sb/%u/", si_coreidx(sih));
		break;
	default:
		slen = -1;
		ASSERT(0);
		break;
	}

	if (slen < 0 || slen >= size) {
		path[0] = '\0';
		return -1;
	}

	return 0;
}

char *
BCMATTACHFN(si_coded_devpathvar)(si_t *sih, char *varname, int var_len, const char *name)
{
	char pathname[SI_DEVPATH_BUFSZ + 32];
	char devpath[SI_DEVPATH_BUFSZ + 32];
	char *p;
	int idx;
	int len;

	/* try to get compact devpath if it exist */
	if (si_devpath(sih, devpath, SI_DEVPATH_BUFSZ) == 0) {
		len = strlen(devpath);
		devpath[len - 1] = '\0';
		for (idx = 0; idx < SI_MAXCORES; idx++) {
			snprintf(pathname, SI_DEVPATH_BUFSZ, "devpath%d", idx);
			if ((p = getvar(NULL, pathname)) == NULL) {
				continue;
			}

			if (strncmp(p, devpath, len) == 0) {
				snprintf(varname, var_len, "%d:%s", idx, name);
				return varname;
			}
		}
	}

	return NULL;
}

/* Get a variable, but only if it has a devpath prefix */
int
BCMATTACHFN(si_getdevpathintvar)(si_t *sih, const char *name)
{
#if defined(BCMBUSTYPE) && (BCMBUSTYPE == SI_BUS)
	return (getintvar(NULL, name));
#else
	char varname[SI_DEVPATH_BUFSZ + 32];
	int val;

	si_devpathvar(sih, varname, sizeof(varname), name);

	if ((val = getintvar(NULL, varname)) != 0) {
		return val;
	}

	/* try to get compact devpath if it exist */
	if (si_coded_devpathvar(sih, varname, sizeof(varname), name) == NULL) {
		return 0;
	}

	return (getintvar(NULL, varname));
#endif /* BCMBUSTYPE && BCMBUSTYPE == SI_BUS */
}

/* Concatenate the dev path with a varname into the given 'var' buffer
 * and return the 'var' pointer.
 * Nothing is done to the arguments if len == 0 or var is NULL, var is still returned.
 * On overflow, the first char will be set to '\0'.
 */
static char *
BCMATTACHFN(si_devpathvar)(si_t *sih, char *var, int len, const char *name)
{
	uint path_len;

	if (!var || len <= 0) {
		return var;
	}

	if (si_devpath(sih, var, len) == 0) {
		path_len = strlen(var);

		if (strlen(name) + 1 > (uint)(len - path_len)) {
			var[0] = '\0';
		} else {
			strncpy(var + path_len, name, len - path_len - 1);
		}
	}

	return var;
}


#if defined(BCMDBG)
#endif 

/* mask&set gpio output enable bits */
uint32
si_gpioouten(si_t *sih, uint32 mask, uint32 val, uint8 priority)
{
	uint regoff;

	regoff = 0;

	/* gpios could be shared on router platforms
	 * ignore reservation if it's high priority (e.g., test apps)
	 */
	if ((priority != GPIO_HI_PRIORITY) &&
	    (BUSTYPE(sih->bustype) == SI_BUS) && (val || mask)) {
		mask = priority ? (si_gpioreservation & mask) :
			((si_gpioreservation | mask) & ~(si_gpioreservation));
		val &= mask;
	}

	regoff = OFFSETOF(chipcregs_t, gpioouten);
	return (si_corereg(sih, SI_CC_IDX, regoff, mask, val));
}

/* mask&set gpio output bits */
uint32
si_gpioout(si_t *sih, uint32 mask, uint32 val, uint8 priority)
{
	uint regoff;

	regoff = 0;

	/* gpios could be shared on router platforms
	 * ignore reservation if it's high priority (e.g., test apps)
	 */
	if ((priority != GPIO_HI_PRIORITY) &&
	    (BUSTYPE(sih->bustype) == SI_BUS) && (val || mask)) {
		mask = priority ? (si_gpioreservation & mask) :
			((si_gpioreservation | mask) & ~(si_gpioreservation));
		val &= mask;
	}

	regoff = OFFSETOF(chipcregs_t, gpioout);
	return (si_corereg(sih, SI_CC_IDX, regoff, mask, val));
}
