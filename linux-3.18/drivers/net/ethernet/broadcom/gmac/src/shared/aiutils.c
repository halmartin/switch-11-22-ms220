/*
 * $Copyright Open Broadcom Corporation$
 *
 * Misc utility routines for accessing chip-specific features
 * of the SiliconBackplane-based Broadcom chips.
 *
 * $Id: aiutils.c 327582 2012-04-14 05:02:37Z kenlo $
 */
#include <bcm_cfg.h>
#include <typedefs.h>
#include <bcmdefs.h>
#include <osl.h>
#include <bcmutils.h>
#include <siutils.h>
#include <hndsoc.h>
#include <sbchipc.h>
#include <pcicfg.h>

#include "siutils_priv.h"
#if defined(CONFIG_MACH_HX4)
#include "hx4_erom.h"
#elif defined(CONFIG_MACH_HR2)
#include "hr2_erom.h"
#elif defined(CONFIG_MACH_KT2)
#include "kt2_erom.h"
#elif defined(CONFIG_MACH_GH)
#include "gh_erom.h"
#elif defined(CONFIG_MACH_SB2)
#include "sb2_erom.h"
#elif defined(CONFIG_MACH_HR3)
#include "hr3_erom.h"
#elif defined(CONFIG_MACH_GH2)
#include "gh2_erom.h"
#endif

/* EROM parsing */
static uint32
get_erom_ent(si_t *sih, uint32 **eromptr, uint32 mask, uint32 match)
{
	uint32 ent;
	uint inv = 0, nom = 0;

	while (TRUE) {
		ent = **eromptr;

		(*eromptr)++;

		if (mask == 0) {
			break;
		}

		if ((ent & ER_VALID) == 0) {
			inv++;
			continue;
		}

		if (ent == (ER_END | ER_VALID)) {
			break;
		}

		if ((ent & mask) == match) {
			break;
		}

		nom++;
	}

	SI_VMSG(("%s: Returning ent 0x%08x\n", __FUNCTION__, ent));
	if (inv + nom) {
		SI_VMSG(("  after %d invalid and %d non-matching entries\n", inv, nom));
	}
	return ent;
}

static uint32
get_asd(si_t *sih, uint32 **eromptr, uint sp, uint ad, uint st, uint32 *addrl, uint32 *addrh,
        uint32 *sizel, uint32 *sizeh)
{
	uint32 asd, sz, szd;

	asd = get_erom_ent(sih, eromptr, ER_VALID, ER_VALID);
	if (((asd & ER_TAG1) != ER_ADD) ||
	    (((asd & AD_SP_MASK) >> AD_SP_SHIFT) != sp) ||
	    ((asd & AD_ST_MASK) != st)) {
		/* This is not what we want, "push" it back */
		(*eromptr)--;
		return 0;
	}
	*addrl = asd & AD_ADDR_MASK;
	if (asd & AD_AG32) {
		*addrh = get_erom_ent(sih, eromptr, 0, 0);
	} else {
		*addrh = 0;
	}
	*sizeh = 0;
	sz = asd & AD_SZ_MASK;
	if (sz == AD_SZ_SZD) {
		szd = get_erom_ent(sih, eromptr, 0, 0);
		*sizel = szd & SD_SZ_MASK;
		if (szd & SD_SG32) {
			*sizeh = get_erom_ent(sih, eromptr, 0, 0);
		}
	} else {
		*sizel = AD_SZ_BASE << (sz >> AD_SZ_SHIFT);
	}

	SI_VMSG(("  SP %d, ad %d: st = %d, 0x%08x_0x%08x @ 0x%08x_0x%08x\n",
	        sp, ad, st, *sizeh, *sizel, *addrh, *addrl));

	return asd;
}

/* parse the enumeration rom to identify all cores */
void
BCMATTACHFN(ai_scan)(si_t *sih, void *regs, uint devid)
{
	si_info_t *sii = SI_INFO(sih);
	chipcregs_t *cc = (chipcregs_t *)regs;
	uint32 erombase, *eromptr, *eromlim;

	erombase = R_REG(sii->osh, &cc->eromptr);

	switch (BUSTYPE(sih->bustype)) {
	case SI_BUS:
#if defined(CONFIG_MACH_HX4)
		eromptr = hx4_erom;
#elif defined(CONFIG_MACH_HR2)
		eromptr = hr2_erom;
#elif defined(CONFIG_MACH_KT2)
		eromptr = kt2_erom;
#elif defined(CONFIG_MACH_GH)
		eromptr = gh_erom;
#elif defined(CONFIG_MACH_SB2)
		eromptr = sb2_erom;
#elif defined(CONFIG_MACH_HR3)
		eromptr = hr3_erom;
#elif defined(CONFIG_MACH_GH2)
		eromptr = gh2_erom;
#endif
		break;

	case PCI_BUS:
		/* Set wrappers address */
		sii->curwrap = (void *)((uintptr)regs + SI_CORE_SIZE);

		/* Now point the window at the erom */
		OSL_PCI_WRITE_CONFIG(sii->osh, PCI_BAR0_WIN, 4, erombase);
		eromptr = regs;
		break;

	case PCMCIA_BUS:
	default:
		SI_ERROR(("Don't know how to do AXI enumertion on bus %d\n", sih->bustype));
		ASSERT(0);
		return;
	}
	eromlim = eromptr + (ER_REMAPCONTROL / sizeof(uint32));

	SI_VMSG(("ai_scan: regs = 0x%p, erombase = 0x%08x, eromptr = 0x%p, eromlim = 0x%p\n",
	         regs, erombase, eromptr, eromlim));
	while (eromptr < eromlim) {
		uint32 cia, cib, cid, mfg, crev, nmw, nsw, nmp, nsp;
		uint32 mpd, asd, addrl, addrh, sizel, sizeh;
		uint i, j, idx;
		bool br;

		br = FALSE;

		/* Grok a component */
		cia = get_erom_ent(sih, &eromptr, ER_TAG, ER_CI);
		if (cia == (ER_END | ER_VALID)) {
			SI_VMSG(("Found END of erom after %d cores\n", sii->numcores));
			return;
		}

		cib = get_erom_ent(sih, &eromptr, 0, 0);

		if ((cib & ER_TAG) != ER_CI) {
			SI_ERROR(("CIA not followed by CIB\n"));
			goto error;
		}

		cid = (cia & CIA_CID_MASK) >> CIA_CID_SHIFT;
		mfg = (cia & CIA_MFG_MASK) >> CIA_MFG_SHIFT;
		crev = (cib & CIB_REV_MASK) >> CIB_REV_SHIFT;
		nmw = (cib & CIB_NMW_MASK) >> CIB_NMW_SHIFT;
		nsw = (cib & CIB_NSW_MASK) >> CIB_NSW_SHIFT;
		nmp = (cib & CIB_NMP_MASK) >> CIB_NMP_SHIFT;
		nsp = (cib & CIB_NSP_MASK) >> CIB_NSP_SHIFT;

#ifdef BCMDBG_SI
		SI_VMSG(("Found component 0x%04x/0x%04x rev %d at erom addr 0x%p, with nmw = %d, "
		         "nsw = %d, nmp = %d & nsp = %d\n",
		         mfg, cid, crev, eromptr - 1, nmw, nsw, nmp, nsp));
#else
		BCM_REFERENCE(crev);
#endif

		if (((mfg == MFGID_ARM) && (cid == DEF_AI_COMP)) || (nsp == 0)) {
			continue;
		}
		
		if ((nmw + nsw == 0)) {
			/* A component which is not a core */
			/* XXX: Should record some info */
			if (cid == OOB_ROUTER_CORE_ID) {
				asd = get_asd(sih, &eromptr, 0, 0, AD_ST_SLAVE,
					&addrl, &addrh, &sizel, &sizeh);
				if (asd != 0) {
					sii->oob_router = addrl;
				}
			}
			if (cid != GMAC_COMMON_4706_CORE_ID) {
				continue;
			}
		}

		idx = sii->numcores;

		sii->cia[idx] = cia;
		sii->cib[idx] = cib;
		sii->coreid[idx] = cid;

		for (i = 0; i < nmp; i++) {
			mpd = get_erom_ent(sih, &eromptr, ER_VALID, ER_VALID);
			if ((mpd & ER_TAG) != ER_MP) {
				SI_ERROR(("Not enough MP entries for component 0x%x\n", cid));
				goto error;
			}
			/* XXX: Record something? */
			SI_VMSG(("  Master port %d, mp: %d id: %d\n", i,
			         (mpd & MPD_MP_MASK) >> MPD_MP_SHIFT,
			         (mpd & MPD_MUI_MASK) >> MPD_MUI_SHIFT));
		}

		/* First Slave Address Descriptor should be port 0:
		 * the main register space for the core
		 */
		asd = get_asd(sih, &eromptr, 0, 0, AD_ST_SLAVE, &addrl, &addrh, &sizel, &sizeh);
		if (asd == 0) {
			do {
			/* Try again to see if it is a bridge */
			asd = get_asd(sih, &eromptr, 0, 0, AD_ST_BRIDGE, &addrl, &addrh,
			              &sizel, &sizeh);
			if (asd != 0) {
				br = TRUE;
			} else {
					if (br == TRUE) {
						break;
					} else if ((addrh != 0) || (sizeh != 0) ||
						(sizel != SI_CORE_SIZE)) {
						/* XXX: Could we have sizel != 4KB? */
						SI_ERROR(("addrh = 0x%x\t sizeh = 0x%x\t size1 ="
							"0x%x\n", addrh, sizeh, sizel));
						SI_ERROR(("First Slave ASD for"
							"core 0x%04x malformed "
							"(0x%08x)\n", cid, asd));
						goto error;
					}
				}
			} while (1);
		}
		sii->coresba[idx] = addrl;
		sii->coresba_size[idx] = sizel;
		/* Get any more ASDs in port 0 */
		j = 1;
		do {
			asd = get_asd(sih, &eromptr, 0, j, AD_ST_SLAVE, &addrl, &addrh,
			              &sizel, &sizeh);
			if ((asd != 0) && (j == 1) && (sizel == SI_CORE_SIZE)) {
				sii->coresba2[idx] = addrl;
				sii->coresba2_size[idx] = sizel;
			}
			j++;
		} while (asd != 0);

		/* Go through the ASDs for other slave ports */
		for (i = 1; i < nsp; i++) {
			j = 0;
			do {
				asd = get_asd(sih, &eromptr, i, j, AD_ST_SLAVE, &addrl, &addrh,
				              &sizel, &sizeh);
				/* XXX: Should record them so we can do error recovery later */

				if (asd == 0)
					break;
				j++;
			} while (1);
			if (j == 0) {
				SI_ERROR((" SP %d has no address descriptors\n", i));
				goto error;
			}
		}

		/* Now get master wrappers */
		for (i = 0; i < nmw; i++) {
			asd = get_asd(sih, &eromptr, i, 0, AD_ST_MWRAP, &addrl, &addrh,
			              &sizel, &sizeh);
			if (asd == 0) {
				SI_ERROR(("Missing descriptor for MW %d\n", i));
				goto error;
			}
			if ((sizeh != 0) || (sizel != SI_CORE_SIZE)) {
				SI_ERROR(("Master wrapper %d is not 4KB\n", i));
				goto error;
			}
			if (i == 0) {
				sii->wrapba[idx] = addrl;
			}
		}

		/* And finally slave wrappers */
		for (i = 0; i < nsw; i++) {
			uint fwp = (nsp == 1) ? 0 : 1;
			asd = get_asd(sih, &eromptr, fwp + i, 0, AD_ST_SWRAP, &addrl, &addrh,
			              &sizel, &sizeh);
			if (asd == 0) {
				SI_ERROR(("Missing descriptor for SW %d\n", i));
				goto error;
			}
			if ((sizeh != 0) || (sizel != SI_CORE_SIZE)) {
				SI_ERROR(("Slave wrapper %d is not 4KB\n", i));
				goto error;
			}
			if ((nmw == 0) && (i == 0)) {
				sii->wrapba[idx] = addrl;
			}
		}

		/* Don't record bridges */
		if (br) {
			continue;
		}

		/* Done with core */
		sii->numcores++;
	}

	SI_ERROR(("Reached end of erom without finding END"));

error:
	sii->numcores = 0;
	return;
}

/* This function changes the logical "focus" to the indicated core.
 * Return the current core's virtual address.
 */
void *
ai_setcoreidx(si_t *sih, uint coreidx)
{
	si_info_t *sii = SI_INFO(sih);
	uint32 addr, wrap;
	void *regs;

	if (coreidx >= MIN(sii->numcores, SI_MAXCORES)) {
		return (NULL);
	}

	addr = sii->coresba[coreidx];
	wrap = sii->wrapba[coreidx];

	/*
	 * If the user has provided an interrupt mask enabled function,
	 * then assert interrupts are disabled before switching the core.
	 */
	ASSERT((sii->intrsenabled_fn == NULL) || !(*(sii)->intrsenabled_fn)((sii)->intr_arg));

	switch (BUSTYPE(sih->bustype)) {
	case SI_BUS:
		/* map new one */
		if (!sii->regs[coreidx]) {
			sii->regs[coreidx] = REG_MAP(addr, SI_CORE_SIZE);
			ASSERT(GOODREGS(sii->regs[coreidx]));
		}
		sii->curmap = regs = sii->regs[coreidx];
		if (!sii->wrappers[coreidx]) {
			sii->wrappers[coreidx] = REG_MAP(wrap, SI_CORE_SIZE);
			ASSERT(GOODREGS(sii->wrappers[coreidx]));
		}
		sii->curwrap = sii->wrappers[coreidx];
		break;

	case PCI_BUS:
		/* point bar0 window */
		OSL_PCI_WRITE_CONFIG(sii->osh, PCI_BAR0_WIN, 4, addr);
		regs = sii->curmap;
		/* point bar0 2nd 4KB window to the primary wrapper */
		if (PCIE_GEN2(sii)) {
			OSL_PCI_WRITE_CONFIG(sii->osh, PCIE2_BAR0_WIN2, 4, wrap);
		} else {
			OSL_PCI_WRITE_CONFIG(sii->osh, PCI_BAR0_WIN2, 4, wrap);
		}
		break;

	case PCMCIA_BUS:
	default:
		ASSERT(0);
		regs = NULL;
		break;
	}

	sii->curmap = regs;
	sii->curidx = coreidx;

	return regs;
}

void
ai_coreaddrspaceX(si_t *sih, uint asidx, uint32 *addr, uint32 *size)
{
	si_info_t *sii = SI_INFO(sih);
	chipcregs_t *cc = NULL;
	uint32 erombase, *eromptr, *eromlim;
	uint i, j, cidx;
	uint32 cia, cib, nmp, nsp;
	uint32 asd, addrl, addrh, sizel, sizeh;

	for (i = 0; i < sii->numcores; i++) {
		if (sii->coreid[i] == CC_CORE_ID) {
			cc = (chipcregs_t *)sii->regs[i];
			break;
		}
	}
	if (cc == NULL) {
		goto error;
	}

	erombase = R_REG(sii->osh, &cc->eromptr);
	eromptr = (uint32 *)REG_MAP(erombase, SI_CORE_SIZE);
	eromlim = eromptr + (ER_REMAPCONTROL / sizeof(uint32));

	cidx = sii->curidx;
	cia = sii->cia[cidx];
	cib = sii->cib[cidx];

	nmp = (cib & CIB_NMP_MASK) >> CIB_NMP_SHIFT;
	nsp = (cib & CIB_NSP_MASK) >> CIB_NSP_SHIFT;

	/* scan for cores */
	while (eromptr < eromlim) {
		if ((get_erom_ent(sih, &eromptr, ER_TAG, ER_CI) == cia) &&
			(get_erom_ent(sih, &eromptr, 0, 0) == cib)) {
			break;
		}
	}

	/* skip master ports */
	for (i = 0; i < nmp; i++) {
		get_erom_ent(sih, &eromptr, ER_VALID, ER_VALID);
	}

	/* Skip ASDs in port 0 */
	asd = get_asd(sih, &eromptr, 0, 0, AD_ST_SLAVE, &addrl, &addrh, &sizel, &sizeh);
	if (asd == 0) {
		/* Try again to see if it is a bridge */
		asd = get_asd(sih, &eromptr, 0, 0, AD_ST_BRIDGE, &addrl, &addrh,
		              &sizel, &sizeh);
	}

	j = 1;
	do {
		asd = get_asd(sih, &eromptr, 0, j, AD_ST_SLAVE, &addrl, &addrh,
		              &sizel, &sizeh);
		j++;
	} while (asd != 0);

	/* Go through the ASDs for other slave ports */
	for (i = 1; i < nsp; i++) {
		j = 0;
		do {
			asd = get_asd(sih, &eromptr, i, j, AD_ST_SLAVE, &addrl, &addrh,
				&sizel, &sizeh);
			if (asd == 0) {
				break;
			}

			if (!asidx--) {
				*addr = addrl;
				*size = sizel;
				return;
			}
			j++;
		} while (1);

		if (j == 0) {
			SI_ERROR((" SP %d has no address descriptors\n", i));
			break;
		}
	}

error:
	*size = 0;
	return;
}

/* Return the number of address spaces in current core */
int
ai_numaddrspaces(si_t *sih)
{
	/* XXX: Either save ot or parse the EROM on demand */
	return 2;
}

/* Return the address of the nth address space in the current core */
uint32
ai_addrspace(si_t *sih, uint asidx)
{
	si_info_t *sii;
	uint cidx;

	sii = SI_INFO(sih);
	cidx = sii->curidx;

	if (asidx == 0) {
		return sii->coresba[cidx];
	} else if (asidx == 1) {
		return sii->coresba2[cidx];
	} else {
		SI_ERROR(("%s: Need to parse the erom again to find addr space %d\n",
		          __FUNCTION__, asidx));
		return 0;
	}
}

/* Return the size of the nth address space in the current core */
uint32
ai_addrspacesize(si_t *sih, uint asidx)
{
	si_info_t *sii;
	uint cidx;

	sii = SI_INFO(sih);
	cidx = sii->curidx;

	if (asidx == 0) {
		return sii->coresba_size[cidx];
	} else if (asidx == 1) {
		return sii->coresba2_size[cidx];
	} else {
		SI_ERROR(("%s: Need to parse the erom again to find addr space %d\n",
		          __FUNCTION__, asidx));
		return 0;
	}
}

uint
ai_flag(si_t *sih)
{
	si_info_t *sii;
	aidmp_t *ai;

	sii = SI_INFO(sih);
	ai = sii->curwrap;
	return (R_REG(sii->osh, &ai->oobselouta30) & 0x1f);
}

void
ai_setint(si_t *sih, int siflag)
{
	/* XXX: Figure out OOB stuff */
}

uint
ai_wrap_reg(si_t *sih, uint32 offset, uint32 mask, uint32 val)
{
	si_info_t *sii = SI_INFO(sih);
	uint32 *map = (uint32 *) sii->curwrap;

	if (mask || val) {
		uint32 w = R_REG(sii->osh, map+(offset/4));
		w &= ~mask;
		w |= val;
		W_REG(sii->osh, map+(offset/4), val);
	}

	return (R_REG(sii->osh, map+(offset/4)));
}

uint
ai_corevendor(si_t *sih)
{
	si_info_t *sii;
	uint32 cia;

	sii = SI_INFO(sih);
	cia = sii->cia[sii->curidx];
	return ((cia & CIA_MFG_MASK) >> CIA_MFG_SHIFT);
}

uint
ai_corerev(si_t *sih)
{
	si_info_t *sii;
	uint32 cib;

	sii = SI_INFO(sih);
	cib = sii->cib[sii->curidx];
	return ((cib & CIB_REV_MASK) >> CIB_REV_SHIFT);
}

bool
ai_iscoreup(si_t *sih)
{
	si_info_t *sii;
	aidmp_t *ai;

	sii = SI_INFO(sih);
	ai = sii->curwrap;

	return (((R_REG(sii->osh, &ai->ioctrl) & (SICF_FGC | SICF_CLOCK_EN)) == SICF_CLOCK_EN) &&
	        ((R_REG(sii->osh, &ai->resetctrl) & AIRC_RESET) == 0));
}

/*
 * Switch to 'coreidx', issue a single arbitrary 32bit register mask&set operation,
 * switch back to the original core, and return the new value.
 *
 * When using the silicon backplane, no fiddling with interrupts or core switches is needed.
 *
 * Also, when using pci/pcie, we can optimize away the core switching for pci registers
 * and (on newer pci cores) chipcommon registers.
 */
uint
ai_corereg(si_t *sih, uint coreidx, uint regoff, uint mask, uint val)
{
	uint origidx = 0;
	uint32 *r = NULL;
	uint w;
	uint intr_val = 0;
	bool fast = FALSE;
	si_info_t *sii;

	sii = SI_INFO(sih);

	ASSERT(GOODIDX(coreidx));
	ASSERT(regoff < SI_CORE_SIZE);
	ASSERT((val & ~mask) == 0);

	if (coreidx >= SI_MAXCORES) {
		return 0;
	}

	if (BUSTYPE(sih->bustype) == SI_BUS) {
		/* If internal bus, we can always get at everything */
		fast = TRUE;
		/* map if does not exist */
		if (!sii->regs[coreidx]) {
			sii->regs[coreidx] = REG_MAP(sii->coresba[coreidx],
			                            SI_CORE_SIZE);
			ASSERT(GOODREGS(sii->regs[coreidx]));
		}
		r = (uint32 *)((uchar *)sii->regs[coreidx] + regoff);
	} else if (BUSTYPE(sih->bustype) == PCI_BUS) {
		/* If pci/pcie, we can get at pci/pcie regs and on newer cores to chipc */

		if ((sii->coreid[coreidx] == CC_CORE_ID) && SI_FAST(sii)) {
			/* Chipc registers are mapped at 12KB */

			fast = TRUE;
			r = (uint32 *)((char *)sii->curmap + PCI_16KB0_CCREGS_OFFSET + regoff);
		} else if (sii->pub.buscoreidx == coreidx) {
			/* pci registers are at either in the last 2KB of an 8KB window
			 * or, in pcie and pci rev 13 at 8KB
			 */
			fast = TRUE;
			if (SI_FAST(sii)) {
				r = (uint32 *)((char *)sii->curmap +
				               PCI_16KB0_PCIREGS_OFFSET + regoff);
			} else {
				r = (uint32 *)((char *)sii->curmap +
				               ((regoff >= SBCONFIGOFF) ?
				                PCI_BAR0_PCISBR_OFFSET : PCI_BAR0_PCIREGS_OFFSET) +
				               regoff);
	        }
		}
	}

	if (!fast) {
		INTR_OFF(sii, intr_val);

		/* save current core index */
		origidx = si_coreidx(&sii->pub);

		/* switch core */
		r = (uint32*) ((uchar*) ai_setcoreidx(&sii->pub, coreidx) + regoff);
	}
	ASSERT(r != NULL);

	/* mask and set */
	if (mask || val) {
		w = (R_REG(sii->osh, r) & ~mask) | val;
		W_REG(sii->osh, r, w);
	}

	/* readback */
	w = R_REG(sii->osh, r);

	if (!fast) {
		/* restore core index */
		if (origidx != coreidx) {
			ai_setcoreidx(&sii->pub, origidx);
		}

		INTR_RESTORE(sii, intr_val);
	}

	return (w);
}

void
ai_core_disable(si_t *sih, uint32 bits)
{
	si_info_t *sii;
	volatile uint32 dummy;
	uint32 status;
	aidmp_t *ai;

	sii = SI_INFO(sih);

	ASSERT(GOODREGS(sii->curwrap));
	ai = sii->curwrap;

	/* if core is already in reset, just return */
	if (R_REG(sii->osh, &ai->resetctrl) & AIRC_RESET) {
		return;
	}

	/* ensure there are no pending backplane operations */
	SPINWAIT(((status = R_REG(sii->osh, &ai->resetstatus)) != 0), 300);

	/* if pending backplane ops still, try waiting longer */
	if (status != 0) {
		/* 300usecs was sufficient to allow backplane ops to clear for big hammer */
		/* during driver load we may need more time */
		SPINWAIT(((status = R_REG(sii->osh, &ai->resetstatus)) != 0), 10000);
		/* if still pending ops, continue on and try disable anyway */
		/* this is in big hammer path, so don't call wl_reinit in this case... */
#ifdef BCMDBG
		if (status != 0) {
			printf("%s: WARN: resetstatus=%0x on core disable\n", __FUNCTION__, status);
		}
#endif
	}

	W_REG(sii->osh, &ai->ioctrl, bits);
	dummy = R_REG(sii->osh, &ai->ioctrl);
	BCM_REFERENCE(dummy);
	OSL_DELAY(10);

	W_REG(sii->osh, &ai->resetctrl, AIRC_RESET);
	dummy = R_REG(sii->osh, &ai->resetctrl);
	BCM_REFERENCE(dummy);
	OSL_DELAY(1);
}

/* reset and re-enable a core
 * inputs:
 * bits - core specific bits that are set during and after reset sequence
 * resetbits - core specific bits that are set only during reset sequence
 */
void
ai_core_reset(si_t *sih, uint32 bits, uint32 resetbits)
{
	si_info_t *sii;
	aidmp_t *ai;
	volatile uint32 dummy;

	sii = SI_INFO(sih);
	ASSERT(GOODREGS(sii->curwrap));
	ai = sii->curwrap;

#ifdef CONFIG_BCM_IPROC_GMAC_ACP
	bits = resetbits = R_REG(sii->osh, &ai->ioctrl) & 0xFFFFFFFC;
#endif /* CONFIG_BCM_IPROC_GMAC_ACP */

	/*
	 * Must do the disable sequence first to work for arbitrary current core state.
	 */
	ai_core_disable(sih, (bits | resetbits));

	/*
	 * Now do the initialization sequence.
	 */
	W_REG(sii->osh, &ai->ioctrl, (bits | SICF_FGC | SICF_CLOCK_EN));
	dummy = R_REG(sii->osh, &ai->ioctrl);
	BCM_REFERENCE(dummy);

	W_REG(sii->osh, &ai->resetctrl, 0);
	dummy = R_REG(sii->osh, &ai->resetctrl);
	BCM_REFERENCE(dummy);
	OSL_DELAY(1);

	W_REG(sii->osh, &ai->ioctrl, (bits | SICF_CLOCK_EN));
	dummy = R_REG(sii->osh, &ai->ioctrl);
	BCM_REFERENCE(dummy);
	OSL_DELAY(1);
}

void
ai_core_cflags_wo(si_t *sih, uint32 mask, uint32 val)
{
	si_info_t *sii;
	aidmp_t *ai;
	uint32 w;

	sii = SI_INFO(sih);

	ASSERT(GOODREGS(sii->curwrap));
	ai = sii->curwrap;

	ASSERT((val & ~mask) == 0);

	if (mask || val) {
		w = ((R_REG(sii->osh, &ai->ioctrl) & ~mask) | val);
		W_REG(sii->osh, &ai->ioctrl, w);
	}
}

uint32
ai_core_cflags(si_t *sih, uint32 mask, uint32 val)
{
	si_info_t *sii;
	aidmp_t *ai;
	uint32 w;

	sii = SI_INFO(sih);

	ASSERT(GOODREGS(sii->curwrap));
	ai = sii->curwrap;

	ASSERT((val & ~mask) == 0);

	if (mask || val) {
		w = ((R_REG(sii->osh, &ai->ioctrl) & ~mask) | val);
		W_REG(sii->osh, &ai->ioctrl, w);
	}

	return R_REG(sii->osh, &ai->ioctrl);
}

uint32
ai_core_sflags(si_t *sih, uint32 mask, uint32 val)
{
	si_info_t *sii;
	aidmp_t *ai;
	uint32 w;

	sii = SI_INFO(sih);

	ASSERT(GOODREGS(sii->curwrap));
	ai = sii->curwrap;

	ASSERT((val & ~mask) == 0);
	ASSERT((mask & ~SISF_CORE_BITS) == 0);

	if (mask || val) {
		w = ((R_REG(sii->osh, &ai->iostatus) & ~mask) | val);
		W_REG(sii->osh, &ai->iostatus, w);
	}

	return R_REG(sii->osh, &ai->iostatus);
}

#if defined(BCMDBG) || defined(BCMDBG_DUMP)
/* print interesting aidmp registers */
void
ai_dumpregs(si_t *sih, struct bcmstrbuf *b)
{
	si_info_t *sii;
	osl_t *osh;
	aidmp_t *ai;
	uint i;

	sii = SI_INFO(sih);
	osh = sii->osh;

	for (i = 0; i < sii->numcores; i++) {
		si_setcoreidx(&sii->pub, i);
		ai = sii->curwrap;

		bcm_bprintf(b, "core 0x%x: \n", sii->coreid[i]);
		bcm_bprintf(b, "ioctrlset 0x%x ioctrlclear 0x%x ioctrl 0x%x iostatus 0x%x"
			    "ioctrlwidth 0x%x iostatuswidth 0x%x\n"
			    "resetctrl 0x%x resetstatus 0x%x resetreadid 0x%x resetwriteid 0x%x\n"
			    "errlogctrl 0x%x errlogdone 0x%x errlogstatus 0x%x"
			    "errlogaddrlo 0x%x errlogaddrhi 0x%x\n"
			    "errlogid 0x%x errloguser 0x%x errlogflags 0x%x\n"
			    "intstatus 0x%x config 0x%x itcr 0x%x\n",
			    R_REG(osh, &ai->ioctrlset),
			    R_REG(osh, &ai->ioctrlclear),
			    R_REG(osh, &ai->ioctrl),
			    R_REG(osh, &ai->iostatus),
			    R_REG(osh, &ai->ioctrlwidth),
			    R_REG(osh, &ai->iostatuswidth),
			    R_REG(osh, &ai->resetctrl),
			    R_REG(osh, &ai->resetstatus),
			    R_REG(osh, &ai->resetreadid),
			    R_REG(osh, &ai->resetwriteid),
			    R_REG(osh, &ai->errlogctrl),
			    R_REG(osh, &ai->errlogdone),
			    R_REG(osh, &ai->errlogstatus),
			    R_REG(osh, &ai->errlogaddrlo),
			    R_REG(osh, &ai->errlogaddrhi),
			    R_REG(osh, &ai->errlogid),
			    R_REG(osh, &ai->errloguser),
			    R_REG(osh, &ai->errlogflags),
			    R_REG(osh, &ai->intstatus),
			    R_REG(osh, &ai->config),
			    R_REG(osh, &ai->itcr));
	}
}
#endif	/* BCMDBG || BCMDBG_DUMP */

#ifdef BCMDBG
static void
_ai_view(osl_t *osh, aidmp_t *ai, uint32 cid, uint32 addr, bool verbose)
{
	uint32 config;

	config = R_REG(osh, &ai->config);
	SI_ERROR(("\nCore ID: 0x%x, addr 0x%x, config 0x%x\n", cid, addr, config));

	if (config & AICFG_RST) {
		SI_ERROR(("resetctrl 0x%x, resetstatus 0x%x, resetreadid 0x%x, resetwriteid 0x%x\n",
		          R_REG(osh, &ai->resetctrl), R_REG(osh, &ai->resetstatus),
		          R_REG(osh, &ai->resetreadid), R_REG(osh, &ai->resetwriteid)));
    }

	if (config & AICFG_IOC) {
		SI_ERROR(("ioctrl 0x%x, width %d\n", R_REG(osh, &ai->ioctrl),
		          R_REG(osh, &ai->ioctrlwidth)));
    }
    
	if (config & AICFG_IOS) {
		SI_ERROR(("iostatus 0x%x, width %d\n", R_REG(osh, &ai->iostatus),
		          R_REG(osh, &ai->iostatuswidth)));
    }
    
	if (config & AICFG_ERRL) {
		SI_ERROR(("errlogctrl 0x%x, errlogdone 0x%x, errlogstatus 0x%x, intstatus 0x%x\n",
		          R_REG(osh, &ai->errlogctrl), R_REG(osh, &ai->errlogdone),
		          R_REG(osh, &ai->errlogstatus), R_REG(osh, &ai->intstatus)));
		SI_ERROR(("errlogid 0x%x, errloguser 0x%x, errlogflags 0x%x, errlogaddr "
		          "0x%x/0x%x\n",
		          R_REG(osh, &ai->errlogid), R_REG(osh, &ai->errloguser),
		          R_REG(osh, &ai->errlogflags), R_REG(osh, &ai->errlogaddrhi),
		          R_REG(osh, &ai->errlogaddrlo)));
	}

	if (verbose && (config & AICFG_OOB)) {
		SI_ERROR(("oobselina30 0x%x, oobselina74 0x%x\n",
		          R_REG(osh, &ai->oobselina30), R_REG(osh, &ai->oobselina74)));
		SI_ERROR(("oobselinb30 0x%x, oobselinb74 0x%x\n",
		          R_REG(osh, &ai->oobselinb30), R_REG(osh, &ai->oobselinb74)));
		SI_ERROR(("oobselinc30 0x%x, oobselinc74 0x%x\n",
		          R_REG(osh, &ai->oobselinc30), R_REG(osh, &ai->oobselinc74)));
		SI_ERROR(("oobselind30 0x%x, oobselind74 0x%x\n",
		          R_REG(osh, &ai->oobselind30), R_REG(osh, &ai->oobselind74)));
		SI_ERROR(("oobselouta30 0x%x, oobselouta74 0x%x\n",
		          R_REG(osh, &ai->oobselouta30), R_REG(osh, &ai->oobselouta74)));
		SI_ERROR(("oobseloutb30 0x%x, oobseloutb74 0x%x\n",
		          R_REG(osh, &ai->oobseloutb30), R_REG(osh, &ai->oobseloutb74)));
		SI_ERROR(("oobseloutc30 0x%x, oobseloutc74 0x%x\n",
		          R_REG(osh, &ai->oobseloutc30), R_REG(osh, &ai->oobseloutc74)));
		SI_ERROR(("oobseloutd30 0x%x, oobseloutd74 0x%x\n",
		          R_REG(osh, &ai->oobseloutd30), R_REG(osh, &ai->oobseloutd74)));
		SI_ERROR(("oobsynca 0x%x, oobseloutaen 0x%x\n",
		          R_REG(osh, &ai->oobsynca), R_REG(osh, &ai->oobseloutaen)));
		SI_ERROR(("oobsyncb 0x%x, oobseloutben 0x%x\n",
		          R_REG(osh, &ai->oobsyncb), R_REG(osh, &ai->oobseloutben)));
		SI_ERROR(("oobsyncc 0x%x, oobseloutcen 0x%x\n",
		          R_REG(osh, &ai->oobsyncc), R_REG(osh, &ai->oobseloutcen)));
		SI_ERROR(("oobsyncd 0x%x, oobseloutden 0x%x\n",
		          R_REG(osh, &ai->oobsyncd), R_REG(osh, &ai->oobseloutden)));
		SI_ERROR(("oobaextwidth 0x%x, oobainwidth 0x%x, oobaoutwidth 0x%x\n",
		          R_REG(osh, &ai->oobaextwidth), R_REG(osh, &ai->oobainwidth),
		          R_REG(osh, &ai->oobaoutwidth)));
		SI_ERROR(("oobbextwidth 0x%x, oobbinwidth 0x%x, oobboutwidth 0x%x\n",
		          R_REG(osh, &ai->oobbextwidth), R_REG(osh, &ai->oobbinwidth),
		          R_REG(osh, &ai->oobboutwidth)));
		SI_ERROR(("oobcextwidth 0x%x, oobcinwidth 0x%x, oobcoutwidth 0x%x\n",
		          R_REG(osh, &ai->oobcextwidth), R_REG(osh, &ai->oobcinwidth),
		          R_REG(osh, &ai->oobcoutwidth)));
		SI_ERROR(("oobdextwidth 0x%x, oobdinwidth 0x%x, oobdoutwidth 0x%x\n",
		          R_REG(osh, &ai->oobdextwidth), R_REG(osh, &ai->oobdinwidth),
		          R_REG(osh, &ai->oobdoutwidth)));
	}
}

void
ai_view(si_t *sih, bool verbose)
{
	si_info_t *sii;
	osl_t *osh;
	aidmp_t *ai;
	uint32 cid, addr;

	sii = SI_INFO(sih);
	ai = sii->curwrap;
	osh = sii->osh;

	cid = sii->coreid[sii->curidx];
	addr = sii->wrapba[sii->curidx];
	_ai_view(osh, ai, cid, addr, verbose);
}

void
ai_viewall(si_t *sih, bool verbose)
{
	si_info_t *sii;
	osl_t *osh;
	aidmp_t *ai;
	uint32 cid, addr;
	uint i;

	sii = SI_INFO(sih);
	osh = sii->osh;
	for (i = 0; i < sii->numcores; i++) {
		si_setcoreidx(sih, i);

		ai = sii->curwrap;
		cid = sii->coreid[sii->curidx];
		addr = sii->wrapba[sii->curidx];
		_ai_view(osh, ai, cid, addr, verbose);
	}
}
#endif	/* BCMDBG */
