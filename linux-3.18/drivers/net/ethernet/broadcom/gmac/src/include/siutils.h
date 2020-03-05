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
 * Misc utility routines for accessing the SOC Interconnects
 * of Broadcom HNBU chips.
 *
 * $Id: siutils.h 323456 2012-03-24 07:17:39Z $
 */

#ifndef	_siutils_h_
#define	_siutils_h_

#if defined(WLC_HIGH) && !defined(WLC_LOW)
#include "bcm_rpc.h"
#endif
/*
 * Data structure to export all chip specific common variables
 *   public (read-only) portion of siutils handle returned by si_attach()
 */
struct si_pub {
	uint	    socitype;       /* SOCI_SB, SOCI_AI */

	uint        bustype;        /* SI_BUS, PCI_BUS */
	uint        buscoretype;    /* PCI_CORE_ID, PCIE_CORE_ID, PCMCIA_CORE_ID */
	uint        buscorerev;     /* buscore rev */
	uint        buscoreidx;     /* buscore index */
	int         ccrev;          /* chip common core rev */
	uint32      cccaps;         /* chip common capabilities */
	uint32      cccaps_ext;     /* chip common capabilities extension */
	int         pmurev;         /* pmu core rev */
	uint32      pmucaps;        /* pmu capabilities */
	uint        boardtype;      /* board type */
	uint        boardrev;       /* board rev */
	uint        boardvendor;    /* board vendor */
	uint        boardflags;     /* board flags */
	uint        boardflags2;    /* board flags2 */
	uint        chip;           /* chip number */
	uint        chiprev;        /* chip revision */
	uint        chippkg;        /* chip package option */
	uint32      chipst;         /* chip status */
	bool        issim;          /* chip is in simulation or emulation */
	uint        socirev;        /* SOC interconnect rev */
	bool        pci_pr32414;
    spinlock_t  sih_lock;
    
#if defined(WLC_HIGH) && !defined(WLC_LOW)
	rpc_info_t  *rpc;
#endif
};

/* for HIGH_ONLY driver, the si_t must be writable to allow states sync from BMAC to HIGH driver
 * for monolithic driver, it is readonly to prevent accident change
 */
#if defined(WLC_HIGH) && !defined(WLC_LOW)
typedef struct si_pub si_t;
#else
typedef const struct si_pub si_t;
#endif

#ifdef ATE_BUILD
typedef struct _ate_params {
	void* wl;
	uint8 gpio_input;
	uint8 gpio_output;
	bool cmd_proceed;
	uint16 cmd_idx;
	bool ate_cmd_done;
} ate_params_t;
#endif /* ATE_BUILD */

/*
 * Many of the routines below take an 'sih' handle as their first arg.
 * Allocate this by calling si_attach().  Free it by calling si_detach().
 * At any one time, the sih is logically focused on one particular si core
 * (the "current core").
 * Use si_setcore() or si_setcoreidx() to change the association to another core.
 */
#define	BADIDX		(SI_MAXCORES + 1)

/* clkctl xtal what flags */
#define	XTAL			0x1	/* primary crystal oscillator (2050) */
#define	PLL			0x2	/* main chip pll */

/* clkctl clk mode */
#define	CLK_FAST		0	/* force fast (pll) clock */
#define	CLK_DYNAMIC		2	/* enable dynamic clock control */

/* GPIO usage priorities */
#define GPIO_DRV_PRIORITY	0	/* Driver */
#define GPIO_APP_PRIORITY	1	/* Application */
#define GPIO_HI_PRIORITY	2	/* Highest priority. Ignore GPIO reservation */

/* GPIO pull up/down */
#define GPIO_PULLUP		0
#define GPIO_PULLDN		1

/* GPIO event regtype */
#define GPIO_REGEVT		0	/* GPIO register event */
#define GPIO_REGEVT_INTMSK	1	/* GPIO register event int mask */
#define GPIO_REGEVT_INTPOL	2	/* GPIO register event int polarity */

/* device path */
#define SI_DEVPATH_BUFSZ	16	/* min buffer size in bytes */

/* SI routine enumeration: to be used by update function with multiple hooks */
#define	SI_DOATTACH	1
#define SI_PCIDOWN	2
#define SI_PCIUP	3

#if defined(BCMQT)
#define	ISSIM_ENAB(sih)	((sih)->issim)
#else
#define	ISSIM_ENAB(sih)	0
#endif

/* PMU clock/power control */
#if defined(BCMPMUCTL)
#define PMUCTL_ENAB(sih)	(BCMPMUCTL)
#else
#define PMUCTL_ENAB(sih)	((sih)->cccaps & CC_CAP_PMU)
#endif

/* chipcommon clock/power control (exclusive with PMU's) */
#if defined(BCMPMUCTL) && BCMPMUCTL
#define CCCTL_ENAB(sih)		(0)
#define CCPLL_ENAB(sih)		(0)
#else
#define CCCTL_ENAB(sih)		((sih)->cccaps & CC_CAP_PWR_CTL)
#define CCPLL_ENAB(sih)		((sih)->cccaps & CC_CAP_PLL_MASK)
#endif

typedef void (*gpio_handler_t)(uint32 stat, void *arg);
/* External BT Coex enable mask */
#define CC_BTCOEX_EN_MASK  0x01
/* External PA enable mask */
#define GPIO_CTRL_EPA_EN_MASK 0x40
/* WL/BT control enable mask */
#define GPIO_CTRL_5_6_EN_MASK 0x60
#define GPIO_CTRL_7_6_EN_MASK 0xC0
#define GPIO_OUT_7_EN_MASK 0x80


/* === exported functions === */
extern si_t *si_attach(uint pcidev, osl_t *osh, void *regs, uint bustype,
                       void *sdh, char **vars, uint *varsz);
extern void si_detach(si_t *sih);

extern uint si_corelist(si_t *sih, uint coreid[]);
extern uint si_coreid(si_t *sih);
extern uint si_flag(si_t *sih);
extern uint si_intflag(si_t *sih);
extern uint si_coreidx(si_t *sih);
extern uint si_coreunit(si_t *sih);
extern uint si_corevendor(si_t *sih);
extern uint si_corerev(si_t *sih);
extern void *si_osh(si_t *sih);
extern void si_setosh(si_t *sih, osl_t *osh);
extern uint si_corereg(si_t *sih, uint coreidx, uint regoff, uint mask, uint val);
extern void *si_coreregs(si_t *sih);
extern uint si_wrapperreg(si_t *sih, uint32 offset, uint32 mask, uint32 val);
extern uint32 si_core_cflags(si_t *sih, uint32 mask, uint32 val);
extern void si_core_cflags_wo(si_t *sih, uint32 mask, uint32 val);
extern uint32 si_core_sflags(si_t *sih, uint32 mask, uint32 val);
#ifdef WLC_HIGH_ONLY
extern bool wlc_bmac_iscoreup(si_t *sih);
#define si_iscoreup(sih)	wlc_bmac_iscoreup(sih)
#else
extern bool si_iscoreup(si_t *sih);
#endif /* __CONFIG_USBAP__ */
extern uint si_findcoreidx(si_t *sih, uint coreid, uint coreunit);
extern void *si_setcoreidx(si_t *sih, uint coreidx);
extern void *si_setcore(si_t *sih, uint coreid, uint coreunit);
extern void *si_switch_core(si_t *sih, uint coreid, uint *origidx, uint *intr_val);
extern void si_restore_core(si_t *sih, uint coreid, uint intr_val);
extern int si_numaddrspaces(si_t *sih);
extern uint32 si_addrspace(si_t *sih, uint asidx);
extern uint32 si_addrspacesize(si_t *sih, uint asidx);
extern void si_coreaddrspaceX(si_t *sih, uint asidx, uint32 *addr, uint32 *size);
extern int si_corebist(si_t *sih);
extern void si_core_reset(si_t *sih, uint32 bits, uint32 resetbits);
extern void si_core_disable(si_t *sih, uint32 bits);
extern uint32 si_clock_rate(uint32 pll_type, uint32 n, uint32 m);
extern uint32 si_clock(si_t *sih);
extern void si_setint(si_t *sih, int siflag);
extern bool si_backplane64(si_t *sih);
extern void si_clkctl_init(si_t *sih);
extern bool si_clkctl_cc(si_t *sih, uint mode);
extern int si_clkctl_xtal(si_t *sih, uint what, bool on);

extern uint32 si_gpioouten(si_t *sih, uint32 mask, uint32 val, uint8 priority);
extern uint32 si_gpioout(si_t *sih, uint32 mask, uint32 val, uint8 priority);

/* Wake-on-wireless-LAN (WOWL) */
extern bool si_pci_pmecap(si_t *sih);
struct osl_info;
extern bool si_pci_fastpmecap(struct osl_info *osh);

/* Fab-id information */
#define	DEFAULT_FAB	0x0	/* Original/first fab used for this chip */
#define	CSM_FAB7	0x1	/* CSM Fab7 chip */
#define	TSMC_FAB12	0x2	/* TSMC Fab12/Fab14 chip */
#define	SMIC_FAB4	0x3	/* SMIC Fab4 chip */

/*
 * Build device path. Path size must be >= SI_DEVPATH_BUFSZ.
 * The returned path is NULL terminated and has trailing '/'.
 * Return 0 on success, nonzero otherwise.
 */
extern int si_devpath(si_t *sih, char *path, int size);
/* Read variable with prepending the devpath to the name */
extern int si_getdevpathintvar(si_t *sih, const char *name);
extern char *si_coded_devpathvar(si_t *sih, char *varname, int var_len, const char *name);


extern void si_war42780_clkreq(si_t *sih, bool clkreq);
extern void si_pcie_extendL1timer(si_t *sih, bool extend);

/* === debug routines === */

#ifdef BCMDBG
extern void si_view(si_t *sih, bool verbose);
extern void si_viewall(si_t *sih, bool verbose);
#endif

#if defined(BCMDBG)
struct bcmstrbuf;
extern void si_dumpregs(si_t *sih, struct bcmstrbuf *b);
#endif 


#endif	/* _siutils_h_ */
