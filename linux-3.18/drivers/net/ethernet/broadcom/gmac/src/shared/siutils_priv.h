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
 * Include file private to the SOC Interconnect support files.
 *
 * $Id: siutils_priv.h 302333 2011-12-11 01:47:49Z $
 */

#ifndef	_siutils_priv_h_
#define	_siutils_priv_h_

#ifdef BCMDBG_ERR
#define	SI_ERROR(args)	printf args
#else
#define	SI_ERROR(args)
#endif	/* BCMDBG_ERR */

#ifdef BCMDBG
#define	SI_MSG(args)	printf args
#else
#define	SI_MSG(args)
#endif	/* BCMDBG */

#ifdef BCMDBG_SI
#define	SI_VMSG(args)	printf args
#else
#define	SI_VMSG(args)
#endif

#define	IS_SIM(chippkg)	((chippkg == HDLSIM_PKG_ID) || (chippkg == HWSIM_PKG_ID))

typedef uint32 (*si_intrsoff_t)(void *intr_arg);
typedef void (*si_intrsrestore_t)(void *intr_arg, uint32 arg);
typedef bool (*si_intrsenabled_t)(void *intr_arg);

typedef struct gpioh_item {
	void			*arg;
	bool			level;
	gpio_handler_t		handler;
	uint32			event;
	struct gpioh_item	*next;
} gpioh_item_t;

/* misc si info needed by some of the routines */
typedef struct si_info {
	struct      si_pub pub;     /* back plane public state (must be first field) */

	void        *osh;           /* osl os handle */
	void        *sdh;           /* bcmsdh handle */

	uint        dev_coreid;     /* the core provides driver functions */
	void        *intr_arg;      /* interrupt callback function arg */
	si_intrsoff_t intrsoff_fn;  /* turns chip interrupts off */
	si_intrsrestore_t intrsrestore_fn;  /* restore chip interrupts */
	si_intrsenabled_t intrsenabled_fn;  /* check if interrupts are enabled */

	void        *pch;               /* PCI/E core handle */
	gpioh_item_t    *gpioh_head;    /* GPIO event handlers list */
	bool        memseg;             /* flag to toggle MEM_SEG register */
	char        *vars;
	uint        varsz;

	void        *curmap;            /* current regs va */
	void        *regs[SI_MAXCORES]; /* other regs va */

	uint        curidx;             /* current core index */
	uint        numcores;           /* # discovered cores */
	uint        coreid[SI_MAXCORES];    /* id of each core */
	uint32      coresba[SI_MAXCORES];   /* backplane address of each core */
	void        *regs2[SI_MAXCORES];    /* va of each core second register set (usbh20) */
	uint32      coresba2[SI_MAXCORES];  /* address of each core second register set (usbh20) */
	uint32      coresba_size[SI_MAXCORES];  /* backplane address space size */
	uint32      coresba2_size[SI_MAXCORES]; /* second address space size */

	void        *curwrap;               /* current wrapper va */
	void        *wrappers[SI_MAXCORES]; /* other cores wrapper va */
	uint32      wrapba[SI_MAXCORES];    /* address of controlling wrapper */

	uint32      cia[SI_MAXCORES];       /* erom cia entry for each core */
	uint32      cib[SI_MAXCORES];       /* erom cia entry for each core */
	uint32      oob_router;             /* oob router registers for axi */
} si_info_t;

#define	SI_INFO(sih)	(si_info_t *)(uintptr)sih

#define	GOODCOREADDR(x, b) (((x) >= (b)) && ((x) < ((b) + SI_MAXCORES * SI_CORE_SIZE)) && \
		ISALIGNED((x), SI_CORE_SIZE))
#define	GOODREGS(regs)	((regs) != NULL && ISALIGNED((uintptr)(regs), SI_CORE_SIZE))
#define BADCOREADDR	0
#define	GOODIDX(idx)	(((uint)idx) < SI_MAXCORES)
#define	NOREV		-1		/* Invalid rev */

#define PCI(si)		((BUSTYPE((si)->pub.bustype) == PCI_BUS) &&	\
			 ((si)->pub.buscoretype == PCI_CORE_ID))

#define PCIE_GEN1(si)	((BUSTYPE((si)->pub.bustype) == PCI_BUS) &&	\
			 ((si)->pub.buscoretype == PCIE_CORE_ID))

#define PCIE_GEN2(si)	((BUSTYPE((si)->pub.bustype) == PCI_BUS) &&	\
			 ((si)->pub.buscoretype == PCIE2_CORE_ID))

#define PCIE(si)	(PCIE_GEN1(si) || PCIE_GEN2(si))

#define PCMCIA(si)	((BUSTYPE((si)->pub.bustype) == PCMCIA_BUS) && ((si)->memseg == TRUE))

/* Newer chips can access PCI/PCIE and CC core without requiring to change
 * PCI BAR0 WIN
 */
#define SI_FAST(si) (PCIE(si) || (PCI(si) && ((si)->pub.buscorerev >= 13)))

#define PCIEREGS(si) (((char *)((si)->curmap) + PCI_16KB0_PCIREGS_OFFSET))
#define CCREGS_FAST(si) (((char *)((si)->curmap) + PCI_16KB0_CCREGS_OFFSET))

/*
 * Macros to disable/restore function core(D11, ENET, ILINE20, etc) interrupts before/
 * after core switching to avoid invalid register accesss inside ISR.
 */
#define INTR_OFF(si, intr_val) \
	if ((si)->intrsoff_fn && (si)->coreid[(si)->curidx] == (si)->dev_coreid) {	\
		intr_val = (*(si)->intrsoff_fn)((si)->intr_arg); }
#define INTR_RESTORE(si, intr_val) \
	if ((si)->intrsrestore_fn && (si)->coreid[(si)->curidx] == (si)->dev_coreid) {	\
		(*(si)->intrsrestore_fn)((si)->intr_arg, intr_val); }

/* dynamic clock control defines */
#define	LPOMINFREQ		25000		/* low power oscillator min */
#define	LPOMAXFREQ		43000		/* low power oscillator max */
#define	XTALMINFREQ		19800000	/* 20 MHz - 1% */
#define	XTALMAXFREQ		20200000	/* 20 MHz + 1% */
#define	PCIMINFREQ		25000000	/* 25 MHz */
#define	PCIMAXFREQ		34000000	/* 33 MHz + fudge */

#define	ILP_DIV_5MHZ		0		/* ILP = 5 MHz */
#define	ILP_DIV_1MHZ		4		/* ILP = 1 MHz */

/* GPIO Based LED powersave defines */
#define DEFAULT_GPIO_ONTIME	10		/* Default: 10% on */
#define DEFAULT_GPIO_OFFTIME	90		/* Default: 10% on */
#ifndef DEFAULT_GPIOTIMERVAL
#define DEFAULT_GPIOTIMERVAL  ((DEFAULT_GPIO_ONTIME << GPIO_ONTIME_SHIFT) | DEFAULT_GPIO_OFFTIME)
#endif

#define sb_scan(a, b, c) do {} while (0)
#define sb_coreid(a) (0)
#define sb_intflag(a) (0)
#define sb_flag(a) (0)
#define sb_setint(a, b) do {} while (0)
#define sb_corevendor(a) (0)
#define sb_corerev(a) (0)
#define sb_corereg(a, b, c, d, e) (0)
#define sb_iscoreup(a) (false)
#define sb_setcoreidx(a, b) (0)
#define sb_core_cflags(a, b, c) (0)
#define sb_core_cflags_wo(a, b, c) do {} while (0)
#define sb_core_sflags(a, b, c) (0)
#define sb_commit(a) do {} while (0)
#define sb_base(a) (0)
#define sb_size(a) (0)
#define sb_core_reset(a, b, c) do {} while (0)
#define sb_core_disable(a, b) do {} while (0)
#define sb_addrspace(a, b)  (0)
#define sb_addrspacesize(a, b) (0)
#define sb_numaddrspaces(a) (0)
#define sb_set_initiator_to(a, b, c) (0)
#define sb_taclear(a, b) (false)
#define sb_view(a, b) do {} while (0)
#define sb_viewall(a, b) do {} while (0)
#define sb_dump(a, b) do {} while (0)
#define sb_dumpregs(a, b) do {} while (0)


/* AMBA Interconnect exported externs */
extern si_t *ai_attach(uint pcidev, osl_t *osh, void *regs, uint bustype,
                       void *sdh, char **vars, uint *varsz);
extern si_t *ai_kattach(osl_t *osh);
extern void ai_scan(si_t *sih, void *regs, uint devid);
extern uint ai_flag(si_t *sih);
extern void ai_setint(si_t *sih, int siflag);
extern uint ai_coreidx(si_t *sih);
extern uint ai_corevendor(si_t *sih);
extern uint ai_corerev(si_t *sih);
extern bool ai_iscoreup(si_t *sih);
extern void *ai_setcoreidx(si_t *sih, uint coreidx);
extern uint32 ai_core_cflags(si_t *sih, uint32 mask, uint32 val);
extern void ai_core_cflags_wo(si_t *sih, uint32 mask, uint32 val);
extern uint32 ai_core_sflags(si_t *sih, uint32 mask, uint32 val);
extern uint ai_corereg(si_t *sih, uint coreidx, uint regoff, uint mask, uint val);
extern void ai_core_reset(si_t *sih, uint32 bits, uint32 resetbits);
extern void ai_core_disable(si_t *sih, uint32 bits);
extern int ai_numaddrspaces(si_t *sih);
extern uint32 ai_addrspace(si_t *sih, uint asidx);
extern uint32 ai_addrspacesize(si_t *sih, uint asidx);
extern void ai_coreaddrspaceX(si_t *sih, uint asidx, uint32 *addr, uint32 *size);
extern uint ai_wrap_reg(si_t *sih, uint32 offset, uint32 mask, uint32 val);
#ifdef BCMDBG
extern void ai_view(si_t *sih, bool verbose);
extern void ai_viewall(si_t *sih, bool verbose);
#endif /* BCMDBG */
#if defined(BCMDBG)
extern void ai_dumpregs(si_t *sih, struct bcmstrbuf *b);
#endif 


#define ub_scan(a, b, c) do {} while (0)
#define ub_flag(a) (0)
#define ub_setint(a, b) do {} while (0)
#define ub_coreidx(a) (0)
#define ub_corevendor(a) (0)
#define ub_corerev(a) (0)
#define ub_iscoreup(a) (0)
#define ub_setcoreidx(a, b) (0)
#define ub_core_cflags(a, b, c) (0)
#define ub_core_cflags_wo(a, b, c) do {} while (0)
#define ub_core_sflags(a, b, c) (0)
#define ub_corereg(a, b, c, d, e) (0)
#define ub_core_reset(a, b, c) do {} while (0)
#define ub_core_disable(a, b) do {} while (0)
#define ub_numaddrspaces(a) (0)
#define ub_addrspace(a, b)  (0)
#define ub_addrspacesize(a, b) (0)
#define ub_view(a, b) do {} while (0)
#define ub_dumpregs(a, b) do {} while (0)

#endif	/* _siutils_priv_h_ */
