/*
 * $Copyright Open Broadcom Corporation$
 *
 * Broadcom Gigabit Ethernet MAC (Unimac) core.
 * This file implements the chip-specific routines for the GMAC core.
 *
 * $Id: etcgmac.c 327582 2012-04-14 05:02:37Z kenlo $
 */

#include <linux/of_address.h>
#include <et_cfg.h>
#include <typedefs.h>
#include <osl.h>
#include <bcmdefs.h>
#include <bcmendian.h>
#include <bcmutils.h>
#include <bcmdevs.h>
#include <bcmenetphy.h>
#include <proto/ethernet.h>
#include <proto/802.1d.h>
#include <siutils.h>
#include <sbhnddma.h>
#include <sbchipc.h>
#include <hnddma.h>
#include <et_dbg.h>
#include <hndsoc.h>
#include <bcmgmacmib.h>
#include <gmac_common.h>
#include <gmac_core.h>
#include <et_export.h>		/* for et_phyxx() routines */
#include <etcgmac.h>
#include <bcmenetrxh.h>
#include <bcmgmacrxh.h>
#include <mach/iproc_regs.h>
#include "bcmiproc_phy.h"

#define ENABLE_MIB_REG_DUMP
#if defined (CONFIG_MACH_KT2)
#define IPROC_WRAP_MISC_CONTROL_OFFSET 0x24
#elif (defined (CONFIG_MACH_HX4) || defined (CONFIG_MACH_HR2))
#define IPROC_WRAP_MISC_CONTROL_OFFSET 0x3C
#else
#define IPROC_WRAP_MISC_CONTROL_OFFSET 0x40
#endif

#if defined(CONFIG_MACH_HX4)
#include "mach/socregs_ing_open.h"
#endif
#if defined(CONFIG_MACH_KT2)
#include "mach/socregs_ing_open.h"
#endif
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2))
#include "bcmiproc_serdes.h"
#include "bcmiproc_phy5461s.h"
#endif
#if defined(CONFIG_MACH_HR2)
#include "bcmiproc_phy5221.h"
#endif
#if defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2)
#include "bcmiproc_phy5481.h"
#endif

#if !defined(CONFIG_MACH_HR2)
/* BCM5221 on HR2 board does not support this feature */
#define CONFIG_FORCED_MODE_AUTO_MDIX 1
#endif

struct bcmgmac;	/* forward declaration */
#define ch_t            struct bcmgmac
#include <etc.h>

extern int nvram_env_gmac_name(int gmac, char *name);

/* private chip state */
struct bcmgmac {
    void        *et;        /* pointer to et private state */
    etc_info_t  *etc;       /* pointer to etc public state */

    gmac_commonregs_t   *regscomm;  /* pointer to GMAC COMMON registers */
    gmacregs_t  *regs;      /* pointer to chip registers */
    osl_t       *osh;       /* os handle */

    void        *etphy;     /* pointer to et for shared mdc/mdio contortion */

    uint32      intstatus;  /* saved interrupt condition bits */
    uint32      intmask;    /* current software interrupt mask */
    uint32      def_intmask;/* default interrupt mask */

    hnddma_t    *di[NUMTXQ];/* dma engine software state */

    bool        mibgood;    /* true once mib registers have been cleared */
    gmacmib_t   mib;        /* mib statistic counters */
    si_t        *sih;       /* si utils handle */

    char        *vars;      /* sprom name=value */
    uint        vars_size;

    void        *adm;       /* optional admtek private data */
    mcfilter_t  mf;         /* multicast filter */
};

/* local prototypes */
static bool chipid(uint vendor, uint device);
static void *chipattach(etc_info_t *etc, void *osh, void *regsva);
static void chipdetach(ch_t *ch);
static void chipreset(ch_t *ch);
static void chipinit(ch_t *ch, uint options);
static bool chiptx(ch_t *ch, void *p);
static void *chiprx(ch_t *ch);
static void chiprxfill(ch_t *ch);
static int chipgetintrevents(ch_t *ch, bool in_isr);
static bool chiperrors(ch_t *ch);
static void chipintrson(ch_t *ch);
static void chipintrsoff(ch_t *ch);
static void chiptxreclaim(ch_t *ch, bool all);
static void chiprxreclaim(ch_t *ch);
static void chipstatsupd(ch_t *ch);
static void chipdumpmib(ch_t *ch, struct bcmstrbuf *b, bool clear);
static void chipenablepme(ch_t *ch);
static void chipdisablepme(ch_t *ch);
static void chipphyreset(ch_t *ch, uint phyaddr);
static uint16 chipphyrd(ch_t *ch, uint phyaddr, uint reg);
static void chipphywr(ch_t *ch, uint phyaddr, uint reg, uint16 v);
static void chipdump(ch_t *ch, struct bcmstrbuf *b);
static void chiplongname(ch_t *ch, char *buf, uint bufsize);
static void chipduplexupd(ch_t *ch);
#ifdef CONFIG_SERDES_ASYMMETRIC_MODE
static void chipforcespddpx(ch_t *ch);
#endif /* CONFIG_SERDES_ASYMMETRIC_MODE */

static void chipphyinit(ch_t *ch, uint phyaddr);
static void chipphyor(ch_t *ch, uint phyaddr, uint reg, uint16 v);
static void chipphyforce(ch_t *ch, uint phyaddr);
static void chipphyadvertise(ch_t *ch, uint phyaddr);
static void chipphyenable(ch_t *ch, uint eth_num, uint phyaddr, int enable);
static void chipdumpregs(ch_t *ch, gmacregs_t *regs, struct bcmstrbuf *b);
static void gmac_mf_cleanup(ch_t *ch);
static int gmac_speed(ch_t *ch, uint32 speed);
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2))
static void gmac_serdes_init(ch_t *ch);
#endif
static void gmac_miiconfig(ch_t *ch);

struct chops bcmgmac_et_chops = {
	chipid,
	chipattach,
	chipdetach,
	chipreset,
	chipinit,
	chiptx,
	chiprx,
	chiprxfill,
	chipgetintrevents,
	chiperrors,
	chipintrson,
	chipintrsoff,
	chiptxreclaim,
	chiprxreclaim,
	chipstatsupd,
	chipdumpmib,
	chipenablepme,
	chipdisablepme,
	chipphyreset,
	chipphyrd,
	chipphywr,
	chipdump,
	chiplongname,
	chipduplexupd,
#ifdef CONFIG_SERDES_ASYMMETRIC_MODE
	chipforcespddpx,
#endif /* CONFIG_SERDES_ASYMMETRIC_MODE */
	chipphyenable
};

static uint devices[] = {
	BCM56150_CHIP_ID,
	BCM56340_CHIP_ID,
	BCM56450_CHIP_ID,
	BCM53400_CHIP_ID,
	BCM56260_CHIP_ID,
	BCM56160_CHIP_ID,
	0x0000
};


#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2))
static void *wrapaddr = 0;
void gmac_set_amac_mdio(int en)
{
	struct device_node *np;
	u32 tmp;
#if defined(CONFIG_MACH_HX4)
	u32 mdio_sel= IPROC_WRAP_MISC_CONTROL__QUAD_SERDES_MDIO_SEL;
	u32 ctrl_sel= IPROC_WRAP_MISC_CONTROL__QUAD_SERDES_CTRL_SEL;
#elif defined(CONFIG_MACH_KT2)
	u32 mdio_sel= IPROC_WRAP_MISC_CONTROL__UNICORE_SERDES_MDIO_SEL;
	u32 ctrl_sel= IPROC_WRAP_MISC_CONTROL__UNICORE_SERDES_CTRL_SEL;
#endif
	u32 iproc_mdio_sel= IPROC_WRAP_MISC_CONTROL__IPROC_MDIO_SEL;

	if (en) {
	    /* Get register base address */
		np = of_find_compatible_node(NULL, NULL, "broadcom,hx4-wrap-ctrl");
		if (!np) {
			printk(KERN_ERR "No WRAP_CTRL found\n");
		}
		wrapaddr = of_iomap(np, 0);
		if (!wrapaddr) {
			printk(KERN_ERR "WRAP_CTRL could not be mapped\n");
		}
		wrapaddr += IPROC_WRAP_MISC_CONTROL_OFFSET;
	}

	tmp = ioread32(wrapaddr);
	if (en) {
#if defined(CONFIG_MACH_SB2)
        /* set bits IPROC_WRAP_MISC_CONTROL__IPROC_MDIO_SEL
			so AMAC can access the Serdes and Phy */
        tmp |= (1 << iproc_mdio_sel);
#else
		/* set bits IPROC_WRAP_MISC_CONTROL__IPROC_MDIO_SEL,
		            IPROC_WRAP_MISC_CONTROL__QUAD_SERDES_MDIO_SEL &
		            IPROC_WRAP_MISC_CONTROL__QUAD_SERDES_CTRL_SEL
			so AMAC can access the Serdes and Phy */
		tmp |= ((1 << mdio_sel) | (1 << ctrl_sel) | (1 << iproc_mdio_sel));
#endif
	} else {
#if defined(CONFIG_MACH_SB2)
        /* clear bits IPROC_WRAP_MISC_CONTROL__IPROC_MDIO_SEL
		    so CMIC can access the Serdes and Phy */
        tmp &= ~(1 << iproc_mdio_sel);
#else
		/* clear bits IPROC_WRAP_MISC_CONTROL__IPROC_MDIO_SEL &
		              IPROC_WRAP_MISC_CONTROL__QUAD_SERDES_MDIO_SEL
		    so CMIC can access the Serdes and Phy */
		tmp &= ~((1 << mdio_sel) | (1 << iproc_mdio_sel));
#endif
	}
	iowrite32(tmp, wrapaddr);

	if (!en) {
		wrapaddr=0;
	}
}


int gmac_has_mdio_access(void)
{
	u32 tmp;
	u32 regmsk = (1 << IPROC_WRAP_MISC_CONTROL__IPROC_MDIO_SEL);

#if defined(CONFIG_MACH_HX4)
	regmsk |= ((1 << IPROC_WRAP_MISC_CONTROL__QUAD_SERDES_MDIO_SEL) |
		       (1 << IPROC_WRAP_MISC_CONTROL__QUAD_SERDES_CTRL_SEL));
#elif defined(CONFIG_MACH_KT2)
	regmsk |= ((1 << IPROC_WRAP_MISC_CONTROL__UNICORE_SERDES_MDIO_SEL) |
               (1 << IPROC_WRAP_MISC_CONTROL__UNICORE_SERDES_CTRL_SEL));
#endif

	if (wrapaddr==0) {
		/* if no wrapaddr then no access */
		return 0;
	}

	tmp = ioread32(wrapaddr);
	tmp &= ~regmsk;
	if (tmp == regmsk) {
		return 0;
	}

	return 1;
}
#endif /* (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2)) */

/* This api will determine if this unit specified is the last interface. */
bool gmac_last_interface(int unit)
{
	char name[128];
	int idx;

	/* if interface 2 or greater then must be last */
	if (unit >= 2) {
		return true;
	}

	/* Look to see if there is a next interface specified */
	for (idx = unit + 1; idx <= 2; idx++) {
		nvram_env_gmac_name(idx, name);
		if (getvar(NULL, name) != NULL) { 
			/* there is a next interface */
			return false;
		}
	}
	/* no other interfaces */
	return true;
}


static bool
chipid(uint vendor, uint device)
{
	int idx;

	if (vendor != VENDOR_BROADCOM) {
		ET_ERROR(("%s ERROR: NOT a BROADCOM Vendor ID (0x%x)\n", __FUNCTION__, vendor));
		return (FALSE);
	}

	for (idx = 0; devices[idx]; idx++) {
		if (device == devices[idx]) {
			return (TRUE);
		}
	}

	ET_ERROR(("%s ERROR: UNKNOWN Device ID (0x%x)\n", __FUNCTION__, device));
	printk("%s ERROR: UNKNOWN Device ID (0x%x)\n", __FUNCTION__, device);
	return (FALSE);
}

static void *
chipattach(etc_info_t *etc, void *osh, void *regsva)
{
    ch_t *ch;
    gmacregs_t *regs;
    void *amacidmaddr;
    uint32 idx, tmp;
    char name[16], *var;
    uint boardflags, boardtype;
    uint coreidx;
    ulong flags;
    
	ET_TRACE(("et%d: chipattach: regsva 0x%lx\n", etc->unit, (ulong)regsva));

	if ((ch = (ch_t *)MALLOC(osh, sizeof(ch_t))) == NULL) {
		ET_ERROR(("et%d: chipattach: out of memory, malloced %d bytes\n", etc->unit, MALLOCED(osh)));
		return (NULL);
	}
	bzero((char *)ch, sizeof(ch_t));

	ch->etc = etc;
	ch->et = etc->et;
	ch->osh = osh;

	/* store the pointer to the sw mib */
	etc->mib = (void *)&ch->mib;

	/* get si handle */
	if ((ch->sih = si_attach(etc->deviceid, ch->osh, regsva, SI_BUS, NULL, &ch->vars,
	                         &ch->vars_size)) == NULL) {
		ET_ERROR(("et%d: chipattach: si_attach error\n", etc->unit));
		goto fail;
	}

	if ((regs = (gmacregs_t *)si_setcore(ch->sih, GMAC_CORE_ID, etc->unit)) == NULL) {
		ET_ERROR(("et%d: chipattach: Could not setcore to GMAC\n", etc->unit));
		goto fail;
	}

	/* 2G_ENABLED: Enable IDM 250MHz for 2G mode */
	spin_lock_irqsave((spinlock_t *)&ch->sih->sih_lock, flags);

	coreidx = si_coreidx(ch->sih);
	si_core_reset(ch->sih, 0, 0);
	si_setcoreidx(ch->sih, coreidx);

	spin_unlock_irqrestore((spinlock_t *)&ch->sih->sih_lock, flags);

	ch->regs = regs;
	etc->chip = ch->sih->chip;
	etc->chiprev = ch->sih->chiprev;
	etc->coreid = si_coreid(ch->sih);
	etc->nicmode = !(ch->sih->bustype == SI_BUS);
	etc->coreunit = si_coreunit(ch->sih);
	etc->boardflags = getintvar(ch->vars, "boardflags");

	boardflags = etc->boardflags;
	boardtype = ch->sih->boardtype;
	
	etc->switch_mode = 0;

	/* get our local ether addr */
	nvram_env_gmac_name(etc->coreunit, name);
	var = getvar(ch->vars, name);
	if (var == NULL) {
		ET_ERROR(("et%d: chipattach: getvar(%s) not found\n", etc->unit, name));
		goto fail;
	}
	bcm_ether_atoe(var, &etc->perm_etheraddr);

	if (ETHER_ISNULLADDR(&etc->perm_etheraddr)) {
		ET_ERROR(("et%d: chipattach: invalid format: %s=%s\n", etc->unit, name, var));
		goto fail;
	}

	bcopy((char *)&etc->perm_etheraddr, (char *)&etc->cur_etheraddr, ETHER_ADDR_LEN);

	/*
	 * Too much can go wrong in scanning MDC/MDIO playing "whos my phy?" .
	 * Instead, explicitly require the environment var "et<coreunit>phyaddr=<val>".
	 */

	/* get our phyaddr value */
	sprintf(name, "et%dphyaddr", etc->coreunit);
	var = getvar(NULL, name);
	if (var == NULL) {
#if (defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2))
        /* default phy address */
        etc->phyaddr = etc->unit+0x18;
#else
        etc->phyaddr = etc->unit+1;
#endif
		ET_ERROR(("et%d: chipattach: getvar(%s) not found set to %d\n", etc->unit, name, etc->phyaddr));
	} else {
		etc->phyaddr = bcm_atoi(var) & EPHY_MASK;
	}
	printf("et%d: chipattach: phyaddr(0x%x)\n", etc->unit, etc->phyaddr);

	/* nvram says no phy is present */
	if (etc->phyaddr == EPHY_NONE) {
		ET_ERROR(("et%d: chipattach: phy not present\n", etc->unit));
		goto fail;
	}

	/* reset the gmac core */
	chipreset(ch);

#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2))
	if (wrapaddr == 0) {
		/* flip switch so AMAC can access serdes */
		gmac_set_amac_mdio(1);
	}

	if (etc->unit == 0) {
		/* Get register base address */
		amacidmaddr = ioremap(AMAC_IDM0_IO_CONTROL_DIRECT, 0x10);
		tmp = ioread32(amacidmaddr);

		tmp &= ~(1 << AMAC_IDM0_IO_CONTROL_DIRECT__CLK_250_SEL);
		tmp |= (1 << AMAC_IDM0_IO_CONTROL_DIRECT__DIRECT_GMII_MODE);
		tmp |= (1 << AMAC_IDM0_IO_CONTROL_DIRECT__DEST_SYNC_MODE_EN);
		iowrite32(tmp, amacidmaddr);
		iounmap(amacidmaddr);
	} else if (etc->unit == 1) {
		/* Get register base address */
		amacidmaddr = ioremap(AMAC_IDM1_IO_CONTROL_DIRECT, 0x10);
		tmp = ioread32(amacidmaddr);

		tmp &= ~(1 << AMAC_IDM1_IO_CONTROL_DIRECT__CLK_250_SEL);
		tmp |= (1 << AMAC_IDM1_IO_CONTROL_DIRECT__DIRECT_GMII_MODE);
		tmp |= (1 << AMAC_IDM1_IO_CONTROL_DIRECT__DEST_SYNC_MODE_EN);
		iowrite32(tmp, amacidmaddr);
		iounmap(amacidmaddr);
	}

	/* enable serdes */
	gmac_serdes_init(ch);
#else
	/* Get register base address */
	amacidmaddr = ioremap(AMAC_IDM0_IO_CONTROL_DIRECT, 0x10);
	tmp = ioread32(amacidmaddr);
	tmp &= ~(1 << AMAC_IDM0_IO_CONTROL_DIRECT__CLK_250_SEL);
	tmp |= (1 << AMAC_IDM0_IO_CONTROL_DIRECT__DIRECT_GMII_MODE);
	tmp |= (1 << AMAC_IDM0_IO_CONTROL_DIRECT__DEST_SYNC_MODE_EN);
	iowrite32(tmp, amacidmaddr);
	iounmap(amacidmaddr);
#endif

	/* dma attach */
	sprintf(name, "et%d", etc->coreunit);

	/* allocate dma resources for txqs */
	/* TX: TC_BK, RX: RX_Q0 */
	ch->di[0] = dma_attach(osh, name, ch->sih,
	                       DMAREG(ch, DMA_TX, TX_Q0),
	                       DMAREG(ch, DMA_RX, RX_Q0),
	                       NTXD, NRXD, RXBUFSZ, -1, NRXBUFPOST, HWRXOFF,
	                       &et_msg_level);

	for (idx = 0; idx < NUMTXQ; idx++) {
		if (ch->di[idx] == NULL) {
			ET_ERROR(("et%d: chipattach: dma_attach failed\n", etc->unit));
			goto fail;
		}
	}

	for (idx = 0; idx < NUMTXQ; idx++) {
		if (ch->di[idx] != NULL) {
			etc->txavail[idx] = (uint *)&ch->di[idx]->txavail;
		}
	}

	/* set default sofware intmask */
	sprintf(name, "et%d_no_txint", etc->coreunit);
	if (getintvar(ch->vars, name)) {
		/* if no_txint variable is non-zero we disable tx interrupts.
		 * we do the tx buffer reclaim once every few frames.
		 */
		ch->def_intmask = (DEF_INTMASK & ~(I_XI0 | I_XI1 | I_XI2 | I_XI3));
		etc->txrec_thresh = (((NTXD >> 2) > TXREC_THR) ? TXREC_THR - 1 : 1);
	} else {
		ch->def_intmask = DEF_INTMASK;
	}

	ch->intmask = ch->def_intmask;

	/* reset phy: reset it once now */
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2))
    if (ch->etc->unit == 0) {
        serdes_reset_core(ch->etc->unit, etc->phyaddr);
    }
#endif

	chipphyreset(ch, etc->phyaddr);

#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2))
    if (gmac_last_interface(etc->unit)) {
        /* must init all serdes lanes, init port 49 (phy 3) */
        serdes_init(etc->unit, 3);
        serdes_start_pll(etc->unit, 1);
    }
#endif

    if (etc->forcespeed == ET_AUTO) {
        etc->needautoneg = TRUE;
        etc->advertise = (ADV_100FULL | ADV_100HALF | ADV_10FULL | ADV_10HALF);
#if defined(CONFIG_MACH_HR2)
        etc->advertise2 = 0;
#else
        etc->advertise2 = ADV_1000FULL;
#endif
    }

	return ((void *) ch);

fail:
	chipdetach(ch);
	return (NULL);
}

static void
chipdetach(ch_t *ch)
{
	int32 idx;

	ET_TRACE(("et%d: chipdetach\n", ch->etc->unit));

	if (ch == NULL) {
		return;
	}

	/* free dma state */
	for (idx = 0; idx < NUMTXQ; idx++) {
		if (ch->di[idx] != NULL) {
			dma_detach(ch->di[idx]);
			ch->di[idx] = NULL;
		}
	}

	/* put the core back into reset */
	if (ch->sih) {
		si_core_disable(ch->sih, 0);
    }
    
	if (ch->etc) {
		if (ch->etc->mib) {
			ch->etc->mib = NULL;
		}
	}

	/* free si handle */
	if (ch->sih) {
		si_detach(ch->sih);
		ch->sih = NULL;
	}

	/* free vars */
	if (ch->vars) {
		MFREE(ch->osh, ch->vars, ch->vars_size);
	}

	/* free chip private state */
	MFREE(ch->osh, ch, sizeof(ch_t));
}

static void
chiplongname(ch_t *ch, char *buf, uint bufsize)
{
	char *s;

	switch (ch->etc->deviceid) {
		case BCM56150_CHIP_ID:
			s = "Broadcom BCM5615x 10/100 Mbps Ethernet Controller";
			break;
		case BCM56340_CHIP_ID:
			s = "Broadcom BCM5634x 10/100/1000 Mbps Ethernet Controller";
			break;
		case BCM56450_CHIP_ID:
			s = "Broadcom BCM5645x 10/100/1000 Mbps Ethernet Controller";
			break;
		case BCM53400_CHIP_ID:
			s = "Broadcom BCM5340x 10/100/1000 Mbps Ethernet Controller";
			break;
		case BCM56260_CHIP_ID:
			s = "Broadcom BCM5626x 10/100/1000 Mbps Ethernet Controller";
			break;
		case BCM56160_CHIP_ID:
			s = "Broadcom BCM5616x 10/100/1000 Mbps Ethernet Controller";
			break;
		default:
			s = "Broadcom BCM5301x 10/100/1000 Mbps Ethernet Controller";
			break;
	}

	strncpy(buf, s, bufsize);
	buf[bufsize - 1] = '\0';
}

static void
chipdump(ch_t *ch, struct bcmstrbuf *b)
{
	bcm_bprintf(b, "regs 0x%lx etphy 0x%lx ch->intstatus 0x%x intmask 0x%x\n",
		(ulong)ch->regs, (ulong)ch->etphy, ch->intstatus, ch->intmask);
	bcm_bprintf(b, "\n");

	/* registers */
	chipdumpregs(ch, ch->regs, b);
	bcm_bprintf(b, "\n");
}


#define	PRREG(name)	bcm_bprintf(b, #name " 0x%x ", R_REG(ch->osh, &regs->name))
#define	PRMIBREG(name)	bcm_bprintf(b, #name " 0x%x ", R_REG(ch->osh, &regs->mib.name))

static void
chipdumpregs(ch_t *ch, gmacregs_t *regs, struct bcmstrbuf *b)
{
	uint phyaddr;

	phyaddr = ch->etc->phyaddr;

	PRREG(devcontrol); PRREG(devstatus);
	bcm_bprintf(b, "\n");
	PRREG(biststatus);
	bcm_bprintf(b, "\n");
	PRREG(intstatus); PRREG(intmask); PRREG(gptimer);
	bcm_bprintf(b, "\n");
	PRREG(intrecvlazy);
	bcm_bprintf(b, "\n");
	PRREG(flowctlthresh); PRREG(wrrthresh); PRREG(gmac_idle_cnt_thresh);
	bcm_bprintf(b, "\n");
	PRREG(phyaccess); PRREG(phycontrol);
	bcm_bprintf(b, "\n");

	PRREG(txqctl); PRREG(rxqctl);
	bcm_bprintf(b, "\n");
	PRREG(gpioselect); PRREG(gpio_output_en);
	bcm_bprintf(b, "\n");
	PRREG(clk_ctl_st); PRREG(pwrctl);
	bcm_bprintf(b, "\n");

	/* unimac registers */
	PRREG(hdbkpctl);
	bcm_bprintf(b, "\n");
	PRREG(cmdcfg);
	bcm_bprintf(b, "\n");
	PRREG(macaddrhigh); PRREG(macaddrlow);
	bcm_bprintf(b, "\n");
	PRREG(rxmaxlength); PRREG(pausequanta); PRREG(macmode);
	bcm_bprintf(b, "\n");
	PRREG(outertag); PRREG(innertag); PRREG(txipg); PRREG(pausectl);
	bcm_bprintf(b, "\n");
	PRREG(txflush); PRREG(rxstatus); PRREG(txstatus);
	bcm_bprintf(b, "\n");
#ifdef ENABLE_MIB_REG_DUMP
	/* mib registers */
	PRMIBREG(tx_good_octets); PRMIBREG(tx_good_pkts); PRMIBREG(tx_octets); PRMIBREG(tx_pkts);
	bcm_bprintf(b, "\n");
	PRMIBREG(tx_broadcast_pkts); PRMIBREG(tx_multicast_pkts);
	bcm_bprintf(b, "\n");
	PRMIBREG(tx_jabber_pkts); PRMIBREG(tx_oversize_pkts); PRMIBREG(tx_fragment_pkts);
	bcm_bprintf(b, "\n");
	PRMIBREG(tx_underruns); PRMIBREG(tx_total_cols); PRMIBREG(tx_single_cols);
	bcm_bprintf(b, "\n");
	PRMIBREG(tx_multiple_cols); PRMIBREG(tx_excessive_cols); PRMIBREG(tx_late_cols);
	bcm_bprintf(b, "\n");
	PRMIBREG(tx_defered); PRMIBREG(tx_carrier_lost); PRMIBREG(tx_pause_pkts);
	bcm_bprintf(b, "\n");

	PRMIBREG(rx_good_octets); PRMIBREG(rx_good_pkts); PRMIBREG(rx_octets); PRMIBREG(rx_pkts);
	bcm_bprintf(b, "\n");
	PRMIBREG(rx_broadcast_pkts); PRMIBREG(rx_multicast_pkts);
	bcm_bprintf(b, "\n");
	PRMIBREG(rx_jabber_pkts);
	PRMIBREG(rx_oversize_pkts); PRMIBREG(rx_fragment_pkts);
	bcm_bprintf(b, "\n");
	PRMIBREG(rx_missed_pkts); PRMIBREG(rx_crc_align_errs); PRMIBREG(rx_undersize);
	bcm_bprintf(b, "\n");
	PRMIBREG(rx_crc_errs); PRMIBREG(rx_align_errs); PRMIBREG(rx_symbol_errs);
	bcm_bprintf(b, "\n");
	PRMIBREG(rx_pause_pkts); PRMIBREG(rx_nonpause_pkts);
#endif /* ENABLE_MIB_REG_DUMP */
	bcm_bprintf(b, "\n");
	if (phyaddr != EPHY_NOREG) {
		/* print a few interesting phy registers */
		bcm_bprintf(b, "phy0 0x%x phy1 0x%x phy2 0x%x phy3 0x%x\n",
		               chipphyrd(ch, phyaddr, 0),
		               chipphyrd(ch, phyaddr, 1),
		               chipphyrd(ch, phyaddr, 2),
		               chipphyrd(ch, phyaddr, 3));
		bcm_bprintf(b, "phy4 0x%x phy5 0x%x phy24 0x%x phy25 0x%x\n",
		               chipphyrd(ch, phyaddr, 4),
		               chipphyrd(ch, phyaddr, 5),
		               chipphyrd(ch, phyaddr, 24),
		               chipphyrd(ch, phyaddr, 25));
	}

}

static void
gmac_clearmib(ch_t *ch)
{
	volatile uint32 *ptr;

	/* enable clear on read */
	OR_REG(ch->osh, &ch->regs->devcontrol, DC_MROR);

	for (ptr = &ch->regs->mib.tx_good_octets; ptr <= &ch->regs->mib.rx_uni_pkts; ptr++) {
		(void)R_REG(ch->osh, ptr);
		if (ptr == &ch->regs->mib.tx_q3_octets_high) {
			ptr++;
		}
	}

	return;
}

static void
gmac_init_reset(ch_t *ch)
{
	OR_REG(ch->osh, &ch->regs->cmdcfg, CC_SR);
	OSL_DELAY(GMAC_RESET_DELAY);
}

static void
gmac_clear_reset(ch_t *ch)
{
	AND_REG(ch->osh, &ch->regs->cmdcfg, ~CC_SR);
	OSL_DELAY(GMAC_RESET_DELAY);
}

static void
gmac_reset(ch_t *ch)
{
	uint32 ocmdcfg, cmdcfg;

	/* put the mac in reset */
	gmac_init_reset(ch);

	/* initialize default config */
	ocmdcfg = cmdcfg = R_REG(ch->osh, &ch->regs->cmdcfg);

	cmdcfg &= ~(CC_TE | CC_RE | CC_RPI | CC_TAI | CC_HD | CC_ML |
	            CC_CFE | CC_RL | CC_RED | CC_PE | CC_TPI | CC_PAD_EN | CC_PF);
	cmdcfg |= (CC_PROM | CC_NLC | CC_CFE);

#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2))
	cmdcfg |= (CC_AE | CC_OT | CC_OR);
#endif

	if (cmdcfg != ocmdcfg) {
		W_REG(ch->osh, &ch->regs->cmdcfg, cmdcfg);
    }
    
	/* bring mac out of reset */
	gmac_clear_reset(ch);
}

static void
gmac_promisc(ch_t *ch, bool mode)
{
	uint32 cmdcfg;

	cmdcfg = R_REG(ch->osh, &ch->regs->cmdcfg);

	/* put the mac in reset */
	gmac_init_reset(ch);

	/* enable or disable promiscuous mode */
	if (mode) {
		cmdcfg |= CC_PROM;
	} else {
		cmdcfg &= ~CC_PROM;
	}

	W_REG(ch->osh, &ch->regs->cmdcfg, cmdcfg);

	/* bring mac out of reset */
	gmac_clear_reset(ch);
}

static int
gmac_speed(ch_t *ch, uint32 speed)
{
	uint32 cmdcfg;
	uint32 hd_ena = 0;
#if defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2)
    uint32_t sdctl;
    uint32 set_speed = speed;
#endif /* CONFIG_MACH_GH || CONFIG_MACH_HR3 || CONFIG_MACH_GH2 */

	switch (speed) {
		case ET_10HALF:
			hd_ena = CC_HD;
			/* FALLTHRU */

		case ET_10FULL:
			speed = 0;
			break;

		case ET_100HALF:
			hd_ena = CC_HD;
			/* FALLTHRU */

		case ET_100FULL:
			speed = 1;
			break;

		case ET_1000FULL:
			speed = 2;
			break;

		case ET_1000HALF:
			ET_ERROR(("et%d: gmac_speed: supports 1000 mbps full duplex only\n",
			          ch->etc->unit));
			return (FAILURE);

		case ET_2500FULL:
			speed = 3;
			break;

		default:
			ET_ERROR(("et%d: gmac_speed: speed %d not supported\n",
			          ch->etc->unit, speed));
			return (FAILURE);
	}

	cmdcfg = R_REG(ch->osh, &ch->regs->cmdcfg);

	/* put mac in reset */
	gmac_init_reset(ch);

	/* set the speed */
	cmdcfg &= ~(CC_ES_MASK | CC_HD);
	cmdcfg |= ((speed << CC_ES_SHIFT) | hd_ena);

#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2))
	cmdcfg |= (CC_AE | CC_OT | CC_OR);
#endif

	W_REG(ch->osh, &ch->regs->cmdcfg, cmdcfg);

	/* bring mac out of reset */
	gmac_clear_reset(ch);
    
#if defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2)
    sdctl = R_REG(ch->osh, &ch->regs->serdes_ctl);
    sdctl &= ~(SC_FORCE_SPD_STRAP_MASK);
    switch (set_speed) {
        case ET_1000FULL:
            sdctl |= SC_FORCE_SPD_1G_VAL;
            break;
        case ET_100FULL:
        case ET_100HALF:
            sdctl |= SC_FORCE_SPD_100M_VAL;
            break;
        default:
            break;
    }
    W_REG(ch->osh, &ch->regs->serdes_ctl, sdctl);

    udelay(1000);
#endif /* CONFIG_MACH_GH || CONFIG_MACH_HR3 || CONFIG_MACH_GH2 */

	return (SUCCESS);
}

static void
gmac_macloopback(ch_t *ch, bool on)
{
	uint32 ocmdcfg, cmdcfg;

	ocmdcfg = cmdcfg = R_REG(ch->osh, &ch->regs->cmdcfg);

	/* put mac in reset */
	gmac_init_reset(ch);

	/* set/clear the mac loopback mode */
	if (on) {
		cmdcfg |= CC_ML;
	} else {
		cmdcfg &= ~CC_ML;
    }
    
	if (cmdcfg != ocmdcfg) {
		W_REG(ch->osh, &ch->regs->cmdcfg, cmdcfg);
    }
    
	/* bring mac out of reset */
	gmac_clear_reset(ch);
}

static int
gmac_loopback(ch_t *ch, uint32 mode)
{
	switch (mode) {
		case LOOPBACK_MODE_DMA:
			/* to enable loopback for any channel set the loopback
			 * enable bit in xmt0control register.
			 */
			dma_fifoloopbackenable(ch->di[TX_Q0]);
			break;

		case LOOPBACK_MODE_MAC:
			gmac_macloopback(ch, TRUE);
			break;

		case LOOPBACK_MODE_NONE:
			gmac_macloopback(ch, FALSE);
			break;

		default:
			ET_ERROR(("et%d: gmac_loopaback: Unknown loopback mode %d\n",
			          ch->etc->unit, mode));
			return (FAILURE);
	}

	return (SUCCESS);
}

static void
gmac_enable(ch_t *ch)
{
	uint32 cmdcfg;
	gmacregs_t *regs;

	regs = ch->regs;

	cmdcfg = R_REG(ch->osh, &ch->regs->cmdcfg);

	/* put mac in reset */
	gmac_init_reset(ch);

	cmdcfg |= CC_SR;

	/* first deassert rx_ena and tx_ena while in reset */
	cmdcfg &= ~(CC_RE | CC_TE);
	W_REG(ch->osh, &regs->cmdcfg, cmdcfg);

	/* bring mac out of reset */
	gmac_clear_reset(ch);

	/* enable the mac transmit and receive paths now */
	OSL_DELAY(2);
	cmdcfg &= ~CC_SR;
	cmdcfg |= (CC_RE | CC_TE);

	/* assert rx_ena and tx_ena when out of reset to enable the mac */
	W_REG(ch->osh, &regs->cmdcfg, cmdcfg);

	/* request ht clock */
	OR_REG(ch->osh, &regs->clk_ctl_st, CS_FH);

	return;
}

static void
gmac_txflowcontrol(ch_t *ch, bool on)
{
	uint32 cmdcfg;

	cmdcfg = R_REG(ch->osh, &ch->regs->cmdcfg);

	/* put the mac in reset */
	gmac_init_reset(ch);

	/* to enable tx flow control clear the rx pause ignore bit */
	if (on) {
		cmdcfg &= ~CC_RPI;
	} else {
		cmdcfg |= CC_RPI;
    }
    
	W_REG(ch->osh, &ch->regs->cmdcfg, cmdcfg);

	/* bring mac out of reset */
	gmac_clear_reset(ch);
}


#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2))
static void
gmac_serdes_init(ch_t *ch)
{
	uint32_t sdctl, sdstat0, sdstat1;
	gmacregs_t *regs;

	regs = ch->regs;

	ET_TRACE(("%s enter\n", __FUNCTION__));

	sdctl = R_REG(ch->osh, &ch->regs->serdes_ctl);
	sdstat0 = R_REG(ch->osh, &ch->regs->serdes_status0);
	sdstat1 = R_REG(ch->osh, &ch->regs->serdes_status1);

    /*
     * Bring up both digital and analog clocks
     *
     * NOTE: Many MAC registers are not accessible until the PLL is locked.
     * An S-Channel timeout will occur before that.
     */

	sdctl = (SC_TX1G_FIFO_RST_VAL|SC_FORCE_SPD_STRAP_VAL);
#if defined(CONFIG_MACH_HX4)
    sdctl |= (SC_REFSEL_VAL|SC_REF_TERM_SEL_MASK); 
#elif defined(CONFIG_MACH_KT2)
	sdctl |= SC_REF_TERM_SEL_MASK;
#endif /* (defined(CONFIG_MACH_HX4) */
	W_REG(ch->osh, &ch->regs->serdes_ctl, sdctl);

	udelay(1000);

	sdctl = R_REG(ch->osh, &ch->regs->serdes_ctl);
	sdctl |= (SC_IDDQ_MASK|SC_PWR_DOWN_MASK);
	W_REG(ch->osh, &ch->regs->serdes_ctl, sdctl);

	sdctl = R_REG(ch->osh, &ch->regs->serdes_ctl);
	sdctl &= ~(SC_IDDQ_MASK|SC_PWR_DOWN_MASK);
	W_REG(ch->osh, &ch->regs->serdes_ctl, sdctl);

    /* Bring hardware out of reset */
	sdctl = R_REG(ch->osh, &ch->regs->serdes_ctl);
	sdctl |= (SC_RSTB_HW_MASK);
	W_REG(ch->osh, &ch->regs->serdes_ctl, sdctl);

    /* Bring MDIOREGS out of reset */
	sdctl = R_REG(ch->osh, &ch->regs->serdes_ctl);
	sdctl |= (SC_RSTB_MDIOREGS_MASK);
	W_REG(ch->osh, &ch->regs->serdes_ctl, sdctl);

	udelay(1000);

    /* Bring PLL out of reset */
	sdctl = R_REG(ch->osh, &ch->regs->serdes_ctl);
	sdctl |= (SC_RSTB_PLL_MASK);
	W_REG(ch->osh, &ch->regs->serdes_ctl, sdctl);

	udelay(1000);

	sdctl = R_REG(ch->osh, &ch->regs->serdes_ctl);
	sdstat0 = R_REG(ch->osh, &ch->regs->serdes_status0);
	sdstat1 = R_REG(ch->osh, &ch->regs->serdes_status1);

	return;
}
#endif /* (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2)) */

static void
gmac_miiconfig(ch_t *ch)
{
	/* BCM53010 GMAC DevStatus register has different definition of "Interface Mode"
	 * Bit 12:8  "interface_mode"  This field is programmed through IDM control bits [6:2]
	 *
	 * Bit 0 : SOURCE_SYNC_MODE_EN - If set, Rx line clock input will be used by Unimac for
	 *          sampling data.If this is reset, PLL reference clock (Clock 250 or Clk 125 based
	 *          on CLK_250_SEL) will be used as receive side line clock.
	 * Bit 1 : DEST_SYNC_MODE_EN - If this is reset, PLL reference clock input (Clock 250 or
	 *          Clk 125 based on CLK_250_SEL) will be used as transmit line clock.
	 *          If this is set, TX line clock input (from external switch/PHY) is used as
	 *          transmit line clock.
	 * Bit 2 : TX_CLK_OUT_INVERT_EN - If set, this will invert the TX clock out of AMAC.
	 * Bit 3 : DIRECT_GMII_MODE - If direct gmii is set to 0, then only 25 MHz clock needs to
	 *          be fed at 25MHz reference clock input, for both 10/100 Mbps speeds.
	 *          Unimac will internally divide the clock to 2.5 MHz for 10 Mbps speed
	 * Bit 4 : CLK_250_SEL - When set, this selects 250Mhz reference clock input and hence
	 *          Unimac line rate will be 2G.
	 *          If reset, this selects 125MHz reference clock input.
	 */
    
    if (ch->etc->forcespeed == ET_AUTO) {
        if (ch->etc->deviceid == BCM56150_CHIP_ID) {
            gmac_speed(ch, ET_100FULL);
        } else {
            gmac_speed(ch, ET_1000FULL);
        }
    } else {
        gmac_speed(ch, ch->etc->forcespeed);
    }
}

#ifdef CONFIG_SERDES_ASYMMETRIC_MODE
void
gmac_serdes_asym_mode(etc_info_t *etcptrs[])
{
	etc_info_t *etc;

	etc = etcptrs[0];

	/* initialize serdes */	
	gmac_serdes_init(etc->ch);
	serdes_reset_core(etc->unit, etc->phyaddr);

	/* initialize lane 0 */
	//printk("et%d %s() phyaddr=%d, speed=%d, dpx=%d\n", etc->unit, __FUNCTION__, etc->phyaddr, etc->speed, etc->duplex);
	serdes_set_asym_mode(etc->unit, etc->phyaddr);
	serdes_init(etc->unit, etc->phyaddr);
	serdes_speeddpx_set(etc->unit, etc->phyaddr, etc->speed, etc->duplex);
	/* initialize lane 1 */
	etc = etcptrs[1];
	if (etc->linkstate) {
		//printk("et%d %s() phyaddr=%d, speed=%d, dpx=%d\n", etc->unit, __FUNCTION__, etc->phyaddr, etc->speed, etc->duplex);
		serdes_set_asym_mode(etc->unit, etc->phyaddr);
		serdes_init(etc->unit, etc->phyaddr);
		serdes_speeddpx_set(etc->unit, etc->phyaddr, etc->speed, etc->duplex);
	}

    /* must init all serdes lanes, init port 49 (phy 3) */
   	serdes_init(etc->unit, 3);

	/* start PLL */
    serdes_start_pll(etc->unit, 1);
}
#endif /* CONFIG_SERDES_ASYMMETRIC_MODE */


static void
chipreset(ch_t *ch)
{
	gmacregs_t *regs;
	uint32 idx, sflags, flagbits = 0;
    
	ET_TRACE(("et%d: chipreset\n", ch->etc->unit));

	regs = ch->regs;

	if (!si_iscoreup(ch->sih)) {
		/* power on reset: reset the enet core */
		goto chipinreset;
	}

	/* Reset other three GMAC cores if needed */
	for (idx = 0; idx < IPROC_NUM_GMACS; idx++) {
		/* As northstar requirement, we have to reset all GAMCs before accessing them.
		 * et_probe() call pci_enable_device() for etx and do si_core_reset for GAMCx only.
		 * then the other three GAMC didn't reset.
		 * We do it here.
		 */
		si_setcore(ch->sih, GMAC_CORE_ID, idx);
		if (!si_iscoreup(ch->sih)) {
			ET_TRACE(("et%d: reset NorthStar GMAC[%d] core\n", ch->etc->unit, idx));
			si_core_reset(ch->sih, flagbits, 0);
		}
	}
	si_setcore(ch->sih, GMAC_CORE_ID, 0);

	/* update software counters before resetting the chip */
	if (ch->mibgood) {
		chipstatsupd(ch);
	}

	/* reset the tx dma engines */
	for (idx = 0; idx < NUMTXQ; idx++) {
		if (ch->di[idx]) {
			ET_TRACE(("et%d: resetting tx dma%d\n", ch->etc->unit, idx));
			dma_txreset(ch->di[idx]);
		}
	}

	/* set gmac into loopback mode to ensure no rx traffic */
	gmac_loopback(ch, LOOPBACK_MODE_MAC);
	OSL_DELAY(1);

	/* reset the rx dma engine */
	if (ch->di[RX_Q0]) {
		ET_TRACE(("et%d: resetting rx dma\n", ch->etc->unit));
		dma_rxreset(ch->di[RX_Q0]);
	}

	/* clear the multicast filter table */
	gmac_mf_cleanup(ch);

chipinreset:
	sflags = si_core_sflags(ch->sih, 0, 0);
	if (sflags & SISF_SW_ATTACHED) {
		ET_TRACE(("et%d: internal switch attached\n", ch->etc->unit));
		flagbits = SICF_SWCLKE;
		if (!ch->etc->robo) {
			ET_TRACE(("et%d: reseting switch\n", ch->etc->unit));
			flagbits |= SICF_SWRST;
		}
	}

	/* Reset all GMAC cores */
	for (idx = 0; idx < IPROC_NUM_GMACS; idx++) {
		/* As northstar requirement, we have to reset all GAMCs before accessing them.
		 * et_probe() call pci_enable_device() for etx and do si_core_reset for GAMCx only.
		 * then the other three GAMC didn't reset.
		 * We do it here.
		 */
		si_setcore(ch->sih, GMAC_CORE_ID, idx);
		if (!si_iscoreup(ch->sih)) {
			ET_TRACE(("et%d: reset NorthStar GMAC[%d] core\n", ch->etc->unit, idx));
			si_core_reset(ch->sih, flagbits, 0);
		}
	}
	si_setcore(ch->sih, GMAC_CORE_ID, 0);

	if ((sflags & SISF_SW_ATTACHED) && (!ch->etc->robo)) {
		ET_TRACE(("et%d: taking switch out of reset\n", ch->etc->unit));
		si_core_cflags(ch->sih, SICF_SWRST, 0);
	}

	/* reset gmac */
	gmac_reset(ch);

	/* clear mib */
	gmac_clearmib(ch);
	ch->mibgood = TRUE;

	/* set mdc_transition_en */
	OR_REG(ch->osh, &regs->phycontrol, PC_MTE);

	/* Read the devstatus to figure out the configuration mode of
	 * the interface. Set the speed to 100 if the switch interface
	 * is mii/rmii.
	 */
	gmac_miiconfig(ch);

	/* clear persistent sw intstatus */
	ch->intstatus = 0;
}

/*
 * Lookup a multicast address in the filter hash table.
 */
static int
gmac_mf_lkup(ch_t *ch, struct ether_addr *mcaddr)
{
	mflist_t *ptr;

	/* find the multicast address */
	for (ptr = ch->mf.bucket[GMAC_MCADDR_HASH(mcaddr)]; ptr != NULL; ptr = ptr->next) {
		if (!ETHER_MCADDR_CMP(&ptr->mc_addr, mcaddr)) {
			return (SUCCESS);
		}
	}

	return (FAILURE);
}

/*
 * Add a multicast address to the filter hash table.
 */
static int
gmac_mf_add(ch_t *ch, struct ether_addr *mcaddr)
{
	uint32 hash;
	mflist_t *entry;
#ifdef BCMDBG
	char mac[ETHER_ADDR_STR_LEN];
#endif /* BCMDBG */

	/* add multicast addresses only */
	if (!ETHER_ISMULTI(mcaddr)) {
		ET_ERROR(("et%d: adding invalid multicast address %s\n",
		          ch->etc->unit, bcm_ether_ntoa(mcaddr, mac)));
		return (FAILURE);
	}

	/* discard duplicate add requests */
	if (gmac_mf_lkup(ch, mcaddr) == SUCCESS) {
		ET_ERROR(("et%d: adding duplicate mcast filter entry\n", ch->etc->unit));
		return (FAILURE);
	}

	/* allocate memory for list entry */
	entry = MALLOC(ch->osh, sizeof(mflist_t));
	if (entry == NULL) {
		ET_ERROR(("et%d: out of memory allocating mcast filter entry\n", ch->etc->unit));
		return (FAILURE);
	}

	/* add the entry to the hash bucket */
	ether_copy(mcaddr, &entry->mc_addr);
	hash = GMAC_MCADDR_HASH(mcaddr);
	entry->next = ch->mf.bucket[hash];
	ch->mf.bucket[hash] = entry;

	return (SUCCESS);
}

/*
 * Cleanup the multicast filter hash table.
 */
static void
gmac_mf_cleanup(ch_t *ch)
{
	mflist_t *ptr, *tmp;
	int32 idx;

	for (idx = 0; idx < GMAC_HASHT_SIZE; idx++) {
		ptr = ch->mf.bucket[idx];
		while (ptr) {
			tmp = ptr;
			ptr = ptr->next;
			MFREE(ch->osh, tmp, sizeof(mflist_t));
		}
		ch->mf.bucket[idx] = NULL;
	}
}

/*
 * Initialize all the chip registers.  If dma mode, init tx and rx dma engines
 * but leave the devcontrol tx and rx (fifos) disabled.
 */
static void
chipinit(ch_t *ch, uint options)
{
	etc_info_t *etc;
	gmacregs_t *regs;
	uint idx;

	regs = ch->regs;
	etc = ch->etc;

	ET_TRACE(("et%d: chipinit\n", etc->unit));

    /* enable one rx interrupt per received frame */
    W_REG(ch->osh, &regs->intrecvlazy, (1 << IRL_FC_SHIFT));

	/* enable 802.3x tx flow control (honor received PAUSE frames) */
	gmac_txflowcontrol(ch, TRUE);

	/* enable/disable promiscuous mode */
	gmac_promisc(ch, etc->promisc);

	/* set our local address */
	W_REG(ch->osh, &regs->macaddrhigh,
	      hton32(*(uint32 *)&etc->cur_etheraddr.octet[0]));
	W_REG(ch->osh, &regs->macaddrlow,
	      hton16(*(uint16 *)&etc->cur_etheraddr.octet[4]));

	if (!etc->promisc) {
		/* gmac doesn't have a cam, hence do the multicast address filtering
		 * in the software
		 */
		/* allmulti or a list of discrete multicast addresses */
		if (!etc->allmulti && etc->nmulticast) {
			for (idx = 0; idx < etc->nmulticast; idx++) {
				(void)gmac_mf_add(ch, &etc->multicast[idx]);
			}
		}
	}

	/* optionally enable mac-level loopback */
	if (etc->loopbk) {
		gmac_loopback(ch, LOOPBACK_MODE_MAC);
	} else {
		gmac_loopback(ch, LOOPBACK_MODE_NONE);
	}

	/* set max frame lengths - account for possible vlan tag */
	W_REG(ch->osh, &regs->rxmaxlength, BCM_ETHER_MAX_LEN + 32);

	/*
	 * Optionally, disable phy autonegotiation and force our speed/duplex
	 * or constrain our advertised capabilities.
	 */
	if (etc->forcespeed != ET_AUTO) {
		gmac_speed(ch, etc->forcespeed);
		chipphyforce(ch, etc->phyaddr);
        switch (etc->forcespeed) {
            case ET_1000FULL:
                etc->speed = 1000;
                etc->duplex = 1;
                break;
            case ET_1000HALF:
                etc->speed = 1000;
                etc->duplex = 0;
                break;
            case ET_100FULL:
                etc->speed = 100;
                etc->duplex = 1;
                break;
            case ET_100HALF:
                etc->speed = 100;
                etc->duplex = 0;
                break;
            case ET_10FULL:
                etc->speed = 10;
                etc->duplex = 1;
                break;
            case ET_10HALF:
                etc->speed = 10;
                etc->duplex = 0;
                break;
            default:
                break;
        }
	} else if (etc->advertise && etc->needautoneg) {
		chipphyadvertise(ch, etc->phyaddr);
    }
	/* enable the overflow continue feature and disable parity */
	dma_ctrlflags(ch->di[0], DMA_CTRL_ROC | DMA_CTRL_PEN /* mask */,
	              DMA_CTRL_ROC /* value */);

	if (options & ET_INIT_FULL) {
		/* initialize the tx and rx dma channels */
		for (idx = 0; idx < NUMTXQ; idx++) {
			dma_txinit(ch->di[idx]);
		}
		dma_rxinit(ch->di[RX_Q0]);

		/* post dma receive buffers */
		dma_rxfill(ch->di[RX_Q0]);

		/* lastly, enable interrupts */
		if (options & ET_INIT_INTRON) {
			et_intrson(etc->et);
		}
	} else {
		dma_rxenable(ch->di[RX_Q0]);
    }
    
	/* turn on the emac */
	gmac_enable(ch);
}

/* dma transmit */
static bool BCMFASTPATH
chiptx(ch_t *ch, void *p0)
{
	int error, len;
	uint32 q = TX_Q0;

	ET_TRACE(("et%d: chiptx\n", ch->etc->unit));
	ET_LOG("et%d: chiptx", ch->etc->unit, 0);

	len = PKTLEN(ch->osh, p0);

	/* check tx max length */
	if (len > (BCM_ETHER_MAX_LEN + 32)) {
		ET_ERROR(("et%d: chiptx: max frame length exceeded\n",
		          ch->etc->unit));
		PKTFREE(ch->osh, p0, TRUE);
		return FALSE;
	}

	/* gmac rev 0 workaround:  unimac can only transmit frames of
	 * length 17 bytes or greater. so pad the frame and send a
	 * 17 byte frame. to do the padding just modify the packet
	 * length that we provide to the dma. unimac does the extra
	 * padding * required to send 64 byte frames.
	 */
	if ((len < GMAC_MIN_FRAMESIZE) && (ch->etc->corerev == 0)) {
		PKTSETLEN(ch->osh, p0, GMAC_MIN_FRAMESIZE);
	}

	ASSERT(q < NUMTXQ);

	/* if tx completion intr is disabled then do the reclaim
	 * once every few frames transmitted.
	 */
	if ((ch->etc->txframes[q] & ch->etc->txrec_thresh) == 1) {
		dma_txreclaim(ch->di[q], HNDDMA_RANGE_TRANSMITTED);
	}

	error = dma_txfast(ch->di[q], p0, TRUE);

	if (error) {
		ET_ERROR(("et%d: chiptx: out of txds\n", ch->etc->unit));
		ch->etc->txnobuf++;
		return FALSE;
	}

	ch->etc->txframes[q]++;

	if ((len < GMAC_MIN_FRAMESIZE) && (ch->etc->corerev == 0)) {
		if (skb_is_nonlinear((struct sk_buff*)p0)) {
            printk("Modified nonlinear skb (et_ctf_pipeline_loopback) - not calling skb_trim\n");
		} else {
			/* set back the orig length */
			PKTSETLEN(ch->osh, p0, len);
		}
	}

	return TRUE;
}

/* reclaim completed transmit descriptors and packets */
static void BCMFASTPATH
chiptxreclaim(ch_t *ch, bool forceall)
{
	int32 idx;

	ET_TRACE(("et%d: chiptxreclaim\n", ch->etc->unit));

	for (idx = 0; idx < NUMTXQ; idx++) {
		dma_txreclaim(ch->di[idx], forceall ? HNDDMA_RANGE_ALL : HNDDMA_RANGE_TRANSMITTED);
		ch->intstatus &= ~(I_XI0 << idx);
	}
}

/* dma receive: returns a pointer to the next frame received, or NULL if there are no more */
static void * BCMFASTPATH
chiprx(ch_t *ch)
{
	void *p;
	struct ether_addr *da;

	ET_TRACE(("et%d: chiprx\n", ch->etc->unit));
	ET_LOG("et%d: chiprx", ch->etc->unit, 0);

	if (dma_rxstopped(ch->di[RX_Q0])) {
		ch->etc->rxdmastopped++;
	}

	/* gmac doesn't have a cam to do address filtering. so we implement
	 * the multicast address filtering here.
	 */
	while ((p = dma_rx(ch->di[RX_Q0])) != NULL) {
		/* check for overflow error packet */
		if (RXH_FLAGS(ch->etc, PKTDATA(ch->osh, p)) & GRXF_OVF) {
			PKTFREE(ch->osh, p, FALSE);
			ch->etc->rxoflodiscards++;
			continue;
		}

#ifdef GMAC_RATE_LIMITING
        /* rate limiting */
        /* printf("et%d: chiprx RXH_PT(0x%x)\n", ch->etc->unit, RXH_PT(ch->etc, PKTDATA(ch->osh, p))); */
		if (RXH_PT(ch->etc, PKTDATA(ch->osh, p)) == 2)
			ch->etc->rx_bc_frame_cnt++;
		if (ch->etc->rl_stopping_broadcasts) {
			/* check if broadcast packet */
			if (RXH_PT(ch->etc, PKTDATA(ch->osh, p)) == 2) {
				/* broadcast packet */
				PKTFREE(ch->osh, p, FALSE);
				ch->etc->rl_dropped_bc_packets++;
				ch->etc->rl_dropped_packets++;
				continue;
			}
		} else if (ch->etc->rl_stopping_all_packets) {
			PKTFREE(ch->osh, p, FALSE);
			ch->etc->rl_dropped_all_packets++;
			ch->etc->rl_dropped_packets++;
			continue;
		}
#endif /* GMAC_RATE_LIMITING */

		if (ch->etc->allmulti) {
			return (p);
		} else {
			/* skip the rx header */
			PKTPULL(ch->osh, p, HWRXOFF);

			/* do filtering only for multicast packets when allmulti is false */
			da = (struct ether_addr *)PKTDATA(ch->osh, p);
			if (!ETHER_ISMULTI(da) ||
			    (gmac_mf_lkup(ch, da) == SUCCESS) || ETHER_ISBCAST(da)) {
				PKTPUSH(ch->osh, p, HWRXOFF);
				return (p);
			}
			PKTFREE(ch->osh, p, FALSE);
		}
	}

	ch->intstatus &= ~I_RI;

	/* post more rx buffers since we consumed a few */
	dma_rxfill(ch->di[RX_Q0]);

	return (NULL);
}

/* reclaim completed dma receive descriptors and packets */
static void
chiprxreclaim(ch_t *ch)
{
	ET_TRACE(("et%d: chiprxreclaim\n", ch->etc->unit));
	dma_rxreclaim(ch->di[RX_Q0]);
	ch->intstatus &= ~I_RI;
}

/* allocate and post dma receive buffers */
static void BCMFASTPATH
chiprxfill(ch_t *ch)
{
	ET_TRACE(("et%d: chiprxfill\n", ch->etc->unit));
	ET_LOG("et%d: chiprxfill", ch->etc->unit, 0);
	dma_rxfill(ch->di[RX_Q0]);
}

#ifdef DBG_CHECK_ERR
/* get current and pending interrupt events */
static void
check_errs(ch_t *ch)
{
	static uint32 crserrs = 0;
	uint32 err;

	/* read the interrupt status register */
	err = R_REG(ch->osh, &ch->regs->mib.tx_jabber_pkts);
	if (err) {
		printk("%s tx_jabber_pkts (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.tx_oversize_pkts);
	if (err) {
		printk("%s tx_oversize_pkts (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.tx_fragment_pkts);
	if (err) {
		printk("%s tx_fragment_pkts (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.tx_underruns);
	if (err) {
		printk("%s tx_underruns (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.tx_total_cols);
	if (err) {
		printk("%s tx_total_cols (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.tx_single_cols);
	if (err) {
		printk("%s tx_single_cols (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.tx_multiple_cols);
	if (err) {
		printk("%s tx_multiple_cols (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.tx_excessive_cols);
	if (err) {
		printk("%s tx_excessive_cols (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.tx_late_cols);
	if (err) {
		printk("%s tx_late_cols (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.tx_defered);
	if (err) {
		printk("%s tx_defered (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.tx_carrier_lost);
	crserrs += err;
	if (crserrs > 100) {
		printk("%s tx_carrier_lost crserrs(0x%x)\n", __FUNCTION__, crserrs);
		crserrs = 0;
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.tx_pause_pkts);
	if (err) {
		printk("%s tx_pause_pkts (0x%x)\n", __FUNCTION__, err);
    }
    
	err = R_REG(ch->osh, &ch->regs->mib.rx_jabber_pkts);
	if (err) {
		printk("%s rx_jabber_pkts (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.rx_oversize_pkts);
	if (err) {
		printk("%s rx_oversize_pkts (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.rx_fragment_pkts);
	if (err) {
		printk("%s rx_fragment_pkts (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.rx_missed_pkts);
	if (err) {
		printk("%s rx_missed_pkts (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.rx_crc_align_errs);
	if (err) {
		printk("%s rx_crc_align_errs (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.rx_undersize);
	if (err) {
		printk("%s rx_undersize (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.rx_crc_errs);
	if (err) {
		printk("%s rx_crc_errs (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.rx_align_errs);
	if (err) {
		printk("%s rx_align_errs (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.rx_symbol_errs);
	if (err) {
		printk("%s rx_symbol_errs (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.rx_pause_pkts);
	if (err) {
		printk("%s rx_pause_pkts (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.rx_nonpause_pkts);
	if (err) {
		printk("%s rx_nonpause_pkts (0x%x)\n", __FUNCTION__, err);
	}
	
	err = R_REG(ch->osh, &ch->regs->mib.rx_sachanges);
	if (err) {
		printk("%s rx_sachanges (0x%x)\n", __FUNCTION__, err);
	}

	err = R_REG(ch->osh, &ch->regs->dmaregs[0].dmaxmt.status1);
	if (err & 0xf0000000) {
		printk("%s dma0 xmit status (0x%x)\n", __FUNCTION__, err);
	}

	err = R_REG(ch->osh, &ch->regs->dmaregs[0].dmarcv.status1);
	if (err & 0xf0000000) {
		printk("%s dma0 rcv status (0x%x)\n", __FUNCTION__, err);
	}

#if defined(CONFIG_MACH_HR2)
	phy5221_chk_err(ch->etc->unit, ch->etc->phyaddr);
#endif /* defined(CONFIG_MACH_HR2) */
}
#endif /* DBG_CHECK_ERR */

/* get current and pending interrupt events */
static int BCMFASTPATH
chipgetintrevents(ch_t *ch, bool in_isr)
{
	uint32 intstatus;
	int events;

	events = 0;

	/* read the interrupt status register */
	intstatus = R_REG(ch->osh, &ch->regs->intstatus);

	/* defer unsolicited interrupts */
	intstatus &= (in_isr ? ch->intmask : ch->def_intmask);

	if (intstatus != 0) {
		events = INTR_NEW;
	}

	/* or new bits into persistent intstatus */
	intstatus = (ch->intstatus |= intstatus);

	/* return if no events */
	if (intstatus == 0) {
		return (0);
	}

#ifdef DBG_CHECK_ERR
	check_errs(ch);
#endif /* DBG_CHECK_ERR */

	/* convert chip-specific intstatus bits into generic intr event bits */
	if (intstatus & I_RI) {
		events |= INTR_RX;
	}
	if (intstatus & (I_XI0 | I_XI1 | I_XI2 | I_XI3)) {
		events |= INTR_TX;
	}
	if (intstatus & I_ERRORS) {
		events |= INTR_ERROR;
	}

	return (events);
}

/* enable chip interrupts */
static void BCMFASTPATH
chipintrson(ch_t *ch)
{
	ch->intmask = ch->def_intmask;
	W_REG(ch->osh, &ch->regs->intmask, ch->intmask);
}

/* disable chip interrupts */
static void BCMFASTPATH
chipintrsoff(ch_t *ch)
{
	/* disable further interrupts from gmac */
	W_REG(ch->osh, &ch->regs->intmask, 0);
	(void) R_REG(ch->osh, &ch->regs->intmask);	/* sync readback */
	ch->intmask = 0;

	/* clear the interrupt conditions */
	W_REG(ch->osh, &ch->regs->intstatus, ch->intstatus);
}

/* return true of caller should re-initialize, otherwise false */
static bool BCMFASTPATH
chiperrors(ch_t *ch)
{
	uint32 intstatus;
	etc_info_t *etc;

	etc = ch->etc;

	intstatus = ch->intstatus;
	ch->intstatus &= ~(I_ERRORS);

	ET_TRACE(("et%d: chiperrors: intstatus 0x%x\n", etc->unit, intstatus));

	if (intstatus & I_PDEE) {
		ET_ERROR(("et%d: descriptor error\n", etc->unit));
		etc->dmade++;
	}

	if (intstatus & I_PDE) {
		ET_ERROR(("et%d: data error\n", etc->unit));
		etc->dmada++;
	}

	if (intstatus & I_DE) {
		ET_ERROR(("et%d: descriptor protocol error\n", etc->unit));
		etc->dmape++;
	}

	if (intstatus & I_RDU) {
		ET_ERROR(("et%d: receive descriptor underflow\n", etc->unit));
		etc->rxdmauflo++;
	}

	if (intstatus & I_RFO) {
		ET_TRACE(("et%d: receive fifo overflow\n", etc->unit));
		etc->rxoflo++;
	}

	if (intstatus & I_XFU) {
		ET_ERROR(("et%d: transmit fifo underflow\n", etc->unit));
		etc->txuflo++;
	}

	/* if overflows or decriptors underflow, don't report it
	 * as an error and provoque a reset
	 */
	if (intstatus & ~(I_RDU | I_RFO) & I_ERRORS) {
		return (TRUE);
	}

	return (FALSE);
}

static void
chipstatsupd(ch_t *ch)
{
	etc_info_t *etc;
	gmacregs_t *regs;
	volatile uint32 *s;
	uint32 *d;

	etc = ch->etc;
	regs = ch->regs;

	/* read the mib counters and update the driver maintained software
	 * counters.
	 */
	OR_REG(ch->osh, &regs->devcontrol, DC_MROR);
	for (s = &regs->mib.tx_good_octets, d = &ch->mib.tx_good_octets;
	     s <= &regs->mib.rx_uni_pkts; s++, d++) {
		*d += R_REG(ch->osh, s);
		if (s == &ch->regs->mib.tx_q3_octets_high) {
			s++;
			d++;
		}
	}

	/*
	 * Aggregate transmit and receive errors that probably resulted
	 * in the loss of a frame are computed on the fly.
	 *
	 * We seem to get lots of tx_carrier_lost errors when flipping
	 * speed modes so don't count these as tx errors.
	 *
	 * Arbitrarily lump the non-specific dma errors as tx errors.
	 */
	etc->txerror = ch->mib.tx_jabber_pkts + ch->mib.tx_oversize_pkts
		+ ch->mib.tx_underruns + ch->mib.tx_excessive_cols
		+ ch->mib.tx_late_cols + etc->txnobuf + etc->dmade
		+ etc->dmada + etc->dmape + etc->txuflo;
	etc->rxerror = ch->mib.rx_jabber_pkts + ch->mib.rx_oversize_pkts
		+ ch->mib.rx_missed_pkts + ch->mib.rx_crc_align_errs
		+ ch->mib.rx_undersize + ch->mib.rx_crc_errs
		+ ch->mib.rx_align_errs + ch->mib.rx_symbol_errs
		+ etc->rxnobuf + etc->rxdmauflo + etc->rxoflo + etc->rxbadlen;
	etc->rxgiants = (ch->di[RX_Q0])->rxgiants;
}

static void
chipdumpmib(ch_t *ch, struct bcmstrbuf *b, bool clear)
{
	gmacmib_t *m;

	m = &ch->mib;

	if (clear) {
		bzero((char *)m, sizeof(gmacmib_t));
		return;
	}

	bcm_bprintf(b, "tx_broadcast_pkts %d tx_multicast_pkts %d tx_jabber_pkts %d "
	               "tx_oversize_pkts %d\n",
	               m->tx_broadcast_pkts, m->tx_multicast_pkts,
	               m->tx_jabber_pkts,
	               m->tx_oversize_pkts);
	bcm_bprintf(b, "tx_fragment_pkts %d tx_underruns %d\n",
	               m->tx_fragment_pkts, m->tx_underruns);
	bcm_bprintf(b, "tx_total_cols %d tx_single_cols %d tx_multiple_cols %d "
	               "tx_excessive_cols %d\n",
	               m->tx_total_cols, m->tx_single_cols, m->tx_multiple_cols,
	               m->tx_excessive_cols);
	bcm_bprintf(b, "tx_late_cols %d tx_defered %d tx_carrier_lost %d tx_pause_pkts %d\n",
	               m->tx_late_cols, m->tx_defered, m->tx_carrier_lost,
	               m->tx_pause_pkts);

	/* receive stat counters */
	/* hardware mib pkt and octet counters wrap too quickly to be useful */
	bcm_bprintf(b, "rx_broadcast_pkts %d rx_multicast_pkts %d rx_jabber_pkts %d "
	               "rx_oversize_pkts %d\n",
	               m->rx_broadcast_pkts, m->rx_multicast_pkts,
	               m->rx_jabber_pkts, m->rx_oversize_pkts);
	bcm_bprintf(b, "rx_fragment_pkts %d rx_missed_pkts %d rx_crc_align_errs %d "
	               "rx_undersize %d\n",
	               m->rx_fragment_pkts, m->rx_missed_pkts,
	               m->rx_crc_align_errs, m->rx_undersize);
	bcm_bprintf(b, "rx_crc_errs %d rx_align_errs %d rx_symbol_errs %d\n",
	               m->rx_crc_errs, m->rx_align_errs, m->rx_symbol_errs);
	bcm_bprintf(b, "rx_pause_pkts %d rx_nonpause_pkts %d\n",
	               m->rx_pause_pkts, m->rx_nonpause_pkts);
}

static void
chipenablepme(ch_t *ch)
{
	return;
}

static void
chipdisablepme(ch_t *ch)
{
	return;
}

static void
chipduplexupd(ch_t *ch)
{
	uint32 cmdcfg;
	int32 duplex, speed;
#if defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2)
    uint32_t sdctl;
#endif /* defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2) */    

	cmdcfg = R_REG(ch->osh, &ch->regs->cmdcfg);

	/* check if duplex mode changed */
	if (ch->etc->duplex && (cmdcfg & CC_HD)) {
		duplex = 0;
	} else if (!ch->etc->duplex && ((cmdcfg & CC_HD) == 0)) {
		duplex = CC_HD;
	} else {
		duplex = -1;
    }
    
	/* check if the speed changed */
	speed = ((cmdcfg & CC_ES_MASK) >> CC_ES_SHIFT);
	if ((ch->etc->speed == 1000) && (speed != 2)) {
		speed = 2;
	} else if ((ch->etc->speed == 100) && (speed != 1)) {
		speed = 1;
	} else if ((ch->etc->speed == 10) && (speed != 0)) {
		speed = 0;
	} else {
		speed = -1;
    }
    
	/* no duplex or speed change required */
	if ((speed == -1) && (duplex == -1)) {
		return;
    }

	/* update the speed */
	if (speed != -1) {
		cmdcfg &= ~CC_ES_MASK;
		cmdcfg |= (speed << CC_ES_SHIFT);
	}

	/* update the duplex mode */
	if (duplex != -1) {
		cmdcfg &= ~CC_HD;
		cmdcfg |= duplex;
	}

#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2))
	cmdcfg |= (CC_AE | CC_OT | CC_OR);
#endif /* (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2)) */

	ET_TRACE(("chipduplexupd: updating speed & duplex %x\n", cmdcfg));

	/* put mac in reset */
	gmac_init_reset(ch);

	W_REG(ch->osh, &ch->regs->cmdcfg, cmdcfg);

	/* bring mac out of reset */
	gmac_clear_reset(ch);

#if defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2)
    sdctl = R_REG(ch->osh, &ch->regs->serdes_ctl);
    sdctl &= ~(SC_FORCE_SPD_STRAP_MASK);
    switch (ch->etc->speed) {
        case 1000:
            sdctl |= SC_FORCE_SPD_1G_VAL;
            break;
        case 100:
            sdctl |= SC_FORCE_SPD_100M_VAL;
            break;
        default:
            break;
    }
    W_REG(ch->osh, &ch->regs->serdes_ctl, sdctl);
#endif /* defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2) */
}

#ifdef CONFIG_SERDES_ASYMMETRIC_MODE
static void
chipforcespddpx(ch_t *ch)
{
	uint32 cmdcfg;
	int32 duplex=0, speed;

	cmdcfg = R_REG(ch->osh, &ch->regs->cmdcfg);

	/* set duplex */
	if (!ch->etc->duplex)
		duplex = CC_HD;

	/* set speed */
	if (ch->etc->speed == 10) {
		speed = 0;
	} else if (ch->etc->speed == 100) {
		speed = 1;
	} else {
		speed = 2;
    }
    
	/* update the speed */
	cmdcfg &= ~CC_ES_MASK;
	cmdcfg |= (speed << CC_ES_SHIFT);

	/* update the duplex mode */
	cmdcfg &= ~CC_HD;
	cmdcfg |= duplex;

	ET_TRACE(("chipforcespddpx: forcing speed & duplex %x\n", cmdcfg));

	/* put mac in reset */
	gmac_init_reset(ch);

	W_REG(ch->osh, &ch->regs->cmdcfg, cmdcfg);

	/* bring mac out of reset */
	gmac_clear_reset(ch);

	if (ch->etc->up) {
		serdes_speeddpx_set(ch->etc->unit, ch->etc->phyaddr, ch->etc->speed, ch->etc->duplex);
	}
}
#endif /* CONFIG_SERDES_ASYMMETRIC_MODE */


static uint16
chipphyrd(ch_t *ch, uint phyaddr, uint reg)
{
	uint32 tmp=0xffffffff;
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2))
	uint32 addr, int_bus, bank, flags;
	uint16 tmp16;

	addr = phyaddr&0xf;
	int_bus = phyaddr&0xf0;
	bank = (phyaddr&0x1f00) >> 8;
	flags = (phyaddr&0x10000)?SOC_PHY_REG_1000X:0;

    if (int_bus) {
        /* internal serdes */
        tmp = serdes_rd_reg(ch->etc->unit, addr, reg);
    } else {
        /* external phy */
        phy5461_rd_reg(ch->etc->unit, addr, flags, bank, reg, &tmp16);
        tmp = tmp16;
    }
#elif defined(CONFIG_MACH_HR2)
	uint32 addr, bank;
	uint16 tmp16;

	addr = phyaddr&0xf;
	bank = (phyaddr&0x1f00) >> 8;

	phy5221_rd_reg(ch->etc->unit, addr, bank, reg, &tmp16);
	tmp = tmp16;
#elif defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2)
	uint32 addr, bank;
	uint16 tmp16;

	addr = phyaddr&0x1f;
	bank = (phyaddr&0x1f00) >> 8;

	phy5481_rd_reg(ch->etc->unit, addr, bank, reg, &tmp16);
	tmp = tmp16;
#endif /* defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2) */

	return (tmp & PA_DATA_MASK);
}

static void
chipphywr(ch_t *ch, uint phyaddr, uint reg, uint16 v)
{
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2))
    uint32 addr, int_bus, bank, flags;

    addr = phyaddr&0xf;
    int_bus = phyaddr&0xf0;
    bank = (phyaddr&0x1f00) >> 8;
    flags = (phyaddr&0x10000)?SOC_PHY_REG_1000X:0;

    if (int_bus) {
        /* internal serdes */
        serdes_wr_reg(ch->etc->unit, addr, reg, v);
    } else {
        /* external phy */
        phy5461_wr_reg(ch->etc->unit, addr, flags, bank, reg, &v);
    }
#elif defined(CONFIG_MACH_HR2)
	uint32 addr, bank;

	addr = phyaddr&0xf;
	bank = (phyaddr&0x1f00) >> 8;

	phy5221_wr_reg(ch->etc->unit, addr, bank, reg, &v);

#elif defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2)
    uint32 addr, bank;
    uint16 tmp16;

    addr = phyaddr&0x1f;
    bank = (phyaddr&0x1f00) >> 8;
    tmp16 = (v & PA_DATA_MASK);

    phy5481_wr_reg(ch->etc->unit, addr, bank, reg, &tmp16);
#endif /* defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2) */
}

static void
chipphyor(ch_t *ch, uint phyaddr, uint reg, uint16 v)
{
	uint16 tmp;

	tmp = chipphyrd(ch, phyaddr, reg);
	tmp |= v;
	chipphywr(ch, phyaddr, reg, tmp);
}

static void
chipphyreset(ch_t *ch, uint phyaddr)
{
	ASSERT(phyaddr < MAXEPHY);

	if (phyaddr == EPHY_NOREG) {
		return;
	}

	ET_TRACE(("et%d: chipphyreset: phyaddr %d\n", ch->etc->unit, phyaddr));

#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2))
    chipphywr(ch, phyaddr, 0, CTL_RESET);
    OSL_DELAY(100);
    if (chipphyrd(ch, phyaddr, 0) & CTL_RESET) {
        ET_ERROR(("et%d: chipphyreset: reset not complete\n", ch->etc->unit));
    }
    serdes_reset(ch->etc->unit, phyaddr);
#elif defined(CONFIG_MACH_HR2)
    chipphywr(ch, phyaddr, 0, CTL_RESET);
    OSL_DELAY(100);
    if (chipphyrd(ch, phyaddr, 0) & CTL_RESET) {
        ET_ERROR(("et%d: chipphyreset: reset not complete\n", ch->etc->unit));
    }
#endif /* defined(CONFIG_MACH_HR2) */

	chipphyinit(ch, phyaddr);
}

static void
chipphyinit(ch_t *ch, uint phyaddr)
{
	if (phyaddr == EPHY_NOREG)
		return;

	ET_TRACE(("et%d: chipphyinit: phyaddr %d\n", ch->etc->unit, phyaddr));
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2))
	phy5461_init(ch->etc->unit, phyaddr);
	serdes_init(ch->etc->unit, phyaddr);
#elif defined(CONFIG_MACH_HR2)
	phy5221_init(ch->etc->unit, phyaddr);
#elif defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2)
	phy5481_init(ch->etc->unit, phyaddr);
#endif /* defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2) */

}

static void
chipphyforce(ch_t *ch, uint phyaddr)
{
	etc_info_t *etc;
	uint16 ctl;
#ifdef CONFIG_FORCED_MODE_AUTO_MDIX
    uint16 adv;
#endif
	ASSERT(phyaddr < MAXEPHY);

	if (phyaddr == EPHY_NOREG) {
		return;
	}

	etc = ch->etc;

	if (etc->forcespeed == ET_AUTO) {
		return;
    }

	ET_TRACE(("et%d: chipphyforce: phyaddr %d speed %d\n",
	          ch->etc->unit, phyaddr, etc->forcespeed));

	ctl = chipphyrd(ch, phyaddr, PHY_MII_CTRLr_ADDR);
	ctl &= ~(CTL_SPEED | CTL_SPEED_MSB | CTL_ANENAB | CTL_DUPLEX);
#ifdef CONFIG_FORCED_MODE_AUTO_MDIX
    adv = chipphyrd(ch, phyaddr, PHY_MII_GB_CTRLr_ADDR);
    adv &= ~(ADV_1000FULL | ADV_1000HALF);
    chipphywr(ch, phyaddr, PHY_MII_GB_CTRLr_ADDR, adv);

    adv = chipphyrd(ch, phyaddr, PHY_MII_ANAr_ADDR);
    adv &= ~(ADV_100FULL | ADV_100HALF | ADV_10FULL | ADV_10HALF);
#endif
	switch (etc->forcespeed) {
		case ET_10HALF:
#ifdef CONFIG_FORCED_MODE_AUTO_MDIX
             adv |= ADV_10HALF;
#endif
			break;

		case ET_10FULL:
			ctl |= CTL_DUPLEX;
#ifdef CONFIG_FORCED_MODE_AUTO_MDIX
             adv |= ADV_10FULL;
#endif
			break;

		case ET_100HALF:
			ctl |= CTL_SPEED_100;
#ifdef CONFIG_FORCED_MODE_AUTO_MDIX
            adv |= ADV_100HALF;
#endif
			break;

		case ET_100FULL:
			ctl |= (CTL_SPEED_100 | CTL_DUPLEX);
#ifdef CONFIG_FORCED_MODE_AUTO_MDIX
            adv |= ADV_100FULL;
#endif
			break;

		case ET_1000FULL:
			ctl |= (CTL_SPEED_1000 | CTL_DUPLEX);
			break;
	}

	chipphywr(ch, phyaddr, PHY_MII_CTRLr_ADDR, ctl);
#ifdef CONFIG_FORCED_MODE_AUTO_MDIX
    chipphywr(ch, phyaddr, PHY_MII_ANAr_ADDR, adv);
    if (etc->forcespeed != ET_1000FULL) {
        adv = chipphyrd(ch, phyaddr | (PHY_MII_MISC_CTRLr_BANK << 8), PHY_MII_MISC_CTRLr_ADDR);
        adv |= MII_FORCED_AUTO_MDIX;
        chipphywr(ch, phyaddr | (PHY_MII_MISC_CTRLr_BANK << 8), PHY_MII_MISC_CTRLr_ADDR, adv);
        adv = chipphyrd(ch, phyaddr | (PHY_MII_MISC_CTRLr_BANK << 8), PHY_MII_MISC_CTRLr_ADDR);
        printk(KERN_DEBUG "misc_ctrl = 0x%x\n", adv);
    }
#endif
}

/* set selected capability bits in autonegotiation advertisement */
static void
chipphyadvertise(ch_t *ch, uint phyaddr)
{
    etc_info_t *etc;
    uint16 adv, adv2;

	ASSERT(phyaddr < MAXEPHY);

	if (phyaddr == EPHY_NOREG) {
		return;
	}

	etc = ch->etc;

	if ((etc->forcespeed != ET_AUTO) || !etc->needautoneg) {
		return;
	}

	ASSERT(etc->advertise);

	ET_TRACE(("et%d: chipphyadvertise: phyaddr %d advertise %x\n",
	          ch->etc->unit, phyaddr, etc->advertise));

	/* reset our advertised capabilitity bits */
	adv = chipphyrd(ch, phyaddr, PHY_MII_ANAr_ADDR);
	adv &= ~(ADV_100FULL | ADV_100HALF | ADV_10FULL | ADV_10HALF);
    adv |= (etc->advertise | ADV_PAUSE);
	chipphywr(ch, phyaddr, PHY_MII_ANAr_ADDR, adv);

	adv2 = chipphyrd(ch, phyaddr, PHY_MII_GB_CTRLr_ADDR);
	adv2 &= ~(ADV_1000FULL | ADV_1000HALF);
	adv2 |= etc->advertise2;
	chipphywr(ch, phyaddr, PHY_MII_GB_CTRLr_ADDR, adv2);

	ET_TRACE(("et%d: chipphyadvertise: phyaddr %d adv %x adv2 %x phyad0 %x\n",
	          ch->etc->unit, phyaddr, adv, adv2, chipphyrd(ch, phyaddr, 0)));
#ifdef CONFIG_FORCED_MODE_AUTO_MDIX
    adv = chipphyrd(ch, phyaddr | (PHY_MII_MISC_CTRLr_BANK << 8), PHY_MII_MISC_CTRLr_ADDR);
    if (adv & MII_FORCED_AUTO_MDIX) {
        adv &= ~MII_FORCED_AUTO_MDIX;
        chipphywr(ch, phyaddr | (PHY_MII_MISC_CTRLr_BANK << 8), PHY_MII_MISC_CTRLr_ADDR, adv);
        adv = chipphyrd(ch, phyaddr | (PHY_MII_MISC_CTRLr_BANK << 8), PHY_MII_MISC_CTRLr_ADDR);
    }
    printk(KERN_DEBUG "misc_ctrl = 0x%x\n", adv);
#endif
	/* restart autonegotiation */
	chipphyor(ch, phyaddr, PHY_MII_CTRLr_ADDR, CTL_RESTART);
	etc->needautoneg = FALSE;
}

static void
chipphyenable(ch_t *ch, uint eth_num, uint phyaddr, int enable)
{
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2))
	phy5461_enable_set(eth_num, phyaddr, enable);
#elif defined(CONFIG_MACH_HR2)
	phy5221_enable_set(eth_num, phyaddr, enable);
#elif defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2)
	phy5481_enable_set(eth_num, phyaddr, enable);
#endif /* defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3) || defined(CONFIG_MACH_GH2) */
}

#ifdef GMAC_RATE_LIMITING
void
etc_check_rate_limiting(etc_info_t *etc, void *pch)
{
	/*ch_t *ch = (ch_t*)pch;*/
	uint32 timediff;
	static uint32 first_run=1;
	static uint32 prev_bc_frame_cnt=0, bc_frame_cnts=0;

	if (first_run) {
	    prev_bc_frame_cnt = etc->rx_bc_frame_cnt;
		first_run = 0;
	}	
	else {
 		bc_frame_cnts += (etc->rx_bc_frame_cnt >= prev_bc_frame_cnt) ?  (etc->rx_bc_frame_cnt - prev_bc_frame_cnt) : (0xffffffff + etc->rx_bc_frame_cnt - prev_bc_frame_cnt);
		prev_bc_frame_cnt = etc->rx_bc_frame_cnt;
	}

	timediff = ((long)jiffies - (long)(etc->rl_prior_jiffies));	
	if ((timediff >> 5) != 0) {
		/* 32 or more jiffies have gone by; see if we're seeing too 
		many packets */
		if ((timediff >> 5) == 1) {
			/* 32-63 jiffies elapsed */
			if (((bc_frame_cnts >> 10) != 0) && !(etc->rl_stopping_broadcasts)) {	
				/* 1K or more broadcast packets have arrived in 32-63 jiffies; try to throttle back the incoming packets */
				etc->rl_stopping_broadcasts = 1;
				printk("et%d: %s: stopping broadcasts bc_frame_cnts(0x%x)\n",
					 etc->unit, __FUNCTION__, bc_frame_cnts);
				if (!timer_pending(&etc->rl_timer)) {
					etc->rl_timer.expires = jiffies + HZ;
					add_timer(&etc->rl_timer);
					etc->rl_set=TRUE;
				}
			}
		}
		etc->rl_prior_jiffies = jiffies;
		bc_frame_cnts = 0;
	}
}
#endif /* GMAC_RATE_LIMITING */


