/*
 * $Copyright Open Broadcom Corporation$
 *
 * Common [OS-independent] portion of
 * Broadcom Home Networking Division 10/100 Mbit/s Ethernet
 * Device Driver.
 *
 * $Id: etc.c 323634 2012-03-26 10:26:11Z groques $
 */

#include <et_cfg.h>
#include <typedefs.h>
#include <osl.h>
#include <bcmendian.h>
#include <proto/ethernet.h>
#include <proto/vlan.h>
#include <proto/bcmip.h>
#include <proto/802.1d.h>
#include <bcmenetmib.h>
#include <bcmenetrxh.h>
#include <bcmenetphy.h>
#include <et_dbg.h>
#include <etc.h>
#include <et_export.h>
#include <bcmutils.h>
#include <bcmnvram.h>
#include <mach/iproc_regs.h>

#ifdef BCMDBG
uint32 et_msg_level = 1;
#else
uint32 et_msg_level = 0;
#endif /* BCMDBG */

uint8 ethup = 0;
uint8 ethupmask = 0;
etc_info_t *ethupetcptr[IPROC_NUM_GMACS];

/* local prototypes */
static void etc_loopback(etc_info_t *etc, int on);
static void etc_dumpetc(etc_info_t *etc, struct bcmstrbuf *b);
int etc_gmac_speed(int gmac);

#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2))
extern void gmac_set_amac_mdio(int en);
extern int gmac_has_mdio_access(void);
#endif /* (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2)) */

#ifdef CONFIG_SERDES_ASYMMETRIC_MODE
void gmac_serdes_asym_mode(etc_info_t *etcptrs[]);
#endif /* CONFIG_SERDES_ASYMMETRIC_MODE */

/* 802.1d priority to traffic class mapping. queues correspond one-to-one
 * with traffic classes.
 */
uint32 up2tc[NUMPRIO] = {
	TC_BE,  	/* 0    BE    TC_BE    Best Effort */
	TC_BK,  	/* 1    BK    TC_BK    Background */
	TC_BK,  	/* 2    --    TC_BK    Background */
	TC_BE,  	/* 3    EE    TC_BE    Best Effort */
	TC_CL,  	/* 4    CL    TC_CL    Controlled Load */
	TC_CL,  	/* 5    VI    TC_CL    Controlled Load */
	TC_VO,  	/* 6    VO    TC_VO    Voice */
	TC_VO   	/* 7    NC    TC_VO    Voice */
};

uint32 priq_selector[] = {
	[0x0] = TC_NONE, [0x1] = TC_BK, [0x2] = TC_BE, [0x3] = TC_BE,
	[0x4] = TC_CL,   [0x5] = TC_CL, [0x6] = TC_CL, [0x7] = TC_CL,
	[0x8] = TC_VO,   [0x9] = TC_VO, [0xa] = TC_VO, [0xb] = TC_VO,
	[0xc] = TC_VO,   [0xd] = TC_VO, [0xe] = TC_VO, [0xf] = TC_VO
};

/* find the chip opsvec for this chip */
struct chops*
etc_chipmatch(uint vendor, uint device)
{
    extern struct chops bcmgmac_et_chops;

    if (bcmgmac_et_chops.id(vendor, device)) {
        return (&bcmgmac_et_chops);
    }
    
	return (NULL);
}

void*
etc_attach(void *et, uint vendor, uint device, uint unit, void *osh, void *regsva)
{
	etc_info_t *etc;
	char *var;

	ET_TRACE(("et%d: etc_attach: vendor 0x%x device 0x%x\n", unit, vendor, device));

	/* some code depends on packed structures */
	ASSERT(sizeof(struct ether_addr) == ETHER_ADDR_LEN);
	ASSERT(sizeof(struct ether_header) == ETHER_HDR_LEN);

	/* allocate etc_info_t state structure */
	if ((etc = (etc_info_t*) MALLOC(osh, sizeof(etc_info_t))) == NULL) {
		ET_ERROR(("et%d: etc_attach: out of memory, malloced %d bytes\n", unit,
		          MALLOCED(osh)));
		return (NULL);
	}
	bzero((char*)etc, sizeof(etc_info_t));

	etc->et = et;
	etc->unit = unit;
	etc->osh = osh;
	etc->vendorid = (uint16) vendor;
	etc->deviceid = (uint16) device;
	etc->forcespeed = etc_gmac_speed(unit);
	etc->linkstate = FALSE;
	etc->mdio_init_time = 5;		/* number of seconds to wait before release mdio bus */
	var = getvar(NULL, "eth_init_time");
	if (var) {
		etc->mdio_init_time = bcm_strtoul(var, NULL, 0);
	}
	printk("%s() mdio_init_time = %d\n", __FUNCTION__, etc->mdio_init_time);
	ethupmask |= 1<<etc->unit;
	ethupetcptr[unit] = etc;

	/* set chip opsvec */
	etc->chops = etc_chipmatch(vendor, device);
	ASSERT(etc->chops);

	/* chip attach */
	if ((etc->ch = (*etc->chops->attach)(etc, osh, regsva)) == NULL) {
		ET_ERROR(("et%d: chipattach error\n", unit));
		goto fail;
	}

	return ((void*)etc);

fail:
	etc_detach(etc);
	return (NULL);
}

void
etc_detach(etc_info_t *etc)
{
	if (etc == NULL)
		return;

	/* free chip private state */
	if (etc->ch) {
		(*etc->chops->detach)(etc->ch);
		etc->chops = etc->ch = NULL;
	}

	MFREE(etc->osh, etc, sizeof(etc_info_t));
}

void
etc_reset(etc_info_t *etc)
{
	ET_TRACE(("et%d: etc_reset\n", etc->unit));

	etc->reset++;

	/* reset the chip */
	(*etc->chops->reset)(etc->ch);

	/* free any posted tx packets */
	(*etc->chops->txreclaim)(etc->ch, TRUE);

#ifdef DMA
	/* free any posted rx packets */
	(*etc->chops->rxreclaim)(etc->ch);
#endif /* DMA */
}

void
etc_init(etc_info_t *etc, uint options)
{
	ET_TRACE(("et%d: etc_init\n", etc->unit));

	ASSERT(etc->pioactive == NULL);
	ASSERT(!ETHER_ISNULLADDR(&etc->cur_etheraddr));
	ASSERT(!ETHER_ISMULTI(&etc->cur_etheraddr));

	/* init the chip */
	(*etc->chops->init)(etc->ch, options);
	/* init the PM change mode and linkstate */
	etc->pm_modechange = FALSE;
	etc->linkstate = FALSE;
}

/* mark interface up */
void
etc_up(etc_info_t *etc)
{
	etc->up = TRUE;

	/* enable the port phy */
	(*etc->chops->phyenable)(etc->ch, etc->unit, etc->phyaddr, 1);

	et_init(etc->et, ET_INIT_FULL | ET_INIT_INTRON);
}

/* mark interface down */
uint
etc_down(etc_info_t *etc, int reset)
{
	uint callback;

	callback = 0;

	ET_FLAG_DOWN(etc);

	/* disable the port phy */
	(*etc->chops->phyenable)(etc->ch, etc->unit, etc->phyaddr, 0);

	if (reset) {
		et_reset(etc->et);
	}

	/* suppress link state changes during power management mode changes */
	if (etc->linkstate) {
		etc->linkstate = FALSE;
		if (!etc->pm_modechange) {
			et_link_down(etc->et);
		}
	}

	return (callback);
}

/* common iovar handler. return 0=ok, -1=error */
int
etc_iovar(etc_info_t *etc, uint cmd, uint set, void *arg)
{
	int error;
	uint *vecarg;

	error = 0;
	vecarg = (uint *)arg;
	ET_TRACE(("et%d: etc_iovar: cmd 0x%x\n", etc->unit, cmd));

	switch (cmd) {
#ifdef BCMDBG
		case IOV_ET_CLEAR_DUMP:
			if (set) {
				uint size = ((char *)(&etc->rxbadlen) - (char *)(&etc->txframe));

				bzero((char *)&etc->txframe, size + sizeof(etc->rxbadlen));
				(*etc->chops->dumpmib)(etc->ch, NULL, TRUE);
				error = 0;
			}
			break;
#endif /* BCMDBG */
		case IOV_PKTC:
			if (set) {
				etc->pktc = *vecarg;
			} else {
				*vecarg = (uint)etc->pktc;
			}
			break;

		case IOV_PKTCBND:
			if (set) {
				etc->pktcbnd = MAX(*vecarg, 32);
			} else {
				*vecarg = etc->pktcbnd;
			}
			break;

		case IOV_COUNTERS:
			{
				struct bcmstrbuf b;
				bcm_binit(&b, (char*)arg, IOCBUFSZ);
				etc_dumpetc(etc, &b);
			}
			break;

		default:
			error = -1;
	}

	return (error);
}

/* common ioctl handler.  return: 0=ok, -1=error */
int
etc_ioctl(etc_info_t *etc, int cmd, void *arg)
{
	int error;
	int val;
	int *vec = (int*)arg;

	error = 0;

	val = arg ? *(int*)arg : 0;

	ET_TRACE(("et%d: etc_ioctl: cmd 0x%x\n", etc->unit, cmd));

	switch (cmd) {
	case ETCUP:
		et_up(etc->et);
		break;

	case ETCDOWN:
		et_down(etc->et, TRUE);
		break;

	case ETCLOOP:
		etc_loopback(etc, val);
		break;

	case ETCDUMP:
		if (et_msg_level & 0x10000) {
			bcmdumplog((char *)arg, IOCBUFSZ);
		} else {
			struct bcmstrbuf b;
			bcm_binit(&b, (char*)arg, IOCBUFSZ);
			et_dump(etc->et, &b);
		}
		break;

	case ETCSETMSGLEVEL:
		et_msg_level = val;
		break;

	case ETCPROMISC:
		etc_promisc(etc, val);
		break;

	case ETCQOS:
		etc_qos(etc, val);
		break;

	case ETCSPEED:
        if (vec) {
            if (vec[0] < ET_AUTO || vec[0] > ET_1000FULL) {
                goto err;
            }

		    etc->forcespeed = vec[0];

		    /* explicitly reset the phy */
		    (*etc->chops->phyreset)(etc->ch, etc->phyaddr);

		    /* request restart autonegotiation if we're reverting to adv mode */
            etc->advertise = etc->advertise2 = 0;
            if (etc->forcespeed == ET_AUTO) {
                if (vec[1] & ADVERTISED_10baseT_Half) {
                    etc->advertise |= ADV_10HALF;
                }
                if (vec[1] & ADVERTISED_10baseT_Full) {
                    etc->advertise |= ADV_10FULL;
                }
                if (vec[1] & ADVERTISED_100baseT_Half) {
                    etc->advertise |= ADV_100HALF;
                }
                if (vec[1] & ADVERTISED_100baseT_Full) {
                    etc->advertise |= ADV_100FULL;
                }
                if (vec[1] & ADVERTISED_1000baseT_Full) {
                    etc->advertise2 |= ADV_1000FULL;
                }
                etc->needautoneg = TRUE;
            } else {
                etc->needautoneg = FALSE;
            }
            et_init(etc->et, ET_INIT_INTRON);
        }
		break;

	case ETCPHYRD:
		if (vec) {
			vec[1] = (*etc->chops->phyrd)(etc->ch, etc->phyaddr, vec[0]);
			ET_TRACE(("etc_ioctl: ETCPHYRD of reg 0x%x => 0x%x\n", vec[0], vec[1]));
		}
		break;

	case ETCPHYRD2:
		if (vec) {
			uint phyaddr, reg;
			phyaddr = vec[0] >> 16;
    		reg = vec[0] & 0xffff;
            vec[1] = (*etc->chops->phyrd)(etc->ch, phyaddr, reg);
		    ET_TRACE(("etc_ioctl: ETCPHYRD2 of phy 0x%x, reg 0x%x => 0x%x\n",
				        phyaddr, reg, vec[1]));
		}
		break;

	case ETCPHYWR:
		if (vec) {
			ET_TRACE(("etc_ioctl: ETCPHYWR to reg 0x%x <= 0x%x\n", vec[0], vec[1]));
			(*etc->chops->phywr)(etc->ch, etc->phyaddr, vec[0], (uint16)vec[1]);
		}
		break;

	case ETCPHYWR2:
		if (vec) {
			uint phyaddr, reg;
			phyaddr = vec[0] >> 16;
			reg = vec[0] & 0xffff;
			(*etc->chops->phywr)(etc->ch, phyaddr, reg, (uint16)vec[1]);
			ET_TRACE(("etc_ioctl: ETCPHYWR2 to phy 0x%x, reg 0x%x <= 0x%x\n",
			          phyaddr, reg, vec[1]));
		}
		break;

	default:
err:
		error = -1;
	}

	return (error);
}

/* called once per second */
void
etc_watchdog(etc_info_t *etc)
{
	uint16 status;
	uint16 lpa;
	uint16 phyaddrflag = 0;

	etc->now++;

	/* no local phy registers */
	if (etc->phyaddr == EPHY_NOREG) {
		etc->linkstate = TRUE;
		etc->duplex = 1;
		/* keep emac txcontrol duplex bit consistent with current phy duplex */
		(*etc->chops->duplexupd)(etc->ch);
		return;
	}

	if (etc->up && etc->linkstate) {
		if (!(ethup & 1<<etc->unit)) {
            printk(KERN_DEBUG "et%d Interface up\n", etc->unit);   
        }
		ethup |= 1<<etc->unit;
	}

#if defined(CONFIG_IPROC_SDK_MGT_PORT_HANDOFF)
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2))
	if ( !gmac_has_mdio_access()) {
        /* we can't monitor link so force link up */
        /* if GMAC does not have access to MDIO then exit */
		if (!etc->linkstate) {
	        etc->linkstate = TRUE;
    	    etc->duplex = 1;
        	etc->speed = 1000;
		}
        /* keep emac txcontrol duplex bit consistent with current phy duplex */
        (*etc->chops->duplexupd)(etc->ch);
        if (!et_is_link_up(etc->et)) {
            printk(KERN_DEBUG "%s rcan't access PHY, forcing link up\n", __FUNCTION__);
            et_link_up(etc->et);
        }
        return;
    }

	/* check if need to release mdio access */
	if ((ethup==ethupmask) || (etc->now > etc->mdio_init_time)) {
		/* either both links up or (5) "eth_init_time" seconds elapsed */
        /* keep mdio access if ethtool is set */
        char *s = getvar(NULL, "ethtool");
        if (!s) {
#ifdef CONFIG_SERDES_ASYMMETRIC_MODE
			gmac_serdes_asym_mode(ethupetcptr);
#endif /* CONFIG_SERDES_ASYMMETRIC_MODE */
            printk(KERN_DEBUG "%s releasing MDIO access; ethup(0x%x)\n", __FUNCTION__, ethup);
            gmac_set_amac_mdio(0);
            return;
        }
    }
#endif /* (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2)) */
#endif /* defined(CONFIG_IPROC_SDK_MGT_PORT_HANDOFF) */

	status = (*etc->chops->phyrd)(etc->ch, phyaddrflag+etc->phyaddr, 1);
	/* check for bad mdio read */
	if (status == 0xffff) {
		ET_ERROR(("et%d: etc_watchdog: bad mdio read: phyaddr %d mdcport %d\n",
			etc->unit, etc->phyaddr, etc->mdcport));
		return;
	}

	if (etc->forcespeed == ET_AUTO) {
		uint16 adv, adv2 = 0, status2 = 0, estatus;

		adv = (*etc->chops->phyrd)(etc->ch, phyaddrflag+etc->phyaddr, 4);
		lpa = (*etc->chops->phyrd)(etc->ch, phyaddrflag+etc->phyaddr, 5);

		/* read extended status register. if we are 1000BASE-T
		 * capable then get our advertised capabilities and the
		 * link partner capabilities from 1000BASE-T control and
		 * status registers.
		 */
		estatus = (*etc->chops->phyrd)(etc->ch, phyaddrflag+etc->phyaddr, 15);
		if ((estatus != 0xffff) && (estatus & EST_1000TFULL)) {
			/* read 1000BASE-T control and status registers */
			adv2 = (*etc->chops->phyrd)(etc->ch, phyaddrflag+etc->phyaddr, 9);
			status2 = (*etc->chops->phyrd)(etc->ch, phyaddrflag+etc->phyaddr, 10);
		}

		/* update current speed and duplex */
		if ((adv2 & ADV_1000FULL) && (status2 & LPA_1000FULL)) {
			etc->speed = 1000;
			etc->duplex = 1;
		} else if ((adv2 & ADV_1000HALF) && (status2 & LPA_1000HALF)) {
			etc->speed = 1000;
			etc->duplex = 0;
		} else if ((adv & ADV_100FULL) && (lpa & LPA_100FULL)) {
			etc->speed = 100;
			etc->duplex = 1;
		} else if ((adv & ADV_100HALF) && (lpa & LPA_100HALF)) {
			etc->speed = 100;
			etc->duplex = 0;
		} else if ((adv & ADV_10FULL) && (lpa & LPA_10FULL)) {
			etc->speed = 10;
			etc->duplex = 1;
		} else {
			etc->speed = 10;
			etc->duplex = 0;
		}
	}

	/* monitor link state */
	if (!etc->linkstate && (status & STAT_LINK)) {
		etc->linkstate = TRUE;
		if (etc->pm_modechange) {
			etc->pm_modechange = FALSE;
		} else {
			et_link_up(etc->et);
#ifdef CONFIG_SERDES_ASYMMETRIC_MODE
	        (*etc->chops->forcespddpx)(etc->ch);
#endif /* CONFIG_SERDES_ASYMMETRIC_MODE */
		}
	} else if (etc->linkstate && !(status & STAT_LINK)) {
		etc->linkstate = FALSE;
		if (!etc->pm_modechange) {
			et_link_down(etc->et);
		}
	}

	/* keep emac txcontrol duplex bit consistent with current phy duplex */
	(*etc->chops->duplexupd)(etc->ch);

	/* check for remote fault error */
	if (status & STAT_REMFAULT) {
		ET_ERROR(("et%d: remote fault\n", etc->unit));
	}

	/* check for jabber error */
	if (status & STAT_JAB) {
		ET_ERROR(("et%d: jabber\n", etc->unit));
	}

	/*
	 * Read chip mib counters occationally before the 16bit ones can wrap.
	 * We don't use the high-rate mib counters.
	 */
	if ((etc->now % 30) == 0) {
		(*etc->chops->statsupd)(etc->ch);
	}
}

static void
etc_loopback(etc_info_t *etc, int on)
{
	ET_TRACE(("et%d: etc_loopback: %d\n", etc->unit, on));

	etc->loopbk = (bool) on;
	et_init(etc->et, ET_INIT_INTRON);
}

void
etc_promisc(etc_info_t *etc, uint on)
{
	ET_TRACE(("et%d: etc_promisc: %d\n", etc->unit, on));

	etc->promisc = (bool) on;
	et_init(etc->et, ET_INIT_INTRON);
}

void
etc_qos(etc_info_t *etc, uint on)
{
	ET_TRACE(("et%d: etc_qos: %d\n", etc->unit, on));

	etc->qos = (bool) on;
	et_init(etc->et, ET_INIT_INTRON);
}

void
etc_dump(etc_info_t *etc, struct bcmstrbuf *b)
{
	etc_dumpetc(etc, b);
	(*etc->chops->dump)(etc->ch, b);
}

static void
etc_dumpetc(etc_info_t *etc, struct bcmstrbuf *b)
{
	char perm[32], cur[32];
	uint i;

	bcm_bprintf(b, "etc 0x%x et 0x%x unit %d msglevel %d speed/duplex %d%s\n",
		(ulong)etc, (ulong)etc->et, etc->unit, et_msg_level,
		etc->speed, (etc->duplex ? "full": "half"));
	bcm_bprintf(b, "up %d promisc %d loopbk %d forcespeed %d advertise 0x%x "
	               "advertise2 0x%x needautoneg %d\n",
	               etc->up, etc->promisc, etc->loopbk, etc->forcespeed,
	               etc->advertise, etc->advertise2, etc->needautoneg);
	bcm_bprintf(b, "piomode %d pioactive 0x%x nmulticast %d allmulti %d qos %d\n",
		etc->piomode, (ulong)etc->pioactive, etc->nmulticast, etc->allmulti, etc->qos);
	bcm_bprintf(b, "vendor 0x%x device 0x%x rev %d coreunit %d phyaddr %d mdcport %d\n",
		etc->vendorid, etc->deviceid, etc->chiprev,
		etc->coreunit, etc->phyaddr, etc->mdcport);

	bcm_bprintf(b, "perm_etheraddr %s cur_etheraddr %s\n",
		bcm_ether_ntoa(&etc->perm_etheraddr, perm),
		bcm_ether_ntoa(&etc->cur_etheraddr, cur));

	if (etc->nmulticast) {
		bcm_bprintf(b, "multicast: ");
		for (i = 0; i < etc->nmulticast; i++) {
			bcm_bprintf(b, "%s ", bcm_ether_ntoa(&etc->multicast[i], cur));
		}
		bcm_bprintf(b, "\n");
	}

	bcm_bprintf(b, "linkstate %d\n", etc->linkstate);
	bcm_bprintf(b, "\n");

	/* refresh stat counters */
	(*etc->chops->statsupd)(etc->ch);

	/* summary stat counter line */
	/* use sw frame and byte counters -- hw mib counters wrap too quickly */
	bcm_bprintf(b, "txframe %d txbyte %d txerror %d rxframe %d rxbyte %d rxerror %d\n",
		etc->txframe, etc->txbyte, etc->txerror,
		etc->rxframe, etc->rxbyte, etc->rxerror);

	/* transmit & receive stat counters */
	/* hardware mib pkt and octet counters wrap too quickly to be useful */
	(*etc->chops->dumpmib)(etc->ch, b, FALSE);

	bcm_bprintf(b, "txnobuf %d reset %d dmade %d dmada %d dmape %d\n",
	               etc->txnobuf, etc->reset, etc->dmade, etc->dmada, etc->dmape);

	/* hardware mib pkt and octet counters wrap too quickly to be useful */
	bcm_bprintf(b, "rxnobuf %d rxdmauflo %d rxoflo %d rxbadlen %d "
	               "rxgiants %d rxoflodiscards %d\n",
	               etc->rxnobuf, etc->rxdmauflo, etc->rxoflo, etc->rxbadlen,
	               etc->rxgiants, etc->rxoflodiscards);

	bcm_bprintf(b, "chained %d chainedsz1 %d unchained %d maxchainsz %d currchainsz %d\n",
	               etc->chained, etc->chainedsz1, etc->unchained, etc->maxchainsz,
	               etc->currchainsz);

	bcm_bprintf(b, "\n");
}

uint
etc_totlen(etc_info_t *etc, void *p)
{
	uint total;

	total = 0;
	for (; p; p = PKTNEXT(etc->osh, p)) {
		total += PKTLEN(etc->osh, p);
	}
	return (total);
}

#ifdef BCMDBG
void
etc_prhdr(char *msg, struct ether_header *eh, uint len, int unit)
{
	char da[32], sa[32];

	if (msg && (msg[0] != '\0')) {
		printf("et%d: %s: ", unit, msg);
	} else {
		printf("et%d: ", unit);
	}

	printf("dst %s src %s type 0x%04X len %d\n",
		bcm_ether_ntoa((struct ether_addr *)eh->ether_dhost, da),
		bcm_ether_ntoa((struct ether_addr *)eh->ether_shost, sa),
		ntoh16(eh->ether_type),
		len);
}
void
etc_prhex(char *msg, uchar *buf, uint nbytes, int unit)
{
	if (msg && (msg[0] != '\0')) {
		printf("et%d: %s:\n", unit, msg);
	} else {
		printf("et%d:\n", unit);
	}

	prhex(NULL, buf, nbytes);
}
#endif /* BCMDBG */

int
etc_gmac_speed(int gmac)
{
	char name[16], *speed;
	sprintf(name, "et%dspeed", gmac); 

	speed = nvram_get(name);
	if (speed == NULL) {
		printf("%s default GMAC%d speed: auto\n", __FUNCTION__, gmac);
		return ET_AUTO;
	}

	if (!strcmp(speed, "2500")) {
		printf("%s specifing GMAC%d speed: 2500\n", __FUNCTION__, gmac);
		return ET_2500FULL;
	} else if (!strcmp(speed, "1000")) {
		printf("%s specifing GMAC%d speed: 1000\n", __FUNCTION__, gmac);
		return ET_1000FULL;
	} else if (!strcmp(speed, "100")) {
		printf("%s specifing GMAC%d speed: 100\n", __FUNCTION__, gmac);
		return ET_100FULL;
	} else if (!strcmp(speed, "10")) {
		printf("%s specifing GMAC%d speed: 10\n", __FUNCTION__, gmac);
		return ET_10FULL;
	}

	printf("%s default GMAC%d speed: auto\n", __FUNCTION__, gmac);
	return ET_AUTO;
}
