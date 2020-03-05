/*
 * $Copyright Open Broadcom Corporation$
 *
 * Linux device driver for
 * Broadcom BCM47XX 10/100/1000 Mbps Ethernet Controller
 *
 * $Id: et_linux.c 327582 2012-04-14 05:02:37Z kenlo $
 */

#include <et_cfg.h>
#define __UNDEF_NO_VERSION__

#include <typedefs.h>

#include <linux/module.h>
#include <linuxver.h>
#include <bcmdefs.h>
#include <osl.h>

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/sockios.h>
#ifdef SIOCETHTOOL
#include <linux/ethtool.h>
#endif /* SIOCETHTOOL */
#include <linux/ip.h>
#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <linux/syscalls.h>
#include <linux/if_vlan.h>
#include <net/tcp.h>

#ifdef CONFIG_OF
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#include <linux/of_net.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#endif

#include <mach/iproc_regs.h>

//#include <asm/system.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>

#include <epivers.h>
#include <bcmendian.h>
#include <bcmdefs.h>
#include <proto/ethernet.h>
#include <proto/vlan.h>
#include <proto/bcmip.h>
#include <bcmdevs.h>
#include <bcmenetmib.h>
#include <bcmgmacmib.h>
#include <bcmenetrxh.h>
#include <bcmenetphy.h>
#include <etioctl.h>
#include <bcmutils.h>
#include <pcicfg.h>
#include <et_dbg.h>
#include <hndsoc.h>
#include <bcmgmacrxh.h>
#include <etc.h>

/* to be cleaned and fixed */
/* to be cleaned Makefile */
#include <bcmnvram.h>
#include <siutils.h>
#include <hndcpu.h>
#include <sbchipc.h>
#include <hndchipc.h>
#include <trxhdr.h>
#include <shm.h>

#ifdef CONFIG_BCM_IPROC_GMAC_PREFETCH
#include <linux/prefetch.h>

#define	SKB_PREFETCH_LEN (128)
/* 30 rxhdr + 34 mac & ip */
#define	SKB_DATA_PREFETCH_LEN (96)
#endif /* CONFIG_BCM_IPROC_GMAC_PREFETCH */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 4, 5)
#error Linux version must be newer than 2.4.5
#endif	/* LINUX_VERSION_CODE <= KERNEL_VERSION(2, 4, 5) */

#define MIN_PACKET_SIZE		70		/* for gmac2 (&GMAC3?)                                    */
									/* if packet is less than 64 bytes, it will not tx        */
									/* if packet is less than 66 bytes, CRC is not generated) */
									/* this length is after brm tag is stripped off           */

#define	DATAHIWAT	        1000    /* data msg txq hiwat mark */

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36)
#define HAVE_NET_DEVICE_OPS     1
#define HAVE_NETDEV_PRIV        1
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36) */

#ifndef	HAVE_NETDEV_PRIV
#define	HAVE_NETDEV_PRIV
#define	netdev_priv(dev)        ((dev)->priv)
#define	ET_INFO(dev)            (et_info_t *)((dev)->priv)
#else
#define	ET_INFO(dev)            netdev_priv(dev)
#endif	/* HAVE_NETDEV_PRIV */

#ifdef GMAC_ALL_PASSIVE
#define ET_LIMIT_TXQ
#define ET_ALL_PASSIVE_ENAB(et)     (!(et)->all_dispatch_mode)

/* passive mode: 1: enable, 0: disable */
static int passivemode = 0;
module_param(passivemode, int, 0);
#else /* GMAC_ALL_PASSIVE */
#define ET_ALL_PASSIVE_ENAB(et)     0
#endif /* GMAC_ALL_PASSIVE */

#ifdef ET_LIMIT_TXQ
#define ET_TXQ_THRESH       0
static int et_txq_thresh = ET_TXQ_THRESH;
module_param(et_txq_thresh, int, 0);
#endif /* ET_LIMIT_TXQ */


/* In 2.6.20 kernels work functions get passed a pointer to the
 * struct work, so things will continue to work as long as the work
 * structure is the first component of the task structure.
 */
typedef struct et_task {
	struct work_struct work;
	void *context;
} et_task_t;

typedef struct et_info {
    etc_info_t          *etc;		/* pointer to common os-independent data */
    struct net_device   *dev;		/* backpoint to device */
    struct pci_dev      *pdev;		/* backpoint to pci_dev */
    void                *osh;		/* pointer to os handle */
    struct semaphore    sem;		/* use semaphore to allow sleep */
    spinlock_t          lock;		/* per-device perimeter lock */
    spinlock_t          txq_lock;	/* lock for txq protection */
    spinlock_t          tx_lock;	/* lock for tx protection */
    spinlock_t          isr_lock;	/* lock for irq reentrancy protection */
    struct sk_buff_head txq[NUMTXQ];/* send queue */
    void                *regsva;    /* opaque chip registers virtual address */
    struct timer_list   timer;      /* one second watchdog timer */
    bool                set;        /* indicate the timer is set or not */
    struct net_device_stats stats;  /* stat counter reporting structure */
    int                 events;	    /* bit channel between isr and dpc */
    struct et_info      *next;      /* pointer to next et_info_t in chain */
#ifdef GMAC_NAPI2_POLL
    struct napi_struct  napi_poll;
#endif  /* GMAC_NAPI2_POLL */
#ifndef GMAC_NAPI_POLL
    struct tasklet_struct   tasklet;/* dpc tasklet */
#endif /* GMAC_NAPI_POLL */
#ifdef GMAC_ALL_PASSIVE
    et_task_t           dpc_task;   /* work queue for rx dpc */
    et_task_t           txq_task;   /* work queue for tx frames */
    bool                all_dispatch_mode;  /* dispatch mode: tasklets or passive */
#endif /* GMAC_ALL_PASSIVE */
    bool                resched;           /* dpc was rescheduled */
#ifdef CONFIG_IPROC_2STAGE_RX
    bool                rxinisr;
#endif /* CONFIG_IPROC_2STAGE_RX */
} et_info_t;

#define ET_LOCK(et) \
do { \
	if (ET_ALL_PASSIVE_ENAB(et)) \
		down(&(et)->sem); \
	else \
		spin_lock_bh(&(et)->lock); \
} while (0)

#define ET_UNLOCK(et) \
do { \
	if (ET_ALL_PASSIVE_ENAB(et)) \
		up(&(et)->sem); \
	else \
		spin_unlock_bh(&(et)->lock); \
} while (0)

#define ET_TXQ_LOCK(et)         spin_lock_bh(&(et)->txq_lock)
#define ET_TXQ_UNLOCK(et)       spin_unlock_bh(&(et)->txq_lock)
#define ET_TX_LOCK(et)          spin_lock_bh(&(et)->tx_lock)
#define ET_TX_UNLOCK(et)        spin_unlock_bh(&(et)->tx_lock)
#define INT_LOCK(et, flags)     spin_lock_irqsave(&(et)->isr_lock, flags)
#define INT_UNLOCK(et, flags)   spin_unlock_irqrestore(&(et)->isr_lock, flags)

extern int nvram_env_gmac_name(int gmac, char *name);

#ifdef GMAC_RATE_LIMITING
static int et_rx_rate_limit = 0;
extern void etc_check_rate_limiting(etc_info_t *etc, void *pch);
#endif /* GMAC_RATE_LIMITING */

#if defined(CONFIG_IPROC_SDK_MGT_PORT_HANDOFF)
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2))
extern int gmac_has_mdio_access(void);
#endif /* (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2)) */
#endif /* defined(CONFIG_IPROC_SDK_MGT_PORT_HANDOFF) */

static int et_found = 0;
static et_info_t *et_list = NULL;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 37)
#define init_MUTEX(x) sema_init(x,1)
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 37) */

/* linux 2.4 doesn't have in_atomic */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
#define in_atomic() 0
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 37) */

/* Prototypes called by etc.c */
#ifdef CONFIG_BCM_GRO_ENABLE
void et_flush(void *dev_id);
#endif /* CONFIG_BCM_GRO_ENABLE */
void et_init(et_info_t *et, uint options);
void et_reset(et_info_t *et);
void et_up(et_info_t *et);
void et_down(et_info_t *et, int reset);
void et_intrson(et_info_t *et);
void et_dump(et_info_t *et, struct bcmstrbuf *b);
void et_link_up(et_info_t *et);
void et_link_down(et_info_t *et);
bool et_is_link_up(et_info_t *et);

/* Local prototypes */
static int iproc_gmac_init_module(void);
static void et_free(et_info_t *et);
static int et_open(struct net_device *dev);
static int et_close(struct net_device *dev);
static int et_start(struct sk_buff *skb, struct net_device *dev);
static int et_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd);
static struct net_device_stats *et_get_stats(struct net_device *dev);
static int et_set_mac_address(struct net_device *dev, void *addr);
static void et_set_multicast_list(struct net_device *dev);

static void et_sendnext(et_info_t *et);
static void _et_watchdog(struct net_device *data);
static void et_watchdog(ulong data);
#ifdef GMAC_ALL_PASSIVE
static void et_watchdog_task(et_task_t *task);
static void et_dpc_work(struct et_task *task);
static int et_schedule_task(et_info_t *et, void (*fn)(struct et_task *task), void *context);
static void et_txq_work(struct et_task *task);
#endif /* GMAC_ALL_PASSIVE */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
static irqreturn_t et_isr(int irq, void *dev_id);
#else
static irqreturn_t et_isr(int irq, void *dev_id, struct pt_regs *ptregs);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20) */
static int et_rxevent(osl_t *osh, et_info_t *et, struct chops *chops, void *ch, int quota);
#ifdef	GMAC_NAPI2_POLL
static int et_poll(struct napi_struct *napi, int budget);
#elif defined(GMAC_NAPI_POLL)
static int et_poll(struct net_device *dev, int *budget);
#else /* ! GMAC_NAPI_POLL */
static void et_dpc(ulong data);
#endif /* GMAC_NAPI_POLL */
static void et_error(et_info_t *et, struct sk_buff *skb, void *rxh);
static void et_sendup(et_info_t *et, struct sk_buff *skb);
static void et_dumpet(et_info_t *et, struct bcmstrbuf *b);
static int et_get_settings(struct net_device *dev, struct ethtool_cmd *ecmd);
static int et_set_settings(struct net_device *dev, struct ethtool_cmd *ecmd);
static void et_get_driver_info(struct net_device *dev, struct ethtool_drvinfo *info);

static int eth_mac_proc_create(struct net_device *dev);
#ifndef CONFIG_OF
static void eth_mac_proc_remove(void);
#else
static void eth_mac_proc_remove(struct net_device *dev);
#endif
static int iproc_gmac_drv_probe(struct platform_device*);
static int __exit iproc_gmac_drv_remove(struct platform_device*);
#if 0
static int iproc_gmac_drv_suspend(struct platform_device *pdev, pm_message_t state);
static int iproc_gmac_drv_resume(struct platform_device *pdev);
#else /* CONFIG_PM */
#define iproc_gmac_drv_suspend   NULL
#define iproc_gmac_drv_resume    NULL
#endif /* CONFIG_PM */

#define DISABLE_FA_BYPASS       0
#define ENABLE_FA_BYPASS        1

#if 0
static unsigned int gBypass = DISABLE_FA_BYPASS;
#endif

#ifdef BCMDBG
static uint32 msglevel = 0xdeadbeef;
module_param(msglevel, uint, 0644);
#endif /* BCMDBG */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
static const struct ethtool_ops et_ethtool_ops = {
    .get_settings = et_get_settings,
    .set_settings = et_set_settings,
    .get_drvinfo = et_get_driver_info,
};
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36) */

#ifdef HAVE_NET_DEVICE_OPS
static const struct net_device_ops et_netdev_ops = {
	.ndo_open = et_open,
	.ndo_stop = et_close,
	.ndo_start_xmit = et_start,
	.ndo_get_stats = et_get_stats,
	.ndo_set_mac_address = et_set_mac_address,
	.ndo_set_rx_mode = et_set_multicast_list,
	.ndo_do_ioctl = et_ioctl,
};
#endif /*HAVE_NET_DEVICE_OPS*/

#ifndef CONFIG_OF
static struct platform_driver gmac_pdrv[IPROC_MAX_GMAC_CORES] = {
    {
        .probe = iproc_gmac_drv_probe,
        .remove = __exit_p(iproc_gmac_drv_remove),
        .suspend = iproc_gmac_drv_suspend,
        .resume = iproc_gmac_drv_resume,
        .driver = {
            .name = "bcm-gmac0",
        },
    },
    {
        .probe = iproc_gmac_drv_probe,
        .remove = __exit_p(iproc_gmac_drv_remove),
        .suspend = iproc_gmac_drv_suspend,
        .resume = iproc_gmac_drv_resume,
        .driver = {
            .name = "bcm-gmac1",
        },
    },
    {
        .probe = iproc_gmac_drv_probe,
        .remove = __exit_p(iproc_gmac_drv_remove),
        .suspend = iproc_gmac_drv_suspend,
        .resume = iproc_gmac_drv_resume,
        .driver = {
            .name = "bcm-gmac2",
        },
    },
    {
        .probe = iproc_gmac_drv_probe,
        .remove = __exit_p(iproc_gmac_drv_remove),
        .suspend = iproc_gmac_drv_suspend,
        .resume = iproc_gmac_drv_resume,
        .driver = {
            .name = "bcm-gmac3",
        },
    }
};
#endif

int gmac_pdev_loaded[IPROC_NUM_GMACS];

/*****************************************************************************
*****************************************************************************/
static bool
et_ctf_pipeline_loopback(et_info_t *et)
{
	if (et->etc->unit == 3) {
		return true;
	} else {
		return false;
	}
}

#ifdef BCMDMASGLISTOSL
static int
et_bcmtag_len(et_info_t *et)
{
    return (et_ctf_pipeline_loopback(et)) ? 8 : 0;
}
#endif /* BCMDMASGLISTOSL */

static void
et_free(et_info_t *et)
{
	et_info_t **prev;
	osl_t *osh;

	ET_TRACE(("et: et_free\n"));

	if (et == NULL) {
		return;
    }
    
	if (et->dev && et->dev->irq) {
		free_irq(et->dev->irq, et);
	}

#ifdef GMAC_NAPI2_POLL
	napi_disable(&et->napi_poll);
	netif_napi_del(&et->napi_poll);
#endif /* GMAC_NAPI2_POLL */

	if (et->dev) {
		unregister_netdev(et->dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
		free_netdev(et->dev);
#else
		MFREE(et->osh, et->dev, sizeof(struct net_device));
#endif
		et->dev = NULL;
	}

	/* free common resources */
	if (et->etc) {
		etc_detach(et->etc);
		et->etc = NULL;
	}

	/* unregister_netdev() calls get_stats() which may read chip registers
	 * so we cannot unmap the chip registers until after calling unregister_netdev() .
	 */
	if (et->regsva) {
		iounmap((void *)et->regsva);
		et->regsva = NULL;
	}

	/* remove us from the global linked list */
	for (prev = &et_list; *prev; prev = &(*prev)->next) {
		if (*prev == et) {
			*prev = et->next;
			break;
		}
	}

	osh = et->osh;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36) 
	free_netdev(et->dev); 
	et->dev = NULL; 
#else 
	MFREE(et->osh, et, sizeof(et_info_t));
#endif

	if (MALLOCED(osh)) {
		ET_ERROR(("Memory leak of bytes %d\n", MALLOCED(osh)));
	}
	ASSERT(MALLOCED(osh) == 0);

	osl_detach(osh);
}

static int
et_open(struct net_device *dev)
{
	et_info_t *et = ET_INFO(dev);

	ET_TRACE(("et%d: et_open\n", et->etc->unit));

	et->etc->promisc = (dev->flags & IFF_PROMISC)? TRUE: FALSE;
	et->etc->allmulti = (dev->flags & IFF_ALLMULTI)? TRUE: et->etc->promisc;
#ifdef GMAC_RATE_LIMITING
	et->etc->rl_enabled = et_rx_rate_limit;
#endif /* GMAC_RATE_LIMITING */

	ET_LOCK(et);
	et_up(et);
	ET_UNLOCK(et);

	OLD_MOD_INC_USE_COUNT;

	return (0);
}

static int
et_close(struct net_device *dev)
{
	et_info_t *et = ET_INFO(dev);

	ET_TRACE(("et%d: et_close\n", et->etc->unit));

	et->etc->promisc = FALSE;
	et->etc->allmulti = FALSE;

	ET_LOCK(et);
	et_down(et, 1);
	ET_UNLOCK(et);

	OLD_MOD_DEC_USE_COUNT;

	return (0);
}

#if defined(BCMDMASGLISTOSL)
/*
 * Driver level checksum offload. This is being done so that we can advertise
 * checksum offload support to Linux.
 */
static void BCMFASTPATH_HOST
et_cso(et_info_t *et, struct sk_buff *skb)
{
	struct ethervlan_header *evh;
	uint8 *th = skb_transport_header(skb);
	uint16 thoff, eth_type, *check;
	uint8 prot;

	ASSERT(!PKTISCTF(et->osh, skb));

	evh = (struct ethervlan_header *)PKTDATA(et->osh, skb);
	eth_type = ((evh->vlan_type == HTON16(ETHER_TYPE_8021Q)) ?
	            evh->ether_type : evh->vlan_type);

	/* tcp/udp checksum calculation */
	thoff = (th - skb->data);
	if (eth_type == HTON16(ETHER_TYPE_IP)) {
		struct iphdr *ih = ip_hdr(skb);
		prot = ih->protocol;
		ASSERT((prot == IP_PROT_TCP) || (prot == IP_PROT_UDP));
		check = (uint16 *)(th + ((prot == IP_PROT_UDP) ?
			offsetof(struct udphdr, check) : offsetof(struct tcphdr, check)));
		*check = 0;
		skb->csum = skb_checksum(skb, thoff, skb->len - thoff, 0);
		*check = csum_tcpudp_magic(ih->saddr, ih->daddr,
		                           skb->len - thoff, prot, skb->csum);
	} else if (eth_type == HTON16(ETHER_TYPE_IPV6)) {
		struct ipv6hdr *ih = ipv6_hdr(skb);
		prot = IPV6_PROT(ih);
		ASSERT((prot == IP_PROT_TCP) || (prot == IP_PROT_UDP));
		check = (uint16 *)(th + ((prot == IP_PROT_UDP) ?
			offsetof(struct udphdr, check) : offsetof(struct tcphdr, check)));
		*check = 0;
		skb->csum = skb_checksum(skb, thoff, skb->len - thoff, 0);
		*check = csum_ipv6_magic(&ih->saddr, &ih->daddr,
		                         skb->len - thoff, prot, skb->csum);
	} else {
		return;
	}

	if ((*check == 0) && (prot == IP_PROT_UDP)) {
		*check = CSUM_MANGLED_0;
	}
}
#endif /* defined(BCMDMASGLISTOSL) */

/*
 * Yeah, queueing the packets on a tx queue instead of throwing them
 * directly into the descriptor ring in the case of dma is kinda lame,
 * but this results in a unified transmit path for both dma and pio
 * and localizes/simplifies the netif_*_queue semantics, too.
 */
static int BCMFASTPATH
et_start(struct sk_buff *skb, struct net_device *dev)
{
	et_info_t *et = ET_INFO(dev);
	uint32 q = 0;
#ifdef BCMDMASGLISTOSL
    bool sw_cksum = true;
	struct iphdr *iph = NULL;
#endif /* BCMDMASGLISTOSL */
#ifdef ET_LIMIT_TXQ
	int qlen;
#endif /* ET_LIMIT_TXQ */

#ifdef BCMDMASGLISTOSL
	if (!PKTSUMNEEDED(skb)) {
		sw_cksum = false;
    }
    
	/* can only update checksum once. */
	/* if checksum is updated later, don't do it here */
	iph = (struct iphdr *)skb->network_header;
	if (((skb->len + et_bcmtag_len(et)) < MIN_PACKET_SIZE) &&
		((iph->protocol == IPPROTO_TCP) || (iph->protocol == IPPROTO_UDP))) {
		sw_cksum = false;
	}

	if (sw_cksum) {
		et_cso(et, skb);
	}
#endif /* BCMDMASGLISTOSL */

	if (skb_is_nonlinear(skb)) {
		et->etc->txsgpkt++;
	}

	if (skb->len > et->etc->txmaxlen) {
		et->etc->txmaxlen = skb->len;
	}
	
	ET_TRACE(("et%d: et_start: len %d\n", et->etc->unit, skb->len));
	ET_LOG("et%d: et_start: len %d", et->etc->unit, skb->len);

	et->etc->txfrm++;
#ifdef ET_LIMIT_TXQ
#ifndef CONFIG_BCM_IPROC_GMAC_LOCK_OPT
	ET_TXQ_LOCK(et);
#endif /* CONFIG_BCM_IPROC_GMAC_LOCK_OPT */
	qlen = skb_queue_len(&et->txq[q]);
#ifndef CONFIG_BCM_IPROC_GMAC_LOCK_OPT
	ET_TXQ_UNLOCK(et);
#endif /* CONFIG_BCM_IPROC_GMAC_LOCK_OPT */
	if (qlen > et->etc->txqlen) {
		et->etc->txqlen = qlen;
	}
	
	if (et_txq_thresh && (qlen >= et_txq_thresh)) {
		//PKTCFREE(et->osh, skb, TRUE);
		//return 0;
		et->etc->txfrmdropped++;
		/* schedule work */
#ifdef GMAC_ALL_PASSIVE
		if (ET_ALL_PASSIVE_ENAB(et)) {
#ifdef CONFIG_BCM_IPROC_GMAC_TXONCPU1
			schedule_work_on(1, &et->txq_task.work);
#else
			schedule_work(&et->txq_task.work);
#endif
		}
#endif /* GMAC_ALL_PASSIVE */
		return NETDEV_TX_BUSY;
	}
#endif /* ET_LIMIT_TXQ */

	/* put it on the tx queue and call sendnext */
	ET_TXQ_LOCK(et);
	__skb_queue_tail(&et->txq[q], skb);
	et->etc->txq_state |= (1 << q);
	ET_TXQ_UNLOCK(et);

	if (!ET_ALL_PASSIVE_ENAB(et)) {
		ET_LOCK(et);
		et_sendnext(et);
		ET_UNLOCK(et);
	}
#ifdef GMAC_ALL_PASSIVE
	else {
#ifdef CONFIG_BCM_IPROC_GMAC_TXONCPU1
		schedule_work_on(1, &et->txq_task.work);
#else
		schedule_work(&et->txq_task.work);
#endif /* CONFIG_BCM_IPROC_GMAC_TXONCPU1 */
    }
#endif /* GMAC_ALL_PASSIVE */

	ET_LOG("et%d: et_start ret\n", et->etc->unit, 0);

	return (0);
}

static void BCMFASTPATH
et_sendnext(et_info_t *et)
{
	etc_info_t *etc;
	struct sk_buff *skb;
	void *p, *n;
	uint32 priq = TX_Q0;
#ifdef DMA
	uint32 txavail;
#endif
#ifdef DBG_PRINT_PKT
	int	tagoff, idx;
#endif /* DBG_PRINT_PKT */

	etc = et->etc;

	ET_TRACE(("et%d: et_sendnext\n", etc->unit));
	ET_LOG("et%d: et_sendnext", etc->unit, 0);

	/* dequeue packets from highest priority queue and send */
	while (1) {
		ET_TXQ_LOCK(et);

		if (etc->txq_state == 0)
			break;

		priq = etc_priq(etc->txq_state);

		ET_TRACE(("et%d: txq_state %x priq %d txavail %d\n",
		          etc->unit, etc->txq_state, priq,
		          *(uint *)etc->txavail[priq]));

		if ((skb = skb_peek(&et->txq[priq])) == NULL) {
			etc->txq_state &= ~(1 << priq);
			ET_TXQ_UNLOCK(et);
			continue;
		}

#ifdef DMA
		/* current highest priority dma queue is full */
		txavail = *(uint *)(etc->txavail[priq]);
		if ((PKTISCHAINED(skb) && (txavail < PKTCCNT(skb))) || (txavail == 0))
#else /* DMA */
		if (etc->pioactive != NULL)
#endif /* DMA */
		{
			etc->txdmafull++;
			break;
		}

		skb = __skb_dequeue(&et->txq[priq]);

		ET_TXQ_UNLOCK(et);
		ET_PRHDR("tx", (struct ether_header *)skb->data, skb->len, etc->unit);
		ET_PRPKT("txpkt", skb->data, skb->len, etc->unit);

#ifdef DBG_PRINT_PKT
        tagoff = 16;
        printf("et%d: txpkt len(0x%x) tag:0x%02x%02x%02x%02x\n", etc->unit, skb->len,
        		skb->data[tagoff], skb->data[tagoff+1], skb->data[tagoff+2], skb->data[tagoff+3]);
        
        printk("et%d: %s len(0x%x) txpkt:", etc->unit, __FUNCTION__, skb->len);
        for (idx = 0; idx < skb->len; idx++) {
            if ((idx % 16) == 0) {
                printk("\n");
            }
            printk("%02x ", skb->data[idx]);
        }
        printk("\n");
#endif /* DBG_PRINT_PKT */

		/* convert the packet. */
		p = PKTFRMNATIVE(etc->osh, skb);
		ASSERT(p != NULL);

		ET_TRACE(("%s: sdu %p chained %d chain sz %d next %p\n",
		          __FUNCTION__, p, PKTISCHAINED(p), PKTCCNT(p), PKTCLINK(p)));

        ET_TX_LOCK(et);
		FOREACH_CHAINED_PKT(p, n) {
			/* replicate vlan header contents from curr frame */
			if (n != NULL) {
				uint8 *n_evh;
				n_evh = PKTPUSH(et->osh, n, VLAN_TAG_LEN);
				*(struct ethervlan_header *)n_evh =
				*(struct ethervlan_header *)PKTDATA(et->osh, p);
			}
			(*etc->chops->tx)(etc->ch, p);
#ifdef CONFIG_BCM_IPROC_GMAC_LOCK_OPT
            ET_LOCK(et);
#endif /* CONFIG_BCM_IPROC_GMAC_LOCK_OPT */
			etc->txframe++;
			etc->txbyte += PKTLEN(et->osh, p);
#ifdef CONFIG_BCM_IPROC_GMAC_LOCK_OPT
            ET_UNLOCK(et);
#endif /* CONFIG_BCM_IPROC_GMAC_LOCK_OPT */
		}
        ET_TX_UNLOCK(et);
	}

	/* no flow control when qos is enabled */
	if (!et->etc->qos) {
		/* stop the queue whenever txq fills */
		if ((skb_queue_len(&et->txq[TX_Q0]) > DATAHIWAT) && !netif_queue_stopped(et->dev)) {
			et->etc->txqstop++;
			netif_stop_queue(et->dev);
		} else if (netif_queue_stopped(et->dev) &&
		         (skb_queue_len(&et->txq[TX_Q0]) < (DATAHIWAT/2))) {
			netif_wake_queue(et->dev);
		}
	} else {
		/* drop the frame if corresponding prec txq len exceeds hiwat
		 * when qos is enabled.
		 */
		if ((priq != TC_NONE) && (skb_queue_len(&et->txq[priq]) > DATAHIWAT)) {
			skb = __skb_dequeue(&et->txq[priq]);
			PKTCFREE(et->osh, skb, TRUE);
			ET_ERROR(("et%d: %s: txqlen %d\n", et->etc->unit,
			          __FUNCTION__, skb_queue_len(&et->txq[priq])));
		}
	}

	ET_TXQ_UNLOCK(et);
}

#ifdef CONFIG_BCM_GRO_ENABLE
#ifdef CONFIG_ET_MODULE
extern int et_flushptr_ready;
extern void (*et_flushptr)(void *dev_id);
#endif /* CONFIG_ET_MODULE */

void 
et_flush(void *dev_id)
{
	et_info_t *et;
	struct chops *chops;
	void *ch;
	osl_t *osh;

	et = (et_info_t *)dev_id;
	chops = et->etc->chops;
	ch = et->etc->ch;
	osh = et->etc->osh;

	/* guard against shared interrupts */
	if (!et->etc->up) {
		ET_TRACE(("et%d: et_isr: not up\n", et->etc->unit));
		return;
	}
    if (!et->napi_poll.gro_list) {
        return;
    }
    
	/* disable interrupts */
	(*chops->intrsoff)(ch);

    et->resched = TRUE;

	napi_gro_flush(&et->napi_poll);

	/* enable interrupts now */
	(*chops->intrson)(ch);
}
#endif /* CONFIG_BCM_GRO_ENABLE */

void
et_init(et_info_t *et, uint options)
{
	ET_TRACE(("et%d: et_init\n", et->etc->unit));
	ET_LOG("et%d: et_init", et->etc->unit, 0);

	etc_init(et->etc, options);

#ifdef CONFIG_BCM_GRO_ENABLE
#ifdef CONFIG_ET_MODULE
	et_flushptr = &et_flush;
	et_flushptr_ready = 1;
#endif /* CONFIG_ET_MODULE */
#endif /* CONFIG_BCM_GRO_ENABLE */

#if defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_HR2) || defined(CONFIG_MACH_KT2)
	netif_carrier_off(et->dev);
#endif /* defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_HR2) || defined(CONFIG_MACH_KT2) */
}


void
et_reset(et_info_t *et)
{
	ET_TRACE(("et%d: et_reset\n", et->etc->unit));

	etc_reset(et->etc);

	/* zap any pending dpc interrupt bits */
	et->events = 0;

	/* dpc will not be rescheduled */
	et->resched = 0;
}

void
et_up(et_info_t *et)
{
	etc_info_t *etc;

	etc = et->etc;

	if (etc->up) {
		return;
	}

	ET_TRACE(("et%d: et_up\n", etc->unit));

	etc_up(etc);

#if defined(CONFIG_IPROC_SDK_MGT_PORT_HANDOFF)
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2))
	if (et->set) { 	
		/* This will happen if running watchdog to monitor mdio bus */
		/* and port not up */
		del_timer(&et->timer);
		et->set = FALSE;
	}
#endif /* (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2)) */
#endif /* defined(CONFIG_IPROC_SDK_MGT_PORT_HANDOFF) */
	
	/* schedule one second watchdog timer */
	et->timer.expires = jiffies + HZ;
	add_timer(&et->timer);
	et->set=TRUE;

	netif_start_queue(et->dev);
}

void
et_down(et_info_t *et, int reset)
{
	etc_info_t *etc;
	struct sk_buff *skb;
	int32 i;
	bool stoptmr = TRUE;

	etc = et->etc;

	ET_TRACE(("et%d: et_down\n", etc->unit));

	netif_down(et->dev);
	netif_stop_queue(et->dev);

#ifdef CONFIG_IPROC_SDK_MGT_PORT_HANDOFF
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2))
	if (gmac_has_mdio_access()) {
		/* we have mdio bus don't stop timer so we can continue to monitor */
		stoptmr = FALSE;
	}
#endif /* (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2)) */
#endif /* CONFIG_IPROC_SDK_MGT_PORT_HANDOFF */

	if ( stoptmr ) {
		/* stop watchdog timer */
		del_timer(&et->timer);
		et->set = FALSE;
	}

#ifdef GMAC_RATE_LIMITING
	/* stop ratelimiting timer */
	del_timer(&et->etc->rl_timer);
	et->etc->rl_set = FALSE;
#endif /* GMAC_RATE_LIMITING */

	etc_down(etc, reset);

	/* flush the txq(s) */
	for (i = 0; i < NUMTXQ; i++) {
		while ((skb = skb_dequeue(&et->txq[i]))) {
			PKTFREE(etc->osh, skb, TRUE);
		}
	}

#if !defined(GMAC_NAPI_POLL) && !defined(GMAC_NAPI2_POLL)
	/* kill dpc */
	ET_UNLOCK(et);
	tasklet_kill(&et->tasklet);
	ET_LOCK(et);
#endif /* GMAC_NAPI_POLL */
}

/*
 * These are interrupt on/off entry points. Disable interrupts
 * during interrupt state transition.
 */
void
et_intrson(et_info_t *et)
{
	unsigned long flags;
	INT_LOCK(et, flags);
	(*et->etc->chops->intrson)(et->etc->ch);
	INT_UNLOCK(et, flags);
}

static void
_et_watchdog(struct net_device *dev)
{
	et_info_t *et;

	et = ET_INFO(dev);

	ET_LOCK(et);

	etc_watchdog(et->etc);

	if (et->set) {
		/* reschedule one second watchdog timer */
		et->timer.expires = jiffies + HZ;
		add_timer(&et->timer);
	}
#if defined(CONFIG_IPROC_SDK_MGT_PORT_HANDOFF)
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2))
	/* this in case port when up then down before we released mdio */
	else if (gmac_has_mdio_access()) {
		/* interface not up but we have mdio bus */
		/* reschedule one second watchdog timer */
		et->timer.expires = jiffies + HZ;
		add_timer(&et->timer);
		et->set = TRUE;
	}
#endif /* (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2)) */
#endif /* defined(CONFIG_IPROC_SDK_MGT_PORT_HANDOFF) */

	ET_UNLOCK(et);
}

#ifdef GMAC_ALL_PASSIVE
/* Schedule a completion handler to run at safe time */
static int
et_schedule_task(et_info_t *et, void (*fn)(struct et_task *task), void *context)
{
	et_task_t *task;

	ET_TRACE(("et%d: et_schedule_task\n", et->etc->unit));

	if (!(task = MALLOC(et->osh, sizeof(et_task_t)))) {
		ET_ERROR(("et%d: et_schedule_task: out of memory, malloced %d bytes\n",
		          et->etc->unit, MALLOCED(et->osh)));
		return -ENOMEM;
	}

	MY_INIT_WORK(&task->work, (work_func_t)fn);
	task->context = context;

	if (!schedule_work(&task->work)) {
		ET_ERROR(("et%d: schedule_work() failed\n", et->etc->unit));
		MFREE(et->osh, task, sizeof(et_task_t));
		return -ENOMEM;
	}

	return 0;
}

static void BCMFASTPATH
et_txq_work(struct et_task *task)
{
	et_info_t *et = (et_info_t *)task->context;

#ifndef CONFIG_BCM_IPROC_GMAC_LOCK_OPT
	ET_LOCK(et);
#endif /* !CONFIG_BCM_IPROC_GMAC_LOCK_OPT */ 

	et_sendnext(et);
	
#ifndef CONFIG_BCM_IPROC_GMAC_LOCK_OPT
	ET_UNLOCK(et);
#endif /* !CONFIG_BCM_IPROC_GMAC_LOCK_OPT */ 
	return;
}

static void
et_watchdog_task(et_task_t *task)
{
	et_info_t *et = ET_INFO((struct net_device *)task->context);

	_et_watchdog((struct net_device *)task->context);
	MFREE(et->osh, task, sizeof(et_task_t));
}
#endif /* GMAC_ALL_PASSIVE */

static void
et_watchdog(ulong data)
{
	struct net_device *dev = (struct net_device *)data;

#ifdef GMAC_ALL_PASSIVE
	et_info_t *et = ET_INFO(dev);
#endif /* GMAC_ALL_PASSIVE */

	if (!ET_ALL_PASSIVE_ENAB(et)) {
		_et_watchdog(dev);
    }
#ifdef GMAC_ALL_PASSIVE
	else {
		et_schedule_task(et, et_watchdog_task, dev);
    }
#endif /* GMAC_ALL_PASSIVE */
}

/* Rate limiting */
#ifdef GMAC_RATE_LIMITING
static void et_release_congestion(ulong data) 
{
	struct net_device *dev = (struct net_device *)data;
	et_info_t *et = ET_INFO(dev);

	if (!et) {
		return;
	}
	
	if (et->etc->rl_stopping_broadcasts) {
		et->etc->rl_stopping_broadcasts = 0;
		/* Clear the number of dropped broadcast packets */
		et->etc->rl_dropped_bc_packets = 0;
	}
	if (et->etc->rl_stopping_all_packets) {
		et->etc->rl_stopping_all_packets = 0;
		et->etc->rl_dropped_all_packets = 0;
	}
}
#endif /* GMAC_RATE_LIMITING */



static int
et_get_settings(struct net_device *dev, struct ethtool_cmd *ecmd)
{
    et_info_t *et = ET_INFO(dev);

    ecmd->supported = (SUPPORTED_10baseT_Half | SUPPORTED_10baseT_Full |
                       SUPPORTED_100baseT_Half | SUPPORTED_100baseT_Full |
                       SUPPORTED_Autoneg | SUPPORTED_TP);
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2))
    ecmd->supported |= SUPPORTED_1000baseT_Full | SUPPORTED_Pause;
#endif
#if defined(CONFIG_MACH_HR2)
    ecmd->supported |= SUPPORTED_Pause;
#endif

    ecmd->advertising = ADVERTISED_TP;
    ecmd->advertising |= (et->etc->advertise & ADV_10HALF) ?
	        ADVERTISED_10baseT_Half : 0;
    ecmd->advertising |= (et->etc->advertise & ADV_10FULL) ?
	        ADVERTISED_10baseT_Full : 0;
    ecmd->advertising |= (et->etc->advertise & ADV_100HALF) ?
	        ADVERTISED_100baseT_Half : 0;
    ecmd->advertising |= (et->etc->advertise & ADV_100FULL) ?
	        ADVERTISED_100baseT_Full : 0;
    ecmd->advertising |= (et->etc->advertise2 & ADV_1000FULL) ?
	        ADVERTISED_1000baseT_Full : 0;
    ecmd->advertising |= (et->etc->advertise2 & ADV_1000HALF) ?
	        ADVERTISED_1000baseT_Half : 0;
    ecmd->advertising |= (et->etc->forcespeed == ET_AUTO) ?
	        ADVERTISED_Autoneg : 0;
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_HR2))
    ecmd->advertising |= ADVERTISED_Pause;
#endif
    if (et->etc->linkstate) {
        ecmd->speed = (et->etc->speed == 1000) ? SPEED_1000 :
		               ((et->etc->speed == 100) ? SPEED_100 : SPEED_10);
        ecmd->duplex = (et->etc->duplex == 1) ? DUPLEX_FULL : DUPLEX_HALF;
    } else {
        ecmd->speed = 0;
        ecmd->duplex = 0;
    }
    ecmd->port = PORT_TP;
    ecmd->phy_address = et->etc->phyaddr;
    ecmd->transceiver = XCVR_INTERNAL;
    ecmd->autoneg = (et->etc->forcespeed == ET_AUTO) ? AUTONEG_ENABLE : AUTONEG_DISABLE;
    ecmd->maxtxpkt = 0;
    ecmd->maxrxpkt = 0;

    return 0;
}

static int
et_set_settings(struct net_device *dev, struct ethtool_cmd *ecmd)
{
	int speed[2];

	et_info_t *et = ET_INFO(dev);

    if (!capable(CAP_NET_ADMIN))
        return (-EPERM);

    if (ecmd->autoneg == AUTONEG_ENABLE) {
        speed[0] = ET_AUTO;
        speed[1] = ecmd->advertising;
    } else if (ecmd->speed == SPEED_10 && ecmd->duplex == DUPLEX_HALF) {
		speed[0] = ET_10HALF;
	} else if (ecmd->speed == SPEED_10 && ecmd->duplex == DUPLEX_FULL) {
		speed[0] = ET_10FULL;
	} else if (ecmd->speed == SPEED_100 && ecmd->duplex == DUPLEX_HALF) {
		speed[0] = ET_100HALF;
	} else if (ecmd->speed == SPEED_100 && ecmd->duplex == DUPLEX_FULL) {
		speed[0] = ET_100FULL;
	} else if (ecmd->speed == SPEED_1000 && ecmd->duplex == DUPLEX_FULL) {
		speed[0] = ET_1000FULL;
	} else {
		return (-EINVAL);
    }
    
	return etc_ioctl(et->etc, ETCSPEED, speed);
}

static void
et_get_driver_info(struct net_device *dev, struct ethtool_drvinfo *info)
{
	et_info_t *et = ET_INFO(dev);
	bzero(info, sizeof(struct ethtool_drvinfo));
	info->cmd = ETHTOOL_GDRVINFO;
	sprintf(info->driver, "et%d", et->etc->unit);
	strncpy(info->version, EPI_VERSION_STR, sizeof(info->version));
	info->version[(sizeof(info->version))-1] = '\0';
}

#ifdef SIOCETHTOOL
static int
et_ethtool(et_info_t *et, struct ethtool_cmd *ecmd)
{
	int ret = 0;

	ET_LOCK(et);

    switch (ecmd->cmd) {
    case ETHTOOL_GSET:
        ret = et_get_settings(et->dev, ecmd);
        break;
    case ETHTOOL_SSET:
        ret = et_set_settings(et->dev, ecmd);
        break;
    case ETHTOOL_GDRVINFO:
        et_get_driver_info(et->dev, (struct ethtool_drvinfo *)ecmd);
        break;
    default:
        ret = -EINVAL;
        break;
    }

	ET_UNLOCK(et);

	return (ret);
}
#endif /* SIOCETHTOOL */

static int
et_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	et_info_t *et;
	int error;
	char *buf;
	int size, ethtoolcmd;
	bool get = 0, set;
	et_var_t *var = NULL;
	void *buffer = NULL;

	et = ET_INFO(dev);

	ET_TRACE(("et%d: et_ioctl: cmd 0x%x\n", et->etc->unit, cmd));

	switch (cmd) {
#ifdef SIOCETHTOOL
	case SIOCETHTOOL:
		if (copy_from_user(&ethtoolcmd, ifr->ifr_data, sizeof(uint32)))
			return (-EFAULT);

		if (ethtoolcmd == ETHTOOL_GDRVINFO)
			size = sizeof(struct ethtool_drvinfo);
		else
			size = sizeof(struct ethtool_cmd);
		get = TRUE; set = TRUE;
		break;
#endif /* SIOCETHTOOL */
	case SIOCGETCDUMP:
		size = IOCBUFSZ;
		get = TRUE; set = FALSE;
		break;
	case SIOCGETCPHYRD:
	case SIOCGETCPHYRD2:
	case SIOCGETCROBORD:
		size = sizeof(int) * 2;
		get = TRUE; set = TRUE;
		break;
	case SIOCSETCSPEED:
	case SIOCSETCPHYWR:
	case SIOCSETCPHYWR2:
	case SIOCSETCROBOWR:
		size = sizeof(int) * 2;
		get = FALSE; set = TRUE;
		break;
	case SIOCSETGETVAR:
		size = sizeof(et_var_t);
		set = TRUE;
		break;
	default:
		size = sizeof(int);
		get = FALSE; set = TRUE;
		break;
	}

	if ((buf = MALLOC(et->osh, size)) == NULL) {
		ET_ERROR(("et: et_ioctl: out of memory, malloced %d bytes\n", MALLOCED(et->osh)));
		return (-ENOMEM);
	}

	if (set && copy_from_user(buf, ifr->ifr_data, size)) {
		MFREE(et->osh, buf, size);
		return (-EFAULT);
	}

	if (cmd == SIOCSETGETVAR) {
		var = (et_var_t *)buf;
		if (var->buf) {
			if (!var->set)
				get = TRUE;

			if (!(buffer = (void *) MALLOC(et->osh, var->len))) {
				ET_ERROR(("et: et_ioctl: out of memory, malloced %d bytes\n",
					MALLOCED(et->osh)));
				MFREE(et->osh, buf, size);
				return (-ENOMEM);
			}

			if (copy_from_user(buffer, var->buf, var->len)) {
				MFREE(et->osh, buffer, var->len);
				MFREE(et->osh, buf, size);
				return (-EFAULT);
			}
		}
	}

	switch (cmd) {
#ifdef SIOCETHTOOL
	case SIOCETHTOOL:
		error = et_ethtool(et, (struct ethtool_cmd *)buf);
		break;
#endif /* SIOCETHTOOL */
	case SIOCSETGETVAR:
		ET_LOCK(et);
		error = etc_iovar(et->etc, var->cmd, var->set, buffer);
		ET_UNLOCK(et);
		if (!error && get) {
			error = copy_to_user(var->buf, buffer, var->len);
        }
        
		if (buffer) {
			MFREE(et->osh, buffer, var->len);
		}
		break;
	default:
		ET_LOCK(et);
		error = etc_ioctl(et->etc, cmd - SIOCSETCUP, buf) ? -EINVAL : 0;
		ET_UNLOCK(et);
		break;
	}

	if (!error && get) {
		error = copy_to_user(ifr->ifr_data, buf, size);
    }
    
	MFREE(et->osh, buf, size);

	return (error);
}

static struct net_device_stats *
et_get_stats(struct net_device *dev)
{
	et_info_t *et;
	etc_info_t *etc;
	struct net_device_stats *stats;
	int locked = 0;

	et = ET_INFO(dev);

	ET_TRACE(("et%d: et_get_stats\n", et->etc->unit));

	if (!in_atomic()) {
		locked = 1;
		ET_LOCK(et);
	}

	etc = et->etc;
	stats = &et->stats;
	bzero(stats, sizeof(struct net_device_stats));

	/* refresh stats */
	if (et->etc->up) {
		(*etc->chops->statsupd)(etc->ch);
    }
    
	/* SWAG */
	stats->rx_packets = etc->rxframe;
	stats->tx_packets = etc->txframe;
	stats->rx_bytes = etc->rxbyte;
	stats->tx_bytes = etc->txbyte;
	stats->rx_errors = etc->rxerror;
	stats->tx_errors = etc->txerror;

	if (ET_GMAC(etc)) {
		gmacmib_t *mib;

		mib = etc->mib;
		stats->collisions = mib->tx_total_cols;
		stats->rx_length_errors = (mib->rx_oversize_pkts + mib->rx_undersize);
		stats->rx_crc_errors = mib->rx_crc_errs;
		stats->rx_frame_errors = mib->rx_align_errs;
		stats->rx_missed_errors = mib->rx_missed_pkts;
	} else {
		bcmenetmib_t *mib;

		mib = etc->mib;
		stats->collisions = mib->tx_total_cols;
		stats->rx_length_errors = (mib->rx_oversize_pkts + mib->rx_undersize);
		stats->rx_crc_errors = mib->rx_crc_errs;
		stats->rx_frame_errors = mib->rx_align_errs;
		stats->rx_missed_errors = mib->rx_missed_pkts;

	}

	stats->rx_fifo_errors = etc->rxoflo;
	stats->rx_over_errors = etc->rxoflo;
	stats->tx_fifo_errors = etc->txuflo;

	if (locked) {
		ET_UNLOCK(et);
    }
    
	return (stats);
}

static int
et_set_mac_address(struct net_device *dev, void *addr)
{
	et_info_t *et;
	struct sockaddr *sa = (struct sockaddr *) addr;

	et = ET_INFO(dev);
	ET_TRACE(("et%d: et_set_mac_address\n", et->etc->unit));

	if (et->etc->up) {
		return -EBUSY;
    }
    
	bcopy(sa->sa_data, dev->dev_addr, ETHER_ADDR_LEN);
	bcopy(dev->dev_addr, &et->etc->cur_etheraddr, ETHER_ADDR_LEN);

	return 0;
}

static void
et_set_multicast_list(struct net_device *dev)
{
	et_info_t *et;
	etc_info_t *etc;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)
	struct dev_mc_list *mclist;
#else
	struct netdev_hw_addr *ha ;
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) */
	int i;
	int locked = 0;

	et = ET_INFO(dev);
	etc = et->etc;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)
	mclist = NULL ;		/* fend off warnings */
#else
	ha = NULL ;
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) */

	ET_TRACE(("et%d: et_set_multicast_list\n", etc->unit));

	if (!in_atomic()) {
		locked = 1;
		ET_LOCK(et);
	}

	if (etc->up) {
		etc->promisc = (dev->flags & IFF_PROMISC)? TRUE: FALSE;
		etc->allmulti = (dev->flags & IFF_ALLMULTI)? TRUE: etc->promisc;

		/* copy the list of multicasts into our private table */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)
		for (i = 0, mclist = dev->mc_list; mclist && (i < dev->mc_count);
			i++, mclist = mclist->next) {
			if (i >= MAXMULTILIST) {
				etc->allmulti = TRUE;
				i = 0;
				break;
			}
			etc->multicast[i] = *((struct ether_addr *)mclist->dmi_addr);
		}
#else	/* >= 2.6.36 */
		i = 0;
		netdev_for_each_mc_addr(ha, dev) {
			i ++;
			if (i >= MAXMULTILIST) {
				etc->allmulti = TRUE;
				i = 0;
				break;
			}
			etc->multicast[i] = *((struct ether_addr *)ha->addr);
		} /* for each ha */
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) */
		etc->nmulticast = i;

		/* LR: partial re-init, DMA is already initialized */
		et_init(et, ET_INIT_INTRON);
	}

	if (locked) {
		ET_UNLOCK(et);
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
static irqreturn_t BCMFASTPATH
et_isr(int irq, void *dev_id)
#else
static irqreturn_t BCMFASTPATH
et_isr(int irq, void *dev_id, struct pt_regs *ptregs)
#endif
{
	et_info_t *et;
	struct chops *chops;
	void *ch;
	uint events = 0;
	osl_t *osh;

	et = (et_info_t *)dev_id;
	chops = et->etc->chops;
	ch = et->etc->ch;
	osh = et->etc->osh;

	/* guard against shared interrupts */
	if (!et->etc->up) {
		ET_TRACE(("et%d: et_isr: not up\n", et->etc->unit));
		goto done;
	}

	/* get interrupt condition bits */
	events = (*chops->getintrevents)(ch, TRUE);

	/* not for us */
	if (!(events & INTR_NEW)) {
		goto done;
	}

	ET_TRACE(("et%d: et_isr: events 0x%x\n", et->etc->unit, events));
	ET_LOG("et%d: et_isr: events 0x%x", et->etc->unit, events);

#ifdef CONFIG_IPROC_2STAGE_RX
	if (events & INTR_RX) {
		et->rxinisr = true;
		/* process a few RX interrupts */
		et_rxevent(osh, et, chops, ch, 1);

		et->rxinisr = false;
		/* get interrupt condition bits */
		events = (*chops->getintrevents)(ch, TRUE);
		et->resched = FALSE;

		/* not for us */
		if (!(events & INTR_NEW)) {
			goto done;
		}
	}
#endif /* CONFIG_IPROC_2STAGE_RX */

	/* disable interrupts */
	(*chops->intrsoff)(ch);

	/* save intstatus bits */
	ASSERT(et->events == 0);
	et->events = events;

	ASSERT(et->resched == FALSE);

#ifdef GMAC_NAPI2_POLL
	napi_schedule(&et->napi_poll);
#elif defined(GMAC_NAPI_POLL)
	/* allow the device to be added to the cpu polling list if we are up */
	if (netif_rx_schedule_prep(et->dev)) {
		/* tell the network core that we have packets to send up */
		__netif_rx_schedule(et->dev);
	} else {
		ET_ERROR(("et%d: et_isr: intr while in poll!\n",
		          et->etc->unit));
		(*chops->intrson)(ch);
	}
#else /* ! GMAC_NAPI_POLL && ! GMAC_NAPI2_POLL */
	/* schedule dpc */
#ifdef GMAC_ALL_PASSIVE
	if (ET_ALL_PASSIVE_ENAB(et)) {
		schedule_work(&et->dpc_task.work);
	} else
#endif /* GMAC_ALL_PASSIVE */
    {
	    tasklet_schedule(&et->tasklet);
	}
#endif /* GMAC_NAPI_POLL */

done:
	ET_LOG("et%d: et_isr ret", et->etc->unit, 0);

	return IRQ_RETVAL(events & INTR_NEW);
}

static inline int
et_rxevent(osl_t *osh, et_info_t *et, struct chops *chops, void *ch, int quota)
{
	uint processed = 0;
	void *p, *h = NULL, *t = NULL;
	struct sk_buff *skb;

#ifdef GMAC_RATE_LIMITING
	/* rate limiting */
	if (et->etc->rl_enabled) {		
		etc_check_rate_limiting(et->etc, ch);
	}
#endif /* GMAC_RATE_LIMITING */

	/* read the buffers first */
	while ((p = (*chops->rx)(ch))) {
		PKTSETLINK(p, NULL);
		if (t == NULL) {
			h = t = p;
		} else {
			PKTSETLINK(t, p);
			t = p;
		}

		/* we reached quota already */
		if (++processed >= quota) {
			/* reschedule et_dpc()/et_poll() */
			et->resched = TRUE;
			et->etc->rxquota++;
			break;
		}
	}

	/* prefetch the headers */
	if (h != NULL) {
#ifdef CONFIG_BCM_IPROC_GMAC_PREFETCH
        prefetch_range(PKTDATA(osh, h), SKB_DATA_PREFETCH_LEN);
#else
		ETPREFHDRS(PKTDATA(osh, h), PREFSZ);
#endif
    }
    
	/* post more rx bufs */
	(*chops->rxfill)(ch);

	while ((p = h) != NULL) {
		h = PKTLINK(h);
		PKTSETLINK(p, NULL);

		/* prefetch the headers */
		if (h != NULL) {
#ifdef CONFIG_BCM_IPROC_GMAC_PREFETCH
            prefetch_range(PKTDATA(osh, h), SKB_DATA_PREFETCH_LEN);
#else
            ETPREFHDRS(PKTDATA(osh, h), PREFSZ);
#endif
        }
                    
		skb = PKTTONATIVE(osh, p);
		et->etc->unchained++;
		et_sendup(et, skb);
	}

	return (processed);
}

#if defined(GMAC_NAPI2_POLL)
static int BCMFASTPATH
et_poll(struct napi_struct *napi, int budget)
{
	int quota = budget;
	struct net_device *dev = napi->dev;
	et_info_t *et = ET_INFO(dev);

#elif defined(GMAC_NAPI_POLL)
static int BCMFASTPATH
et_poll(struct net_device *dev, int *budget)
{
	int quota = min(RXBND, *budget);
	et_info_t *et = ET_INFO(dev);
#else /* GMAC_NAPI_POLL */
static void BCMFASTPATH
et_dpc(ulong data)
{
	et_info_t *et = (et_info_t *)data;
	int quota = RXBND;
#endif /* GMAC_NAPI_POLL */
	struct chops *chops;
	void *ch;
	osl_t *osh;
	uint nrx = 0;

	chops = et->etc->chops;
	ch = et->etc->ch;
	osh = et->etc->osh;

	ET_TRACE(("et%d: et_dpc: events 0x%x\n", et->etc->unit, et->events));
	ET_LOG("et%d: et_dpc: events 0x%x", et->etc->unit, et->events);

#if !defined(GMAC_NAPI_POLL) && !defined(GMAC_NAPI2_POLL)
	ET_LOCK(et);
#endif /* ! NAPIx_POLL */

	if (!et->etc->up) {
		goto done;
	}

	/* get interrupt condition bits again when dpc was rescheduled */
	if (et->resched) {
		et->events = (*chops->getintrevents)(ch, FALSE);
		et->resched = FALSE;
	}

	if (et->events & INTR_RX) {
		nrx = et_rxevent(osh, et, chops, ch, quota);
    }
    
	if (et->events & INTR_TX) {
		(*chops->txreclaim)(ch, FALSE);
	}

	(*chops->rxfill)(ch);

	/* handle error conditions, if reset required leave interrupts off! */
	if (et->events & INTR_ERROR) {
		if ((*chops->errors)(ch)) {
			printk("%s error, calling et_init() for et%d\n", __FUNCTION__, et->etc->unit);
			et_init(et, ET_INIT_INTROFF);
		} else {
			if (nrx < quota) {
				nrx += et_rxevent(osh, et, chops, ch, quota);
			}
		}
	}

	/* run the tx queue */
	if (et->etc->txq_state != 0) {
		if (!ET_ALL_PASSIVE_ENAB(et)) {
			et_sendnext(et);
	    }
#ifdef GMAC_ALL_PASSIVE
		else {
#ifdef CONFIG_BCM_IPROC_GMAC_TXONCPU1
            schedule_work_on(1, &et->txq_task.work);
#else
            schedule_work(&et->txq_task.work);
#endif
        }
#endif /* GMAC_ALL_PASSIVE */
    }

	/* clear this before re-enabling interrupts */
	et->events = 0;

	/* something may bring the driver down */
	if (!et->etc->up) {
		et->resched = FALSE;
		goto done;
	}

#if !defined(GMAC_NAPI_POLL) && !defined(GMAC_NAPI2_POLL)
#ifdef GMAC_ALL_PASSIVE
	if (et->resched) {
		if (!ET_ALL_PASSIVE_ENAB(et)) {
			tasklet_schedule(&et->tasklet);
		} else {
			schedule_work(&et->dpc_task.work);
		}
	} else {
		(*chops->intrson)(ch);
	}
#else /* GMAC_ALL_PASSIVE */
    if (et->resched) { /* there may be frames left, reschedule et_dpc() */
	    tasklet_schedule(&et->tasklet);
	} else { /* re-enable interrupts */
	    (*chops->intrson)(ch);
	}
#endif /* GMAC_ALL_PASSIVE */
#endif /* ! NAPIx_POLL */

done:
#if defined(GMAC_NAPI_POLL)
	/* update number of frames processed */
	*budget -= nrx;
	dev->quota -= nrx;

	ET_TRACE(("et%d: et_poll: quota %d budget %d\n",
	          et->etc->unit, dev->quota, *budget));

	/* we got packets but no quota */
	if (et->resched) {
		return (1);
	}

	netif_rx_complete(dev);

	/* enable interrupts now */
	(*chops->intrson)(ch);

	/* indicate that we are done */
	return (0);
#elif defined(GMAC_NAPI2_POLL)
	ET_TRACE(("et%d: et_poll: budget %d\n",
	          et->etc->unit, budget));

	/* we got packets but no quota */
	if (et->resched) {
		return (1);
	}

    napi_complete(napi);

	/* enable interrupts now */
	(*chops->intrson)(ch);

	/* indicate that we are done */
	return (0);
#else /* !defined(GMAC_NAPI_POLL) && !defined(GMAC_NAPI2_POLL) */
	ET_UNLOCK(et);
	return;
#endif
}

#ifdef GMAC_ALL_PASSIVE
static void BCMFASTPATH
et_dpc_work(struct et_task *task)
{
#if !defined(GMAC_NAPI_POLL) && !defined(GMAC_NAPI2_POLL)
	et_info_t *et = (et_info_t *)task->context;
	et_dpc((unsigned long)et);
#else
	BUG_ON(1);
#endif
	return;
}
#endif /* GMAC_ALL_PASSIVE */

static void
et_error(et_info_t *et, struct sk_buff *skb, void *rxh)
{
	uchar eabuf[32];
	struct ether_header *eh;

	eh = (struct ether_header *)skb->data;
	bcm_ether_ntoa((struct ether_addr *)eh->ether_shost, eabuf);

	if (RXH_OVERSIZE(et->etc, rxh)) {
		ET_ERROR(("et%d: rx: over size packet from %s\n", et->etc->unit, eabuf));
	}
	if (RXH_CRC(et->etc, rxh)) {
		ET_ERROR(("et%d: rx: crc error from %s\n", et->etc->unit, eabuf));
	}
	if (RXH_OVF(et->etc, rxh)) {
		ET_ERROR(("et%d: rx: fifo overflow\n", et->etc->unit));
	}
	if (RXH_NO(et->etc, rxh)) {
		ET_ERROR(("et%d: rx: crc error (odd nibbles) from %s\n",
		          et->etc->unit, eabuf));
	}
	if (RXH_RXER(et->etc, rxh)) {
		ET_ERROR(("et%d: rx: symbol error from %s\n", et->etc->unit, eabuf));
	}
}

static void BCMFASTPATH
et_sendup(et_info_t *et, struct sk_buff *skb)
{
	etc_info_t *etc;
	void *rxh;
	uint16 flags;
#ifdef DBG_PRINT_PKT
	int idx;
#endif /* DBG_PRINT_PKT */
#ifdef CONFIG_BCM_IPROC_GMAC_PREFETCH
    struct sk_buff *next;
#endif /* CONFIG_BCM_IPROC_GMAC_PREFETCH */

	etc = et->etc;

	/* packet buffer starts with rxhdr */
	rxh = skb->data;

	/* strip off rxhdr */
	__skb_pull(skb, HWRXOFF);

	ET_TRACE(("et%d: et_sendup: %d bytes\n", et->etc->unit, skb->len));
	ET_LOG("et%d: et_sendup: len %d", et->etc->unit, skb->len);

	etc->rxframe++;
	etc->rxbyte += skb->len;

	/* eh should now be aligned 2-mod-4 */
	ASSERT(((ulong)skb->data & 3) == 2);

	/* strip off crc32 */
	__skb_trim(skb, skb->len - ETHER_CRC_LEN);

	ET_PRHDR("rx", (struct ether_header *)skb->data, skb->len, etc->unit);
	ET_PRPKT("rxpkt", skb->data, skb->len, etc->unit);

#ifdef DBG_PRINT_PKT
    printk("et%d: rxpkt len(0x%x) tag:0x%02x%02x%02x%02x\n", etc->unit, skb->len,
                skb->data[12], skb->data[13], skb->data[14], skb->data[15]);
    
    printk("et%d: %s len(0x%x) rxpkt:", etc->unit, __FUNCTION__, skb->len);
    for (idx = 0; idx < skb->len; idx++) {
        if ((idx % 16) == 0) {
            printk("\n");
        }
        printk("%02x ", skb->data[idx]);
    }
    printk("\n");
#endif /* DBG_PRINT_PKT */

	/* get the error flags */
	flags = RXH_FLAGS(etc, rxh);

	/* check for reported frame errors */
	if (flags) {
		goto err;
    }
    
	skb->dev = et->dev;

	ASSERT(!PKTISCHAINED(skb));

	/* extract priority from payload and store it out-of-band
	 * in skb->priority
	 */
	if (et->etc->qos) {
		pktsetprio(skb, TRUE);
	}

	skb->protocol = eth_type_trans(skb, et->dev);

#ifdef CONFIG_BCM_IPROC_GMAC_PREFETCH
    next = skb->next;
    while (1) {
        if (next != NULL) {
    
            prefetch_range(next, SKB_PREFETCH_LEN);
            next = next->next;
        } else {
            break;
        }
    } 
#endif /* CONFIG_BCM_IPROC_GMAC_PREFETCH */

	/* send it up */
#if defined(GMAC_NAPI_POLL) || defined(GMAC_NAPI2_POLL)
#ifdef CONFIG_IPROC_2STAGE_RX
	if (!et->rxinisr) {
		netif_receive_skb(skb);
	} else {
		netif_rx(skb);
    }
#else /* CONFIG_IPROC_2STAGE_RX */
    if (et->dev->features & NETIF_F_GRO) {
        skb->ip_summed = CHECKSUM_UNNECESSARY;
        if (skb->protocol == cpu_to_be16(ETH_P_8021Q)) {
            skb = vlan_untag(skb);
            if (unlikely(!skb)) {
                goto err;
            }
        }
        napi_gro_receive(&et->napi_poll, skb);
    } else {
        netif_receive_skb(skb);
    }
#endif /* CONFIG_IPROC_2STAGE_RX */
#else 
	netif_rx(skb);
#endif /* defined(GMAC_NAPI_POLL) || defined(GMAC_NAPI2_POLL) */

	ET_LOG("et%d: et_sendup ret", et->etc->unit, 0);

	return;

err:
	et_error(et, skb, rxh);

	PKTFRMNATIVE(etc->osh, skb);
	PKTFREE(etc->osh, skb, FALSE);

	return;
}

static void
et_dumpet(et_info_t *et, struct bcmstrbuf *b)
{
	bcm_bprintf(b, "et %p dev %p name %s tbusy %d txq[0].qlen %d malloced %d\n",
            et, et->dev, et->dev->name, (uint)netif_queue_stopped(et->dev), et->txq[0].qlen,
    MALLOCED(et->osh));
}

void
et_dump(et_info_t *et, struct bcmstrbuf *b)
{
/*	bcm_bprintf(b, "et%d: %s %s version %s\n", et->etc->unit,
		__DATE__, __TIME__, EPI_VERSION_STR);
*/
	bcm_bprintf(b, "et%d: version %s\n", et->etc->unit, EPI_VERSION_STR);

	et_dumpet(et, b);
	etc_dump(et->etc, b);

	bcm_bprintf(b, "txdfrm(%d); txdfrmropped(%d); txqlen(%d); txqstop(%d); txdmafull(%d) txmaxlen(%d) txsgpkt(%d)\n",
			et->etc->txfrm, et->etc->txfrmdropped, et->etc->txqlen, et->etc->txqstop, et->etc->txdmafull,
			et->etc->txmaxlen, et->etc->txsgpkt);
	et->etc->txfrm=0;
	et->etc->txfrmdropped=0;
	et->etc->txqlen=0;
	et->etc->txqstop=0;
	et->etc->txdmafull=0;
	et->etc->txmaxlen=0;
	et->etc->txsgpkt=0;

	bcm_bprintf(b, "rxquota(%d); rxdmastopped(%d)\n",
			et->etc->rxquota, et->etc->rxdmastopped);
	et->etc->rxquota=0;
	et->etc->rxdmastopped=0;
#ifdef GMAC_RATE_LIMITING
	bcm_bprintf(b, "rxd_dropped_packets(%d)\n",
			et->etc->rl_dropped_packets);
	et->etc->rl_dropped_packets=0;
#endif /* GMAC_RATE_LIMITING */

}

void
et_link_up(et_info_t *et)
{
	ET_ERROR(("et%d: link up (%d%s)\n",
		et->etc->unit, et->etc->speed, (et->etc->duplex? "FD" : "HD")));
    printk(KERN_DEBUG "et%d Link Up: %d%s\n", et->etc->unit, et->etc->speed, et->etc->duplex?"FD":"HD");
	netif_carrier_on(et->dev);
}

void
et_link_down(et_info_t *et)
{
	ET_ERROR(("et%d: link down\n", et->etc->unit));
    printk(KERN_DEBUG "et%d Link Down\n", et->etc->unit);
	netif_carrier_off(et->dev);
}

bool
et_is_link_up(et_info_t *et)
{
	return netif_carrier_ok(et->dev);
}

/**********************************************************************
 *  iproc_gmac_drv_probe(device)
 *
 *  The Platform Driver Probe function.
 *
 *  Input parameters:
 *         device: The Device Context
 *
 *  Return value:
 *		    0: Driver Probe is Succesful
 *		not 0: ERROR
 **********************************************************************/
static int iproc_gmac_drv_probe(struct platform_device* pldev)
{
	struct net_device *dev = NULL;
#ifndef CONFIG_OF
	void __iomem *macbase = NULL;
	struct resource *memres = NULL;	
	struct resource *irqres = NULL;
#endif	
	osl_t *osh = NULL;
	et_info_t *et = NULL;
	int unit = et_found;
	int err = 0;
    unsigned char devname[8] = {0};
	char name[128];
	int idx;
#ifdef CONFIG_OF
  	struct device_node *np = pldev->dev.of_node;
#endif

	printk("%s enter name:%s; id:0x%x; unit:%d\n", __FUNCTION__, pldev->name, pldev->id, unit);

	/* Validation of platform device structure */
	if (!pldev) {
		ET_ERROR(("WRONG INPUT\nplatfrom_device ppointer should not be NULL.\n"));
		return -EINVAL;
	}
 
	et_found++;

	nvram_env_gmac_name(unit, name);
	if (getvar(NULL, name) == NULL) { 
		printk("et%d: %s not found, ignore it\n", unit, name);
		return -ENODEV; 
	}

	osh = osl_attach(pldev, PCI_BUS, FALSE);
	ASSERT(osh);

	ET_TRACE(("%s call alloc_etherdev\n", __FUNCTION__));
	if ((dev = alloc_etherdev(sizeof( et_info_t ))) == NULL) {
		ET_ERROR(("%s: alloc_etherdev() failed\n", __FUNCTION__));
		err = -ENOMEM;
		goto exit;
	}

	et = ET_INFO(dev);
	bzero(et, sizeof(et_info_t));	/* Is this needed in 2.6.36 ? -LR */
	et->dev = dev;
	et->osh = osh;

#ifndef CONFIG_OF
	ET_TRACE(("%s get resources\n", __FUNCTION__));
	memres = iproc_platform_get_resource(pldev, IORESOURCE_MEM, 0);
	if (NULL == memres) {
		ET_ERROR(("ERROR: Could not get Platform Resource MAC Register Memory Resurce\n"));
		err = -ENOMEM;
		goto exit;
	}

	if (!request_mem_region(memres->start, (memres->end - memres->start + 1), pldev->name)) {
		ET_ERROR(("ERROR: Could not request mem region. In file %s, LN:%d\n", __FILE__, __LINE__));
		err = -ENOMEM;
		goto exit;
	}
	irqres = iproc_platform_get_resource(pldev, IORESOURCE_IRQ, 0);
	if (NULL == irqres) {
		ET_ERROR(("ERROR: Could not get Platform Resource GMAC Register IRQ Resource\n"));
		err = -ENOMEM;
		goto exit;
	}

	dev->base_addr = memres->start;
	dev->irq = irqres->start;
#else
  	dev->base_addr = (unsigned long)of_iomap(np, 0);
	dev->irq = (unsigned int)irq_of_parse_and_map(np, 0);
#endif /*CONFIG_OF*/

	printk("et%d: base_addr (0x%x) irq (%d)\n", unit, (uint32)dev->base_addr, dev->irq); 

#ifndef CONFIG_OF
	if ((et->regsva = ioremap_nocache(dev->base_addr, 0xc00)) == NULL) {
		ET_ERROR(("et%d: ioremap() failed\n", unit));
		err = -ENOMEM;
		goto exit;
	}
#else
	et->regsva = dev->base_addr;
#endif
	ET_TRACE(("%s base_addr: 0x%x; regsva:0x%x\n", __FUNCTION__, (uint32)dev->base_addr, (uint32)et->regsva));

	pldev->id = dev->base_addr;
	dev_set_drvdata(&(pldev->dev), dev);
	SET_NETDEV_DEV(dev, (&pldev->dev));

	init_MUTEX(&et->sem);
	spin_lock_init(&et->lock);
	spin_lock_init(&et->txq_lock);
	spin_lock_init(&et->tx_lock);
	spin_lock_init(&et->isr_lock);

	for (idx = 0; idx < NUMTXQ; idx++) {
		skb_queue_head_init(&et->txq[idx]);
    }
    
	/* Common load-time initialization */
	et->etc = etc_attach((void *)et, VENDOR_BROADCOM, BCMIPROC_CHIP_ID, unit, osh, et->regsva);
	if (et->etc == NULL) {
		ET_ERROR(("et%d: etc_attach() failed\n", unit));
		err = -ENOMEM;
		goto exit;
	}

	bcopy(&et->etc->cur_etheraddr, dev->dev_addr, ETHER_ADDR_LEN);

	/* init 1 second watchdog timer */
	init_timer(&et->timer);
	et->timer.data = (ulong)dev;
	et->timer.function = et_watchdog;

#if defined(CONFIG_IPROC_SDK_MGT_PORT_HANDOFF)
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2))
	/* schedule one second watchdog timer */
	et->timer.expires = jiffies + HZ;
	add_timer(&et->timer);
	et->set = TRUE;
#endif /* (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2)) */
#endif /* defined(CONFIG_IPROC_SDK_MGT_PORT_HANDOFF) */

#ifdef GMAC_RATE_LIMITING
	/* Init 1 second watchdog timer */
	init_timer(&et->etc->rl_timer);
	et->etc->rl_timer.data = (ulong)dev;
	et->etc->rl_timer.function = et_release_congestion;
#endif /* GMAC_RATE_LIMITING */

#ifdef GMAC_ALL_PASSIVE
	if (ET_ALL_PASSIVE_ENAB(et)) {
		MY_INIT_WORK(&et->dpc_task.work, (work_func_t)et_dpc_work);
		et->dpc_task.context = et;
		MY_INIT_WORK(&et->txq_task.work, (work_func_t)et_txq_work);
		et->txq_task.context = et;
	}
    if (et_ctf_pipeline_loopback(et)) {
        et->all_dispatch_mode = FALSE;
    } else {
		et->all_dispatch_mode = (passivemode == 0) ? TRUE : FALSE;
	}
#endif /* GMAC_ALL_PASSIVE */

	ET_TRACE(("%s request irq\n", __FUNCTION__));
	/* register our interrupt handler */
	if (request_irq(dev->irq, et_isr, IRQF_SHARED, dev->name, et)) {
		ET_ERROR(("%s: request_irq(%d) failed\n", __FUNCTION__, dev->irq));
		err = -ENOMEM;
		goto exit;
	}

	/* add us to the global linked list */
	et->next = et_list;
	et_list = et;

#ifdef HAVE_NET_DEVICE_OPS
	dev->netdev_ops = &et_netdev_ops ;
#else /* HAVE_NET_DEVICE_OPS */
	dev->open = et_open;
	dev->stop = et_close;
	dev->hard_start_xmit = et_start;
	dev->get_stats = et_get_stats;
	dev->set_mac_address = et_set_mac_address;
	dev->set_multicast_list = et_set_multicast_list;
	dev->do_ioctl = et_ioctl;
#endif /* HAVE_NET_DEVICE_OPS */

#if defined(GMAC_NAPI_POLL)
	dev->poll = et_poll;
	dev->weight = (ET_GMAC(et->etc) ? 64 : 32);
#elif defined(GMAC_NAPI2_POLL)
	netif_napi_add(dev, & et->napi_poll, et_poll, 64);
	napi_enable(&et->napi_poll);
#else /* !GMAC_NAPI_POLL && !GMAC_NAPI2_POLL */
	/* Setup the bottom half handler */
	tasklet_init(&et->tasklet, et_dpc, (ulong)et);
#endif 

#if defined(BCMDMASGLISTOSL)
	dev->features = (NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_ALL_CSUM);
	dev->vlan_features = (NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_ALL_CSUM);
	
#ifdef CONFIG_BCM_GRO_ENABLE
	dev->features |= NETIF_F_GRO;
	dev->vlan_features |= NETIF_F_GRO;
	printk("et%d: Enable Checksum-SG-GRO\n", unit);
#endif /* CONFIG_BCM_GRO_ENABLE */
#endif /* BCMDMASGLISTOSL */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    dev->ethtool_ops = &et_ethtool_ops;
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36) */

	/* Assign netdev name consistently, even if GMAC0 or 1 is disabled */
    snprintf(devname, 8, "eth%d", unit);
    dev_alloc_name(dev, devname);

    ET_TRACE(("%s register netdev\n", __FUNCTION__));
    if (register_netdev(dev)) {
        ET_ERROR(("%s register_netdev() failed\n", __FUNCTION__));
        err = -ENOMEM;
        goto exit;
    }

    /* Print hello string */
    (*et->etc->chops->longname)(et->etc->ch, name, sizeof(name));
    printk("%s: %s %s\n", dev->name, name, EPI_VERSION_STR);

    eth_mac_proc_create(dev);	

    ET_TRACE(("%s: exit\n", __FUNCTION__));

	iproc_gmac_init_module();

	return 0;

exit:
#ifndef CONFIG_OF  	
    if (macbase) {
        iounmap(macbase);
        macbase=NULL;
    }  
    if (memres) {
        release_mem_region(memres->start, (memres->end - memres->start + 1));
        memres=NULL;
    }
#endif    
    if (dev) {
        free_netdev(dev);
        dev = NULL;
    }
    if (osh) {
        osl_detach(osh);
        osh=NULL;
    }
    if (et) {
        etc_detach(et->etc);
        et->dev = NULL;
        et->osh = NULL;
        et_free(et);
        et=NULL;
    }
    return err;
}


/**********************************************************************
 *  iproc_gmac_drv_remove(device)
 *
 *  The Removal of Platform Device, and un-initialize the previously
 *  added MAC, and it's MEM Regions and Resources.
 *
 *  Input parameters:
 *         device: The Device Context
 *
 *  Return value:
 *		    0: Driver Entry is Succesfull
 **********************************************************************/
static int __exit iproc_gmac_drv_remove(struct platform_device *pldev)
{
	struct net_device *dev = platform_get_drvdata(pldev);
	int retVal = 0;
	et_info_t *et				= NULL;
	struct resource *memres		= NULL;

	ET_TRACE(("%s: enter\n", __FUNCTION__));
	printk("%s: enter\n", __FUNCTION__);

#if 0
	iproc_gmac_drv_suspend(pldev, PMSG_SUSPEND);
#endif

	et = ET_INFO(dev);

	iounmap(et->regsva);
	unregister_netdev(dev);

	memres = iproc_platform_get_resource(pldev, IORESOURCE_MEM, 0);
	if (memres) {
		release_mem_region(memres->start, (memres->end - memres->start + 1));
	} else {
		ET_ERROR(("ERROR: Could not get Platform Resource GMAC Register Memory Resource\n"));
		retVal = -ENOMEM;
	}

	free_netdev(dev);

#ifdef CONFIG_OF
	eth_mac_proc_remove (dev);
#endif		

	et->dev = NULL;
	et_free(et);

	ET_TRACE(("%s: exit\n", __FUNCTION__));

	return retVal;
}

#if 0
static int iproc_gmac_drv_suspend(struct platform_device *pdev, pm_message_t state)
{
	int ret;
	char *filename = "/usr/sbin/ifdown";
	char *argv[] = {filename, "eth0", NULL};
	char *envp[] = {"HOME=/",
					 "TERM=linux",
					 "PATH=/sbin:/usr/sbin:/bin:/usr/bin",
					 NULL};

	ET_TRACE(("%s: enter\n", __FUNCTION__));
	printk("%s: enter\n", __FUNCTION__);

/*	ret = kernel_execve(filename, (const char * const*) argv, (const char * const*) envp);*/
	ret = do_execve(getname_kernel(filename), (const char *const *)argv, (const char *const *)envp);
	ET_TRACE(("%s: exit\n", __FUNCTION__));

	return 0;
}

static int iproc_gmac_drv_resume(struct platform_device *pdev)
{
	int ret;
	char *filename = "/usr/sbin/ifup";
	char *argv[] = {filename, "eth0", NULL};
	char *envp[] = {"HOME=/",
					 "TERM=linux",
					 "PATH=/sbin:/usr/sbin:/bin:/usr/bin",
					 NULL};

	ET_TRACE(("%s: enter\n", __FUNCTION__));
	printk("%s: enter\n", __FUNCTION__);
	/*ret = kernel_execve(filename, (const char * const*) argv, (const char * const*) envp);*/
	ret = do_execve(getname_kernel(filename), (const char *const *)argv, (const char *const *)envp);

	ET_TRACE(("%s: exit\n", __FUNCTION__));

	return 0;
}
#endif /* CONFIG_PM */


/**********************************************************************
 *  iproc_gmac_init_module(VOID)
 *
 *  The Driver Entry Function
 *
 *  Input parameters:
 *         None
 *
 *  Return value:
 *		    0: Driver Entry is Succesful
 *		not 0: ERROR
 **********************************************************************/
static int
iproc_gmac_init_module(void)
{
	ET_TRACE(("%s: enter\n", __FUNCTION__));
	
#ifdef BCMDBG
	if (msglevel != 0xdeadbeef) {
		et_msg_level = msglevel;
	} else {
		char *var = getvar(NULL, "et_msglevel");
		if (var) {
			et_msg_level = bcm_strtoul(var, NULL, 0);
	    }
	}

	printk("%s: msglevel set to 0x%x\n", __FUNCTION__, et_msg_level);
#endif /* BCMDBG */

#ifdef GMAC_ALL_PASSIVE
	{
		char *var = getvar(NULL, "et_dispatch_mode");
		if (var)
			passivemode = bcm_strtoul(var, NULL, 0);
		printk("%s: passivemode set to 0x%x\n", __FUNCTION__, passivemode);
	}
#endif /* GMAC_ALL_PASSIVE */

#ifdef	GMAC_NAPI_POLL
	printk("%s: GMAC_NAPI_POLL mode\n", __FUNCTION__);
#endif	/* GMAC_NAPI_POLL */

#ifdef	GMAC_NAPI2_POLL
	printk("%s: GMAC_NAPI2_POLL mode\n", __FUNCTION__);
#endif	/* GMAC_NAPI2_POLL */

#ifdef ET_LIMIT_TXQ
	{
		char *var = getvar(NULL, "et_txq_thresh");
		if (var) {
			et_txq_thresh = bcm_strtoul(var, NULL, 0);
		}
		printk("%s: et_txq_thresh set to 0x%x\n", __FUNCTION__, et_txq_thresh);
	}
#endif /* ET_LIMIT_TXQ */

#ifdef GMAC_RATE_LIMITING
	{
		char *var = getvar(NULL, "et_rx_rate_limit");
		if (var) {
			et_rx_rate_limit = bcm_strtoul(var, NULL, 0);
		}
		printk("%s: et_rx_rate_limit set to 0x%x\n", __FUNCTION__, et_rx_rate_limit);
	}
#endif /* GMAC_RATE_LIMITING */
  
    ET_TRACE(("%s: exit\n", __FUNCTION__));
    return 0;
}


#ifndef CONFIG_OF
/**********************************************************************
 *  iproc_gmac_cleanup_module(VOID)
 *
 *  The Driver Exit Function
 *
 *  Input parameters:
 *         None
 *
 *  Return value:
 *		    Nothing
 **********************************************************************/
static void __exit
iproc_gmac_cleanup_module(void)
{
    int idx;
    
    ET_TRACE(("%s: enter\n", __FUNCTION__));
    
    for (idx = 0; idx < IPROC_NUM_GMACS; idx++) {
        if (gmac_pdev_loaded[idx]) {
            /* Unregister GMAC driver */
            iproc_platform_driver_unregister(&gmac_pdrv[idx]);
        }
    }

	/* Clean up the proc directory */
    eth_mac_proc_remove();

    ET_TRACE(("%s: exit\n", __FUNCTION__));
    return;
}
#endif /*CONFIG_OF*/

#if 0
static int get_fa_bypass(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	unsigned int len=0;
	len += sprintf(page+len, "\n\n## Current FA Bypass setting = 0x%x, %s ##\n\n",gBypass, gBypass?"enabled":"disabled");
	*eof = 1;
	return len;
}

static int set_fa_bypass(struct file *file, const char *buffer, unsigned long count, void *data)
{
	unsigned int len=1;
	unsigned char debug_buffer[2];
	int bypass =0;

	if (count != 2) {
		ET_ERROR(("Please pass (one:1) digit FA bypass value only, 0=disable FA bypass, 1 = enable FA bypass\n"));
		return -EINVAL;
	}

	/* Last buffer byte will be LF or CR only */
	if(copy_from_user(&debug_buffer[0], buffer, len)) {
		ET_ERROR(("Problem in copying invalid user buffer\n"));
		return -EFAULT;
	}

	debug_buffer[len]='\0'; /* Only one byte value is available now */
	if ( sscanf(debug_buffer,"%d",&bypass) != 1) {
		ET_ERROR(("\n##Invalid value :%s: is passed ##\n",debug_buffer));
		return -EINVAL;
	}
	if (!((bypass >=DISABLE_FA_BYPASS) && (bypass <= ENABLE_FA_BYPASS))) {
		ET_ERROR(("\n##Passed value :%d: is not in valid range %d-%d \n",bypass,DISABLE_FA_BYPASS,ENABLE_FA_BYPASS));
		return -EINVAL;
	}
	ET_TRACE(("\n##set_fa_bypass(): Previous:  0x%x %s ##\n", gBypass, gBypass?"enabled":"disabled"));
	gBypass = bypass;
	ET_TRACE(("\n##set_fa_bypass(): New:  0x%x %s ##\n", gBypass, gBypass?"enabled":"disabled"));
	return count;
}
#endif

static char* iproc_eth_proc_root="iproc_eth";
static struct proc_dir_entry *iproc_eth_root_dir=NULL; // BCM5892  eth proc root directory
static int eth_mac_proc_create(struct net_device *dev )
{
/*	struct proc_dir_entry *dent, *ent;*/
	struct proc_dir_entry *dent;
	et_info_t *et = NULL;
	etc_info_t *etc = NULL;
    char fname[32];

	et = ET_INFO(dev);
    if (et != NULL) {
	    etc = et->etc;
    }

    if ((et == NULL) || (etc == NULL)) {
        printk("%s: error: Unit probably not initialized by probe function."
              " et=0x%pm etc=0x%p\n", __FUNCTION__, et, etc);
        return -1;
    }

	ET_TRACE(("%s: enter\n", __FUNCTION__));

    snprintf(fname, 32, "%s%u", iproc_eth_proc_root, etc->unit);

	dent =	proc_mkdir(fname,iproc_eth_root_dir);
#if 0	
	if (dent) {
        /* unit 2 has FA connectivity, create bypass path only for unit 2 */
        if (etc->unit == 2) {
	        printk("\nCreating fa bypass proc entry\n");

		    ent = create_proc_entry("fa_bypass", S_IFREG|S_IRUGO, dent);
		    if (ent) {
			    ent->read_proc  = get_fa_bypass;
			    ent->write_proc = set_fa_bypass;
		    } else {
	            printk("Error creating proc_entry, returning\n");
                return -1;
		    }
        }
	}
#endif	
	ET_TRACE(("%s: exit\n", __FUNCTION__));
	return 0; 
}

#ifndef CONFIG_OF
static void eth_mac_proc_remove(void)
{
	ET_TRACE(("%s: enter\n", __FUNCTION__));
	printk("%s: enter\n", __FUNCTION__);
	remove_proc_entry(iproc_eth_proc_root,NULL);
	ET_TRACE(("%s: exit\n", __FUNCTION__));
}
#else
static void eth_mac_proc_remove(struct net_device *dev)
{
	et_info_t *et;
	etc_info_t *etc;
    char fname[32];

	ET_TRACE(("%s: enter\n", __FUNCTION__));
	printk("%s: enter\n", __FUNCTION__);
	
	et = ET_INFO(dev);
	if (et == NULL) {
		printk("%s: error: Unit probably not initialized by probe function.\n", __FUNCTION__);
		return;
	}
 
	etc = et->etc;
    if (etc == NULL) {
        printk("%s: error: Unit probably not initialized by probe function.\n", __FUNCTION__);
        return;
    }
    
    snprintf(fname, 32, "%s%u", iproc_eth_proc_root, etc->unit);
	remove_proc_entry(fname,NULL);
	
	ET_TRACE(("%s: exit\n", __FUNCTION__));
}
#endif /* CONFIG_OF */ 

#ifdef CONFIG_OF
static const struct of_device_id brcm_iproc_dt_ids[] = {
	{ .compatible = "brcm,iproc-gmac"},
	{ }
};
MODULE_DEVICE_TABLE(of, brcm_iproc_dt_ids);

static struct platform_driver iproc_gmac_driver =
{
	.probe = iproc_gmac_drv_probe,
	.remove = __exit_p(iproc_gmac_drv_remove),
	.driver =
        {
		.name = "bcmiproc-gmac",
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(brcm_iproc_dt_ids),
	},
};
module_platform_driver(iproc_gmac_driver);
#else
module_init(iproc_gmac_init_module);
module_exit(iproc_gmac_cleanup_module);
#endif /*CONFIG_OF*/

MODULE_DESCRIPTION("Broadcom Northstar Ethernet Driver");
MODULE_LICENSE("GPL");
