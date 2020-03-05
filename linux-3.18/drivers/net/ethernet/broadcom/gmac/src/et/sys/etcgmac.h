/*
 * $Copyright Open Broadcom Corporation$
 *
 * Broadcom Gigabit Ethernet MAC defines.
 *
 * $Id: etcgmac.h 267700 2011-06-19 15:41:07Z sudhirbs $
 */

#ifndef _etcgmac_h_
#define _etcgmac_h_

/* chip interrupt bit error summary */
#define	I_ERRORS		(I_PDEE | I_PDE | I_DE | I_RDU | I_RFO | I_XFU)
#define	DEF_INTMASK		(I_XI0 | I_XI1 | I_XI2 | I_XI3 | I_RI | I_ERRORS)

#define GMAC_RESET_DELAY 	2

#define GMAC_MIN_FRAMESIZE	17	/* gmac can only send frames of
	                                 * size above 17 octetes.
	                                 */

#define LOOPBACK_MODE_DMA	0	/* loopback the packet at the DMA engine */
#define LOOPBACK_MODE_MAC	1	/* loopback the packet at MAC */
#define LOOPBACK_MODE_NONE	2	/* no Loopback */

#define FA2_GMAC_MAX_LEN    2048

#define DMAREG(ch, dir, qnum)	((dir == DMA_TX) ? \
	                         (void *)(uintptr)&(ch->regs->dmaregs[qnum].dmaxmt) : \
	                         (void *)(uintptr)&(ch->regs->dmaregs[qnum].dmarcv))

/*
 * Add multicast address to the list. Multicast address are maintained as
 * hash table with chaining.
 */
typedef struct mclist {
	struct ether_addr mc_addr;	/* multicast address to allow */
	struct mclist *next;		/* next entry */
} mflist_t;

#define GMAC_HASHT_SIZE		16	/* hash table size */
#define GMAC_MCADDR_HASH(m)	((((uint8 *)(m))[3] + ((uint8 *)(m))[4] + \
	                         ((uint8 *)(m))[5]) & (GMAC_HASHT_SIZE - 1))

#define ETHER_MCADDR_CMP(x, y) ((((uint16 *)(x))[0] ^ ((uint16 *)(y))[0]) | \
				(((uint16 *)(x))[1] ^ ((uint16 *)(y))[1]) | \
				(((uint16 *)(x))[2] ^ ((uint16 *)(y))[2]))

#define SUCCESS			0
#define FAILURE			-1

typedef struct mcfilter {
					/* hash table for multicast filtering */
	mflist_t *bucket[GMAC_HASHT_SIZE];
} mcfilter_t;

extern uint32 find_priq(uint32 pri_map);

#endif /* _etcgmac_h_ */
