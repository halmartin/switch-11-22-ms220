/*
 * $Copyright Open Broadcom Corporation$
 *
 * Minimal debug/trace/assert driver definitions for
 * Broadcom Home Networking Division 10/100 Mbit/s Ethernet
 * Device Driver.
 *
 * $Id: et_dbg.h 286404 2011-09-27 19:29:08Z nisar $
 */

#ifndef _et_dbg_
#define _et_dbg_

#ifdef	BCMDBG
struct ether_header;
extern void etc_prhdr(char *msg, struct ether_header *eh, uint len, int unit);
extern void etc_prhex(char *msg, uchar *buf, uint nbytes, int unit);
/*
 * et_msg_level is a bitvector:
 *	0	errors
 *	1	function-level tracing
 *	2	one-line frame tx/rx summary
 *	3	complex frame tx/rx in hex
 */
#define	ET_ERROR(args)	if (!(et_msg_level & 1)) ; else printf args
#define	ET_TRACE(args)	if (!(et_msg_level & 2)) ; else printf args
#define	ET_PRHDR(msg, eh, len, unit)	if (!(et_msg_level & 4)) ; else etc_prhdr(msg, eh, len, unit)
#define	ET_PRPKT(msg, buf, len, unit)	if (!(et_msg_level & 8)) ; else etc_prhex(msg, buf, len, unit)
#else	/* BCMDBG */
#define	ET_ERROR(args)
#define	ET_TRACE(args)
#define	ET_PRHDR(msg, eh, len, unit)
#define	ET_PRPKT(msg, buf, len, unit)
#endif	/* BCMDBG */

extern uint32 et_msg_level;

#define	ET_LOG(fmt, a1, a2)

/* include port-specific tunables */
#if defined(linux)
#include <et_linux.h>
#else
#error
#endif

#endif /* _et_dbg_ */
