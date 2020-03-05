/*
 * $Copyright Open Broadcom Corporation$
 *
 * Required functions exported by the port-specific (os-dependent) driver
 * to common (os-independent) driver code.
 *
 * $Id: et_export.h 322208 2012-03-20 01:53:23Z rnuti $
 */

#ifndef _et_export_h_
#define _et_export_h_

/* misc callbacks */
extern void et_init(void *et, uint options);
extern void et_reset(void *et);
extern void et_link_up(void *et);
extern void et_link_down(void *et);
extern bool et_is_link_up(void *et);
extern int et_up(void *et);
extern int et_down(void *et, int reset);
extern void et_dump(void *et, struct bcmstrbuf *b);
extern void et_intrson(void *et);

/* for BCM5222 dual-phy shared mdio contortion */
extern void *et_phyfind(void *et, uint coreunit);
extern uint16 et_phyrd(void *et, uint phyaddr, uint reg);
extern void et_phywr(void *et, uint reg, uint phyaddr, uint16 val);
#endif	/* _et_export_h_ */
