#ifndef _BIRD_MERAKI_GW_H_
#define _BIRD_MERAKI_GW_H_

// Keeping track of Meraki gateways

// Information about a Meraki gateway
struct meraki_gw {
    node n;             // linkage
    ip_addr gw;         // the address of the gateway
    unsigned gw_num;    // the number of the gateway
};

extern struct meraki_gw *meraki_gw_find(list *gw_list, ip_addr gw);
extern struct meraki_gw *meraki_gw_create(struct proto *p, ip_addr gw,
                                          unsigned int gw_num);
extern void meraki_gw_add(list *gw_list, struct meraki_gw *gw);
extern void meraki_gw_purge(list *gw_list);

#endif
