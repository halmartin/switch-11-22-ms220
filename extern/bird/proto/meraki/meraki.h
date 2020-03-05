#ifndef _BIRD_MERAKI_H_
#define _BIRD_MERAKI_H_

#include "proto/meraki/meraki_gw.h"

/*
 * Note that we do not create our own EAP_MERAKI since that would
 * require changing nest/route.h.  We use EAP_GENERIC and start the id
 * numbers at 10 to avoid other EA codes under EAP_GENERIC.  As of
 * BIRD 1.6, there is only of these: EA_GEN_IGP_METRIC.
 */
#define EA_MERAKI_NOT_CONN      EA_CODE(EAP_GENERIC, 10)

struct meraki_config {
  struct proto_config c;
  /* List of gateways associated with the MX */
  list gateway_list;
};

struct meraki_proto {
  struct proto p;
};

extern struct protocol proto_meraki;

static inline int proto_is_meraki(struct proto *p)
{ return p->proto == &proto_meraki; }

#endif
