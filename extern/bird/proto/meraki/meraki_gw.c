#include "nest/bird.h"
#include "nest/protocol.h"
#include "meraki_gw.h"

struct meraki_gw *
meraki_gw_find(list *gw_list, ip_addr gw)
{
    struct meraki_gw *mgw;

    WALK_LIST(mgw, *gw_list) {
        if (mgw->gw == gw) {
            return mgw;
        }
    }

    return NULL;
}

struct meraki_gw *
meraki_gw_create(struct proto *p, ip_addr gw, unsigned int gw_num)
{
    struct meraki_gw *mgw = mb_allocz(p->pool, sizeof(struct meraki_gw));
    mgw->gw = gw;
    mgw->gw_num = gw_num;

    return mgw;
}

void
meraki_gw_add(list *gw_list, struct meraki_gw *gw)
{
    add_tail(gw_list, &gw->n);
}

void
meraki_gw_purge(list *gw_list)
{
    struct meraki_gw *mgw, *next_mgw;
    WALK_LIST_DELSAFE(mgw, next_mgw, *gw_list) {
        rem_node(&mgw->n);
    }
}

