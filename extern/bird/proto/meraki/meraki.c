/**
 * DOC: Meraki
 *
 * The Meraki protocol will output a meraki-style config file with options for
 * use by an MX. The primary purpose is to allow BGP negotiation/route
 * forwarding for sending routes via meraki VPN.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "lib/ip.h"
#include "lib/string.h"
#include "proto/bgp/bgp.h"

#include "meraki.h"
#include "meraki_gw.h"
#include "meraki_route.h"
#include "meraki_bird_defines.hh"

#include <stdio.h>

static void
write_bgp_info(rte *e, FILE *fp, const char* fname)
{
    ea_list *attrs = e->attrs->eattrs;
    byte as_path[ASPATH_BUF_LEN];
    char origin;

    eattr *origin_attr = ea_find(attrs, EA_CODE(EAP_BGP, BA_ORIGIN));
    eattr *aspath_attr = ea_find(attrs, EA_CODE(EAP_BGP, BA_AS_PATH));
    eattr *nexthop_attr = ea_find(attrs, EA_CODE(EAP_BGP, BA_NEXT_HOP));
    eattr *localpref_attr = ea_find(attrs, EA_CODE(EAP_BGP, BA_LOCAL_PREF));

    /* If any of the file writes fail the Json emitted will be malformed
     * or incomplete. Thus returning early in these cases. The consumer of
     * json i.e. poder_agent has been programmed to handle malformed json.
     */
    // Extracting the origin attribute
    origin = get_bgp_origin_char(origin_attr);
    if (0 > fprintf(fp, "\"bgp_info\" :{"
                        "\"origin\" : \"%c\",",
                        origin)) {
        log("failed to write to %s!", fname);
        return;
    }

    // Extracting the as path
    as_path_format(aspath_attr->u.ptr, as_path, ASPATH_BUF_LEN);
    if (0 > fprintf(fp, "\"aspath\" : \"%s\",", as_path)) {
        log("failed to write to %s!", fname);
        return;
    }

    // Extracting the nexthop IP address
    ip_addr *ipp = (ip_addr *) nexthop_attr->u.ptr->data;
    byte nexthop[NEXTHOP_BUF_LEN];
#ifdef IPV6
    // In IPv6, we might have two addresses in NEXT HOP
    if ((nexthop_attr->u.ptr->length == NEXT_HOP_LENGTH)
            && ipa_nonzero(ipp[1])) {
        bsprintf(nexthop, "[\"%I\", \"%I\"]", ipp[0], ipp[1]);
    } else {
        bsprintf(nexthop, "[\"%I\"]", ipp[0]);
    }
#else
    bsprintf(nexthop, "[\"%I\"]", ipp[0]);
#endif
    if (0 > fprintf(fp, "\"nexthop\" : %s,", nexthop)) {
        log("failed to write to %s!", fname);
        return;
    }

    // Extracting the localpref attribute
    if (0 > fprintf(fp, "\"localpref\" : %u }", localpref_attr->u.data)) {
        log("failed to write to %s!", fname);
        return;
    }
}

static int
get_gateway_number(const list *gateway_list, ip_addr gw)
{
    const struct meraki_gw *e;

    /* Returns the gateway number associated with the provided gw */
    WALK_LIST(e, *gateway_list) {
        if (e->gw == gw) {
            return e->gw_num;
        }
    }

    return -1;
}

static void
meraki_notify(struct proto *P, rtable *src_table, net *n, rte *new UNUSED, rte *old UNUSED, ea_list *attrs UNUSED)
{
   unsigned peer_num, route_count = BIRD_EXPORTED_ROUTE_BEGIN;
   unsigned gw_count = BIRD_EXPORTED_GATEWAY_BEGIN;
   char ip_buf[STD_ADDRESS_P_LENGTH], source_key[BGP_SOURCE_KEY_LEN];
   list bgp_learned_gw_list;

   const char* outfile_tmp = BIRD_ROUTES_EXPORT_FILE ".tmp";
   const char* outfile = BIRD_ROUTES_EXPORT_FILE;

   FILE *out = fopen(outfile_tmp, "w");
   if (!out) {
      log("unable to open %s\n", outfile_tmp);
      return;
   }

   const char* info_outfile_tmp = BIRD_ROUTES_JSON_FILE ".tmp";
   const char* info_outfile = BIRD_ROUTES_JSON_FILE;
   int is_bgp_route = 0;

   FILE *info_out = fopen(info_outfile_tmp, "w");
   if (!info_out) {
      log("unable to open %s\n", info_outfile_tmp);
      // Not returning since writing this file is not critical
   } else {
       if (0 > fprintf(info_out,"{ \"routes\" : [")) {
           log("failed to write to %s!", info_outfile_tmp);
       }
   }

   // Keep track of all gateways.
   init_list(&bgp_learned_gw_list);

   FIB_WALK(&src_table->fib, fn)
   {
       n = (net *) fn;
       rte *e;
       for (e = n->routes; e; e=e->next) {
           if (e->net->routes != e) {
               //route is not "primary", ie it should not forward traffic
               continue;
           }
#ifdef IPV6
           ip6_ntop(n->n.prefix, ip_buf);
#else
           ip4_ntop(n->n.prefix, ip_buf);
#endif
           is_bgp_route = 0;
           if (sscanf(e->attrs->src->proto->name, "peer%u", &peer_num) > 0) {
               get_bgp_source_key(e, source_key, BGP_SOURCE_KEY_LEN, 'I');
               if (0 > fprintf(out,
                           "route%u:subnet %s/%d\n"
                           "route%u:type l3_vpn\n"
                           "route%u:l3_vpn_peer_num %u\n"
                           "route%u:metric %d\n"
                           "route%u:source src_bgp\n"
                           "route%u:source_key %s\n",
                           route_count, ip_buf, n->n.pxlen,
                           route_count,
                           route_count, peer_num,
                           route_count, BIRD_EXPORTED_ROUTE_METRIC,
                           route_count,
                           route_count, source_key)) {
                   log("failed to write to %s!", outfile_tmp);
               }
               route_count++;
               is_bgp_route = 1;
           } else if (sscanf(e->attrs->src->proto->name, "neighbor%u", &peer_num) > 0) {
               const struct meraki_config *c = (const struct meraki_config *) (P->cf);
               int gw_num = get_gateway_number(&c->gateway_list, e->attrs->gw);

               if (gw_num < 0) {
                   //
                   // Find or create a gateway since this is one that
                   // wired_brain doesn't already know about.
                   //
                   struct meraki_gw *mgw = meraki_gw_find(&bgp_learned_gw_list, e->attrs->gw);
                   if (mgw == NULL) {
                       char gw_buf[STD_ADDRESS_P_LENGTH];

                       // A new gateway to configure.
                       mgw = meraki_gw_create(P, e->attrs->gw, gw_count);
                       meraki_gw_add(&bgp_learned_gw_list, mgw);
                       gw_count++;
#ifdef IPV6
                       ip6_ntop(e->attrs->gw, gw_buf);
#else
                       ip4_ntop(e->attrs->gw, gw_buf);
#endif
                       if (0 > fprintf(out, "gateway%u:address %s\n",
                                       mgw->gw_num, gw_buf)) {
                           log("failed to write to %s!", outfile_tmp);
                       }
                   }
                   gw_num = mgw->gw_num;
               }

               get_bgp_source_key(e, source_key, BGP_SOURCE_KEY_LEN, 'E');
               if (0 > fprintf(out,
                           "route%u:subnet %s/%d\n"
                           "route%u:type static\n"
                           "route%u:static_gateway_num %u\n"
                           "route%u:metric %d\n"
                           "route%u:source src_bgp\n"
                           "route%u:source_key %s\n"
                           "vpn_joined_subnet%u:subnet %s/%d\n",
                           route_count, ip_buf, n->n.pxlen,
                           route_count,
                           route_count, gw_num,
                           route_count, BIRD_EXPORTED_ROUTE_METRIC,
                           route_count,
                           route_count, source_key,
                           route_count, ip_buf, n->n.pxlen)) {
                   log("failed to write to %s!", outfile_tmp);
               }
               route_count++;
               is_bgp_route = 1;
           }

           if (info_out && is_bgp_route) {
               if (0 > fprintf(info_out,
                           "{ \"prefix\" : \"%s\", "
                           "\"prefix_len\" : %d, "
                           "\"nexthops\" : [ "
                           "{\"src\" : \"BGP\","
                           "\"source_key\" : \"%s\", ",
                           ip_buf, n->n.pxlen, source_key)) {
                   log("failed to write to %s!", info_outfile_tmp);
               }
               write_bgp_info(e, info_out, info_outfile_tmp);
               if (0 > fprintf(info_out, " }] }\n,")) {
                   log("failed to write to %s!", info_outfile_tmp);
               }
           }
       }
   }
   FIB_WALK_END;

   fclose(out);
   log("%s: updating config file with %d routes", P->name,
       route_count - BIRD_EXPORTED_ROUTE_BEGIN);
   rename(outfile_tmp, outfile);

   if (info_out) {
       // To remove the trailing ',' when atleast one route info is written
       if (route_count > BIRD_EXPORTED_ROUTE_BEGIN) {
           fseek(info_out, -1, SEEK_CUR);
       }
       if (0 > fprintf(info_out,"] }")) {
           log("failed to write to %s!", info_outfile_tmp);
       }
       fclose(info_out);
       log("%s: updating route info file with %d routes", P->name,
               route_count - BIRD_EXPORTED_ROUTE_BEGIN);
       rename(info_outfile_tmp, info_outfile);
   }

   // Forget all gateways.
   meraki_gw_purge(&bgp_learned_gw_list);
}


static struct proto *
meraki_init(struct proto_config *C)
{
  struct meraki_config *c = (struct meraki_config *)C;
  struct proto *P = proto_new(C, sizeof(struct meraki_proto));
  struct meraki_proto *p = (struct meraki_proto *) P;

  //these will probably be useful later, but don't worry for now
  (void)c;
  (void)p;

  P->rt_notify = meraki_notify;
  P->accept_ra_types = RA_OPTIMAL;

  return P;
}

static int
meraki_start(struct proto *P)
{
    log("meraki_config starting!!");
    if (P->gr_recovery) {
        log("meraki_config waiting on graceful recovery");
        P->gr_wait = 1;
    }
    return PS_UP;
}

static int
meraki_reconfigure(struct proto *P UNUSED, struct proto_config *C UNUSED)
{
    log("meraki_config noop reconfigure");
    return 1;
}

struct protocol proto_meraki = {
  .name =        "Meraki Config",
  .template =    "meraki%d",
  .config_size =  sizeof(struct meraki_config),
  .init =         meraki_init,
  .start =        meraki_start,
  .reconfigure =  meraki_reconfigure,
};
