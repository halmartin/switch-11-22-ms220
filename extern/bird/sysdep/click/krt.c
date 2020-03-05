/*
 *  Meraki/Click BIRD route synchronizer
 *
 *  (c) 2014--2017 Cisco Systems, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "filter/filter.h"
#include "conf/conf.h"
#include "lib/eventlog.h"
#include "lib/string.h"

#include "unix.h"
#include "krt.h"
#include "sockproxy.h"

static bool defined = false;

void
krt_io_init(void)
{
}

static int
krt_capable(rte *e)
{
    rta *a = e->attrs;

    if (a->cast != RTC_UNICAST)
        return 0;

    switch (a->dest)
    {
    case RTD_ROUTER:
    case RTD_DEVICE:
        if (a->iface == NULL)
            return 0;
    case RTD_MULTIPATH:
        break;
    default:
        return 0;
    }
    return 1;
}

static int
rte_is_ospf(const rte* e)
{
    return (e->attrs->source == RTS_OSPF ||
            e->attrs->source == RTS_OSPF_IA ||
            e->attrs->source == RTS_OSPF_EXT1 ||
            e->attrs->source == RTS_OSPF_EXT2);
}

static void
krt_preconfig(struct protocol* p UNUSED, struct config* c UNUSED)
{
    defined = false;
}

static int
krt_import_control(struct proto *p, rte **new, ea_list **attrs UNUSED, struct linpool *pool UNUSED)
{
  rte *e = *new;
  struct krt_config* cf = (struct krt_config*)p->cf;
  struct krt_proto* kp = (struct krt_proto*)p;

  if (e->attrs->src->proto == p)
      return -1;

  if (!krt_capable(e))
      return -1;

  if (rte_is_ospf(e) && cf->reject_overlaps) {
      struct iface* iface;
      WALK_LIST(iface, iface_list) {
          struct ifa* ifa;
          WALK_LIST(ifa, iface->addrs) {
              if (ifa->pxlen != e->net->n.pxlen &&
                  net_in_net(e->net->n.prefix, e->net->n.pxlen,
                             ifa->prefix, ifa->pxlen)) {
                  log_event("ospf_route_iface_overlap",
                            "route_subnet='%I/%d' route_next_hop='%I' iface_subnet='%I/%d' vlan='%d'",
                            e->net->n.prefix, e->net->n.pxlen, e->attrs->gw, ifa->prefix, ifa->pxlen, iface->index);
                  return -1;
              }
          }
      }
  }

  if (cf->max_dynamic_routes &&
      kp->num_dynamic_routes >= cf->max_dynamic_routes &&
      rte_is_ospf(e) &&
      e->net->n.pxlen != 0 && // whitelist default route
      !(e->net->n.flags & KRF_INSTALLED)) {
      time_t current = time(NULL);
      if (difftime(current, kp->max_routes_event_time) >= cf->max_routes_event_timeout) {
          log_event("ospf_route_overflow", "subnet='%I/%d' next_hop='%I'",
                    e->net->n.prefix, e->net->n.pxlen, e->attrs->gw);
          kp->max_routes_event_time = current;
      }
      return -1;
  }

  return 0;
}

/**
 * Requires: 'route' is non NULL.
 *
 * Returns a non-zero value if 'route' is a multipath route (multiple next hops
 * exist for a given destination), 0 otherwise.
 */
static int
route_is_multipath(const rte *route)
{
    return route->attrs->dest == RTD_MULTIPATH
           && route->attrs->nexthops != NULL;
}

/**
 * Requires: 'p', 'route_info' are non NULL, and the value of 'action' is
 * either CLICK_ROUTE_ADD or CLICK_ROUTE_REMOVE.
 *
 * Writes the contents of 'route_info' to the appropriate Click handler
 * (either the add_route or the remove_route handler) based on the value of
 * 'action'.
 */
static void
write_route_to_click(const struct proto *p,
        const struct click_route_info *route_info,
        int action)
{
    const char *click_handler = NULL;
    char cbuf[MERAKI_CLICK_COMMAND_SIZE + 1];
    char prefix_str[STD_ADDRESS_P_LENGTH+1];
    char gateway_str[STD_ADDRESS_P_LENGTH+1];

    net *net = route_info->net;
#ifdef IPV6
    ip6_ntop(net->n.prefix, prefix_str);
    ip6_ntop(route_info->gateway, gateway_str);
#else
    ip4_ntop(net->n.prefix, prefix_str);
    ip4_ntop(route_info->gateway, gateway_str);
#endif
    /* Determine whether we're trying to add or remove a route */
    struct krt_config* const config = (struct krt_config *)p->cf;
    switch (action) {
    case CLICK_ROUTE_ADD:
        click_handler = config->add_handler;
        break;
    case CLICK_ROUTE_REMOVE:
        click_handler = config->remove_handler;
        break;
    default:
        bug("%s: Illegal Click route action: %d", action);
    }

    const char *action_str = action == CLICK_ROUTE_ADD ? "Adding" : "Removing";
    log(L_TRACE "%s: %s route %s/%d %s %s (vlan %d)", p->name, action_str,
            prefix_str, net->n.pxlen, gateway_str, route_info->ospf_src,
            route_info->vlan);

    int ret = snprintf(cbuf, MERAKI_CLICK_COMMAND_SIZE, "%s/%d %s %d %s %d",
            prefix_str, net->n.pxlen, gateway_str, route_info->vlan,
            route_info->ospf_src, route_info->multipath);
    if (ret > MERAKI_CLICK_COMMAND_SIZE) {
        log(L_ERR "%s: Command too long: click handler \"%s\", error: %m",
            p->name, click_handler, cbuf);
        return;
    }

    /* Push route info string to Click */
    if (meraki_click_write(click_handler, cbuf) != 0) {
        log(L_ERR "%s: Failed to write to route click handler \"%s\", error: %m",
            p->name, click_handler);
        return;
    }
}

/**
 * Requires: 'p', 'net', 'route' are non NULL, and the value of 'action' is
 * either CLICK_ROUTE_ADD or CLICK_ROUTE_REMOVE.
 *
 * Tells Click to either add or remove a route, depending on the 'action'.
 * The route information is derived from the information contained in 'net'
 * and 'route'.
 *
 * Does not assume ownership of 'net'.
 */
static void
push_route_info_to_click(const struct proto *p, net *net, const rte *route,
        int action)
{
    char ospf_src[16] = "0.0.0.0";
#ifdef CONFIG_OSPF
    if (rte_is_ospf(route))
        bsnprintf(ospf_src, sizeof(ospf_src), "%R", route->u.ospf.router_id);
#endif

    struct click_route_info route_info;
    memset(&route_info, 0, sizeof(route_info));
    route_info.net = net;
    route_info.ospf_src = ospf_src;

    if (route_is_multipath(route)) {
        route_info.multipath = 1;
        const struct mpnh *nexthop = route->attrs->nexthops;
        if (!nexthop)
            log(L_ERR "%s: Multipath route does not have Next Hops", p->name);
        for (; nexthop; nexthop = nexthop->next) {
            route_info.gateway = nexthop->gw;
            route_info.vlan = nexthop->iface->index;
            write_route_to_click(p, &route_info, action);
        }
    } else {
        route_info.multipath = 0;
        route_info.gateway = route->attrs->gw;
        route_info.vlan = route->attrs->iface->index;
        write_route_to_click(p, &route_info, action);
    }
}

static void
krt_notify(struct proto *p, struct rtable *table UNUSED, net *net,
       rte *new, rte *old, struct ea_list *eattrs UNUSED)
{
    struct krt_proto* kp = (struct krt_proto*)p;

    if (config->shutdown)
        return;

    if (old && (net->n.flags & KRF_INSTALLED)) {
        push_route_info_to_click(p, net, old, CLICK_ROUTE_REMOVE);
        net->n.flags &= ~KRF_INSTALLED;
        if (rte_is_ospf(old))
            kp->num_dynamic_routes--;
    }

    if (new && !(net->n.flags & KRF_INSTALLED)) {
        push_route_info_to_click(p, net, new, CLICK_ROUTE_ADD);
        net->n.flags |= KRF_INSTALLED;
        if (rte_is_ospf(new))
            kp->num_dynamic_routes++;
    }
}

static void
krt_flush_click_routes(struct proto* p)
{
    struct krt_config* cf = (struct krt_config*)p->cf;

    log(L_TRACE "%s: Flushing kernel routes", p->name);

    /* Contents of write are unimportant */
    if (meraki_click_write(cf->flush_handler, "true") !=0) {
        log(L_ERR "%s: Failed to write to route flush handler \"%s\", error: %m",
            p->name, cf->flush_handler);
        return;
    }
}

static void
krt_flush_routes(struct proto* p)
{
    struct krt_proto* kp = (struct krt_proto*)p;

    krt_flush_click_routes(p);
    FIB_WALK(&p->table->fib, f) {
        net* n = (net*)f;
        n->n.flags &= ~KRF_INSTALLED;
    }
    FIB_WALK_END;
    kp->num_dynamic_routes = 0;
}


static struct proto*
krt_init(struct proto_config *c)
{
    struct proto *p = proto_new(c, sizeof(struct krt_proto));

    p->accept_ra_types = RA_OPTIMAL;
    p->import_control = krt_import_control;
    p->rt_notify = krt_notify;

    // In case we crashed and left some cruft in the click tables.
    krt_flush_click_routes(p);

    return p;
}

static int
krt_start(struct proto *p UNUSED)
{
    return PS_UP;
}

static int
krt_shutdown(struct proto *p)
{
    krt_flush_routes(p);
    return PS_DOWN;
}

static int
krt_reconfigure(struct proto *p, struct proto_config *new)
{
    struct krt_config* cf = (struct krt_config*)p->cf;
    struct krt_config* new_cf = (struct krt_config*)new;

    /* If the dynamic route limit has changed, flush all routes and
       repopulate while enforcing the new limit */
    if (new_cf->max_dynamic_routes != cf->max_dynamic_routes) {
        krt_flush_routes(p);
        proto_request_feeding(p);
    }

    return 1;
}

static void
krt_copy_config(struct proto_config *dest, struct proto_config *src)
{
    /* Shallow copy of everything */
    proto_copy_rest(dest, src, sizeof(struct krt_config));
}

struct protocol proto_click_kernel = {
    .name =         "Kernel",
    .template =     "kernel%d",
    .attr_class =   EAP_KRT,
    .preference =   DEF_PREF_INHERITED,
    .config_size =  sizeof(struct krt_config),
    .preconfig =    krt_preconfig,
    .init =         krt_init,
    .start =        krt_start,
    .shutdown =     krt_shutdown,
    .reconfigure =  krt_reconfigure,
    .copy_config =  krt_copy_config,
};

struct proto_config *
krt_init_config(int class)
{
    if (defined)
        cf_error("Kernel protocol already defined");

    struct krt_config* cf;
    cf = (struct krt_config*)proto_config_new(&proto_click_kernel, class);

    if (!cf)
        cf_error("Unable to create krt_config");

    defined = true;
    return (struct proto_config*)cf;
}
