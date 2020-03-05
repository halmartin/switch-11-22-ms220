#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "nest/cli.h"
#include "nest/route.h"
#include "nest/attrs.h"
#include "meraki.h"
#include "meraki_route.h"

#include "proto/bgp/bgp.h"

/* Use this code as a unique value for the "export route state" command. */
static const int export_route_state_cli_code = -1107;

char
get_bgp_origin_char(const eattr *origin_attr)
{
    if (!origin_attr) {
        log("Route received doesn't have origin attribute.");
        return '?';
    }
    switch (origin_attr->u.data) {
    case ORIGIN_IGP:
        return 'i';
    case ORIGIN_EGP:
        return 'e';
    case ORIGIN_INCOMPLETE:
    default:
        return '?';
    }
}

void
get_bgp_source_key(rte *e, char* source_key, int len, char bgp_type)
{
    struct bgp_proto *p = (struct bgp_proto *) (e->attrs->src->proto);
    bsnprintf(source_key, len, "BGP:%cBGP:%u:%I", bgp_type, p->remote_as, p->remote_id);
}

static const char *
rt_source_to_type(byte source)
{
    switch (source) {
    case RTS_DUMMY:
        return "dummy";
    case RTS_STATIC:
    case RTS_STATIC_DEVICE:
        return "static";
    case RTS_INHERIT:
        return "inherit";
    case RTS_DEVICE:
        return "device";
    case RTS_REDIRECT:
        return "redirect";
    case RTS_RIP:
        return "rip";
    case RTS_OSPF:
    case RTS_OSPF_IA:
    case RTS_OSPF_EXT1:
    case RTS_OSPF_EXT2:
        return "ospf";
    case RTS_BGP:
        return "bgp";
    case RTS_PIPE:
        return "pipe";
    case RTS_BABEL:
        return "babel";
    }
    return "???";
}

/* Similar to rt_show_net() */
static void
export_route_state_json_net(struct cli *c, net *n, struct rt_show_data *d)
{
    cli_printf(c, export_route_state_cli_code, "%s{\"prefix\": \"%I\", \"prefix_len\": %u, ",
               d->net_counter ? "" : ", ", n->n.prefix, n->n.pxlen);

    cli_printf(c, export_route_state_cli_code, "\"routes\": [ ");
    int first_route = 1;
    rte *e;
    for (e = n->routes; e; e = e->next) {
        rta *a = e->attrs;

        /* Assume connected until proven otherwise */
        int connected = 1;
        ea_list *attrs = a->eattrs;
        if (attrs) {
            eattr *meraki_not_conn_attr = ea_find(attrs, EA_MERAKI_NOT_CONN);
            if (meraki_not_conn_attr) {
                connected = 0;
            }
        }

        int primary = 0;
        if ((e->net->routes == e) && rte_is_valid(e)) {
            primary = 1;
        }

        cli_printf(c, export_route_state_cli_code,
                   "%s{"
                   "\"type\": \"%s\", "
                   "\"protocol_name\": \"%s\", "
                   "\"best\": %s, "
                   "\"connected\": %s, ",
                   first_route ? "" : ", ",
                   rt_source_to_type(a->source),
                   a->src->proto->name,
                   primary ? "true" : "false",
                   connected ? "true" : "false");

        switch (a->source) {
        case RTS_BGP: {
            byte as_path[ASPATH_BUF_LEN];
            char origin;
            char source_key[BGP_SOURCE_KEY_LEN];

            struct bgp_proto *p = (struct bgp_proto *) (a->src->proto);
            get_bgp_source_key(e, source_key, sizeof(source_key),
                               (p->local_as == p->remote_as) ? 'I' : 'E');

            eattr *origin_attr = ea_find(attrs, EA_CODE(EAP_BGP, BA_ORIGIN));
            eattr *aspath_attr = ea_find(attrs, EA_CODE(EAP_BGP, BA_AS_PATH));
            eattr *nexthop_attr = ea_find(attrs, EA_CODE(EAP_BGP, BA_NEXT_HOP));
            eattr *localpref_attr = ea_find(attrs, EA_CODE(EAP_BGP, BA_LOCAL_PREF));
            origin = get_bgp_origin_char(origin_attr);
            as_path_format(aspath_attr->u.ptr, as_path, ASPATH_BUF_LEN);

            /*
             * Extract the nexthop IP address.
             * See bgp_format_next_hop() for implementation reference.
             */
            ip_addr *ipp = (ip_addr *) nexthop_attr->u.ptr->data;
            byte nexthop[NEXTHOP_BUF_LEN];
#ifdef IPV6
            /* In IPv6, we might have two addresses in NEXT HOP */
            if ((nexthop_attr->u.ptr->length == NEXT_HOP_LENGTH)
                && ipa_nonzero(ipp[1])) {
                bsprintf(nexthop, "[\"%I\", \"%I\"]", ipp[0], ipp[1]);
            } else {
                bsprintf(nexthop, "[\"%I\"]", ipp[0]);
            }
#else
            bsprintf(nexthop, "[\"%I\"]", ipp[0]);
#endif
            cli_printf(c, export_route_state_cli_code,
                       "\"source\": \"src_bgp\", "
                       "\"source_key\": \"%s\", "
                       "\"bgp_info\": { \"origin\": \"%c\", "
                       "\"aspath\": \"%s\", "
                       "\"nexthop\": %s, "
                       "\"localpref\": %u}, ",
                       source_key, origin, as_path, nexthop, localpref_attr->u.data);
            break;
        }
        case RTS_OSPF:
            cli_printf(c, export_route_state_cli_code,
                       "\"source\": \"src_ospf\", "
                       "\"source_key\": \"SRC_OSPF\", ");
            break;
        default:
            cli_printf(c, export_route_state_cli_code,
                       "\"source\": \"src_unknown\", "
                       "\"source_key\": \"SRC_UNKNOWN\", ");
            break;
        }

        cli_printf(c, export_route_state_cli_code, "\"nexthops\": [ ");
        switch (a->dest) {
        case RTD_ROUTER:
            cli_printf(c, export_route_state_cli_code, "{\"nexthop\": \"%I\", \"interface\": \"%s\"}",
                       a->gw, a->iface->name);
            break;
        case RTD_DEVICE:
            cli_printf(c, export_route_state_cli_code, "{\"interface\": \"%s\"}",
                       a->iface->name);
            break;
        case RTD_MULTIPATH: {
            struct mpnh *nh;
            int first_nh = 1;
            for (nh = a->nexthops; nh; nh = nh->next) {
                cli_printf(c, export_route_state_cli_code, "%s{\"nexthop\": \"%I\", \"interface\": \"%s\"}",
                           first_nh ? "" : ", ", nh->gw, nh->iface->name);
                first_nh = 0;
            }
            break;
        }
        }
        cli_printf(c, export_route_state_cli_code, "] }");

        first_route = 0;
    }
    cli_printf(c, export_route_state_cli_code, " ] }");

    d->net_counter = 0;
}

/* Similar to rt_show_cont() */
static void
export_route_state_json_cont(struct cli *c)
{
    struct rt_show_data *d = c->rover;
#ifdef DEBUGGING
    unsigned max = 4;
#else
    unsigned max = 64;
#endif
    struct fib *fib = &d->table->fib;
    struct fib_iterator *it = &d->fit;

    FIB_ITERATE_START(fib, it, f) {
        net *n = (net *) f;
        if (!max--) {
            FIB_ITERATE_PUT(it, f);
            return;
        }
        export_route_state_json_net(c, n, d);
    }
    FIB_ITERATE_END(f);

    /* Close the array and object opened in export_route_state_json() */
    cli_printf(c, export_route_state_cli_code, " ] }");
    cli_printf(c, 0, "");

    c->cont = c->cleanup = NULL;
}

/* Similar to rt_show_cleanup() */
static void
export_route_state_json_cleanup(struct cli *c)
{
    struct rt_show_data *d = c->rover;

    /* Unlink the iterator */
    fit_get(&d->table->fib, &d->fit);
}

/* Similar to rt_show() */
void
export_route_state_json(struct rt_show_data *d)
{
    /* This will be closed in export_route_state_json_cont() */
    cli_msg(export_route_state_cli_code, "{ \"networks\": [ ");

    if (d->table == NULL) {
        d->table = config->master_rtc->table;
    }
    FIB_ITERATE_INIT(&d->fit, &d->table->fib);

    /*
     * This counter (used for another purpose in "show route") is used
     * as a "first_net" flag to guide the hand-crafted JSON output.
     */
    d->net_counter = 1;

    this_cli->cont = export_route_state_json_cont;
    this_cli->cleanup = export_route_state_json_cleanup;
    this_cli->rover = d;
}
