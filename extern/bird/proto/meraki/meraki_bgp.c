#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/cli.h"
#include "proto/bgp/bgp.h"
#include "meraki_bgp.h"

/* Meraki-specific code */

struct bgp_meraki_sh_peer_json_context {
    int opened;
    int opened_peers;
};

static int
bgp_meraki_sh_peer_json(const struct proto *P, void *ctx)
{
    struct bgp_proto *p = NULL;
    struct bgp_meraki_sh_peer_json_context *context = ctx;

    if (P == NULL) {
        /* Walk is done, close any open containers */
        if (context->opened_peers) {
            cli_msg(-1106, "]");
        }
        cli_msg(-1106, "}");
        cli_msg(0, "");
        return 1;
    }

    if (!context->opened) {
        /* Open the outermost container */
        cli_msg(-1106, "{");
        context->opened = 1;
    }

    if (P->proto != &proto_bgp) {
        /* Skip this one */
        return 1;
    }

    p = (struct bgp_proto *) P;

    if (!context->opened_peers) {
        cli_msg(-1106, "\"peers\": [");
    }
    cli_msg(-1106, "%s{ "
            "\"type\":\"%s\", "
            "\"remote_as_number\":%u, "
            "\"remote_address\":\"%I\", "
            "\"state\":\"%s\", "
            "\"exported_routes\":%u, "
            "\"imported_routes\":%u "
            "}",
            context->opened_peers ? ", " : "",
            p->is_internal ? "IBGP" : "EBGP",
            p->remote_as, p->cf->remote_ip,
            bgp_state_dsc(p),
            P->stats.exp_routes,
            P->stats.imp_routes);
    if (!context->opened_peers) {
        context->opened_peers = 1;
    }

    return 1;
}

void
bgp_meraki_sh_peers_json(void)
{
    struct bgp_meraki_sh_peer_json_context context;
    context.opened = context.opened_peers = 0;
    proto_walk(bgp_meraki_sh_peer_json, &context);
}
