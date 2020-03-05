CF_HDR

#include "proto/meraki/meraki_gw.h"
#include "proto/meraki/meraki.h"
#include "proto/meraki/meraki_bgp.h"
#include "proto/meraki/meraki_route.h"

CF_DEFINES

#define MERAKI_CFG ((struct meraki_config *) this_proto)

CF_DECLS

CF_KEYWORDS(MERAKI, GATEWAYS)
CF_KEYWORDS(MERAKI_NOT_CONN)

%type <ra> ers_args

CF_GRAMMAR

CF_ADDTO(proto, meraki_proto '}')

meraki_proto_start: proto_start MERAKI {
     this_proto = proto_config_new(&proto_meraki, $1);
     init_list(&MERAKI_CFG->gateway_list);
  }
 ;

meraki_proto:
   meraki_proto_start proto_name '{'
 | meraki_proto meraki_proto_item ';'
 ;

meraki_proto_item:
   proto_item
 | GATEWAYS '{' meraki_gateway_list '}'
 ;

meraki_gateway_list:
 /* empty */
 | meraki_gateway_list meraki_gateway_item
 ;

meraki_gateway_item: meraki_gateway_base ';' ;

meraki_gateway_base: expr ipa
 {
   struct meraki_gw *gateway =
       cfg_allocz(sizeof(struct meraki_gw));
   add_tail(&MERAKI_CFG->gateway_list, NODE gateway);
   gateway->gw_num = $1;
   gateway->gw = $2;
 }
;

CF_CLI_HELP(EXPORT BGP, ..., [[Export information about BGP protocol]]);
CF_CLI(EXPORT BGP PEERS,,, [[Export information about BGP peers in JSON]])
{ bgp_meraki_sh_peers_json(); };

CF_CLI_HELP(EXPORT ROUTE, ..., [[Export routing table]])
CF_CLI(EXPORT ROUTE STATE, ers_args, [table <t>], [[Export routing table in JSON]])
{
    export_route_state_json($4);
} ;

ers_args:
   /* empty */ {
     $$ = cfg_allocz(sizeof(struct rt_show_data));
   }
 | ers_args TABLE SYM {
     $$ = $1;
     if ($3->class != SYM_TABLE) cf_error("%s is not a table", $3->name);
     $$->table = ((struct rtable_config *)$3->def)->table;
   }
 ;

CF_ADDTO(dynamic_attr, MERAKI_NOT_CONN { $$ = f_new_dynamic_attr(EAF_TYPE_INT | EAF_TEMP, T_INT, EA_MERAKI_NOT_CONN); })

CF_CODE

CF_END
