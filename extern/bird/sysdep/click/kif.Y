/*
 *  Meraki BIRD Kernel Syncer Configuration
 *
 *  Copyright (C) 2014--2017 Cisco Systems, Inc.
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

CF_HDR

#include "lib/kif.h"
#include "nest/iface.h"

CF_DEFINES

static struct kif_config* this_kif;
static struct kif_vlan_config* this_vlan;

static void
kif_interface_finish(void)
{
    struct kif_vlan_config* vc;

    if (this_vlan->vid == 0)
        cf_error("VID not specified for interface \"%s\"!", this_vlan->name);

    if (ipa_zero(this_vlan->addr.ip))
        cf_error("Interface \"%s\" has no addresses!", this_vlan->name);

    WALK_LIST(vc, this_kif->vlans) {
        if (strcmp(this_vlan->name, vc->name) == 0)
            cf_error("Duplicate VLAN interface name \"%s\" detected!", vc->name);

        if (this_vlan->vid == vc->vid)
            cf_error("Duplicate VID %hu detected!", vc->vid);
    }
    add_tail(&this_kif->vlans, NODE this_vlan);
}


CF_DECLS

CF_KEYWORDS(ADDR, VLAN, INTERFACE, VID, MTU, PROXY, DEVICE, HOST, PORT, SOCKETS, ADD, REMOVE, MEMBERSHIP, HANDLER)

CF_GRAMMAR

CF_ADDTO(proto, kif_proto)

kif_proto_start: proto_start DEVICE {
    this_proto = kif_init_config($1);
    this_kif = (struct kif_config*)this_proto;
    init_list(&this_kif->vlans);
}
 ;

kif_proto_item:
    proto_item
    | kif_interface
    | PROXY DEVICE TEXT { this_kif->proxy_device = $3; }
    | PROXY HOST TEXT { this_kif->proxy_host = $3; }
    | PROXY PORT expr { this_kif->proxy_port = $3; }
    | ADD MEMBERSHIP HANDLER TEXT { this_kif->add_memb_handler = $4; }
    | REMOVE MEMBERSHIP HANDLER TEXT { this_kif->remove_memb_handler = $4; }
 ;

kif_proto_opts:
    /* empty */
    | kif_proto_opts kif_proto_item ';'

kif_proto:
    kif_proto_start proto_name '{' kif_proto_opts '}'


kif_interface: kif_interface_start '{' kif_interface_opts '}' { kif_interface_finish(); }
 ;

kif_interface_opts:
    | kif_interface_opts kif_interface_item ';'
 ;


kif_interface_start: VLAN INTERFACE TEXT {
    this_vlan = cfg_allocz(sizeof(struct iface));
    this_vlan->name = $3;
    this_vlan->mtu = 1500;
}
 ;

kif_interface_item:
    VID expr {
        if ($2 <= 0 || $2 >= 4095) cf_error("Invalid VID %d", $2);
        this_vlan->vid = $2;
    }
    | ADDR ipa pxlen {
        if (ipa_nonzero(this_vlan->addr.ip))
            cf_error("Only one address per VLAN permitted.");

        if (ipa_zero($2) || $3 == 0)
            cf_error("Non-null address required for interface %s!", this_vlan->name);

        this_vlan->addr.ip = $2;
        this_vlan->addr.pxlen = $3;
        this_vlan->addr.prefix = ipa_and(this_vlan->addr.ip, ipa_mkmask(this_vlan->addr.pxlen));
        this_vlan->addr.brd = ipa_or(this_vlan->addr.prefix, ipa_not(ipa_mkmask(this_vlan->addr.pxlen)));
        this_vlan->addr.scope = IADDR_HOST | SCOPE_UNIVERSE;
    }
    | MTU expr {
        if ($2 < 1500 || $2 > 0xFFFF) cf_error("Invalid MTU");
        this_vlan->mtu = (u16)$2;
    }
 ;

CF_CODE

CF_END
