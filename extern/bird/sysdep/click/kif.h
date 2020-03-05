/*
 *  BIRD -- Meraki Kernel Route Syncer
 *
 *  (c) 1998--2000 Martin Mares <mj@ucw.cz>
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _BIRD_MERAKI_KIF_H_
#define _BIRD_MERAKI_KIF_H_

#include "lib/lists.h"
#include "lib/ip.h"

extern struct protocol proto_click_iface;

struct kif_config {
    struct proto_config c;
    list vlans;
    char* proxy_device;
    char* proxy_host;
    u16   proxy_port;
    char* add_memb_handler;
    char* remove_memb_handler;
};


struct kif_vlan_config {
    node n;
    char* name;
    u16 vid;
    u16 mtu;
    struct ifa addr;
};

extern struct proto_config* kif_init_config(int class);

#endif
