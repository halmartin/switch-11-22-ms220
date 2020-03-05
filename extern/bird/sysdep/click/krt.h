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

#ifndef _BIRD_MERAKI_KRT_H_
#define _BIRD_MERAKI_KRT_H_

#include <time.h>
#include "nest/route.h"

#define CLICK_ROUTE_ADD 1
#define CLICK_ROUTE_REMOVE 2

extern struct protocol proto_click_kernel;

struct krt_config {
    struct proto_config c;
    char* add_handler;
    char* remove_handler;
    char* flush_handler;
    int reject_overlaps;
    int max_dynamic_routes;
    int max_routes_event_timeout;
};

struct krt_proto {
    struct proto p;
    time_t max_routes_event_time;
    int num_dynamic_routes;
};

struct click_route_info {
    net *net;
    ip_addr gateway;
    unsigned vlan;
    char *ospf_src;
    int multipath;
};

extern struct proto_config* krt_init_config(int class);

#endif
