/*
 *	BIRD -- Click Kernel Syncer Configuration
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *      (c) 2014--2017 Cisco Systems, Inc.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "lib/krt.h"

CF_DEFINES

#define THIS_KRT ((struct krt_config *) this_proto)

CF_DECLS

CF_KEYWORDS(KERNEL, ROUTES, ADD, ROUTE, REMOVE, ROUTES, HANDLER, FLUSH)
CF_KEYWORDS(REJECT, OVERLAPS, MAX, EVENT, TIMEOUT, DYNAMIC)

CF_GRAMMAR

/* Kernel syncer protocol */

CF_ADDTO(proto, kern_proto '}')

kern_proto_start: proto_start KERNEL { this_proto = krt_init_config($1); }
 ;

CF_ADDTO(kern_proto, kern_proto_start proto_name '{')
CF_ADDTO(kern_proto, kern_proto proto_item ';')
CF_ADDTO(kern_proto, kern_proto kern_item ';')

kern_item:
 ADD ROUTE HANDLER TEXT { THIS_KRT->add_handler = $4; }
 | REMOVE ROUTE HANDLER TEXT { THIS_KRT->remove_handler = $4; }
 | FLUSH ROUTES HANDLER TEXT { THIS_KRT->flush_handler = $4; }
 | REJECT OVERLAPS { THIS_KRT->reject_overlaps = 1; }
 | MAX DYNAMIC ROUTES expr { THIS_KRT->max_dynamic_routes = $4; }
 | MAX ROUTES EVENT TIMEOUT expr { THIS_KRT->max_routes_event_timeout = $5; }
 ;

CF_CODE

CF_END
