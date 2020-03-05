/*
 *  BIRD -- Meraki/Click Interface Synchronization
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <stdbool.h>
#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "filter/filter.h"
#include "conf/conf.h"
#include "lib/string.h"
#include "lib/socket.h"

#include "unix.h"
#include "kif.h"
#include "sysio.h"
#include <sockproxy.h>

static bool defined = false;

static bool
kif_populate_interfaces(struct proto* p, struct kif_config* cf)
{
    struct kif_vlan_config* vc;
    struct iface iface;
    struct sockproxy_cfg cfg = {0};

    int blksize = sizeof(struct sockproxy_iface);
    linpool* lp = lp_new(p->pool, blksize);
    if (!lp)
        return false;

    cfg.num_ifaces = 0;

    WALK_LIST(vc, cf->vlans) {
        cfg.num_ifaces++;
    }

    if (cfg.num_ifaces) {
        cfg.ifaces = lp_allocz(lp, sizeof(struct sockproxy_iface) * cfg.num_ifaces);
        if (cfg.ifaces == NULL) {
            rfree(lp);
            return false;
        }
    } else
        cfg.ifaces = NULL;

    struct sockproxy_iface* spif_idx = cfg.ifaces;

    if_start_update();

    WALK_LIST(vc, cf->vlans) {
        memset(&iface, 0, sizeof(iface));

        strncpy(iface.name, vc->name, sizeof(iface.name)-1);
        strncpy(spif_idx->name, vc->name, sizeof(spif_idx->name)-1);
        iface.flags = IF_ADMIN_UP | IF_LINK_UP | IF_BROADCAST | IF_MULTICAST | IF_MULTIACCESS;
        iface.mtu = vc->mtu;
        iface.index = vc->vid;
        spif_idx->vid = vc->vid;
        if_update(&iface);

        struct ifa addr = vc->addr;
        struct iface* stored_iface = if_find_by_index(vc->vid);
        addr.iface = stored_iface;
        ifa_update(&addr);
        set_inaddr(&spif_idx->addr, addr.ip);
        spif_idx++;
    }

    cfg.proxy_device = cf->proxy_device;
    cfg.proxy_host = cf->proxy_host;
    cfg.proxy_port = cf->proxy_port;
    cfg.add_membership_handler = cf->add_memb_handler;
    cfg.del_membership_handler = cf->remove_memb_handler;
    CSP_set_config(&cfg);

    if_end_update();
    rfree(lp);

    return true;
}

static struct proto *
kif_init(struct proto_config *c)
{
    return proto_new(c, sizeof(struct proto));
}

static void
kif_preconfig(struct protocol* p, struct config* c)
{
    defined = false;
}

static int
kif_start(struct proto *p)
{
    struct kif_config* kif_cf = (struct kif_config*)p->cf;

    if (!kif_populate_interfaces(p, kif_cf))
        return PS_DOWN;

    return PS_UP;
}

static int
kif_shutdown(struct proto *p)
{
    if_flush_ifaces(p);

    return PS_DOWN;
}

/**
 * Test two strings for equality, handling null pointers.
 */
static inline int
strings_are_equal(const char *p, const char *q)
{
    return (!p && !q) || (p && q && !strcmp(p, q));
}

static int
kif_reconfigure(struct proto *p, struct proto_config *new)
{
    struct kif_config *kif_cf_old = (struct kif_config*) p->cf;
    struct kif_config *kif_cf_new = (struct kif_config*) new;
    struct kif_vlan_config *vc;
    int num_old_itfs = 0;
    WALK_LIST(vc, kif_cf_old->vlans) {
        num_old_itfs++;
        bool found = false;
        struct kif_vlan_config *vc_new;
        WALK_LIST(vc_new, kif_cf_new->vlans) {
            if (strcmp(vc->name, vc_new->name) == 0 &&
                vc->vid == vc_new->vid &&
                vc->mtu == vc_new->mtu &&
                vc->addr.ip == vc_new->addr.ip &&
                vc->addr.pxlen == vc_new->addr.pxlen)
                found = true;
        }

        if (!found)
            return 0;
    }

    int num_new_itfs = 0;
    WALK_LIST(vc, kif_cf_new->vlans) {
        num_new_itfs++;
    }

    if (num_old_itfs != num_new_itfs ||
        !strings_are_equal(kif_cf_old->proxy_device, kif_cf_new->proxy_device) ||
        !strings_are_equal(kif_cf_old->proxy_host, kif_cf_new->proxy_host) ||
        kif_cf_old->proxy_port != kif_cf_new->proxy_port ||
        !strings_are_equal(kif_cf_old->add_memb_handler, kif_cf_new->add_memb_handler) ||
        !strings_are_equal(kif_cf_old->remove_memb_handler, kif_cf_new->remove_memb_handler))
        return 0;

    return 1;
}

static void
kif_copy_config(struct proto_config *dest, struct proto_config *src)
{
    struct kif_config *d = (struct kif_config *) dest;
    struct kif_config *s = (struct kif_config *) src;

    proto_copy_rest(dest, src, sizeof(struct kif_config));

    init_list(&d->vlans);
    cfg_copy_list(&d->vlans, &s->vlans, sizeof(struct kif_vlan_config));
}

struct protocol proto_click_iface = {
    .name =            "Device",
    .template =        "device%d",
    .preference =      DEF_PREF_DIRECT,
    .config_size =     sizeof(struct kif_config),
    .preconfig =       kif_preconfig,
    .init =            kif_init,
    .start =           kif_start,
    .shutdown =        kif_shutdown,
    .reconfigure =     kif_reconfigure,
    .copy_config =     kif_copy_config
};


struct proto_config*
kif_init_config(int class)
{
    if (defined)
        cf_error("Kernel device protocol already defined");

    struct kif_config* cf;
    cf = (struct kif_config*)proto_config_new(&proto_click_iface, class);

    if (!cf)
        cf_error("Unable to create krt_config");

    defined = true;
    return (struct proto_config*)cf;
}

struct ifa *
kif_choose_primary(struct iface *i)
{
    return HEAD(i->addrs);
}

