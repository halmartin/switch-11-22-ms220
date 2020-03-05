/*
 *  Click socket proxy
 *
 *  Copyright (C) 2014 Cisco Systems, Inc.
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


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <list>
#include <limits.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>

#include "sockproxy.h"
#include "sockproxy_pkt.h"
#include "sockproxy_int.hh"

SOCKPROXY_DECLS

SockproxyGlobals* g_csp = NULL;

int
_csp_set_config(const sockproxy_cfg* cfg)
{
    if (!cfg) {
        errno = EINVAL;
        return -1;
    }

    if (!g_csp)
        g_csp = new SockproxyGlobals;

    if (g_csp->fd_map.size() > 0) {
        errno = EBUSY;
        return -1;
    }

    if (g_csp->mcast_members.size() > 0) {
        // This should never happen if fd_map is empty.
        warning("CSP_set_config: fd_map is empty while mcast_members is not!");
        g_csp->mcast_members.clear();
    }

#ifndef SOCKPROXY_TEST
    bool config_is_valid = true;
    bool multicast_config_is_valid = true;

    if (!cfg->proxy_device && !cfg->proxy_host) {
        error("Missing \"proxy device\" or \"proxy host\"");
        config_is_valid = false;
    }

    if (cfg->proxy_device && cfg->proxy_host) {
        error("\"proxy device\" and \"proxy host\" are mutually exclusive");
        config_is_valid = false;
    }

    if (cfg->proxy_host && !cfg->proxy_port) {
        error("Missing or invalid \"proxy port\"");
        config_is_valid = false;
    }

    if (!cfg->add_membership_handler) {
        error("Missing add_membership_handler");
        config_is_valid = false;
    }

    if (!cfg->del_membership_handler) {
        error("Missing del_membership_handler");
        config_is_valid = false;
    }

#ifdef SOCKPROXY_HAS_MULTICAST
#define CHECK_MCAST_HANDLER(name) do { \
    if (!cfg-> name##_handler) { \
        warning("Missing " #name "_handler"); \
        multicast_config_is_valid = false; \
    } \
} while (0)

    CHECK_MCAST_HANDLER(add_mfc);
    CHECK_MCAST_HANDLER(del_mfc);
    CHECK_MCAST_HANDLER(add_vif);
    CHECK_MCAST_HANDLER(del_vif);
    CHECK_MCAST_HANDLER(init_mrt);
    CHECK_MCAST_HANDLER(init_pim);
    CHECK_MCAST_HANDLER(packet_count);

#undef CHECK_MCAST_HANDLER

#else
    multicast_config_is_valid = false;
#endif /* SOCKPROXY_HAS_MULTICAST */

    if (!config_is_valid) {
        errno = EINVAL;
        return -1;
    }
#endif

    InterfaceSet new_ifaces;
    AddressMap new_addrs;

    for (int i = 0; i < cfg->num_ifaces; i++) {
        if (!new_ifaces.insert(cfg->ifaces[i]).second) {
            error("Duplicate interface");
            errno = EINVAL;
            return -1;
        }
        new_addrs.emplace(cfg->ifaces[i].addr.s_addr, cfg->ifaces[i].vid);
    }

#ifdef SOCKPROXY_TEST
    g_csp->click_tunnel_fd = cfg->device_fd;
    g_csp->add_membership_fd = cfg->add_membership_fd;
    g_csp->del_membership_fd = cfg->del_membership_fd;
    g_csp->add_mfc_fd = cfg->add_mfc_fd;
    g_csp->del_mfc_fd = cfg->del_mfc_fd;
    g_csp->add_vif_fd = cfg->add_vif_fd;
    g_csp->del_vif_fd = cfg->del_vif_fd;
    g_csp->init_mrt_fd = cfg->init_mrt_fd;
    g_csp->init_pim_fd = cfg->init_pim_fd;
    g_csp->lookup_route_fd = cfg->lookup_route_fd;
    g_csp->packet_count_fd = cfg->packet_count_fd;
#else
    if (g_csp->click_tunnel_fd >= 0)
        close(g_csp->click_tunnel_fd);

    int fd;

    if (cfg->proxy_device) {
        fd = open(cfg->proxy_device, O_RDWR | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) {
            error("failed to open proxy device \"%s\": %s", cfg->proxy_device, strerror(errno));
            return -1;
        }
    } else if (cfg->proxy_host) {
        struct sockaddr_in remote_addr = {
            .sin_family = AF_INET,
            .sin_port = htons(cfg->proxy_port),
            .sin_addr = { .s_addr = 0 }
        };

        // NB: We require a dotted-quad IP to avoid potential DNS issues during switch initialization
        if (!inet_pton(AF_INET, cfg->proxy_host, &remote_addr.sin_addr)) {
            error("Invalid proxy host \"%s\": must be a dotted quad IPv4 address", cfg->proxy_host);
            errno = EINVAL;
            return -1;
        }

        fd = socket(AF_INET, SOCK_DGRAM, 0);

        if (fd < 0) {
            error("failed to create proxy socket: %s", strerror(errno));
            return -1;
        }
        if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
            error("failed to set proxy socket non-blocking: %s", strerror(errno));
            return -1;
        }
        if (connect(fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) < 0) {
            error("failed to connect proxy socket: %s", strerror(errno));
            return -1;
        }
    }

    g_csp->click_tunnel_fd = fd;
    g_csp->add_membership_handler = cfg->add_membership_handler;
    g_csp->del_membership_handler = cfg->del_membership_handler;
    if (multicast_config_is_valid) {
        g_csp->add_mfc_handler = cfg->add_mfc_handler;
        g_csp->del_mfc_handler = cfg->del_mfc_handler;
        g_csp->add_vif_handler = cfg->add_vif_handler;
        g_csp->del_vif_handler = cfg->del_vif_handler;
        g_csp->init_mrt_handler = cfg->init_mrt_handler;
        g_csp->init_pim_handler = cfg->init_pim_handler;
        g_csp->packet_count_handler = cfg->packet_count_handler;
        g_csp->multicast_routing_support = true;
    }
#endif /* SOCKPROXY_TEST */

    g_csp->ifaces.swap(new_ifaces);
    g_csp->addr_map.swap(new_addrs);
    g_csp->rand_seed = time(NULL) % UINT_MAX;

    return 0;
}

int
_csp_clear_config()
{
    if (g_csp) {
        delete g_csp;
        g_csp = 0;
    }

    return 0;
}


int
_csp_socket(int domain, int type, int protocol)
{
    if (!g_csp) {
        errno = ENXIO;
        return -1;
    }

    dbg("CSP_socket(domain=%d, type=%d, protocol=%d)", domain, type, protocol);
    if (domain != AF_INET) {
        return socket(domain, type, protocol);
    }

    if (type != SOCK_DGRAM && type != SOCK_RAW) {
        errno = ESOCKTNOSUPPORT;
        return -1;
    }

    if (type == SOCK_DGRAM) {
        if (protocol != IPPROTO_UDP && protocol != 0) {
            errno = EPROTOTYPE;
            return -1;
        }
        protocol = IPPROTO_UDP;
    }

    std::shared_ptr<Socket> s(new Socket);

    s->domain = domain;
    s->type = type;
    s->protocol = protocol;

    // We create a dummy socket in order to reserve a file descriptor
    // in the normal system namespace.
    s->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s->fd < 0)
        return -1;

    g_csp->fd_map.emplace(s->fd, s);

    return s->fd;
}

int
_csp_bind(int sockfd, struct sockaddr* addr, socklen_t addrlen)
{
    if (!g_csp)
        return bind(sockfd, addr, addrlen);

    FDMap::iterator it = g_csp->fd_map.find(sockfd);

    if (it == g_csp->fd_map.end())
        return bind(sockfd, addr, addrlen);

    std::shared_ptr<Socket> s = it->second;

    // Make sure addr is a sockaddr_in and socket isn't already bound.
    if (!addr || s->sa_bind.sin_port != 0) {
        errno = EINVAL;
        return -1;
    }

    if (addr->sa_family != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    if (addrlen != sizeof(struct sockaddr_in)) {
        errno = EINVAL;
        return -1;
    }

    struct sockaddr_in* addr_in = (struct sockaddr_in*)addr;

    // Make sure addr is a valid address to be bound.
    if (addr_in->sin_addr.s_addr != INADDR_ANY &&
        addr_in->sin_addr.s_addr != INADDR_BROADCAST &&
        !is_multicast(addr_in->sin_addr) &&
        !g_csp->addr_map.count(addr_in->sin_addr.s_addr)) {
        errno = EADDRNOTAVAIL;
        return -1;
    }

    // Make sure addr isn't already bound (or, if so, is eligible to
    // be reused).  For unicast addresses, only one socket can be
    // bound to an address/port combination unless ALL the sockets
    // that wish to use that address and port have SO_REUSEADDR set.
    // NOTE: Using INADDR_ANY or INADDR_BROADCAST is effectively the
    // same as binding to every address on the given port.
    if (s->type != SOCK_RAW && addr_in->sin_port != 0) {
        for (it = g_csp->fd_map.begin(); it != g_csp->fd_map.end(); it++) {
            std::shared_ptr<Socket> other_sock = it->second;
            if (other_sock != s &&
                (other_sock->sa_bind.sin_addr.s_addr == addr_in->sin_addr.s_addr ||
                 other_sock->sa_bind.sin_addr.s_addr == INADDR_ANY ||
                 other_sock->sa_bind.sin_addr.s_addr == INADDR_BROADCAST) &&
                other_sock->sa_bind.sin_port == addr_in->sin_port &&
                (!other_sock->reuse_addr || !s->reuse_addr)) {
                errno = EADDRINUSE;
                return -1;
            }
        }
    }

    memcpy(&s->sa_bind, addr_in, sizeof(struct sockaddr_in));

    return 0;
}

int
_csp_getsockname(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
    if (!g_csp)
        return getsockname(sockfd, addr, addrlen);

    FDMap::iterator it = g_csp->fd_map.find(sockfd);

    if (it == g_csp->fd_map.end())
        return getsockname(sockfd, addr, addrlen);

    if (!addr || !addrlen || *addrlen < sizeof(struct sockaddr_in)) {
        errno = EINVAL;
        return -1;
    }
    memcpy(addr, &it->second->sa_bind, sizeof(struct sockaddr_in));
    *addrlen = sizeof(struct sockaddr_in);

    return 0;
}


#ifdef SOCKPROXY_TEST
    int test_dup_print(int fd, const char* msg)
    {
        FILE* file = NULL;
        int new_fd = dup(fd);
        if (new_fd < 0) {
            error("%s: dup failed, errno = %m", __func__);
            return -1;
        }
        file = fdopen(new_fd, "w");
        if (!file) {
            error("%s: fdopen failed, errno = %m", __func__);
            return -1;
        }
        if (fprintf(file, "%s", msg) < 0) {
            error("%s: Error writing to test handler = %m", __func__);
            fclose(file);
            return -1;
        }
        fclose(file);
        return 0;
    }
#endif // SOCKPROXY_TEST


static int
add_multicast_group(std::shared_ptr<Socket> s, struct ip_mreqn* req)
{
    if (!req || !is_multicast(req->imr_multiaddr)) {
        errno = EINVAL;
        return -1;
    }

    uint16_t vid;
    // imr_ifindex gets priority, because that's what happens in the
    // Linux kernel.
    if (req->imr_ifindex != 0) {
        Interface iface;
        iface.vid = req->imr_ifindex;
        if (!g_csp->ifaces.count(iface)) {
            errno = ENODEV;
            return -1;
        }
        vid = req->imr_ifindex;
    } else if (req->imr_address.s_addr != INADDR_ANY) {
        AddressMap::iterator it = g_csp->addr_map.find(req->imr_address.s_addr);
        if (it == g_csp->addr_map.end()) {
            errno = ENODEV;
            return -1;
        }
        vid = it->second;
    } else {
        // Normally Linux would determine this via a route lookup.
        // But we're going to just enforce that an outgoing interface
        // be provided for simplicity.
        errno = ENODEV;
        return -1;
    }

    std::pair<MulticastMemberMap::iterator,
              MulticastMemberMap::iterator> range =
        g_csp->mcast_members.equal_range(AddrVlan(req->imr_multiaddr, vid));
    for (MulticastMemberMap::iterator it = range.first;
         it != range.second;
         it++) {
        if (it->second == s) {
            errno = EADDRINUSE;
            return -1;
        }
    }

    g_csp->mcast_members.emplace(AddrVlan(req->imr_multiaddr, vid), s);

    if (range.first != range.second)
        return 0;

    char maddr[20];
    inet_ntop(AF_INET, &req->imr_multiaddr, maddr, 20);

#ifdef SOCKPROXY_TEST
    int i = 0;
    char cbuf[MERAKI_CLICK_COMMAND_SIZE + 1];
    i = snprintf(cbuf, MERAKI_CLICK_COMMAND_SIZE, "GROUP_IP %s, VLAN %d", maddr, vid);
    if (i >= MERAKI_CLICK_COMMAND_SIZE) {
        error("%s: Handler command too long = %m", __func__);
        return -1;
    }

    if (test_dup_print(g_csp->add_membership_fd, cbuf) < 0)
        return -1;
#else
    int i = 0;
    char cbuf[MERAKI_CLICK_COMMAND_SIZE + 1];
    i = snprintf(cbuf, MERAKI_CLICK_COMMAND_SIZE, "GROUP_IP %s, VLAN %d", maddr, vid);
    if (i >= MERAKI_CLICK_COMMAND_SIZE) {
        error("%s: Handler command too long = %m", __func__);
        return -1;
    }

    if (meraki_click_write(g_csp->add_membership_handler.c_str(), cbuf) != 0) {
        error("%s: Error writing to add handler = %m: %s", __func__,
              g_csp->add_membership_handler.c_str());
        return -1;
    }
#endif

    return 0;
}

static int
drop_multicast_group(const AddrVlan& mm, std::shared_ptr<Socket> sock)
{
    std::pair<MulticastMemberMap::iterator, MulticastMemberMap::iterator> range =
        g_csp->mcast_members.equal_range(mm);

    if (range.first == range.second) {
        errno = EADDRNOTAVAIL;
        return -1;
    }

    MulticastMemberMap::iterator it;
    for (it = range.first; it != range.second; it++)
        if (it->second == sock)
            break;

    g_csp->mcast_members.erase(it);
    if (g_csp->mcast_members.count(mm) != 0)
        return 0;

    char maddr[20];
    inet_ntop(AF_INET, &mm.addr, maddr, 20);

#ifdef SOCKPROXY_TEST
    int i = 0;
    char cbuf[MERAKI_CLICK_COMMAND_SIZE + 1];
    i = snprintf(cbuf, MERAKI_CLICK_COMMAND_SIZE, "GROUP_IP %s, VLAN %d", maddr, mm.vlan);
    if (i >= MERAKI_CLICK_COMMAND_SIZE) {
        error("%s: Handler command too long = %m", __func__);
        return -1;
    }

    if (test_dup_print(g_csp->del_membership_fd, cbuf) < 0)
        return -1;
#else
    int i = 0;
    char cbuf[MERAKI_CLICK_COMMAND_SIZE + 1];
    i = snprintf(cbuf, MERAKI_CLICK_COMMAND_SIZE, "GROUP_IP %s, VLAN %d", maddr, mm.vlan);
    if (i >= MERAKI_CLICK_COMMAND_SIZE) {
        error("%s: Handler command too long = %m", __func__);
        return -1;
    }

    if (meraki_click_write(g_csp->del_membership_handler.c_str(), cbuf) != 0) {
        error("%s: Error writing to del handler = %m: %s", __func__,
              g_csp->del_membership_handler.c_str());
        return -1;
    }
#endif

    return 0;
}

static int
drop_multicast_group(std::shared_ptr<Socket> s, struct ip_mreqn* req)
{
    if (!req) {
        errno = EINVAL;
        return -1;
    }

    uint16_t vid;
    if (req->imr_ifindex != 0) {
        Interface iface;
        iface.vid = req->imr_ifindex;
        if (!g_csp->ifaces.count(iface)) {
            errno = ENODEV;
            return -1;
        }
        vid = req->imr_ifindex;
    } else if (req->imr_address.s_addr != INADDR_ANY) {
        AddressMap::iterator it = g_csp->addr_map.find(req->imr_address.s_addr);
        if (it == g_csp->addr_map.end()) {
            errno = ENODEV;
            return -1;
        }
        vid = it->second;
    } else {
        errno = ENODEV;
        return -1;
    }

    return drop_multicast_group(AddrVlan(req->imr_multiaddr, vid), s);
};

#ifdef SOCKPROXY_HAS_MULTICAST
static int
add_mfc(struct mfcctl *mc)
{
    int i = 0;
    char cbuf[MERAKI_CLICK_COMMAND_SIZE + 1];
    char srcaddr[INET_ADDRSTRLEN];
    char grpaddr[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &mc->mfcc_origin, srcaddr, INET_ADDRSTRLEN)) {
        error("%s: inet_ntop: %s", __func__, strerror(errno));
        return -1;
    }

    if (!inet_ntop(AF_INET, &mc->mfcc_mcastgrp, grpaddr, INET_ADDRSTRLEN)) {
        error("%s: inet_ntop: %s", __func__, strerror(errno));
        return -1;
    }

    i = snprintf(cbuf, MERAKI_CLICK_COMMAND_SIZE, "%s %s %u",
                 srcaddr, grpaddr, mc->mfcc_parent);
    if (i >= MERAKI_CLICK_COMMAND_SIZE) {
        error("%s: Handler command too long = %m", __func__);
        return -1;
    } else if (i < 0) {
        error("%s: snprintf: %s", __func__, strerror(errno));
        return -1;
    }

    for (vifi_t vifi = 0; vifi < MAXVIFS; ++vifi) {
        char ttl_buf[5]; // max ttl value: 255 plus a space and a null character
        int j = snprintf(ttl_buf, 5, "\n%u", mc->mfcc_ttls[vifi]);
        i += j;
        if (j >= 5 || i >= MERAKI_CLICK_COMMAND_SIZE) {
            error("%s: Handler command too long = %m", __func__);
            return -1;
        }
        strncat(cbuf, ttl_buf, j);
    }

#ifdef SOCKPROXY_TEST
    if (test_dup_print(g_csp->add_mfc_fd, cbuf) < 0)
        return -1;
#else
    if (meraki_click_write(g_csp->add_mfc_handler.c_str(), cbuf) != 0) {
        error("%s: Error writing to add handler = %m: %s", __func__,
              g_csp->add_mfc_handler.c_str());
        return -1;
    }
#endif // SOCKPROXY_TEST
    return 0;
}

static int
del_mfc(struct mfcctl *mc)
{
    int i = 0;
    char cbuf[MERAKI_CLICK_COMMAND_SIZE + 1];
    char srcaddr[INET_ADDRSTRLEN];
    char grpaddr[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &mc->mfcc_origin, srcaddr, INET_ADDRSTRLEN)) {
        error("%s: inet_ntop: %s", __func__, strerror(errno));
        return -1;
    }

    if (!inet_ntop(AF_INET, &mc->mfcc_mcastgrp, grpaddr, INET_ADDRSTRLEN)) {
        error("%s: inet_ntop: %s", __func__, strerror(errno));
        return -1;
    }

    i = snprintf(cbuf, MERAKI_CLICK_COMMAND_SIZE, "%s %s %u",
                 srcaddr, grpaddr, mc->mfcc_parent);
    if (i >= MERAKI_CLICK_COMMAND_SIZE) {
        error("%s: Handler command too long = %m", __func__);
        return -1;
    } else if (i < 0) {
        error("%s: snprintf: %s", __func__, strerror(errno));
        return -1;
    }

#ifdef SOCKPROXY_TEST
    if (test_dup_print(g_csp->del_mfc_fd, cbuf) < 0)
        return -1;
#else
    if (meraki_click_write(g_csp->del_mfc_handler.c_str(), cbuf) != 0) {
        error("%s: Error writing to del handler = %m: %s", __func__,
              g_csp->del_mfc_handler.c_str());
        return -1;
    }
#endif // SOCKPROXY_TEST
    return 0;
}

static int
add_vif(struct vifctl *vifc)
{
    int i = 0;
    char cbuf[MERAKI_CLICK_COMMAND_SIZE + 1];
    char addr[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &vifc->vifc_lcl_addr, addr, INET_ADDRSTRLEN)) {
        error("%s: inet_ntop: %s", __func__, strerror(errno));
        return -1;
    }

    i = snprintf(cbuf, MERAKI_CLICK_COMMAND_SIZE, "%s %02x %u %u %u",
                 addr, vifc->vifc_flags, vifc->vifc_threshold,
                 vifc->vifc_rate_limit, vifc->vifc_vifi);
    if (i >= MERAKI_CLICK_COMMAND_SIZE) {
        error("%s: Handler command too long = %m", __func__);
        return -1;
    } else if (i < 0) {
        error("%s: snprintf: %s", __func__, strerror(errno));
        return -1;
    }

#ifdef SOCKPROXY_TEST
    if (test_dup_print(g_csp->add_vif_fd, cbuf) < 0)
        return -1;
#else
    if (meraki_click_write(g_csp->add_vif_handler.c_str(), cbuf) != 0) {
        error("%s: Error writing to add handler = %m: %s", __func__,
              g_csp->add_vif_handler.c_str());
        return -1;
    }
#endif // SOCKPROXY_TEST
    return 0;
}

static int
del_vif(struct vifctl *vifc)
{
    int i = 0;
    char cbuf[MERAKI_CLICK_COMMAND_SIZE + 1];
    char addr[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &vifc->vifc_lcl_addr, addr, INET_ADDRSTRLEN)) {
        error("%s: inet_ntop: %s", __func__, strerror(errno));
        return -1;
    }

    i = snprintf(cbuf, MERAKI_CLICK_COMMAND_SIZE, "%s %02x %u %u %u",
                 addr, vifc->vifc_flags, vifc->vifc_threshold,
                 vifc->vifc_rate_limit, vifc->vifc_vifi);
    if (i >= MERAKI_CLICK_COMMAND_SIZE) {
        error("%s: Handler command too long = %m", __func__);
        return -1;
    } else if (i < 0) {
        error("%s: snprintf: %s", __func__, strerror(errno));
        return -1;
    }

#ifdef SOCKPROXY_TEST
    if (test_dup_print(g_csp->del_vif_fd, cbuf) < 0)
        return -1;
#else
    if (meraki_click_write(g_csp->del_vif_handler.c_str(), cbuf) != 0) {
        error("%s: Error writing to del handler = %m: %s", __func__,
              g_csp->del_vif_handler.c_str());
        return -1;
    }
#endif // SOCKPROXY_TEST
    return 0;
}
#endif /* SOCKPROXY_HAS_MULTICAST */

int
_csp_close(int fd)
{
    if (!g_csp)
        return close(fd);

    FDMap::iterator it = g_csp->fd_map.find(fd);

    if (it == g_csp->fd_map.end())
        return close(fd);

    std::shared_ptr<Socket> s = it->second;
    std::list<AddrVlan> to_delete;

    for (MulticastMemberMap::iterator it2 = g_csp->mcast_members.begin();
         it2 != g_csp->mcast_members.end();
         it2++) {
        if (it2->second == s) {
            to_delete.push_back(it2->first);
        }
    }

    for (std::list<AddrVlan>::iterator it2 = to_delete.begin();
         it2 != to_delete.end(); it2++)
        drop_multicast_group(*it2, s);

    g_csp->fd_map.erase(it);

    return 0;
}

int
_csp_setsockopt(int sockfd, int level, int optname,
                const void *optval, socklen_t optlen)
{
    if (!g_csp)
        return setsockopt(sockfd, level, optname, optval, optlen);

    FDMap::iterator it = g_csp->fd_map.find(sockfd);

    if (it == g_csp->fd_map.end())
        return setsockopt(sockfd, level, optname, optval, optlen);

    if (!optval && optlen != 0) {
        errno = EFAULT;
        return -1;
    }

    std::shared_ptr<Socket> s = it->second;
    if (level == SOL_SOCKET) {
        switch (optname) {
        case SO_BROADCAST:
            if (optlen != sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            s->broadcast = *(int*)optval;
            return 0;
        case SO_DONTROUTE:
            // We don't route any packets for now.
            if (optlen != sizeof(int) || !(*(int*)optval)) {
                errno = EINVAL;
                return -1;
            }
            return 0;
        case SO_REUSEADDR:
            if (s->type == SOCK_RAW) {
                errno = EOPNOTSUPP;
                return -1;
            }
            // We only allow this if the port hasn't been bound.
            if (optlen != sizeof(int) || s->sa_bind.sin_port != 0) {
                errno = EINVAL;
                return -1;
            }
            s->reuse_addr = *(int*)optval;
            return 0;
        case SO_PRIORITY:
            // Since we only support IP, this is the same as IP_TOS.
            if (optlen != sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            s->ip_tos = *(int*)optval;
            return 0;
        case SO_BINDTODEVICE: {
            const char* dev = static_cast<const char*>(optval);
            if (optlen == 0 || dev[0] == '\0') {
                s->bound_vlan = 0;
                return 0;
            }
            for (InterfaceSet::iterator it = g_csp->ifaces.begin(); it != g_csp->ifaces.end(); it++) {
                if (strnlen(dev, optlen) < optlen && it->name == dev) {
                    // This protects us from having vlan_mcast_send
                    // and bound_vlan set to different vlans.
                    if (s->vlan_mcast_send != it->vid &&
                        s->vlan_mcast_send != 0) {
                        errno = EINVAL;
                        return -1;
                    }
                    s->bound_vlan = it->vid;
                    return 0;
                }
            }
            errno = ENODEV;
            return -1;
        }
        default:
            errno = ENOPROTOOPT;
            return -1;
        }
    } else if (level == SOL_IP) {
        switch (optname) {
#ifdef SOCKPROXY_HAS_MULTICAST
        case MRT_ADD_MFC:
        case MRT_DEL_MFC:
            if (!g_csp->multicast_routing_support) {
                errno = ENOPROTOOPT;
                return -1;
            }
            if (optlen != sizeof(struct mfcctl)) {
                errno = EINVAL;
                return -1;
            }
            if (optname == MRT_ADD_MFC)
                return add_mfc((struct mfcctl *)optval);
            else
                return del_mfc((struct mfcctl *)optval);
        case MRT_ADD_VIF:
        case MRT_DEL_VIF:
            if (!g_csp->multicast_routing_support) {
                errno = ENOPROTOOPT;
                return -1;
            }
            if (optlen != sizeof(struct vifctl)) {
                errno = EINVAL;
                return -1;
            }
            if (optname == MRT_ADD_VIF)
                return add_vif((struct vifctl *)optval);
            else
                return del_vif((struct vifctl *)optval);
        case MRT_INIT:
            if (!g_csp->multicast_routing_support) {
                errno = ENOPROTOOPT;
                return -1;
            }
            if (optlen != sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            if (g_csp->mroute_sock_fd != -1) {
                errno = EADDRINUSE;
                return -1;
            }
#ifdef SOCKPROXY_TEST
            if (test_dup_print(g_csp->init_mrt_fd, "true") < 0)
                return -1;
#else
            if (meraki_click_write(g_csp->init_mrt_handler.c_str(), "true") < 0) {
                errno = ENODEV;
                return -1;
            }
#endif // SOCKPROXY_TEST
            g_csp->mroute_sock_fd = sockfd;
            return 0;
        case MRT_DONE:
            if (!g_csp->multicast_routing_support) {
                errno = ENOPROTOOPT;
                return -1;
            }
            if (g_csp->mroute_sock_fd != sockfd) {
                errno = EACCES;
                return -1;
            }
#ifdef SOCKPROXY_TEST
            if (test_dup_print(g_csp->init_mrt_fd, "false") < 0)
                return -1;
#else
            if (meraki_click_write(g_csp->init_mrt_handler.c_str(), "false") < 0) {
                errno = ENODEV;
                return -1;
            }
#endif // SOCKPROXY_TEST
            g_csp->mroute_sock_fd = -1;
            return 0;
        case MRT_PIM:
            if (!g_csp->multicast_routing_support) {
                errno = ENOPROTOOPT;
                return -1;
            }
            if (optlen != sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
#ifdef SOCKPROXY_TEST
            if (test_dup_print(g_csp->init_pim_fd, !!optval ? "true" : "false") < 0)
                return -1;
#else
            if (meraki_click_write(g_csp->init_pim_handler.c_str(), !!optval ? "true" : "false") < 0) {
                errno = ENODEV;
                return -1;
            }
#endif // SOCKPROXY_TEST
            return 0;
#endif /* SOCKPROXY_HAS_MULTICAST */
        case IP_ADD_MEMBERSHIP:
            if (optlen != sizeof(ip_mreqn)) {
                errno = EINVAL;
                return -1;
            }
            return add_multicast_group(s, (struct ip_mreqn*)optval);
        case IP_DROP_MEMBERSHIP:
            if (optlen != sizeof(ip_mreqn)) {
                errno = EINVAL;
                return -1;
            }
            return drop_multicast_group(s, (struct ip_mreqn*)optval);
        case IP_TOS:
            if (optlen != sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            s->ip_tos = *(int*)optval;
            return 0;
        case IP_HDRINCL:
            if (optlen != sizeof(int) || s->type != SOCK_RAW) {
                errno = EINVAL;
                return -1;
            }
            s->hdr_incl = *(int*)optval;
            return 0;
        case IP_PKTINFO:
            if (optlen != sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            s->ip_pktinfo = *(int*)optval;
            return 0;
        case IP_PMTUDISC:
            if (optlen != sizeof(int) || *(int*)optval != IP_PMTUDISC_DONT) {
                errno = EINVAL;
                return -1;
            }
            return 0;
        case IP_MULTICAST_LOOP:
            if (optlen != sizeof(int) &&
                optlen != sizeof(unsigned char)) {
                errno = EINVAL;
                return -1;
            }

            /* pimd will not work properly if sockproxy doesn't accept this
             * option. It sets IP_MULTICAST_LOOP before it sends any periodic
             * packet to an all_BLANK_hosts address i.e. IGMP queries, PIM
             * hellos, etc.
             *
             * pimd still functions properly if it does not receive these
             * loopback packets so skipping the implementation of this option.
             */
            return 0;
        case IP_MULTICAST_TTL:
            if (optlen != sizeof(int) &&
                optlen != sizeof(unsigned char)) {
                errno = EINVAL;
                return -1;
            }
            s->mcast_ttl = *(int*)optval;
            return 0;
        case IP_TTL:
            if (optlen != sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            s->ttl = *(int*)optval;
            return 0;
        case IP_MULTICAST_IF:
            if (optlen != sizeof(struct ip_mreqn) &&
                optlen != sizeof(struct in_addr)) {
                errno = EINVAL;
                return -1;
            }
            if (optlen == sizeof(struct ip_mreqn)) {
                struct ip_mreqn* mreq = (struct ip_mreqn*)optval;
                uint16_t vid = 0;
                if (mreq->imr_ifindex != 0) {
                    Interface iface;
                    iface.vid = mreq->imr_ifindex;
                    InterfaceSet::iterator it =
                        g_csp->ifaces.find(iface);
                    if (it == g_csp->ifaces.end() ||
                        (mreq->imr_address.s_addr != it->addr.s_addr &&
                         mreq->imr_address.s_addr != INADDR_ANY)) {
                        errno = EADDRNOTAVAIL;
                        return -1;
                    }
                    vid = mreq->imr_ifindex;
                } else if (mreq->imr_address.s_addr != INADDR_ANY) {
                    AddressMap::iterator it =
                        g_csp->addr_map.find(mreq->imr_address.s_addr);
                    if (it == g_csp->addr_map.end()) {
                        errno = EADDRNOTAVAIL;
                        return -1;
                    }
                    vid = it->second;
                }
                if (vid != 0 && s->bound_vlan != 0 && s->bound_vlan != vid) {
                    errno = EINVAL;
                    return -1;
                }
                s->vlan_mcast_send = vid;
                s->addr_mcast_send = mreq->imr_address;
            } else if (optlen == sizeof(struct in_addr)) {
                s->addr_mcast_send = *(struct in_addr*)optval;
                AddressMap::iterator it =
                    g_csp->addr_map.find(s->addr_mcast_send.s_addr);
                if (it == g_csp->addr_map.end()) {
                    errno = EADDRNOTAVAIL;
                    return -1;
                }
                uint16_t vid = it->second;
                if (vid != 0 && s->bound_vlan != 0 && s->bound_vlan != vid) {
                    errno = EINVAL;
                    return -1;
                }
                s->vlan_mcast_send = vid;
            }
            return 0;
        default:
            errno = ENOPROTOOPT;
            return -1;
        }
    } else {
        errno = ENOPROTOOPT;
        return -1;
    }
}

int
_csp_getsockopt(int sockfd, int level, int optname,
                void *optval, socklen_t* optlen)
{
    if (!g_csp)
        return getsockopt(sockfd, level, optname, optval, optlen);

    FDMap::iterator it = g_csp->fd_map.find(sockfd);

    if (it == g_csp->fd_map.end())
        return getsockopt(sockfd, level, optname, optval, optlen);

    if ((!optval && optlen && *optlen != 0) ||
        (optval && !optlen)) {
        errno = EFAULT;
        return -1;
    }

    std::shared_ptr<Socket> s = it->second;
    if (level == SOL_SOCKET) {
        switch (optname) {
        case SO_BROADCAST:
            if (*optlen < sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            *(int*)optval = s->broadcast;
            *optlen = sizeof(int);
            return 0;
        case SO_DONTROUTE:
            // We don't route any packets for now.
            if (*optlen < sizeof(int) || !(*(int*)optval)) {
                errno = EINVAL;
                return -1;
            }
            *(int*)optval = 1;
            *optlen = sizeof(int);
            return 0;
        case SO_REUSEADDR:
            if (*optlen < sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            *(int*)optval = s->reuse_addr;
            *optlen = sizeof(int);
            return 0;
        case SO_PRIORITY:
            // Since we only support IP, this is the same as IP_TOS.
            if (*optlen < sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            *(int*)optval = s->ip_tos;
            *optlen = sizeof(int);
            return 0;
        case SO_BINDTODEVICE: {
            char* dev = static_cast<char*>(optval);
            socklen_t len = *optlen;
            *optlen = 0;
            memset(dev, 0, len);
            if (s->bound_vlan == 0)
                return 0;

            Interface iface;
            iface.vid = s->bound_vlan;
            InterfaceSet::iterator it = g_csp->ifaces.find(iface);
            if (it != g_csp->ifaces.end()) {
                int name_len = it->name.length() + 1;
                strncpy(dev, it->name.c_str(), len);
                *optlen = (len < name_len ? len : name_len);
            }

            return 0;
        }
        default:
            errno = ENOPROTOOPT;
            return -1;
        }
    } else if (level == SOL_IP) {
        switch (optname) {
        case IP_TOS:
            if (*optlen < sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            *(int*)optval = s->ip_tos;
            *optlen = sizeof(int);
            return 0;
        case IP_HDRINCL:
            if (*optlen < sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            *(int*)optval = s->hdr_incl;
            *optlen = sizeof(int);
            return 0;
        case IP_PKTINFO:
            if (*optlen < sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            *(int*)optval = s->ip_pktinfo;
            *optlen = sizeof(int);
            return 0;
        case IP_PMTUDISC:
            if (*optlen < sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            *(int*)optval = IP_PMTUDISC_DONT;
            *optlen = sizeof(int);
            return 0;
        case IP_MULTICAST_LOOP:
            if (*optlen < sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            *(int*)optval = 0;
            *optlen = sizeof(int);
            return 0;
        case IP_MULTICAST_TTL:
            if (*optlen < sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            *(int*)optval = s->mcast_ttl;
            *optlen = sizeof(int);
            return 0;
        case IP_TTL:
            if (*optlen < sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            *(int*)optval = s->ttl;
            *optlen = sizeof(int);
            return 0;
        case IP_MULTICAST_IF:
            if (*optlen < sizeof(struct ip_mreqn)) {
                errno = EINVAL;
                return -1;
            } else {
                struct ip_mreqn* mreq = (struct ip_mreqn*)optval;
                mreq->imr_ifindex = s->vlan_mcast_send;
                mreq->imr_address = s->addr_mcast_send;
                *optlen = sizeof(struct ip_mreqn);
            }
            return 0;
        default:
            errno = ENOPROTOOPT;
            return -1;
        }
    } else {
        errno = ENOPROTOOPT;
        return -1;
    }
}

int
_csp_fcntl_int(int fd, int cmd, int optval)
{
    if (!g_csp)
        return fcntl(fd, cmd, optval);

    FDMap::iterator it = g_csp->fd_map.find(fd);

    if (it == g_csp->fd_map.end())
        return fcntl(fd, cmd, optval);

    switch (cmd) {
    case F_SETFL:
        it->second->fd_flags = optval;
        return 0;
    case F_GETFL:
        return it->second->fd_flags;
    default:
        errno = EINVAL;
        return -1;
    }
}

#ifdef SOCKPROXY_HAS_MULTICAST
/*
 * parse packet_count_handler response of the form:
 * "<packet count> <byte count> <wrong interface count>"
 */
static int
parse_packet_count_response(char *rbuf, unsigned long int *pktcnt,
        unsigned long int *bytecnt, unsigned long int *wrong_if)
{
    char *token = strtok(rbuf, " ");
    if (token == NULL)
        return -1;
    *pktcnt = atol(token);

    token = strtok(NULL, " ");
    if (token == NULL)
        return -1;
    *bytecnt = atol(token);

    token = strtok(NULL, " ");
    if (token == NULL)
        return -1;
    *wrong_if = atol(token);

    return 0;
}

static int
get_sg_count(struct sioc_sg_req *sr)
{
    char cbuf[MERAKI_CLICK_COMMAND_SIZE + 1];
    char src_addr[INET_ADDRSTRLEN];
    char grp_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sr->src, src_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &sr->grp, grp_addr, INET_ADDRSTRLEN);
    int i = snprintf(cbuf, MERAKI_CLICK_COMMAND_SIZE, "%s %s", src_addr, grp_addr);
    if (i >= MERAKI_CLICK_COMMAND_SIZE) {
        errno = EINVAL;
        return -1;
    }

    char rbuf[MERAKI_CLICK_COMMAND_SIZE + 1];
    size_t bytes_read = 0;
#ifdef SOCKPROXY_TEST
    FILE* file = NULL;
    int new_fd = dup(g_csp->init_pim_fd);
    if (new_fd < 0) {
        error("%s: dup failed, errno = %m", __func__);
        return -1;
    }
    file = fdopen(new_fd, "w");
    if (!file) {
        error("%s: fdopen failed, errno = %m", __func__);
        return -1;
    }
    if (fread(rbuf, sizeof(char), MERAKI_CLICK_COMMAND_SIZE + 1, file) < 0) {
        error("%s: Error writing to test handler = %m", __func__);
        fclose(file);
        return -1;
    }
    fclose(file);
#else
    if (meraki_click_read(rbuf, MERAKI_CLICK_COMMAND_SIZE, g_csp->packet_count_handler.c_str(), cbuf, &bytes_read) != 0) {
        error("%s: Error reading from handler = %m: %s", __func__, g_csp->packet_count_handler.c_str());
        return -1;
    }
#endif // SOCKPROXY_TEST
    if (parse_packet_count_response(rbuf, &sr->pktcnt, &sr->bytecnt, &sr->wrong_if) < 0) {
        errno = EADDRNOTAVAIL;
        return -1;
    }
    return 0;
}
#endif /* SOCKPROXY_HAS_MULTICAST */

int
_csp_ioctl(int fd, unsigned long int request, void *arg)
{
    switch(request) {
#ifdef SOCKPROXY_HAS_MULTICAST
        case SIOCGETSGCNT:
            if (!g_csp->multicast_routing_support) {
                errno = ENOPROTOOPT;
                return -1;
            }
            return get_sg_count((struct sioc_sg_req *)arg);
#endif /* SOCKPROXY_HAS_MULTICAST */
        default:
            errno = ENOPROTOOPT;
            return -1;
    }
}

SOCKPROXY_ENDDECLS
