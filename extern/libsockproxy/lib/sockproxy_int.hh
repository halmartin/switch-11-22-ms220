/*
 *  Click socket proxy -- internal header
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

#ifndef SOCKPROXY_INT_HH
#define SOCKPROXY_INT_HH

#include <string>
#include <memory>
#include <queue>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <map>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#ifdef __linux__
#define _LINUX_IN_H             /* For Linux <= 2.6.25 */
#include <linux/types.h>
#include <linux/mroute.h>

#define SOCKPROXY_HAS_MULTICAST

#endif /* __linux__ */
#include "sockproxy_pkt.h"

#define SOCKPROXY_DECLS       namespace CSP {
#define SOCKPROXY_ENDDECLS    }
#define SOCKPROXY_USING_DECLS using namespace CSP;
#define SOCKPROXY_NAME(x)     ::CSP::x

SOCKPROXY_DECLS

static const size_t MAX_PACKET_LEN = 65535;
static const int MAX_QUEUE_SIZE = 30;

// The IANA ephemeral port range
static const uint16_t EPHEMERAL_PORT_MIN = 49152;
static const uint16_t EPHEMERAL_PORT_MAX = 65535;

struct Interface {
    std::string name;
    struct in_addr addr;
    uint16_t vid;

    struct Hasher {
        size_t operator()(const Interface& iface) const throw() {
            return iface.vid;
        }
    };

    struct HashEqual {
        bool operator()(const Interface& iface1, const Interface& iface2) const throw() {
            return (iface1.vid == iface2.vid);
        }
    };

    Interface() {}
    Interface(const sockproxy_iface& iface)  : name(iface.name), vid(iface.vid),
                                               addr(iface.addr) {}
    Interface(const Interface& src) : name(src.name), vid(src.vid), addr(src.addr) {}
};


struct AddrVlan {
    struct in_addr addr;
    uint16_t vlan;
    struct Hasher {
        size_t operator()(const AddrVlan& av) const throw() {
            // We're mainly using this for multicast addresses, for which
            // the upper 3 bytes are rarely different.  So XORing
            // the VID there makes for a very efficient hash function.
            // Remember that struct in_addr is always big-endian.
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            return (av.addr.s_addr ^ av.vlan);
#else
            return (av.addr.s_addr ^ ((uint32_t)av.vlan << 24));
#endif
        }
    };

    struct Equal {
        size_t operator()(const AddrVlan& av1, const AddrVlan& av2) const throw() {
            return (av1.addr.s_addr == av2.addr.s_addr && av1.vlan == av2.vlan);
        }
    };

    AddrVlan(const struct in_addr& addr, uint16_t vlan) : addr(addr), vlan(vlan) {}
};

struct Socket {
    int fd;
    int domain;
    int type;
    int protocol;
    struct sockaddr_in sa_bind;
    int fd_flags;
    std::queue< std::shared_ptr<std::vector<uint8_t> > > recv_queue;
    bool broadcast;
    bool hdr_incl;
    int ip_tos;
    bool ip_pktinfo;
    int ttl;
    int mcast_ttl;
    uint16_t bound_vlan;
    uint16_t vlan_mcast_send;
    struct in_addr addr_mcast_send;
    bool reuse_addr;

    uint32_t rx_packets;
    uint32_t rx_dropped_packets;
    uint32_t tx_packets;

    Socket() : fd(-1), domain(0), type(0), protocol(0), fd_flags(0),
               broadcast(false), hdr_incl(false), ip_tos(0), ip_pktinfo(false),
               ttl(64), mcast_ttl(1), bound_vlan(0), vlan_mcast_send(0),
               reuse_addr(false), rx_packets(0), rx_dropped_packets(0),
               tx_packets(0) {
        memset(&sa_bind, 0, sizeof(sa_bind));
        memset(&addr_mcast_send, 0, sizeof(addr_mcast_send));
    }

    ~Socket() {
        if (fd >= 0)
            close(fd);
    }

};

#define CSP_IP_OFFSET   (sizeof(sockproxy_pkt_hdr))

inline size_t get_ip_payload_offset(struct iphdr* ip_hdr)
{
    return CSP_IP_OFFSET + (ip_hdr->ihl * 4);
}

inline size_t get_udp_payload_offset(struct iphdr* ip_hdr)
{
    return get_ip_payload_offset(ip_hdr) + sizeof(struct udphdr);
}


typedef std::unordered_map<int, std::shared_ptr<Socket> > FDMap;
typedef std::unordered_map<in_addr_t, uint16_t> AddressMap;
typedef std::unordered_multimap<AddrVlan, std::shared_ptr<Socket>, AddrVlan::Hasher, AddrVlan::Equal > MulticastMemberMap;
typedef std::unordered_set<Interface, Interface::Hasher, Interface::HashEqual> InterfaceSet;

struct SockproxyGlobals {
    FDMap fd_map;
    AddressMap addr_map;
    MulticastMemberMap mcast_members;
    InterfaceSet ifaces;
    int mroute_sock_fd;

#ifdef SOCKPROXY_TEST
    int add_membership_fd;
    int del_membership_fd;
    int add_mfc_fd;
    int del_mfc_fd;
    int add_vif_fd;
    int del_vif_fd;
    int init_mrt_fd;
    int init_pim_fd;
    int lookup_route_fd;
    int packet_count_fd;
#else
    std::string add_membership_handler;
    std::string del_membership_handler;
    std::string add_mfc_handler;
    std::string del_mfc_handler;
    std::string add_vif_handler;
    std::string del_vif_handler;
    std::string init_mrt_handler;
    std::string init_pim_handler;
    std::string packet_count_handler;
#endif

    int click_tunnel_fd;
    unsigned int rand_seed;
    bool multicast_routing_support;

    uint32_t rx_packets;
    uint32_t rx_undelivered_packets;
    uint32_t tx_packets;

    SockproxyGlobals() : click_tunnel_fd(-1), rx_packets(0),
                         rx_undelivered_packets(0), tx_packets(0),
                         multicast_routing_support(false), mroute_sock_fd(-1) {}
};

extern SockproxyGlobals* g_csp;
extern csp_debug_fn g_csp_debug_fn;

static inline bool
is_multicast(uint32_t addr) throw()
{
    return ((addr & htonl(0xf0000000)) == htonl(0xe0000000));
}

static inline bool
is_multicast(struct in_addr addr) throw()
{
    return is_multicast(addr.s_addr);
}

static inline void
dbg(const char* format, ...) throw()
{
    if (!g_csp_debug_fn)
        return;

    va_list va;
    va_start(va, 0);
    (*g_csp_debug_fn)(CSP_DEBUG_MSG, format, va);
    va_end(va);
}

static inline void
warning(const char* format, ...) throw()
{
    if (!g_csp_debug_fn)
        return;

    va_list va;
    va_start(va, 0);
    (*g_csp_debug_fn)(CSP_DEBUG_WARN, format, va);
    va_end(va);
}

static inline void
error(const char* format, ...) throw()
{
    if (!g_csp_debug_fn)
        return;

    va_list va;
    va_start(va, format);
    (*g_csp_debug_fn)(CSP_DEBUG_ERR, format, va);
    va_end(va);
}

static inline void
critical(const char* format, ...) throw()
{
    if (!g_csp_debug_fn)
        return;

    va_list va;
    va_start(va, format);
    (*g_csp_debug_fn)(CSP_DEBUG_CRIT, format, va);
    va_end(va);
}

int _csp_set_config(const sockproxy_cfg* cfg);
int _csp_clear_config();
int _csp_socket(int domain, int type, int protocol);
int _csp_bind(int sockfd, struct sockaddr* addr, socklen_t addrlen);
int _csp_getsockname(int sockfd, struct sockaddr* addr, socklen_t* addrlen);
ssize_t _csp_sendmsg(int sockfd, const struct msghdr* msg, int flags);
ssize_t _csp_sendto(int sockfd, const void* buf, size_t len, int flags,
                    const struct sockaddr* dest_addr, socklen_t addrlen);
ssize_t _csp_recvmsg(int sockfd, struct msghdr* msg, int flags);
ssize_t _csp_recvfrom(int sockfd, void* buf, size_t len, int flags,
                      struct sockaddr* src_addr, socklen_t* addrlen);
int _csp_close(int fd);
int _csp_setsockopt(int sockfd, int level, int optname,
                    const void *optval, socklen_t optlen);
int _csp_getsockopt(int sockfd, int level, int optname,
                    void *optval, socklen_t* optlen);
int _csp_select(int nfds, fd_set* read_fds, fd_set* write_fds,
                fd_set* except_fds, struct timeval* timeout);
int _csp_fcntl_int(int fd, int cmd, int optval);
int _csp_ioctl(int fd, unsigned long int request, void *arg);
int _csp_read(int fd, void* buf, size_t count);
int _csp_write(int fd, const void* buf, size_t count);

int _csp_get_open_sockets(int* fds, socklen_t* count);
int _csp_get_stats(struct sockproxy_stats* stats);
int _csp_get_socket_stats(int fd, struct sockproxy_socket_stats* stats);
int _csp_reset_stats(void);
SOCKPROXY_ENDDECLS

#endif
