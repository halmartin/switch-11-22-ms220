/*
 *  Click socket proxy -- transfer functions
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

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <bitset>
#include <new>
#include <algorithm>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "sockproxy.h"
#include "sockproxy_int.hh"
#include "sockproxy_pkt.h"

SOCKPROXY_DECLS

static uint16_t
get_ephemeral_port()
{
    // Since we'll do this pretty rarely, it's okay if it's slow.
    std::bitset<65535> ports_in_use;
    FDMap::iterator it;
    for (it = g_csp->fd_map.begin(); it != g_csp->fd_map.end(); it++)
        if (it->second->sa_bind.sin_port != 0)
            ports_in_use[it->second->sa_bind.sin_port] = true;

    uint16_t tgt_port = (rand_r(&g_csp->rand_seed) %
                         (EPHEMERAL_PORT_MAX - EPHEMERAL_PORT_MIN + 1)) + EPHEMERAL_PORT_MIN;
    uint16_t port;
    for (port = tgt_port; port <= EPHEMERAL_PORT_MAX; port++)
        if (!ports_in_use[port])
            break;
    if (port > EPHEMERAL_PORT_MAX) {
        for (port = tgt_port - 1; port >= EPHEMERAL_PORT_MIN; port--)
            if (!ports_in_use[port])
                break;
        if (port < EPHEMERAL_PORT_MIN) {
            return 0;
        }
    }
    return port;
}

ssize_t
_csp_sendmsg(int sockfd, const struct msghdr* msg, int flags)
{
    if (!g_csp) {
        errno = ENXIO;
        return -1;
    }

    FDMap::iterator it = g_csp->fd_map.find(sockfd);

    if (it == g_csp->fd_map.end())
        return sendmsg(sockfd, msg, flags);

    if (msg == NULL ||
        (msg->msg_name != NULL && msg->msg_namelen < sizeof(struct sockaddr)) ||
        msg->msg_iov == NULL || msg->msg_iovlen != 1)
    {
        errno = EINVAL;
        return -1;
    }

    if (msg->msg_name == NULL) {
        errno = EDESTADDRREQ;
        return -1;
    }

    if (((struct sockaddr*)msg->msg_name)->sa_family != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    if (msg->msg_namelen < sizeof(struct sockaddr_in)) {
        errno = EINVAL;
        return -1;
    }

    std::shared_ptr<Socket> s = it->second;
    const struct sockaddr_in* dest = (const struct sockaddr_in*)msg->msg_name;
    struct sockaddr_in zsa;

    memset(&zsa, 0, sizeof(zsa));
    if (memcmp(dest, &zsa, sizeof(dest)) == 0) {
        errno = EDESTADDRREQ;
        return -1;
    }

    if (dest->sin_addr.s_addr == INADDR_BROADCAST && !s->broadcast) {
        errno = EACCES;
        return -1;
    }

    if (msg->msg_iovlen != 1) {
        errno = EOPNOTSUPP;
        return -1;
    }

    ssize_t payload_len = msg->msg_iov->iov_len;
    ssize_t hdrlen;
    if (s->hdr_incl)
        hdrlen = sizeof(sockproxy_pkt_hdr);
    else
        hdrlen = sizeof(sockproxy_pkt_hdr) + sizeof(struct iphdr) + (s->type == SOCK_DGRAM ? sizeof(struct udphdr) : 0);
    uint16_t pktlen = hdrlen + payload_len;
    std::vector<uint8_t> sndbuf(pktlen, 0);
    uint32_t saddr = (is_multicast(dest->sin_addr) ? s->addr_mcast_send.s_addr : s->sa_bind.sin_addr.s_addr);
    sockproxy_pkt_hdr* sphdr = (sockproxy_pkt_hdr*)sndbuf.data();

    if (is_multicast(dest->sin_addr)) {
        if (s->vlan_mcast_send == 0) {
            if (s->bound_vlan == 0) {
                errno = ENOTCONN;
                return -1;
            } else {
                sphdr->vlan = s->bound_vlan;
            }
        } else {
            sphdr->vlan = s->vlan_mcast_send;
        }
    } else {
        if (s->bound_vlan == 0) {
            AddressMap::iterator it = g_csp->addr_map.find(s->sa_bind.sin_addr.s_addr);
            if (it == g_csp->addr_map.end()) {
                // Send packets to Click with VID 0 to be routed
                sphdr->vlan = 0;
            } else {
                sphdr->vlan = it->second;
            }
        } else {
            sphdr->vlan = s->bound_vlan;
        }
    }
    if (!s->hdr_incl) {
        struct iphdr* ip_hdr = (struct iphdr*)(sndbuf.data() + CSP_IP_OFFSET);
        struct cmsghdr *cmsg;

        for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(const_cast<struct msghdr*>(msg), cmsg)) {
            if (cmsg->cmsg_len < sizeof(struct cmsghdr) ||
                cmsg->cmsg_len > msg->msg_controllen - ((const char*)cmsg - (const char*)msg->msg_control) ||
                cmsg->cmsg_level != SOL_IP)
                return -EINVAL;
            switch (cmsg->cmsg_type) {
            case IP_PKTINFO: {
                struct in_pktinfo *pi;
                if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct in_pktinfo)))
                    return -EINVAL;
                pi = (struct in_pktinfo*)CMSG_DATA(cmsg);
                if (pi->ipi_ifindex)
                    sphdr->vlan = pi->ipi_ifindex;
                if (pi->ipi_spec_dst.s_addr)
                    saddr = pi->ipi_spec_dst.s_addr;
                break;
            }
            default:
                return -EINVAL;
            }
        }

        ip_hdr->version = 4;
        ip_hdr->ihl = 5;
        ip_hdr->tot_len = htons(pktlen - sizeof(sockproxy_pkt_hdr));
        ip_hdr->id = 0;
        ip_hdr->frag_off = 0;
        ip_hdr->ttl = (is_multicast(dest->sin_addr) ? s->mcast_ttl : s->ttl);
        ip_hdr->tos = s->ip_tos;
        ip_hdr->protocol = s->protocol;
        ip_hdr->saddr = saddr;
        ip_hdr->daddr = dest->sin_addr.s_addr;
        ip_hdr->check = 0;  // Checksum will be set in Click
        if (s->type == SOCK_DGRAM) {
            struct udphdr* udp_hdr = (struct udphdr*)(sndbuf.data() + get_ip_payload_offset(ip_hdr));
            if (s->sa_bind.sin_port == 0) {
                s->sa_bind.sin_port = htons(get_ephemeral_port());
                s->sa_bind.sin_family = AF_INET;
                if (s->sa_bind.sin_port == 0) {
                    errno = ENOBUFS;
                    return -1;
                }
            }
            udp_hdr->source = s->sa_bind.sin_port;
            udp_hdr->dest = dest->sin_port;
            udp_hdr->len = htons(payload_len + sizeof(struct udphdr));
            udp_hdr->check = 0;  // Checksum will be set in Click
        }
    }

    memcpy(sndbuf.data() + hdrlen, msg->msg_iov->iov_base, msg->msg_iov->iov_len);

    // Write to device or send to connected socket
    ssize_t bytes = write(g_csp->click_tunnel_fd, sndbuf.data(), sndbuf.size());
    if (bytes < 0)
        return -1;

    bytes -= hdrlen;
    if (bytes < 0) {
        // We couldn't even send the whole header!
        errno = ECOMM;
        return -1;
    }

    s->tx_packets++;
    g_csp->tx_packets++;

    return bytes;
}

ssize_t
_csp_sendto(int sockfd, const void* buf, size_t len, int flags,
            const struct sockaddr* dest_addr, socklen_t addrlen)
{
    if (!g_csp) {
        errno = ENXIO;
        return -1;
    }

    bool found = (g_csp->fd_map.count(sockfd) != 0);

    if (!found)
        return send(sockfd, buf, len, flags);

    struct iovec iov = {
        .iov_base = const_cast<void*>(buf),
        .iov_len = len
    };

    struct msghdr hdr;

    hdr.msg_name = const_cast<struct sockaddr*>(dest_addr);
    hdr.msg_namelen = addrlen;
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags = 0;   // For received messages only.


    return _csp_sendmsg(sockfd, &hdr, flags);
}

static int
read_dev_packets()
{
    const size_t buf_size = sizeof(sockproxy_pkt_hdr) + MAX_PACKET_LEN + 1;

    int packets = 0;

    while (true) {
        std::shared_ptr<std::vector<uint8_t> > buf =
            std::make_shared<std::vector<uint8_t> >(buf_size);
        ssize_t bytes = read(g_csp->click_tunnel_fd, buf->data(), buf_size);
        if (bytes < 0) {
            if (errno == EAGAIN)
                break;
            else
                return -1;
        }

        // A non-blocking file descriptor is supposed to return an error
        // with errno == EAGAIN when there's no data.  Click, however,
        // returns bytes == 0.
        if (bytes == 0)
            break;

        if (bytes == buf_size) {
            warning("Packet truncated!");
            bytes--;
        }

        if (bytes < (CSP_IP_OFFSET + sizeof(struct iphdr))) {
            warning("Packet too short (%d)", bytes);
            continue;
        }

        // Click will have validated the IP checksum.

        buf->resize(bytes);

        struct iphdr* ip_hdr = (struct iphdr*)(buf->data() + CSP_IP_OFFSET);
        if (ip_hdr->version != 4) {
            warning("Non-IPv4 packet received.");
            continue;
        }

        if ((bytes - CSP_IP_OFFSET) != ntohs(ip_hdr->tot_len)) {
            warning("Packet IP header length %d incorrect (should be %d)",
                    ntohs(ip_hdr->tot_len), bytes - CSP_IP_OFFSET);
            continue;
        }

        uint16_t dst_port_be = 0; // big endian
        if (ip_hdr->protocol == IPPROTO_UDP) {
            size_t offset = get_ip_payload_offset(ip_hdr);
            if (bytes < offset + sizeof(struct udphdr)) {
                warning("UDP packet too short for UDP header (%d)", bytes);
                continue;
            }
            struct udphdr* udp_hdr = (struct udphdr*)(buf->data() + offset);
            if (ntohs(udp_hdr->len) != (bytes - offset)) {
                warning("Packet UDP header length %d incorrect (should be %d)",
                        ntohs(udp_hdr->len), bytes - offset);
                continue;
            }

            dst_port_be = udp_hdr->dest;
        }

        g_csp->rx_packets++;
        sockproxy_pkt_hdr* sp_hdr = (sockproxy_pkt_hdr*)buf->data();
        if (is_multicast(ip_hdr->daddr)) {
            // multicast
            bool delivered = false;
            if (g_csp->mroute_sock_fd != -1 && (ip_hdr->protocol == 0 || ip_hdr->protocol == IPPROTO_IGMP)) {
                FDMap::iterator it = g_csp->fd_map.find(g_csp->mroute_sock_fd);
                if (it != g_csp->fd_map.end()) {
                    delivered = true;
                    std::shared_ptr<Socket>& s = it->second;
                    if (s->recv_queue.size() < MAX_QUEUE_SIZE) {
                        s->recv_queue.push(buf);
                        s->rx_packets++;
                    } else if ((++s->rx_dropped_packets % 10) == 1) {
                        warning("Socket %d has dropped %u total packets!", s->fd, s->rx_dropped_packets);
                    }
                }
            } else {
                uint32_t group_addr = ip_hdr->daddr;
                std::pair<MulticastMemberMap::iterator, MulticastMemberMap::iterator> range =
                    g_csp->mcast_members.equal_range(AddrVlan( { group_addr }, sp_hdr->vlan));
                for (MulticastMemberMap::iterator it = range.first;
                     it != range.second;
                     it++) {
                    std::shared_ptr<Socket>& s = it->second;
                    if (s->protocol == ip_hdr->protocol &&
                        s->sa_bind.sin_port == dst_port_be &&
                        (s->sa_bind.sin_addr.s_addr == ip_hdr->daddr ||
                         s->sa_bind.sin_addr.s_addr == INADDR_ANY ||
                         s->sa_bind.sin_addr.s_addr == INADDR_BROADCAST)) {
                        delivered = true;
                        if (s->recv_queue.size() < MAX_QUEUE_SIZE) {
                            s->recv_queue.push(buf);
                            s->rx_packets++;
                        } else if ((++s->rx_dropped_packets % 10) == 1) {
                            warning("Socket %d has dropped %u total packets!", s->fd, s->rx_dropped_packets);
                        }
                    }
                }
            }
            if (!delivered)
                g_csp->rx_undelivered_packets++;
        } else {
            // unicast or broadcast
            Interface iface;
            iface.vid = sp_hdr->vlan;
            InterfaceSet::iterator it = g_csp->ifaces.find(iface);
            if (it != g_csp->ifaces.end()) {
                std::vector<std::shared_ptr<Socket> > candidates;
                for (FDMap::iterator it2 = g_csp->fd_map.begin();
                     it2 != g_csp->fd_map.end();
                     it2++) {
                    std::shared_ptr<Socket>& s = it2->second;
                    if ((s->bound_vlan == iface.vid || s->bound_vlan == 0) &&
                        s->protocol == ip_hdr->protocol &&
                        s->sa_bind.sin_port == dst_port_be &&
                        (s->sa_bind.sin_addr.s_addr == ip_hdr->daddr ||
                         s->sa_bind.sin_addr.s_addr == INADDR_ANY ||
                         s->sa_bind.sin_addr.s_addr == INADDR_BROADCAST)) {
                        candidates.push_back(s);
                        if (!s->reuse_addr)
                            break;
                    }
                }
                // When there are multiple sockets that want the same
                // packet, Linux will attempt to evenly distribute
                // arriving packets across all of them.  BSD, however,
                // makes no guarantees regarding the distribution.
                //
                // In our case, we'll take the simple approach and just
                // distribute them randomly.
                size_t num_candidates = candidates.size();
                if (num_candidates > 0) {
                    std::shared_ptr<Socket>& s = candidates[rand_r(&g_csp->rand_seed) % num_candidates];
                    if (s->recv_queue.size() < MAX_QUEUE_SIZE) {
                        s->recv_queue.push(buf);
                        s->rx_packets++;
                    } else if ((++s->rx_dropped_packets % 10) == 1) {
                        warning("Socket %d has dropped %u total packets!", s->fd, s->rx_dropped_packets);
                    }
                } else {
                    g_csp->rx_undelivered_packets++;
                }
            }
        }
        packets++;
    }

    return packets;
}

ssize_t
_csp_recvmsg(int sockfd, struct msghdr* msg, int flags)
{
    if (!g_csp) {
        errno = ENXIO;
        return -1;
    }

    FDMap::iterator it = g_csp->fd_map.find(sockfd);

    if (it == g_csp->fd_map.end())
        return recvmsg(sockfd, msg, flags);

    if (msg == NULL ||
        (msg->msg_name != NULL && msg->msg_namelen < sizeof(struct sockaddr)) ||
        (msg->msg_name == NULL && msg->msg_namelen != 0) ||
        msg->msg_iov == NULL || msg->msg_iovlen != 1 ||
        msg->msg_iov->iov_base == NULL || msg->msg_iov->iov_len == 0) {
        errno = EINVAL;
        return -1;
    }

    std::shared_ptr<Socket> s = it->second;

    if (msg->msg_name != NULL) {
        if (msg->msg_namelen < sizeof(struct sockaddr_in)) {
            errno = EINVAL;
            return -1;
        }
    }

    while (s->recv_queue.empty()) {
        int num_packets = read_dev_packets();
        if (num_packets < 0) {
            return -1;
        } else if (num_packets == 0) {
            if ((s->fd_flags & O_NONBLOCK) || (flags & MSG_DONTWAIT))
                return -1;
            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(g_csp->click_tunnel_fd, &fdset);
            if (select(g_csp->click_tunnel_fd+1, &fdset, NULL, NULL, NULL) < 0)
                return -1;
        }
    }

    std::shared_ptr<std::vector<uint8_t> > buf;
    struct iphdr* ip_hdr;
    sockproxy_pkt_hdr* sp_hdr;

    buf = s->recv_queue.front();
    s->recv_queue.pop();
    struct sockaddr_in* msg_addr = (struct sockaddr_in*)msg->msg_name;

    sp_hdr = (sockproxy_pkt_hdr*)(buf->data());
    ip_hdr = (struct iphdr*)(buf->data() + CSP_IP_OFFSET);

    if (msg_addr != NULL) {
        msg_addr->sin_family = AF_INET;
        msg_addr->sin_addr.s_addr = ip_hdr->saddr;
        if (s->type == SOCK_DGRAM) {
            struct udphdr* udp_hdr = (struct udphdr*)(buf->data() + get_ip_payload_offset(ip_hdr));
            msg_addr->sin_port = udp_hdr->source;
        } else
            msg_addr->sin_port = ip_hdr->protocol;  // By POSIX convention
        msg->msg_namelen = sizeof(struct sockaddr_in);
    }

    msg->msg_flags = 0;
    size_t payload_offset;
    if (s->type == SOCK_DGRAM)
        payload_offset = get_udp_payload_offset(ip_hdr);
    else
        payload_offset = CSP_IP_OFFSET;
    size_t count = buf->size() - payload_offset;
    size_t bytes_to_write = count;
    if (count > msg->msg_iov->iov_len) {
        bytes_to_write = msg->msg_iov->iov_len;
        msg->msg_flags |= MSG_TRUNC;
    }
    memcpy(msg->msg_iov->iov_base, buf->data() + payload_offset, bytes_to_write);

    if (msg->msg_control && msg->msg_controllen > 0) {
        struct cmsghdr* cmsg = CMSG_FIRSTHDR(msg);
        if (s->ip_pktinfo) {
            if (CMSG_SPACE(sizeof(in_pktinfo)) > msg->msg_controllen) {
                msg->msg_flags |= MSG_CTRUNC;
            } else {
                cmsg->cmsg_level = SOL_IP;
                cmsg->cmsg_type = IP_PKTINFO;
                cmsg->cmsg_len = sizeof(in_pktinfo);
                struct in_pktinfo* pi = (struct in_pktinfo*)CMSG_DATA(cmsg);
                pi->ipi_ifindex = sp_hdr->vlan;
                pi->ipi_spec_dst.s_addr = ip_hdr->saddr;
                pi->ipi_addr.s_addr = ip_hdr->daddr;
            }
        }
    }

    return ((flags & MSG_TRUNC) ? count : bytes_to_write);
}

ssize_t
_csp_recvfrom(int sockfd, void* buf, size_t len, int flags,
              struct sockaddr* src_addr, socklen_t* addrlen)
{
    if (!g_csp) {
        errno = ENXIO;
        return -1;
    }

    bool found = (g_csp->fd_map.count(sockfd) != 0);

    if (!found)
        return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);

    struct iovec iov = {
        .iov_base = buf,
        .iov_len = len
    };

    struct msghdr hdr;

    hdr.msg_name = src_addr;
    hdr.msg_namelen = addrlen ? *addrlen : 0;
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags = 0;

    ssize_t ret = _csp_recvmsg(sockfd, &hdr, flags);
    if (ret >= 0 && addrlen)
        *addrlen = hdr.msg_namelen;

    return ret;
}

int
_csp_read(int fd, void* buf, size_t count)
{
    if (!g_csp) {
        errno = ENXIO;
        return -1;
    }

    bool found = (g_csp->fd_map.count(fd) != 0);

    if (!found)
        return read(fd, buf, count);
    else
        return _csp_recvfrom(fd, buf, count, 0, NULL, NULL);
}

int
_csp_write(int fd, const void* buf, size_t count)
{
    if (!g_csp) {
        errno = ENXIO;
        return -1;
    }

    bool found = (g_csp->fd_map.count(fd) != 0);

    if (!found)
        return write(fd, buf, count);
    else
        return _csp_sendto(fd, buf, count, 0, NULL, 0);
}


class FDSet
{
public:
    FDSet() : _nfds(0), _count(0) {
        FD_ZERO(&_set);
    }

    FDSet(int nfds, const fd_set* set) : _nfds(nfds), _count(0) {
        if (set == NULL) {
            FD_ZERO(&_set);
        } else {
            _set = *set;
            for (int i = 0; i < _nfds; i++)
                if (FD_ISSET(i, &_set))
                    _count++;
        }
    }

    void set(int fd) {
        if (!is_set(fd)) {
            FD_SET(fd, &_set);
            _count++;
            if (fd >= _nfds)
                _nfds = fd + 1;
        }
    }

    void clear(int fd) {
        if (is_set(fd)) {
            FD_CLR(fd, &_set);
            _count--;
            if (fd == (_nfds - 1)) {
                _nfds--;
                for (; _nfds > 0; _nfds--) {
                    if (is_set(_nfds - 1))
                        break;
                }
            }
        }
    }

    void zero() {
        FD_ZERO(&_set);
        _nfds = 0;
        _count = 0;
    }

    int nfds() const {
        return _nfds;
    }

    bool is_set(int fd) const {
        return FD_ISSET(fd, &_set);
    }

    int count() const {
        return _count;
    }

    FDSet& operator |= (const FDSet& other) {
        for (int i = 0; i < other._nfds; i++) {
            if (other.is_set(i) && !is_set(i)) {
                FD_SET(i, &_set);
                _count++;
            }
        }
        if (other._nfds > _nfds)
            _nfds = other._nfds;
    }

    operator fd_set&() {
        return _set;
    }

    operator const fd_set&() const {
        return _set;
    }

    operator bool() const {
        return (_count > 0);
    }

private:
    fd_set _set;
    int _nfds;
    int _count;
};


int
_csp_select(int nfds, fd_set* read_fds, fd_set* write_fds,
               fd_set* except_fds, struct timeval* timeout)
{

    if (!g_csp) {
        errno = ENXIO;
        return -1;
    }

    // If we have no open CSP sockets, then just pass through to
    // normal select.
    if (g_csp->fd_map.size() < 0)
        return select(nfds, read_fds, write_fds, except_fds, timeout);

    FDSet orig_read_fds(nfds, read_fds);
    FDSet orig_write_fds(nfds, write_fds);
    FDSet orig_except_fds(nfds, except_fds);

    FDSet real_read_fds, real_write_fds, real_except_fds;
    FDSet result_read_fds, result_write_fds, result_except_fds;
    FDSet waiting_fake_read_fds, waiting_fake_write_fds;
    FDSet waiting_fake_except_fds;

    // First, let's see if there are any CSP sockets in the original
    // fd sets.  If a CSP socket has data waiting and was a member of
    // read_fds, then let's go ahead and add to to the result set.
    // Otherwise, if a CSP socket is in any of the original FD sets
    // then we add the actual tunnel FD to the corresponding
    // real_XXX_fds to be passed to the actual select call.
    //
    // Regular (non-CSP) sockets are just added directly to the
    // corresponding real_XXX_fds set.
    for (int i = 0; i < nfds; i++) {
        FDMap::iterator it = g_csp->fd_map.find(i);
        if (orig_read_fds.is_set(i)) {
            if (it == g_csp->fd_map.end()) {
                real_read_fds.set(i);
            } else {
                if (!it->second->recv_queue.empty()) {
                    result_read_fds.set(i);
                } else {
                    real_read_fds.set(g_csp->click_tunnel_fd);
                    waiting_fake_read_fds.set(i);
                }
            }
        }
        if (orig_write_fds.is_set(i)) {
            if (it == g_csp->fd_map.end()) {
                real_write_fds.set(i);
            } else {
                real_write_fds.set(g_csp->click_tunnel_fd);
                waiting_fake_write_fds.set(i);
            }
        }
        if (orig_except_fds.is_set(i)) {
            if (it == g_csp->fd_map.end()) {
                real_except_fds.set(i);
            } else {
                real_except_fds.set(g_csp->click_tunnel_fd);
                waiting_fake_except_fds.set(i);
            }
        }
    }

    // If all the real_XXX_fds sets are empty, then there's nothing
    // else to do.  Otherwise, we need to call select.
    if (real_read_fds || real_write_fds || real_except_fds) {
        struct timeval zero_timeout = {0, 0};
        struct timeval* time_remaining;

        // If we already have results to return, we don't want to
        // block.  We just want to see if we need to add any other
        // sockets to the result sets.
        if (result_read_fds || result_write_fds || result_except_fds)
            time_remaining = &zero_timeout;
        else
            time_remaining = timeout;

        int real_nfds = std::max(real_read_fds.nfds(),
                                 std::max(real_write_fds.nfds(),
                                          real_except_fds.nfds()));
        do {
            int select_result;
            select_result = select(real_nfds,
                                   &(fd_set&)real_read_fds,
                                   &(fd_set&)real_write_fds,
                                   &(fd_set&)real_except_fds,
                                   time_remaining);

            if (select_result < 0)
                return select_result;
            else if (select_result > 0) {
                for (int i = 0; i < real_nfds; i++) {
                    if (real_read_fds.is_set(i)) {
                        if (i == g_csp->click_tunnel_fd) {
                            // Process any pending packets.
                            if (read_dev_packets() < 0) {
                                error("read_dev_packets gave an error: %m");
                                return -1;
                            }

                            // If we've queued any packets for sockets
                            // in waiting_fake_read_fds, then add the
                            // socket(s) to the result set.
                            for (int j = 0; j < waiting_fake_read_fds.nfds(); j++) {
                                if (waiting_fake_read_fds.is_set(j)) {
                                    FDMap::iterator it = g_csp->fd_map.find(j);
                                    if (it == g_csp->fd_map.end()) {
                                        error("Fake read FD missing from fd_map in _csp_select");
                                        continue;
                                    }
                                    if (!it->second->recv_queue.empty())
                                        result_read_fds.set(j);
                                }
                            }
                        } else {
                            result_read_fds.set(i);
                        }
                    }
                    if (real_write_fds.is_set(i)) {
                        // If the click tunnel is ready for write,
                        // then ALL sockets in waiting_fake_write_fds
                        // are ready for write.
                        if (i == g_csp->click_tunnel_fd)
                            result_write_fds |= waiting_fake_write_fds;
                        else
                            result_write_fds.set(i);
                    }
                    if (real_except_fds.is_set(i)) {
                        // If the click tunnel has an exception then
                        // ALL sockets in waiting_fake_except_fds
                        // should generate an exception.
                        if (i == g_csp->click_tunnel_fd)
                            result_except_fds |= waiting_fake_except_fds;
                        else
                            result_except_fds.set(i);
                    }
                }
            }
        } while (!result_read_fds && !result_write_fds && !result_except_fds &&
                 (time_remaining->tv_sec != 0 || time_remaining->tv_usec != 0));
    }
    if (read_fds)
        *read_fds = result_read_fds;
    if (write_fds)
        *write_fds = result_write_fds;
    if (except_fds)
        *except_fds = result_except_fds;

    return result_read_fds.count() + result_write_fds.count() + result_except_fds.count();
}

SOCKPROXY_ENDDECLS

