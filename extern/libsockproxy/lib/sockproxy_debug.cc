/*
 *  Click socket proxy debug utils
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

#include <string.h>
#include <errno.h>
#include "sockproxy.h"
#include "sockproxy_pkt.h"
#include "sockproxy_int.hh"

SOCKPROXY_DECLS

int
_csp_get_open_sockets(int* fds, socklen_t* count)
{
    if (!g_csp || !count) {
        errno = EINVAL;
        return -1;
    }

    if (!fds || g_csp->fd_map.size() > *count) {
        *count = g_csp->fd_map.size();
        errno = ENOSPC;
        return -1;
    }

    int i = 0;
    for (FDMap::iterator it = g_csp->fd_map.begin();
         it != g_csp->fd_map.end();
         it++, i++) {
        fds[i] = it->first;
    }

    return 0;
}

int
_csp_get_stats(struct sockproxy_stats* stats)
{
    if (!g_csp || !stats) {
        errno = EINVAL;
        return -1;
    }

    stats->rx_packets = g_csp->rx_packets;
    stats->rx_undelivered_packets = g_csp->rx_undelivered_packets;
    stats->tx_packets = g_csp->tx_packets;

    return 0;
}

int
_csp_reset_stats(void)
{
    if (!g_csp) {
        errno = EINVAL;
        return -1;
    }

    g_csp->rx_packets = 0;
    g_csp->rx_undelivered_packets = 0;
    g_csp->tx_packets = 0;

    FDMap::iterator it;
    for (it = g_csp->fd_map.begin(); it != g_csp->fd_map.end(); it++) {
        std::shared_ptr<Socket> s = it->second;

        s->rx_packets = 0;
        s->rx_dropped_packets = 0;
        s->tx_packets = 0;
    }
};

int
_csp_get_socket_stats(int fd, struct sockproxy_socket_stats* stats)
{
    if (!g_csp || !stats) {
        errno = EINVAL;
        return -1;
    }

    FDMap::iterator it = g_csp->fd_map.find(fd);

    if (it == g_csp->fd_map.end()) {
        errno = EINVAL;
        return -1;
    }

    std::shared_ptr<Socket> s = it->second;

    stats->rx_packets = s->rx_packets;
    stats->rx_dropped_packets = s->rx_dropped_packets;
    stats->rx_waiting = s->recv_queue.size();
    stats->tx_packets = s->tx_packets;

    return 0;
}

SOCKPROXY_ENDDECLS
