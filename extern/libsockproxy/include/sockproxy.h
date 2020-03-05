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


#ifndef SOCKPROXY_H
#define SOCKPROXY_H

#include <stdarg.h>
#include <net/if.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/select.h>

#ifdef __cplusplus
#define NOEXCEPT throw()
#else
#define NOEXCEPT
#endif

enum csp_debug_class {
    CSP_DEBUG_MSG,
    CSP_DEBUG_WARN,
    CSP_DEBUG_ERR,
    CSP_DEBUG_CRIT
};

typedef void (*csp_debug_fn)(enum csp_debug_class, const char*, va_list);

struct sockproxy_iface {
    char name[IFNAMSIZ];
    struct in_addr addr;
    uint16_t vid;
};

struct sockproxy_cfg {
#ifdef SOCKPROXY_TEST
    int device_fd;
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
    const char* proxy_device;
    const char* proxy_host;
    uint16_t    proxy_port; // Host byte order
    const char* add_membership_handler;
    const char* del_membership_handler;
    const char* add_mfc_handler;
    const char* del_mfc_handler;
    const char* add_vif_handler;
    const char* del_vif_handler;
    const char* init_mrt_handler;
    const char* init_pim_handler;
    const char* lookup_route_handler;
    const char* packet_count_handler;
#endif
    struct sockproxy_iface* ifaces;
    size_t num_ifaces;
};

struct sockproxy_socket_stats {
    uint32_t rx_packets;
    uint32_t rx_dropped_packets;
    uint32_t rx_waiting;
    uint32_t tx_packets;
};

struct sockproxy_stats {
    uint32_t rx_packets;
    uint32_t rx_undelivered_packets;
    uint32_t tx_packets;
};

#ifdef __cplusplus
extern "C" {
#endif
    void CSP_register_debug(csp_debug_fn fn) NOEXCEPT;

    int CSP_set_config(const struct sockproxy_cfg* cfg) NOEXCEPT;
    int CSP_clear_config(void) NOEXCEPT;
    int CSP_socket(int domain, int type, int protocol) NOEXCEPT;
    int CSP_close(int fd) NOEXCEPT;
    int CSP_bind(int sockfd, struct sockaddr* addr, socklen_t addrlen) NOEXCEPT;
    int CSP_getsockname(int sockfd, struct sockaddr* addr, socklen_t* addrlen) NOEXCEPT;
    ssize_t CSP_sendmsg(int sockfd, const struct msghdr* msg, int flags) NOEXCEPT;
    ssize_t CSP_sendto(int sockfd, const void* buf, size_t len, int flags,
                       const struct sockaddr* dest_addr, socklen_t addrlen) NOEXCEPT;
    ssize_t CSP_send(int sockfd, const void* buf, size_t len, int flags) NOEXCEPT;
    ssize_t CSP_recvmsg(int sockfd, struct msghdr* msg, int flags) NOEXCEPT;
    ssize_t CSP_recvfrom(int sockfd, void* buf, size_t len, int flags,
                         struct sockaddr* src_addr, socklen_t* addrlen) NOEXCEPT;
    ssize_t CSP_recv(int sockfd, void* buf, size_t len, int flags) NOEXCEPT;
    int CSP_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) NOEXCEPT;
    int CSP_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t* optlen) NOEXCEPT;
    int CSP_select(int nfds, fd_set* read_fds, fd_set* write_fds,
                   fd_set* except_fds, struct timeval* timeout) NOEXCEPT;
    int CSP_fcntl_int(int fd, int cmd, int optval) NOEXCEPT;
    int CSP_ioctl(int fd, unsigned long int request, void *arg) NOEXCEPT;
    int CSP_read(int fd, void* buf, size_t count) NOEXCEPT;
    int CSP_write(int fd, const void* buf, size_t count) NOEXCEPT;

    int CSP_get_open_sockets(int* fds, socklen_t* count) NOEXCEPT;
    int CSP_get_stats(struct sockproxy_stats* stats) NOEXCEPT;
    int CSP_get_socket_stats(int fd, struct sockproxy_socket_stats* stats) NOEXCEPT;
    int CSP_reset_stats(void) NOEXCEPT;
    int meraki_click_write(const char *, const char *) NOEXCEPT;
    int meraki_click_read(char *buf, size_t bufsize, const char *clickpath, const char *value, size_t *bytes_read) NOEXCEPT;

#ifdef __cplusplus
}
#endif

#define MERAKI_CLICK_COMMAND_SIZE 512

#endif
