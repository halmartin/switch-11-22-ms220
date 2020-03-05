/*
 *  Click socket proxy test app -- UDP tests
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

#include <stdio.h>
#include <gtest/gtest.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "CSPFixture.hh"
#include "sockproxy.h"
#include "sockproxy_pkt.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "csptest.h"
#include <fcntl.h>
#include <stdlib.h>

TEST_F(CSPFixture, SendUDPPacket)
{
    static const int BUF_SIZE = 1198;
    ASSERT_EQ_WITH_ERRNO(0, CSP_set_config(&_cfg));

    int fd = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE_WITH_ERRNO(fd, 0);

    // Generate a repeatable "random" sequence for the data.
    unsigned int seed = 8675309;
    uint8_t out_buf[BUF_SIZE];
    for (int i = 0; i < sizeof(out_buf); i++)
        out_buf[i] = rand_r(&seed) % 0xFF;

    // Let's bind to a specific device.
    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "vlan5", sizeof("vlan5")));

    // Put together a packet and send it.
    struct sockaddr_in sa_dest;
    sa_dest.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.5.20", &sa_dest.sin_addr);
    sa_dest.sin_port = htons(2000);
    struct iovec iov = {
        .iov_base = out_buf,
        .iov_len = sizeof(out_buf)
    };
    struct msghdr msg = {
        .msg_name = &sa_dest,
        .msg_namelen = sizeof(sa_dest),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = 0,
        .msg_controllen = 0,
        .msg_flags = 0
    };

    ASSERT_EQ_WITH_ERRNO(sizeof(out_buf), CSP_sendmsg(fd, &msg, 0));

    // We should have been assigned a random port.
    struct sockaddr_in sa_bind;
    socklen_t sa_bind_len = sizeof(sa_bind);
    memset(&sa_bind, 0, sa_bind_len);

    ASSERT_EQ_WITH_ERRNO(0, CSP_getsockname(fd,
                                       (struct sockaddr*)&sa_bind,
                                       &sa_bind_len));
    ASSERT_EQ(sizeof(sa_bind), sa_bind_len);
    ASSERT_EQ(AF_INET, sa_bind.sin_family);
    ASSERT_GE(ntohs(sa_bind.sin_port), 49152);
    ASSERT_EQ(INADDR_ANY, sa_bind.sin_addr.s_addr);

    // Read it out as if we're Click.
    uint8_t in_buf[BUF_SIZE + SOCKPROXY_UDP_HEADERS_SIZE + 1];
    ssize_t bytes = read(_device_socks[0], in_buf, sizeof(in_buf));

    ASSERT_EQ_WITH_ERRNO(sizeof(out_buf) + SOCKPROXY_UDP_HEADERS_SIZE, bytes);
    ASSERT_EQ(0, memcmp(in_buf + SOCKPROXY_UDP_HEADERS_SIZE, out_buf, sizeof(out_buf)));
    ASSERT_EQ(5, ((struct sockproxy_pkt_hdr*)in_buf)->vlan);

    verify_ip_header((struct iphdr*)&in_buf[sizeof(sockproxy_pkt_hdr)],
                     0,
                     sa_dest.sin_addr.s_addr,
                     IPPROTO_UDP,
                     htons(sizeof(out_buf) + sizeof(struct iphdr) + sizeof(struct udphdr)));

    verify_udp_header((struct udphdr*)&in_buf[sizeof(sockproxy_pkt_hdr)+sizeof(struct iphdr)],
                      sa_bind.sin_port,
                      sa_dest.sin_port,
                      htons(sizeof(out_buf) + sizeof(struct udphdr)));

    // Let's try doing a proper bind.
    sa_bind.sin_family = AF_INET;
    sa_bind.sin_port = htons(1492);
    inet_pton(AF_INET, "192.168.5.1", &sa_bind.sin_addr);

    // This bind should fail, since the sendmsg above should have
    // caused an implicit bind.
    ASSERT_EQ(-1, CSP_bind(fd, (struct sockaddr*)&sa_bind, sizeof(sa_bind)));
    ASSERT_EQ(EINVAL, errno);

    // We'll have to close the socket and open a new one to re-bind.
    ASSERT_EQ_WITH_ERRNO(0, CSP_close(fd));
    fd = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE_WITH_ERRNO(fd, 0);
    ASSERT_EQ_WITH_ERRNO(0, CSP_bind(fd, (struct sockaddr*)&sa_bind, sizeof(sa_bind)));

    // Send the packet again.
    ASSERT_EQ_WITH_ERRNO(sizeof(out_buf), CSP_sendmsg(fd, &msg, 0));

    // Read it out as if we're click.
    bytes = read(_device_socks[0], in_buf, sizeof(in_buf));

    ASSERT_EQ_WITH_ERRNO(sizeof(out_buf) + SOCKPROXY_UDP_HEADERS_SIZE, bytes);
    ASSERT_EQ(0, memcmp(in_buf + SOCKPROXY_UDP_HEADERS_SIZE, out_buf, sizeof(out_buf)));
    ASSERT_EQ(5, ((struct sockproxy_pkt_hdr*)in_buf)->vlan);

    verify_ip_header((struct iphdr*)&in_buf[sizeof(sockproxy_pkt_hdr)],
                     sa_bind.sin_addr.s_addr,
                     sa_dest.sin_addr.s_addr,
                     IPPROTO_UDP,
                     htons(sizeof(out_buf) + sizeof(struct iphdr) + sizeof(struct udphdr)));

    verify_udp_header((struct udphdr*)&in_buf[sizeof(sockproxy_pkt_hdr) + sizeof(struct iphdr)],
                      sa_bind.sin_port,
                      sa_dest.sin_port,
                      htons(sizeof(out_buf) + sizeof(struct udphdr)));

    // Try to send a message with a destination address from the wrong
    // family
    struct sockaddr_un sa_dest_unix;
    sa_dest_unix.sun_family = AF_UNIX;
    strcpy(sa_dest_unix.sun_path, "foobar");
    msg.msg_name = &sa_dest_unix;
    msg.msg_namelen = sizeof(sa_dest_unix);

    ASSERT_EQ(-1, CSP_sendmsg(fd, &msg, 0));
    ASSERT_EQ(EAFNOSUPPORT, errno);

    ASSERT_EQ_WITH_ERRNO(0, CSP_close(fd));
}

struct blocking_read_params {
    int fd;
    uint8_t* in_buf;
    size_t in_buf_size;
    ssize_t result;
};

static void* blocking_read_thread(void* arg)
{
    blocking_read_params* params = (blocking_read_params*)arg;
    params->result = 0;

    params->result = CSP_read(params->fd, params->in_buf, params->in_buf_size);
    if (params->result < 0)
        params->result = -errno;

    return NULL;
}


TEST_F(CSPFixture, ReceiveUDPPacket)
{
    static const int BUF_SIZE = 500;
    ASSERT_EQ_WITH_ERRNO(0, CSP_set_config(&_cfg));

    int fd = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE_WITH_ERRNO(fd, 0);

    ASSERT_EQ_WITH_ERRNO(0, CSP_fcntl_int(fd, F_SETFL, O_NONBLOCK));

    // Write a packet into the proxy as if it's from Click.
    uint8_t out_buf[BUF_SIZE + SOCKPROXY_UDP_HEADERS_SIZE];
    memset(out_buf, 0, sizeof(out_buf));
    struct sockproxy_pkt_hdr* sphdr = (struct sockproxy_pkt_hdr*)out_buf;
    struct iphdr* iphdr = (struct iphdr*)(out_buf + sizeof(struct sockproxy_pkt_hdr));
    struct udphdr* udphdr = (struct udphdr*)(out_buf + sizeof(struct sockproxy_pkt_hdr) +
                                             sizeof(struct iphdr));

    struct in_addr srcaddr, dstaddr;

    inet_pton(AF_INET, "192.168.20.42", &srcaddr);
    inet_pton(AF_INET, "192.168.20.1", &dstaddr);

    sphdr->vlan = 20;
    iphdr->version = 4;
    iphdr->ihl = 5;
    iphdr->tos = 0;
    iphdr->ttl = 64;
    iphdr->tot_len = htons(sizeof(out_buf) - sizeof(struct sockproxy_pkt_hdr));
    iphdr->protocol = IPPROTO_UDP;
    iphdr->saddr = srcaddr.s_addr;
    iphdr->daddr = dstaddr.s_addr;
    udphdr->source = htons(2000);
    udphdr->dest = htons(2001);
    udphdr->len = htons(BUF_SIZE + sizeof(struct udphdr));

    unsigned int seed = 5551212;
    for (int i = 0; i < BUF_SIZE; i++)
        out_buf[SOCKPROXY_UDP_HEADERS_SIZE + i] = rand_r(&seed) % 0xFF;

    struct sockaddr_in sa_bind;
    sa_bind.sin_family = AF_INET;
    sa_bind.sin_addr = dstaddr;
    sa_bind.sin_port = htons(2001);

    ASSERT_EQ_WITH_ERRNO(0, CSP_bind(fd, (struct sockaddr*)&sa_bind, sizeof(sa_bind)));
    ASSERT_EQ_WITH_ERRNO(sizeof(out_buf), write(_device_socks[0], out_buf, sizeof(out_buf)));

    // Read the response out.
    uint8_t in_buf[BUF_SIZE + 1];
    struct iovec iov = {
        .iov_base = in_buf,
        .iov_len = sizeof(in_buf)
    };
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0
    };

    ASSERT_EQ_WITH_ERRNO(BUF_SIZE, CSP_recvmsg(fd, &msg, 0));
    ASSERT_EQ(0, memcmp(in_buf, out_buf + SOCKPROXY_UDP_HEADERS_SIZE, BUF_SIZE));

    // Try to read again, except do a blocking read!
    ASSERT_EQ_WITH_ERRNO(0, CSP_fcntl_int(fd, F_SETFL, 0));
    blocking_read_params brp = {
        .fd = fd,
        .in_buf = in_buf,
        .in_buf_size = sizeof(in_buf)
    };

    pthread_t thread;
    ASSERT_GE(pthread_create(&thread, NULL, blocking_read_thread, &brp), 0);
    usleep(100000);

    // If this assertion fails, then it's safe to just fail the whole
    // test because the thread is now dead AND joined.
    ASSERT_EQ(EBUSY, pthread_tryjoin_np(thread, NULL));

    // For everything after this point, we have to make sure to cancel
    // and join the thread before exiting out of the test.
    EXPECT_EQ_WITH_ERRNO(sizeof(out_buf), write(_device_socks[0], out_buf, sizeof(out_buf)));
    usleep(100000);
    EXPECT_EQ(ESRCH, pthread_cancel(thread));
    void* thread_ret;
    ASSERT_EQ(0, pthread_join(thread, &thread_ret));
    ASSERT_EQ(NULL, thread_ret);
    ASSERT_EQ(BUF_SIZE, brp.result);
    ASSERT_EQ(0, memcmp(in_buf, out_buf + SOCKPROXY_UDP_HEADERS_SIZE, BUF_SIZE));

    ASSERT_EQ_WITH_ERRNO(0, CSP_close(fd));

}
