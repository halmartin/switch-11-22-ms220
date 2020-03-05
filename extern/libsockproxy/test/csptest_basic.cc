/*
 *  Click socket proxy test app -- basic tests
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

#include <gtest/gtest.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <gtest/gtest.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "sys/un.h"
#include "sockproxy.h"
#include "CSPFixture.hh"
#include <errno.h>
#include "csptest.h"
#include "pthread.h"

TEST_F(CSPFixture, CreateSocket)
{
    ASSERT_EQ(0, CSP_set_config(&_cfg));

    // Try to make a TCP socket (should fail)
    int fd = CSP_socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_EQ(-1, fd);
    EXPECT_EQ(ESOCKTNOSUPPORT, errno);

    // Make a UDP socket
    fd = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(0, CSP_close(fd));

    // Make a RAW socket (89 is OSPF)
    fd = CSP_socket(AF_INET, SOCK_RAW, 89);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(0, CSP_close(fd));
}

TEST_F(CSPFixture, BindSocket)
{
    ASSERT_EQ(0, CSP_set_config(&_cfg));

    // Create a socket and bind it.
    int fd = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE_WITH_ERRNO(fd, 0);

    struct sockaddr_in sa_inet;
    sa_inet.sin_family = AF_INET;
    sa_inet.sin_port = htons(2000);
    inet_pton(AF_INET, "192.168.5.1", &sa_inet.sin_addr);

    EXPECT_EQ_WITH_ERRNO(0, CSP_bind(fd, (struct sockaddr*)&sa_inet, sizeof(sa_inet)));

    // Try to un-bind the socket.
    sa_inet.sin_port = 0;
    EXPECT_EQ(-1, CSP_bind(fd, (struct sockaddr*)&sa_inet, sizeof(sa_inet)));
    EXPECT_EQ(EINVAL, errno);

    // Try to bind a socket to an address with no port.
    EXPECT_EQ_WITH_ERRNO(0, CSP_close(fd));
    fd = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE_WITH_ERRNO(fd, 0);
    EXPECT_EQ(0, CSP_bind(fd, (struct sockaddr*)&sa_inet, sizeof(sa_inet)));

    // Try to bind a socket to a unicast address that doesn't match an
    // interface (should fail)
    EXPECT_EQ_WITH_ERRNO(0, CSP_close(fd));
    fd = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE_WITH_ERRNO(fd, 0);
    inet_pton(AF_INET, "128.227.8.10", &sa_inet.sin_addr);
    sa_inet.sin_port = htons(2270);
    EXPECT_EQ(-1, CSP_bind(fd, (struct sockaddr*)&sa_inet, sizeof(sa_inet)));
    EXPECT_EQ(EADDRNOTAVAIL, errno);

    // Now try binding two sockets to the same address and port
    // (should fail).
    inet_pton(AF_INET, "192.168.250.1", &sa_inet.sin_addr);
    EXPECT_EQ(0, CSP_bind(fd, (struct sockaddr*)&sa_inet, sizeof(sa_inet)));

    int fd2 = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE_WITH_ERRNO(fd, 0);

    EXPECT_EQ(-1, CSP_bind(fd2, (struct sockaddr*)&sa_inet, sizeof(sa_inet)));
    EXPECT_EQ(EADDRINUSE, errno);

    // Try again after enabling SO_REUSEADDR on just the unbound port (should fail)
    int optval = 1;
    EXPECT_EQ(0, CSP_setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)));

    EXPECT_EQ(-1, CSP_bind(fd2, (struct sockaddr*)&sa_inet, sizeof(sa_inet)));
    EXPECT_EQ(EADDRINUSE, errno);

    // Try again after enabling SO_REUSEADDR on both ports.
    EXPECT_EQ_WITH_ERRNO(0, CSP_close(fd));
    fd = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE_WITH_ERRNO(fd, 0);

    EXPECT_EQ_WITH_ERRNO(0, CSP_bind(fd2, (struct sockaddr*)&sa_inet, sizeof(sa_inet)));

    EXPECT_EQ(0, CSP_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)));
    EXPECT_EQ_WITH_ERRNO(0, CSP_bind(fd, (struct sockaddr*)&sa_inet, sizeof(sa_inet)));

    EXPECT_EQ_WITH_ERRNO(0, CSP_close(fd));
    EXPECT_EQ_WITH_ERRNO(0, CSP_close(fd2));

    // Try binding an address from the wrong address family.
    fd = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE_WITH_ERRNO(fd, 0);
    struct sockaddr_un sa_unix;
    sa_unix.sun_family = AF_UNIX;
    strcpy(sa_unix.sun_path, "foobar");
    EXPECT_EQ(-1, CSP_bind(fd, (struct sockaddr*)&sa_unix, sizeof(sa_unix)));
    EXPECT_EQ(EAFNOSUPPORT, errno);
    EXPECT_EQ_WITH_ERRNO(0, CSP_close(fd));
}

TEST_F(CSPFixture, BindToDevice)
{
    ASSERT_EQ(0, CSP_set_config(&_cfg));

    int fd = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(fd, 0);

    EXPECT_EQ(0, CSP_setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (const void*)"vlan5", sizeof("vlan5")));
    EXPECT_EQ(0, CSP_setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (const void*)"vlan20", sizeof("vlan20")));
    EXPECT_EQ(0, CSP_setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (const void*)"vlan4094", sizeof("vlan4094")));
    EXPECT_EQ(-1, CSP_setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (const void*)"vlan3987", sizeof("vlan3987")));
    EXPECT_EQ(-1, CSP_setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (const void*)"miles", sizeof("miles")));

    EXPECT_EQ_WITH_ERRNO(0, CSP_close(fd));
}

struct delayed_write_params {
    struct timespec delay;
    int fd;
    uint8_t* buf;
    size_t bufsize;
};

static void* delayed_write_thread(void* arg)
{
    delayed_write_params* params = (delayed_write_params*)arg;

    nanosleep(&params->delay, NULL);
    write(params->fd, params->buf, params->bufsize);

    return NULL;
}

/**
 * Here we are testing the following scenarios:
 *   - There's data available to read for a CSP socket and CSP_select() is able
 *     to report the CSP socket as ready for read and does not report non-CSP
 *     sockets as ready.
 *   - There's data available to read for a non-CSP socket and select() is able
 *     to report the non-CSP socket as ready for read and does not report CSP
 *     sockets as ready.
 *   - When multiple CSP sockets have been created, select() reports only the
 *     sockets that are ready for read as such.
 */
TEST_F(CSPFixture, Select)
{
    static const int BUF_SIZE = 1207;
    ASSERT_EQ(0, CSP_set_config(&_cfg));

    int fd = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE_WITH_ERRNO(fd, 0);

    struct sockaddr_in sa_inet;
    sa_inet.sin_family = AF_INET;
    sa_inet.sin_port = htons(2001);
    inet_pton(AF_INET, "192.168.5.1", &sa_inet.sin_addr);

    ASSERT_EQ_WITH_ERRNO(0, CSP_bind(fd, (struct sockaddr*)&sa_inet, sizeof(sa_inet)));

    // Prepare a packet.
    uint8_t out_buf[sizeof(iphdr) + sizeof(sockproxy_pkt_hdr) +
                    sizeof(udphdr) + BUF_SIZE];

    sockproxy_pkt_hdr* sp_hdr = (sockproxy_pkt_hdr*)out_buf;
    iphdr* ip_hdr = (iphdr*)(out_buf + sizeof(sockproxy_pkt_hdr));
    udphdr* udp_hdr = (udphdr*)(out_buf + sizeof(sockproxy_pkt_hdr) + sizeof(iphdr));
    uint8_t* payload = out_buf + sizeof(sockproxy_pkt_hdr) + sizeof(iphdr) +
        sizeof(udphdr);

    // Generate a repeatable "random" sequence for the data.
    unsigned int seed = 42;
    for (int i = 0; i < BUF_SIZE; i++)
        payload[i] = rand_r(&seed) % 0xFF;

    sp_hdr->vlan = 5;
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->tos = 0;
    ip_hdr->ttl = 64;
    ip_hdr->tot_len = htons(sizeof(out_buf) - sizeof(struct sockproxy_pkt_hdr));
    ip_hdr->protocol = IPPROTO_UDP;
    ip_hdr->saddr = htonl(0x02020202); // 2.2.2.2
    ip_hdr->daddr = sa_inet.sin_addr.s_addr;
    udp_hdr->source = htons(2000);
    udp_hdr->dest = htons(2001);
    udp_hdr->len = htons(BUF_SIZE + sizeof(struct udphdr));
    // Checksums would be handled in Click, so they're not added here.

    // Send and select.
    pthread_t thread;
    delayed_write_params dwp = {
        .delay = {
            .tv_sec = 0,
            .tv_nsec = 500000000
        },
        .fd = _device_socks[0],
        .buf = out_buf,
        .bufsize = sizeof(out_buf),
    };

    int testsocks[2];
    ASSERT_EQ_WITH_ERRNO(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, testsocks));

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);
    FD_SET(testsocks[0], &read_fds);
    timeval tv = {
        .tv_sec = 1,
        .tv_usec = 0
    };

    int nfds = std::max(fd, testsocks[0]) + 1;

    ASSERT_GE(pthread_create(&thread, NULL, delayed_write_thread, &dwp), 0);
    EXPECT_EQ(0, pthread_detach(thread));
    EXPECT_EQ(1, CSP_select(nfds, &read_fds, NULL, NULL, &tv));
    EXPECT_TRUE(FD_ISSET(fd, &read_fds));
    EXPECT_FALSE(FD_ISSET(testsocks[0], &read_fds));

    // Read it out to clear the queue.
    uint8_t in_buf[BUF_SIZE + 1];
    ASSERT_EQ_WITH_ERRNO(BUF_SIZE, CSP_read(fd, in_buf, sizeof(in_buf)));
    ASSERT_EQ(0, memcmp(in_buf, payload, BUF_SIZE));

    // Read data from a non-CSP file descriptor.
    uint8_t out_buf2[] = {0x01, 0x23, 0x45};
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);
    FD_SET(testsocks[0], &read_fds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    dwp.fd = testsocks[1];
    dwp.buf = out_buf2;
    dwp.bufsize = sizeof(out_buf2);

    ASSERT_GE(pthread_create(&thread, NULL, delayed_write_thread, &dwp), 0);
    EXPECT_EQ(0, pthread_detach(thread));
    EXPECT_EQ(1, CSP_select(nfds, &read_fds, NULL, NULL, &tv));
    EXPECT_TRUE(FD_ISSET(testsocks[0], &read_fds));
    EXPECT_FALSE(FD_ISSET(fd, &read_fds));

    // Clear the queue
    ASSERT_EQ_WITH_ERRNO(sizeof(out_buf2), CSP_read(testsocks[0], in_buf, sizeof(in_buf)));

    // Test write wait
    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(fd, &write_fds);
    FD_SET(testsocks[0], &write_fds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    ASSERT_EQ_WITH_ERRNO(2, CSP_select(nfds, NULL, &write_fds, NULL, &tv));
    EXPECT_TRUE(FD_ISSET(testsocks[0], &write_fds));
    EXPECT_TRUE(FD_ISSET(fd, &write_fds));

    close(testsocks[0]);
    close(testsocks[1]);

    // Open another socket.
    int fd2 = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE_WITH_ERRNO(fd2, 0);

    // Send buffer data back through
    ASSERT_EQ_WITH_ERRNO(sizeof(out_buf), write(_device_socks[0], out_buf, sizeof(out_buf)));
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);
    FD_SET(fd2, &read_fds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    EXPECT_EQ(1, CSP_select(nfds, &read_fds, NULL, NULL, &tv));
    EXPECT_TRUE(FD_ISSET(fd, &read_fds));
    EXPECT_FALSE(FD_ISSET(fd2, &read_fds));

    // Clear the queue
    memset(in_buf, 0, sizeof(in_buf));
    ASSERT_EQ_WITH_ERRNO(BUF_SIZE, CSP_read(fd, in_buf, sizeof(in_buf)));
    ASSERT_EQ(0, memcmp(in_buf, payload, BUF_SIZE));

    EXPECT_EQ_WITH_ERRNO(0, CSP_close(fd));
    EXPECT_EQ_WITH_ERRNO(0, CSP_close(fd2));
}
