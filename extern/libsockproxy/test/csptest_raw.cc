/*
 *  Click socket proxy test app -- raw IP tests
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
#include <arpa/inet.h>
#include <fcntl.h>
#include "csptest.h"
#include "CSPFixture.hh"

TEST_F(CSPFixture, SendRawPacket)
{
    static const int BUF_SIZE = 1304;
    ASSERT_EQ_WITH_ERRNO(0, CSP_set_config(&_cfg));

    // Let's pretend this is ICMP (even though it's not).
    int fd = CSP_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    ASSERT_GE_WITH_ERRNO(fd, 0);

    // Generate a repeatable "random" sequence for the data.
    unsigned int seed = 3442687;
    uint8_t out_buf[BUF_SIZE];
    for (int i = 0; i < sizeof(out_buf); i++)
        out_buf[i] = rand_r(&seed) % 0xFF;

    // Bind to VLAN 4094.
    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd,
                                      SOL_SOCKET,
                                      SO_BINDTODEVICE,
                                      "vlan4094",
                                      sizeof("vlan4094")));

    // Put together a packet and send it.
    struct sockaddr_in sa_dest;
    sa_dest.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.250.20", &sa_dest.sin_addr);
    struct iovec iov = {
        .iov_base = out_buf,
        .iov_len = BUF_SIZE
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

    ASSERT_EQ_WITH_ERRNO(BUF_SIZE, CSP_sendmsg(fd, &msg, 0));

    // Read it out as if we're Click
    uint8_t in_buf[BUF_SIZE + sizeof(struct iphdr) + sizeof(struct sockproxy_pkt_hdr) + 1];
    memset(in_buf, 0, sizeof(in_buf));

    ssize_t bytes = read(_device_socks[0], in_buf, sizeof(in_buf));

    ASSERT_EQ_WITH_ERRNO(sizeof(in_buf) - 1, bytes);
    ASSERT_EQ(0, memcmp(out_buf,
                        in_buf + sizeof(struct iphdr) + sizeof(struct sockproxy_pkt_hdr),
                        BUF_SIZE));
    EXPECT_EQ(4094, ((struct sockproxy_pkt_hdr*)in_buf)->vlan);

    verify_ip_header((struct iphdr*)&in_buf[sizeof(sockproxy_pkt_hdr)],
                     0,
                     sa_dest.sin_addr.s_addr,
                     IPPROTO_ICMP,
                     htons(BUF_SIZE + sizeof(struct iphdr)));

    // Let's try it with our own header.
    int optval = 1;
    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd, SOL_IP, IP_HDRINCL,
                                      &optval, sizeof(optval)));

    uint8_t out_buf2[BUF_SIZE + sizeof(struct iphdr)];
    memset(out_buf2, 0, sizeof(struct iphdr));
    memcpy(out_buf2 + sizeof(struct iphdr), out_buf, BUF_SIZE);

    struct iphdr* ip_hdr = (struct iphdr*)out_buf2;
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->tos = 0;
    ip_hdr->ttl = 64;
    ip_hdr->tot_len = htons(sizeof(out_buf));
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->saddr = 0;
    ip_hdr->daddr = sa_dest.sin_addr.s_addr;

    iov.iov_base = out_buf2;
    iov.iov_len = sizeof(out_buf2);
    ASSERT_EQ_WITH_ERRNO(sizeof(out_buf2), CSP_sendmsg(fd, &msg, 0));

    // Read it out as if we're Click
    memset(in_buf, 0, sizeof(in_buf));
    bytes = read(_device_socks[0], in_buf, sizeof(in_buf));

    ASSERT_EQ_WITH_ERRNO(sizeof(in_buf) - 1, bytes);
    EXPECT_EQ(0, memcmp(out_buf2,
                        in_buf + sizeof(struct sockproxy_pkt_hdr),
                        BUF_SIZE + sizeof(struct iphdr)));
    EXPECT_EQ(4094, ((struct sockproxy_pkt_hdr*)in_buf)->vlan);

    EXPECT_EQ_WITH_ERRNO(0, CSP_close(fd));
}


TEST_F(CSPFixture, ReceiveRawPacket)
{
    static const int BUF_SIZE = 492;
    ASSERT_EQ_WITH_ERRNO(0, CSP_set_config(&_cfg));

    // Let's pretend this is ICMP (even though it's not).
    int fd = CSP_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    ASSERT_GE_WITH_ERRNO(fd, 0);

    ASSERT_EQ_WITH_ERRNO(0, CSP_fcntl_int(fd, F_SETFL, O_NONBLOCK));

    // Bind to VLAN 200
    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd,
                                      SOL_SOCKET,
                                      SO_BINDTODEVICE,
                                      "vlan200",
                                      sizeof("vlan200")));

    uint8_t out_buf[BUF_SIZE + sizeof(sockproxy_pkt_hdr) + sizeof(iphdr)];
    memset(out_buf, 0, sizeof(out_buf));

    sockproxy_pkt_hdr* sp_hdr = (sockproxy_pkt_hdr*)out_buf;
    iphdr* ip_hdr = (iphdr*)(out_buf + sizeof(sockproxy_pkt_hdr));
    uint8_t* payload = out_buf + sizeof(sockproxy_pkt_hdr) + sizeof(iphdr);

    // Generate a repeatable "random" sequence for the data.
    unsigned int seed = 3467849;
    for (int i = 0; i < BUF_SIZE; i++)
        payload[i] = rand_r(&seed) % 0xFF;

    sp_hdr->vlan = 200;
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->tos = 0;
    ip_hdr->ttl = 64;
    ip_hdr->tot_len = htons(BUF_SIZE + sizeof(iphdr));
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->saddr = htonl(0x0A000503);   // 10.0.5.3
    ip_hdr->daddr = htonl(0xC0A8C801);   // 192.168.200.1

    ssize_t bytes = write(_device_socks[0], out_buf, sizeof(out_buf));
    ASSERT_EQ_WITH_ERRNO(sizeof(out_buf), bytes);

    uint8_t in_buf[BUF_SIZE + sizeof(iphdr) + 1];
    memset(in_buf, 0, sizeof(in_buf));

    struct iovec iov = {
        .iov_base = in_buf,
        .iov_len = sizeof(in_buf)
    };

    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = 0;
    sa.sin_port = 0;

    struct msghdr msg = {
        .msg_name = &sa,
        .msg_namelen = sizeof(sa),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = 0,
        .msg_controllen = 0,
        .msg_flags = 0
    };

    bytes = CSP_recvmsg(fd, &msg, 0);
    ASSERT_EQ_WITH_ERRNO(BUF_SIZE + sizeof(iphdr), bytes);
    EXPECT_EQ(0, memcmp(in_buf, ip_hdr, BUF_SIZE + sizeof(iphdr)));
    EXPECT_EQ(AF_INET, sa.sin_family);
    EXPECT_EQ(ip_hdr->saddr, sa.sin_addr.s_addr);
    EXPECT_EQ(ip_hdr->protocol, sa.sin_port);
    EXPECT_EQ_WITH_ERRNO(0, CSP_close(fd));
}

