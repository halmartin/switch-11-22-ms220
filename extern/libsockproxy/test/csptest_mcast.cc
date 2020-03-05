/*
 *  Click socket proxy test app -- mulitcast tests
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
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "csptest.h"
#include "sockproxy.h"
#include "sockproxy_pkt.h"
#include "CSPFixture.hh"

static void
check_socket_string_read(int sockfd, const char* str)
{
    size_t len = strlen(str) + 2;
    char buf[len];
    memset(buf, 0, len);

    ssize_t bytes = read(sockfd, buf, len - 1);
    ASSERT_GT_WITH_ERRNO(bytes, 0);
    ASSERT_STREQ(str, buf);
}

TEST_F(CSPFixture, MulticastMemberships)
{
    ASSERT_EQ_WITH_ERRNO(0, CSP_set_config(&_cfg));

    int fd = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE_WITH_ERRNO(fd, 0);

    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons(2000);

    ASSERT_EQ_WITH_ERRNO(0, CSP_bind(fd, (struct sockaddr*)&sa, sizeof(sa)));

    struct ip_mreqn mreq;
    mreq.imr_address.s_addr = INADDR_ANY;
    mreq.imr_ifindex = 20;

    // Adding 224.0.0.5 on VLAN 20
    inet_pton(AF_INET, "224.0.0.5", &mreq.imr_multiaddr);
    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd, SOL_IP, IP_ADD_MEMBERSHIP,
                                      &mreq, sizeof(mreq)));

    ASSERT_NO_FATAL_FAILURE(
        check_socket_string_read(_add_mbr_socks[0], "GROUP_IP 224.0.0.5, VLAN 20"));

    // Adding 224.0.0.6 on VLAN 20
    inet_pton(AF_INET, "224.0.0.6", &mreq.imr_multiaddr);
    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd, SOL_IP, IP_ADD_MEMBERSHIP,
                                      &mreq, sizeof(mreq)));
    ASSERT_NO_FATAL_FAILURE(
        check_socket_string_read(_add_mbr_socks[0], "GROUP_IP 224.0.0.6, VLAN 20"));

    // Adding 224.0.0.6 on VLAN 20 again (should fail)
    ASSERT_EQ(-1, CSP_setsockopt(fd, SOL_IP, IP_ADD_MEMBERSHIP,
                                 &mreq, sizeof(mreq)));
    EXPECT_EQ(EADDRINUSE, errno);

    // Drop non-existant 224.0.0.1 from VLAN 20
    inet_pton(AF_INET, "224.0.0.1", &mreq.imr_multiaddr);
    ASSERT_EQ(-1, CSP_setsockopt(fd, SOL_IP, IP_DROP_MEMBERSHIP,
                                 &mreq, sizeof(mreq)));
    EXPECT_EQ(EADDRNOTAVAIL, errno);

    // Add 224.0.0.6 on VLAN 10
    inet_pton(AF_INET, "224.0.0.6", &mreq.imr_multiaddr);
    mreq.imr_ifindex = 10;
    ASSERT_EQ(0, CSP_setsockopt(fd, SOL_IP, IP_ADD_MEMBERSHIP,
                                &mreq, sizeof(mreq)));
    ASSERT_NO_FATAL_FAILURE(
        check_socket_string_read(_add_mbr_socks[0], "GROUP_IP 224.0.0.6, VLAN 10"));

    // Add 224.0.0.6 on VLAN 10 using address (should fail because it's already added)
    inet_pton(AF_INET, "192.168.10.1", &mreq.imr_address);
    mreq.imr_ifindex = 0;
    ASSERT_EQ(-1, CSP_setsockopt(fd, SOL_IP, IP_ADD_MEMBERSHIP,
                                 &mreq, sizeof(mreq)));
    EXPECT_EQ(EADDRINUSE, errno);

    // Add 224.1.0.1 on unknown IP address (should fail)
    inet_pton(AF_INET, "224.1.0.1", &mreq.imr_multiaddr);
    inet_pton(AF_INET, "128.227.205.222", &mreq.imr_address);
    ASSERT_EQ(-1, CSP_setsockopt(fd, SOL_IP, IP_ADD_MEMBERSHIP,
                                 &mreq, sizeof(mreq)));
    EXPECT_EQ(ENODEV, errno);

    // Add 224.1.0.1 on VLAN 98 (should fail because VLAN 98 is not defined)
    mreq.imr_address.s_addr = INADDR_ANY;
    mreq.imr_ifindex = 98;
    ASSERT_EQ(-1, CSP_setsockopt(fd, SOL_IP, IP_ADD_MEMBERSHIP,
                                 &mreq, sizeof(mreq)));
    EXPECT_EQ(ENODEV, errno);

    // Drop 224.0.0.6 from VLAN 20
    inet_pton(AF_INET, "224.0.0.6", &mreq.imr_multiaddr);
    mreq.imr_ifindex = 20;
    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd, SOL_IP, IP_DROP_MEMBERSHIP,
                                      &mreq, sizeof(mreq)));
    ASSERT_NO_FATAL_FAILURE(
        check_socket_string_read(_remove_mbr_socks[0],"GROUP_IP 224.0.0.6, VLAN 20"));

    // Drop 224.0.0.6 from VLAN 10
    inet_pton(AF_INET, "224.0.0.6", &mreq.imr_multiaddr);
    mreq.imr_ifindex = 10;
    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd, SOL_IP, IP_DROP_MEMBERSHIP,
                                      &mreq, sizeof(mreq)));
    ASSERT_NO_FATAL_FAILURE(
        check_socket_string_read(_remove_mbr_socks[0],"GROUP_IP 224.0.0.6, VLAN 10"));

    // Add 224.0.0.6 on VLAN 10 using address
    // This should work now because we dropped it previously.
    inet_pton(AF_INET, "192.168.10.1", &mreq.imr_address);
    mreq.imr_ifindex = 0;
    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd, SOL_IP, IP_ADD_MEMBERSHIP,
                                      &mreq, sizeof(mreq)));
    ASSERT_NO_FATAL_FAILURE(
        check_socket_string_read(_add_mbr_socks[0], "GROUP_IP 224.0.0.6, VLAN 10"));

    // Drop 224.0.0.5 from VLAN 20
    inet_pton(AF_INET, "224.0.0.5", &mreq.imr_multiaddr);
    mreq.imr_address.s_addr = INADDR_ANY;
    mreq.imr_ifindex = 20;
    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd, SOL_IP, IP_DROP_MEMBERSHIP,
                                      &mreq, sizeof(mreq)));
    ASSERT_NO_FATAL_FAILURE(
        check_socket_string_read(_remove_mbr_socks[0],"GROUP_IP 224.0.0.5, VLAN 20"));

    // Drop 224.0.0.6 from VLAN 10 using address
    inet_pton(AF_INET, "224.0.0.6", &mreq.imr_multiaddr);
    inet_pton(AF_INET, "192.168.10.1", &mreq.imr_address);
    mreq.imr_ifindex = 0;
    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd, SOL_IP, IP_DROP_MEMBERSHIP,
                                      &mreq, sizeof(mreq)));
    ASSERT_NO_FATAL_FAILURE(
        check_socket_string_read(_remove_mbr_socks[0], "GROUP_IP 224.0.0.6, VLAN 10"));

    EXPECT_EQ_WITH_ERRNO(0, CSP_close(fd));
}


TEST_F(CSPFixture, MulticastInterfaces)
{
    ASSERT_EQ_WITH_ERRNO(0, CSP_set_config(&_cfg));

    int fd = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE_WITH_ERRNO(fd, 0);

    struct ip_mreqn mreq;
    // Set interface to VLAN 200 via address.
    inet_pton(AF_INET, "192.168.200.1", &mreq.imr_address);
    mreq.imr_ifindex = 0;
    mreq.imr_multiaddr.s_addr = 0;

    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd, SOL_IP, IP_MULTICAST_IF,
                                      &mreq, sizeof(mreq)));

    // Set interface to VLAN 200 via both address and index.
    mreq.imr_ifindex = 200;

    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd, SOL_IP, IP_MULTICAST_IF,
                                      &mreq, sizeof(mreq)));

    // Set interface with conflicting address and index (should fail)
    mreq.imr_ifindex = 876;

    ASSERT_EQ(-1, CSP_setsockopt(fd, SOL_IP, IP_MULTICAST_IF,
                                 &mreq, sizeof(mreq)));
    ASSERT_EQ(EADDRNOTAVAIL, errno);

    // Set interface to VLAN 200 via index.
    mreq.imr_ifindex = 200;
    mreq.imr_address.s_addr = 0;

    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd, SOL_IP, IP_MULTICAST_IF,
                                      &mreq, sizeof(mreq)));

    // Set interface to incorrect address (should fail)
    mreq.imr_ifindex = 0;
    inet_pton(AF_INET, "128.227.205.231", &mreq.imr_address);

    ASSERT_EQ(-1, CSP_setsockopt(fd, SOL_IP, IP_MULTICAST_IF,
                                 &mreq, sizeof(mreq)));
    ASSERT_EQ(EADDRNOTAVAIL, errno);
}

TEST_F(CSPFixture, MulticastReceive)
{
    static const int BUF_SIZE = 800;
    ASSERT_EQ_WITH_ERRNO(0, CSP_set_config(&_cfg));

    int fd = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE_WITH_ERRNO(fd, 0);

    // Set non-blocking
    ASSERT_EQ_WITH_ERRNO(0, CSP_fcntl_int(fd, F_SETFL, O_NONBLOCK));

    // Bind to a port
    struct sockaddr_in sa_bind;
    sa_bind.sin_family = AF_INET;
    sa_bind.sin_addr.s_addr = INADDR_ANY;
    sa_bind.sin_port = htons(2000);

    ASSERT_EQ_WITH_ERRNO(0, CSP_bind(fd, (struct sockaddr*)&sa_bind, sizeof(sa_bind)));

    // Join multicast group 224.0.0.5
    struct ip_mreqn mreq;
    mreq.imr_address.s_addr = INADDR_ANY;
    mreq.imr_ifindex = 20;
    inet_pton(AF_INET, "224.0.0.5", &mreq.imr_multiaddr);

    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd, SOL_IP, IP_ADD_MEMBERSHIP,
                                      &mreq, sizeof(mreq)));
    ASSERT_NO_FATAL_FAILURE(
        check_socket_string_read(_add_mbr_socks[0], "GROUP_IP 224.0.0.5, VLAN 20"));

    // Set up a sockproxy packet that would be arriving from Click.
    uint8_t buf[BUF_SIZE + SOCKPROXY_UDP_HEADERS_SIZE];
    memset(buf, 0, sizeof(buf));
    struct sockproxy_pkt_hdr* sphdr = (struct sockproxy_pkt_hdr*)buf;
    struct iphdr* iphdr = (struct iphdr*)(buf + sizeof(struct sockproxy_pkt_hdr));
    struct udphdr* udphdr = (struct udphdr*)(buf + sizeof(struct sockproxy_pkt_hdr) +
                                             sizeof(struct iphdr));
    uint8_t* payload = buf + SOCKPROXY_UDP_HEADERS_SIZE;

    sphdr->vlan = 20;
    iphdr->version = 4;
    iphdr->ihl = 5;
    iphdr->tos = 0;
    iphdr->ttl = 1;
    iphdr->tot_len = htons(sizeof(buf) - sizeof(struct sockproxy_pkt_hdr));
    iphdr->protocol = IPPROTO_UDP;
    iphdr->saddr = 0x01010101;  // 1.1.1.1 (NOTE: this should be network order)
    iphdr->daddr = mreq.imr_multiaddr.s_addr;
    udphdr->source = htons(2001);
    udphdr->dest = htons(2000);
    udphdr->len = htons(BUF_SIZE + sizeof(struct udphdr));

    for (int i = 0; i < BUF_SIZE; i++)
        payload[i] = i % 0xFF;

    // Inject the packet.
    ASSERT_EQ_WITH_ERRNO(sizeof(buf), write(_device_socks[0], buf, sizeof(buf)));

    // Read the packet out.
    uint8_t in_buf[BUF_SIZE + 1];
    memset(in_buf, 0, sizeof(in_buf));
    struct sockaddr_in sa_recv = {0};
    socklen_t sa_recv_len = sizeof(sa_recv);

    ASSERT_EQ_WITH_ERRNO(BUF_SIZE,
                    CSP_recvfrom(fd,
                                 in_buf,
                                 sizeof(in_buf),
                                 0,
                                 (struct sockaddr*)&sa_recv,
                                 &sa_recv_len));

    EXPECT_EQ(0, memcmp(in_buf, buf + SOCKPROXY_UDP_HEADERS_SIZE, BUF_SIZE));
    EXPECT_EQ(sa_recv_len, sizeof(sa_recv));
    EXPECT_EQ(AF_INET, sa_recv.sin_family);
    EXPECT_EQ(iphdr->saddr, sa_recv.sin_addr.s_addr);
    EXPECT_EQ(udphdr->source, sa_recv.sin_port);

    ASSERT_EQ_WITH_ERRNO(0, CSP_close(fd));
}

TEST_F(CSPFixture, MulticastSend)
{
    static const int BUF_SIZE = 1294;
    ASSERT_EQ_WITH_ERRNO(0, CSP_set_config(&_cfg));

    int fd = CSP_socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE_WITH_ERRNO(fd, 0);

    // Set interface to VLAN 5 via address.
    struct ip_mreqn mreq_if;
    inet_pton(AF_INET, "192.168.5.1", &mreq_if.imr_address);
    mreq_if.imr_ifindex = 0;
    mreq_if.imr_multiaddr.s_addr = 0;

    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd, SOL_IP, IP_MULTICAST_IF,
                                      &mreq_if, sizeof(mreq_if)));

    // Bind to port 41923.
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr= INADDR_ANY;
    sa.sin_port = htons(41923);

    ASSERT_EQ_WITH_ERRNO(0, CSP_bind(fd, (struct sockaddr*)&sa, sizeof(sa)));

    // Send something to 224.0.0.5, port 28123.
    struct sockaddr_in sa_dest = {
        .sin_family = AF_INET,
        .sin_port = htons(28123),
        .sin_addr = {
            .s_addr = htonl(0xE0000005) // 224.0.0.5
        }
    };

    uint8_t out_buf[BUF_SIZE];
    for (int i = 0; i < BUF_SIZE; i++)
        out_buf[i] = i % 0xFF;

    ASSERT_EQ_WITH_ERRNO(BUF_SIZE,
                    CSP_sendto(fd, out_buf, BUF_SIZE, 0,
                               (struct sockaddr*)&sa_dest, sizeof(sa_dest)));

    uint8_t in_buf[BUF_SIZE + SOCKPROXY_UDP_HEADERS_SIZE + 1];
    ssize_t bytes = read(_device_socks[0], in_buf, sizeof(in_buf));
    ASSERT_EQ_WITH_ERRNO(BUF_SIZE + SOCKPROXY_UDP_HEADERS_SIZE, bytes);
    EXPECT_EQ(5, ((struct sockproxy_pkt_hdr*)in_buf)->vlan);

    verify_ip_header((struct iphdr*)(in_buf + sizeof(struct sockproxy_pkt_hdr)),
                     mreq_if.imr_address.s_addr,
                     htonl(0xE0000005),  // 224.0.0.5
                     IPPROTO_UDP,
                     htons(BUF_SIZE + sizeof(struct iphdr) + sizeof(struct udphdr)),
                     1);

    // Let's do it again, but with TTL 5.
    int new_ttl = 5;
    ASSERT_EQ_WITH_ERRNO(0, CSP_setsockopt(fd, SOL_IP, IP_MULTICAST_TTL, &new_ttl,
                                      sizeof(new_ttl)));

    ASSERT_EQ_WITH_ERRNO(BUF_SIZE,
                    CSP_sendto(fd, out_buf, BUF_SIZE, 0,
                               (struct sockaddr*)&sa_dest, sizeof(sa_dest)));

    memset(in_buf, 0, sizeof(in_buf));
    bytes = read(_device_socks[0], in_buf, sizeof(in_buf));
    ASSERT_EQ_WITH_ERRNO(BUF_SIZE + SOCKPROXY_UDP_HEADERS_SIZE, bytes);
    EXPECT_EQ(5, ((struct sockproxy_pkt_hdr*)in_buf)->vlan);

    verify_ip_header((struct iphdr*)(in_buf + sizeof(struct sockproxy_pkt_hdr)),
                     mreq_if.imr_address.s_addr,
                     htonl(0xE0000005), // 224.0.0.5
                     IPPROTO_UDP,
                     htons(BUF_SIZE + sizeof(struct iphdr) + sizeof(struct udphdr)),
                     new_ttl);

    EXPECT_EQ_WITH_ERRNO(0, CSP_close(fd));
}

