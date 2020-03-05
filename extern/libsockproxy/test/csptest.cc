/*
 *  Click socket proxy test app
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
#include "sockproxy.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <errno.h>

// ALL integer parameters to this function should be in network order!
void
verify_ip_header(struct iphdr* iphdr, in_addr_t src_addr,
                 in_addr_t dst_addr, uint8_t protocol,
                 uint16_t tot_len, uint8_t ttl, uint8_t tos)
{
    EXPECT_EQ(4, iphdr->version);
    EXPECT_EQ(5, iphdr->ihl);
    EXPECT_EQ(src_addr, iphdr->saddr);
    EXPECT_EQ(dst_addr, iphdr->daddr);
    EXPECT_EQ(protocol, iphdr->protocol);
    EXPECT_EQ(ttl, iphdr->ttl);
    EXPECT_EQ(tos, iphdr->tos);
    EXPECT_EQ(tot_len, iphdr->tot_len);
}

// ALL integer parameters to this function should be in network order!
void
verify_udp_header(struct udphdr* udphdr, uint16_t src_port,
                  uint16_t dst_port, uint16_t len)
{
    EXPECT_EQ(src_port, udphdr->source);
    EXPECT_EQ(dst_port, udphdr->dest);
    EXPECT_EQ(len, udphdr->len);
}

static void
debug_function(enum csp_debug_class dbg, const char* msg, va_list args)
{
    vprintf(msg, args);
    printf("\n");
}

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    //CSP_register_debug(debug_function);
    return RUN_ALL_TESTS();
}
