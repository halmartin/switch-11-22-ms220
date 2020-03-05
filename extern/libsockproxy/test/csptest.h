/*
 *  Click socket proxy test app -- master header
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

#ifndef CSPTEST_H
#define CSPTEST_H

#include <gtest/gtest.h>
#include <errno.h>
#include <stdint.h>
#include "sockproxy_pkt.h"
#include "sockproxy.h"


// These macros extend the normal Google Test assertion macros by also
// outputting the value of errno.
#define ASSERT_EQ_WITH_ERRNO(expected, actual) \
    ASSERT_EQ(expected, actual) << "Error: " << strerror(errno) << " (" << errno << ")"
#define ASSERT_NE_WITH_ERRNO(expected, actual) \
    ASSERT_NE(expected, actual) << "Error: " << strerror(errno) << " (" << errno << ")"
#define ASSERT_LT_WITH_ERRNO(val1, val2)       \
    ASSERT_LT(val1, val2) << "Error: " << strerror(errno) << " (" << errno << ")"
#define ASSERT_LE_WITH_ERRNO(val1, val2)       \
    ASSERT_LE(val1, val2) << "Error: " << strerror(errno) << " (" << errno << ")"
#define ASSERT_GT_WITH_ERRNO(val1, val2)       \
    ASSERT_GT(val1, val2) << "Error: " << strerror(errno) << " (" << errno << ")"
#define ASSERT_GE_WITH_ERRNO(val1, val2)       \
    ASSERT_GE(val1, val2) << "Error: " << strerror(errno) << " (" << errno << ")"


#define EXPECT_EQ_WITH_ERRNO(expected, actual) \
    EXPECT_EQ(expected, actual) << "Error: " << strerror(errno) << " (" << errno << ")"
#define EXPECT_NE_WITH_ERRNO(expected, actual) \
    EXPECT_EQ(expected, actual) << "Error: " << strerror(errno) << " (" << errno << ")"
#define EXPECT_LT_WITH_ERRNO(val1, val2)       \
    EXPECT_LT(val1, val2) << "Error: " << strerror(errno) << " (" << errno << ")"
#define EXPECT_LE_WITH_ERRNO(val1, val2)       \
    EXPECT_LE(val1, val2) << "Error: " << strerror(errno) << " (" << errno << ")"
#define EXPECT_GT_WITH_ERRNO(val1, val2)       \
    EXPECT_GT(val1, val2) << "Error: " << strerror(errno) << " (" << errno << ")"
#define EXPECT_GE_WITH_ERRNO(val1, val2)       \
    EXPECT_GE(val1, val2) << "Error: " << strerror(errno) << " (" << errno << ")"

#define SOCKPROXY_UDP_HEADERS_SIZE (sizeof(sockproxy_pkt_hdr) + \
                                    sizeof(struct iphdr) +      \
                                    sizeof(struct udphdr))

void
verify_ip_header(struct iphdr* iphdr, in_addr_t src_addr,
                 in_addr_t dst_addr, uint8_t protocol,
                 uint16_t tot_len, uint8_t ttl = 64, uint8_t tos = 0);

void
verify_udp_header(struct udphdr* udphdr, uint16_t src_port,
                  uint16_t dst_port, uint16_t len);

#endif
