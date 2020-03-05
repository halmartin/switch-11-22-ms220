/*
 *  Click socket proxy test fixture
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
#include "sockproxy.h"
#include <vector>

class CSPFixture : public ::testing::Test {
protected:
    int _device_socks[2];
    int _add_mbr_socks[2];
    int _remove_mbr_socks[2];

    virtual void SetUp();
    virtual void TearDown();

    struct sockproxy_cfg _cfg;
    std::vector<struct sockproxy_iface> _ifaces;

    void add_interface(const char* name, const char* ip_addr, uint16_t vid);
    static void fill_sockproxy_iface(struct sockproxy_iface* iface,
                                     const char* name, const char* ip_addr,
                                     uint16_t vid);
};
