/*
 *  Click socket proxy test fixture implementation
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

#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include "CSPFixture.hh"

void
CSPFixture::SetUp()
{
    _device_socks[0] = -1;
    _device_socks[1] = -1;
    _add_mbr_socks[0] = -1;
    _add_mbr_socks[1] = -1;
    _remove_mbr_socks[0] = -1;
    _remove_mbr_socks[1] = -1;

    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, _device_socks));
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, _add_mbr_socks));
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, _remove_mbr_socks));

    fcntl(_device_socks[0], F_SETFL, O_NONBLOCK);
    fcntl(_device_socks[1], F_SETFL, O_NONBLOCK);
    fcntl(_add_mbr_socks[0], F_SETFL, O_NONBLOCK);
    fcntl(_add_mbr_socks[1], F_SETFL, O_NONBLOCK);
    fcntl(_remove_mbr_socks[0], F_SETFL, O_NONBLOCK);
    fcntl(_remove_mbr_socks[1], F_SETFL, O_NONBLOCK);

    memset(&_cfg, 0, sizeof(sockproxy_cfg));
    _cfg.device_fd = _device_socks[1];
    _cfg.add_membership_fd = _add_mbr_socks[1];
    _cfg.del_membership_fd = _remove_mbr_socks[1];

    ASSERT_NO_FATAL_FAILURE(add_interface("vlan5", "192.168.5.1", 5));
    ASSERT_NO_FATAL_FAILURE(add_interface("vlan10", "192.168.10.1", 10));
    ASSERT_NO_FATAL_FAILURE(add_interface("vlan20", "192.168.20.1", 20));
    ASSERT_NO_FATAL_FAILURE(add_interface("vlan200", "192.168.200.1", 200));
    ASSERT_NO_FATAL_FAILURE(add_interface("vlan4094", "192.168.250.1", 4094));
}

void
CSPFixture::TearDown()
{
    close(_device_socks[0]);
    close(_device_socks[1]);
    close(_add_mbr_socks[0]);
    close(_add_mbr_socks[1]);
    close(_remove_mbr_socks[0]);
    close(_remove_mbr_socks[1]);

    ASSERT_EQ(0, CSP_clear_config());
}

void
CSPFixture::add_interface(const char* name, const char* ip_addr, uint16_t vid)
{
    ASSERT_NE((char*)NULL, name);
    ASSERT_NE((char*)NULL, ip_addr);
    ASSERT_NE(0, vid);
    ASSERT_GE(4095, vid);
    ASSERT_GE(IFNAMSIZ, strnlen(name, IFNAMSIZ));
    ASSERT_GE(INET_ADDRSTRLEN, strnlen(ip_addr, INET_ADDRSTRLEN));

    struct sockproxy_iface iface;
    strcpy(iface.name, name);
    ASSERT_EQ(1, inet_pton(AF_INET, ip_addr, &iface.addr));
    iface.vid = vid;

    _ifaces.push_back(iface);
    _cfg.ifaces = _ifaces.data();
    _cfg.num_ifaces = _ifaces.size();
}
