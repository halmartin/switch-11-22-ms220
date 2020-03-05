# Makefile for libsockproxy
#
# Copyright (C) 2014 Cisco Systems, Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

CROSS_COMPILE=

.PHONY: all clean test run-test

all:
	$(MAKE) -C lib CROSS_COMPILE=$(CROSS_COMPILE)

clean:
	$(MAKE) -C lib clean
	$(MAKE) -C lib OBJ_DIR=$(PWD)/test clean
	$(MAKE) -C test clean

test:
	$(MAKE) -C lib SOCKPROXY_TEST=1 DEBUG=1 OBJ_DIR=$(PWD)/test
	$(MAKE) -C test

run-test: test
	test/csptest


