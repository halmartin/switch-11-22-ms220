# Makefile for libsockproxy/test
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

CXX=g++
AR=ar
CPPFLAGS=-I../include -DSOCKPROXY_TEST
CXXFLAGS=-ggdb -O0

# Current Debian and Ubuntu systems include the gtest source and not the binaries,
# while older systems include the binaries and not the source!  This should let us
# build on either.
ifeq ($(shell which gtest-config),)

GTEST_OBJ=gtest-all.o
GTEST_LIBS=-pthread $(GTEST_OBJ)
GTEST_DIR=/usr/src/gtest
CXXFLAGS += -pthread
ifeq ($(wildcard $(GTEST_DIR)),)
$(error Google C++ Testing Framework not found, please run "sudo apt-get install libgtest-dev")
endif

else
GTEST_OBJ=
GTEST_LIBS=$(shell gtest-config --ldflags --libs)
CPPFLAGS += $(shell gtest-config --cppflags)
CXXFLAGS += $(shell gtest-config --cxxflags)
endif

OBJS=csptest.o CSPFixture.o csptest_basic.o csptest_udp.o csptest_mcast.o csptest_raw.o

.PHONY: all clean

all: csptest

clean:
	rm -f csptest $(OBJS) $(GTEST_OBJ)

ifneq ($(GTEST_OBJ),)
$(GTEST_OBJ):
	$(CXX) -c -I$(GTEST_DIR) -o $(GTEST_OBJ) $(CPPFLAGS) $(CXXFLAGS) $(GTEST_DIR)/src/gtest-all.cc
endif

csptest: $(GTEST_OBJ) $(OBJS) libsockproxy.a
	$(CXX) -o $@ $(OBJS) libsockproxy.a $(GTEST_LIBS)

%.o: %.cc
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) -o $@ $<
