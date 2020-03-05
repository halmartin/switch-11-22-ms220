# Makefile for libsockproxy/lib
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
CXX=$(CROSS_COMPILE)g++
CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar
CPPFLAGS=-I../include
CXXFLAGS=-std=gnu++0x -fnothrow-opt
CFLAGS=

OBJS=sockproxy.o sockproxy_api.o sockproxy_xfer.o sockproxy_debug.o
OBJ_DIR=.

ifeq ($(SOCKPROXY_TEST),1)
CPPFLAGS += -DSOCKPROXY_TEST
endif

ifeq ($(DEBUG),1)
CXXFLAGS += -O0 -ggdb
CFLAGS += --O0 -ggdb
else
CXXFLAGS += -Os
CFLAGS += -Os
endif

.PHONY: all clean

all: $(OBJ_DIR)/libsockproxy.a

clean:
	rm -f $(OBJ_DIR)/libsockproxy.a $(addprefix $(OBJ_DIR)/,$(OBJS))

$(OBJ_DIR)/libsockproxy.a: $(OBJS)
	$(AR) rs $@ $(addprefix $(OBJ_DIR)/,$(OBJS))

%.o: %.cc
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) -o $(OBJ_DIR)/$@ $<

%.o: %.c
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $(OBJ_DIR)/$@ $<
