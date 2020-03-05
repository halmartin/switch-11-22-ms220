#
# Makefile for the Broadcom et driver
#
# Copyright (C) 2013, Broadcom Corporation. All Rights Reserved.
# 
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
ETSRCDIR := ../src/et
SHARED   := ../src/shared

et-objs := $(ETSRCDIR)/sys/et_linux.o $(ETSRCDIR)/sys/etc.o

## from linux dir ##########
export SRCBASE_et := $(src)/$(ETSRCDIR)/sys/../../
export SRCBASE_hnd := $(src)/$(SHARED)/../
KBUILD_CFLAGS += -I$(SRCBASE_et)/include -I$(SRCBASE_hnd)/include -DBCMDRIVER -Dlinux
KBUILD_AFLAGS += -I$(SRCBASE_et)/include -I$(SRCBASE_hnd)/include
#################################

ifdef $(CONFIG_ET)
obj-$(CONFIG_ET) := et.o

else
@SWITCH_ARM_BOARD@ = y

ifeq ($(MERAKI_WOLFCASTLE),y)
CONFIG_MACH_HX4 = y
EXTRA_CFLAGS += -DCONFIG_MACH_HX4
obj-m := et.o
else ifeq ($(MERAKI_BRUMBY),y)
CONFIG_MACH_HR3 = y
CONFIG_MACH_IPROC_P7 = y
EXTRA_CFLAGS += -DCONFIG_MACH_HR3 -DCONFIG_MACH_IPROC_P7
obj-m := et.o
endif

endif

et-objs         += $(ETSRCDIR)/sys/etcgmac.o
EXTRA_CFLAGS	+= -DDMA -Wno-error
EXTRA_CFLAGS    += -DGMAC_RATE_LIMITING -DBCMDMA32 -DBCMDBG_ERR

ifeq ($(CONFIG_BCM_IPROC_GMAC_SG),y)
EXTRA_CFLAGS    += -DBCMDMASGLISTOSL
endif

ifeq ($(CONFIG_ET_ALL_PASSIVE_ON),y)
EXTRA_CFLAGS	+= -DGMAC_ALL_PASSIVE
else
ifeq ($(CONFIG_ET_ALL_PASSIVE_RUNTIME),y)
EXTRA_CFLAGS	+= -DGMAC_ALL_PASSIVE
endif
endif

ifeq ($(CONFIG_ET_NAPI_POLL),y)
EXTRA_CFLAGS	+= -DGMAC_NAPI_POLL
else
ifeq ($(CONFIG_ET_NAPI2_POLL),y)
EXTRA_CFLAGS	+= -DGMAC_NAPI2_POLL
endif
endif

EXTRA_CFLAGS	+= -I$(src)/$(ETSRCDIR)/sys

et-objs += $(SHARED)/nvramstubs.o
et-objs += $(SHARED)/hnddma.o
et-objs += $(SHARED)/bcmutils.o
et-objs += $(SHARED)/linux_osl.o
et-objs += $(SHARED)/siutils.o
et-objs += $(SHARED)/aiutils.o


ifeq ($(CONFIG_MACH_HX4),y)
et-objs += $(SHARED)/bcmiproc_serdes.o
et-objs += $(SHARED)/bcmiproc_phy5461s.o
et-objs += $(SHARED)/hx4_erom.o
endif

ifeq ($(CONFIG_MACH_SB2),y)
et-objs += $(SHARED)/bcmiproc_serdes.o
et-objs += $(SHARED)/bcmiproc_phy5461s.o
et-objs += $(SHARED)/sb2_erom.o
endif

ifeq ($(CONFIG_MACH_KT2),y)
et-objs += $(SHARED)/bcmiproc_serdes.o
et-objs += $(SHARED)/bcmiproc_phy5461s.o
et-objs += $(SHARED)/kt2_erom.o
endif

ifeq ($(CONFIG_MACH_HR2),y)
et-objs += $(SHARED)/bcmiproc_phy5221.o
et-objs += $(SHARED)/hr2_erom.o
endif

ifeq ($(CONFIG_MACH_GH),y)
et-objs += $(SHARED)/bcmiproc_phy5481.o
et-objs += $(SHARED)/gh_erom.o
endif

ifeq ($(CONFIG_MACH_HR3),y)
et-objs += $(SHARED)/bcmiproc_phy5481.o
et-objs += $(SHARED)/hr3_erom.o
endif

ifeq ($(CONFIG_MACH_GH2),y)
et-objs += $(SHARED)/bcmiproc_phy5481.o
et-objs += $(SHARED)/gh2_erom.o
endif

et-objs += ../hnd/shared_ksyms.o

ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
else
# Normal makefile
KERNELDIR := ../../kernel/linux
all:
	$(MAKE) -C $(KERNELDIR) M=`pwd`

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` clean
endif

clean-files += $(ETSRCDIR)/sys/*.o $(ETSRCDIR)/sys/.*.o.cmd $(SHARED)/*.o $(SHARED)/*.o.cmd
