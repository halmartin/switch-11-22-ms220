#
# Copyright (C) 2012-2014 Broadcom Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation version 2.
#
# This program is distributed "as is" WITHOUT ANY WARRANTY of any
# kind, whether express or implied; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# BCM281XX
obj-$(CONFIG_ARCH_BCM_281XX)	+= board_bcm281xx.o

# BCM21664
obj-$(CONFIG_ARCH_BCM_21664)	+= board_bcm21664.o

# BCM281XX and BCM21664 SMP support
obj-$(CONFIG_ARCH_BCM_MOBILE_SMP) += platsmp.o

# BCM281XX and BCM21664 L2 cache control
obj-$(CONFIG_ARCH_BCM_MOBILE_L2_CACHE) += kona_l2_cache.o

# Support for secure monitor traps
obj-$(CONFIG_ARCH_BCM_MOBILE_SMC) += bcm_kona_smc.o
ifeq ($(call as-instr,.arch_extension sec,as_has_sec),as_has_sec)
CFLAGS_bcm_kona_smc.o		+= -Wa,-march=armv7-a+sec -DREQUIRES_SEC
endif

# BCM2835
obj-$(CONFIG_ARCH_BCM2835)	+= board_bcm2835.o

# BCM5301X
obj-$(CONFIG_ARCH_BCM_5301X)	+= bcm_5301x.o

# Meraki switch-arm
obj-$(CONFIG_ARCH_BCM_SWITCH_ARM)	+= bcm_switch-arm.o shm.o \
                                	   board_brumby.o \
                                	   board_wolfcastle.o \
                                	   board_hungry_hungry_hippo.o \
                                	   xldk/
ifeq ($(CONFIG_ARCH_BCM_SWITCH_ARM),y)
obj-$(CONFIG_SMP) += platsmp.o
endif

# gpio-cfg driver
obj-$(CONFIG_BCMA_DRIVER_GPIO)		+= gpio_cfg.o

# BCM63XXx
obj-$(CONFIG_ARCH_BCM_63XX)	:= bcm63xx.o

ifeq ($(CONFIG_ARCH_BRCMSTB),y)
obj-y				+= brcmstb.o
endif
