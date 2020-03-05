include $(TOPDIR)/.config

BOARD := unknown-board
ifeq ($(BR2_LINUX_2_6_X86),y)
BOARD := x86
endif
ifeq ($(BR2_LINUX_2_6_AR7100), y)
BOARD := ar7100
endif
ifeq ($(BR2_LINUX_2_6_POWERPC), y)
BOARD := powerpc
endif

SHELL=/bin/bash
export SHELL

ifeq ($(V),)
V=5
endif


ifneq ($(V),0)
TRACE:=echo "---> "
START_TRACE:=echo -n "---> "
END_TRACE:=echo
else
START_TRACE:=:
END_TRACE:=:
TRACE:=:
endif

ifeq (${shell [ "$(V)" -ge 5 ] && echo 1},)
CMD_TRACE:=:
PKG_TRACE:=:
else
CMD_TRACE:=echo -n
PKG_TRACE:=echo "------> "
endif

ifeq (${shell [ "$(V)" -ge 10 ] && echo 1},)
EXTRA_MAKEFLAGS:=-s
MAKE_TRACE:=>> $(TOPDIR)/make-log 2>&1 || { echo "Build failed. Please re-run make with V=99 to see what's going on (or look at make-log)"; /bin/false; }
else
MAKE_TRACE:=
EXTRA_MAKEFLAGS:=
TRACE:=:
PKG_TRACE:=:
CMD_TRACE:=:
START_TRACE:=:
END_TRACE:=:
endif

CP=cp -fpR
MAKE1=make
MAKEFLAGS += V=$(V) $(EXTRA_MAKEFLAGS)
# Strip off the annoying quoting
ARCH:=$(strip $(subst ",, $(BR2_ARCH)))
WGET:=$(strip $(subst ",, $(BR2_WGET)))
GCC_VERSION:=$(strip $(subst ",, $(BR2_GCC_VERSION)))
GCC_USE_SJLJ_EXCEPTIONS:=$(strip $(subst ",, $(BR2_GCC_USE_SJLJ_EXCEPTIONS)))
TARGET_OPTIMIZATION:=$(strip $(subst ",, $(BR2_TARGET_OPTIMIZATION)))
#"))"))"))"))")) # for vim's broken syntax highlighting :)

ifeq ($(BR2_SOFT_FLOAT),y)
SOFT_FLOAT_CONFIG_OPTION:=--with-float=soft
TARGET_SOFT_FLOAT:=-msoft-float
ARCH_FPU_SUFFIX:=_nofpu
else
# ARM defaults to soft float.
ifeq ($(ARCH),arm)
SOFT_FLOAT_CONFIG_OPTION:=--with-float=hard
else ifeq ($(ARCH),armeb)
SOFT_FLOAT_CONFIG_OPTION:=--with-float=hard
else
SOFT_FLOAT_CONFIG_OPTION:=
endif
TARGET_SOFT_FLOAT:=
ARCH_FPU_SUFFIX:=
endif


ifeq ($(BR2_TAR_VERBOSITY),y)
TAR_OPTIONS=-xvf
else
TAR_OPTIONS=-xf
endif

ifneq ($(BR2_LARGEFILE),y)
DISABLE_LARGEFILE= --disable-largefile
endif

ifeq ($(BR2_TARGET_DEBUGGER_INFO),y)
TARGET_DEBUGGING=-g
endif

TARGET_CFLAGS:=$(TARGET_OPTIMIZATION) $(TARGET_DEBUGGING)

OPTIMIZE_FOR_CPU=$(ARCH)

ifeq ($(ARCH),arm64)
OPTIMIZE_FOR_CPU=aarch64
endif

ifeq ($(OPENWRT_CCACHE),)
HOSTCC:=$(or $(OPENWRT_HOSTCC),gcc)
HOSTCXX:=$(or $(OPENWRT_HOSTCXX),g++)
else
HOSTCC:=$(OPENWRT_CCACHE) $(or $(OPENWRT_HOSTCC),gcc)
HOSTCXX:=$(OPENWRT_CCACHE) $(or $(OPENWRT_HOSTCXX),g++)
endif

BASE_DIR:=$(TOPDIR)
DL_DIR:=$(BASE_DIR)/dl
BUILD_DIR:=$(BASE_DIR)/build_$(ARCH)$(ARCH_FPU_SUFFIX)$(OPENWRT_EXTRA_BOARD_SUFFIX)
HOST_STAGING_DIR:=$(BASE_DIR)/staging_dir_$(ARCH)$(ARCH_FPU_SUFFIX)$(OPENWRT_EXTRA_BOARD_SUFFIX)
SCRIPT_DIR:=$(BASE_DIR)/scripts
BIN_DIR:=$(BUILD_DIR)/bin
STAMP_DIR:=$(BUILD_DIR)/stamp
PACKAGE_DIR:=$(BIN_DIR)/packages
STAMP_DIR:=$(BUILD_DIR)/stamp
TARGET_DIR:=$(BUILD_DIR)/root
TOOL_BUILD_DIR=$(BASE_DIR)/toolchain_build_$(ARCH)$(ARCH_FPU_SUFFIX)$(OPENWRT_EXTRA_BOARD_SUFFIX)
TARGET_PATH=$(HOST_STAGING_DIR)/usr/bin:$(HOST_STAGING_DIR)/bin:/bin:/sbin:/usr/bin:/usr/sbin
IMAGE:=$(BUILD_DIR)/root_fs_$(ARCH)$(ARCH_FPU_SUFFIX)

ifeq ($(BR2_SOFT_FLOAT),y)
ARM_HARD_FLOAT_SUFFIX=
else
ARM_HARD_FLOAT_SUFFIX=hf
endif

ifeq ($(BR2_LIBC_UCLIBC),y)
  ifeq ($(ARCH),armeb)
    REAL_GNU_TARGET_NAME=$(OPTIMIZE_FOR_CPU)-unknown-linux-uclibcgnueabi$(ARM_HARD_FLOAT_SUFFIX)
  else ifeq ($(ARCH),arm)
    REAL_GNU_TARGET_NAME=$(OPTIMIZE_FOR_CPU)-unknown-linux-uclibcgnueabi$(ARM_HARD_FLOAT_SUFFIX)
  else ifeq ($(BR2_POWERPC_E500),y)
    REAL_GNU_TARGET_NAME=$(OPTIMIZE_FOR_CPU)-linux-uclibcspe
  else
    REAL_GNU_TARGET_NAME=$(OPTIMIZE_FOR_CPU)-linux-uclibc
  endif
else ifeq ($(BR2_LIBC_MUSL),y)
  ifeq ($(ARCH),arm)
    REAL_GNU_TARGET_NAME=$(OPTIMIZE_FOR_CPU)-linux-musleabi$(ARM_HARD_FLOAT_SUFFIX)
  else ifeq ($(ARCH),armeb)
    REAL_GNU_TARGET_NAME=$(OPTIMIZE_FOR_CPU)-linux-musleabi$(ARM_HARD_FLOAT_SUFFIX)
  else
    REAL_GNU_TARGET_NAME=$(OPTIMIZE_FOR_CPU)-linux-musl
  endif
endif

STAGING_DIR:=$(HOST_STAGING_DIR)/$(REAL_GNU_TARGET_NAME)
KERNEL_CROSS:=$(HOST_STAGING_DIR)/bin/$(REAL_GNU_TARGET_NAME)-
TARGET_CROSS:=$(HOST_STAGING_DIR)/bin/$(REAL_GNU_TARGET_NAME)-
LINUX_HEADERS_DIR:=$(TOOL_BUILD_DIR)/linux
GNU_TARGET_NAME=$(OPTIMIZE_FOR_CPU)-linux
ifeq ($(OPENWRT_CCACHE),)
TARGET_CC:=$(TARGET_CROSS)gcc
TARGET_CXX:=$(TARGET_CROSS)g++
else
TARGET_CC:=$(OPENWRT_CCACHE) $(TARGET_CROSS)gcc
TARGET_CXX:=$(OPENWRT_CCACHE) $(TARGET_CROSS)g++
endif
TARGET_AR:=$(TARGET_CROSS)ar
STRIP:=$(HOST_STAGING_DIR)/bin/sstrip
PATCH=$(SCRIPT_DIR)/patch-kernel.sh
SED:=$(HOST_STAGING_DIR)/bin/sed -i -e
LINUX_DIR:=$(BUILD_DIR)/linux

HOST_ARCH:=$(shell $(HOSTCC) -dumpmachine | sed -e s'/-.*//' \
	-e 's/aarch64.*/aarch64/' \
	-e 's/sparc.*/sparc/' \
	-e 's/arm.*/arm/g' \
	-e 's/m68k.*/m68k/' \
	-e 's/ppc/powerpc/g' \
	-e 's/v850.*/v850/g' \
	-e 's/sh[234]/sh/' \
	-e 's/mips-.*/mips/' \
	-e 's/mipsel-.*/mipsel/' \
	-e 's/cris.*/cris/' \
	-e 's/i[3-9]86/i386/' \
	)
GNU_HOST_NAME:=$(HOST_ARCH)-pc-linux-gnu
TARGET_CONFIGURE_OPTS=PATH=$(TARGET_PATH) \
		AR=$(TARGET_CROSS)ar \
		AS=$(TARGET_CROSS)as \
		LD=$(TARGET_CROSS)ld \
		NM=$(TARGET_CROSS)nm \
		CC=$(TARGET_CROSS)gcc \
		GCC=$(TARGET_CROSS)gcc \
		CXX=$(TARGET_CROSS)g++ \
		STRIP=$(TARGET_CROSS)strip \
		OBJCOPY=$(TARGET_CROSS)objcopy \
		RANLIB=$(TARGET_CROSS)ranlib

ifeq ($(ENABLE_LOCALE),true)
DISABLE_NLS:=
else
DISABLE_NLS:=--disable-nls
endif

ifeq ($(BR2_ENABLE_MULTILIB),y)
MULTILIB:=--enable-multilib
else
MULTILIB:=--disable-multilib
endif

# invoke ipkg-build with some default options
IPKG_BUILD := PATH="$(TARGET_PATH)" ipkg-build -c -o root -g root
# where to build (and put) .ipk packages
IPKG_TARGET_DIR := $(PACKAGE_DIR)
IPKG:=IPKG_TMP=$(BUILD_DIR)/tmp IPKG_INSTROOT=$(TARGET_DIR) IPKG_CONF_DIR=$(HOST_STAGING_DIR)/etc IPKG_OFFLINE_ROOT=$(BUILD_DIR)/root $(SCRIPT_DIR)/ipkg -force-defaults -force-depends
IPKG_STATE_DIR := $(TARGET_DIR)/usr/lib/ipkg

RSTRIP:=STRIP="$(STRIP)" $(SCRIPT_DIR)/rstrip.sh
RSTRIP_KMOD:=STRIP="$(TARGET_CROSS)strip --strip-unneeded --remove-section=.comment" $(SCRIPT_DIR)/rstrip.sh

