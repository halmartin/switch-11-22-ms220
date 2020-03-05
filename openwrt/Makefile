# Makefile for OpenWrt
#
# Copyright (C) 2005 by Felix Fietkau <openwrt@nbd.name>
# Copyright (C) 1999-2004 by Erik Andersen <andersen@codepoet.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

#--------------------------------------------------------------
# Just run 'make menuconfig', configure stuff, then run 'make'.
# You shouldn't need to mess with anything beyond this point...
#--------------------------------------------------------------
TOPDIR=${shell pwd}
export TOPDIR

${shell mv make-log make-log.old 2>/dev/null}

ifneq ($(DEVELOPER),)
CONFIG_CONFIG_IN = Config.in.devel
else
CONFIG_CONFIG_IN = Config.in
endif
CONFIG_DEFCONFIG = .defconfig
CONFIG = package/config

noconfig_targets := menuconfig config oldconfig randconfig \
	defconfig allyesconfig allnoconfig release tags

# Pull in the user's configuration file
ifeq ($(filter $(noconfig_targets),$(MAKECMDGOALS)),)
-include $(TOPDIR)/.config
endif

ifeq ($(strip $(BR2_HAVE_DOT_CONFIG)),y)
include $(TOPDIR)/rules.mk

all: world

.NOTPARALLEL:

#############################################################
#
# You should probably leave this stuff alone unless you know
# what you are doing.
#
#############################################################

# In this section, we need .config
include .config.cmd

boardconfig: configtest
	@(echo "#" Built `date`; \
	echo OPENWRT_ARCH_SUFFIX = $(ARCH); \
	echo OPENWRT_FPU_SUFFIX = $(ARCH_FPU_SUFFIX); \
	echo KERNEL_CROSS = $(KERNEL_CROSS); \
	echo TARGET_CROSS = $(TARGET_CROSS); \
	echo RSTRIP = $(RSTRIP); \
	echo STAGING_DIR = $(STAGING_DIR); \
	echo GNU_TARGET_NAME = $(GNU_TARGET_NAME); \
	echo REAL_GNU_TARGET_NAME = $(REAL_GNU_TARGET_NAME); \
	echo GNU_HOST_NAME = $(GNU_HOST_NAME); \
	echo TARGET_CONFIGURE_OPTS = $(TARGET_CONFIGURE_OPTS); \
	echo TARGET_PATH = $(TARGET_PATH); \
	echo TARGET_DIR = $(TARGET_DIR); \
	echo HOST_STAGING_DIR = $(HOST_STAGING_DIR); \
	echo TOOL_BUILD_DIR = $(TOOL_BUILD_DIR); \
	echo LIBC = $(BR2_LIBC); \
	echo BOARD_LINUX_VERSION = $(BR2_LINUX_VERSION); \
	) \
	> boardconfig-$(BOARD).mk

world: $(DL_DIR) $(BUILD_DIR) configtest
	$(MAKE) toolchain/install target/compile patchwork_quilt package/compile root_clean package/install target/install
	@$(TRACE) Build complete.
	$(MAKE) boardconfig

.PHONY: all world boardconfig clean dirclean distclean image_clean target_clean source configtest

configtest:
	-cp .config .config.test
	-scripts/configtest.pl

package_index:
	(cd $(PACKAGE_DIR); $(STAGING_DIR)/usr/bin/ipkg-make-index . > Packages)

$(DL_DIR):
	@mkdir -p $(DL_DIR)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR) $(STAMP_DIR)

source: toolchain/source package/source target/source

ifeq ($(BOARD),armeb)
patchwork_quilt:
	-@if [ ! -f .patchwork_quilt ]; then \
		touch .patchwork_quilt; \
		ln -sf $(STAGING_DIR)/armeb-linux/sys-include/asm/arch-ixp4xx $(STAGING_DIR)/armeb-linux/sys-include/asm/arch; \
		patch -b $(STAGING_DIR)/armeb-linux/sys-include/asm/memory.h toolchain/kernel-headers/remove_deprecated.patch; \
		mkdir -p $(BUILD_DIR)/stamp; \
	fi
else
patchwork_quilt:
	@:
endif

package/%:
	@$(TRACE) $@
	$(MAKE) -C package $(patsubst package/%,%,$@)

target/%:
	@$(TRACE) $@
	$(MAKE) -C target $(patsubst target/%,%,$@)

toolchain/%:
	@$(TRACE) $@
	$(MAKE) -C toolchain $(patsubst toolchain/%,%,$@)

#############################################################
#
# Cleanup and misc junk
#
#############################################################
root_clean:
	@$(TRACE) root_clean
	rm -rf $(BUILD_DIR)/linux-*/root $(BUILD_DIR)/root

target_clean: root_clean
	rm -f $(STAMP_DIR)/.*-compile
	rm -f $(STAMP_DIR)/.*-install
	rm -rf $(BIN_DIR)

clean: dirclean

dirclean:
	@$(TRACE) dirclean
	@$(MAKE) -C $(CONFIG) clean
	rm -rf $(BUILD_DIR)

distclean: dirclean
	rm -rf $(STAMP_DIR) $(DL_DIR) $(TOOL_BUILD_DIR) $(STAGING_DIR)
	rm -f .config* .tmpconfig.h
	rm -rf .patchwork_quilt

else # ifeq ($(strip $(BR2_HAVE_DOT_CONFIG)),y)

all: menuconfig

# configuration
# ---------------------------------------------------------------------------

$(CONFIG)/conf:
	$(MAKE) -C $(CONFIG) conf
	-@if [ ! -f .config ] ; then \
		cp $(CONFIG_DEFCONFIG) .config; \
	fi
$(CONFIG)/mconf:
	$(MAKE) -C $(CONFIG) 
	-@if [ ! -f .config ] ; then \
		cp $(CONFIG_DEFCONFIG) .config; \
	fi

menuconfig: $(CONFIG)/mconf
	-touch .config
	-cp .config .config.test
	@$(CONFIG)/mconf $(CONFIG_CONFIG_IN)
	-./scripts/configtest.pl

config: $(CONFIG)/conf
	-touch .config
	-cp .config .config.test
	@$(CONFIG)/conf $(CONFIG_CONFIG_IN)
	-./scripts/configtest.pl

oldconfig: $(CONFIG)/conf
	-touch .config
	-cp .config .config.test
	@$(CONFIG)/conf -o $(CONFIG_CONFIG_IN)
	-./scripts/configtest.pl

randconfig: $(CONFIG)/conf
	-touch .config
	-cp .config .config.test
	@$(CONFIG)/conf -r $(CONFIG_CONFIG_IN)
	-./scripts/configtest.pl

allyesconfig: $(CONFIG)/conf
	-touch .config
	-cp .config .config.test
	@$(CONFIG)/conf -o $(CONFIG_CONFIG_IN)
	-./scripts/configtest.pl

allnoconfig: $(CONFIG)/conf
	-touch .config
	-cp .config .config.test
	@$(CONFIG)/conf -n $(CONFIG_CONFIG_IN)
	-./scripts/configtest.pl

defconfig: $(CONFIG)/conf
	-touch .config
	-cp .config .config.test
	@$(CONFIG)/conf -d $(CONFIG_CONFIG_IN)
	-./scripts/configtest.pl

endif # ifeq ($(strip $(BR2_HAVE_DOT_CONFIG)),y)

all-oldconfig:
	for f in config-* ; do \
		cp "$$f" .config && yes "" | $(MAKE) oldconfig && cp .config "$$f"; \
	done

.PHONY: dummy subdirs release distclean clean config oldconfig \
	menuconfig tags check test depend all-oldconfig


x86_image:
	rm -f bin/x86.tgz
	rm -rf /tmp/dd
	mkdir -p /tmp/dd
	cp bin/openwrt-x86-2.6-jffs2-8MB.img /tmp/dd/openwrt.img
	cp bin/openwrt-x86-2.6-vmlinuz /tmp/dd/vmlinuz
	tar -C /tmp/dd -czf bin/x86.tgz .

