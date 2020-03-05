#
# Copyright (C) 2006-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=uboot-envtools
PKG_VERSION:=20081215
PKG_RELEASE:=2
PKG_MD5SUM:=21191178f21da802754063069a882b5b

PKG_SOURCE:=$(PKG_NAME)_$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://dl.meraki.net/

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install
PKG_CAT:=zcat

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,UBOOT_ENVTOOLS,uboot-envtools,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) CC="$(TARGET_CC)" CPPFLAGS="-I$(STAGING_DIR)/include -I$(STAGING_DIR)/usr/include" all
	touch $@

$(IPKG_UBOOT_ENVTOOLS):
	install -m0755 -d $(IDIR_UBOOT_ENVTOOLS)/usr/bin
	install -m0755 $(PKG_BUILD_DIR)/fw_printenv $(IDIR_UBOOT_ENVTOOLS)/usr/bin
	$(RSTRIP) $(IDIR_UBOOT_ENVTOOLS)
	$(IPKG_BUILD) $(IDIR_UBOOT_ENVTOOLS) $(PACKAGE_DIR)

