# Copyright (C) 2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: $

include $(TOPDIR)/rules.mk

PKG_NAME:=usb-modeswitch
PKG_VERSION:=1.2.5
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=https://dl.meraki.net
PKG_CAT:=bzcat
PKG_MD5SUM:=c393603908eceab95444c5bde790f6f0

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,USB_MODESWITCH,$(PKG_NAME),$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)/usr/bin
	$(TARGET_CC) $(TARGET_CFLAGS) -I $(STAGING_DIR)/include/ \
	-I $(STAGING_DIR)/usr/include/ -L $(STAGING_DIR)/lib/ \
	-L $(STAGING_DIR)/usr/lib/ -l usb \
	-o $(PKG_BUILD_DIR)/usb-modeswitch \
	$(PKG_BUILD_DIR)/usb_modeswitch.c
	$(CP) $(PKG_BUILD_DIR)/usb-modeswitch $(PKG_INSTALL_DIR)/usr/bin/usb-modeswitch
	touch $@

$(IPKG_USB_MODESWITCH): $(STAGING_DIR)/usr/bin/usb-modeswitch
	install -d -m0755 $(IDIR_USB_MODESWITCH)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/usb-modeswitch $(IDIR_USB_MODESWITCH)/usr/bin/
	$(IPKG_BUILD) $(IDIR_USB_MODESWITCH) $(PACKAGE_DIR)



uninstall-dev:

$(STAGING_DIR)/usr/bin/usb-modeswitch: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/usb-modeswitch $(STAGING_DIR)/usr/bin/
	touch $@

install-dev: $(STAGING_DIR)/usr/bin/usb-modeswitch

compile-targets: install-dev
clean-targets: uninstall-dev

mostlyclean:
	-$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm -f $(PKG_BUILD_DIR)/.built
