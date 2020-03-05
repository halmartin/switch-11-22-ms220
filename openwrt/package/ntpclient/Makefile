# $Id: Makefile 2364 2005-11-07 01:12:51Z nbd $

include $(TOPDIR)/rules.mk

PKG_NAME:=ntpclient
PKG_VERSION:=2010_365
PKG_RELEASE:=0
PKG_MD5SUM:=a64689398f2df8933ee0d8da246e9eaa

#PKG_SOURCE_URL:=https://dl.meraki.net
UNUSED_ORIGINAL_PKG_SOURCE_URL:=http://doolittle.faludi.com/ntpclient
PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)_$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-2010

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,NTPCLIENT,ntpclient,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" CFLAGS="$(TARGET_CFLAGS)"
	touch $@

$(IPKG_NTPCLIENT):
	install -d -m0755 $(IDIR_NTPCLIENT)/etc/hotplug.d/iface
	install -m0755 ./files/ntpclient.init $(IDIR_NTPCLIENT)/etc/hotplug.d/iface/10-ntpclient
	install -d -m0755 $(IDIR_NTPCLIENT)/usr/sbin
	install -m0755 $(PKG_BUILD_DIR)/ntpclient $(IDIR_NTPCLIENT)/usr/sbin/
	$(RSTRIP) $(IDIR_NTPCLIENT)
	$(IPKG_BUILD) $(IDIR_NTPCLIENT) $(PACKAGE_DIR)

