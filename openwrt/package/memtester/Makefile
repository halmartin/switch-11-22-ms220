# $Id: Makefile 2230 2005-10-22 12:12:59Z nbd $

include $(TOPDIR)/rules.mk

PKG_NAME:=memtester
PKG_VERSION:=4.2.2
PKG_RELEASE:=1
PKG_MD5SUM:=0118616cc8860c6b85ef6a1281da1783

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,MEMTESTER,memtester,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	echo "$(TARGET_CC) $(TARGET_CFLAGS)" > $(PKG_BUILD_DIR)/conf-ld
	echo "$(TARGET_CC) $(TARGET_CFLAGS)" > $(PKG_BUILD_DIR)/conf-cc
	$(MAKE) -C $(PKG_BUILD_DIR)
	touch $@

$(IPKG_MEMTESTER):
	install -d -m0755 $(IDIR_MEMTESTER)/usr/bin
	install -m0755 $(PKG_BUILD_DIR)/memtester $(IDIR_MEMTESTER)/usr/bin/
	$(RSTRIP) $(IDIR_MEMTESTER)
	$(IPKG_BUILD) $(IDIR_MEMTESTER) $(PACKAGE_DIR)
