# $Id: Makefile 3112 2010-09-16 23:53:19Z rts $

include $(TOPDIR)/rules.mk

PKG_NAME:=dmidecode
PKG_VERSION:=2.10
PKG_RELEASE:=1
PKG_MD5SUM:=3c9c4d55a40b78600f3b43bfa64616f9

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,DMIDECODE,dmidecode,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -Wall" \
		CROSS="$(TARGET_CROSS)" \
		prefix="/usr" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_DMIDECODE):
	install -m0755 -d $(IDIR_DMIDECODE)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/../dmidecode $(IDIR_DMIDECODE)/usr/bin/
	$(RSTRIP) $(IDIR_DMIDECODE)
	$(IPKG_BUILD) $(IDIR_DMIDECODE) $(PACKAGE_DIR)
