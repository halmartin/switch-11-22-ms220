# $Id: Makefile 3112 2010-09-16 23:53:19Z rts $

include $(TOPDIR)/rules.mk

PKG_NAME:=mdadm
PKG_VERSION:=3.2
PKG_RELEASE:=1
PKG_MD5SUM:=4ac70ccead74f947bf5aa4d189a977a0

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,MDADM,mdadm,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -DUCLIBC -DHAVE_STDINT_H" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		mdadm mdassemble
	touch $@

$(IPKG_MDADM):
	install -m0755 -d $(IDIR_MDADM)/sbin
	$(CP) $(PKG_BUILD_DIR)/mdadm $(IDIR_MDADM)/sbin
	$(CP) $(PKG_BUILD_DIR)/mdassemble $(IDIR_MDADM)/sbin
	$(IPKG_BUILD) $(IDIR_MDADM) $(PACKAGE_DIR)

