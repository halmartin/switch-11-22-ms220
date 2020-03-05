include $(TOPDIR)/rules.mk

PKG_NAME:=nuttcp
PKG_VERSION:=6.1.2
PKG_RELEASE:=1
PKG_MD5SUM:=a16d4d6d5def02cea980e57feaf30500

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_BUILD_DIR:=$(BUILD_DIR)/nuttcp-$(PKG_VERSION)
PKG_CAT:=bzcat

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,NUTTCP,nuttcp,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) CC="$(TARGET_CC)" CFLAGS="$(TARGET_CFLAGS)" -C "$(PKG_BUILD_DIR)" all
	touch $@

$(IPKG_NUTTCP):
	install -d -m0755 $(IDIR_NUTTCP)/usr/bin
	install -m0755 $(PKG_BUILD_DIR)/nuttcp-$(PKG_VERSION) $(IDIR_NUTTCP)/usr/bin/nuttcp
	$(RSTRIP) $(IDIR_NUTTCP)
	$(IPKG_BUILD) $(IDIR_NUTTCP) $(PACKAGE_DIR)
