include $(TOPDIR)/rules.mk

PKG_NAME:=mii-tool
PKG_VERSION:=1.9.1.1
PKG_RELEASE:=1
PKG_MD5SUM:=f65dbeb1c2392acffd4c94138b1f2e52

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,MIITOOL,mii-tool,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) CC="$(TARGET_CC)"
	touch $@

$(IPKG_MIITOOL):
	install -d -m0755 $(IDIR_MIITOOL)/usr/sbin
	install -m0755 $(PKG_BUILD_DIR)/mii-tool $(IDIR_MIITOOL)/usr/sbin
	$(RSTRIP) $(IDIR_MIITOOL)
	$(IPKG_BUILD) $(IDIR_MIITOOL) $(PACKAGE_DIR)

mostlyclean:
	$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm -f $(PKG_BUILD_DIR)/.built
