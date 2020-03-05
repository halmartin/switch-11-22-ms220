include $(TOPDIR)/rules.mk

PKG_NAME:=hdparm
PKG_VERSION:=9.48
PKG_RELEASE:=1
PKG_MD5SUM:=213efdbe7471fad3408198918e164354

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,HDPARM,hdparm,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		STRIP="/bin/true" \
		CC="$(TARGET_CC)"
	touch $@

$(IPKG_HDPARM):
	install -d -m0755 $(IDIR_HDPARM)/usr/sbin
	install -m0755 $(PKG_BUILD_DIR)/hdparm $(IDIR_HDPARM)/usr/sbin
	$(RSTRIP) $(IDIR_HDPARM)
	$(IPKG_BUILD) $(IDIR_HDPARM) $(PACKAGE_DIR)

mostlyclean:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		clean
	rm -f $(PKG_BUILD_DIR)/.built
