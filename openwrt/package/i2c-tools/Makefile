include $(TOPDIR)/rules.mk

PKG_NAME:=i2c-tools
PKG_VERSION:=3.1.2
PKG_RELEASE:=1
PKG_MD5SUM:=7104a1043d11a5e2c7b131614eb1b962

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bunzip2 -c

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,I2CTOOLS,i2c-tools,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" CFLAGS="$(TARGET_CFLAGS) -Iinclude -I$(STAGING_DIR)/usr/include" LDFLAGS="-L$(STAGING_DIR)/usr/lib" IDSDIR="/usr/share" HOST=$(GNU_TARGET_NAME)
	touch $@

$(IPKG_I2CTOOLS):
	install -d -m0755 $(IDIR_I2CTOOLS)/usr/sbin
	$(CP) $(PKG_BUILD_DIR)/tools/{i2cget,i2cset,i2cdetect,i2cdump} $(IDIR_I2CTOOLS)/usr/sbin
	$(RSTRIP) $(IDIR_I2CTOOLS)/
	$(IPKG_BUILD) $(IDIR_I2CTOOLS) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/include/i2c-tools/i2c-dev.h: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include/i2c-tools
	$(CP) -r $(PKG_BUILD_DIR)/include/linux/i2c-dev.h $@

compile-targets: $(STAGING_DIR)/usr/include/i2c-tools/i2c-dev.h
