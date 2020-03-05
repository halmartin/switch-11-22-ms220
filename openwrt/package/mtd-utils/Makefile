# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=mtd-utils
PKG_VERSION:=1.5.2
PKG_RELEASE:=1
PKG_MD5SUM:=596bc7b20a6d4fb86d63fc9b8af674d6

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=mtd-utils-$(PKG_VERSION).tar.bz2
PKG_CAT:=bzcat
PKG_BUILD_DIR:=$(BUILD_DIR)/mtd-utils-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,MTD_UTILS,mtd-utils,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	(cd $(PKG_BUILD_DIR); \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		$(MAKE) `pwd`/nanddump  `pwd`/flash_eraseall `pwd`/flash_erase `pwd`/nandtest `pwd`/nandwrite )
	(cd $(PKG_BUILD_DIR)/ubi-utils; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		$(MAKE) -C .. `pwd`/ubiformat `pwd`/ubinfo `pwd`/ubiattach `pwd`/ubidetach `pwd`/ubimkvol `pwd`/ubirename `pwd`/ubirmvol `pwd`/ubiupdatevol `pwd`/mtdinfo `pwd`/ubirsvol )
	touch $@

$(IPKG_MTD_UTILS):
	install -d -m0755 $(IDIR_MTD_UTILS)/usr/sbin
	for x in nanddump flash_eraseall flash_erase nandtest nandwrite ubi-utils/ubiattach ubi-utils/ubidetach ubi-utils/ubiformat ubi-utils/ubimkvol ubi-utils/ubinfo ubi-utils/ubirename ubi-utils/ubirmvol ubi-utils/ubirsvol ubi-utils/ubiupdatevol ubi-utils/mtdinfo ; do $(CP) $(PKG_BUILD_DIR)/$$x $(IDIR_MTD_UTILS)/usr/sbin/; done
	$(RSTRIP) $(IDIR_MTD_UTILS)
	$(IPKG_BUILD) $(IDIR_MTD_UTILS) $(PACKAGE_DIR)

mostlyclean:
	-$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm -f $(PKG_BUILD_DIR)/.built
