include $(TOPDIR)/rules.mk

PKG_NAME:=sscep
PKG_VERSION:=0.6.1
PKG_RELEASE:=1
PKG_MD5SUM:=c05599690caf50f1a2c332dbb28bc71e

PKG_SOURCE_URL:=https://dl.meraki.net
UNUSED_ORIGINAL_PKG_SOURCE_URL:=https://github.com/certnanny/sscep
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,SSCEP,sscep,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built: $(PKG_BUILD_DIR)/.configured
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) -f Linux/Makefile \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		all install
	touch $@

$(IPKG_SSCEP):
	install -m0755 -d $(IDIR_SSCEP)/usr/sbin
	install -m0755 $(PKG_BUILD_DIR)/sscep_dyn $(IDIR_SSCEP)/usr/sbin/sscep
	$(RSTRIP) $(IDIR_SSCEP)
	$(IPKG_BUILD) $(IDIR_SSCEP) $(PACKAGE_DIR)
