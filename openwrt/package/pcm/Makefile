include $(TOPDIR)/rules.mk

PKG_NAME:=pcm
PKG_VERSION:=20170503_befffdcc
PKG_RELEASE:=1
PKG_MD5SUM:=3aea844fd5d6edee82821c5de9ae835f

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,PCM,pcm,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built: $(PKG_BUILD_DIR)/.configured
	$(MAKE) -C $(PKG_BUILD_DIR) \
		STAGING_DIR="$(STAGING_DIR)" \
		UNAME="Linux" \
		CXX="$(TARGET_CXX)" \
		all
	touch $@

$(IPKG_PCM):
	install -d -m0755 $(IDIR_PCM)/usr/bin
	install -m0755 $(PKG_BUILD_DIR)/pcm*.x $(IDIR_PCM)/usr/bin/
	$(RSTRIP) $(IDIR_PCM)
	$(IPKG_BUILD) $(IDIR_PCM) $(PACKAGE_DIR)

install-dev: $(PKG_BUILD_DIR)/.built

uninstall-dev:
	$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm -f $(PKG_BUILD_DIR)/.built

compile-targets: install-dev
clean-targets: uninstall-dev
