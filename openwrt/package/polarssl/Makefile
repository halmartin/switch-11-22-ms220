include $(TOPDIR)/rules.mk

PKG_NAME:=polarssl
PKG_VERSION:=1.3.9
PKG_RELEASE:=0
PKG_MD5SUM:=

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBPOLARSSL,libpolarssl,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.prepared:
	mkdir -p $(PKG_BUILD_DIR); touch $@

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	touch $@

$(IPKG_LIBPOLARSSL):

install-dev:
uninstall-dev:

compile-targets: install-dev
clean-targets: uninstall-dev
