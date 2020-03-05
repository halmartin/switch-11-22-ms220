# $Id: Makefile 3365 2006-03-14 00:26:47Z nico $

include $(TOPDIR)/rules.mk

PKG_NAME:=pciutils
PKG_VERSION:=3.3.0
PKG_RELEASE:=1
PKG_MD5SUM:=bf6ce5c50b273ffc2d27f659e929a37e

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,PCIUTILS,pciutils,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		ZLIB=yes CC="$(TARGET_CC)" STRIP="$(STRIP)" CFLAGS="$(TARGET_CFLAGS) -fPIC -I$(STAGING_DIR)/usr/include" LDFLAGS="-L$(STAGING_DIR)/usr/lib -lz" \
		PREFIX="/usr" SHARED=yes HWDB=no HOST=$(GNU_TARGET_NAME) DESTDIR=$(PKG_INSTALL_DIR) install install-lib
	touch $@

$(STAGING_DIR)/usr/lib/libpci.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include/pci
	$(CP) $(PKG_INSTALL_DIR)/usr/include/pci/* $(STAGING_DIR)/usr/include/pci
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libpci.* $(STAGING_DIR)/usr/lib

install-dev: $(STAGING_DIR)/usr/lib/libpci.so
uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/usr/lib/libpci.* \
		$(STAGING_DIR)/usr/include/pci

$(IPKG_PCIUTILS):
	install -d -m0755 $(IDIR_PCIUTILS)/usr/sbin
	install -d -m0755 $(IDIR_PCIUTILS)/usr/share
	install -d -m0755 $(IDIR_PCIUTILS)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/{lspci,setpci} $(IDIR_PCIUTILS)/usr/sbin/
	$(CP) $(PKG_INSTALL_DIR)/usr/share/pci.ids.gz $(IDIR_PCIUTILS)/usr/share/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libpci.so.* $(IDIR_PCIUTILS)/usr/lib/
	$(RSTRIP) $(IDIR_PCIUTILS)/
	$(IPKG_BUILD) $(IDIR_PCIUTILS) $(PACKAGE_DIR)

compile-targets: install-dev
clean-targets: uninstall-dev

.PHONY: install-dev uninstall-dev compile-targets clean-targets
