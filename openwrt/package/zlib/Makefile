# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=zlib
PKG_VERSION:=1.2.11
PKG_RELEASE:=0
PKG_MD5SUM:=1c9f62f0778697a09d36121ead88e08e

#PKG_SOURCE_URL:=https://dl.meraki.net
UNUSED_ORIGINAL_PKG_SOURCE_URL:=http://www.zlib.net
PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,ZLIB,zlib,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); \
		$(TARGET_CONFIGURE_OPTS) \
		LDSHARED="$(TARGET_CC) -shared -Wl,-soname,libz.so.1" \
		CFLAGS="$(TARGET_CFLAGS) $(CFLAGS_LARGEFILE)" \
		./configure \
		--prefix=/usr \
		--shared \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) $(CFLAGS_LARGEFILE)" \
		libz.a libz.so
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		install
	touch $@

$(IPKG_ZLIB):
	install -m0755 -d $(IDIR_ZLIB)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libz.so.* $(IDIR_ZLIB)/usr/lib/
	$(RSTRIP) $(IDIR_ZLIB)
	$(IPKG_BUILD) $(IDIR_ZLIB) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libz.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/*.h $(STAGING_DIR)/usr/include
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/* $(STAGING_DIR)/usr/lib
	touch $(STAGING_DIR)/usr/lib/libz.so

install-dev: $(STAGING_DIR)/usr/lib/libz.so

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/include/zconf.h
	rm -rf $(STAGING_DIR)/usr/include/zlib.h
	rm -rf $(STAGING_DIR)/usr/lib/libz.*

compile-targets: install-dev
clean-targets: uninstall-dev
