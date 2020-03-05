# $Id$

include $(TOPDIR)/rules.mk

PKG_NAME := json-glib
PKG_VERSION := 1.0.4
PKG_RELEASE := 1
PKG_MD5SUM := 3131b0417ecde3da1ae72acceaa375cf

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE := $(PKG_NAME)-$(PKG_VERSION).tar.xz
PKG_CAT := xzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,JSON-GLIB,json-glib,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status}; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="-I$(STAGING_DIR)/usr/include $(TARGET_CFLAGS)" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
		./configure \
		  --target=$(GNU_TARGET_NAME) \
		  --host=$(GNU_TARGET_NAME) \
		  --build=$(GNU_HOST_NAME) \
		  --program-prefix="" \
		  --program-suffix="" \
		  --prefix=/usr \
		  --exec-prefix=/usr \
		  --bindir=/usr/bin \
		  --libexecdir=/usr/lib \
		  --datadir=/usr/share \
		  --mandir=/usr/man \
		  $(DISABLE_NLS) \
		  $(DISABLE_LARGEFILE) \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_JSON-GLIB):
	install -m0755 -d $(IDIR_JSON-GLIB)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libjson-glib-1.0.so.* $(IDIR_JSON-GLIB)/usr/lib/
	$(RSTRIP) $(IDIR_JSON-GLIB)
	$(IPKG_BUILD) $(IDIR_JSON-GLIB) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/json-glib.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/json-glib.so
	$(MAKE) -C $(PKG_BUILD_DIR) install DESTDIR=$(STAGING_DIR)

uninstall-dev:


compile-targets: install-dev
clean-targets: uninstall-dev
