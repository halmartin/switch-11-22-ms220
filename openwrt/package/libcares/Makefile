include $(TOPDIR)/rules.mk

PKG_NAME:=c-ares
PKG_VERSION:=1.14.0
PKG_RELEASE:=1
PKG_MD5SUM:=e57b37a7c46283e83c21cde234df10c7

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBCARES,libcares,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status}; \
		$(TARGET_CONFIG_OPTS) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
		$(TARGET_CONFIGURE_OPTS) \
		./configure \
			--target=$(GNU_TARGET_NAME) \
			--host=$(GNU_TARGET_NAME) \
			--build=$(GNU_HOST_NAME) \
			--program-prefix="" \
			--program-suffix="" \
			--prefix=/usr \
			--exec-prefix=/usr \
			--bindir=/usr/bin \
			--datadir=/usr/share \
			--includedir=/usr/include \
			--infodir=/usr/share/info \
			--libdir=/usr/lib \
			--libexecdir=/usr/lib \
			--localstatedir=/var \
			--mandir=/usr/share/man \
			--sbindir=/usr/sbin \
			--sysconfdir=/etc \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	libtool --finish $(PKG_INSTALL_DIR)/usr/lib/
	touch $@

$(IPKG_LIBCARES):
	install -d -m0755 $(IDIR_LIBCARES)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libcares.so* $(IDIR_LIBCARES)/usr/lib
	$(RSTRIP) $(IDIR_LIBCARES)
	$(IPKG_BUILD) $(IDIR_LIBCARES) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libcares.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libcares.so* $(STAGING_DIR)/usr/lib/
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/ares{,_*}.h $(STAGING_DIR)/usr/include/
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/libcares.so

uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/usr/lib/libcares.so* \
		$(STAGING_DIR)/usr/include/ares{,_*}.h

compile-targets: install-dev
clean-targets: uninstall-dev

