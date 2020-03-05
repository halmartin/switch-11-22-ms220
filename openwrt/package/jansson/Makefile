# $Id$

include $(TOPDIR)/rules.mk

PKG_NAME:=jansson
PKG_VERSION:=2.7
PKG_RELEASE:=1
PKG_MD5SUM:=3a106a465bbb77637550b422f5b262ef

PKG_SOURCE_URL:=https://dl.meraki.net
UNUSED_ORIGINAL_PKG_SOURCE_URL:=http://www.digip.org/jansson/releases/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,JANSSON,jansson,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
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
		  --datadir=/usr/share \
		  --includedir=/usr/include \
		  --infodir=/usr/share/info \
		  --libdir=/usr/lib \
		  --libexecdir=/usr/lib \
		  --localstatedir=/var \
		  --mandir=/usr/share/man \
		  --sbindir=/usr/sbin \
		  --sysconfdir=/etc \
		  $(DISABLE_NLS) \
		  $(DISABLE_LARGEFILE) \
		  --enable-shared \
		  --enable-static \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install

$(IPKG_JANSSON):
	install -d -m0755 $(IDIR_JANSSON)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libjansson.so.* $(IDIR_JANSSON)/usr/lib/
	$(RSTRIP) $(IDIR_JANSSON)
	$(IPKG_BUILD) $(IDIR_JANSSON) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libjansson.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/jansson{,_config}.h $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libjansson.{a,so*} $(STAGING_DIR)/usr/lib/
	touch $@
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/jansson.pc $(STAGING_DIR)/usr/lib/pkgconfig/

install-dev: $(STAGING_DIR)/usr/lib/libjansson.so

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/include/jansson{,_config}.h
	rm -rf $(STAGING_DIR)/usr/lib/libjansson.{a,so*}

compile-targets: install-dev
clean-targets: uninstall-dev
