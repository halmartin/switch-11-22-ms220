# $Id$

include $(TOPDIR)/rules.mk

PKG_NAME := libsoup
PKG_VERSION := 2.54.0.1
PKG_RELEASE := 1
PKG_MD5SUM := 758dd62709fdf342c663cc63705eed4b

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE := $(PKG_NAME)-$(PKG_VERSION).tar.xz
PKG_CAT := xzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBSOUP,libsoup,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status}; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="-I$(STAGING_DIR)/usr/include $(TARGET_CFLAGS)" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -lintl" \
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
		  --enable-vala=no \
		  --with-gssapi=no \
		  --disable-tls-check \
		  --disable-documentation \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBSOUP):
	install -m0755 -d $(IDIR_LIBSOUP)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libsoup-2.4.so.* $(IDIR_LIBSOUP)/usr/lib/
	$(RSTRIP) $(IDIR_LIBSOUP)
	$(IPKG_BUILD) $(IDIR_LIBSOUP) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libsoup.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	touch $@

install-dev:  $(STAGING_DIR)/usr/lib/libsoup.so
	$(MAKE) -C $(PKG_BUILD_DIR) install DESTDIR=$(STAGING_DIR)

uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/usr/lib/pkgconfig/libsoup* \
		$(STAGING_DIR)/usr/lib/libsoup*

compile-targets: install-dev
clean-targets: uninstall-dev
