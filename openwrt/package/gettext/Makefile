# $Id$

include $(TOPDIR)/rules.mk

PKG_NAME:=gettext
PKG_VERSION:=0.19.4
PKG_RELEASE:=1
PKG_MD5SUM:=d3511af1e604a3478900d2c2b4a4a48e

PKG_SOURCE_URL:=https://dl.meraki.net
UNUSED_ORIGINAL_PKG_SOURCE_URL:=https://ftp.gnu.org/pub/gnu/gettext/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,GETTEXT,gettext,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
		LIBS="-liconv -lrt" \
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
		  --disable-rpath \
		  --enable-nls \
		  --disable-java \
		  --disable-native-java \
		  --disable-openmp \
		  --with-included-gettext \
		  --without-libintl-prefix \
		  --without-libexpat-prefix \
		  --without-emacs \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install

$(IPKG_GETTEXT):
	install -d -m0755 $(IDIR_GETTEXT)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/ngettext $(IDIR_GETTEXT)/usr/bin/
	install -d -m0755 $(IDIR_GETTEXT)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libintl.so.* $(IDIR_GETTEXT)/usr/lib/
	$(RSTRIP) $(IDIR_GETTEXT)
	$(IPKG_BUILD) $(IDIR_GETTEXT) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libintl.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/ngettext $(STAGING_DIR)/usr/bin/
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/libintl.h $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libintl.{a,so*} $(STAGING_DIR)/usr/lib/
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/libintl.so

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/bin/ngettext
	rm -rf $(STAGING_DIR)/usr/include/libintl.h
	rm -rf $(STAGING_DIR)/usr/lib/libintl.{a,so*}

compile-targets: install-dev
clean-targets: uninstall-dev
