# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=pcre

PKG_VERSION:=8.39
PKG_RELEASE:=0
PKG_MD5SUM:=e3fca7650a0556a2647821679d81f585
VERSION_OPTIONS:= --enable-jit --disable-rebuild-chartables --enable-unicode-properties --enable-pcre16 --enable-pcre32
INSTALL_FILES := ,16,32,cpp,posix

PKG_SOURCE_URL:=https://dl.meraki.net/
#                @SF/pcre
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install


include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBPCRE,libpcre,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status}; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
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
			$(DISABLE_LARGEFILE) \
			$(VERSION_OPTIONS) \
			$(DISABLE_NLS) \
			--enable-shared \
			--enable-static \
			--enable-utf8 \
	);
	touch $@

$(PKG_BUILD_DIR)/.built: $(PKG_BUILD_DIR)/.configured
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C "$(PKG_BUILD_DIR)" \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBPCRE):
	install -d -m0755 $(IDIR_LIBPCRE)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libpcre{$(INSTALL_FILES)}.so.* $(IDIR_LIBPCRE)/usr/lib/
	$(RSTRIP) $(IDIR_LIBPCRE)
	$(IPKG_BUILD) $(IDIR_LIBPCRE) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libpcre.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/pcre-config $(STAGING_DIR)/usr/bin/
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/pcre*.h $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libpcre{$(INSTALL_FILES)}.{a,so*} $(STAGING_DIR)/usr/lib/
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/libpcre.pc $(STAGING_DIR)/usr/lib/pkgconfig
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/libpcre.so

uninstall-dev:
	rm -rf \
	  $(STAGING_DIR)/usr/bin/pcre-config \
	  $(STAGING_DIR)/usr/include/pcre{$(INSTALL_FILES)}.h \
	  $(STAGING_DIR)/usr/lib/libpcre{$(INSTALL_FILES)}.{a,so*} \
	  $(STAGING_DIR)/usr/lib/pkgconfig/libpcre.pc

compile-targets: install-dev
clean-targets: uninstall-dev
