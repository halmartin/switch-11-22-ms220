# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=curl
PKG_VERSION:=7.64.0
PKG_RELEASE:=1
PKG_MD5SUM:=d0bcc586873cfef08b4b9594e5395a33

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,CURL,curl,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIBCURL,libcurl,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(strip $(TARGET_CFLAGS))" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		LIBS="-lssl -lcrypto" \
		PKG_CONFIG_PATH="$(STAGING_DIR)/usr/lib/pkgconfig" \
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
			$(DISABLE_NLS) \
			--enable-shared \
			--enable-static \
			--disable-rpath \
			--with-gnu-ld \
			--enable-optimize \
			--enable-symbol-hiding \
			--disable-thread \
			--enable-cookies \
			--enable-crypto-auth \
			--enable-nonblocking \
			--enable-file \
			--enable-ftp \
			--enable-http \
			--enable-ipv6 \
			--enable-tftp \
			--disable-ares \
			--disable-crypto-auth \
			--disable-debug \
			--disable-dict \
			--disable-gopher \
			--disable-imap \
			--disable-ldap \
			--disable-manual \
			--disable-ntlm-wb \
			--disable-pop3 \
			--disable-rtsp \
			--disable-smtp \
			--disable-sspi \
			--disable-telnet \
			--with-random="/dev/urandom" \
			--with-ssl="$(STAGING_DIR)/usr" \
			--without-ca-bundle \
			--without-gnutls \
			--without-libidn \
	)
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_CURL):
	install -m0755 -d $(IDIR_CURL)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/curl $(IDIR_CURL)/usr/bin/
	$(RSTRIP) $(IDIR_CURL)
	$(IPKG_BUILD) $(IDIR_CURL) $(PACKAGE_DIR)

$(IPKG_LIBCURL):
	install -m0755 -d $(IDIR_LIBCURL)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libcurl.so.* $(IDIR_LIBCURL)/usr/lib/
	$(RSTRIP) $(IDIR_LIBCURL)
	$(IPKG_BUILD) $(IDIR_LIBCURL) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libcurl.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/curl-config $(STAGING_DIR)/usr/bin/
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/curl $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libcurl.a $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libcurl.so* $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/libcurl.pc $(STAGING_DIR)/usr/lib/pkgconfig/
	$(SED) 's,-I/usr/include,,g' $(STAGING_DIR)/usr/bin/curl-config
	$(SED) 's,-L/usr/lib,,g' $(STAGING_DIR)/usr/bin/curl-config
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/libcurl.so

uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/usr/bin/curl-config \
		$(STAGING_DIR)/usr/include/curl \
		$(STAGING_DIR)/usr/lib/libcurl.a \
		$(STAGING_DIR)/usr/lib/libcurl.so* \

compile-targets: install-dev
clean-targets: uninstall-dev

mostlyclean:
	-$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm -f $(PKG_BUILD_DIR)/.built

