# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=gnutls
PKG_VERSION:=3.4.9
PKG_RELEASE:=0
PKG_MD5SUM:=1b3b6d55d0e2b6d01a54f53129f1da9b

PKG_SOURCE_URL:=https://dl.meraki.net/
UNUSED_ORIGINAL_PKG_SOURCE_URL:=ftp://ftp.gnutls.org/pub/gnutls/ \
	ftp://ftp.gnupg.org/gcrypt/alpha/gnutls/ \
	http://www.mirrors.wiretapped.net/security/network-security/gnutls/ \
	ftp://ftp.mirrors.wiretapped.net/pub/security/network-security/gnutls/ \
	http://josefsson.org/gnutls/releases/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.xz
PKG_CAT:=xzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBGNUTLS,libgnutls,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,GNUTLS_UTILS,gnutls-utils,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIBGNUTLS_OPENSSL,libgnutls-openssl,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib" \
		PKG_CONFIG_SYSROOT_DIR="$(STAGING_DIR)" \
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
		--enable-shared \
		--enable-static \
		--disable-rpath \
		--enable-local-libopts \
		--disable-cryptodev \
		--disable-cxx \
		--with-included-libtasn1=yes \
		--without-p11-kit \
		--without-idn \
		--without-tpm \
		--disable-libdane \
		--disable-guile \
		--disable-doc \
		--disable-tests \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBGNUTLS):
	install -m0755 -d $(IDIR_LIBGNUTLS)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libgnutls.so.* $(IDIR_LIBGNUTLS)/usr/lib/
	$(RSTRIP) $(IDIR_LIBGNUTLS)
	$(IPKG_BUILD) $(IDIR_LIBGNUTLS) $(PACKAGE_DIR)

$(IPKG_LIBGNUTLS_OPENSSL):
	install -m0755 -d $(IDIR_LIBGNUTLS_OPENSSL)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libgnutls*.so.* $(IDIR_LIBGNUTLS_OPENSSL)/usr/lib/
	$(RSTRIP) $(IDIR_LIBGNUTLS_OPENSSL)
	$(IPKG_BUILD) $(IDIR_LIBGNUTLS_OPENSSL) $(PACKAGE_DIR)

$(IPKG_GNUTLS_UTILS):
	install -m0755 -d $(IDIR_GNUTLS_UTILS)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/certtool $(IDIR_GNUTLS_UTILS)/usr/bin/
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/gnutls-{cli,serv} $(IDIR_GNUTLS_UTILS)/usr/bin/
	$(RSTRIP) $(IDIR_GNUTLS_UTILS)
	$(IPKG_BUILD) $(IDIR_GNUTLS_UTILS) $(PACKAGE_DIR)

#We only install the libraries, but it would be possible to also copy the utilities from $(PKG_INSTALL_DIR)/usr/bin here
$(STAGING_DIR)/usr/lib/libgnutls.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/gnutls $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libgnutls.{a,so*} $(STAGING_DIR)/usr/lib/
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/gnutls.pc $(STAGING_DIR)/usr/lib/pkgconfig/
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/libgnutls.so

uninstall-dev:
	rm -rf  $(STAGING_DIR)/usr/include/gnutls \
		$(STAGING_DIR)/usr/lib/libgnutls.{a,so*} \
		$(STAGING_DIR)/usr/lib/pkgconfig/gnutls.pc \

compile-targets: install-dev
clean-targets: uninstall-dev

mostlyclean:
	make -C $(PKG_BUILD_DIR) clean
	rm -f $(PKG_BUILD_DIR)/.built
