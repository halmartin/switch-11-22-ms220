# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=libpam
PKG_VERSION:=1.2.0
PKG_RELEASE:=1
PKG_MD5SUM:=ee4a480d77b341c99e8b1375f8f180c0

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=Linux-PAM-$(PKG_VERSION).tar.bz2
PKG_CAT:=bzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/Linux-PAM-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBPAM,libpam,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status}; \
		autoreconf && \
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
			$(DISABLE_NLS) \
			--enable-shared \
			--enable-static \
			--enable-pamlocking \
			--disable-prelude \
			--disable-lckpwdf \
			--disable-selinux \
			--disable-nls \
			--disable-rpath \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CFLAGS="$(TARGET_CFLAGS) -Wall" \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBPAM):
	install -d -m0755 $(IDIR_LIBPAM)/usr/sbin/
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/* $(IDIR_LIBPAM)/usr/sbin
	install -d -m0755 $(IDIR_LIBPAM)/lib
	$(CP) $(PKG_INSTALL_DIR)/lib/*.so* $(IDIR_LIBPAM)/lib
	install -d -m0755 $(IDIR_LIBPAM)/lib/security
	$(CP) $(PKG_INSTALL_DIR)/lib/security/pam_permit.so $(IDIR_LIBPAM)/lib/security
	$(RSTRIP) $(IDIR_LIBPAM)
	$(IPKG_BUILD) $(IDIR_LIBPAM) $(PACKAGE_DIR)

compile-targets: install-dev

install-dev: $(PKG_BUILD_DIR)/.built $(STAGING_DIR)/include
	mkdir -p $(STAGING_DIR)/usr/include/security
	$(CP) $(PKG_INSTALL_DIR)/usr/include/*.h $(STAGING_DIR)/usr/include/security
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/lib/*.so* $(STAGING_DIR)/usr/lib
