# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=libpng
PKG_VERSION:=1.2.57
PKG_RELEASE:=1
PKG_MD5SUM:=dfcda3603e29dcc11870c48f838ef75b

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBPNG,libpng,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		ac_cv_func_setpgrp_void=no \
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
			--with-zlib=$(STAGING_DIR)/usr/ \
	)
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBPNG):
	install -d -m0755 $(IDIR_LIBPNG)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libpng{,12}.so.* $(IDIR_LIBPNG)/usr/lib/
	$(RSTRIP) $(IDIR_LIBPNG)
	$(IPKG_BUILD) $(IDIR_LIBPNG) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libpng.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/libpng{,12}-config $(STAGING_DIR)/usr/bin/
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/png{,conf}.h $(STAGING_DIR)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/libpng12 $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libpng{,12}.{a,so*} $(STAGING_DIR)/usr/lib/
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/libpng{,12}.pc $(STAGING_DIR)/usr/lib/pkgconfig/
	$(SED) 's,^[ILR]_opts=".\+",,g' $(STAGING_DIR)/usr/bin/libpng*-config
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/libpng.so

uninstall-dev:
	rm -rf \
	  $(STAGING_DIR)/usr/bin/libpng{,12}-config \
	  $(STAGING_DIR)/usr/include/png{,conf}.h \
	  $(STAGING_DIR)/usr/include/libpng \
	  $(STAGING_DIR)/usr/lib/libpng{,12}.{a,so*} \
	  $(STAGING_DIR)/usr/lib/pkgconfig/libpng{,12}.pc

compile-targets: install-dev
clean-targets: uninstall-dev

