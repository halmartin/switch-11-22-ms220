include $(TOPDIR)/rules.mk

PKG_NAME:=libfontenc
PKG_VERSION:=1.1.1
PKG_RELEASE:=1
PKG_MD5SUM:=7b1775d237cb0768f5e710fc0ef425b6

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBFONTENC,libfontenc,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -Wall -I$(PKG_BUILD_DIR)/include/linux -I$(PKG_BUILD_DIR)/include" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		PKG_CONFIG_PATH="$(STAGING_DIR)/usr/lib/pkgconfig" \
		./autogen.sh \
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
			--with-sysroot=$(STAGING_DIR) \
			$(DISABLE_LARGEFILE) \
	)
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -Wall" \
		CROSS="$(TARGET_CROSS)" \
		prefix="/usr" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBFONTENC):
	install -m0755 -d $(IDIR_LIBFONTENC)/usr/include/X11/fonts
	install -m0755 -d $(IDIR_LIBFONTENC)/usr/lib
	install -m0755 -d $(IDIR_LIBFONTENC)/usr/lib/pkgconfig/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/X11/fonts/* $(IDIR_LIBFONTENC)/usr/include/X11/fonts/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/* $(IDIR_LIBFONTENC)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/* $(IDIR_LIBFONTENC)/usr/lib/pkgconfig/
	$(IPKG_BUILD) $(IDIR_LIBFONTENC) $(PACKAGE_DIR)

install-dev:
	mkdir -p $(STAGING_DIR)/usr/include/X11/fonts
	mkdir -p $(STAGING_DIR)/usr/lib
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/include/X11/fonts/* $(STAGING_DIR)/usr/include/X11/fonts/
	$(CP) -r $(PKG_INSTALL_DIR)/usr/lib/* $(STAGING_DIR)/usr/lib/

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/include/X11/fonts/fontenc.h
	rm -rf $(STAGING_DIR)/usr/lib/libfontenc*
	rm -rf $(STAGING_DIR)/usr/lib/pkgconf/fontenc.pc

compile-targets: install-dev

clean-target: uninstall-dev
