include $(TOPDIR)/rules.mk

PKG_NAME:=libxau
PKG_VERSION:=1.0.7
PKG_RELEASE:=1
PKG_MD5SUM:=0ec2611a06dba4db7c2b3d2850bd8474

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=libXau-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/libXau-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBXAU,libxau,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

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

$(IPKG_LIBXAU):
	install -m0755 -d $(IDIR_LIBXAU)/usr/include/X11/
	install -m0755 -d $(IDIR_LIBXAU)/usr/lib/pkgconfig/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/X11/* $(IDIR_LIBXAU)/usr/include/X11/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/* $(IDIR_LIBXAU)/usr/lib/pkgconfig/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/lib* $(IDIR_LIBXAU)/usr/lib/
	$(IPKG_BUILD) $(IDIR_LIBXAU) $(PACKAGE_DIR)

install-dev:
	mkdir -p $(STAGING_DIR)/usr/include/X11/
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/include/X11/* $(STAGING_DIR)/usr/include/X11/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/* $(STAGING_DIR)/usr/lib/pkgconfig/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/lib* $(STAGING_DIR)/usr/lib/

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/lib/libXau*
	rm -rf $(STAGING_DIR)/usr/lib/pkgconf/xau.pc

compile-targets: install-dev

clean-target: uninstall-dev
