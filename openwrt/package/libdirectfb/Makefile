# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=libdirectfb
PKG_VERSION:=1.7.7
PKG_RELEASE:=1
PKG_MD5SUM:=152cf1863b1a3a28aa1370e9053440bf

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=DirectFB-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/DirectFB-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBDIRECTFB,libdirectfb,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/usr/include/freetype2" \
		LDFLAGS="-L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib -Wl,-rpath-link=$(STAGING_DIR)/usr/lib" \
		$(TARGET_CONFIGURE_OPTS) \
		PKG_CONFIG_PATH="$(STAGING_DIR)/usr/lib/pkgconfig" \
		LIBPNG_CFLAGS="-I$(STAGING_DIR)/usr/include/libpng12" \
		LIBPNG_LIBS="-L$(STAGING_DIR)/lib -lpng12 -lz -lm" \
		./configure \
			--target=$(GNU_TARGET_NAME) \
			--host=$(GNU_TARGET_NAME) \
			--build=$(GNU_HOST_NAME) \
			--program-prefix="" \
			--program-suffix="" \
			--prefix=/usr \
			--exec-prefix=/usr \
			--bindir=/usr/bin \
			--sbindir=/usr/sbin \
			--libexecdir=/usr/lib \
			--sysconfdir=/etc \
			--datadir=/usr/share \
			--localstatedir=/var \
			--mandir=/usr/man \
			--infodir=/usr/info \
			$(DISABLE_NLS) \
			$(DISABLE_LARGEFILE) \
			--disable-osx \
			--disable-x11 \
			--enable-debug-support \
			--disable-network \
			--disable-mmx \
			--disable-sse \
			--enable-fbdev \
			--disable-sdl \
			--disable-vnc \
			--enable-sysfs \
			--with-inputdrivers=linuxinput,keyboard \
			--with-gfxdrivers=none \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBDIRECTFB):
	install -d -m0755 $(IDIR_LIBDIRECTFB)/usr/lib
	install -d -m0755 $(IDIR_LIBDIRECTFB)/usr/bin
	install -d -m0755 $(IDIR_LIBDIRECTFB)/usr/share/directfb-1.7.7
	install -d -m0755 $(IDIR_LIBDIRECTFB)/usr/lib/directfb-1.7-7/interfaces/IDirectFBFont
	install -d -m0755 $(IDIR_LIBDIRECTFB)/usr/lib/directfb-1.7-7/interfaces/IDirectFBImageProvider
	install -d -m0755 $(IDIR_LIBDIRECTFB)/usr/lib/directfb-1.7-7/interfaces/IDirectFBVideoProvider
	install -d -m0755 $(IDIR_LIBDIRECTFB)/usr/lib/directfb-1.7-7/wm
	install -d -m0755 $(IDIR_LIBDIRECTFB)/usr/lib/directfb-1.7-7/systems
	install -d -m0755 $(IDIR_LIBDIRECTFB)/usr/lib/directfb-1.7-7/inputdrivers
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/* $(IDIR_LIBDIRECTFB)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/share/directfb-1.7.7/* $(IDIR_LIBDIRECTFB)/usr/share/directfb-1.7.7/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/lib{direct,fusion}*.so* $(IDIR_LIBDIRECTFB)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/directfb-1.7-7/interfaces/IDirectFBFont/*.so* $(IDIR_LIBDIRECTFB)/usr/lib/directfb-1.7-7/interfaces/IDirectFBFont/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/directfb-1.7-7/interfaces/IDirectFBImageProvider/*.so* $(IDIR_LIBDIRECTFB)/usr/lib/directfb-1.7-7/interfaces/IDirectFBImageProvider/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/directfb-1.7-7/interfaces/IDirectFBVideoProvider/*.so* $(IDIR_LIBDIRECTFB)/usr/lib/directfb-1.7-7/interfaces/IDirectFBVideoProvider/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/directfb-1.7-7/wm/*.so* $(IDIR_LIBDIRECTFB)/usr/lib/directfb-1.7-7/wm/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/directfb-1.7-7/systems/*.so* $(IDIR_LIBDIRECTFB)/usr/lib/directfb-1.7-7/systems/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/directfb-1.7-7/inputdrivers/*.so* $(IDIR_LIBDIRECTFB)/usr/lib/directfb-1.7-7/inputdrivers/
	$(RSTRIP) $(IDIR_LIBDIRECTFB)
	$(IPKG_BUILD) $(IDIR_LIBDIRECTFB) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libdirectfb.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/lib
	mkdir -p $(STAGING_DIR)/usr/include/directfb
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/lib{direct,fusion}*.so* $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/include/directfb/* $(STAGING_DIR)/usr/include/directfb

install-dev: $(STAGING_DIR)/usr/lib/libdirectfb.so

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/lib/libdirectfb.so


compile-targets: install-dev

clean-targets: uninstall-dev
