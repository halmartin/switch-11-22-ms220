include $(TOPDIR)/rules.mk

PKG_NAME:=xorg-server
PKG_VERSION:=1.9.3
PKG_RELEASE:=1
PKG_MD5SUM:=5bef6839a76d029204ab31aa2fcb5201

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bunzip2 -c

PKG_BUILD_DIR:=$(BUILD_DIR)/xorg-server-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,XORG_SERVER,$(PKG_NAME),$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -Wall -I$(PKG_BUILD_DIR)/include/linux -I$(PKG_BUILD_DIR)/include" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		PKG_CONFIG_PATH="$(STAGING_DIR)/usr/lib/pkgconfig" \
		PKG_CONFIG_SYSROOT_DIR="$(STAGING_DIR)" \
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
			--enable-shared \
			--disable-static \
			--with-gnu-ld \
			--enable-shared \
			--with-sysroot=$(STAGING_DIR) \
		--disable-dependency-tracking \
		--disable-debug \
		--disable-unit-tests \
		--disable-builddocs \
		--disable-glx-tls \
		--disable-composite \
		--disable-xres \
		--disable-record \
		--enable-xv \
		--enable-xvmc \
		--disable-dga \
		--disable-screensaver \
		--disable-xdmcp \
		--disable-xdm-auth-1 \
		--disable-glx \
		--disable-dri \
		--disable-dri2 \
		--disable-xinerama \
		--disable-xf86vidmode \
		--disable-xace \
		--disable-xselinux \
		--disable-xcalibrate \
		--disable-tslib \
		--disable-dbe \
		--disable-xf86bigfont \
		--enable-dpms \
		--disable-config-dbus \
		--disable-config-hal \
		--disable-xfree86-utils \
		--disable-xaa \
		--enable-vgahw \
		--disable-vbe \
		--enable-int10-module \
		--enable-xorg \
		--disable-dmx \
		--disable-xvfb \
		--disable-xnest \
		--disable-xquartz \
		--disable-standalone-xpbproxy \
		--disable-xwin \
		--disable-kdrive \
		--disable-xfake \
		--disable-secure-rpc \
		--enable-silent-rules \
	)
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_XORG_SERVER):
	mkdir -p $(IDIR_XORG_SERVER)/usr/bin
	mkdir -p $(IDIR_XORG_SERVER)/usr/include/xorg
	mkdir -p $(IDIR_XORG_SERVER)/usr/lib/xorg/modules
	mkdir -p $(IDIR_XORG_SERVER)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/* $(IDIR_XORG_SERVER)/usr/bin
	$(CP) -r $(PKG_INSTALL_DIR)/usr/lib/* $(IDIR_XORG_SERVER)/usr/lib
	$(CP) -r $(PKG_INSTALL_DIR)/usr/include/xorg/* $(IDIR_XORG_SERVER)/usr/include/
	$(CP) -r $(PKG_INSTALL_DIR)/usr/include/* $(IDIR_XORG_SERVER)/usr/include/
	$(RSTRIP) $(IDIR_XORG_SERVER)
	$(IPKG_BUILD) $(IDIR_XORG_SERVER) $(PACKAGE_DIR)

install-dev:
	mkdir -p $(STAGING_DIR)/usr/bin
	mkdir -p $(STAGING_DIR)/usr/lib/xorg
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	mkdir -p $(STAGING_DIR)/usr/include/xorg
	$(CP) -r $(PKG_INSTALL_DIR)/usr/bin/* $(STAGING_DIR)/usr/bin/
	$(CP) -r $(PKG_INSTALL_DIR)/usr/lib/* $(STAGING_DIR)/usr/lib
	$(CP) -r $(PKG_INSTALL_DIR)/usr/include/* $(STAGING_DIR)/usr/include/

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/lib/xorg
	rm -rf $(STAGING_DIR)/usr/bin/X
	rm -rf $(STAGING_DIR)/usr/bin/Xorg
	rm -rf $(STAGING_DIR)/usr/include/xorg
	rm -rf $(STAGING_DIR)/usr/lib/pkgconf/xorg-server.pc

compile-targets: install-dev

clean-targets: uninstall-dev
