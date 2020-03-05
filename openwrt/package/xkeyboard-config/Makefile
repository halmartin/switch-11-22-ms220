include $(TOPDIR)/rules.mk

PKG_NAME:=xkeyboard-config
PKG_VERSION:=2.5
PKG_RELEASE:=1
PKG_MD5SUM:=8cd1d7e074a810ef21b09ea963c43ad3

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bunzip2 -c

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,XKEYBOARD_CONFIG,$(PKG_NAME),$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

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
	)
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_XKEYBOARD_CONFIG):
	mkdir -p $(IDIR_XKEYBOARD_CONFIG)/usr/lib/pkgconfig
	mkdir -p $(IDIR_XKEYBOARD_CONFIG)/usr/lib/locale
	mkdir -p $(IDIR_XKEYBOARD_CONFIG)/usr/share/X11/xkb
	$(CP) $(PKG_INSTALL_DIR)/usr/share/pkgconfig/* $(IDIR_XKEYBOARD_CONFIG)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/share/X11/xkb/* $(IDIR_XKEYBOARD_CONFIG)/usr/share/X11/xkb
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/* $(IDIR_XKEYBOARD_CONFIG)/usr/lib
	$(RSTRIP) $(IDIR_XKEYBOARD_CONFIG)
	$(IPKG_BUILD) $(IDIR_XKEYBOARD_CONFIG) $(PACKAGE_DIR)

install-dev:
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	mkdir -p $(STAGING_DIR)/usr/lib/locale
	mkdir -p $(STAGING_DIR)/usr/share/X11/xkb
	$(CP) $(PKG_INSTALL_DIR)/usr/* $(STAGING_DIR)/usr/

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/share/X11/xkb
	rm -f $(STAGING_DIR)/usr/lib/pkgconfig/xkeyboard-config.pc
	rm -f $(STAGING_DIR)/usr/lib/locale/*/LC_MESSAGES/xkeyboard-config*

compile-targets: install-dev

clean-targets: uninstall-dev
