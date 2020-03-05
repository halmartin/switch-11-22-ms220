include $(TOPDIR)/rules.mk

PKG_NAME:=xf86-input-keyboard
PKG_VERSION:=1.6.1
PKG_RELEASE:=1
PKG_MD5SUM:=09744e8dc9a1fe5e61927c1073cd3428

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bunzip2 -c

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,XF86_INPUT_KEYBOARD,$(PKG_NAME),$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

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
			--with-xorg-module-dir=/usr/lib/xorg/modules \
	)
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_XF86_INPUT_KEYBOARD):
	mkdir -p $(IDIR_XF86_INPUT_KEYBOARD)/usr/lib/xorg/modules/input
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/xorg/modules/input/* $(IDIR_XF86_INPUT_KEYBOARD)/usr/lib/xorg/modules/input
	$(RSTRIP) $(IDIR_XF86_INPUT_KEYBOARD)
	$(IPKG_BUILD) $(IDIR_XF86_INPUT_KEYBOARD) $(PACKAGE_DIR)

install-dev:
	mkdir -p $(STAGING_DIR)/usr/lib/xorg/modules/input
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/xorg/modules/input/* $(STAGING_DIR)/usr/lib/xorg/modules/input

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/lib/xorg/modules/input/kbd_drv*

compile-targets: install-dev

clean-targets: uninstall-dev
