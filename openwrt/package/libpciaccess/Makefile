include $(TOPDIR)/rules.mk

PKG_NAME:=libpciaccess
PKG_VERSION:=0.13.1
PKG_RELEASE:=1
PKG_MD5SUM:=c5ff61cae4d6631f486953834f81790d

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBPCIACCESS,libpciaccess,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

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

$(IPKG_LIBPCIACCESS):
	install -m0755 -d $(IDIR_LIBPCIACCESS)/usr/include/
	install -m0755 -d $(IDIR_LIBPCIACCESS)/usr/lib/pkgconfig/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/* $(IDIR_LIBPCIACCESS)/usr/include/
	$(CP) -r $(PKG_INSTALL_DIR)/usr/lib/* $(IDIR_LIBPCIACCESS)/usr/lib/
	$(IPKG_BUILD) $(IDIR_LIBPCIACCESS) $(PACKAGE_DIR)

install-dev:
	mkdir -p $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/include/* $(STAGING_DIR)/usr/include/
	$(CP) -r $(PKG_INSTALL_DIR)/usr/lib/* $(STAGING_DIR)/usr/lib/

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/include/pciaccess*
	rm -rf $(STAGING_DIR)/usr/lib/libpciaccess*
	rm -rf $(STAGING_DIR)/usr/lib/pkgconf/pciaccess*

compile-targets: install-dev

clean-target: uninstall-dev
