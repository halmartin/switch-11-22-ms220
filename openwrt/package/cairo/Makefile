include $(TOPDIR)/rules.mk

PKG_NAME:=cairo
PKG_VERSION:=1.12.2
PKG_RELEASE:=1
PKG_MD5SUM:=87649eb75789739d517c743e94879e51

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=cairo-$(PKG_VERSION).tar.xz
PKG_CAT:=xzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,CAIRO,cairo,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib -Wl,-rpath-link=$(STAGING_DIR)/usr/lib" \
		$(TARGET_CONFIGURE_OPTS) \
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
			$(DISABLE_LARGEFILE) \
			--disable-xlib \
			--disable-xcb \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_CAIRO):
	install -d -m0755 $(IDIR_CAIRO)/usr/lib
	install -d -m0755 $(IDIR_CAIRO)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/* $(IDIR_CAIRO)/usr/bin
	$(RSTRIP) $(IDIR_CAIRO)
	$(IPKG_BUILD) $(IDIR_CAIRO) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/cairo.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/lib

install-dev: $(STAGING_DIR)/usr/lib/cairo.so

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/lib/cairo.so


compile-targets: install-dev

clean-targets: uninstall-dev