include $(TOPDIR)/rules.mk

PKG_NAME:=pixman
PKG_VERSION:=0.26.0
PKG_RELEASE:=1
PKG_MD5SUM:=6563b6400b9fa23b47fd52105faf72b4

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=pixman-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,PIXMAN,pixman,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

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
			--with-sysroot=$(STAGING_DIR) \
			$(DISABLE_LARGEFILE) \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_PIXMAN):
	install -d -m0755 $(IDIR_PIXMAN)/usr/lib
	install -d -m0755 $(IDIR_PIXMAN)/usr/include/pixman-1
	$(CP) -r $(PKG_INSTALL_DIR)/usr/include/* $(IDIR_PIXMAN)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/* $(IDIR_PIXMAN)/usr/lib
	$(IPKG_BUILD) $(IDIR_PIXMAN) $(PACKAGE_DIR)

install-dev:
	mkdir -p $(STAGING_DIR)/usr/lib
	mkdir -p $(STAGING_DIR)/usr/incude/pixman-1
	$(CP) -r $(IDIR_PIXMAN)/usr/include/* $(STAGING_DIR)/usr/include
	$(CP) $(IDIR_PIXMAN)/usr/lib/* $(STAGING_DIR)/usr/lib

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/lib/libpixman*
	rm -rf $(STAGING_DIR)/usr/include/pixman-1

compile-targets: install-dev

clean-targets: uninstall-dev