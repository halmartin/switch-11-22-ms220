include $(TOPDIR)/rules.mk

PKG_NAME:=fontconfig
PKG_VERSION:=2.9.0
PKG_RELEASE:=1
PKG_MD5SUM:=26c83855ed256b5c032baae032fadc4f

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,FONTCONFIG,fontconfig,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib -Wl,-rpath-link=$(STAGING_DIR)/usr/lib" \
		$(TARGET_CONFIGURE_OPTS) \
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
			--sbindir=/usr/sbin \
			--libexecdir=/usr/lib \
			--sysconfdir=/etc \
			--datadir=/usr/share \
			--localstatedir=/var \
			--mandir=/usr/man \
			--infodir=/usr/info \
			$(DISABLE_LARGEFILE) \
			--disable-docs \
			--with-sysroot=$(STAGING_DIR) \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_FONTCONFIG):
	install -d -m0755 $(IDIR_FONTCONFIG)/usr/lib
	install -d -m0755 $(IDIR_FONTCONFIG)/usr/bin
	install -d -m0755 $(IDIR_FONTCONFIG)/etc/fonts
	install -d -m0755 $(IDIR_FONTCONFIG)/etc/fonts/conf.avail
	install -d -m0755 $(IDIR_FONTCONFIG)/etc/fonts/conf.d
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/* $(IDIR_FONTCONFIG)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/* $(IDIR_FONTCONFIG)/usr/bin
	$(CP) -r $(PKG_INSTALL_DIR)/etc/* $(IDIR_FONTCONFIG)/etc
	$(RSTRIP) $(IDIR_FONTCONFIG)
	$(IPKG_BUILD) $(IDIR_FONTCONFIG) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/fontconfig.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/lib
	mkdir -p $(STAGING_DIR)/usr/bin
	mkdir -p $(STAGING_DIR)/etc/fonts/conf.avail
	mkdir -p $(STAGING_DIR)/etc/fonts/conf.d
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/*.so* $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/*.a $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/* $(STAGING_DIR)/usr/bin
	$(CP) -r $(PKG_INSTALL_DIR)/etc/* $(IDIR_FONTCONFIG)/etc

install-dev: $(STAGING_DIR)/usr/lib/fontconfig.so

uninstal-dev:
	rm -rf $(STAGING_DIR)/usr/lib/fontconfig.so* $(STAGING_DIR)/usr/lib/fontconfig.a
	rm -rf $(STAGING_DIR)/etc/fonts
	rm -rf $(STAGING_DIR)/usr/bin/fc-*

compile-targets: install-dev

clean-targets: uninstall-dev

mostlyclean:
	-$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm -f $(PKG_BUILD_DIR)/.built
