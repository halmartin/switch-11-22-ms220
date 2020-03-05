include $(TOPDIR)/rules.mk

PKG_NAME:=imagemagick
PKG_VERSION:=6.7.6-1
PKG_RELEASE:=1
PKG_MD5SUM:=4405f92e4302b5c6783df95f5576629b

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=ImageMagick-$(PKG_VERSION).tar.bz2
PKG_CAT:=bunzip2 -c

PKG_BUILD_DIR:=$(BUILD_DIR)/ImageMagick-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,IMAGEMAGICK,imagemagick,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -Wall -I$(PKG_BUILD_DIR)/include/linux -I$(PKG_BUILD_DIR)/include" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		PKG_CONFIG_PATH="$(STAGING_DIR)/usr/lib/pkgconfig" \
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
		        --with-modules \
			--enable-shared \
			--enable-static \
			--without-xml \
			--without-x \
			--without-lqr \
			--without-gvc \
			--without-openexr \
			--with-quantum-depth=8 \
			--without-fontconfig \
			--without-pango \
			--without-rsvg \
	)
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_IMAGEMAGICK):
	install -d -m0755 $(IDIR_IMAGEMAGICK)/usr/include/ImageMagick
	install -d -m0755 $(IDIR_IMAGEMAGICK)/usr/lib/ImageMagick-$(PKG_VERSION)/modules-Q16/coders
	install -d -m0755 $(IDIR_IMAGEMAGICK)/etc/ImageMagick
	$(CP) $(PKG_INSTALL_DIR)/usr/include/* $(IDIR_IMAGEMAGICK)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/* $(IDIR_IMAGEMAGICK)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/etc/ImageMagick/* $(IDIR_IMAGEMAGICK)/etc/ImageMagick/
	$(RSTRIP) $(IDIR_IMAGEMAGICK)
	$(IPKG_BUILD) $(IDIR_IMAGEMAGICK) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libMagickCore.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/lib $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/ImageMagick $(STAGING_DIR)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libMagick*.a $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libMagick*.so* $(STAGING_DIR)/usr/lib/
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/libMagickCore.so

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/lib/libMagick*.a \
	  $(STAGING_DIR)/usr/lib/libMagick*.so*

install-dev: $(PKG_BUILD_DIR)/.built

compile-targets: install-dev
clean-targets: uninstall-dev

mostlyclean:
	-$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm -f $(PKG_BUILD_DIR)/.built
