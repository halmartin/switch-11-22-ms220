include $(TOPDIR)/rules.mk

PKG_NAME:=libsodium
PKG_VERSION:=1.0.11
PKG_RELEASE:=2
PKG_MD5SUM:=b58928d035064b2a46fb564937b83540

PKG_SOURCE_URL:=http://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBSODIUM,libsodium,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(strip $(TARGET_CFLAGS)) -std=c99" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
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
		  $(DISABLE_NLS) \
		  --enable-shared \
		  --enable-static \
		  --disable-ssp \
		  --enable-minimal=yes \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR)/src/libsodium \
		CFLAGS_O="$(TARGET_CFLAGS)" \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBSODIUM):
	install -d -m0755 $(IDIR_LIBSODIUM)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libsodium.so.* $(IDIR_LIBSODIUM)/usr/lib
	$(RSTRIP) $(IDIR_LIBSODIUM)
	$(IPKG_BUILD) $(IDIR_LIBSODIUM) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libsodium.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include/sodium
	$(CP) $(PKG_INSTALL_DIR)/usr/include/sodium.h $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/sodium/*.h $(STAGING_DIR)/usr/include/sodium
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libsodium.{a,so*} $(STAGING_DIR)/usr/lib
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	touch $(STAGING_DIR)/usr/lib/libsodium.so

install-dev: $(STAGING_DIR)/usr/lib/libsodium.so

uninstall-dev:
	rm -rf \
	  $(STAGING_DIR)/usr/include/sodium*.h \
	  $(STAGING_DIR)/usr/include/sodium \
	  $(STAGING_DIR)/usr/lib/libsodium.{a,so*} \

compile-targets: install-dev
clean-targets: uninstall-dev
