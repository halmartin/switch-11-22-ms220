include $(TOPDIR)/rules.mk

PKG_NAME:=libtirpc
PKG_VERSION:=1.1.4
PKG_RELEASE:=1
PKG_MD5SUM:=f5d2a623e9dfbd818d2f3f3a4a878e3a

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBTIRPC,libtirpc,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; autoreconf -i; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		./configure \
			--target=$(REAL_GNU_TARGET_NAME) \
			--host=$(REAL_GNU_TARGET_NAME) \
			--build=$(GNU_HOST_NAME) \
			--prefix=/usr \
			--disable-gssapi \
			--enable-shared \
			--enable-static \
	)
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBTIRPC):
	install -d -m0755 $(IDIR_LIBTIRPC)/usr/lib
	cp -a $(PKG_INSTALL_DIR)/usr/lib/libtirpc.so* $(IDIR_LIBTIRPC)/usr/lib
	install -d -m0755 $(IDIR_LIBTIRPC)/etc
	cp -a $(PKG_INSTALL_DIR)/usr/etc/netconfig $(IDIR_LIBTIRPC)/etc
	$(RSTRIP) $(IDIR_LIBTIRPC)
	$(IPKG_BUILD) $(IDIR_LIBTIRPC) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libtirpc.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/lib
	cp -a $(PKG_INSTALL_DIR)/usr/lib/libtirpc.* $(STAGING_DIR)/lib
	mkdir -p $(STAGING_DIR)/include/
	cp -a $(PKG_INSTALL_DIR)/usr/include/tirpc $(STAGING_DIR)/include

install-dev: $(STAGING_DIR)/usr/lib/libtirpc.so

uninstall-dev:
	rm -rf \
	  $(STAGING_DIR)/lib/libtirpc.* \
	  $(STAGING_DIR)/include/tirpc/* \

compile-targets: install-dev
clean-targets: uninstall-dev
