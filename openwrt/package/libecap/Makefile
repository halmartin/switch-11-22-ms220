# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=libecap
PKG_VERSION:=1.0.0
PKG_RELEASE:=1.0.0
PKG_MD5SUM:=68cbd5b8e505e3fa7da520c3b0fe5a3c

PKG_SOURCE_URL:=http://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBECAP,libecap,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.ecap_mods:
	(mkdir -p $(PKG_BUILD_DIR)/ecap_src ; \
		$(CP) ./src/* $(PKG_BUILD_DIR)/ecap_src ; \
		cd $(PKG_BUILD_DIR)/ecap_src; rm -rf config.{cache,status} ; \
		./bootstrap.sh ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
		DESTDIR="$(PKG_BUILD_DIR)" \
		PKG_CONFIG_SYSROOT_DIR="$(STAGING_DIR)" \
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
			--datadir=/usr/share/squid \
	);
	touch $@

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
		DESTDIR="$(PKG_BUILD_DIR)" \
		./configure \
			--target=$(GNU_TARGET_NAME) \
			--host=$(GNU_TARGET_NAME) \
			--build=$(GNU_HOST_NAME) \
			--program-prefix="" \
			--program-suffix="" \
			--prefix=/usr \
			--exec-prefix=/usr \
			--bindir=/usr/bin \
			--datadir=/usr/share/squid \
	)
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		DESTDIR=$(PKG_INSTALL_DIR) \
		all install
	touch $@

$(IPKG_LIBECAP):
	install -d -m0755 $(IDIR_LIBECAP)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libecap.so* $(IDIR_LIBECAP)/usr/lib
	$(RSTRIP) $(IDIR_LIBECAP)
	$(IPKG_BUILD) $(IDIR_LIBECAP) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libecap.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include/libecap
	$(CP) $(PKG_INSTALL_DIR)/usr/include/libecap/* $(STAGING_DIR)/usr/include/libecap
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libecap.so* $(STAGING_DIR)/usr/lib/
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/libecap.pc $(STAGING_DIR)/usr/lib/pkgconfig/
	$(MAKE) $(PKG_BUILD_DIR)/.ecap_mods
	$(MAKE) -C $(PKG_BUILD_DIR)/ecap_src \
		DESTDIR=$(PKG_INSTALL_DIR) \
		install
	install -d -m0755 $(IDIR_LIBECAP)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/squid_ssl_sniffer.so $(IDIR_LIBECAP)/usr/bin

install-dev: $(STAGING_DIR)/usr/lib/libecap.so

uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/usr/include/libecap

compile-targets: install-dev
clean-targets: uninstall-dev

