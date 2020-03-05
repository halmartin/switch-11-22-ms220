# $Id: Makefile 973 2005-05-19 21:22:09Z nico $

include $(TOPDIR)/rules.mk

PKG_NAME:=libfastjson
PKG_VERSION:=0.99.8
PKG_RELEASE:=1
PKG_MD5SUM:=fe7b4eae1bf40499f6f92b51d7e5899e

#http://download.rsyslog.com/libfastjson/libfastjson-0.99.8.tar.gz
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://dl.meraki.net/

PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBFASTJSON,libfastjson,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="-Wno-error=unused-but-set-variable -lm -I$(STAGING_DIR)/usr/include $(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
		ac_cv_func_malloc_0_nonnull="yes" \
		ac_cv_func_realloc_0_nonnull="yes" \
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
		  --datadir=/usr/share \
		  --includedir=/usr/include \
		  --infodir=/usr/share/info \
		  --libdir=/usr/lib \
		  --libexecdir=/usr/lib \
		  --localstatedir=/var \
		  --mandir=/usr/share/man \
		  --sbindir=/usr/sbin \
		  --sysconfdir=/etc \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBFASTJSON):
	install -m0755 -d $(IDIR_LIBFASTJSON)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libfastjson.so* $(IDIR_LIBFASTJSON)/usr/lib
	$(RSTRIP) $(IDIR_LIBFASTJSON)
	$(IPKG_BUILD) $(IDIR_LIBFASTJSON) $(PACKAGE_DIR)

install-dev:
	$(MAKE) -C $(PKG_BUILD_DIR) install DESTDIR=$(STAGING_DIR)

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/lib/libfastjson.{a,so*}

compile-targets: install-dev
clean-targets: uninstall-dev
