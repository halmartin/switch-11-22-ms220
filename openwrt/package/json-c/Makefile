# $Id: Makefile 973 2005-05-19 21:22:09Z nico $

include $(TOPDIR)/rules.mk

PKG_NAME:=json-c
PKG_VERSION:=0.12
PKG_RELEASE:=1
PKG_MD5SUM:=c2d07750dfd3edbdb1be18430dce2d94

# https://github.com/downloads/json-c/json-c/json-c-0.10-nodoc.tar.gz
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-nodoc.tar.gz
PKG_SOURCE_URL:=https://dl.meraki.net/

PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,JSON-C,json-c,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="-Wno-error=unused-but-set-variable -I$(STAGING_DIR)/usr/include $(TARGET_CFLAGS)" \
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

$(IPKG_JSON-C):
	install -m0755 -d $(IDIR_JSON-C)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libjson-c.so* $(IDIR_JSON-C)/usr/lib
	$(RSTRIP) $(IDIR_JSON-C)
	$(IPKG_BUILD) $(IDIR_JSON-C) $(PACKAGE_DIR)

install-dev:
	$(MAKE) -C $(PKG_BUILD_DIR) install DESTDIR=$(STAGING_DIR)

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/lib/libjson.{a,so*}

compile-targets: install-dev
clean-targets: uninstall-dev
