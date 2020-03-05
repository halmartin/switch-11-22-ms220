# $Id$

include $(TOPDIR)/rules.mk

PKG_NAME := glib-networking
PKG_VERSION := 2.48.2
PKG_RELEASE := 1
PKG_MD5SUM := d7cf81d52c856b0c66f7821021f40e08

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE := $(PKG_NAME)-$(PKG_VERSION).tar.xz
PKG_CAT := xzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,GLIB-NETWORKING,glib-networking,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status}; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="-I$(STAGING_DIR)/usr/include $(TARGET_CFLAGS)" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
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
		--enable-shared \
		--enable-static \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_GLIB-NETWORKING):
	install -m0755 -d $(IDIR_GLIB-NETWORKING)/usr/lib/gio/modules
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/gio/modules/libgiognutls.so $(IDIR_GLIB-NETWORKING)/usr/lib/gio/modules
	$(RSTRIP) $(IDIR_GLIB-NETWORKING)
	$(IPKG_BUILD) $(IDIR_GLIB-NETWORKING) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/gio/modules/libgiognutls.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/lib/gio/modules
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/gio/modules/libgiognutls.{a,so*} $(STAGING_DIR)/usr/lib/gio/modules/
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/gio/modules/libgiognutls.so

uninstall-dev:


compile-targets: install-dev
clean-targets: uninstall-dev
