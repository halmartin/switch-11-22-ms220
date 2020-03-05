# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=popt
PKG_VERSION:=1.16
PKG_RELEASE:=4
PKG_MD5SUM:=3743beefa3dd6247a73f8f7a32c14c33

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBPOPT,libpopt,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
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
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBPOPT):
	install -d -m0755 $(IDIR_LIBPOPT)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libpopt.so.* $(IDIR_LIBPOPT)/usr/lib/
	$(RSTRIP) $(IDIR_LIBPOPT)
	$(IPKG_BUILD) $(IDIR_LIBPOPT) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libpopt.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/popt.h $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libpopt.{a,so*} $(STAGING_DIR)/usr/lib/
	touch $(STAGING_DIR)/usr/lib/libpopt.so

install-dev: $(STAGING_DIR)/usr/lib/libpopt.so

uninstall-dev:
	rm -rf \
	  $(STAGING_DIR)/usr/include/popt.h \
	  $(STAGING_DIR)/usr/lib/libpopt.{a,so*} \

compile-targets: install-dev
clean-targets: uninstall-dev
