# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=libgpg-error
PKG_VERSION:=1.32
PKG_RELEASE:=0
PKG_MD5SUM:=ef3d928a5a453fa701ecc3bb22be1c64

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBGPG_ERROR,libgpg-error,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		cp $(PKG_BUILD_DIR)/src/syscfg/lock-obj-pub.arm-unknown-linux-gnueabi.h $(PKG_BUILD_DIR)/src/syscfg/lock-obj-pub.arm-unknown-linux-gnu.h ; \
		cp $(PKG_BUILD_DIR)/src/syscfg/lock-obj-pub.i686-pc-linux-gnu.h $(PKG_BUILD_DIR)/src/syscfg/lock-obj-pub.i386-pc-linux-gnu.h ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib" \
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
		$(DISABLE_NLS) \
		$(DISABLE_LARGEFILE) \
		--enable-shared \
		--enable-static \
		--disable-rpath \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBGPG_ERROR):
	install -m0755 -d $(IDIR_LIBGPG_ERROR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libgpg-error.so.* $(IDIR_LIBGPG_ERROR)/usr/lib/
	$(RSTRIP) $(IDIR_LIBGPG_ERROR)
	$(IPKG_BUILD) $(IDIR_LIBGPG_ERROR) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libgpg-error.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/gpg-error-config $(STAGING_DIR)/usr/bin/
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/gpg-error.h $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libgpg-error.{a,so*} $(STAGING_DIR)/usr/lib/
	mkdir -p $(STAGING_DIR)/usr/share/aclocal
	$(CP) $(PKG_INSTALL_DIR)/usr/share/aclocal/gpg-error.m4 $(STAGING_DIR)/usr/share/aclocal/
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/libgpg-error.so

uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/usr/bin/gpg-error-config \
		$(STAGING_DIR)/usr/include/gpg-error.h \
		$(STAGING_DIR)/usr/lib/libgpg-error.{a,so*} \
		$(STAGING_DIR)/usr/share/aclocal/gpg-error.m4 \

compile-targets: install-dev
clean-targets: uninstall-dev

mostlyclean:
	make -C $(PKG_BUILD_DIR) clean
	rm -f $(PKG_BUILD_DIR)/.built
