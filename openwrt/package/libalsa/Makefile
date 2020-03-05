#
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id$

include $(TOPDIR)/rules.mk

PKG_NAME:=alsa-lib
PKG_VERSION:=1.0.27.2
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_MD5SUM:=69129a7c37697f81ac092335e9fa452b
PKG_CAT:=bzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBALSA,libalsa,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

ifeq ($(KERNEL),2.4)
DEPENDS_KMOD:=+kmod-alsa
else
DEPENDS_KMOD:=+kmod-sound-core
endif

SOFT_FLOAT_CONFIG_OPTION:=
ifeq ($(strip $(BR2_SOFT_FLOAT)),y)
SOFT_FLOAT_CONFIG_OPTION += --with-softfloat
endif

CONFIGURE_ARGS += \
        --enable-shared \
        --enable-static \
        --disable-debugging \
        --disable-profiling \
        --with-softfloat \
        --with-versioned=no \

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
		ac_cv_c_bigendian=no \
		ac_cv_func_uselocale=no \
		ac_cv_header_wordexp_h=no \
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
      --disable-static \
      --enable-shared \
      --disable-debug \
      --disable-profiling \
      --disable-python \
      --without-debug \
      $(SOFT_FLOAT_CONFIG_OPTION) \
      --with-versioned=no \
	);
	touch $@

$(PKG_BUILD_DIR)/.built: $(PKG_BUILD_DIR)/.configured
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		TARGET_CC="$(TARGET_CC)" \
		OPT_FLAGS="$(TARGET_CFLAGS)" \
		AM_CFLAGS="" \
		STRIP=/bin/true \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBALSA):
	install -d -m0755 $(IDIR_LIBALSA)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libasound.{la,so*} $(IDIR_LIBALSA)/usr/lib/
	install -d -m0755 $(IDIR_LIBALSA)/usr/share/alsa
	$(CP) $(PKG_INSTALL_DIR)/usr/share/alsa/alsa.conf $(IDIR_LIBALSA)/usr/share/alsa/
	$(RSTRIP) $(IDIR_LIBALSA)
	$(IPKG_BUILD) $(IDIR_LIBALSA) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libasound.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include/alsa
	$(CP) $(PKG_INSTALL_DIR)/usr/include/alsa/*.h $(STAGING_DIR)/usr/include/alsa/
	mkdir -p $(STAGING_DIR)/usr/include/sys
	$(CP) $(PKG_INSTALL_DIR)/usr/include/sys/*.h $(STAGING_DIR)/usr/include/sys/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libasound.{la,so*} $(STAGING_DIR)/usr/lib/
	mkdir -p $(STAGING_DIR)/usr/share/alsa
	$(CP) $(PKG_INSTALL_DIR)/usr/share/alsa/alsa.conf $(STAGING_DIR)/usr/share/alsa/
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/alsa.pc $(STAGING_DIR)/usr/lib/pkgconfig/
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/libasound.so

uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/usr/lib/libasound.{a,so*} \
		$(STAGING_DIR)/usr/lib/pkgconfig/alsa.pc \
		$(STAGING_DIR)/usr/include/alsa \
		$(STAGING_DIR)/usr/share/alsa

compile-targets: install-dev
clean-targets: uninstall-dev
