#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=fftw
PKG_VERSION:=3.3.3
PKG_RELEASE:=2
PKG_MD5SUM:=0a05ca9c7b3bfddc8278e7c40791a1c2

PKG_SOURCE:=fftw-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://dl.meraki.net
UNUSED_ORIGINAL_PKG_SOURCE_URL:=http://www.fftw.org
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install
PKG_FIXUP:=autoreconf

# include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,FFTW,fftw3,$(PKG_VERSION)-$(PKG-RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIBFFTW,libfftw3,$(PKG_VERSION)-$(PKG-RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.cache; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
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
            --disable-debug \
            --disable-fortran \
            $(DISABLE_NLS) \
            $(DISABLE_LARGEFILE) \
            --enable-shared \
            --enable-threads \
            --enable-type-prefix \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -j4 -C $(PKG_BUILD_DIR) \
		DESTDIR=$(PKG_INSTALL_DIR) \
		install
	touch $@

$(IPKG_LIBFFTW):
	install -m0755 -d $(IDIR_LIBFFTW)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libfftw3.so* $(IDIR_LIBFFTW)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libfftw3_threads.so* $(IDIR_LIBFFTW)/usr/lib
	$(RSTRIP) $(IDIR_LIBFFTW)/
	 $(IPKG_BUILD) $(IDIR_LIBFFTW) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libfftw3.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/bin
	mkdir -p $(STAGING_DIR)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/ $(STAGING_DIR)/usr/
	mkdir -p $(STAGING_DIR)/usr/share/
	$(CP) $(PKG_INSTALL_DIR)/usr/share/ $(STAGING_DIR)/usr/
	mkdir -p $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libfftw3.{a,la,so}* $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libfftw3_threads.{a,la,so}* $(STAGING_DIR)/usr/lib/
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/libfftw3.so

uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/usr/bin/fftw-wisdom-to-conf \
		$(STAGING_DIR)/usr/include/fftw3* \
		$(STAGING_DIR)/usr/lib/libfftw3.a \
		$(STAGING_DIR)/usr/lib/libfftw3.so* \
		$(STAGING_DIR)/usr/lib/libfftw3_threads.a \
		$(STAGING_DIR)/usr/lib/libfftw3_threads.so* \


compile-targets: install-dev
clean-targets: uninstall-dev

mostlyclean:
	$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm -f $(PKG_BUILD_DIR)/.built
