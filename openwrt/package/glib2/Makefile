# $Id$

include $(TOPDIR)/rules.mk

PKG_NAME := glib2
PKG_VERSION := 2.49.7
PKG_RELEASE := 1
PKG_MD5SUM := 397ead3fcf325cb921d54e2c9e7dfd7a

PKG_SOURCE_URL:=https://dl.meraki.net
UNUSED_ORIGINAL_PKG_SOURCE_URL := http://ftp.gnome.org/pub/GNOME/sources/glib/
PKG_SOURCE := glib-$(PKG_VERSION).tar.xz
PKG_CAT := xzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/glib-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,GLIB2,glib2,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

ifeq ($(BR2_PACKAGE_LIBPCRE_8),y)
GLIB2_PCRE_OPT := --with-pcre=system
else
GLIB2_PCRE_OPT := --with-pcre=internal
endif

ifeq ($(BR2_LIBC_MUSL),y)
GLIB2_ICONV_OPT := --with-libiconv=gnu
else
GLIB2_ICONV_OPT :=
endif

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status}; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="-I$(STAGING_DIR)/usr/include $(TARGET_CFLAGS)" \
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
		  --libexecdir=/usr/lib \
		  --datadir=/usr/share \
		  --mandir=/usr/man \
		  $(GLIB2_PCRE_OPT) \
		  $(GLIB2_ICONV_OPT) \
		  $(DISABLE_NLS) \
		  $(DISABLE_LARGEFILE) \
		  --enable-shared=yes \
		  --enable-static=yes \
		  --with-threads=posix \
		  --with-pcre=system \
		  glib_cv_stack_grows=no \
		  glib_cv_uscore=no \
		  ac_cv_func_posix_getpwuid_r=yes \
		  ac_cv_func_posix_getgrgid_r=yes \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_GLIB2):
	install -m0755 -d $(IDIR_GLIB2)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libg{lib,module,thread,object,io*}-2.0.so.* $(IDIR_GLIB2)/usr/lib/
	$(RSTRIP) $(IDIR_GLIB2)
	$(IPKG_BUILD) $(IDIR_GLIB2) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libglib-2.0.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/glib-2.0 $(STAGING_DIR)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/gio-unix-2.0 $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libg{lib,module,thread,object,io}-2.0.{a,so} $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libg{lib,module,thread,object,io}-*.so.* $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/glib-2.0 $(STAGING_DIR)/usr/lib/
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/g{lib,module*,thread,object,io*}-2.0.pc $(STAGING_DIR)/usr/lib/pkgconfig/
	touch $(STAGING_DIR)/usr/lib/libglib.so

install-dev: $(STAGING_DIR)/usr/lib/libglib-2.0.so

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/include/glib-2.0
	rm -rf $(STAGING_DIR)/usr/include/gio-unix-2.0
	rm -rf $(STAGING_DIR)/usr/lib/libg{lib,module,thread,object,io}-2.-.{a,so}
	rm -rf $(STAGING_DIR)/usr/lib/libg{lib,module,thread,object,io}-*.so.*
	rm -rf $(STAGING_DIR)/usr/lib/glib-2.0
	rm -rf $(STAGING_DIR)/usr/lib/pkgconfig/g{lib,module*,thread,object,io*}-2.0.pc

compile-targets: install-dev
clean-targets: uninstall-dev
