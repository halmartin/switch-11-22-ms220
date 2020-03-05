# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=sqlite3
PKG_VERSION:=3.14.2
PKG_RELEASE:=1
PKG_MD5SUM:=0ddc784028af01e0c427295a8a374295


PKG_SOURCE_URL:=https://dl.meraki.net
UNUSED_ORIGINAL_PKG_SOURCE_URL:=http://www.sqlite.org/
PKG_SOURCE:=sqlite3-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/sqlite3-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBSQLITE3,libsqlite3,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		config_BUILD_CC="$(HOSTCC)" \
		config_BUILD_CFLAGS="-O2" \
		config_TARGET_CC="$(TARGET_CC)" \
		config_TARGET_CFLAGS="$(TARGET_CFLAGS)" \
		config_TARGET_READLINE_INC="-I$(STAGING_DIR)/usr/include" \
		config_TARGET_READLINE_LIBS="-L$(STAGING_DIR)/usr/lib -lreadline -lncurses" \
		config_TARGET_TCL_INC="-DNO_TCL=1" \
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
			--enable-shared \
			--enable-static \
			--disable-tcl \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBSQLITE3):
	install -d -m0755 $(IDIR_LIBSQLITE3)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libsqlite3.so.* $(IDIR_LIBSQLITE3)/usr/lib/
	$(RSTRIP) $(IDIR_LIBSQLITE3)
	$(IPKG_BUILD) $(IDIR_LIBSQLITE3) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libsqlite3.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/sqlite3.h $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libsqlite3.{a,so*} $(STAGING_DIR)/usr/lib/
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/sqlite3.pc $(STAGING_DIR)/usr/lib/pkgconfig/
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/libsqlite3.so

uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/usr/include/sqlite3.h \
		$(STAGING_DIR)/usr/lib/libsqlite3.{a,so*} \
		$(STAGING_DIR)/usr/lib/pkgconfig/sqlite3.pc \

compile-targets: install-dev
clean-targets: uninstall-dev

mostlyclean:
	-$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm -f $(PKG_BUILD_DIR)/.built 
