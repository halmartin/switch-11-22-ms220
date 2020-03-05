include $(TOPDIR)/rules.mk

PKG_NAME:=slang
PKG_VERSION:=2.2.4
PKG_RELEASE:=1
PKG_MD5SUM:=7fcfd447e378f07dd0c0bae671fe6487

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_CAT:=bzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,SLANG,slang,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

TARGET_CFLAGS += $(FPIC)
TARGET_LDFLAGS += -L../src/${ARCH}objs

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib $(TARGET_LDFLAGS)" \
		mr_cv_target_elf=yes \
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
		  --enable-shared \
		  --enable-static \
		  --enable-largefile \
		  --disable-warnings \
		  --with-terminfo=default \
		  --with-readline=slang \
		  --without-x \
		  --without-pcre \
		  --without-onig \
		  --without-png \
		  --without-z \
		  ac_cv_path_nc5config=$(PWD)/files/ncurses5-config \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) -j1 \
		CC="$(TARGET_CC)" LD=$(TARGET_CROSS)ld ARCH=$(ARCH) DESTDIR="$(PKG_INSTALL_DIR)" \
		all static install install-static
	touch $@

$(IPKG_SLANG):
	install -d -m0755 $(IDIR_SLANG)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libslang.so.* $(IDIR_SLANG)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/slang/ $(IDIR_SLANG)/usr/lib/
	$(RSTRIP) $(IDIR_SLANG)
	$(IPKG_BUILD) $(IDIR_SLANG) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libslang.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) -r $(PKG_INSTALL_DIR)/usr/include/*.h $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libslang.{a,so*} $(STAGING_DIR)/usr/lib/

install-dev: $(STAGING_DIR)/usr/lib/libslang.so

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/include/libslang*
	rm -rf $(STAGING_DIR)/usr/lib/libslang.{a,so*}

compile-targets: install-dev
clean-targets: uninstall-dev
