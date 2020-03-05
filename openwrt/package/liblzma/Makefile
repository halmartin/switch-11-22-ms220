include $(TOPDIR)/rules.mk

PKG_NAME:=xz
PKG_VERSION:=5.2.2
PKG_RELEASE:=1
PKG_MD5SUM:=7cf6a8544a7dae8e8106fdf7addfa28c

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBLZMA,liblzma,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

ifeq ($(BOARD),$(filter $(BOARD),axe))
XZ_BUILD_CONFIG= --disable-shared --enable-small
XZ_BUILD_CFLAGS=-Os
endif

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(strip $(TARGET_CFLAGS)) -std=c99 $(XZ_BUILD_CFLAGS)" \
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
		  $(XZ_BUILD_CONFIG) \
	);
	touch $@

ifneq ($(BOARD),$(filter $(BOARD),axe))
$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR)/src/liblzma \
		CFLAGS_O="$(TARGET_CFLAGS)" \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBLZMA):
	install -d -m0755 $(IDIR_LIBLZMA)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/liblzma.so.* $(IDIR_LIBLZMA)/usr/lib
	$(RSTRIP) $(IDIR_LIBLZMA)
	$(IPKG_BUILD) $(IDIR_LIBLZMA) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/liblzma.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/lzma*.h $(STAGING_DIR)/usr/include/
	$(CP) -r $(PKG_INSTALL_DIR)/usr/include/lzma $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/liblzma.{a,so*} $(STAGING_DIR)/usr/lib/
	touch $(STAGING_DIR)/usr/lib/liblzma.so

install-dev: $(STAGING_DIR)/usr/lib/liblzma.so

uninstall-dev:
	rm -rf \
	  $(STAGING_DIR)/usr/include/lzma*.h \
	  $(STAGING_DIR)/usr/include/lzma \
	  $(STAGING_DIR)/usr/lib/liblzma.{a,so*}
else
$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR)/src \
		CFLAGS_O="$(TARGET_CFLAGS)" \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBLZMA):
	install -d -m0755 $(IDIR_LIBLZMA)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/xz $(IDIR_LIBLZMA)/usr/bin/
	$(RSTRIP) $(IDIR_LIBLZMA)
	$(IPKG_BUILD) $(IDIR_LIBLZMA) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/bin/xz: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/xz $(STAGING_DIR)/usr/bin/

install-dev: $(STAGING_DIR)/usr/bin/xz

uninstall-dev:
	rm -rf \
	  $(STAGING_DIR)/usr/bin/xz
endif
compile-targets: install-dev
clean-targets: uninstall-dev
