# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=libelf
PKG_VERSION:=0.8.13
PKG_RELEASE:=1
PKG_MD5SUM:=4136d7b4c04df68b686570afa26988ac

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBELF,libelf,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
		mr_cv_target_elf=yes \
		libelf_64bit=yes \
		libelf_cv_struct_elf64_ehdr=yes \
		libelf_cv_type_elf64_addr=no \
		libelf_cv_struct_elf64_rel=yes \
		ac_cv_sizeof_long_long=8 \
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
		  --enable-elf64=yes \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) -j1 \
		CC="$(TARGET_CC)" LD=$(TARGET_CROSS)ld ARCH=$(ARCH) \
		instroot="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBELF):
	install -d -m0755 $(IDIR_LIBELF)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libelf.so.* $(IDIR_LIBELF)/usr/lib/
	$(RSTRIP) $(IDIR_LIBELF)
	$(IPKG_BUILD) $(IDIR_LIBELF) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libelf.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) -r $(PKG_INSTALL_DIR)/usr/include/* $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libelf.{a,so*} $(STAGING_DIR)/usr/lib/

install-dev: $(STAGING_DIR)/usr/lib/libelf.so

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/include/libelf*
	rm -rf $(STAGING_DIR)/usr/lib/libelf.{a,so*}

compile-targets: install-dev
clean-targets: uninstall-dev
