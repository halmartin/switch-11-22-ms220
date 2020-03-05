# $Id: Makefile 3112 2010-09-16 23:53:19Z rts $

include $(TOPDIR)/rules.mk

PKG_NAME:=LVM2
PKG_VERSION:=2.02.165
PKG_RELEASE:=1
PKG_MD5SUM:=66c1be756e544fe4938256aec2ca4358

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME).$(PKG_VERSION).tgz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME).$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LVM2,lvm2,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -fPIC -Wall" \
		CXXFLAGS="$(TARGET_CFLAGS) -fPIC -fno-builtin -fno-rtti -nostdinc++" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include  -I$(STAGING_DIR)/pcap" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		LIBS="-lc -lm -lgcc" \
		./configure \
		  --target=$(GNU_TARGET_NAME) \
		  --host=$(GNU_TARGET_NAME) \
		  --build=$(GNU_HOST_NAME) \
		--disable-nls \
		--disable-o_direct \
		--disable-udev-systemd-background-jobs \
		  ac_cv_func_malloc_0_nonnull=yes \
		  ac_cv_func_realloc_0_nonnull=yes \
		  ac_cv_func_mmap_fixed_mapped=yes \
		  jm_cv_func_working_malloc=yes \
		  ac_cv_func_alloca_works=yes \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		prefix="/" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	chmod 755 $(PKG_INSTALL_DIR)/lib/libdevmapper.so*
	chmod 755 $(PKG_INSTALL_DIR)/sbin/lvm
	touch $@

$(STAGING_DIR)/lib/libdevmapper.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/lib/
	mkdir -p $(STAGING_DIR)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/lib/libdevmapper.so* $(STAGING_DIR)/lib/
	$(CP) $(PKG_INSTALL_DIR)/include/libdevmapper.h $(STAGING_DIR)/usr/include
	touch $@

install-dev: $(STAGING_DIR)/lib/libdevmapper.so

uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/lib/libdevmapper.so* \
		$(STAGING_DIR)/include/libdevmapper.h


$(IPKG_LVM2):
	install -m0755 -d $(IDIR_LVM2)/usr/bin
	install -m0755 -d $(IDIR_LVM2)/sbin
	$(CP) $(PKG_INSTALL_DIR)/sbin/lvm $(IDIR_LVM2)/sbin
	install -m0755 -d $(IDIR_LVM2)/lib
	$(CP) $(PKG_INSTALL_DIR)/lib/libdevmapper.so* $(IDIR_LVM2)/lib
	$(RSTRIP) $(IDIR_LVM2)
	$(IPKG_BUILD) $(IDIR_LVM2) $(PACKAGE_DIR)

compile-targets: install-dev
clean-targets: uninstall-dev
