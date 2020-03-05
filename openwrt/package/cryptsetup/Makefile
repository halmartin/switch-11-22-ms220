# $Id: Makefile 3112 2010-09-16 23:53:19Z rts $

include $(TOPDIR)/rules.mk

PKG_NAME:=cryptsetup
PKG_VERSION:=1.7.3
PKG_RELEASE:=1
PKG_MD5SUM:=7e3fdb1a1cd055cb9c5f847b15230d81

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.xz
PKG_CAT:=xzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,CRYPTSETUP,cryptsetup,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

ifeq ($(BR2_PACKAGE_CRYPTSETUP_KERNEL),y)
CRYPTSETUP_USE_KERNEL=
else
CRYPTSETUP_USE_KERNEL=--disable-kernel_crypto
endif

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CXXFLAGS="$(TARGET_CFLAGS) -fno-builtin -fno-rtti -nostdinc++" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include  -I$(STAGING_DIR)/pcap" \
		LDFLAGS="-nodefaultlibs -L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		LIBS="-luuid -ldevmapper -lgcrypt -lgpg-error -lc -lm -lgcc" \
		./configure \
		  --target=$(GNU_TARGET_NAME) \
		  --host=$(GNU_TARGET_NAME) \
		  --build=$(GNU_HOST_NAME) \
		  --with-libgcrypt-prefix=$(STAGING_DIR) \
		  --disable-nls \
		  $(CRYPTSETUP_USE_KERNEL) \
		ac_cv_lib_uuid_uuid_clear=yes \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CROSS)gcc" \
		CFLAGS="$(TARGET_CFLAGS) -Wall" \
		CROSS="$(TARGET_CROSS)" \
		prefix="/usr" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_CRYPTSETUP):
	install -m0755 -d $(IDIR_CRYPTSETUP)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/cryptsetup $(IDIR_CRYPTSETUP)/usr/sbin/
	install -m0755 -d $(IDIR_CRYPTSETUP)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/*.so* $(IDIR_CRYPTSETUP)/usr/lib/
	$(IPKG_BUILD) $(IDIR_CRYPTSETUP) $(PACKAGE_DIR)
