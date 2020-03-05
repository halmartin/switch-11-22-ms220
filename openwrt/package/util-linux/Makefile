# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=util-linux
PKG_VERSION:=2.26.1
PKG_RELEASE:=1
PKG_MD5SUM:=e47d177f4106fc05998ede680e2780c3

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat
PKG_BUILD_DIR:=$(BUILD_DIR)/util-linux-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,FDISK,fdisk,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,MOUNT,mount,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FINDFS,findfs,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIBFDISK,libfdisk,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIBUUID,libuuid,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIBBLKID,libblkid,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIBMOUNT,libmount,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIBSMARTCOLS,libsmartcols,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LOSETUP,losetup,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,SWAP_UTILS,swap-utils,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,UNSHARE,unshare,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,NSENTER,nsenter,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); \
		autoreconf; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -std=gnu99" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		PKG_CONFIG_PATH="$(STAGING_DIR)/usr/lib/pkgconfig" \
		./configure \
                --target=$(GNU_TARGET_NAME) \
                --host=$(GNU_TARGET_NAME) \
                --build=$(GNU_HOST_NAME) \
                --prefix=/usr \
		--without-ncurses \
		--disable-wall \
		--disable-sulogin \
		--without-python \
		--without-udev \
		--disable-more \
		--disable-agetty \
		--disable-ul \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		OPT="$(TARGET_CFLAGS)" \
		CC="$(TARGET_CROSS)gcc" DESTDIR="$(PKG_INSTALL_DIR)" \
		INSTALLSUID="install -m 4755" \
		all install
	touch $@

$(IPKG_FDISK):
	install -d -m0755 $(IDIR_FDISK)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/sbin/fdisk $(IDIR_FDISK)/usr/sbin/
	$(CP) $(PKG_INSTALL_DIR)/sbin/sfdisk $(IDIR_FDISK)/usr/sbin/
	$(RSTRIP) $(IDIR_FDISK)
	$(IPKG_BUILD) $(IDIR_FDISK) $(PACKAGE_DIR)

$(IPKG_FINDFS):
	install -d -m0755 $(IDIR_FINDFS)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/sbin/findfs $(IDIR_FINDFS)/usr/sbin/
	$(RSTRIP) $(IDIR_FINDFS)
	$(IPKG_BUILD) $(IDIR_FINDFS) $(PACKAGE_DIR)

$(IPKG_MOUNT):
	install -d -m0755 $(IDIR_MOUNT)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/bin/mount $(IDIR_MOUNT)/usr/sbin/
	$(RSTRIP) $(IDIR_MOUNT)
	$(IPKG_BUILD) $(IDIR_MOUNT) $(PACKAGE_DIR)

$(IPKG_LIBFDISK):
	install -d -m0755 $(IDIR_LIBFDISK)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/lib/libfdisk.so.* $(IDIR_LIBFDISK)/usr/lib/
	$(RSTRIP) $(IDIR_LIBFDISK)
	$(IPKG_BUILD) $(IDIR_LIBFDISK) $(PACKAGE_DIR)

$(STAGING_DIR)/lib/libfdisk.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/lib/
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/lib/libfdisk.so.* $(STAGING_DIR)/lib/
	ln -sf libfdisk.so.1.1.0 $(STAGING_DIR)/lib/libfdisk.so
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libfdisk.a $(STAGING_DIR)/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/libfdisk $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/fdisk.pc $(STAGING_DIR)/usr/lib/pkgconfig

$(IPKG_LIBSMARTCOLS):
	install -d -m0755 $(IDIR_LIBSMARTCOLS)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/lib/libsmartcols.so.* $(IDIR_LIBSMARTCOLS)/usr/lib/
	$(RSTRIP) $(IDIR_LIBSMARTCOLS)
	$(IPKG_BUILD) $(IDIR_LIBSMARTCOLS) $(PACKAGE_DIR)

$(STAGING_DIR)/lib/libsmartcols.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/lib/
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/lib/libsmartcols.so.* $(STAGING_DIR)/lib/
	ln -sf libsmartcols.so.1.1.0 $(STAGING_DIR)/lib/libsmartcols.so
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libsmartcols.a $(STAGING_DIR)/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/libsmartcols $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/smartcols.pc $(STAGING_DIR)/usr/lib/pkgconfig

$(IPKG_LIBUUID):
	install -d -m0755 $(IDIR_LIBUUID)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/lib/libuuid.so.* $(IDIR_LIBUUID)/usr/lib/
	$(RSTRIP) $(IDIR_LIBUUID)
	$(IPKG_BUILD) $(IDIR_LIBUUID) $(PACKAGE_DIR)

$(STAGING_DIR)/lib/libuuid.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/lib/
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/lib/libuuid.so.* $(STAGING_DIR)/lib/
	ln -sf libuuid.so.1.3.0 $(STAGING_DIR)/lib/libuuid.so
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libuuid.a $(STAGING_DIR)/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/uuid $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/uuid.pc $(STAGING_DIR)/usr/lib/pkgconfig

$(IPKG_LIBBLKID):
	install -d -m0755 $(IDIR_LIBBLKID)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/lib/libblkid.so.* $(IDIR_LIBBLKID)/usr/lib/
	$(RSTRIP) $(IDIR_LIBBLKID)
	$(IPKG_BUILD) $(IDIR_LIBBLKID) $(PACKAGE_DIR)

$(STAGING_DIR)/lib/libblkid.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/lib/
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/lib/libblkid.so.* $(STAGING_DIR)/lib/
	ln -sf libblkid.so.1.1.0 $(STAGING_DIR)/lib/libblkid.so
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libblkid.a $(STAGING_DIR)/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/blkid $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/blkid.pc $(STAGING_DIR)/usr/lib/pkgconfig

$(IPKG_LIBMOUNT):
	install -d -m0755 $(IDIR_LIBMOUNT)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/lib/libmount.so.* $(IDIR_LIBMOUNT)/usr/lib/
	$(RSTRIP) $(IDIR_LIBMOUNT)
	$(IPKG_BUILD) $(IDIR_LIBMOUNT) $(PACKAGE_DIR)

$(STAGING_DIR)/lib/libmount.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/lib/
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/lib/libmount.so.* $(STAGING_DIR)/lib/
	ln -sf libmount.so.1.1.0 $(STAGING_DIR)/lib/libmount.so
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libmount.a $(STAGING_DIR)/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/libmount $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/mount.pc $(STAGING_DIR)/usr/lib/pkgconfig

$(IPKG_LOSETUP):
	install -d -m0755 $(IDIR_LOSETUP)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/sbin/losetup $(IDIR_LOSETUP)/usr/sbin/
	$(RSTRIP) $(IDIR_LOSETUP)
	$(IPKG_BUILD) $(IDIR_LOSETUP) $(PACKAGE_DIR)

$(IPKG_SWAP_UTILS):
	install -d -m0755 $(IDIR_SWAP_UTILS)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/sbin/mkswap $(IDIR_SWAP_UTILS)/usr/sbin/
	$(CP) $(PKG_INSTALL_DIR)/sbin/swap{on,off} $(IDIR_SWAP_UTILS)/usr/sbin/
	$(RSTRIP) $(IDIR_SWAP_UTILS)
	$(IPKG_BUILD) $(IDIR_SWAP_UTILS) $(PACKAGE_DIR)

$(IPKG_UNSHARE):
	install -d -m0755 $(IDIR_UNSHARE)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/unshare $(IDIR_UNSHARE)/usr/bin/
	$(RSTRIP) $(IDIR_UNSHARE)
	$(IPKG_BUILD) $(IDIR_UNSHARE) $(PACKAGE_DIR)

$(IPKG_NSENTER):
	install -d -m0755 $(IDIR_NSENTER)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/nsenter $(IDIR_NSENTER)/usr/bin/
	$(RSTRIP) $(IDIR_NSENTER)
	$(IPKG_BUILD) $(IDIR_NSENTER) $(PACKAGE_DIR)

UTIL_LINUX_DEV_TARGETS=
ifneq ($(BR2_PACKAGE_LIBFDISK),n)
UTIL_LINUX_DEV_TARGETS += $(STAGING_DIR)/lib/libfdisk.so
endif
ifneq ($(BR2_PACKAGE_LIBUUID),n)
UTIL_LINUX_DEV_TARGETS += $(STAGING_DIR)/lib/libuuid.so
endif
ifneq ($(BR2_PACKAGE_LIBBLKID),n)
UTIL_LINUX_DEV_TARGETS += $(STAGING_DIR)/lib/libblkid.so
endif
ifneq ($(BR2_PACKAGE_LIBMOUNT),n)
UTIL_LINUX_DEV_TARGETS += $(STAGING_DIR)/lib/libmount.so
endif
ifneq ($(BR2_PACKAGE_LIBSMARTCOLS),n)
UTIL_LINUX_DEV_TARGETS += $(STAGING_DIR)/lib/libsmartcols.so
endif

install-dev: $(PKG_BUILD_DIR)/.built $(UTIL_LINUX_DEV_TARGETS)

uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/lib/libfdisk.* \
		$(STAGING_DIR)/usr/include/libfdisk \
		$(STAGING_DIR)/lib/libuuid.* \
		$(STAGING_DIR)/usr/include/uuid \
		$(STAGING_DIR)/lib/libblkid.* \
		$(STAGING_DIR)/usr/include/blkid \
		$(STAGING_DIR)/lib/libmount.* \
		$(STAGING_DIR)/usr/include/libmount \
		$(STAGING_DIR)/lib/libsmartcols.* \
		$(STAGING_DIR)/usr/include/libsmartcols

mostlyclean:
	-$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm -f $(PKG_BUILD_DIR)/.built

compile-targets: install-dev
clean-targets: uninstall-dev

