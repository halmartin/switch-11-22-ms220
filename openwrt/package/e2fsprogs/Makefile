# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=e2fsprogs
PKG_VERSION:=1.42.12
PKG_RELEASE:=1
PKG_MD5SUM:=40100c67d61ecba9e0d375974cd121e8

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,E2FSPROGS,$(PKG_NAME),$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status}; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -fPIC" \
		CPPFLAGS="$(TARGET_CFLAGS) -fPIC -fno-builtin -I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib -fPIC" \
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
			--sbindir=/sbin \
			--sysconfdir=/etc \
			$(DISABLE_LARGEFILE) \
			$(DISABLE_NLS) \
			--disable-rpath \
			--with-gnu-ld \
			--enable-elf-shlibs \
			--enable-libuuid \
			--enable-libblkid \
			--disable-defrag \
			--disable-tls \
			--disable-uuidd \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR)/util \
		BUILDCC="$(HOSTCC)" CFLAGS="" CPPFLAGS="" LDFLAGS="" \
		subst
	$(MAKE) -C $(PKG_BUILD_DIR) \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_E2FSPROGS):
	mkdir -p $(IDIR_E2FSPROGS)/sbin
	$(CP) $(PKG_INSTALL_DIR)/sbin/e2fsck $(IDIR_E2FSPROGS)/sbin/
	$(CP) $(PKG_INSTALL_DIR)/sbin/mke2fs $(IDIR_E2FSPROGS)/sbin/
	ln -sf mke2fs $(IDIR_E2FSPROGS)/sbin/mkfs.ext2
	ln -sf mke2fs $(IDIR_E2FSPROGS)/sbin/mkfs.ext3
	ln -sf mke2fs $(IDIR_E2FSPROGS)/sbin/mkfs.ext4
	$(CP) $(PKG_INSTALL_DIR)/sbin/tune2fs $(IDIR_E2FSPROGS)/sbin/
	$(CP) $(PKG_INSTALL_DIR)/sbin/resize2fs $(IDIR_E2FSPROGS)/sbin/
	$(CP) $(PKG_INSTALL_DIR)/sbin/badblocks $(IDIR_E2FSPROGS)/sbin/
	mkdir -p $(IDIR_E2FSPROGS)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/lib{com_err,e2p,ext2fs}.so.* $(IDIR_E2FSPROGS)/usr/lib/
	$(RSTRIP) $(IDIR_E2FSPROGS)
	$(IPKG_BUILD) $(IDIR_E2FSPROGS) $(PACKAGE_DIR)
