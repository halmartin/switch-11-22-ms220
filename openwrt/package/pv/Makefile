# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=pv
PKG_VERSION:=1.4.6
PKG_RELEASE:=1
PKG_MD5SUM:=683940054db811de3c830fb90646e799

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_CAT:=zcat

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,PV,$(PKG_NAME),$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.cache; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L $(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		./configure \
		--target=$(GNU_TARGET_NAME) \
		--host=$(GNU_TARGET_NAME) \
		--build=$(GNU_HOST_NAME) \
		--prefix=/usr \
		--exec-prefix=/usr \
		--bindir=/usr/bin \
		--sbindir=/usr/sbin \
		--libexecdir=/usr/lib \
		--sysconfdir=/etc \
		--datadir=/usr/share \
		--localstatedir=/var \
		--mandir=/usr/man \
		--infodir=/usr/info \
		$(DISABLE_NLS) \
		$(DISABLE_LARGEFILE) \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -j1 LD=$(TARGET_CROSS)ld -C $(PKG_BUILD_DIR) $(PKG_NAME)
	touch $@

$(IPKG_PV):
	install -d -m0755 $(IDIR_PV)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/$(PKG_NAME) $(IDIR_PV)/usr/bin/$(PKG_NAME)
	$(STRIP) $(IDIR_PV)/usr/bin/*
	$(IPKG_BUILD) $(IDIR_PV) $(PACKAGE_DIR)

