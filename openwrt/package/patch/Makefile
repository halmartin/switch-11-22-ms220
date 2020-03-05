include $(TOPDIR)/rules.mk

PKG_NAME:=patch
PKG_VERSION:=2.7.1
PKG_RELEASE:=1
PKG_MD5SUM:=95dd8d7e41dcbcecdd5cd88ef915378d

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_CAT:=zcat

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,PATCH,$(PKG_NAME),$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

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
	$(MAKE) -j1 LD=$(TARGET_CROSS)ld -C $(PKG_BUILD_DIR)
	touch $@

$(IPKG_PATCH):
	install -d -m0755 $(IDIR_PATCH)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/src/$(PKG_NAME) $(IDIR_PATCH)/usr/bin/$(PKG_NAME)
	$(STRIP) $(IDIR_PATCH)/usr/bin/*
	$(IPKG_BUILD) $(IDIR_PATCH) $(PACKAGE_DIR)

