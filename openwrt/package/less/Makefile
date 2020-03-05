# $Id: Makefile 2230 2005-10-22 12:12:59Z nbd $

include $(TOPDIR)/rules.mk

PKG_NAME:=less
PKG_VERSION:=481
PKG_RELEASE:=1
PKG_MD5SUM:=50ef46065c65257141a7340123527767

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LESS,less,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="-I$(STAGING_DIR)/usr/include $(TARGET_CFLAGS)" \
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
		  --disable-static \
		  --without-regex \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	LD="$(TARGET_CC) $(TARGET_CFLAGS)" CC="$(TARGET_CC) $(TARGET_CFLAGS)" $(MAKE) -C $(PKG_BUILD_DIR)
	touch $@

$(IPKG_LESS):
	install -d -m0755 $(IDIR_LESS)/usr/bin
	install -m0755 $(PKG_BUILD_DIR)/less $(IDIR_LESS)/usr/bin/
	$(RSTRIP) $(IDIR_LESS)
	$(IPKG_BUILD) $(IDIR_LESS) $(PACKAGE_DIR)
