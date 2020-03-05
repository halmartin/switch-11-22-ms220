# $Id$

include $(TOPDIR)/rules.mk

PKG_NAME := intltool
PKG_VERSION := 0.50.2
PKG_RELEASE := 1
PKG_MD5SUM := 23fbd879118253cb99aeac067da5f591

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE := $(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT := zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,INTLTOOL,intltool,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status}; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="-I$(STAGING_DIR)/usr/include $(TARGET_CFLAGS)" \
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
		  --libexecdir=/usr/lib \
		  --datadir=/usr/share \
		  --mandir=/usr/man \
		  $(DISABLE_NLS) \
		  $(DISABLE_LARGEFILE) \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

install-dev:
	$(MAKE) -C $(PKG_BUILD_DIR) install DESTDIR=$(HOST_STAGING_DIR)

uninstall-dev:


compile-targets: install-dev
clean-targets: uninstall-dev
