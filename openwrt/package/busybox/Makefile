# $Id: Makefile 2977 2006-01-14 17:22:39Z kaloz $

include $(TOPDIR)/rules.mk

PKG_NAME:=busybox
PKG_RELEASE:=1

ifeq ($(strip $(BR2_PACKAGE_BUSYBOX_VERSION_1_29)),y)
    PKG_VERSION:=1.29.0
    PKG_MD5SUM:=3c4a8f5d544907277e9df7130bac9f14
else ifeq ($(strip $(BR2_PACKAGE_BUSYBOX_VERSION_1_25)),y)
    PKG_VERSION:=1.25.1
    PKG_MD5SUM:=4f4c5de50b479b11ff636d7d8eb902a2
else ifeq ($(strip $(BR2_PACKAGE_BUSYBOX_VERSION_1_24)),y)
    PKG_VERSION:=1.24.1
    PKG_MD5SUM:=be98a40cadf84ce2d6b05fa41a275c6a
else ifeq ($(strip $(BR2_PACKAGE_BUSYBOX_VERSION_1_23)),y)
    PKG_VERSION:=1.23.1
    PKG_MD5SUM:=5c94d6301a964cd91619bd4d74605245
else ifeq ($(strip $(BR2_PACKAGE_BUSYBOX_VERSION_1_20)),y)
    PKG_VERSION:=1.20.2
    PKG_MD5SUM:=e025414bc6cd79579cc7a32a45d3ae1c
else
    PKG_VERSION:=1.29.0
    PKG_MD5SUM:=3c4a8f5d544907277e9df7130bac9f14
endif
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_CAT:=bzcat

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,BUSYBOX,$(PKG_NAME),$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	$(CP) ./files/config.$(ARCH)$(OPENWRT_EXTRA_BOARD_SUFFIX)$(BUSYBOX_EXTRA_BOARD_SUFFIX) $(PKG_BUILD_DIR)/.config
	$(SED) 's,CROSS_COMPILER_PREFIX.*,CROSS_COMPILER_PREFIX="$(TARGET_CROSS)",g' $(PKG_BUILD_DIR)/.config
	$(SED) 's,EXTRA_CFLAGS.*,EXTRA_CFLAGS="$(TARGET_CFLAGS)",g' $(PKG_BUILD_DIR)/.config
	$(MAKE) CC="$(TARGET_CC)" CROSS_COMPILE="$(TARGET_CROSS)" -C $(PKG_BUILD_DIR) oldconfig
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) CC="$(TARGET_CC)" EXTRA_LDFLAGS="$(EXTRA_LDFLAGS)" \
		CROSS_COMPILE="$(TARGET_CROSS)" PREFIX="$(IDIR_BUSYBOX)" \
		EXTRA_CFLAGS="$(TARGET_CFLAGS)" ARCH="$(ARCH)" -C $(PKG_BUILD_DIR)
	touch $@

ifeq ($(strip $(BR2_PACKAGE_BUSYBOX_STATIC_IN_STAGING)),y)
$(PKG_BUILD_DIR)/busybox-static: $(PKG_BUILD_DIR)/.built
	$(MAKE) CC="$(TARGET_CC)" CROSS_COMPILE="$(TARGET_CROSS)" PREFIX="$(IDIR_BUSYBOX)" \
		EXTRA_CFLAGS="$(TARGET_CFLAGS)" ARCH="$(ARCH)" \
		BUSYBOX_SUFFIX=-static EXTRA_LDFLAGS="$(EXTRA_LDFLAGS) -static" \
		-C $(PKG_BUILD_DIR)

$(STAGING_DIR)/bin/busybox-static: $(PKG_BUILD_DIR)/busybox-static
	mkdir -p $(STAGING_DIR)/bin && cp -a $< $@

install-dev: $(STAGING_DIR)/bin/busybox-static
endif

install-dev:

uninstall-dev:
	rm -rf $(STAGING_DIR)/bin/busybox-static

compile-targets: install-dev
clean-targets: uninstall-dev

$(IPKG_BUSYBOX):
	$(MAKE) CC="$(TARGET_CC)" CROSS_COMPILE="$(TARGET_CROSS)" PREFIX="$(IDIR_BUSYBOX)" \
		EXTRA_CFLAGS="$(TARGET_CFLAGS)" -C $(PKG_BUILD_DIR) install
	$(STRIP) $(IDIR_BUSYBOX)/bin/busybox
	$(IPKG_BUILD) $(IDIR_BUSYBOX) $(PACKAGE_DIR)
