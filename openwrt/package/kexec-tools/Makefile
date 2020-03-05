#
# Copyright (C) 2006-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=kexec-tools
PKG_VERSION:=2.0.16
PKG_RELEASE:=1
PKG_MD5SUM:=5198968de79b5ded96f97f3c2ea9637b

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,KEXEC_TOOLS,kexec-tools,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

ifeq ($(BR2_PACKAGE_LIBLZMA),y)
WITH_LZMA:=yes
else
WITH_LZMA:=no
endif

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.cache; \
		$(TARGET_CONFIGURE_OPTS) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		./configure \
		--target=$(GNU_TARGET_NAME) \
		--host=$(GNU_TARGET_NAME) \
		--build=$(GNU_HOST_NAME) \
		--program-prefix="" \
		--program-suffix="" \
		--prefix=/usr \
		--exec-prefix=/usr \
		--bindir=/usr/bin \
		--sbindir=/sbin \
		--libexecdir=/usr/lib \
		--sysconfdir=/etc \
		--with-lzma=$(WITH_LZMA) \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		CC="$(TARGET_CC)"
	$(MAKE) -C $(PKG_BUILD_DIR) \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		CC="$(TARGET_CC)" \
		install
	touch $@

ifeq ($(strip $(BR2_PACKAGE_KEXEC_TOOLS_STATIC_IN_STAGING)),y)

$(PKG_BUILD_DIR)/build_static/sbin/kexec-static: $(PKG_BUILD_DIR)/.built
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" static

$(STAGING_DIR)/usr/sbin/kexec-static: $(PKG_BUILD_DIR)/build_static/sbin/kexec-static
	mkdir -p $(STAGING_DIR)/usr/sbin
	cp -a $< $@
	$(RSTRIP) $@

install-dev: $(STAGING_DIR)/usr/sbin/kexec-static
endif

install-dev:

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/sbin/kexec-static

compile-targets: install-dev
clean-targets: uninstall-dev

$(IPKG_KEXEC_TOOLS):
	install -d -m0755 $(IDIR_KEXEC_TOOLS)/usr/sbin
	install -m0755 $(PKG_BUILD_DIR)/build/sbin/kexec $(IDIR_KEXEC_TOOLS)/usr/sbin/kexec
	install -m0755 $(PKG_BUILD_DIR)/build/sbin/vmcore-dmesg $(IDIR_KEXEC_TOOLS)/usr/sbin/vmcore-dmesg
	$(RSTRIP) $(IDIR_KEXEC_TOOLS)
	$(IPKG_BUILD) $(IDIR_KEXEC_TOOLS) $(PACKAGE_DIR)

mostlyclean:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		clean
	rm -f $(PKG_BUILD_DIR)/.built
