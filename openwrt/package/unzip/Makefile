include $(TOPDIR)/rules.mk

PKG_NAME:=unzip
PKG_VERSION:=60
PKG_RELEASE:=1
PKG_MD5SUM:=62b490407489521db863b523a7f86375

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,UNZIP,unzip,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	cp $(PKG_BUILD_DIR)/unix/Makefile $(PKG_BUILD_DIR)/
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		generic
	touch $@

$(IPKG_UNZIP):
	mkdir -p $(IDIR_UNZIP)/usr/bin
	install -m 755 $(PKG_BUILD_DIR)/$(PKG_NAME) $(IDIR_UNZIP)/usr/bin/
	$(STRIP) $(IDIR_UNZIP)/usr/bin/*
	$(IPKG_BUILD) $(IDIR_UNZIP) $(PACKAGE_DIR)
