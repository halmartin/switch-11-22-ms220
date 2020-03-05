# $Id: Makefile for blescan.c $

include $(TOPDIR)/rules.mk

PKG_NAME:=blescan
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/blescan

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,BLESCAN,blescan,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.prepared:
	mkdir -p $(PKG_BUILD_DIR)
	touch $@

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(TARGET_CC) $(TARGET_CFLAGS) -o $(PKG_BUILD_DIR)/blescan blescan.cc -I$(STAGING_DIR)/usr/include -L$(STAGING_DIR)/usr/lib -lbluetooth
	touch $@

$(IPKG_BLESCAN):
	install -d -m0755 $(IDIR_BLESCAN)/usr/bin
	install -m0755 $(PKG_BUILD_DIR)/blescan $(IDIR_BLESCAN)/usr/bin/
	$(RSTRIP) $(IDIR_BLESCAN)
	$(IPKG_BUILD) $(IDIR_BLESCAN) $(PACKAGE_DIR)
