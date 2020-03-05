# ipkg-utils
#
# http://handhelds.org/packages/ipkg-utils
#

PKG_NAME := ipkg-utils
PKG_VERSION := 1.7

#PKG_SOURCE_SITE := http://handhelds.org/packages/ipkg-utils/
PKG_SOURCE_SITE := https://dl.meraki.net/
PKG_SOURCE_FILE := $(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_CAT := zcat
PKG_SOURCE_DIR := $(PKG_NAME)-$(PKG_VERSION)
PKG_MD5:= da3e3ef772973d7370a6ac95f0fef9b8

include $(TOPDIR)/rules.mk

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_SOURCE_DIR)


$(DL_DIR)/$(PKG_SOURCE_FILE):
	mkdir -p $(DL_DIR)
	$(SCRIPT_DIR)/download.pl $(DL_DIR) $(PKG_SOURCE_FILE) $(PKG_MD5) $(PKG_SOURCE_SITE)

$(PKG_BUILD_DIR)/.unpacked: $(DL_DIR)/$(PKG_SOURCE_FILE)
	mkdir -p $(BUILD_DIR)
	$(PKG_SOURCE_CAT) $(DL_DIR)/$(PKG_SOURCE_FILE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	touch $(PKG_BUILD_DIR)/.unpacked

$(PKG_BUILD_DIR)/.patched: $(PKG_BUILD_DIR)/.unpacked
	$(PATCH) $(PKG_BUILD_DIR) $(PKG_VERSION)/ \*.patch
	touch $(PKG_BUILD_DIR)/.patched

$(HOST_STAGING_DIR)/usr/bin/ipkg-build: $(PKG_BUILD_DIR)/.patched
	mkdir -p $(HOST_STAGING_DIR)/etc
	echo "dest root /" > $(HOST_STAGING_DIR)/etc/ipkg.conf
	echo "option offline_root $(TARGET_DIR)" >> $(HOST_STAGING_DIR)/etc/ipkg.conf
	mkdir -p $(HOST_STAGING_DIR)/usr/bin
	install -m0755 $(PKG_BUILD_DIR)/ipkg-build $(HOST_STAGING_DIR)/usr/bin
	install -m0755 $(PKG_BUILD_DIR)/ipkg-buildpackage $(HOST_STAGING_DIR)/usr/bin
	install -m0755 $(PKG_BUILD_DIR)/ipkg-make-index $(HOST_STAGING_DIR)/usr/bin
	install -m0755 $(PKG_BUILD_DIR)/ipkg.py $(HOST_STAGING_DIR)/usr/bin

source: $(DL_DIR)/$(PKG_SOURCE_FILE)

prepare: $(PKG_BUILD_DIR)/.patched

compile:

install: $(HOST_STAGING_DIR)/usr/bin/ipkg-build

clean:
	rm -f $(HOST_STAGING_DIR)/etc/ipkg.conf
	rm -f $(HOST_STAGING_DIR)/usr/bin/ipkg*
	rm -rf $(PKG_BUILD_DIR)


