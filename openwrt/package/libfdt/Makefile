include $(TOPDIR)/rules.mk

PKG_NAME:=dtc
PKG_VERSION:=v1.3.0
PKG_RELEASE:=1
PKG_MD5SUM:=0b94ed452ed3d3b5c1546c27788c416f

PKG_SOURCE_URL:=https://dl.meraki.net
UNUSED_ORIGINAL_PKG_SOURCE_URL:=http://jdl.com/software
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tgz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBFDT,libfdt,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CC="$(TARGET_CROSS)gcc" DESTDIR="$(PKG_INSTALL_DIR)" HOME="" \
		all install
	touch $@

$(IPKG_LIBFDT):
	install -m0755 -d $(IDIR_LIBFDT)/lib
	install -m0755 -d $(IDIR_LIBFDT)/include
	$(CP) $(PKG_INSTALL_DIR)/lib/libfdt*so* $(IDIR_LIBFDT)/lib/
	$(CP) $(PKG_INSTALL_DIR)/include/* $(IDIR_LIBFDT)/include/
	$(RSTRIP) $(IDIR_LIBFDT)
	$(IPKG_BUILD) $(IDIR_LIBFDT) $(PACKAGE_DIR)

$(STAGING_DIR)/lib/libfdt.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include
	mkdir -p $(STAGING_DIR)/lib
	$(CP) $(PKG_INSTALL_DIR)/lib/libfdt.a $(STAGING_DIR)/lib/
	$(CP) $(PKG_INSTALL_DIR)/lib/libfdt*so* $(STAGING_DIR)/lib/
	$(CP) $(PKG_INSTALL_DIR)/include/* $(STAGING_DIR)/include/
	touch $@

install-dev: $(STAGING_DIR)/lib/libfdt.so

uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/lib/libfdt.a \
		$(STAGING_DIR)/lib/libfdt*so* \
		$(STAGING_DIR)/include/*fdt*.h

compile-targets: install-dev
clean-targets: uninstall-dev

mostlyclean:
	-$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm -f $(PKG_BUILD_DIR)/.built

