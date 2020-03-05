# $Id: Makefile 3114 2006-02-02 10:07:28Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=wireless-tools
PKG_VERSION:=29
PKG_RELEASE:=1
PKG_MD5SUM:=e06c222e186f7cc013fd272d023710cb

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=wireless_tools.$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/wireless_tools.29
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,WIRELESS_TOOLS,wireless-tools,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built: $(PKG_BUILD_DIR)/.configured
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" CFLAGS="$(TARGET_CFLAGS) -I." \
		libiw.so.29 iwmulticall
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		PREFIX="$(PKG_INSTALL_DIR)" \
		INSTALL_DIR="$(PKG_INSTALL_DIR)/usr/sbin" \
		INSTALL_LIB="$(PKG_INSTALL_DIR)/usr/lib" \
		install-iwmulticall
	touch $@

$(IPKG_WIRELESS_TOOLS):
	mkdir -p $(IDIR_WIRELESS_TOOLS)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libiw.so.29 $(IDIR_WIRELESS_TOOLS)/usr/lib/
	mkdir -p $(IDIR_WIRELESS_TOOLS)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/iw{config,getid,list,priv,spy} $(IDIR_WIRELESS_TOOLS)/usr/sbin/
	$(RSTRIP) $(IDIR_WIRELESS_TOOLS)
	$(IPKG_BUILD) $(IDIR_WIRELESS_TOOLS) $(PACKAGE_DIR)

install-dev: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/{lib,include}
	$(CP) $(PKG_BUILD_DIR)/libiw.so* $(STAGING_DIR)/usr/lib/
	ln -sf libiw.so.29 $(STAGING_DIR)/usr/lib/libiw.so
	$(CP) $(PKG_BUILD_DIR)/{iwlib,wireless}.h $(STAGING_DIR)/usr/include/

uninstall-dev:
	rm -f $(STAGING_DIR)/usr/lib/libiw.*
	rm -f $(STAGING_DIR)/usr/include/{iwlib,wireless}.h

compile-targets: install-dev
clean-targets: uninstall-dev
