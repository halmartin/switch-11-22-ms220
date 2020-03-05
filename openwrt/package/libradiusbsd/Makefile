include $(TOPDIR)/rules.mk

PKG_NAME:=libradiusbsd
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBRADIUSBSD,libradiusbsd,$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.prepared:
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
	touch $@

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -I $(STAGING_DIR)/usr/include -I $(STAGING_DIR)/include -D__USE_GNU" \
		STAGING_DIR="$(STAGING_DIR)"
	touch $@

$(IPKG_LIBRADIUSBSD):
	mkdir -p $(IDIR_LIBRADIUSBSD)/lib $(IDIR_LIBRADIUSBSD)/include
	$(CP) $(PKG_BUILD_DIR)/*.so $(IDIR_LIBRADIUSBSD)/lib
	$(CP) $(PKG_BUILD_DIR)/radlib*.h $(IDIR_LIBRADIUSBSD)/include
	$(RSTRIP) $(IDIR_LIBRADIUSBSD)
	$(IPKG_BUILD) $(IDIR_LIBRADIUSBSD) $(PACKAGE_DIR)

$(STAGING_DIR)/include/radlib.h: $(PKG_BUILD_DIR)/.built
	rm -f $@
	mkdir -p $(STAGING_DIR)/include
	$(CP) $(PKG_BUILD_DIR)/radlib*.h $(STAGING_DIR)/include/


compile-targets: install-dev
install-dev: $(PKG_BUILD_DIR)/.built $(STAGING_DIR)/include/radlib.h
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/*.so $(STAGING_DIR)/usr/lib

