include $(TOPDIR)/rules.mk

PKG_NAME:=libubacktrace
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBUBACKTRACE,libubacktrace,$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.prepared:
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
	touch $@

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -I $(STAGING_DIR)/usr/include -I $(STAGING_DIR)/include -D__USE_GNU"
	touch $@

$(IPKG_LIBUBACKTRACE):
	mkdir -p $(IDIR_LIBUBACKTRACE)/lib
	-mkdir -p $(IDIR_LIBUBACKTRACE)/include
	$(CP) $(PKG_BUILD_DIR)/*.so $(IDIR_LIBUBACKTRACE)/lib
	$(CP) $(PKG_BUILD_DIR)/execinfo.h $(IDIR_LIBUBACKTRACE)/include
	$(RSTRIP) $(IDIR_LIBUBACKTRACE)
	$(IPKG_BUILD) $(IDIR_LIBUBACKTRACE) $(PACKAGE_DIR)

$(STAGING_DIR)/include/execinfo.h: $(PKG_BUILD_DIR)/.built
	rm -f $@
	mkdir -p $(STAGING_DIR)/include
	$(CP) $(PKG_BUILD_DIR)/execinfo.h $(STAGING_DIR)/include/


compile-targets: install-dev
install-dev: $(PKG_BUILD_DIR)/.built $(STAGING_DIR)/include/execinfo.h
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/*.so $(STAGING_DIR)/usr/lib

