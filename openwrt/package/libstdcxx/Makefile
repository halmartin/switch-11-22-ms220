include $(TOPDIR)/rules.mk

PKG_NAME:=libstdcxx
PKG_VERSION:=6.0.13
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBSTDCXX,libstdcxx,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	touch $@

$(PKG_BUILD_DIR)/.prepared:
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	touch $@

$(IPKG_LIBSTDCXX):
	install -d -m0755 $(IDIR_LIBSTDCXX)/usr/lib
	$(CP) $(STAGING_DIR)/lib*/libstdc++*.so* $(IDIR_LIBSTDCXX)/usr/lib/
	rm -f $(IDIR_LIBSTDCXX)/usr/lib/libstdc++.so*-gdb.py
	-$(STRIP) $(IDIR_LIBSTDCXX)/usr/lib*/*.so*
	mkdir -p $(PACKAGE_DIR)
	$(IPKG_BUILD) $(IDIR_LIBSTDCXX) $(PACKAGE_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	cp COPYING3 $(PKG_BUILD_DIR)/COPYING3
	cp COPYING.RUNTIME $(PKG_BUILD_DIR)/COPYING.RUNTIME

compile-targets: install-dev
install-dev: $(PKG_BUILD_DIR)/.built
