include $(TOPDIR)/rules.mk

PKG_NAME:=dmalloc
PKG_VERSION:=5.5.2
PKG_RELEASE:=1
PKG_MD5SUM:=f92e5606c23a8092f3d5694e8d1c932e

PKG_SOURCE_URL:=https://dl.meraki.net
UNUSED_ORIGINAL_PKG_SOURCE_URL:=http://dmalloc.com/releases
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tgz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,DMALLOC,dmalloc,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
	        $(TARGET_CONFIGURE_OPTS) \
	        CFLAGS="$(TARGET_CFLAGS) -DMAX_UPLOAD_KB=8192" \
	        ./configure \
	          --target=$(GNU_TARGET_NAME) \
	          --host=$(GNU_TARGET_NAME) \
	          --build=$(GNU_HOST_NAME) \
	          --program-prefix="" \
	          --program-suffix="" \
	          --prefix=/usr \
	          --exec-prefix=/usr \
	          --bindir=/usr/bin \
	          --datadir=/usr/share \
	          --includedir=/usr/include \
	          --infodir=/usr/share/info \
	          --libdir=/usr/lib \
	          --libexecdir=/usr/lib \
	          --localstatedir=/var \
	          --mandir=/usr/share/man \
	          --sbindir=/usr/sbin \
	          --sysconfdir=/etc \
	          --enable-threads \
	          --enable-shlib \
	)
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_DMALLOC):
	install -m0755 -d $(IDIR_DMALLOC)/usr/lib
	install -m0755 -d $(IDIR_DMALLOC)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libdmallocthcxx.so* $(IDIR_DMALLOC)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/dmalloc.h $(IDIR_DMALLOC)/usr/include/
	$(RSTRIP) $(IDIR_DMALLOC)
	$(IPKG_BUILD) $(IDIR_DMALLOC) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libdmallocthcxx.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libdmallocthcxx.a $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libdmallocthcxx.so* $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libdmalloc.a $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/dmalloc.h $(STAGING_DIR)/usr/include/
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/libdmallocthcxx.so

uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/lib/*dmalloc*.a \
		$(STAGING_DIR)/lib/*dmalloc*.so* \
		$(STAGING_DIR)/include/*dmalloc*.h

compile-targets: install-dev
clean-targets: uninstall-dev
