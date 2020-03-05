
include $(TOPDIR)/rules.mk

PKG_NAME:=mbluez
PKG_VERSION:=5.44
PKG_RELEASE:=1
PKG_MD5SUM:=00121be75a7b448f9c662e9f029b1dfd

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,MBLUEZ,mbluez,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIBMBLUEZ,libmbluez,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,MBLUEZ_HCIDUMP,hcidump,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured: 
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
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
			$(DISABLE_LARGEFILE) \
			--enable-shared \
			--enable-static \
			--disable-manpages \
			--enable-deprecated \
			--enable-library \
			--enable-tools \
			--disable-nfc \
			--disable-sap \
			--disable-health \
			--disable-android \
			--disable-sixaxis \
			--disable-midi \
			--disable-a2dp \
			--disable-avrcp \
			--disable-network \
			--disable-hid \
			--disable-hog \
			--disable-udev \
			--disable-obex \
			--disable-cups \
			--disable-datafiles \
			--disable-client \
	)
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_MBLUEZ):
	install -d -m0755 $(IDIR_MBLUEZ)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/{hciconfig,hcitool,hciattach} $(IDIR_MBLUEZ)/usr/bin/
	$(RSTRIP) $(IDIR_MBLUEZ)
	$(IPKG_BUILD) $(IDIR_MBLUEZ) $(PACKAGE_DIR)

$(IPKG_MBLUEZ_HCIDUMP):
	install -d -m0755 $(IDIR_MBLUEZ_HCIDUMP)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/hcidump $(IDIR_MBLUEZ_HCIDUMP)/usr/bin/
	$(RSTRIP) $(IDIR_MBLUEZ_HCIDUMP)
	$(IPKG_BUILD) $(IDIR_MBLUEZ_HCIDUMP) $(PACKAGE_DIR)

$(IPKG_LIBMBLUEZ):
	install -d -m0755 $(IDIR_LIBMBLUEZ)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libbluetooth.so.* $(IDIR_LIBMBLUEZ)/usr/lib/
	$(RSTRIP) $(IDIR_LIBMBLUEZ)
	$(IPKG_BUILD) $(IDIR_LIBMBLUEZ) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libbluetooth.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include/bluetooth
	$(CP) $(PKG_INSTALL_DIR)/usr/include/bluetooth/*.h $(STAGING_DIR)/usr/include/bluetooth
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libbluetooth.{a,so*} $(STAGING_DIR)/usr/lib/

install-dev: $(STAGING_DIR)/usr/lib/libbluetooth.so

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/include/bluetooth
	rm -rf $(STAGING_DIR)/usr/lib/libbluetooth.{a,so*}

compile-targets: install-dev
clean-targets: uninstall-dev

mostlyclean:
	-$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm -f $(PKG_BUILD_DIR)/.built
