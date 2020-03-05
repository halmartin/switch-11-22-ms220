include $(TOPDIR)/rules.mk

PKG_NAME:=daq
PKG_VERSION:=2.0.6
PKG_RELEASE:=1
PKG_MD5SUM:=2cd6da422a72c129c685fc4bb848c24c
PKG_SOURCE_URL:= https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/daq-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,DAQ,daq,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
		libpcap_version_1x=yes \
		ac_cv_func_malloc_0_nonnull=yes \
		ac_cv_func_realloc_0_nonnull=yes \
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
		--localstatedir=/var/run \
		--mandir=/usr/share/man \
		--sbindir=/usr/sbin \
		--sysconfdir=/etc \
		$(DISABLE_NLS) \
		$(DISABLE_LARGEFILE) \
		--enable-shared \
		--enable-static \
		--with-dnet-includes="$(STAGING_DIR)/usr/include" \
		--with-dnet-libraries="$(STAGING_DIR)/usr/libraries" \
		--with-libpcap-libraries="$(STAGING_DIR)/usr/lib" \
		--with-libpcre-includes="$(STAGING_DIR)/usr/include" \
		--with-libpcre-libraries="$(STAGING_DIR)/usr/lib" \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="-D_GNU_SOURCE $(TARGET_CFLAGS)" \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_DAQ):
	install -m0755 -d $(IDIR_DAQ)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libdaq.so* $(IDIR_DAQ)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libsfbpf.so* $(IDIR_DAQ)/usr/lib/
	install -m0755 -d $(IDIR_DAQ)/usr/lib/daq
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/daq/daq_*.so $(IDIR_DAQ)/usr/lib/daq/
	$(RSTRIP) $(IDIR_DAQ)
	$(IPKG_BUILD) $(IDIR_DAQ) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libdaq.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/daq-modules-config $(STAGING_DIR)/usr/bin/
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/{daq_api.h,daq_common.h,daq.h,sfbpf_dlt.h,sfbpf.h} $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libdaq.{a,so*} $(STAGING_DIR)/usr/lib/
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/libdaq.so

uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/usr/bin/daq-modules-config \
		$(STAGING_DIR)/usr/include/{daq_api.h,daq_common.h,daq.h,sfbpf_dlt.h,sfbpf.h} \
		$(STAGING_DIR)/usr/lib/libdaq.{a,so*} \
		$(STAGING_DIR)/usr/lib/daq/daq_*.so \

compile-targets: install-dev
clean-targets: uninstall-dev
