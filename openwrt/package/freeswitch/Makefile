# $Id: Makefile 3566 2006-04-01 15:21:14Z nico $

include $(TOPDIR)/rules.mk

PKG_NAME:=freeswitch
PKG_VERSION:=1.6.16-2b79de
PKG_RELEASE:=2
PKG_MD5SUM:=0e8d3c641b3d61079a9011dd1ff89ff6


PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

CONFIGURE_ARGS = \
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
		  $(DISABLE_NLS) \
		  --with-libpcre="$(STAGING_DIR)/usr" \
			--disable-core-libedit-support \
			--disable-libvpx
CONFIGURE_VARS = \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -Wno-unused-but-set-variable"  \
		CXXFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="$(TARGET_CPPFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		PKG_CONFIG_SYSROOT_DIR="$(STAGING_DIR)" \
		PKG_CONFIG_PATH="$(STAGING_DIR)/usr/lib/pkgconfig" \
		PKG_CONFIG_LIBDIR="$(PKG_CONFIG_LIBDIR)" \
		ac_cv_file__dev_zero=yes \
		ac_cv_func_setpgrp_void=yes \
		apr_cv_tcp_nodelay_with_cork=yes \
		ac_cv_file_dbd_apr_dbd_mysql_c=no \
		ac_cv_file___dev_urandom_=yes \
		ac_cv_va_copy=C99 \
		ac_cv_sizeof_ssize_t=4 \
		ac_cv_func_malloc_0_nonnull=yes\
		ac_cv_func_realloc_0_nonnull=yes\
		apr_cv_mutex_recursive=yes \
		ac_cv_func_pthread_rwlock_init=yes \
		apr_cv_type_rwlock_t=yes \
		ac_cv_pcap_where_inc=$(STAGING_DIR)/include \
		ac_cv_pcap_where_lib=$(STAGING_DIR)/lib \
		with_ssl=$(STAGING_DIR) \
		ac_cv_file__dev_urandom=yes \
		ac_cv_dev_urandom=yes \
		ac_cv_file__dev_random=no \
		enable_visibility=no \
		SWITCH_CONF_DIR="$(FS_PREFIX)/conf" \
		config_BUILD_CC="$(HOSTCC)" \
		config_TARGET_CC="$(TARGET_CC)" \
		config_TARGET_CFLAGS="$(TARGET_CFLAGS)" \
		config_TARGET_LINK="$(TARGET_CC)" \
		BUILD_CC="$(HOSTCC)" \

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,FREESWITCH,freeswitch,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); \
		$(TARGET_CONFIGURE_OPTS) \
		config_BUILD_CC="$(HOSTCC)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		./bootstrap.sh \
	);
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		$(CONFIGURE_VARS) \
		./configure \
		$(CONFIGURE_ARGS) \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -Wno-unused-but-set-variable"  \
    DESTDIR="$(PKG_INSTALL_DIR)" \
    target="$(GNU_TARGET_NAME)" \
		install
# we don't need library and libtool files in space constrained environment
	rm -rf $(PKG_INSTALL_DIR)/usr/lib/freeswitch/mod/*.la \
		$(PKG_INSTALL_DIR)/usr/lib/freeswitch/mod/*.a $(PKG_INSTALL_DIR)/usr/lib/*.la \
		$(PKG_INSTALL_DIR)/usr/lib/*.a $(PKG_INSTALL_DIR)/usr/lib/include
	touch $@

$(IPKG_FREESWITCH):
	install -d -m0755 $(IDIR_FREESWITCH)/usr/lib/
	install -d -m0755 $(IDIR_FREESWITCH)/usr/lib/freeswitch/mod
	install -d -m0755 $(IDIR_FREESWITCH)/usr/bin/

	$(CP) -r $(PKG_INSTALL_DIR)/usr/lib/*.so* $(IDIR_FREESWITCH)/usr/lib/
	$(CP) -r $(PKG_INSTALL_DIR)/usr/bin/freeswitch $(IDIR_FREESWITCH)/usr/bin/
	$(CP) -r $(PKG_INSTALL_DIR)/usr/bin/gentls_cert $(IDIR_FREESWITCH)/usr/bin/
	$(CP) -r $(PKG_INSTALL_DIR)/usr/bin/fs_cli $(IDIR_FREESWITCH)/usr/bin/
	$(CP) -r $(PKG_INSTALL_DIR)/usr/lib/freeswitch/mod/*.so $(IDIR_FREESWITCH)/usr/lib/freeswitch/mod/
	$(RSTRIP) $(IDIR_FREESWITCH)
	$(IPKG_BUILD) $(IDIR_FREESWITCH) $(PACKAGE_DIR)

mostlyclean:
	$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm $(PKG_BUILD_DIR)/.built
