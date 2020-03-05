# $Id: Makefile 973 2005-05-19 21:22:09Z nico $

include $(TOPDIR)/rules.mk

PKG_NAME:=rsyslog
PKG_VERSION:=8.36.0
PKG_RELEASE:=1
PKG_MD5SUM:=6846bb6d37af3ce067988dd2460d3a5d
#http://www.rsyslog.com/files/download/rsyslog/rsyslog-8.36.0.tar.gz
PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk
include $(TOPDIR)/package/depend.mk

$(eval $(call PKG_template,RSYSLOG,rsyslog,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.imchardevice: $(PKG_BUILD_DIR)/.prepared
	$(CP) ./src/imchardevice $(PKG_BUILD_DIR)/contrib/
	touch $@

$(PKG_BUILD_DIR)/.configured: $(PKG_BUILD_DIR)/.imchardevice
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; autoreconf -i ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="-I$(STAGING_DIR)/usr/include -DHAVE_JSON_OBJECT_OBJECT_GET_EX -DHAVE_JSON_TOKENER_ERROR_DESC $(TARGET_CFLAGS) -D_INT64_TYPE" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
		ac_cv_func_malloc_0_nonnull="yes" \
		ac_cv_func_realloc_0_nonnull="yes" \
		PKG_CONFIG_SYSROOT_DIR="$(STAGING_DIR)" \
		PKG_CONFIG_PATH="$(STAGING_DIR)/usr/lib/pkgconfig" \
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
		  --enable-liblogging-stdlog=no \
		  --enable-libgcrypt=no \
		  --enable-imchardevice \
		  --enable-imuxsock \
		  --enable-gnutls \
	);
	touch $@

$(PKG_BUILD_DIR)/.built: $(PKG_BUILD_DIR)/.configured
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_RSYSLOG):
	install -m0755 -d $(IDIR_RSYSLOG)/usr/lib/rsyslog
	install -m0755 -d $(IDIR_RSYSLOG)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/rsyslog/*.so $(IDIR_RSYSLOG)/usr/lib/rsyslog/
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/rsyslogd $(IDIR_RSYSLOG)/usr/sbin/
	$(RSTRIP) $(IDIR_RSYSLOG)
	$(IPKG_BUILD) $(IDIR_RSYSLOG) $(PACKAGE_DIR)

install-dev:
	$(MAKE) -C $(PKG_BUILD_DIR) install DESTDIR=$(STAGING_DIR)

uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/usr/sbin/rsyslogd \
		$(STAGING_DIR)/usr/lib/rsyslog \
		$(STAGING_DIR)/usr/share/man/man5/rsyslog* \
		$(STAGING_DIR)/usr/share/man/man8/rsyslog*

compile-targets: install-dev
clean-targets: uninstall-dev

