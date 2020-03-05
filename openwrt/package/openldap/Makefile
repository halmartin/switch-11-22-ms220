# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=openldap
PKG_VERSION:=2.4.47
PKG_RELEASE:=1
PKG_MD5SUM:=e508f97bfd778fec7799f286e5c07176

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tgz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

PKG_CONFIGURE_OPTIONS = \
	--enable-shared \
	--enable-static \
	--disable-debug \
	--enable-dynamic \
	--enable-syslog \
	--disable-local \
	--disable-slapd \
	--with-cyrus-sasl \
	--without-fetch \
	--with-threads \
	--with-tls \
	--with-yielding_select="yes" \

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBOPENLDAP,libopenldap,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,OPENLDAP_UTILS,openldap-utils,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -DLDAP_DEPRECATED=1" \
		LDFLAGS="-L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib" \
		ac_cv_func_memcmp_clean="yes" \
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
		  --libdir=/usr/lib \
		  --libexecdir=/usr/lib \
		  --localstatedir=/var \
		  --mandir=/usr/share/man \
		  --sbindir=/usr/sbin \
		  --sysconfdir=/etc \
		  $(DISABLE_LARGEFILE) \
		  $(DISABLE_NLS) \
		  $(PKG_CONFIGURE_OPTIONS) \
	)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		HOSTCC="$(HOSTCC)" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		depend all install
	touch $@


$(IPKG_LIBOPENLDAP):
	mkdir -p $(IDIR_LIBOPENLDAP)/etc/openldap
	$(CP) $(PKG_INSTALL_DIR)/etc/openldap/ldap.conf $(IDIR_LIBOPENLDAP)/etc/openldap/
	mkdir -p $(IDIR_LIBOPENLDAP)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/libraries/lib{lber,ldap}/.libs/*.so.* $(IDIR_LIBOPENLDAP)/usr/lib/
	$(RSTRIP) $(IDIR_LIBOPENLDAP)
	$(IPKG_BUILD) $(IDIR_LIBOPENLDAP) $(PACKAGE_DIR)

$(IPKG_OPENLDAP_UTILS):
	mkdir -p $(IDIR_OPENLDAP_UTILS)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/{ldapsearch,ldapadd,ldapmodify} $(IDIR_OPENLDAP_UTILS)/usr/bin/
	$(RSTRIP) $(IDIR_OPENLDAP_UTILS)
	$(IPKG_BUILD) $(IDIR_OPENLDAP_UTILS) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libldap.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/{lber,ldap}*.h $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/libraries/lib{lber,ldap}/.libs/*.{a,so*} $(STAGING_DIR)/usr/lib/
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/libldap.so

uninstall-dev:
	rm -rf $(STAGING_DIR)/usr/include/{lber,ldap}*.h
	rm -rf $(STAGING_DIR)/usr/lib/lib{lber,ldap}*.{a,so*}

compile-targets: install-dev
clean-targets: uninstall-dev
