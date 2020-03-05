include $(TOPDIR)/rules.mk

PKG_NAME:=pam-ldap
PKG_VERSION:=186
PKG_RELEASE:=1
PKG_MD5SUM:=58c8689921c5c4578363438acd8503c2

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=pam_ldap-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/pam_ldap-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,PAMLDAP,pam-ldap,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/include -I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib" \
		LIBS="-lsasl -lssl -lcrypto" \
		CXXFLAGS="$(TARGET_CFLAGS)" \
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
		  $(DISABLE_NLS) \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS)
	touch $@

$(IPKG_PAMLDAP):
	install -m0755 -d $(IDIR_PAMLDAP)/lib/security
	$(CP) $(PKG_BUILD_DIR)/pam_ldap.so $(IDIR_PAMLDAP)/lib/security
	$(RSTRIP) $(IDIR_PAMLDAP)
	$(IPKG_BUILD) $(IDIR_PAMLDAP) $(PACKAGE_DIR)
