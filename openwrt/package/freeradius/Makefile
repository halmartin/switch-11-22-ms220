# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=freeradius-server
PKG_VERSION:=2.2.5
PKG_RELEASE:=1
PKG_MD5SUM:=da77eb23b4c5e2f9fc55119025a91b61

PKG_SOURCE_URL:=https://dl.meraki.net
UNUSED_ORIGINAL_PKG_SOURCE_URL:=ftp://ftp.freeradius.org/pub/radius/ \
	http://freeradius.portal-to-web.de/ \
	ftp://ftp.uk.freeradius.org/pub/radius/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

PKG_CONFIGURE_OPTIONS := \
	--enable-shared \
	--disable-static \
	--disable-ltdl-install \
	--with-ltdl-include="$(STAGING_DIR)/usr/include" \
	--with-ltdl-lib="$(STAGING_DIR)/usr/lib" \
	--with-openssl-includes="$(STAGING_DIR)/usr/include" \
	--with-openssl-libraries="$(STAGING_DIR)/usr/lib" \
	--enable-strict-dependencies \
	--with-raddbdir=/etc/freeradius \
	--without-edir \
	--without-snmp \
	--with-experimental-modules \
	--without-rlm_attr-rewrite \
	--without-rlm_checkval \
	--without-rlm_counter \
	--without-rlm_dbm \
	--with-rlm_eap \
	--without-rlm_eap_sim \
	--without-rlm_example \
	--without-rlm_ippool \
	--without-rlm_krb5 \
	--without-rlm_otp \
	--without-rlm_smsotp \
	--without-rlm_pam \
	--without-rlm_perl \
	--without-rlm_python \
	--without-rlm_radutmp \
	--without-rlm_smb \
	--with-rlm_sql \
	--with-rlm_sqlcounter \
	--without-rlm_sqlhpwippool \
	--without-rlm_sqlippool \
	--without-rlm_sql_db2 \
	--without-rlm_sql_firebird \
	--without-rlm_sql_freetds \
	--without-rlm_sql_iodbc \
	--without-rlm_sql_oracle \
	--without-rlm_sql_sybase \
	--without-rlm_sql_unixodbc \
	--without-rlm_sql_log \
	--without-rlm_sql_sqlite \
	--without-rlm_unix \
	--without-rlm_eap_tnc \
	--without-rlm_eap_ikev2 \
	--without-rlm_opendirectory \
	--without-rlm_wimax \
	--without-rlm_ruby \
	--without-rlm_x99-token \
	--without-rlm_caching \
	--without-rlm_redis \
	--without-rlm_rediswho \
	--without-threads \

PKG_DICTIONARIES:= \
	freeradius freeradius.internal compat \
	rfc2865 rfc2866 rfc2867 rfc2868 rfc2869 rfc3162 rfc3576 rfc3580 \
	rfc4372 rfc4675 rfc4679 \
	microsoft wispr cisco

ifneq ($(BR2_PACKAGE_FREERADIUS_MOD_LDAP),)
PKG_CONFIGURE_OPTIONS += \
	--with-rlm_ldap-include-dir="$(STAGING_DIR)/usr/include" \
	--with-rlm_ldap-lib-dir="$(STAGING_DIR)/usr/lib"
else
PKG_CONFIGURE_OPTIONS += --without-rlm_ldap
endif
ifneq ($(BR2_PACKAGE_FREERADIUS_MOD_SQL_MYSQL),)
PKG_CONFIGURE_OPTIONS += \
	--with-mysql-include-dir="$(STAGING_DIR)/usr/include/mysql" \
	--with-mysql-lib-dir="$(STAGING_DIR)/usr/lib/mysql"
else
PKG_CONFIGURE_OPTIONS += --without-rlm_sql_mysql
endif
ifneq ($(BR2_PACKAGE_FREERADIUS_MOD_SQL_PGSQL),)
PKG_CONFIGURE_OPTIONS += \
	--with-rlm_sql_postgresql-include-dir="$(STAGING_DIR)/usr/include" \
	--with-rlm_sql_postgresql-lib-dir="$(STAGING_DIR)/usr/lib"
else
PKG_CONFIGURE_OPTIONS += --without-rlm_sql_postgresql
endif

include $(TOPDIR)/package/rules.mk

define PKG_mod_template

$$(IPKG_$(1)):
	[ -z "$(2)" ] || install -d -m0755 $$(IDIR_$(1))/usr/lib
	for m in $(2); do \
		$(CP) $(PKG_INSTALL_DIR)/usr/lib/$$$${m}{,-*}.so \
		  $$(IDIR_$(1))/usr/lib/ ; \
	done
	[ -z "$(3)" ] || install -d -m0755 $$(IDIR_$(1))/etc/freeradius
	for f in $(3); do \
		$(CP) $(PKG_INSTALL_DIR)/etc/freeradius/$$$${f} \
		  $$(IDIR_$(1))/etc/freeradius/$$$${f} ; \
	done
	$(RSTRIP) $$(IDIR_$(1))
	$(IPKG_BUILD) $$(IDIR_$(1)) $(PACKAGE_DIR)

endef

$(eval $(call PKG_template,FREERADIUS,freeradius,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_DEMOCERTS,freeradius-democerts,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_CHAP,freeradius-mod-chap,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_DETAIL,freeradius-mod-detail,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_EAP,freeradius-mod-eap,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_EAP_GTC,freeradius-mod-eap-gtc,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_EAP_MD5,freeradius-mod-eap-md5,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_EAP_LEAP,freeradius-mod-eap-leap,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_EAP_MSCHAPV2,freeradius-mod-eap-mschapv2,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_EAP_PEAP,freeradius-mod-eap-peap,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_EAP_TLS,freeradius-mod-eap-tls,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_EAP_TTLS,freeradius-mod-eap-ttls,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_EXEC,freeradius-mod-exec,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_FILES,freeradius-mod-files,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_LDAP,freeradius-mod-ldap,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_MSCHAP,freeradius-mod-mschap,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_PAP,freeradius-mod-pap,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_PREPROCESS,freeradius-mod-preprocess,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_REALM,freeradius-mod-realm,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_SQL,freeradius-mod-sql,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_SQL_MYSQL,freeradius-mod-sql-mysql,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_SQL_PGSQL,freeradius-mod-sql-pgsql,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_SQLCOUNTER,freeradius-mod-sqlcounter,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_RADUTMP,freeradius-mod-radutmp,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_LOGINTIME,freeradius-mod-logintime,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_EXPR,freeradius-mod-expr,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_ATTR_FILTER,freeradius-mod-attr-filter,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_EXPIRATION,freeradius-mod-expiration,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_ALWAYS,freeradius-mod-always,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_DIGEST,freeradius-mod-digest,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_UNIX,freeradius-mod-unix,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_CACHE,freeradius-mod-cache,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_MOD_ACCT_UNIQUE,freeradius-mod-acct-unique,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,FREERADIUS_UTILS,freeradius-utils,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(eval $(call PKG_mod_template,FREERADIUS_MOD_CHAP,rlm_chap,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_DETAIL,rlm_detail,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_EAP,libfreeradius rlm_eap,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_EAP_GTC,rlm_eap_gtc,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_EAP_MD5,rlm_eap_md5,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_EAP_LEAP,rlm_eap_leap,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_EAP_MSCHAPV2,rlm_eap_mschapv2,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_EAP_PEAP,rlm_eap_peap,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_EAP_TLS,rlm_eap_tls,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_EAP_TTLS,rlm_eap_ttls,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_EXEC,rlm_exec,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_FILES,rlm_files,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_LDAP,rlm_ldap,ldap.attrmap))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_MSCHAP,rlm_mschap,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_PAP,rlm_pap,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_PREPROCESS,rlm_preprocess,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_REALM,rlm_realm,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_SQL,rlm_sql,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_SQL_MYSQL,rlm_sql_mysql,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_SQL_PGSQL,rlm_sql_postgresql,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_SQLCOUNTER,rlm_sqlcounter,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_RADUTMP,rlm_radutmp,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_LOGINTIME,rlm_logintime,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_EXPR,rlm_expr,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_ATTR_FILTER,rlm_attr_filter,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_EXPIRATION,rlm_expiration,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_ALWAYS,rlm_always,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_DIGEST,rlm_digest,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_UNIX,rlm_unix,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_CACHE,rlm_cache,))
$(eval $(call PKG_mod_template,FREERADIUS_MOD_ACCT_UNIQUE,rlm_acct_unique,))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		LIBS="-lldap -lssl -llber -lsasl -lcrypto " \
		sys_lib_dlsearch_path_spec="$(STAGING_DIR)/usr/lib $(STAGING_DIR)/lib" \
		sys_lib_search_path_spec="$(STAGING_DIR)/usr/lib $(STAGING_DIR)/lib" \
		MYSQL_CONFIG="no" \
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
			$(PKG_CONFIGURE_OPTIONS) \
	)
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		R="$(PKG_INSTALL_DIR)" \
		INSTALLSTRIP="" \
		all install
	touch $@

$(IPKG_FREERADIUS):
	install -m0755 -d $(IDIR_FREERADIUS)/etc/init.d
	install -m0755 ./files/radiusd.init $(IDIR_FREERADIUS)/etc/init.d/radiusd
	install -m0755 -d $(IDIR_FREERADIUS)/etc/freeradius
	install -m0755 -d $(IDIR_FREERADIUS)/etc/freeradius/certs
	for f in dictionary; do \
		$(CP) $(PKG_INSTALL_DIR)/etc/freeradius/$${f} \
		  $(IDIR_FREERADIUS)/etc/freeradius/ ; \
	done
	install -m0755 -d $(IDIR_FREERADIUS)/usr/share/freeradius
	$(CP) $(PKG_INSTALL_DIR)/usr/share/freeradius/dictionary \
		$(IDIR_FREERADIUS)/usr/share/freeradius/
	for f in $(PKG_DICTIONARIES); do \
		$(CP) $(PKG_INSTALL_DIR)/usr/share/freeradius/dictionary.$${f} \
		  $(IDIR_FREERADIUS)/usr/share/freeradius/ ; \
	done
	install -m0755 -d $(IDIR_FREERADIUS)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libfreeradius-radius{,-*}.so \
	  $(IDIR_FREERADIUS)/usr/lib/
	install -m0755 -d $(IDIR_FREERADIUS)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/radiusd \
	  $(IDIR_FREERADIUS)/usr/sbin/
	$(RSTRIP) $(IDIR_FREERADIUS)
	$(IPKG_BUILD) $(IDIR_FREERADIUS) $(PACKAGE_DIR)

$(IPKG_FREERADIUS_DEMOCERTS):
	install -m0755 -d $(IDIR_FREERADIUS_DEMOCERTS)/etc/freeradius
	$(CP) $(PKG_INSTALL_DIR)/etc/freeradius/certs \
	  $(IDIR_FREERADIUS_DEMOCERTS)/etc/freeradius/
	rm -rf $(IDIR_FREERADIUS_DEMOCERTS)/etc/freeradius/certs/README
	rm -rf $(IDIR_FREERADIUS_DEMOCERTS)/etc/freeradius/certs/new*
	rm -rf $(IDIR_FREERADIUS_DEMOCERTS)/etc/freeradius/certs/demoCA/index*
	rm -rf $(IDIR_FREERADIUS_DEMOCERTS)/etc/freeradius/certs/demoCA/serial*
	$(RSTRIP) $(IDIR_FREERADIUS_DEMOCERTS)
	$(IPKG_BUILD) $(IDIR_FREERADIUS_DEMOCERTS) $(PACKAGE_DIR)

$(IPKG_FREERADIUS_UTILS):
	install -m0755 -d $(IDIR_FREERADIUS_UTILS)/usr/bin
	for f in radclient radeapclient; do \
	  $(CP) $(PKG_INSTALL_DIR)/usr/bin/$${f} \
	    $(IDIR_FREERADIUS_UTILS)/usr/bin/ ; \
	done
	$(RSTRIP) $(IDIR_FREERADIUS_UTILS)
	$(IPKG_BUILD) $(IDIR_FREERADIUS_UTILS) $(PACKAGE_DIR)
