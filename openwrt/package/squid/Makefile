include $(TOPDIR)/rules.mk

PKG_NAME:=squid
PKG_VERSION:=3.5.23
PKG_RELEASE:=1
PKG_MD5SUM:=f30826f339f3f28de03ce6b3ff793069

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=squid-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/squid-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

AUTH_MODULES:=basic digest ntlm
ifneq ($(BR2_PACKAGE_SQUID_MOD_BASIC_AUTH_GETPWNAM),)
BASIC_AUTH_HELPERS+= getpwnam
endif
ifneq ($(BR2_PACKAGE_SQUID_MOD_BASIC_AUTH_NCSA),)
BASIC_AUTH_HELPERS+= NCSA
endif
ifneq ($(BR2_PACKAGE_SQUID_MOD_BASIC_AUTH_SMB),)
BASIC_AUTH_HELPERS+= SMB
endif
ifneq ($(BR2_PACKAGE_SQUID_MOD_BASIC_AUTH_WINBIND),)
BASIC_AUTH_HELPERS+= winbind
endif
BASIC_AUTH_HELPERS?=none

ifneq ($(BR2_PACKAGE_SQUID_MOD_DIGEST_AUTH_PASSWORD),)
DIGEST_AUTH_HELPERS:=password
endif
DIGEST_AUTH_HELPERS?=none

ifneq ($(BR2_PACKAGE_SQUID_MOD_EXTERNAL_ACL_IP_USER),)
EXTERNAL_ACL_HELPERS+= ip_user
endif
ifneq ($(BR2_PACKAGE_SQUID_MOD_EXTERNAL_ACL_UNIX_GROUP),)
EXTERNAL_ACL_HELPERS+= unix_group
endif
ifneq ($(BR2_PACKAGE_SQUID_MOD_EXTERNAL_ACL_WINBIND_GROUP),)
EXTERNAL_ACL_HELPERS+= winbind_group
endif
EXTERNAL_ACL_HELPERS?=none

ifneq ($(BR2_PACKAGE_SQUID_MOD_NTLM_AUTH_FAKEAUTH),)
NTLM_AUTH_HELPERS+= fakeauth
endif
ifneq ($(BR2_PACKAGE_SQUID_MOD_NTLM_AUTH_SMB_AUTH),)
NTLM_AUTH_HELPERS+= SMB
endif
ifneq ($(BR2_PACKAGE_SQUID_MOD_NTLM_AUTH_WINBIND_AUTH),)
NTLM_AUTH_HELPERS+= winbind
endif
NTLM_AUTH_HELPERS?=none

include $(TOPDIR)/package/rules.mk

define PKG_mod_template

$$(IPKG_$(1)):
	install -d -m0755 $$(IDIR_$(1))/usr/lib/squid
	if [ -e $(PKG_INSTALL_DIR)/usr/lib/squid/$(2) ]; then \
		$(CP) $(PKG_INSTALL_DIR)/usr/lib/squid/$(2) $$(IDIR_$(1))/usr/lib/squid/ ; \
	fi
	$(RSTRIP) $$(IDIR_$(1))
	$(IPKG_BUILD) $$(IDIR_$(1)) $(PACKAGE_DIR)

endef

ifeq ($(BR2_64BIT_ARCH),y)
SQUID_SIZEOF_LONG=8
else
SQUID_SIZEOF_LONG=4
endif


$(eval $(call PKG_template,SQUID,$(PKG_NAME),$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,SQUID_MOD_BASIC_AUTH_GETPWNAM,$(PKG_NAME)-mod-basic-auth-getpwnam,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,SQUID_MOD_BASIC_AUTH_NCSA,$(PKG_NAME)-mod-basic-auth-ncsa,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,SQUID_MOD_BASIC_AUTH_SMB,$(PKG_NAME)-mod-basic-auth-smb,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,SQUID_MOD_BASIC_AUTH_WINBIND,$(PKG_NAME)-mod-basic-auth-winbind,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,SQUID_MOD_DIGEST_AUTH_PASSWORD,$(PKG_NAME)-mod-digest-auth-password,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,SQUID_MOD_EXTERNAL_ACL_IP_USER,$(PKG_NAME)-mod-external-acl-ip-user,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,SQUID_MOD_EXTERNAL_ACL_UNIX_GROUP,$(PKG_NAME)-mod-external-acl-unix-group,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,SQUID_MOD_EXTERNAL_ACL_WINBIND_GROUP,$(PKG_NAME)-mod-external-acl-winbind-group,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,SQUID_MOD_NTLM_AUTH_FAKEAUTH,$(PKG_NAME)-mod-ntlm-auth-fakeauth,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,SQUID_MOD_NTLM_AUTH_SMB_AUTH,$(PKG_NAME)-mod-ntlm-auth-smb-auth,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,SQUID_MOD_NTLM_AUTH_WINBIND_AUTH,$(PKG_NAME)-mod-ntlm-auth-winbind-auth,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(eval $(call PKG_mod_template,SQUID_MOD_BASIC_AUTH_GETPWNAM,getpwname_auth))
$(eval $(call PKG_mod_template,SQUID_MOD_BASIC_AUTH_LDAP,ldap))
$(eval $(call PKG_mod_template,SQUID_MOD_BASIC_AUTH_NCSA,ncsa_auth))
$(eval $(call PKG_mod_template,SQUID_MOD_BASIC_AUTH_SMB,smb_auth))
$(eval $(call PKG_mod_template,SQUID_MOD_BASIC_AUTH_WINBIND,wb_auth))
$(eval $(call PKG_mod_template,SQUID_MOD_DIGEST_AUTH_PASSWORD,digest_pw_auth))
$(eval $(call PKG_mod_template,SQUID_MOD_EXTERNAL_ACL_IP_USER,ip_user_check))
$(eval $(call PKG_mod_template,SQUID_MOD_EXTERNAL_ACL_LDAP_GROUP,ldap_auth))
$(eval $(call PKG_mod_template,SQUID_MOD_EXTERNAL_ACL_UNIX_GROUP,squid_unix_group))
$(eval $(call PKG_mod_template,SQUID_MOD_EXTERNAL_ACL_WINBIND_GROUP,wb_group))
$(eval $(call PKG_mod_template,SQUID_MOD_NTLM_AUTH_FAKEAUTH,fakeauth_auth))
$(eval $(call PKG_mod_template,SQUID_MOD_NTLM_AUTH_SMB_AUTH,ntlm_auth))
$(eval $(call PKG_mod_template,SQUID_MOD_NTLM_AUTH_WINBIND_AUTH,wb_ntlmauth))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.cache; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		squid_filedescriptors_num=16384 \
		BUILDCXX="$(HOSTCXX)" \
		ac_cv_sizeof_void_p=$(SQUID_SIZEOF_LONG) \
		ac_cv_sizeof_short=2 \
		ac_cv_sizeof_int=4 \
		ac_cv_sizeof_long=$(SQUID_SIZEOF_LONG) \
		ac_cv_sizeof_long_long=8 \
		ac_cv_sizeof___int64=0 \
		ac_cv_sizeof_int16_t=2 \
		ac_cv_sizeof_uint16_t=2 \
		ac_cv_sizeof_u_int16_t=2 \
		ac_cv_sizeof_int32_t=4 \
		ac_cv_sizeof_uint32_t=4 \
		ac_cv_sizeof_u_int32_t=4 \
		ac_cv_sizeof_int64_t=8 \
		ac_cv_sizeof_uint64_t=8 \
		ac_cv_sizeof_u_int64_t=8 \
		ac_cv_func_setresuid=no \
		ac_cv_func_va_copy=no \
		ac_cv_func___va_copy=no \
		./configure \
			--target=$(GNU_TARGET_NAME) \
			--host=$(GNU_TARGET_NAME) \
			--build=$(GNU_HOST_NAME) \
			--program-prefix="" \
			--program-suffix="" \
			--prefix=/usr \
			--exec-prefix=/usr \
			--bindir=/usr/bin \
			--datadir=/usr/share/squid \
			--includedir=/usr/include \
			--infodir=/usr/share/info \
			--libdir=/usr/lib \
			--libexecdir=/usr/lib/squid \
			--localstatedir=/var \
			--mandir=/usr/share/man \
			--sbindir=/usr/sbin \
			--sysconfdir=/etc/squid \
			$(DISABLE_LARGEFILE) \
			--enable-shared \
			--enable-static \
			--with-gnu-ld \
			--enable-x-accelerator-vary \
			--with-pthreads \
			--with-dl \
			--enable-icmp \
			--enable-kill-parent-hack \
			--enable-arp-acl \
			--disable-ssl \
			--enable-htcp \
			--enable-err-languages=English \
			--enable-default-err-language=English \
			--disable-linux-netfilter \
			--enable-icmp \
			--enable-external-acl-helpers="" \
			--enable-underscores \
			--enable-cache-digests \
			--enable-referer-log \
			--enable-delay-pools \
			--enable-useragent-log \
			--with-openssl=$(STAGING_DIR)/usr \
			--enable-auth \
			--enable-auth-basic="$(BASIC_AUTH_HELPERS)" \
			--enable-auth-ntlm="$(NTLM_AUTH_HELPERS)" \
			--disable-auth-negotiate \
			--enable-auth-digest="$(DIGEST_AUTH_HELPERS)" \
			--enable-external-acl-helpers="$(EXTERNAL_ACL_HELPERS)" \
			--with-krb5-config=no \
			--without-mit-krb5 \
			--with-openssl \
			--enable-ssl \
			--enable-ssl-crtd \
			--enable-ecap \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		DESTDIR=$(PKG_INSTALL_DIR) \
		all install
	touch $@

$(IPKG_SQUID):
	install -d -m0755 $(IDIR_SQUID)/etc/squid
	$(CP) $(PKG_INSTALL_DIR)/etc/squid/mime.conf $(IDIR_SQUID)/etc/squid/
	$(CP) $(PKG_INSTALL_DIR)/etc/squid/squid.conf $(IDIR_SQUID)/etc/squid/
	install -d -m0755 $(IDIR_SQUID)/usr/share/squid
	$(CP) $(PKG_INSTALL_DIR)/usr/share/squid/* $(IDIR_SQUID)/usr/share/squid/
	install -d -m0755 $(IDIR_SQUID)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/squid $(IDIR_SQUID)/usr/sbin/
	install -d -m0755 $(IDIR_SQUID)/usr/lib/squid
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/squid/{unlinkd,pinger,log_file_daemon,diskd,ssl_crtd} $(IDIR_SQUID)/usr/lib/squid/
	$(RSTRIP) $(IDIR_SQUID)
	$(IPKG_BUILD) $(IDIR_SQUID) $(PACKAGE_DIR)
