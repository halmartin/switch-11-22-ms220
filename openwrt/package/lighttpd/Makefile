# $Id: Makefile 3518 2006-03-28 07:12:49Z nico $

include $(TOPDIR)/rules.mk

PKG_NAME:=lighttpd
PKG_VERSION:=1.4.39
PKG_RELEASE:=1
PKG_MD5SUM:=b49e133a4b321921331eba5a343872ab

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

define PKG_mod_template

$$(IPKG_$(1)):
	install -d -m0755 $$(IDIR_$(1))/usr/lib/lighttpd
	install -m0755 $(PKG_INSTALL_DIR)/usr/lib/lighttpd/mod_$(2).so $$(IDIR_$(1))/usr/lib/lighttpd/
	$(RSTRIP) $$(IDIR_$(1))
	$(IPKG_BUILD) $$(IDIR_$(1)) $(PACKAGE_DIR)

endef

ifeq ($(BR2_PACKAGE_LIGHTTPD_MOD_OPENSSL),y)
ENABLE_OPENSSL="--with-openssl"
ENABLE_OPENSSL_LIBS="--with-openssl-libs=/usr/lib"
else
ENABLE_OPENSSL="--without-openssl"
endif

$(eval $(call PKG_template,LIGHTTPD,lighttpd,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIGHTTPD_MOD_ACCESSLOG,lighttpd-mod-accesslog,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIGHTTPD_MOD_ACCESS,lighttpd-mod-access,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIGHTTPD_MOD_ALIAS,lighttpd-mod-alias,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIGHTTPD_MOD_AUTH,lighttpd-mod-auth,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIGHTTPD_MOD_CGI,lighttpd-mod-cgi,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIGHTTPD_MOD_EVASIVE,lighttpd-mod-evasive,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIGHTTPD_MOD_EXPIRE,lighttpd-mod-expire,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIGHTTPD_MOD_FASTCGI,lighttpd-mod-fastcgi,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIGHTTPD_MOD_PROXY,lighttpd-mod-proxy,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIGHTTPD_MOD_REDIRECT,lighttpd-mod-redirect,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIGHTTPD_MOD_REWRITE,lighttpd-mod-rewrite,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIGHTTPD_MOD_SETENV,lighttpd-mod-setenv,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIGHTTPD_MOD_SIMPLE_VHOST,lighttpd-mod-simple-vhost,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIGHTTPD_MOD_SSI,lighttpd-mod-ssi,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIGHTTPD_MOD_STATUS,lighttpd-mod-status,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,LIGHTTPD_MOD_USERTRACK,lighttpd-mod-usertrack,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(eval $(call PKG_mod_template,LIGHTTPD_MOD_ACCESSLOG,accesslog))
$(eval $(call PKG_mod_template,LIGHTTPD_MOD_ACCESS,access))
$(eval $(call PKG_mod_template,LIGHTTPD_MOD_ALIAS,alias))
$(eval $(call PKG_mod_template,LIGHTTPD_MOD_AUTH,auth))
$(eval $(call PKG_mod_template,LIGHTTPD_MOD_CGI,cgi))
$(eval $(call PKG_mod_template,LIGHTTPD_MOD_EVASIVE,evasive))
$(eval $(call PKG_mod_template,LIGHTTPD_MOD_EXPIRE,expire))
$(eval $(call PKG_mod_template,LIGHTTPD_MOD_FASTCGI,fastcgi))
$(eval $(call PKG_mod_template,LIGHTTPD_MOD_PROXY,proxy))
$(eval $(call PKG_mod_template,LIGHTTPD_MOD_REDIRECT,redirect))
$(eval $(call PKG_mod_template,LIGHTTPD_MOD_REWRITE,rewrite))
$(eval $(call PKG_mod_template,LIGHTTPD_MOD_SETENV,setenv))
$(eval $(call PKG_mod_template,LIGHTTPD_MOD_SIMPLE_VHOST,simple_vhost))
$(eval $(call PKG_mod_template,LIGHTTPD_MOD_SSI,ssi))
$(eval $(call PKG_mod_template,LIGHTTPD_MOD_STATUS,status))
$(eval $(call PKG_mod_template,LIGHTTPD_MOD_USERTRACK,usertrack))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		PCRECONFIG="$(STAGING_DIR)/usr/bin/pcre-config" \
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
			--libdir=/usr/lib/lighttpd \
			--libexecdir=/usr/lib \
			--localstatedir=/var \
			--mandir=/usr/share/man \
			--sbindir=/usr/sbin \
			--sysconfdir=/etc/lighttpd \
			$(DISABLE_LARGEFILE) \
			$(DISABLE_NLS) \
			--enable-shared \
			--enable-static \
			--disable-rpath \
			--without-attr \
			--without-bzip2 \
			--without-fam \
			--without-gdbm \
			--without-ldap \
			--without-lua \
			--without-memcache \
			--without-mysql \
			$(ENABLE_OPENSSL) \
			$(ENABLE_OPENSSL_LIBS) \
			--with-pcre \
			--without-valgrind \
			--without-webdav-props \
	)
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIGHTTPD):
	install -m0755 -d $(IDIR_LIGHTTPD)/usr/lib/lighttpd
	for m in dirlisting indexfile staticfile; do \
		$(CP) $(PKG_INSTALL_DIR)/usr/lib/lighttpd/mod_$$m.so $(IDIR_LIGHTTPD)/usr/lib/lighttpd/ ; \
	done
	install -m0755 -d $(IDIR_LIGHTTPD)/usr/sbin
	install -m0755 -d $(IDIR_LIGHTTPD)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/lighttpd $(IDIR_LIGHTTPD)/usr/sbin/
	$(RSTRIP) $(IDIR_LIGHTTPD)
	$(IPKG_BUILD) $(IDIR_LIGHTTPD) $(PACKAGE_DIR)

