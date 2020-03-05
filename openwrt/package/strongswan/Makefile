include $(TOPDIR)/rules.mk

PKG_NAME:=strongswan
PKG_VERSION:=5.6.3
PKG_RELEASE:=1
PKG_MD5SUM:=a6a28eeb22aa58080a7581771a5b63f9

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

SS_PREFIX=/usr

WITH_CONFIG=\
	--with-gnu-ld \
	--with-ipsecdir=/usr/sbin

DEFAULT_CONFIG=\
	--disable-static \
	--enable-charon \
	--enable-scripts \
	--enable-ikev1 \
	--enable-ikev2 \
	--enable-swanctl \
	--enable-libtool-lock \
	--enable-monolithic

STRONGSWAN_CONFIG=\
	--enable-aes \
	--enable-des \
	--enable-ctr \
	--enable-hmac \
	--enable-md5 \
	--enable-openssl \
	--enable-nonce \
	--enable-random \
	--enable-sha1 \
	--enable-sha2

CHARON_CONFIG=\
	--enable-attr \
	--enable-coupling \
	--enable-kernel-netlink \
	--enable-socket-default \
	--enable-vici \
	--enable-systime-fix

$(eval $(call PKG_template,STRONGSWAN,strongswan,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status}; \
		$(TARGET_CONFIGURE_OPTS) \
		CC="$(TARGET_CC)" \
		CXX="$(TARGET_CXX)" \
		CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		SED="/bin/sed" \
		./configure \
			--build=$(GNU_HOST_NAME) \
			--host=$(GNU_TARGET_NAME) \
			--target=$(GNU_TARGET_NAME) \
			--prefix=$(SS_PREFIX) \
			--exec-prefix=$(SS_PREFIX) \
			--program-prefix="" \
			--program-suffix="" \
			--bindir=$(SS_PREFIX)/bin \
			--sbindir=$(SS_PREFIX)/sbin \
			--libexecdir=$(SS_PREFIX)/lib \
			--sysconfdir=/etc \
			--localstatedir=/var \
			--libdir=$(SS_PREFIX)/lib \
			--includedir=$(SS_PREFIX)/include \
			--datadir=$(SS_PREFIX)/share \
			--infodir=$(SS_PREFIX)/share/info \
			--mandir=$(SS_PREFIX)/share/man \
			--docdir=$(SS_PREFIX)/share/doc/strongswan \
			$(WITH_CONFIG) \
			--disable-defaults \
			$(DEFAULT_CONFIG) \
			$(STRONGSWAN_CONFIG) \
			$(CHARON_CONFIG) \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		install
	libtool --finish $(PKG_INSTALL_DIR)/usr/lib/ipsec/
	touch $@

$(IPKG_STRONGSWAN):
	install -d -m0755 $(IDIR_STRONGSWAN)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/ipsec/libstrongswan.so.* $(IDIR_STRONGSWAN)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/ipsec/libcharon.so.* $(IDIR_STRONGSWAN)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/ipsec/libvici.so.* $(IDIR_STRONGSWAN)/usr/lib/
	install -d -m0755 $(IDIR_STRONGSWAN)/usr/bin
	install -d -m0755 $(IDIR_STRONGSWAN)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/charon $(IDIR_STRONGSWAN)/usr/sbin/
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/swanctl $(IDIR_STRONGSWAN)/usr/sbin/
	install -d -m0755 $(IDIR_STRONGSWAN)/etc/
	install -d -m0755 $(IDIR_STRONGSWAN)/etc/strongswan.d/
	install -d -m0755 $(IDIR_STRONGSWAN)/etc/strongswan.d/charon/
	$(CP) $(PKG_INSTALL_DIR)/etc/strongswan.d/charon/*.conf $(IDIR_STRONGSWAN)/etc/strongswan.d/charon/
	install -d -m0755 $(IDIR_STRONGSWAN)/etc/swanctl
	install -d -m0755 $(IDIR_STRONGSWAN)/etc/swanctl/x509
	install -d -m0755 $(IDIR_STRONGSWAN)/etc/swanctl/x509ca
	install -d -m0755 $(IDIR_STRONGSWAN)/etc/swanctl/x509ocsp
	install -d -m0755 $(IDIR_STRONGSWAN)/etc/swanctl/x509aa
	install -d -m0755 $(IDIR_STRONGSWAN)/etc/swanctl/x509ac
	install -d -m0755 $(IDIR_STRONGSWAN)/etc/swanctl/x509crl
	install -d -m0700 $(IDIR_STRONGSWAN)/etc/swanctl/private
	install -d -m0755 $(IDIR_STRONGSWAN)/etc/swanctl/pubkey
	install -d -m0755 $(IDIR_STRONGSWAN)/etc/swanctl/rsa
	install -d -m0755 $(IDIR_STRONGSWAN)/etc/swanctl/ecdsa
	install -d -m0755 $(IDIR_STRONGSWAN)/etc/swanctl/bliss
	install -d -m0755 $(IDIR_STRONGSWAN)/etc/swanctl/pkcs8
	install -d -m0755 $(IDIR_STRONGSWAN)/etc/swanctl/pkcs12
	$(RSTRIP) $(IDIR_STRONGSWAN)
	$(IPKG_BUILD) $(IDIR_STRONGSWAN) $(PACKAGE_DIR)
