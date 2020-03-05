# $Id: Makefile 3386 2006-03-16 21:31:14Z florian $

include $(TOPDIR)/rules.mk

PKG_NAME:=dnscrypt-proxy
PKG_VERSION:=1.9.4
PKG_RELEASE:=3
PKG_MD5SUM:=aebafce53bc91274c7b8278585734ce4

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_CAT:=bzcat

PKG_DEPENDS += libsodium
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,DNSCRYPT_PROXY,$(PKG_NAME),$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(strip $(TARGET_CFLAGS))" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
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
		  --disable-ssp \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
	  CC="$(TARGET_CC)" CFLAGS="$(TARGET_CFLAGS) -fomit-frame-pointer -fdata-sections -ffunction-sections" \
	  LDFLAGS="$(TARGET_LDFLAGS) -Wl,-gc-sections" \
		MANDIR=/usr/man DESTDIR="$(PKG_INSTALL_DIR)"\
		install
	touch $@

$(IPKG_DNSCRYPT_PROXY):
	install -d -m0755 $(IDIR_DNSCRYPT_PROXY)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/dnscrypt-proxy $(IDIR_DNSCRYPT_PROXY)/usr/sbin
	install -d -m0755 $(IDIR_DNSCRYPT_PROXY)/usr/share/dnscrypt-proxy
	$(CP) ./files/dnscrypt-resolvers.csv $(IDIR_DNSCRYPT_PROXY)/usr/share/dnscrypt-proxy/
	install -d -m0755 $(IDIR_DNSCRYPT_PROXY)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/hostip $(IDIR_DNSCRYPT_PROXY)/usr/bin/
	$(RSTRIP) $(IDIR_DNSCRYPT_PROXY)
	$(IPKG_BUILD) $(IDIR_DNSCRYPT_PROXY) $(PACKAGE_DIR)
