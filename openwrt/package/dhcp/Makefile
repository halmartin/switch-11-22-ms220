# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=dhcp
PKG_VERSION:=4.3.6-P1
PKG_RELEASE:=1
PKG_MD5SUM:=c0c45f217b2b831dc67574d46e307249

#PKG_SOURCE_URL:=https://dl.meraki.net
UNUSED_ORIGINAL_PKG_SOURCE_URL:=ftp://ftp.isc.org/isc/dhcp/
PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,DHCP_RELAY,dhcp-relay,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,DHCP_SERVER,dhcp-server,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR) ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(strip $(TARGET_CFLAGS))" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
		BUILD_CC=cc \
		./configure \
		  --target=$(GNU_TARGET_NAME) \
		  --host=$(GNU_TARGET_NAME) \
		  --build=$(GNU_HOST_NAME) \
		  --enable-use-sockets \
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
		  --with-randomdev=/dev/random \
		  ac_cv_file__dev_random=yes \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
	        $(TARGET_CONFIGURE_OPTS) \
		DESTDIR="$(PKG_INSTALL_DIR)"
	$(MAKE) -C $(PKG_BUILD_DIR) \
	        $(TARGET_CONFIGURE_OPTS) \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		install
	touch $@

$(IPKG_DHCP_RELAY):
	install -d -m0755 $(IDIR_DHCP_RELAY)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/dhcrelay $(IDIR_DHCP_RELAY)/usr/sbin/
	$(RSTRIP) $(IDIR_DHCP_RELAY)
	$(IPKG_BUILD) $(IDIR_DHCP_RELAY) $(PACKAGE_DIR)

$(IPKG_DHCP_SERVER):
	install -d -m0755 $(IDIR_DHCP_SERVER)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/dhcpd $(IDIR_DHCP_SERVER)/usr/sbin/
	$(RSTRIP) $(IDIR_DHCP_SERVER)
	$(IPKG_BUILD) $(IDIR_DHCP_SERVER) $(PACKAGE_DIR)
