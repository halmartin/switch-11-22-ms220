# $Id: Makefile 3386 2006-03-16 21:31:14Z florian $

include $(TOPDIR)/rules.mk

PKG_NAME:=dnsmasq
PKG_VERSION:=2.79
PKG_RELEASE:=0
PKG_MD5SUM:=5d7120a46d0c16a334f46757d7e2ba55

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_CAT:=zcat

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,DNSMASQ,$(PKG_NAME),$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" CFLAGS="$(TARGET_CFLAGS)" COPTS="-DNO_TFTP -DNO_DHCP -DNO_INOTIFY" \
		BINDIR=/usr/sbin MANDIR=/usr/man
	touch $@

$(IPKG_DNSMASQ):
	install -d -m0755 $(IDIR_DNSMASQ)/usr/sbin
	$(CP) $(PKG_BUILD_DIR)/src/$(PKG_NAME) $(IDIR_DNSMASQ)/usr/sbin/
	$(STRIP) $(IDIR_DNSMASQ)/usr/sbin/*
	install -d -m0755 $(IDIR_DNSMASQ)/etc/init.d/
#	install -m0644 ./files/dnsmasq.conf $(IDIR_DNSMASQ)/etc/dnsmasq.conf
#	install -m0755 ./files/S50dnsmasq $(IDIR_DNSMASQ)/etc/init.d/S50dnsmasq
	$(IPKG_BUILD) $(IDIR_DNSMASQ) $(PACKAGE_DIR)

