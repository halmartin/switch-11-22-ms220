# $Id: Makefile 2870 2006-01-10 13:45:36Z nico $

include $(TOPDIR)/rules.mk

PKG_NAME:=netperf
PKG_VERSION:=2.6.0
PKG_RELEASE:=1
PKG_MD5SUM:=0381930a6b3bd4d52dd7b75fc397770a

PKG_SOURCE_URL:=https://dl.meraki.net
UNUSED_ORIGINAL_PKG_SOURCE_URL:=ftp://ftp.netperf.org/netperf/archive/ \
	ftp://ftp.cup.hp.com/dist/networking/benchmarks/netperf/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,NETPERF,netperf,$(PKG_VERSION)$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -I$(PKG_BUILD_DIR)/include/linux -I$(PKG_BUILD_DIR)/include" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		ac_cv_func_setpgrp_void=yes \
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
			--enable-shared \
			--enable-static \
			--enable-slotlookup=none \
	)
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_NETPERF):
	#install -d -m0755 $(IDIR_NETPERF)/etc/init.d
	#install -m0755 ./files/netserver.init $(IDIR_NETPERF)/etc/init.d/S51netserver
	install -d -m0755 $(IDIR_NETPERF)/usr/bin
	install -m0755 $(PKG_BUILD_DIR)/src/netperf $(IDIR_NETPERF)/usr/bin/
	install -m0755 $(PKG_BUILD_DIR)/src/netserver $(IDIR_NETPERF)/usr/bin/
	$(RSTRIP) $(IDIR_NETPERF)
	$(IPKG_BUILD) $(IDIR_NETPERF) $(PACKAGE_DIR)
